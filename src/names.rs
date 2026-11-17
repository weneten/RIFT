//! RIFT's names for VPN devices: `NAME.internal` resolves to the tunnel address of the agent
//! NAME, for devices that have a grant on it, as long as the agent has names on and the
//! device has not turned them off (see `vpn::named_agents`).
//!
//! Such a device has the server's tunnel address as its DNS server, and WireGuard apps send
//! every lookup there while the tunnel is on. So this small server answers the `.internal`
//! names itself and passes every other question on unchanged: to the device's own DNS agent
//! (`rift vpn dns`) or else to `RIFT_VPN_DNS`. It listens on a high port of the server's
//! tunnel address; nftables redirects port 53 of the devices that use names to it, so the
//! container needs no extra capability, and nobody else reaches it.

use crate::{
    config::Config,
    model::{AgentRecord, StateSnapshot, VpnAccess, VpnPeer},
    state::StateStore,
    vpn,
};
use anyhow::{Context, Result};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{RwLock, Semaphore},
    time::timeout,
};

/// The port the server answers on; devices reach it as port 53 through a redirect.
pub const DNS_PORT: u16 = 53053;
/// Seconds a device may cache an answer; short, so a moved agent is found again quickly.
const TTL: u32 = 30;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
const TCP_IDLE: Duration = Duration::from_secs(10);
const MAX_UDP: usize = 4096;

const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;
const RCODE_FORMERR: u8 = 1;
const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_NOTIMP: u8 = 4;
const RCODE_REFUSED: u8 = 5;

/// nftables rules for the server: redirect port 53 of devices that use names, and accept
/// them on the DNS port. Devices without names never reach it.
pub fn server_rules(config: &Config, snap: &StateSnapshot) -> vpn::Rules {
    let mut rules = vpn::Rules::default();
    let interface = &config.interface;
    let server = config.server_ipv4;
    for peer in snap.vpn_peers.iter().filter(|p| vpn::uses_names(snap, p)) {
        let source = peer.ipv4;
        rules.prerouting.push_str(&format!(
            "add rule inet rift prerouting_nat iifname \"{interface}\" ip saddr {source} ip daddr {server} meta l4proto {{ tcp, udp }} th dport 53 redirect to :{DNS_PORT}\n"
        ));
        rules.input.push_str(&format!(
            "add rule inet rift input iifname \"{interface}\" ip saddr {source} ip daddr {server} meta l4proto {{ tcp, udp }} th dport {DNS_PORT} accept\n"
        ));
    }
    rules
}

/// Agents that must answer DNS from the server: those that are the DNS agent (`vpn dns`) of
/// a device that uses names. The server asks them on the device's behalf.
pub fn upstream_agents(snap: &StateSnapshot) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for peer in snap.vpn_peers.iter().filter(|p| vpn::uses_names(snap, p)) {
        if let Some(agent) = vpn::dns_agent(snap, peer) {
            if !out.contains(&agent.id) {
                out.push(agent.id.clone());
            }
        }
    }
    out
}

/// Where a device's other lookups go: its DNS agent, or `RIFT_VPN_DNS` (IPv4 first; IPv6
/// servers only when the server has a public IPv6 address).
fn upstreams(snap: &StateSnapshot, peer: &VpnPeer, config: &Config) -> Vec<SocketAddr> {
    if let Some(agent) = vpn::dns_agent(snap, peer) {
        return vec![SocketAddr::new(agent.tunnel_ipv4.into(), 53)];
    }
    let ipv6 = config.public_ips.iter().any(IpAddr::is_ipv6);
    let mut out: Vec<SocketAddr> = config
        .vpn_dns
        .iter()
        .filter(|ip| ip.is_ipv4())
        .map(|ip| SocketAddr::new(*ip, 53))
        .collect();
    if ipv6 {
        out.extend(
            config
                .vpn_dns
                .iter()
                .filter(|ip| ip.is_ipv6())
                .map(|ip| SocketAddr::new(*ip, 53)),
        );
    }
    out
}

/// The question of a query: its name in lower case without the final dot, its type and the
/// offset just after the question.
struct Question {
    name: String,
    qtype: u16,
    qclass: u16,
    end: usize,
}

fn read_question(packet: &[u8]) -> Option<Question> {
    if packet.len() < 12 || u16::from_be_bytes([packet[4], packet[5]]) != 1 {
        return None;
    }
    let mut labels = Vec::new();
    let mut pos = 12;
    loop {
        let len = *packet.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        // A question carries its name in full; compression would point back into the header.
        if len > 63 {
            return None;
        }
        let label = packet.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += len;
        if pos > 12 + 255 {
            return None;
        }
    }
    let qtype = u16::from_be_bytes([*packet.get(pos)?, *packet.get(pos + 1)?]);
    let qclass = u16::from_be_bytes([*packet.get(pos + 2)?, *packet.get(pos + 3)?]);
    Some(Question {
        name: labels.join("."),
        qtype,
        qclass,
        end: pos + 4,
    })
}

/// A response to `query` with `rcode`, its question and, if given, one A record.
fn respond(
    query: &[u8],
    question_end: Option<usize>,
    rcode: u8,
    answer: Option<Ipv4Addr>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(query.get(0..2).unwrap_or(&[0, 0]));
    let opcode_rd = query.get(2).copied().unwrap_or(0) & 0b0111_1001;
    // QR, the query's opcode and RD, AA for our own names; RA; the response code.
    out.push(
        0x80 | opcode_rd
            | if answer.is_some() || rcode == RCODE_NXDOMAIN {
                0x04
            } else {
                0
            },
    );
    out.push(0x80 | rcode);
    let question = question_end.and_then(|end| query.get(12..end));
    out.extend_from_slice(&[0, u8::from(question.is_some())]);
    out.extend_from_slice(&[0, u8::from(answer.is_some())]);
    out.extend_from_slice(&[0, 0, 0, 0]);
    if let Some(question) = question {
        out.extend_from_slice(question);
    }
    if let Some(ip) = answer {
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&TTL.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&ip.octets());
    }
    out
}

/// What to do with a query from `peer`.
enum Reply {
    /// Answered here: a name under `.internal`, or a query that is refused or malformed.
    Local(Vec<u8>),
    /// Any other name: pass it on unchanged.
    Forward,
}

fn decide(query: &[u8], snap: &StateSnapshot, peer: &VpnPeer) -> Reply {
    if query.len() < 12 || query[2] & 0x80 != 0 {
        return Reply::Local(respond(query, None, RCODE_FORMERR, None));
    }
    if (query[2] >> 3) & 0x0f != 0 {
        return Reply::Local(respond(query, None, RCODE_NOTIMP, None));
    }
    let Some(question) = read_question(query) else {
        return Reply::Local(respond(query, None, RCODE_FORMERR, None));
    };
    let suffix = format!(".{}", vpn::NAMES_SUFFIX);
    let Some(label) = question.name.strip_suffix(&suffix) else {
        if question.name == vpn::NAMES_SUFFIX {
            return Reply::Local(respond(query, Some(question.end), 0, None));
        }
        return Reply::Forward;
    };
    let agent: Option<&AgentRecord> = vpn::named_agents(snap, peer)
        .into_iter()
        .find(|a| vpn::dns_label(&a.name).as_deref() == Some(label));
    match agent {
        // The name exists; only an IPv4 address: grants reach agents over IPv4 only, and an
        // AAAA answer would send apps to an address the device does not route.
        Some(agent) if question.qtype == TYPE_A && question.qclass == CLASS_IN => Reply::Local(
            respond(query, Some(question.end), 0, Some(agent.tunnel_ipv4)),
        ),
        Some(_) => Reply::Local(respond(query, Some(question.end), 0, None)),
        None => Reply::Local(respond(query, Some(question.end), RCODE_NXDOMAIN, None)),
    }
}

/// The current snapshot, read again at most every two seconds.
struct Snapshots {
    state: Arc<StateStore>,
    cached: RwLock<Option<(Instant, Arc<StateSnapshot>)>>,
}

impl Snapshots {
    async fn get(&self) -> Option<Arc<StateSnapshot>> {
        if let Some((at, snap)) = self.cached.read().await.as_ref() {
            if at.elapsed() < Duration::from_secs(2) {
                return Some(snap.clone());
            }
        }
        let snap = Arc::new(self.state.snapshot().ok()?);
        *self.cached.write().await = Some((Instant::now(), snap.clone()));
        Some(snap)
    }
}

/// The device a query comes from, if it uses names.
fn device(snap: &StateSnapshot, source: IpAddr) -> Option<&VpnPeer> {
    let IpAddr::V4(source) = source else {
        return None;
    };
    snap.vpn_peers
        .iter()
        .find(|p| p.ipv4 == source && vpn::uses_names(snap, p))
}

async fn forward_udp(query: &[u8], upstreams: &[SocketAddr]) -> Option<Vec<u8>> {
    for upstream in upstreams {
        let bind: SocketAddr = if upstream.is_ipv4() {
            "0.0.0.0:0".parse().ok()?
        } else {
            "[::]:0".parse().ok()?
        };
        let Ok(socket) = UdpSocket::bind(bind).await else {
            continue;
        };
        if socket.send_to(query, upstream).await.is_err() {
            continue;
        }
        let mut buf = vec![0u8; MAX_UDP];
        let deadline = Instant::now() + UPSTREAM_TIMEOUT;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match timeout(left, socket.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) if from == *upstream && n >= 2 && buf[..2] == query[..2] => {
                    return Some(buf[..n].to_vec());
                }
                Ok(Ok(_)) => continue,
                _ => break,
            }
        }
    }
    None
}

async fn forward_tcp(query: &[u8], upstreams: &[SocketAddr]) -> Option<Vec<u8>> {
    for upstream in upstreams {
        let attempt = async {
            let mut stream = TcpStream::connect(upstream).await.ok()?;
            let len = u16::try_from(query.len()).ok()?;
            stream.write_all(&len.to_be_bytes()).await.ok()?;
            stream.write_all(query).await.ok()?;
            let n = stream.read_u16().await.ok()? as usize;
            let mut buf = vec![0u8; n];
            stream.read_exact(&mut buf).await.ok()?;
            Some(buf)
        };
        if let Ok(Some(answer)) = timeout(UPSTREAM_TIMEOUT, attempt).await {
            return Some(answer);
        }
    }
    None
}

async fn handle(query: &[u8], source: IpAddr, ctx: &Names, tcp: bool) -> Vec<u8> {
    let Some(snap) = ctx.snapshots.get().await else {
        return respond(query, None, RCODE_SERVFAIL, None);
    };
    let Some(peer) = device(&snap, source) else {
        return respond(query, None, RCODE_REFUSED, None);
    };
    match decide(query, &snap, peer) {
        Reply::Local(answer) => answer,
        Reply::Forward => {
            let upstreams = upstreams(&snap, peer, &ctx.config);
            let answer = if tcp {
                forward_tcp(query, &upstreams).await
            } else {
                forward_udp(query, &upstreams).await
            };
            answer.unwrap_or_else(|| {
                let end = read_question(query).map(|q| q.end);
                respond(query, end, RCODE_SERVFAIL, None)
            })
        }
    }
}

struct Names {
    config: Config,
    snapshots: Snapshots,
    limit: Arc<Semaphore>,
}

/// Serves the names on the server's tunnel address until the process ends. Binding waits for
/// the tunnel address, which appears once the WireGuard interface is up.
pub async fn serve(config: Config, state: Arc<StateStore>) {
    let address = SocketAddr::new(config.server_ipv4.into(), DNS_PORT);
    let ctx = Arc::new(Names {
        config,
        snapshots: Snapshots {
            state,
            cached: RwLock::new(None),
        },
        limit: Arc::new(Semaphore::new(256)),
    });
    let (udp, tcp) = loop {
        match (
            UdpSocket::bind(address).await,
            TcpListener::bind(address).await,
        ) {
            (Ok(udp), Ok(tcp)) => break (udp, tcp),
            (udp, tcp) => {
                let error = udp
                    .err()
                    .or(tcp.err())
                    .map(|e| e.to_string())
                    .unwrap_or_default();
                tracing::debug!("names: waiting to listen on {address}: {error}");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    tracing::info!(
        "names (.{}) for VPN devices on {address}",
        vpn::NAMES_SUFFIX
    );
    let udp = Arc::new(udp);
    let tcp_ctx = ctx.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, from)) = tcp.accept().await else {
                continue;
            };
            let ctx = tcp_ctx.clone();
            tokio::spawn(async move {
                let _ = serve_tcp(stream, from.ip(), &ctx).await;
            });
        }
    });
    let mut buf = vec![0u8; MAX_UDP];
    loop {
        let Ok((n, from)) = udp.recv_from(&mut buf).await else {
            continue;
        };
        let Ok(permit) = ctx.limit.clone().acquire_owned().await else {
            continue;
        };
        let (query, udp, ctx) = (buf[..n].to_vec(), udp.clone(), ctx.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let answer = handle(&query, from.ip(), &ctx, false).await;
            let _ = udp.send_to(&answer, from).await;
        });
    }
}

async fn serve_tcp(mut stream: TcpStream, from: IpAddr, ctx: &Names) -> Result<()> {
    loop {
        let len = match timeout(TCP_IDLE, stream.read_u16()).await {
            Ok(Ok(len)) => len as usize,
            _ => return Ok(()),
        };
        let mut query = vec![0u8; len];
        timeout(TCP_IDLE, stream.read_exact(&mut query))
            .await
            .context("read timeout")??;
        let answer = handle(&query, from, ctx, true).await;
        let len = u16::try_from(answer.len()).context("answer too long")?;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&answer).await?;
    }
}

/// A grant the server adds to an agent's policy so it may ask that agent's DNS server on
/// behalf of devices that use names.
pub fn upstream_rule(server_ipv4: Ipv4Addr) -> crate::model::AgentVpnRule {
    crate::model::AgentVpnRule {
        source: server_ipv4,
        access: VpnAccess::Dns,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AgentRecord, AgentStatus, PortRange, Protocol, VpnGrant};

    fn agent(name: &str, last: u8, names: bool) -> AgentRecord {
        AgentRecord {
            names,
            id: format!("id-{name}"),
            name: name.into(),
            public_key: format!("key-{name}"),
            tunnel_ipv4: Ipv4Addr::new(10, 13, 0, last),
            tunnel_ipv6: format!("fd88:5249:4654::{last}").parse().unwrap(),
            status: AgentStatus::Active,
            attempt_id: name.into(),
            generation: 1,
            applied_generation: 1,
            last_error: None,
            created_at: 0,
            pending_deadline: None,
            limits: None,
            exit: None,
            exit_port: None,
        }
    }
    fn peer(name: &str, last: u8) -> VpnPeer {
        VpnPeer {
            names_off: false,
            name: name.into(),
            public_key: format!("key-{name}"),
            ipv4: Ipv4Addr::new(10, 14, 0, last),
            enabled: true,
            created_at: 0,
            panel: false,
            ipv6: format!("fd88:5249:4655::{last}").parse().unwrap(),
            server_exit: false,
            agent_exits: Vec::new(),
        }
    }
    fn port(peer: &str, agent: &str, port: u16) -> VpnGrant {
        VpnGrant {
            peer: peer.into(),
            agent_id: format!("id-{agent}"),
            access: VpnAccess::Port {
                protocol: Protocol::Tcp,
                ports: PortRange {
                    start: port,
                    end: port,
                },
            },
        }
    }
    /// PP and core have names on, other does not. The phone reaches PP and other; the
    /// laptop reaches nothing; the tablet reaches PP but turned names off.
    fn snap() -> StateSnapshot {
        let mut tablet = peer("tablet", 4);
        tablet.names_off = true;
        StateSnapshot {
            agents: vec![
                agent("PP", 2, true),
                agent("core", 3, true),
                agent("other", 4, false),
            ],
            vpn_peers: vec![peer("phone", 2), peer("laptop", 3), tablet],
            vpn_grants: vec![
                port("phone", "PP", 3000),
                port("phone", "other", 22),
                port("tablet", "PP", 3000),
            ],
            ..Default::default()
        }
    }
    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        q
    }
    fn local(reply: Reply) -> Vec<u8> {
        match reply {
            Reply::Local(answer) => answer,
            Reply::Forward => panic!("expected a local answer"),
        }
    }
    fn rcode(answer: &[u8]) -> u8 {
        answer[3] & 0x0f
    }
    fn answers(answer: &[u8]) -> u16 {
        u16::from_be_bytes([answer[6], answer[7]])
    }

    #[test]
    fn a_device_resolves_the_named_agents_it_reaches() {
        let snap = snap();
        let phone = &snap.vpn_peers[0];
        let q = query("PP.internal", TYPE_A);
        let answer = local(decide(&q, &snap, phone));
        assert_eq!(&answer[..2], &[0x12, 0x34], "the ID is kept");
        assert_eq!(answer[2] & 0x80, 0x80, "it is a response");
        assert_eq!(rcode(&answer), 0);
        assert_eq!(answers(&answer), 1);
        assert_eq!(&answer[answer.len() - 4..], &[10, 13, 0, 2]);
        // The question is echoed and the record points back to it.
        assert_eq!(&answer[12..q.len()], &q[12..]);
        assert_eq!(&answer[q.len()..q.len() + 2], &[0xc0, 0x0c]);
    }

    #[test]
    fn names_the_device_may_not_see_do_not_exist() {
        let snap = snap();
        let phone = &snap.vpn_peers[0];
        // core has names on, but the phone has no grant on it; other has names off.
        for name in ["core.internal", "other.internal", "nothing.internal"] {
            let answer = local(decide(&query(name, TYPE_A), &snap, phone));
            assert_eq!(rcode(&answer), RCODE_NXDOMAIN, "{name}");
            assert_eq!(answers(&answer), 0, "{name}");
        }
    }

    #[test]
    fn only_ipv4_is_answered_and_other_names_are_passed_on() {
        let snap = snap();
        let phone = &snap.vpn_peers[0];
        let aaaa = local(decide(&query("pp.internal", 28), &snap, phone));
        assert_eq!(
            (rcode(&aaaa), answers(&aaaa)),
            (0, 0),
            "AAAA: the name exists, no data"
        );
        assert!(matches!(
            decide(&query("example.com", TYPE_A), &snap, phone),
            Reply::Forward
        ));
        // A response or a strange opcode is not taken for a question.
        let mut response = query("pp.internal", TYPE_A);
        response[2] |= 0x80;
        assert_eq!(
            rcode(&local(decide(&response, &snap, phone))),
            RCODE_FORMERR
        );
        let mut update = query("pp.internal", TYPE_A);
        update[2] = 5 << 3;
        assert_eq!(rcode(&local(decide(&update, &snap, phone))), RCODE_NOTIMP);
        assert_eq!(
            rcode(&local(decide(&[1, 2, 3], &snap, phone))),
            RCODE_FORMERR
        );
    }

    #[test]
    fn only_devices_that_use_names_are_served_and_let_through_the_firewall() {
        let snap = snap();
        assert!(
            device(&snap, "10.14.0.2".parse().unwrap()).is_some(),
            "phone"
        );
        assert!(
            device(&snap, "10.14.0.3".parse().unwrap()).is_none(),
            "laptop: no grant"
        );
        assert!(
            device(&snap, "10.14.0.4".parse().unwrap()).is_none(),
            "tablet: names off"
        );
        assert!(
            device(&snap, "10.13.0.2".parse().unwrap()).is_none(),
            "an agent"
        );
        let config = Config {
            server_ipv4: "10.13.0.1".parse().unwrap(),
            ..Config::default()
        };
        let rules = server_rules(&config, &snap);
        assert!(rules.prerouting.contains(&format!(
            "ip saddr 10.14.0.2 ip daddr 10.13.0.1 meta l4proto {{ tcp, udp }} th dport 53 redirect to :{DNS_PORT}"
        )));
        assert!(rules.input.contains(&format!("ip saddr 10.14.0.2 ip daddr 10.13.0.1 meta l4proto {{ tcp, udp }} th dport {DNS_PORT} accept")));
        assert!(!rules.input.contains("10.14.0.3") && !rules.input.contains("10.14.0.4"));
    }

    #[test]
    fn other_lookups_go_to_the_device_dns_agent_or_rift_vpn_dns() {
        let mut snap = snap();
        let config = Config {
            vpn_dns: vec!["9.9.9.9".parse().unwrap(), "2620:fe::fe".parse().unwrap()],
            ..Config::default()
        };
        let phone = snap.vpn_peers[0].clone();
        assert_eq!(
            upstreams(&snap, &phone, &config),
            vec!["9.9.9.9:53".parse().unwrap()]
        );
        assert!(upstream_agents(&snap).is_empty());
        snap.vpn_grants.push(VpnGrant {
            peer: "phone".into(),
            agent_id: "id-other".into(),
            access: VpnAccess::Dns,
        });
        assert_eq!(
            upstreams(&snap, &phone, &config),
            vec!["10.13.0.4:53".parse().unwrap()]
        );
        assert_eq!(upstream_agents(&snap), vec!["id-other".to_string()]);
    }

    /// The real sockets: a query over UDP and over TCP on loopback, from a device whose
    /// address is the loopback address.
    #[tokio::test]
    async fn the_server_answers_over_udp_and_tcp() {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(StateStore::open(&dir.path().join("state.db")).unwrap());
        let mut phone = peer("phone", 9);
        phone.ipv4 = Ipv4Addr::LOCALHOST;
        state
            .mutate("test", |x| {
                x.agents = vec![agent("PP", 2, true)];
                x.vpn_peers = vec![phone];
                x.vpn_grants = vec![port("phone", "PP", 3000)];
                Ok(())
            })
            .unwrap();
        let config = Config {
            server_ipv4: Ipv4Addr::LOCALHOST,
            ..Config::default()
        };
        tokio::spawn(serve(config, state));
        let server: SocketAddr = (Ipv4Addr::LOCALHOST, DNS_PORT).into();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let q = query("pp.internal", TYPE_A);
        let mut buf = [0u8; 512];
        let mut answer = None;
        for _ in 0..50 {
            socket.send_to(&q, server).await.unwrap();
            if let Ok(Ok((n, _))) =
                timeout(Duration::from_millis(100), socket.recv_from(&mut buf)).await
            {
                answer = Some(buf[..n].to_vec());
                break;
            }
        }
        let answer = answer.expect("no answer over UDP");
        assert_eq!(&answer[answer.len() - 4..], &[10, 13, 0, 2]);

        let mut stream = TcpStream::connect(server).await.unwrap();
        let q = query("nothing.internal", TYPE_A);
        stream
            .write_all(&(q.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&q).await.unwrap();
        let n = stream.read_u16().await.unwrap() as usize;
        let mut answer = vec![0u8; n];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(rcode(&answer), RCODE_NXDOMAIN);
    }

    /// Other names are passed on unchanged and the upstream's answer comes back as it is.
    #[tokio::test]
    async fn other_names_are_relayed_to_the_upstream() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = upstream.recv_from(&mut buf).await.unwrap();
            let mut reply = buf[..n].to_vec();
            reply[2] |= 0x80;
            reply.extend_from_slice(b"upstream");
            upstream.send_to(&reply, from).await.unwrap();
        });
        let q = query("example.com", TYPE_A);
        // An unreachable upstream first: the next one answers.
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let answer = forward_udp(&q, &[dead, address])
            .await
            .expect("no relayed answer");
        assert_eq!(&answer[..2], &q[..2]);
        assert!(answer.ends_with(b"upstream"));
    }

    #[test]
    fn agent_names_become_dns_labels() {
        assert_eq!(vpn::dns_label("PP").as_deref(), Some("pp"));
        assert_eq!(
            vpn::dns_label("home_server").as_deref(),
            Some("home-server")
        );
        assert_eq!(vpn::dns_label("-x"), None);
        assert_eq!(vpn::dns_label(&"a".repeat(64)), None);
    }
}
