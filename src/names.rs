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
    model::{AgentRecord, AgentStatus, StateSnapshot, VpnAccess, VpnPeer},
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

/// The default port the server answers on (`RIFT_NAMES_PORT`); devices reach it as port 53
/// through a redirect.
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
    let port = config.names_port;
    for peer in snap.vpn_peers.iter().filter(|p| vpn::uses_names(snap, p)) {
        let source = peer.ipv4;
        rules.prerouting.push_str(&format!(
            "add rule inet rift prerouting_nat iifname \"{interface}\" ip saddr {source} ip daddr {server} meta l4proto {{ tcp, udp }} th dport 53 redirect to :{port}\n"
        ));
        rules.input.push_str(&format!(
            "add rule inet rift input iifname \"{interface}\" ip saddr {source} ip daddr {server} meta l4proto {{ tcp, udp }} th dport {port} accept\n"
        ));
    }
    // Agents that link to named agents ask the name server directly, on its own port, for
    // those names only (their host's resolver sends nothing else).
    for agent in snap
        .agents
        .iter()
        .filter(|a| !link_agents(snap, &a.id).is_empty())
    {
        let source = agent.tunnel_ipv4;
        rules.input.push_str(&format!(
            "add rule inet rift input iifname \"{interface}\" ip saddr {source} ip daddr {server} meta l4proto {{ tcp, udp }} th dport {port} accept\n"
        ));
    }
    rules
}

/// The agents whose names an agent's host resolves: those it opens links to that have names
/// on (`rift link allow`, `rift vpn names agent NAME on`).
pub fn link_agents<'a>(snap: &'a StateSnapshot, agent_id: &str) -> Vec<&'a AgentRecord> {
    let mut out: Vec<&AgentRecord> = Vec::new();
    for link in vpn::effective_links(snap) {
        if link.from.id == agent_id && link.to.names && !out.iter().any(|a| a.id == link.to.id) {
            out.push(link.to);
        }
    }
    out
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
    // QR, the query's opcode and RD, AA for our own names (answers that repeat the question);
    // RA; the response code.
    out.push(0x80 | opcode_rd | if question_end.is_some() { 0x04 } else { 0 });
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
    decide_under(query, snap, peer, &vpn::names_suffix())
}

/// `decide` for the names under `names` (`internal`, `home.arpa`, a domain of your own).
fn decide_under(query: &[u8], snap: &StateSnapshot, peer: &VpnPeer, names: &str) -> Reply {
    decide_among(query, &vpn::named_agents(snap, peer), names)
}

/// Answers the name of one of `agents` under `names`; every other well-formed query goes on.
fn decide_among(query: &[u8], agents: &[&AgentRecord], names: &str) -> Reply {
    if query.len() < 12 || query[2] & 0x80 != 0 {
        return Reply::Local(respond(query, None, RCODE_FORMERR, None));
    }
    if (query[2] >> 3) & 0x0f != 0 {
        return Reply::Local(respond(query, None, RCODE_NOTIMP, None));
    }
    let Some(question) = read_question(query) else {
        return Reply::Local(respond(query, None, RCODE_FORMERR, None));
    };
    let Some(label) = question.name.strip_suffix(&format!(".{names}")) else {
        return Reply::Forward;
    };
    let agent = agents
        .iter()
        .find(|a| vpn::dns_label(&a.name).as_deref() == Some(label));
    // Every other name under the suffix goes on, as any name does: public ones of a domain of
    // your own keep working, and for a private suffix the upstream answers that it does not
    // exist. RIFT needs no list of which suffixes are which.
    let Some(agent) = agent else {
        return Reply::Forward;
    };
    if question.qtype == TYPE_A && question.qclass == CLASS_IN {
        Reply::Local(respond(
            query,
            Some(question.end),
            0,
            Some(agent.tunnel_ipv4),
        ))
    } else {
        // The name exists; only an IPv4 address: grants reach agents over IPv4 only, and an
        // AAAA answer would send apps to an address the device does not route.
        Reply::Local(respond(query, Some(question.end), 0, None))
    }
}

/// The agents whose names the VPS host itself resolves: active, names on, and the host has a
/// grant on them (`rift host allow`).
pub fn host_agents(snap: &StateSnapshot) -> Vec<&AgentRecord> {
    snap.agents
        .iter()
        .filter(|a| {
            a.names
                && a.status == AgentStatus::Active
                && snap.host_grants.iter().any(|g| g.agent_id == a.id)
        })
        .collect()
}

/// The file in the web panel's queue directory (shared with the host) that lists the names the
/// VPS host resolves. The host service `rift-host-names` (`sudo rift host names on`) watches it
/// and gives systemd-resolved one routing domain per name, so only these exact names go to
/// RIFT: other names under the suffix, such as a cloud provider's `metadata.google.internal`,
/// keep the host's own DNS.
pub const HOST_NAMES_FILE: &str = "host-names";

/// The text of `HOST_NAMES_FILE`: `KEY=VALUE` lines the host service reads with sed.
pub fn host_names_text(config: &Config, snap: &StateSnapshot) -> String {
    let suffix = vpn::names_suffix();
    let mut domains: Vec<String> = host_agents(snap)
        .iter()
        .filter_map(|a| vpn::dns_label(&a.name))
        .map(|label| format!("{label}.{suffix}"))
        .collect();
    domains.sort();
    domains.dedup();
    format!(
        "# Written by rift-server: the names this host resolves through RIFT (rift host names).\n\
         server={}:{}\ninterface={}\ndomains={}\n",
        config.server_ipv4,
        config.names_port,
        config.interface,
        domains.join(" ")
    )
}

/// Writes `HOST_NAMES_FILE` into `dir` when its text changed; nothing without the directory
/// (no host command installed). Written in place, so the host's path unit sees one close.
pub fn write_host_names(dir: &std::path::Path, text: &str) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    let path = dir.join(HOST_NAMES_FILE);
    if std::fs::read_to_string(&path).is_ok_and(|old| old == text) {
        return Ok(());
    }
    std::fs::write(&path, text).with_context(|| format!("write {}", path.display()))
}

/// On an agent, the directory it shares with its host (`deploy/install-cli` creates it, the
/// compose file mounts it): rift-agent writes `HOST_NAMES_FILE` there for the host service
/// `rift-host-names`, which writes its status beside it.
pub const AGENT_HOST_DIR: &str = "/var/lib/rift-agent-host";

/// The text of `HOST_NAMES_FILE` on an agent: the names of the agents it links to (already
/// checked by `agent_policy::names_for_host`) and the server's name server.
pub fn agent_host_names_text(
    interface: &str,
    server: SocketAddr,
    names: Option<&crate::model::AgentNames>,
) -> String {
    let domains = names.map(|n| n.domains.join(" ")).unwrap_or_default();
    let server = names.map_or(server, |n| n.server);
    format!(
        "# Written by rift-agent: the names this host resolves through RIFT (rift link allow).\n\
         server={server}\ninterface={interface}\ndomains={domains}\n"
    )
}

/// How the agent's host resolves the names of the agents it links to, for `rift doctor` on the
/// agent: (fine, text). None while it has no such name and the host part is not installed.
pub fn agent_host_names_note(dir: &std::path::Path) -> Option<(bool, String)> {
    let wanted: Vec<String> = std::fs::read_to_string(dir.join(HOST_NAMES_FILE))
        .ok()
        .and_then(|text| {
            text.lines()
                .filter_map(|l| l.strip_prefix("domains="))
                .next_back()
                .map(|d| d.split_whitespace().map(String::from).collect())
        })
        .unwrap_or_default();
    let status = host_names_status(dir);
    let detail = status["detail"].as_str().unwrap_or_default();
    let list = wanted.join(", ");
    Some(match status["state"].as_str() {
        None if wanted.is_empty() => return None,
        None => (
            false,
            format!("{list}: the host part is missing (sudo sh deploy/install-cli on this host)"),
        ),
        Some("off") => (
            wanted.is_empty(),
            "switched off on this host (sudo rift host names on)".to_string(),
        ),
        Some("unavailable") => (wanted.is_empty(), format!("not possible here: {detail}")),
        Some("error") => (false, detail.to_string()),
        _ if wanted.is_empty() => (
            true,
            "none: this agent links to no agent with names on".to_string(),
        ),
        _ if !wanted
            .iter()
            .all(|w| status["domains"].as_array().is_some_and(|d| d.iter().any(|d| d == w))) =>
        {
            (false, format!("{list}: being applied"))
        }
        _ if status["lookup"] == "missing" => (
            false,
            format!("{list} resolve, but ssh does not ask systemd-resolved (apt install libnss-resolve)"),
        ),
        _ => (true, format!("{list} ✓")),
    })
}

/// What the host service last did (`host-names.status`, written by `rift-host-names`):
/// `{"state": "active|off|unavailable|error", "detail", "domains": [...], "lookup": "ok|missing"}`,
/// or null when the host part is not installed or older.
pub fn host_names_status(dir: &std::path::Path) -> serde_json::Value {
    let Ok(text) = std::fs::read_to_string(dir.join(format!("{HOST_NAMES_FILE}.status"))) else {
        return serde_json::Value::Null;
    };
    let field = |key: &str| {
        text.lines()
            .filter_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .next_back()
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    let domains: Vec<String> = field("domains")
        .split_whitespace()
        .map(String::from)
        .collect();
    serde_json::json!({
        "state": field("state"),
        "detail": field("detail"),
        "domains": domains,
        "lookup": field("lookup"),
    })
}

/// How the VPS host resolves this agent's name, for the agent's details: (fine, text). None
/// when the host has no grant on the agent or the agent's name is no DNS label.
pub fn host_name_note(
    agent: &serde_json::Value,
    host: &serde_json::Value,
) -> Option<(bool, String)> {
    if agent["host_grants"].as_array().is_none_or(|g| g.is_empty()) {
        return None;
    }
    let name = agent["dns_name"].as_str()?;
    if agent["names"] != true {
        return Some((false, format!("{name}: names off (n turns them on)")));
    }
    let detail = host["detail"].as_str().unwrap_or_default();
    Some(match host["state"].as_str() {
        None => (
            false,
            format!("{name}: the host part is missing (sudo sh deploy/install-cli)"),
        ),
        Some("off") => (
            false,
            format!("{name}: switched off on the VPS (sudo rift host names on)"),
        ),
        Some("unavailable") => (false, format!("{name}: not possible here: {detail}")),
        Some("error") => (false, format!("{name}: {detail}")),
        _ if !host["domains"]
            .as_array()
            .is_some_and(|d| d.iter().any(|d| d == name)) =>
        {
            (false, format!("{name}: being applied"))
        }
        _ if host["lookup"] == "missing" => (
            false,
            format!("{name} resolves, but ssh does not ask systemd-resolved (apt install libnss-resolve)"),
        ),
        _ => (true, format!("{name} ✓ (ssh USER@{name} on the VPS)")),
    })
}

/// A query of the VPS host itself. Its resolver sends only the names of `HOST_NAMES_FILE` here
/// (`rift host names on`), so nothing is passed on: an unknown name under the suffix does not
/// exist, and any other name is refused rather than resolved for the host.
fn decide_host(query: &[u8], snap: &StateSnapshot, names: &str) -> Reply {
    decide_only(query, &host_agents(snap), names)
}

/// Answers the names of `agents` and nothing else: an unknown name under the suffix does not
/// exist, any other name is refused. For hosts whose resolver sends only RIFT's names here.
fn decide_only(query: &[u8], agents: &[&AgentRecord], names: &str) -> Reply {
    match decide_among(query, agents, names) {
        Reply::Forward => {
            let question = read_question(query);
            let under = question
                .as_ref()
                .is_some_and(|q| q.name == names || q.name.ends_with(&format!(".{names}")));
            Reply::Local(if under {
                respond(query, question.map(|q| q.end), RCODE_NXDOMAIN, None)
            } else {
                respond(query, None, RCODE_REFUSED, None)
            })
        }
        local => local,
    }
}

const TYPE_OPT: u16 = 41;
const OPTION_ECS: u16 = 8;
/// The UDP payload size RIFT announces in an OPT record it adds (the common safe value).
const EDNS_PAYLOAD: u16 = 1232;

fn count(packet: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_be_bytes([*packet.get(at)?, *packet.get(at + 1)?]) as usize)
}

/// The offset after the name that starts at `pos` (labels or a compression pointer).
fn skip_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    for _ in 0..128 {
        let len = *packet.get(pos)?;
        match len {
            0 => return Some(pos + 1),
            l if l & 0xc0 == 0xc0 => {
                packet.get(pos + 1)?;
                return Some(pos + 2);
            }
            l if l & 0xc0 == 0 => pos += 1 + l as usize,
            _ => return None,
        }
    }
    None
}

/// The resource records of a message: (start, offset of the type field, offset after its
/// data) for every record, and the section each one is in (0 answer, 1 authority, 2
/// additional). `None` when the message is malformed.
fn records(packet: &[u8]) -> Option<Vec<(usize, usize, usize, u8)>> {
    let qd = count(packet, 4)?;
    let counts = [count(packet, 6)?, count(packet, 8)?, count(packet, 10)?];
    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(packet, pos)? + 4;
    }
    let mut out = Vec::new();
    for (section, n) in counts.iter().enumerate() {
        for _ in 0..*n {
            let start = pos;
            let typ = skip_name(packet, pos)?;
            let rdlen = count(packet, typ + 8)?;
            pos = typ + 10 + rdlen;
            if pos > packet.len() {
                return None;
            }
            out.push((start, typ, pos, section as u8));
        }
    }
    (pos == packet.len()).then_some(out)
}

/// `query` with an EDNS Client Subnet option that names the device (`ip`/32), so the device's
/// DNS server can show and filter per device (Pi-hole reads it). A client's own ECS option is
/// replaced; without an OPT record one is added, and the bool says so, to take it out of the
/// answer again. A query that cannot be parsed goes out unchanged.
fn with_client_subnet(query: &[u8], ip: Ipv4Addr) -> (Vec<u8>, bool) {
    let mut ecs = Vec::with_capacity(12);
    ecs.extend_from_slice(&OPTION_ECS.to_be_bytes());
    ecs.extend_from_slice(&8u16.to_be_bytes());
    ecs.extend_from_slice(&1u16.to_be_bytes()); // family: IPv4
    ecs.extend_from_slice(&[32, 0]); // source prefix /32, scope 0
    ecs.extend_from_slice(&ip.octets());
    let Some(list) = records(query) else {
        return (query.to_vec(), false);
    };
    let opt = list.iter().find(|(_, typ, _, section)| {
        *section == 2 && count(query, *typ) == Some(TYPE_OPT as usize)
    });
    match opt {
        Some(&(_, typ, end, _)) => {
            let data = typ + 10;
            let mut options = Vec::new();
            let mut pos = data;
            while pos + 4 <= end {
                let code = count(query, pos).unwrap_or(0) as u16;
                let len = count(query, pos + 2).unwrap_or(0);
                if pos + 4 + len > end {
                    return (query.to_vec(), false);
                }
                if code != OPTION_ECS {
                    options.extend_from_slice(&query[pos..pos + 4 + len]);
                }
                pos += 4 + len;
            }
            options.extend_from_slice(&ecs);
            let Ok(rdlen) = u16::try_from(options.len()) else {
                return (query.to_vec(), false);
            };
            let mut out = query[..typ + 8].to_vec();
            out.extend_from_slice(&rdlen.to_be_bytes());
            out.extend_from_slice(&options);
            out.extend_from_slice(&query[end..]);
            (out, false)
        }
        None => {
            let mut out = query.to_vec();
            let ar = count(query, 10).unwrap_or(0) as u16 + 1;
            out[10..12].copy_from_slice(&ar.to_be_bytes());
            out.push(0); // the root name
            out.extend_from_slice(&TYPE_OPT.to_be_bytes());
            out.extend_from_slice(&EDNS_PAYLOAD.to_be_bytes());
            out.extend_from_slice(&[0, 0, 0, 0]);
            out.extend_from_slice(&(ecs.len() as u16).to_be_bytes());
            out.extend_from_slice(&ecs);
            (out, true)
        }
    }
}

/// `answer` without its OPT record: for a device that sent no EDNS, which RIFT added.
fn without_opt(answer: &[u8]) -> Vec<u8> {
    let Some(list) = records(answer) else {
        return answer.to_vec();
    };
    let Some(&(start, _, end, _)) = list.iter().find(|(_, typ, _, section)| {
        *section == 2 && count(answer, *typ) == Some(TYPE_OPT as usize)
    }) else {
        return answer.to_vec();
    };
    let mut out = answer[..start].to_vec();
    out.extend_from_slice(&answer[end..]);
    let ar = count(answer, 10).unwrap_or(1).saturating_sub(1) as u16;
    out[10..12].copy_from_slice(&ar.to_be_bytes());
    out
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
    // The VPS host itself asks from the server's tunnel address. Nobody else can: the kernel
    // drops packets from outside that carry a local source address, and WireGuard admits an
    // agent or a device only from its own address.
    if source == IpAddr::V4(ctx.config.server_ipv4) {
        return match decide_host(query, &snap, &vpn::names_suffix()) {
            Reply::Local(answer) => answer,
            Reply::Forward => respond(query, None, RCODE_REFUSED, None),
        };
    }
    // An agent's host asks for the agents it links to (its resolver sends only those names).
    if let Some(agent) = snap
        .agents
        .iter()
        .find(|a| IpAddr::V4(a.tunnel_ipv4) == source && a.status == AgentStatus::Active)
    {
        return match decide_only(query, &link_agents(&snap, &agent.id), &vpn::names_suffix()) {
            Reply::Local(answer) => answer,
            Reply::Forward => respond(query, None, RCODE_REFUSED, None),
        };
    }
    let Some(peer) = device(&snap, source) else {
        return respond(query, None, RCODE_REFUSED, None);
    };
    match decide(query, &snap, peer) {
        Reply::Local(answer) => answer,
        Reply::Forward => {
            let upstreams = upstreams(&snap, peer, &ctx.config);
            // The device's own DNS server (an AdGuard or Pi-hole on its DNS agent) learns which
            // device asks; public resolvers (RIFT_VPN_DNS) never get the address.
            let (outgoing, added) = if vpn::dns_agent(&snap, peer).is_some() {
                with_client_subnet(query, peer.ipv4)
            } else {
                (query.to_vec(), false)
            };
            let answer = if tcp {
                forward_tcp(&outgoing, &upstreams).await
            } else {
                forward_udp(&outgoing, &upstreams).await
            };
            let answer = answer.map(|a| if added { without_opt(&a) } else { a });
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
    let address = SocketAddr::new(config.server_ipv4.into(), config.names_port);
    let ctx = Arc::new(Names {
        config,
        snapshots: Snapshots {
            state,
            cached: RwLock::new(None),
        },
        limit: Arc::new(Semaphore::new(256)),
    });
    let mut waited = 0u32;
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
                // The tunnel address appears a moment after the start; longer than that, say it.
                waited += 1;
                if waited == 6 {
                    tracing::warn!("names: cannot listen on {address} for 30 s: {error}; devices that use RIFT's names resolve nothing until it can");
                } else {
                    tracing::debug!("names: waiting to listen on {address}: {error}");
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    tracing::info!(
        "names (.{}) for VPN devices on {address}",
        vpn::names_suffix()
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
            protocol: 0,
            rift_version: String::new(),
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
    /// node1 and node2 have names on, other does not. The phone reaches node1 and other;
    /// the laptop reaches nothing; the tablet reaches node1 but turned names off.
    fn snap() -> StateSnapshot {
        let mut tablet = peer("tablet", 4);
        tablet.names_off = true;
        StateSnapshot {
            agents: vec![
                agent("node1", 2, true),
                agent("node2", 3, true),
                agent("other", 4, false),
            ],
            vpn_peers: vec![peer("phone", 2), peer("laptop", 3), tablet],
            vpn_grants: vec![
                port("phone", "node1", 3000),
                port("phone", "other", 22),
                port("tablet", "node1", 3000),
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
        let q = query("NODE1.internal", TYPE_A);
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
    fn the_server_host_resolves_named_agents_it_has_a_host_grant_on_and_nothing_else() {
        let mut snap = snap();
        let host = |agent: &str| crate::model::HostGrant {
            agent_id: format!("id-{agent}"),
            access: VpnAccess::Server,
        };
        // node1: names on and a host grant. node2: names on, no host grant. other: a host
        // grant, names off.
        snap.host_grants = vec![host("node1"), host("other")];
        let names: Vec<&str> = host_agents(&snap).iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["node1"]);
        let a = local(decide_host(
            &query("node1.internal", TYPE_A),
            &snap,
            "internal",
        ));
        assert_eq!((rcode(&a), answers(&a)), (0, 1));
        assert_eq!(&a[a.len() - 4..], &[10, 13, 0, 2]);
        let aaaa = local(decide_host(&query("node1.internal", 28), &snap, "internal"));
        assert_eq!((rcode(&aaaa), answers(&aaaa)), (0, 0), "exists, IPv4 only");
        for unknown in [
            "node2.internal",
            "other.internal",
            "nope.internal",
            "internal",
        ] {
            let answer = local(decide_host(&query(unknown, TYPE_A), &snap, "internal"));
            assert_eq!(rcode(&answer), RCODE_NXDOMAIN, "{unknown}");
        }
        // Nothing is passed on for the host: its own resolver handles every other name.
        let public = local(decide_host(
            &query("example.com", TYPE_A),
            &snap,
            "internal",
        ));
        assert_eq!(rcode(&public), RCODE_REFUSED);
        // A disabled agent is not found either.
        snap.agents[0].status = AgentStatus::Disabled;
        let gone = local(decide_host(
            &query("node1.internal", TYPE_A),
            &snap,
            "internal",
        ));
        assert_eq!(rcode(&gone), RCODE_NXDOMAIN);
    }

    #[test]
    fn an_agent_resolves_the_named_agents_it_links_to_and_nothing_else() {
        let mut snap = snap();
        let link = |from: &str, to: &str| crate::model::AgentLink {
            from_agent_id: format!("id-{from}"),
            to_agent_id: format!("id-{to}"),
            access: VpnAccess::Server,
        };
        // node1 links to node2 (names on) and other (names off); nobody links to node1.
        snap.agent_links = vec![link("node1", "node2"), link("node1", "other")];
        let names: Vec<&str> = link_agents(&snap, "id-node1")
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(names, ["node2"]);
        assert!(
            link_agents(&snap, "id-node2").is_empty(),
            "links are one way"
        );
        let agents = link_agents(&snap, "id-node1");
        let a = local(decide_only(
            &query("node2.internal", TYPE_A),
            &agents,
            "internal",
        ));
        assert_eq!(&a[a.len() - 4..], &[10, 13, 0, 3]);
        for unknown in ["node1.internal", "other.internal"] {
            let answer = local(decide_only(&query(unknown, TYPE_A), &agents, "internal"));
            assert_eq!(rcode(&answer), RCODE_NXDOMAIN, "{unknown}");
        }
        let public = local(decide_only(
            &query("example.com", TYPE_A),
            &agents,
            "internal",
        ));
        assert_eq!(
            rcode(&public),
            RCODE_REFUSED,
            "nothing is resolved for the agent's host"
        );
        // The server lets node1 ask on the name server's port, and nobody else.
        let config = Config {
            server_ipv4: Ipv4Addr::new(10, 13, 0, 1),
            ..Config::default()
        };
        let rules = server_rules(&config, &snap).input;
        assert!(rules.contains("ip saddr 10.13.0.2 ip daddr 10.13.0.1 meta l4proto { tcp, udp } th dport 53053 accept"), "{rules}");
        assert!(
            !rules.contains("ip saddr 10.13.0.3 ") && !rules.contains("ip saddr 10.13.0.4 "),
            "{rules}"
        );
        // A disabled target is no longer named.
        snap.agents[1].status = AgentStatus::Disabled;
        assert!(link_agents(&snap, "id-node1").is_empty());
    }

    #[test]
    fn an_agent_tells_its_host_the_names_and_doctor_reads_what_the_host_did() {
        let names = crate::model::AgentNames {
            server: "10.13.0.1:53053".parse().unwrap(),
            domains: vec!["nas.internal".into(), "pi.internal".into()],
        };
        let text = agent_host_names_text("rift0", "10.13.0.1:53053".parse().unwrap(), Some(&names));
        assert!(
            text.contains(
                "\nserver=10.13.0.1:53053\ninterface=rift0\ndomains=nas.internal pi.internal\n"
            ),
            "{text}"
        );
        let none = agent_host_names_text("rift0", "10.13.0.1:53053".parse().unwrap(), None);
        assert!(none.ends_with("\ndomains=\n"), "{none}");

        let dir = std::env::temp_dir().join(format!("rift-agent-host-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            agent_host_names_note(&dir),
            None,
            "nothing wanted, nothing installed"
        );
        write_host_names(&dir, &text).unwrap();
        let (fine, note) = agent_host_names_note(&dir).unwrap();
        assert!(!fine && note.contains("deploy/install-cli"), "{note}");
        let status = |body: &str| std::fs::write(dir.join("host-names.status"), body).unwrap();
        status("state=active\ndetail=\ndomains=nas.internal\nlookup=ok\n");
        assert!(agent_host_names_note(&dir)
            .unwrap()
            .1
            .contains("being applied"));
        status("state=active\ndetail=\ndomains=nas.internal pi.internal\nlookup=ok\n");
        assert_eq!(
            agent_host_names_note(&dir).unwrap(),
            (true, "nas.internal, pi.internal ✓".into())
        );
        status("state=active\ndetail=\ndomains=nas.internal pi.internal\nlookup=missing\n");
        assert!(agent_host_names_note(&dir)
            .unwrap()
            .1
            .contains("libnss-resolve"));
        status("state=unavailable\ndetail=systemd-resolved does not run on this host\ndomains=\nlookup=missing\n");
        assert_eq!(
            agent_host_names_note(&dir).unwrap(),
            (
                false,
                "not possible here: systemd-resolved does not run on this host".into()
            )
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_host_names_file_lists_each_name_once_and_is_written_only_on_change() {
        let mut snap = snap();
        let config = Config {
            server_ipv4: Ipv4Addr::new(10, 13, 0, 1),
            ..Config::default()
        };
        let empty = host_names_text(&config, &snap);
        assert!(empty.contains("\nserver=10.13.0.1:53053\n"), "{empty}");
        assert!(empty.contains("\ninterface=rift0\n"), "{empty}");
        assert!(
            empty.ends_with("\ndomains=\n"),
            "no name, no routing domain: {empty}"
        );
        let host = |agent: &str, access| crate::model::HostGrant {
            agent_id: format!("id-{agent}"),
            access,
        };
        snap.host_grants = vec![
            host("node2", VpnAccess::Server),
            host("node1", VpnAccess::Full),
            host("node1", VpnAccess::Server),
            host("other", VpnAccess::Server),
        ];
        let text = host_names_text(&config, &snap);
        assert!(
            text.ends_with("\ndomains=node1.internal node2.internal\n"),
            "sorted, once each, names on only: {text}"
        );
        let dir = tempfile::tempdir().unwrap();
        write_host_names(dir.path(), &text).unwrap();
        let path = dir.path().join(HOST_NAMES_FILE);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        let before = std::fs::metadata(&path).unwrap().modified().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        write_host_names(dir.path(), &text).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            before,
            "an unchanged list does not wake the host service"
        );
        write_host_names(&dir.path().join("missing"), &text).unwrap();
        assert!(!dir.path().join("missing").exists());
    }

    #[test]
    fn the_host_service_status_tells_per_agent_whether_its_name_works_on_the_vps() {
        let dir = tempfile::tempdir().unwrap();
        assert!(host_names_status(dir.path()).is_null(), "no host part");
        std::fs::write(
            dir.path().join("host-names.status"),
            "state=active\ndetail=\ndomains=pp.internal nas.internal\nlookup=ok\n",
        )
        .unwrap();
        let host = host_names_status(dir.path());
        assert_eq!(host["state"], "active");
        assert_eq!(
            host["domains"],
            serde_json::json!(["pp.internal", "nas.internal"])
        );
        let agent = |names: bool, grants: bool| {
            serde_json::json!({"dns_name": "pp.internal", "names": names,
                "host_grants": if grants { serde_json::json!([{"access": "server"}]) } else { serde_json::json!([]) }})
        };
        let note =
            |agent: &serde_json::Value, host: &serde_json::Value| host_name_note(agent, host);
        assert_eq!(
            note(&agent(true, false), &host),
            None,
            "no host grant, no line"
        );
        let (fine, text) = note(&agent(true, true), &host).unwrap();
        assert!(fine && text.starts_with("pp.internal ✓"), "{text}");
        let (fine, text) = note(&agent(false, true), &host).unwrap();
        assert!(!fine && text.contains("names off"), "{text}");
        let mut other = host.clone();
        other["lookup"] = "missing".into();
        assert!(note(&agent(true, true), &other)
            .unwrap()
            .1
            .contains("libnss-resolve"));
        other["domains"] = serde_json::json!([]);
        assert!(note(&agent(true, true), &other)
            .unwrap()
            .1
            .contains("being applied"));
        for (state, expected) in [
            ("off", "sudo rift host names on"),
            ("unavailable", "not possible here: no resolved"),
            ("error", "no resolved"),
        ] {
            let host = serde_json::json!({"state": state, "detail": "no resolved"});
            let (fine, text) = note(&agent(true, true), &host).unwrap();
            assert!(!fine && text.contains(expected), "{state}: {text}");
        }
        let (_, text) = note(&agent(true, true), &serde_json::Value::Null).unwrap();
        assert!(text.contains("deploy/install-cli"), "{text}");
    }

    #[test]
    fn other_suffixes_answer_the_agents_and_pass_on_public_names() {
        let snap = snap();
        let phone = &snap.vpn_peers[0];
        let a = local(decide_under(
            &query("node1.home.arpa", TYPE_A),
            &snap,
            phone,
            "home.arpa",
        ));
        assert_eq!(&a[a.len() - 4..], &[10, 13, 0, 2]);
        // Unknown names under any suffix go to the upstream.
        assert!(matches!(
            decide_under(
                &query("nothing.home.arpa", TYPE_A),
                &snap,
                phone,
                "home.arpa"
            ),
            Reply::Forward
        ));
        // A domain of your own: the agent is answered here, every other name goes on, so the
        // public www.example.net keeps working while the tunnel is on.
        let own = "home.example.net";
        let a = local(decide_under(
            &query("node1.home.example.net", TYPE_A),
            &snap,
            phone,
            own,
        ));
        assert_eq!(&a[a.len() - 4..], &[10, 13, 0, 2]);
        for name in [
            "nothing.home.example.net",
            "home.example.net",
            "www.example.net",
        ] {
            assert!(
                matches!(
                    decide_under(&query(name, TYPE_A), &snap, phone, own),
                    Reply::Forward
                ),
                "{name}"
            );
        }
        // The old suffix is an ordinary name then.
        assert!(matches!(
            decide_under(&query("node1.internal", TYPE_A), &snap, phone, own),
            Reply::Forward
        ));
    }

    #[test]
    fn names_the_device_may_not_see_are_not_answered_here() {
        let snap = snap();
        let phone = &snap.vpn_peers[0];
        // node2 has names on, but the phone has no grant on it; other has names off. They go
        // to the upstream like any unknown name, which does not know them.
        for name in ["node2.internal", "other.internal", "nothing.internal"] {
            assert!(
                matches!(decide(&query(name, TYPE_A), &snap, phone), Reply::Forward),
                "{name}"
            );
        }
    }

    #[test]
    fn only_ipv4_is_answered_and_other_names_are_passed_on() {
        let snap = snap();
        let phone = &snap.vpn_peers[0];
        let aaaa = local(decide(&query("node1.internal", 28), &snap, phone));
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
        let mut response = query("node1.internal", TYPE_A);
        response[2] |= 0x80;
        assert_eq!(
            rcode(&local(decide(&response, &snap, phone))),
            RCODE_FORMERR
        );
        let mut update = query("node1.internal", TYPE_A);
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
    /// address is 127.0.0.1, and one of the host itself from the server's address 127.0.0.2.
    #[tokio::test]
    async fn the_server_answers_over_udp_and_tcp() {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(StateStore::open(&dir.path().join("state.db")).unwrap());
        let mut phone = peer("phone", 9);
        phone.ipv4 = Ipv4Addr::LOCALHOST;
        state
            .mutate("test", |x| {
                x.agents = vec![agent("node1", 2, true)];
                x.vpn_peers = vec![phone];
                x.vpn_grants = vec![port("phone", "node1", 3000)];
                x.host_grants = vec![crate::model::HostGrant {
                    agent_id: "id-node1".into(),
                    access: VpnAccess::Server,
                }];
                Ok(())
            })
            .unwrap();
        let server_ip = Ipv4Addr::new(127, 0, 0, 2);
        let config = Config {
            server_ipv4: server_ip,
            ..Config::default()
        };
        tokio::spawn(serve(config, state));
        let server: SocketAddr = (server_ip, DNS_PORT).into();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let q = query("node1.internal", TYPE_A);
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
        let q = query("NODE1.internal", TYPE_A);
        stream
            .write_all(&(q.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&q).await.unwrap();
        let n = stream.read_u16().await.unwrap() as usize;
        let mut answer = vec![0u8; n];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer[answer.len() - 4..], &[10, 13, 0, 2], "over TCP too");

        // The host itself: it asks from the server's own address.
        let host = UdpSocket::bind((server_ip, 0)).await.unwrap();
        host.send_to(&query("node1.internal", TYPE_A), server)
            .await
            .unwrap();
        let (n, _) = timeout(Duration::from_secs(2), host.recv_from(&mut buf))
            .await
            .expect("no answer for the host")
            .unwrap();
        assert_eq!(&buf[n - 4..n], &[10, 13, 0, 2], "the host resolves node1");
        host.send_to(&query("example.com", TYPE_A), server)
            .await
            .unwrap();
        let (n, _) = timeout(Duration::from_secs(2), host.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rcode(&buf[..n]), RCODE_REFUSED, "and nothing else");
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

    /// The ECS option in a message, if any: (family, source prefix, address bytes).
    fn ecs_of(packet: &[u8]) -> Option<(u16, u8, Vec<u8>)> {
        let list = records(packet)?;
        let &(_, typ, end, _) = list
            .iter()
            .find(|(_, typ, _, s)| *s == 2 && count(packet, *typ) == Some(41))?;
        let mut pos = typ + 10;
        while pos + 4 <= end {
            let (code, len) = (count(packet, pos)?, count(packet, pos + 2)?);
            if code == 8 {
                let family = count(packet, pos + 4)? as u16;
                return Some((
                    family,
                    packet[pos + 6],
                    packet[pos + 8..pos + 4 + len].to_vec(),
                ));
            }
            pos += 4 + len;
        }
        None
    }

    #[test]
    fn the_device_address_is_added_for_its_dns_server() {
        let device = Ipv4Addr::new(10, 14, 0, 2);
        // A query without EDNS: an OPT record with the address is added.
        let plain = query("example.com", TYPE_A);
        let (out, added) = with_client_subnet(&plain, device);
        assert!(added);
        assert_eq!(count(&out, 10), Some(1), "ARCOUNT");
        assert_eq!(ecs_of(&out), Some((1, 32, vec![10, 14, 0, 2])));
        assert_eq!(
            &out[..12][..10],
            &plain[..10],
            "the header is otherwise unchanged"
        );
        // The answer loses the OPT record RIFT added.
        assert_eq!(without_opt(&out), plain);
        // A query with EDNS and the client's own ECS: replaced, other options kept.
        let mut edns = plain.clone();
        edns[11] = 1;
        let cookie = [0u8, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let own_ecs = [0u8, 8, 0, 7, 0, 1, 24, 0, 192, 168, 1];
        let options: Vec<u8> = cookie.iter().chain(own_ecs.iter()).copied().collect();
        // Root name, type OPT, payload 4096, TTL 0, then the two-byte data length.
        edns.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0]);
        edns.push(options.len() as u8);
        edns.extend_from_slice(&options);
        let (out, added) = with_client_subnet(&edns, device);
        assert!(!added, "the client's OPT record stays");
        assert_eq!(count(&out, 10), Some(1));
        assert_eq!(ecs_of(&out), Some((1, 32, vec![10, 14, 0, 2])));
        assert!(
            out.windows(cookie.len()).any(|w| w == cookie),
            "other options are kept"
        );
        // Garbage goes out unchanged.
        assert_eq!(
            with_client_subnet(&[1, 2, 3], device),
            (vec![1, 2, 3], false)
        );
    }

    #[test]
    fn agent_names_become_dns_labels() {
        assert_eq!(vpn::dns_label("Node1").as_deref(), Some("node1"));
        assert_eq!(
            vpn::dns_label("home_server").as_deref(),
            Some("home-server")
        );
        assert_eq!(vpn::dns_label("-x"), None);
        assert_eq!(vpn::dns_label(&"a".repeat(64)), None);
    }
}
