//! Private VPN access. Roaming devices join the VPS's `rift0` as extra WireGuard peers and
//! reach only what a grant names: an agent's own tunnel address, or a named network behind
//! it. Everything here is pure: it turns the snapshot into nftables text and client files.
//! `net.rs` applies the result.
//!
//! Trust boundary: both ends authorise by the peer's VPN source address. The agent trusts
//! the VPS to deliver only traffic from the right peer, so a compromised VPS can forge an
//! allowed source address. Stronger isolation needs end-to-end authentication between the
//! device and the agent, which this design does not provide.
//!
//! Internet exit: a device with `Exit::Server` sends everything through the VPS, which
//! masquerades it. A device with `Exit::Agent` runs a second WireGuard tunnel to the agent's
//! `rift-exit` interface, carried inside the agent's tunnel to the VPS by an ordinary UDP
//! forward, so the VPS only relays ciphertext and the agent masquerades the traffic.

use crate::model::*;
use anyhow::{ensure, Context, Result};
use ipnet::{Ipv4Net, Ipv6Net};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// Name of the agent's second WireGuard interface; fixed, at most 15 characters.
pub const EXIT_INTERFACE: &str = "rift-exit";
/// Bytes a second WireGuard tunnel inside the first one costs: IPv6 + UDP + WireGuard headers.
pub const EXIT_OVERHEAD: u16 = 80;

/// The address pools RIFT hands out. An internet exit never leads into them.
#[derive(Clone, Copy, Debug)]
pub struct Pools {
    pub tunnel4: Ipv4Net,
    pub tunnel6: Ipv6Net,
    pub vpn4: Ipv4Net,
    pub vpn6: Ipv6Net,
}
impl Pools {
    pub fn of(config: &crate::config::Config) -> Self {
        Self {
            tunnel4: config.ipv4_pool,
            tunnel6: config.ipv6_pool,
            vpn4: config.vpn_pool,
            vpn6: config.vpn_pool6,
        }
    }
    fn nft4(&self) -> String {
        format!("{{ {}, {}, 169.254.0.0/16 }}", self.tunnel4, self.vpn4)
    }
    fn nft6(&self) -> String {
        format!("{{ {}, {}, fe80::/10 }}", self.tunnel6, self.vpn6)
    }
}

/// The address of the exit interface on every agent: the first host of each VPN pool. Devices
/// never get these.
pub fn exit_gateway(pool: Ipv4Net, pool6: Ipv6Net) -> (Ipv4Addr, Ipv6Addr) {
    (
        pool.hosts().next().expect("a VPN pool has hosts"),
        Ipv6Addr::from(u128::from(pool6.network()) + 1),
    )
}

/// A grant whose peer is enabled and whose agent is active.
pub struct Effective<'a> {
    pub peer: &'a VpnPeer,
    pub agent: &'a AgentRecord,
    pub access: &'a VpnAccess,
}

/// nftables text for the places where VPN rules must sit ahead of the final drops.
#[derive(Default)]
pub struct Rules {
    pub input: String,
    pub forward: String,
    /// Rules for the `postrouting_nat` chain, which the renderer adds when this is not
    /// empty. Empty unless a grant asks for SNAT or an internet exit masquerades.
    pub nat: String,
}

pub fn effective(snap: &StateSnapshot) -> Vec<Effective<'_>> {
    snap.vpn_grants
        .iter()
        .filter_map(|grant| {
            let peer = snap
                .vpn_peers
                .iter()
                .find(|p| p.name == grant.peer && p.enabled)?;
            let agent = snap
                .agents
                .iter()
                .find(|a| a.id == grant.agent_id && a.status == AgentStatus::Active)?;
            Some(Effective {
                peer,
                agent,
                access: &grant.access,
            })
        })
        .collect()
}

/// Networks the VPS must route to, and accept packets from, this agent.
pub fn agent_subnets(effective: &[Effective<'_>], agent_id: &str) -> BTreeSet<Ipv4Net> {
    effective
        .iter()
        .filter(|e| e.agent.id == agent_id)
        .filter_map(|e| match e.access {
            VpnAccess::Subnet { net, .. } => Some(*net),
            _ => None,
        })
        .collect()
}

/// Enabled devices whose internet exit is the VPS.
pub fn server_exit_peers(snap: &StateSnapshot) -> Vec<&VpnPeer> {
    snap.vpn_peers
        .iter()
        .filter(|p| p.enabled && p.exit == Exit::Server)
        .collect()
}

/// Enabled devices whose internet exit is this agent (given by ID).
pub fn agent_exit_peers<'a>(snap: &'a StateSnapshot, agent_id: &str) -> Vec<&'a VpnPeer> {
    snap.vpn_peers
        .iter()
        .filter(|p| p.enabled && matches!(&p.exit, Exit::Agent(id) if id == agent_id))
        .collect()
}

/// What an active agent is asked to run for the devices that exit through it.
pub fn agent_exit_policy(
    snap: &StateSnapshot,
    agent_id: &str,
    pool: Ipv4Net,
    pool6: Ipv6Net,
) -> Option<ExitPolicy> {
    let agent = snap
        .agents
        .iter()
        .find(|a| a.id == agent_id && a.status == AgentStatus::Active)?;
    let peers = agent_exit_peers(snap, agent_id);
    if peers.is_empty() {
        return None;
    }
    let (gateway_v4, gateway_v6) = exit_gateway(pool, pool6);
    Some(ExitPolicy {
        listen_port: agent.exit_port?,
        gateway_v4,
        gateway_v6,
        peers: peers
            .into_iter()
            .map(|p| ExitPeer {
                public_key: p.public_key.clone(),
                ipv4: p.ipv4,
                ipv6: p.ipv6,
            })
            .collect(),
    })
}

/// Why the exit of `peer` does not work (yet), if it does not: `refused` when the agent will
/// not offer it, `waiting` while the agent has not reported what devices need.
pub fn exit_problem(snap: &StateSnapshot, peer: &VpnPeer) -> Option<(&'static str, String)> {
    let Exit::Agent(id) = &peer.exit else {
        return None;
    };
    let Some(agent) = snap.agents.iter().find(|a| a.id == *id) else {
        return Some(("refused", "the agent no longer exists".into()));
    };
    if agent.status != AgentStatus::Active {
        return Some(("waiting", format!("agent {} is not active", agent.name)));
    }
    if let Some(why) = agent.limits.as_ref().and_then(AgentLimits::refuse_exit) {
        return Some(("refused", why));
    }
    if agent.exit.is_none() {
        return Some((
            "waiting",
            format!(
                "agent {} has not reported its exit key yet; is RIFT_AGENT_ALLOW_EXIT=true set on it and is it online?",
                agent.name
            ),
        ));
    }
    if agent.exit_port.is_none() {
        return Some((
            "waiting",
            format!("no exit port is assigned to agent {} yet", agent.name),
        ));
    }
    None
}

pub fn agent_rules(snap: &StateSnapshot, agent_id: &str) -> Vec<AgentVpnRule> {
    effective(snap)
        .into_iter()
        .filter(|e| e.agent.id == agent_id)
        .map(|e| AgentVpnRule {
            source: e.peer.ipv4,
            access: e.access.clone(),
        })
        .collect()
}

/// The accesses the `vpn allow`/`deny` selectors name, in CLI flag terms.
pub fn accesses(
    server: bool,
    full: bool,
    ports: &[String],
    subnets: &[Ipv4Net],
    snat: bool,
) -> Result<Vec<VpnAccess>> {
    let mut out = Vec::new();
    if server {
        out.push(VpnAccess::Server);
    }
    if full {
        out.push(VpnAccess::Full);
    }
    for spec in ports {
        ensure!(
            !spec.contains(':'),
            "{spec:?} must be PORT/tcp, PORT/udp or PORT/both"
        );
        for plan in parse_forward_specs(std::slice::from_ref(spec))? {
            ensure!(
                plan.on.is_none(),
                "{spec:?}: /v4, /v6 and /all apply only to forwards"
            );
            out.push(VpnAccess::Port {
                protocol: plan.protocol,
                ports: plan.listen,
            });
        }
    }
    for net in subnets {
        out.push(VpnAccess::Subnet { net: *net, snat });
    }
    Ok(out)
}

pub fn validate_access(access: &VpnAccess) -> Result<()> {
    match access {
        VpnAccess::Port { ports, .. } => ports.validate(),
        VpnAccess::Subnet { net, .. } => {
            ensure!(
                net.addr() == net.network(),
                "subnet {net} has host bits set; write it as {}",
                net.trunc()
            );
            ensure!(
                net.prefix_len() >= 8 && net.addr().is_private(),
                "a subnet grant must be a private network of at least /8, such as 192.168.178.0/24"
            );
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Whether two accesses name the same target, so a repeated `allow` replaces rather than adds.
pub fn same_target(a: &VpnAccess, b: &VpnAccess) -> bool {
    match (a, b) {
        (VpnAccess::Subnet { net: x, .. }, VpnAccess::Subnet { net: y, .. }) => x == y,
        _ => a == b,
    }
}

fn destination(tunnel: Ipv4Addr, access: &VpnAccess) -> String {
    match access {
        VpnAccess::Subnet { net, .. } => net.to_string(),
        _ => tunnel.to_string(),
    }
}

// Keep meta l4proto before the port match, as the other renderers do.
fn protocols(access: &VpnAccess) -> String {
    match access {
        VpnAccess::Server => "meta l4proto { tcp, udp, icmp } ".into(),
        VpnAccess::Port { protocol, ports } => {
            format!("meta l4proto {protocol} {protocol} dport {ports} ")
        }
        VpnAccess::Full | VpnAccess::Subnet { .. } => String::new(),
    }
}

/// The match shared by the VPS forward chain, the agent chains and the UFW jump.
pub fn flow_match(source: Ipv4Addr, tunnel: Ipv4Addr, access: &VpnAccess) -> String {
    format!(
        "ip saddr {source} ip daddr {} {}",
        destination(tunnel, access),
        protocols(access)
    )
}

/// `ipv6_exit` says whether the VPS can carry IPv6 for devices that exit through it; without
/// it their IPv6 traffic is dropped, never sent out unmasqueraded.
pub fn server_rules(interface: &str, pools: Pools, ipv6_exit: bool, snap: &StateSnapshot) -> Rules {
    let mut rules = Rules::default();
    if !snap.vpn_peers.iter().any(|p| p.enabled) {
        return rules;
    }
    let (pool, pool6) = (pools.vpn4, pools.vpn6);
    // Peers may not talk to the VPS itself or to each other, whatever a grant says.
    rules.input = format!(
        "add rule inet rift input iifname \"{interface}\" ip saddr {pool} drop\n\
         add rule inet rift input iifname \"{interface}\" ip6 saddr {pool6} drop\n"
    );
    rules.forward = format!(
        "add rule inet rift forward iifname \"{interface}\" ip saddr {pool} ip daddr {pool} drop\n\
         add rule inet rift forward iifname \"{interface}\" ip6 saddr {pool6} ip6 daddr {pool6} drop\n"
    );
    for e in effective(snap) {
        let tunnel = e.agent.tunnel_ipv4;
        rules.forward.push_str(&format!(
            "add rule inet rift forward iifname \"{interface}\" oifname \"{interface}\" {}accept\n\
             add rule inet rift forward iifname \"{interface}\" oifname \"{interface}\" ip saddr {} ip daddr {} ct state established,related accept\n",
            flow_match(e.peer.ipv4, tunnel, e.access),
            destination(tunnel, e.access),
            e.peer.ipv4,
        ));
    }
    // Internet exit through the VPS. These accepts come before the final drops of the
    // renderer and leave out every RIFT pool, so a device still reaches no other device and
    // no agent beyond its grants.
    let (tunnel4, tunnel6) = (pools.nft4(), pools.nft6());
    for peer in server_exit_peers(snap) {
        let (v4, v6) = (peer.ipv4, peer.ipv6);
        rules.forward.push_str(&format!(
            "add rule inet rift forward iifname \"{interface}\" oifname != \"{interface}\" ip saddr {v4} ip daddr != {tunnel4} accept\n\
             add rule inet rift forward iifname != \"{interface}\" oifname \"{interface}\" ip daddr {v4} ct state established,related accept\n"
        ));
        rules.nat.push_str(&format!(
            "add rule inet rift postrouting_nat ip saddr {v4} oifname != \"{interface}\" masquerade\n"
        ));
        if ipv6_exit {
            rules.forward.push_str(&format!(
                "add rule inet rift forward iifname \"{interface}\" oifname != \"{interface}\" ip6 saddr {v6} ip6 daddr != {tunnel6} accept\n\
                 add rule inet rift forward iifname != \"{interface}\" oifname \"{interface}\" ip6 daddr {v6} ct state established,related accept\n"
            ));
            rules.nat.push_str(&format!(
                "add rule inet rift postrouting_nat ip6 saddr {v6} oifname != \"{interface}\" masquerade\n"
            ));
        } else {
            rules.forward.push_str(&format!(
                "add rule inet rift forward iifname \"{interface}\" ip6 saddr {v6} drop\n"
            ));
        }
    }
    rules
}

const PRIVATE_V4: &str = "{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4 }";
const PRIVATE_V6: &str = "{ ::/128, ::1/128, fc00::/7, fe80::/10, ff00::/8 }";

/// What the agent's `rift-exit` interface may do.
pub struct AgentExit<'a> {
    /// The tunnel to the VPS, which exit traffic must never use.
    pub tunnel: &'a str,
    pub peers: &'a [ExitPeer],
    /// Whether the agent host has a global IPv6 address. Without it the devices' IPv6 is
    /// dropped.
    pub ipv6: bool,
    /// Networks behind the agent the devices may reach, `RIFT_AGENT_ALLOW_SUBNETS`.
    pub subnets: &'a [Ipv4Net],
}

/// The agent's rules for devices exiting through it: masquerade towards the internet, nothing
/// towards private, local or RIFT networks except the allowed subnets, nothing to the agent
/// host itself.
pub fn agent_exit_rules(exit: &AgentExit<'_>) -> Rules {
    let (iface, tunnel) = (EXIT_INTERFACE, exit.tunnel);
    let out_ifaces = format!("{{ \"{iface}\", \"{tunnel}\" }}");
    let mut rules = Rules {
        input: format!("add rule inet rift input iifname \"{iface}\" drop\n"),
        ..Default::default()
    };
    for net in exit.subnets {
        rules.forward.push_str(&format!(
            "add rule inet rift forward iifname \"{iface}\" oifname != {out_ifaces} ip daddr {net} accept\n"
        ));
    }
    rules.forward.push_str(&format!(
        "add rule inet rift forward iifname \"{iface}\" ip daddr {PRIVATE_V4} drop\n\
         add rule inet rift forward iifname \"{iface}\" ip6 daddr {PRIVATE_V6} drop\n"
    ));
    for peer in exit.peers {
        let (v4, v6) = (peer.ipv4, peer.ipv6);
        rules.forward.push_str(&format!(
            "add rule inet rift forward iifname \"{iface}\" oifname != {out_ifaces} ip saddr {v4} accept\n"
        ));
        rules.nat.push_str(&format!(
            "add rule inet rift postrouting_nat iifname \"{iface}\" oifname != {out_ifaces} ip saddr {v4} masquerade\n"
        ));
        if exit.ipv6 {
            rules.forward.push_str(&format!(
                "add rule inet rift forward iifname \"{iface}\" oifname != {out_ifaces} ip6 saddr {v6} accept\n"
            ));
            rules.nat.push_str(&format!(
                "add rule inet rift postrouting_nat iifname \"{iface}\" oifname != {out_ifaces} ip6 saddr {v6} masquerade\n"
            ));
        }
    }
    // Whatever is left, including the IPv6 of a host without global IPv6, is dropped.
    rules.forward.push_str(&format!(
        "add rule inet rift forward iifname \"{iface}\" drop\n\
         add rule inet rift forward iifname != \"{iface}\" oifname \"{iface}\" ct state established,related accept\n\
         add rule inet rift forward oifname \"{iface}\" drop\n"
    ));
    rules
}

impl Rules {
    /// Appends the rules of `other` after these.
    pub fn merge(&mut self, other: Rules) {
        self.input.push_str(&other.input);
        self.forward.push_str(&other.forward);
        self.nat.push_str(&other.nat);
    }
}

pub fn agent_nft_rules(interface: &str, tunnel: Ipv4Addr, rules: &[AgentVpnRule]) -> Rules {
    let mut out = Rules::default();
    for rule in rules {
        let flow = flow_match(rule.source, tunnel, &rule.access);
        let (source, dest) = (rule.source, destination(tunnel, &rule.access));
        // Packets to the agent host itself (including its own LAN address) are INPUT.
        out.input.push_str(&format!(
            "add rule inet rift input iifname \"{interface}\" {flow}accept\n"
        ));
        if let VpnAccess::Subnet { snat, .. } = rule.access {
            out.forward.push_str(&format!(
                "add rule inet rift forward iifname \"{interface}\" oifname != \"{interface}\" {flow}accept\n\
                 add rule inet rift forward iifname != \"{interface}\" oifname \"{interface}\" ip saddr {dest} ip daddr {source} ct state established,related accept\n"
            ));
            if snat {
                out.nat.push_str(&format!(
                    "add rule inet rift postrouting_nat iifname \"{interface}\" oifname != \"{interface}\" {flow}masquerade\n"
                ));
            }
        }
    }
    out
}

/// What a device configuration needs besides the device itself.
pub struct ClientParams<'a> {
    pub server_public_key: &'a str,
    /// `RIFT_PUBLIC_ENDPOINT`, without a port.
    pub host: &'a str,
    pub wg_port: u16,
    pub mtu: u16,
    /// The VPS's tunnel address when the web panel is on, for devices that may open it.
    pub panel: Option<Ipv4Addr>,
    /// `RIFT_VPN_DNS`.
    pub dns: &'a [IpAddr],
    /// Whether the VPS can carry IPv6 for devices that exit through it.
    pub server_ipv6: bool,
}

/// `host:port`, with brackets around an IPv6 address.
pub fn host_port(host: &str, port: u16) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn dns_line(dns: &[IpAddr], ipv6: bool) -> Result<String> {
    let list: Vec<String> = dns
        .iter()
        .filter(|ip| ipv6 || ip.is_ipv4())
        .map(ToString::to_string)
        .collect();
    ensure!(
        !list.is_empty(),
        "RIFT_VPN_DNS has no IPv4 address for an exit without IPv6"
    );
    Ok(format!("DNS = {}\n", list.join(", ")))
}

/// WireGuard configuration for one device. Without an exit it is a split tunnel: only the
/// addresses the peer may reach. With one, everything goes through the exit.
pub fn client_config(
    snap: &StateSnapshot,
    peer: &VpnPeer,
    private_key: &str,
    p: &ClientParams<'_>,
) -> Result<String> {
    let address = format!("{}/32, {}/128", peer.ipv4, peer.ipv6);
    if let Exit::Agent(id) = &peer.exit {
        let agent = snap
            .agents
            .iter()
            .find(|a| a.id == *id)
            .context("the agent of this device's internet exit no longer exists")?;
        if let Some((_, why)) = exit_problem(snap, peer) {
            anyhow::bail!("{}: internet exit via {}: {why}", peer.name, agent.name);
        }
        let report = agent.exit.as_ref().context("exit key missing")?;
        let port = agent.exit_port.context("exit port missing")?;
        let mtu = p.mtu.saturating_sub(EXIT_OVERHEAD);
        ensure!(
            mtu >= 1280,
            "the MTU {} leaves less than 1280 bytes inside the exit tunnel; raise it",
            p.mtu
        );
        return Ok(format!(
            "# Internet exit via agent {name}. This profile carries all traffic through {name}'s\n\
             # connection; the web panel and other RIFT grants are not reachable with it.\n\
             [Interface]\nPrivateKey = {private_key}\nAddress = {address}\n{dns}MTU = {mtu}\n\n\
             [Peer]\nPublicKey = {key}\nEndpoint = {endpoint}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
            name = agent.name,
            dns = dns_line(p.dns, report.ipv6)?,
            key = report.public_key,
            endpoint = host_port(p.host, port),
        ));
    }
    let endpoint = host_port(p.host, p.wg_port);
    let (routes, dns) = if peer.exit == Exit::Server {
        (
            "0.0.0.0/0, ::/0".to_string(),
            dns_line(p.dns, p.server_ipv6)?,
        )
    } else {
        let mut routes = BTreeSet::new();
        if let Some(server) = p.panel.filter(|_| peer.panel) {
            routes.insert(format!("{server}/32"));
        }
        for grant in snap.vpn_grants.iter().filter(|g| g.peer == peer.name) {
            let Some(agent) = snap.agents.iter().find(|a| a.id == grant.agent_id) else {
                continue;
            };
            routes.insert(match &grant.access {
                VpnAccess::Subnet { net, .. } => net.to_string(),
                _ => format!("{}/32", agent.tunnel_ipv4),
            });
        }
        ensure!(
            !routes.is_empty(),
            "{} has no access yet; grant some with `rift vpn allow` or `rift panel allow`",
            peer.name
        );
        (
            routes.into_iter().collect::<Vec<_>>().join(", "),
            String::new(),
        )
    };
    Ok(format!(
        "[Interface]\nPrivateKey = {private_key}\nAddress = {address}\n{dns}MTU = {}\n\n[Peer]\nPublicKey = {}\nEndpoint = {endpoint}\nAllowedIPs = {routes}\nPersistentKeepalive = 25\n",
        p.mtu, p.server_public_key
    ))
}

/// The lowest unused host address of the pool. The first host is the exit gateway of the
/// agents and is never handed out.
pub fn allocate(pool: Ipv4Net, peers: &[VpnPeer]) -> Result<Ipv4Addr> {
    pool.hosts()
        .skip(1)
        .find(|ip| !peers.iter().any(|p| p.ipv4 == *ip))
        .ok_or_else(|| anyhow::anyhow!("VPN address pool is exhausted"))
}

/// The lowest unused address of the IPv6 pool, after the exit gateway.
pub fn allocate6(pool: Ipv6Net, peers: &[VpnPeer]) -> Result<Ipv6Addr> {
    let start = u128::from(pool.network());
    let end = u128::from(pool.broadcast());
    (start + 2..=end.min(start + 1_000_000))
        .map(Ipv6Addr::from)
        .find(|ip| !peers.iter().any(|p| p.ipv6 == *ip))
        .ok_or_else(|| anyhow::anyhow!("VPN IPv6 address pool is exhausted"))
}

/// The same QR code as an SVG image, for the web panel.
pub fn qr_svg(text: &str) -> Result<String> {
    use qrcode::{render::svg, QrCode};
    Ok(QrCode::new(text.as_bytes())?
        .render::<svg::Color>()
        .min_dimensions(264, 264)
        .quiet_zone(true)
        .build())
}

pub fn qr(text: &str) -> Result<String> {
    use qrcode::{render::unicode, QrCode};
    Ok(QrCode::new(text.as_bytes())?
        .render::<unicode::Dense1x2>()
        .quiet_zone(true)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(id: &str, last: u8) -> AgentRecord {
        AgentRecord {
            id: id.into(),
            name: id.into(),
            public_key: format!("key-{id}"),
            tunnel_ipv4: Ipv4Addr::new(10, 13, 0, last),
            tunnel_ipv6: format!("fd88:5249:4654::{last}").parse().unwrap(),
            status: AgentStatus::Active,
            attempt_id: id.into(),
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
    fn peer(name: &str, last: u8, enabled: bool) -> VpnPeer {
        VpnPeer {
            name: name.into(),
            public_key: format!("key-{name}"),
            ipv4: Ipv4Addr::new(10, 14, 0, last),
            enabled,
            created_at: 0,
            panel: false,
            ipv6: format!("fd88:5249:4655::{last}").parse().unwrap(),
            exit: Exit::None,
        }
    }
    fn grant(peer: &str, agent: &str, access: VpnAccess) -> VpnGrant {
        VpnGrant {
            peer: peer.into(),
            agent_id: agent.into(),
            access,
        }
    }
    fn snapshot() -> StateSnapshot {
        StateSnapshot {
            agents: vec![agent("home", 2)],
            vpn_peers: vec![peer("iphone", 2, true), peer("old", 3, false)],
            vpn_grants: vec![
                grant("iphone", "home", VpnAccess::Server),
                grant("old", "home", VpnAccess::Full),
            ],
            ..Default::default()
        }
    }
    fn pools() -> Pools {
        Pools {
            tunnel4: "10.13.0.0/24".parse().unwrap(),
            tunnel6: "fd88:5249:4654::/64".parse().unwrap(),
            vpn4: POOL.parse().unwrap(),
            vpn6: POOL6.parse().unwrap(),
        }
    }
    const POOL: &str = "10.14.0.0/24";
    const POOL6: &str = "fd88:5249:4655::/64";
    const DNS: [&str; 2] = ["9.9.9.9", "2620:fe::fe"];

    fn dns() -> Vec<IpAddr> {
        DNS.iter().map(|ip| ip.parse().unwrap()).collect()
    }
    fn params<'a>(
        dns: &'a [IpAddr],
        panel: Option<Ipv4Addr>,
        server_ipv6: bool,
    ) -> ClientParams<'a> {
        ClientParams {
            server_public_key: "PUB",
            host: "vps.example",
            wg_port: 51820,
            mtu: 1380,
            panel,
            dns,
            server_ipv6,
        }
    }
    fn config(snap: &StateSnapshot, name: &str, server_ipv6: bool) -> Result<String> {
        let dns = dns();
        let peer = snap.vpn_peers.iter().find(|p| p.name == name).unwrap();
        client_config(snap, peer, "SECRET", &params(&dns, None, server_ipv6))
    }
    /// An agent that offers an exit and has reported its key.
    fn exit_agent(ipv6: bool) -> AgentRecord {
        AgentRecord {
            limits: Some(AgentLimits {
                exit: true,
                ..Default::default()
            }),
            exit: Some(ExitReport {
                public_key: "EXITKEY".into(),
                listen_port: Some(51821),
                ipv6,
            }),
            exit_port: Some(51821),
            ..agent("home", 2)
        }
    }

    #[test]
    fn nothing_is_emitted_without_an_enabled_peer() {
        let mut snap = snapshot();
        snap.vpn_peers.retain(|p| !p.enabled);
        let rules = server_rules("rift0", pools(), true, &snap);
        assert!(rules.input.is_empty() && rules.forward.is_empty() && rules.nat.is_empty());
    }

    #[test]
    fn disabled_peers_and_inactive_agents_get_no_access() {
        let mut snap = snapshot();
        let rules = server_rules("rift0", pools(), true, &snap).forward;
        assert!(rules.contains("ip saddr 10.14.0.2 ip daddr 10.13.0.2"));
        assert!(!rules.contains("10.14.0.3 ip daddr"), "{rules}");
        snap.agents[0].status = AgentStatus::Disabled;
        assert!(effective(&snap).is_empty());
    }

    #[test]
    fn server_access_never_names_a_lan_and_peers_are_isolated() {
        let rules = server_rules("rift0", pools(), true, &snapshot());
        assert!(rules
            .input
            .contains("input iifname \"rift0\" ip saddr 10.14.0.0/24 drop"));
        // IPv6 devices reach the VPS as little as IPv4 ones, control port included.
        assert!(rules
            .input
            .contains("input iifname \"rift0\" ip6 saddr fd88:5249:4655::/64 drop"));
        let isolation = rules.forward.lines().next().unwrap();
        assert!(isolation.contains("ip saddr 10.14.0.0/24 ip daddr 10.14.0.0/24 drop"));
        assert!(rules
            .forward
            .contains("ip6 saddr fd88:5249:4655::/64 ip6 daddr fd88:5249:4655::/64 drop"));
        assert!(rules
            .forward
            .contains("meta l4proto { tcp, udp, icmp } accept"));
        assert!(!rules.forward.contains("192.168"));
        // Without an exit there is nothing to masquerade.
        assert!(rules.nat.is_empty());
    }

    #[test]
    fn port_grants_are_limited_to_one_protocol_and_range() {
        let rules = agent_nft_rules(
            "rift0",
            Ipv4Addr::new(10, 13, 0, 2),
            &[AgentVpnRule {
                source: Ipv4Addr::new(10, 14, 0, 2),
                access: VpnAccess::Port {
                    protocol: Protocol::Tcp,
                    ports: "8000-8010".parse().unwrap(),
                },
            }],
        );
        assert!(rules.input.contains(
            "ip saddr 10.14.0.2 ip daddr 10.13.0.2 meta l4proto tcp tcp dport 8000-8010 accept"
        ));
        assert!(rules.forward.is_empty() && rules.nat.is_empty());
    }

    #[test]
    fn subnet_grants_forward_and_only_masquerade_on_request() {
        let net: Ipv4Net = "192.168.178.0/24".parse().unwrap();
        let rule = |snat| AgentVpnRule {
            source: Ipv4Addr::new(10, 14, 0, 2),
            access: VpnAccess::Subnet { net, snat },
        };
        let plain = agent_nft_rules("rift0", Ipv4Addr::new(10, 13, 0, 2), &[rule(false)]);
        assert!(plain
            .forward
            .contains("ip saddr 10.14.0.2 ip daddr 192.168.178.0/24 accept"));
        assert!(plain.forward.contains(
            "ip saddr 192.168.178.0/24 ip daddr 10.14.0.2 ct state established,related accept"
        ));
        assert!(plain.nat.is_empty());
        let natted = agent_nft_rules("rift0", Ipv4Addr::new(10, 13, 0, 2), &[rule(true)]);
        assert!(natted
            .nat
            .contains("ip saddr 10.14.0.2 ip daddr 192.168.178.0/24 masquerade"));
    }

    #[test]
    fn client_config_is_split_tunnel_and_dual_stack() {
        let mut snap = snapshot();
        snap.vpn_grants.push(grant(
            "iphone",
            "home",
            VpnAccess::Subnet {
                net: "192.168.178.0/24".parse().unwrap(),
                snat: false,
            },
        ));
        let dns = dns();
        let text = client_config(
            &snap,
            &snap.vpn_peers[0],
            "SECRET",
            &params(&dns, Some(Ipv4Addr::new(10, 13, 0, 1)), true),
        )
        .unwrap();
        assert!(
            text.contains("Address = 10.14.0.2/32, fd88:5249:4655::2/128\n"),
            "{text}"
        );
        assert!(text.contains("Endpoint = vps.example:51820\n"));
        assert!(text.contains("AllowedIPs = 10.13.0.2/32, 192.168.178.0/24\n"));
        assert!(
            !text.contains("0.0.0.0/0") && !text.contains("DNS"),
            "{text}"
        );
        let new = peer("new", 9, true);
        assert!(client_config(&snap, &new, "k", &params(&dns, None, true)).is_err());
    }

    #[test]
    fn a_panel_device_routes_only_the_vps_tunnel_address() {
        let snap = snapshot();
        let mut admin = peer("laptop", 9, true);
        admin.panel = true;
        let dns = dns();
        let server = Some(Ipv4Addr::new(10, 13, 0, 1));
        let text = client_config(&snap, &admin, "k", &params(&dns, server, false)).unwrap();
        assert!(text.contains("AllowedIPs = 10.13.0.1/32\n"), "{text}");
        // Panel switched off on the VPS: the device has nothing to route.
        assert!(client_config(&snap, &admin, "k", &params(&dns, None, false)).is_err());
        // Without the flag the server address is never routed.
        assert!(
            client_config(&snap, &snap.vpn_peers[0], "k", &params(&dns, server, false))
                .unwrap()
                .contains("AllowedIPs = 10.13.0.2/32\n")
        );
    }

    #[test]
    fn a_server_exit_routes_everything_and_takes_dns_for_the_families_it_carries() {
        let mut snap = snapshot();
        snap.vpn_peers[0].exit = Exit::Server;
        // No grant is needed for an exit, and the VPS has IPv6: both DNS families.
        snap.vpn_grants.clear();
        let text = config(&snap, "iphone", true).unwrap();
        assert!(text.contains("AllowedIPs = 0.0.0.0/0, ::/0\n"), "{text}");
        assert!(text.contains("DNS = 9.9.9.9, 2620:fe::fe\n"), "{text}");
        assert!(text.contains("Endpoint = vps.example:51820\n"));
        assert!(text.contains("PublicKey = PUB\n") && text.contains("MTU = 1380\n"));
        // The VPS has no IPv6: ::/0 stays (so IPv6 dead-ends), but no IPv6 resolver is used.
        let text = config(&snap, "iphone", false).unwrap();
        assert!(text.contains("AllowedIPs = 0.0.0.0/0, ::/0\n"), "{text}");
        assert!(
            text.contains("DNS = 9.9.9.9\n") && !text.contains("2620"),
            "{text}"
        );
        // A resolver list without any IPv4 address cannot serve an IPv4-only exit.
        let only6: Vec<IpAddr> = vec!["2620:fe::fe".parse().unwrap()];
        let device = &snap.vpn_peers[0];
        assert!(client_config(&snap, device, "k", &params(&only6, None, false)).is_err());
    }

    #[test]
    fn an_agent_exit_is_a_second_tunnel_to_the_agent() {
        let mut snap = snapshot();
        snap.agents[0] = exit_agent(true);
        snap.vpn_peers[0].exit = Exit::Agent("home".into());
        let text = config(&snap, "iphone", false).unwrap();
        // The agent's key and the exit port, on the VPS address; not the VPS's key and port.
        assert!(text.contains("PublicKey = EXITKEY\n"), "{text}");
        assert!(text.contains("Endpoint = vps.example:51821\n"), "{text}");
        assert!(!text.contains("PUB\n") && !text.contains("51820"), "{text}");
        assert!(text.contains("AllowedIPs = 0.0.0.0/0, ::/0\n"));
        assert!(
            text.contains("Address = 10.14.0.2/32, fd88:5249:4655::2/128\n"),
            "{text}"
        );
        // 80 bytes of the VPS tunnel's MTU go to the outer WireGuard headers.
        assert!(text.contains("MTU = 1300\n"), "{text}");
        // The agent has IPv6, so the IPv6 resolver is used whatever the VPS has.
        assert!(text.contains("DNS = 9.9.9.9, 2620:fe::fe\n"), "{text}");
        assert!(text.starts_with("# Internet exit via agent home"), "{text}");
        assert!(text.contains("web panel and other RIFT grants are not reachable"));
        // An agent without global IPv6 leaves the IPv6 resolver out, even if the VPS has one.
        snap.agents[0] = exit_agent(false);
        let text = config(&snap, "iphone", true).unwrap();
        assert!(
            text.contains("DNS = 9.9.9.9\n") && !text.contains("2620"),
            "{text}"
        );
        // IPv6 addresses in the endpoint host are bracketed.
        let dns = dns();
        let mut p = params(&dns, None, false);
        p.host = "2001:db8::1";
        let v6 = client_config(&snap, &snap.vpn_peers[0], "k", &p).unwrap();
        assert!(v6.contains("Endpoint = [2001:db8::1]:51821\n"), "{v6}");
    }

    #[test]
    fn an_agent_exit_explains_why_there_is_no_configuration_yet() {
        let mut snap = snapshot();
        snap.vpn_peers[0].exit = Exit::Agent("home".into());
        // Before the agent reported anything.
        let error = config(&snap, "iphone", true).unwrap_err().to_string();
        assert!(error.contains("not reported its exit key"), "{error}");
        assert!(error.contains("RIFT_AGENT_ALLOW_EXIT=true"), "{error}");
        let waiting = exit_problem(&snap, &snap.vpn_peers[0]).unwrap();
        assert_eq!(waiting.0, "waiting");
        // The agent reported, but its owner does not allow exits.
        snap.agents[0] = exit_agent(true);
        snap.agents[0].limits = Some(AgentLimits::default());
        let error = config(&snap, "iphone", true).unwrap_err().to_string();
        assert!(error.contains("does not offer an internet exit"), "{error}");
        assert_eq!(
            exit_problem(&snap, &snap.vpn_peers[0]).unwrap().0,
            "refused"
        );
        // No port assigned yet.
        snap.agents[0] = exit_agent(true);
        snap.agents[0].exit_port = None;
        assert!(config(&snap, "iphone", true)
            .unwrap_err()
            .to_string()
            .contains("no exit port"));
        // Everything in place.
        snap.agents[0] = exit_agent(true);
        assert!(exit_problem(&snap, &snap.vpn_peers[0]).is_none());
        // A tunnel MTU too small for the inner tunnel is an error, not a broken profile.
        let dns = dns();
        let mut p = params(&dns, None, true);
        p.mtu = 1340;
        assert!(client_config(&snap, &snap.vpn_peers[0], "k", &p).is_err());
    }

    #[test]
    fn server_exit_rules_masquerade_and_leave_out_every_rift_network() {
        let mut snap = snapshot();
        snap.vpn_peers[0].exit = Exit::Server;
        let rules = server_rules("rift0", pools(), true, &snap);
        let forward = &rules.forward;
        let tunnel4 = "{ 10.13.0.0/24, 10.14.0.0/24, 169.254.0.0/16 }";
        let tunnel6 = "{ fd88:5249:4654::/64, fd88:5249:4655::/64, fe80::/10 }";
        assert!(forward.contains(&format!(
            "forward iifname \"rift0\" oifname != \"rift0\" ip saddr 10.14.0.2 ip daddr != {tunnel4} accept"
        )), "{forward}");
        assert!(forward.contains(&format!(
            "forward iifname \"rift0\" oifname != \"rift0\" ip6 saddr fd88:5249:4655::2 ip6 daddr != {tunnel6} accept"
        )), "{forward}");
        // Replies come back, but only for connections the device opened.
        assert!(forward.contains(
            "forward iifname != \"rift0\" oifname \"rift0\" ip daddr 10.14.0.2 ct state established,related accept"
        ));
        assert!(forward.contains(
            "forward iifname != \"rift0\" oifname \"rift0\" ip6 daddr fd88:5249:4655::2 ct state established,related accept"
        ));
        // Masquerade IPv4 and, because the VPS has IPv6, IPv6.
        assert!(rules
            .nat
            .contains("postrouting_nat ip saddr 10.14.0.2 oifname != \"rift0\" masquerade"));
        assert!(rules.nat.contains(
            "postrouting_nat ip6 saddr fd88:5249:4655::2 oifname != \"rift0\" masquerade"
        ));
        // The isolation rules come first; the exit accepts never name another device's address.
        assert!(forward.lines().next().unwrap().ends_with("drop"));
        assert!(
            !forward.contains("10.14.0.3"),
            "the disabled device gets nothing"
        );
        // The grant of the device is still there beside its exit.
        assert!(forward.contains("ip saddr 10.14.0.2 ip daddr 10.13.0.2"));
    }

    #[test]
    fn without_server_ipv6_the_devices_ipv6_is_dropped_and_not_masqueraded() {
        let mut snap = snapshot();
        snap.vpn_peers[0].exit = Exit::Server;
        let rules = server_rules("rift0", pools(), false, &snap);
        assert!(rules
            .forward
            .contains("forward iifname \"rift0\" ip6 saddr fd88:5249:4655::2 drop"));
        assert!(!rules.forward.contains("ip6 daddr !="), "{}", rules.forward);
        assert!(!rules.nat.contains("ip6"), "{}", rules.nat);
        assert!(rules.nat.contains("ip saddr 10.14.0.2"));
        // Only exit devices get these rules.
        snap.vpn_peers[0].exit = Exit::None;
        let none = server_rules("rift0", pools(), false, &snap);
        assert!(none.nat.is_empty() && !none.forward.contains("masquerade"));
        assert!(!none.forward.contains("ip6 saddr fd88:5249:4655::2 drop"));
        // A disabled device and an agent exit add nothing on the VPS.
        snap.vpn_peers[0].exit = Exit::Agent("home".into());
        assert!(server_rules("rift0", pools(), true, &snap).nat.is_empty());
        snap.vpn_peers[0].exit = Exit::Server;
        snap.vpn_peers[0].enabled = false;
        snap.vpn_peers[1].enabled = true;
        assert!(server_rules("rift0", pools(), true, &snap).nat.is_empty());
    }

    fn exit_peers() -> Vec<ExitPeer> {
        vec![ExitPeer {
            public_key: "k".into(),
            ipv4: Ipv4Addr::new(10, 14, 0, 2),
            ipv6: "fd88:5249:4655::2".parse().unwrap(),
        }]
    }
    fn agent_exit(ipv6: bool, subnets: &[Ipv4Net]) -> Rules {
        agent_exit_rules(&AgentExit {
            tunnel: "rift0",
            peers: &exit_peers(),
            ipv6,
            subnets,
        })
    }

    #[test]
    fn agent_exit_masquerades_and_keeps_the_devices_out_of_private_networks() {
        let rules = agent_exit(true, &[]);
        let forward = &rules.forward;
        let out = "oifname != { \"rift-exit\", \"rift0\" }";
        assert!(
            forward.contains(&format!(
                "forward iifname \"rift-exit\" {out} ip saddr 10.14.0.2 accept"
            )),
            "{forward}"
        );
        assert!(forward.contains(&format!(
            "forward iifname \"rift-exit\" {out} ip6 saddr fd88:5249:4655::2 accept"
        )));
        assert!(rules.nat.contains(&format!(
            "postrouting_nat iifname \"rift-exit\" {out} ip saddr 10.14.0.2 masquerade"
        )));
        assert!(rules.nat.contains("ip6 saddr fd88:5249:4655::2 masquerade"));
        for private in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "100.64.0.0/10",
            "169.254.0.0/16",
            "127.0.0.0/8",
            "fc00::/7",
            "fe80::/10",
        ] {
            let line = forward
                .lines()
                .find(|l| l.contains(private))
                .unwrap_or_else(|| panic!("{private} is not blocked: {forward}"));
            assert!(line.contains("iifname \"rift-exit\"") && line.ends_with("drop"));
        }
        // The blocks come before the accepts, and everything else is dropped at the end.
        let at = |needle: &str| forward.find(needle).unwrap_or_else(|| panic!("{needle}"));
        assert!(at("10.0.0.0/8") < at("ip saddr 10.14.0.2 accept"));
        assert!(at("fc00::/7") < at("ip6 saddr fd88:5249:4655::2 accept"));
        assert!(at("ip saddr 10.14.0.2 accept") < at("iifname \"rift-exit\" drop"));
        // Replies in, nothing else; the agent host itself is closed to the devices.
        assert!(forward.contains(
            "forward iifname != \"rift-exit\" oifname \"rift-exit\" ct state established,related accept"
        ));
        assert!(forward.contains("forward oifname \"rift-exit\" drop"));
        assert_eq!(
            rules.input,
            "add rule inet rift input iifname \"rift-exit\" drop\n"
        );
    }

    #[test]
    fn allowed_subnets_are_the_only_private_networks_an_agent_exit_reaches() {
        let lan: Ipv4Net = "192.168.178.0/24".parse().unwrap();
        let rules = agent_exit(true, &[lan]);
        let forward = &rules.forward;
        let allow = forward.find("ip daddr 192.168.178.0/24 accept").unwrap();
        let block = forward.find("192.168.0.0/16").unwrap();
        assert!(
            allow < block,
            "the exception must precede the block:\n{forward}"
        );
        assert!(forward.contains("iifname \"rift-exit\" oifname != { \"rift-exit\", \"rift0\" } ip daddr 192.168.178.0/24 accept"));
        // Without the exception the network is covered by the block alone.
        assert!(!agent_exit(true, &[])
            .forward
            .contains("192.168.178.0/24 accept"));
    }

    #[test]
    fn an_agent_without_global_ipv6_drops_the_devices_ipv6() {
        let rules = agent_exit(false, &[]);
        assert!(!rules.forward.contains("ip6 saddr"), "{}", rules.forward);
        assert!(!rules.nat.contains("ip6"), "{}", rules.nat);
        assert!(rules.nat.contains("ip saddr 10.14.0.2 masquerade"));
        // The catch-all drop is what keeps the IPv6 packets from leaving.
        assert!(rules.forward.contains("forward iifname \"rift-exit\" drop"));
        let ipv6_block = rules
            .forward
            .lines()
            .position(|l| l.contains("fc00::/7"))
            .unwrap();
        let catch_all = rules
            .forward
            .lines()
            .position(|l| l.ends_with("iifname \"rift-exit\" drop"))
            .unwrap();
        assert!(ipv6_block < catch_all);
    }

    #[test]
    fn the_exit_policy_names_the_devices_and_the_gateway_addresses() {
        let mut snap = snapshot();
        snap.vpn_peers[0].exit = Exit::Agent("home".into());
        let pool: Ipv4Net = POOL.parse().unwrap();
        let pool6: Ipv6Net = POOL6.parse().unwrap();
        // The agent has no port yet: no policy.
        assert!(agent_exit_policy(&snap, "home", pool, pool6).is_none());
        snap.agents[0].exit_port = Some(51821);
        let policy = agent_exit_policy(&snap, "home", pool, pool6).unwrap();
        assert_eq!(policy.listen_port, 51821);
        assert_eq!(policy.gateway_v4, Ipv4Addr::new(10, 14, 0, 1));
        assert_eq!(
            policy.gateway_v6,
            "fd88:5249:4655::1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            policy.peers,
            [ExitPeer {
                public_key: "key-iphone".into(),
                ipv4: Ipv4Addr::new(10, 14, 0, 2),
                ipv6: "fd88:5249:4655::2".parse().unwrap(),
            }]
        );
        // A disabled device, another exit and an inactive agent are not part of it.
        snap.vpn_peers[0].enabled = false;
        assert!(agent_exit_policy(&snap, "home", pool, pool6).is_none());
        snap.vpn_peers[0].enabled = true;
        snap.vpn_peers[0].exit = Exit::Server;
        assert!(agent_exit_policy(&snap, "home", pool, pool6).is_none());
        snap.vpn_peers[0].exit = Exit::Agent("home".into());
        snap.agents[0].status = AgentStatus::Disabled;
        assert!(agent_exit_policy(&snap, "home", pool, pool6).is_none());
    }

    #[test]
    fn subnet_validation() {
        let net = |s: &str| VpnAccess::Subnet {
            net: s.parse().unwrap(),
            snat: false,
        };
        assert!(validate_access(&net("192.168.178.0/24")).is_ok());
        assert!(validate_access(&net("192.168.178.5/24")).is_err());
        assert!(validate_access(&net("0.0.0.0/0")).is_err());
        assert!(validate_access(&net("8.8.8.0/24")).is_err());
    }

    #[test]
    fn allocation_reuses_the_lowest_free_address_and_keeps_the_gateway() {
        let pool: Ipv4Net = POOL.parse().unwrap();
        // The first host is the exit gateway of the agents and is never a device.
        assert_eq!(allocate(pool, &[]).unwrap(), Ipv4Addr::new(10, 14, 0, 2));
        let peers = [peer("a", 2, true), peer("b", 4, true)];
        assert_eq!(allocate(pool, &peers).unwrap(), Ipv4Addr::new(10, 14, 0, 3));
        let full: Ipv4Net = "10.14.0.0/30".parse().unwrap();
        assert!(allocate(full, &[peer("a", 2, true)]).is_err());
    }

    #[test]
    fn ipv6_addresses_are_allocated_like_ipv4_ones() {
        let pool6: Ipv6Net = POOL6.parse().unwrap();
        let at = |n: u8| format!("fd88:5249:4655::{n}").parse::<Ipv6Addr>().unwrap();
        assert_eq!(allocate6(pool6, &[]).unwrap(), at(2));
        let peers = [peer("a", 2, true), peer("b", 4, true)];
        assert_eq!(allocate6(pool6, &peers).unwrap(), at(3));
        let full = [peer("a", 2, true), peer("b", 3, true)];
        let tiny: Ipv6Net = "fd88:5249:4655::/126".parse().unwrap();
        assert!(
            allocate6(tiny, &full).is_err(),
            "::0 and ::1 are not devices"
        );
        assert_eq!(
            exit_gateway("10.14.0.0/24".parse().unwrap(), pool6),
            (Ipv4Addr::new(10, 14, 0, 1), at(1))
        );
    }
}
