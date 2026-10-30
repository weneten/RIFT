//! Private VPN access. Roaming devices join the VPS's `rift0` as extra WireGuard peers and
//! reach only what a grant names: an agent's own tunnel address, or a named network behind
//! it. Everything here is pure: it turns the snapshot into nftables text and client files.
//! `net.rs` applies the result.
//!
//! Trust boundary: both ends authorise by the peer's VPN source address. The agent trusts
//! the VPS to deliver only traffic from the right peer, so a compromised VPS can forge an
//! allowed source address. Stronger isolation needs end-to-end authentication between the
//! device and the agent, which this design does not provide.

use crate::model::*;
use anyhow::{ensure, Result};
use ipnet::Ipv4Net;
use std::{collections::BTreeSet, net::Ipv4Addr};

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
    /// Starts with its own `add chain`; empty unless a grant asks for SNAT.
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

pub fn server_rules(interface: &str, pool: Ipv4Net, snap: &StateSnapshot) -> Rules {
    let mut rules = Rules::default();
    if !snap.vpn_peers.iter().any(|p| p.enabled) {
        return rules;
    }
    // Peers may not talk to the VPS itself or to each other, whatever a grant says.
    rules.input =
        format!("add rule inet rift input iifname \"{interface}\" ip saddr {pool} drop\n");
    rules.forward = format!(
        "add rule inet rift forward iifname \"{interface}\" ip saddr {pool} ip daddr {pool} drop\n"
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
    rules
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
                if out.nat.is_empty() {
                    out.nat = "add chain inet rift postrouting_nat { type nat hook postrouting priority srcnat; policy accept; }\n".into();
                }
                out.nat.push_str(&format!(
                    "add rule inet rift postrouting_nat iifname \"{interface}\" oifname != \"{interface}\" {flow}masquerade\n"
                ));
            }
        }
    }
    out
}

/// WireGuard configuration for one device. Split tunnel: only addresses the peer may reach.
pub fn client_config(
    snap: &StateSnapshot,
    peer: &VpnPeer,
    private_key: &str,
    server_public_key: &str,
    endpoint: &str,
    mtu: u16,
) -> Result<String> {
    let mut routes = BTreeSet::new();
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
        "{} has no access yet; grant some with `rift vpn allow`",
        peer.name
    );
    Ok(format!(
        "[Interface]\nPrivateKey = {private_key}\nAddress = {}/32\nMTU = {mtu}\n\n[Peer]\nPublicKey = {server_public_key}\nEndpoint = {endpoint}\nAllowedIPs = {}\nPersistentKeepalive = 25\n",
        peer.ipv4,
        routes.into_iter().collect::<Vec<_>>().join(", ")
    ))
}

/// The lowest unused host address of the pool.
pub fn allocate(pool: Ipv4Net, peers: &[VpnPeer]) -> Result<Ipv4Addr> {
    pool.hosts()
        .find(|ip| !peers.iter().any(|p| p.ipv4 == *ip))
        .ok_or_else(|| anyhow::anyhow!("VPN address pool is exhausted"))
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
        }
    }
    fn peer(name: &str, last: u8, enabled: bool) -> VpnPeer {
        VpnPeer {
            name: name.into(),
            public_key: format!("key-{name}"),
            ipv4: Ipv4Addr::new(10, 14, 0, last),
            enabled,
            created_at: 0,
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
    const POOL: &str = "10.14.0.0/24";

    #[test]
    fn nothing_is_emitted_without_an_enabled_peer() {
        let mut snap = snapshot();
        snap.vpn_peers.retain(|p| !p.enabled);
        let rules = server_rules("rift0", POOL.parse().unwrap(), &snap);
        assert!(rules.input.is_empty() && rules.forward.is_empty());
    }

    #[test]
    fn disabled_peers_and_inactive_agents_get_no_access() {
        let mut snap = snapshot();
        let rules = server_rules("rift0", POOL.parse().unwrap(), &snap).forward;
        assert!(rules.contains("ip saddr 10.14.0.2 ip daddr 10.13.0.2"));
        assert!(!rules.contains("10.14.0.3 ip daddr"), "{rules}");
        snap.agents[0].status = AgentStatus::Disabled;
        assert!(effective(&snap).is_empty());
    }

    #[test]
    fn server_access_never_names_a_lan_and_peers_are_isolated() {
        let rules = server_rules("rift0", POOL.parse().unwrap(), &snapshot());
        assert!(rules
            .input
            .contains("input iifname \"rift0\" ip saddr 10.14.0.0/24 drop"));
        let isolation = rules.forward.lines().next().unwrap();
        assert!(isolation.contains("ip saddr 10.14.0.0/24 ip daddr 10.14.0.0/24 drop"));
        assert!(rules
            .forward
            .contains("meta l4proto { tcp, udp, icmp } accept"));
        assert!(!rules.forward.contains("192.168"));
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
    fn client_config_is_split_tunnel() {
        let mut snap = snapshot();
        snap.vpn_grants.push(grant(
            "iphone",
            "home",
            VpnAccess::Subnet {
                net: "192.168.178.0/24".parse().unwrap(),
                snat: false,
            },
        ));
        let text = client_config(
            &snap,
            &snap.vpn_peers[0],
            "SECRET",
            "PUB",
            "vps.example:51820",
            1380,
        )
        .unwrap();
        assert!(text.contains("Address = 10.14.0.2/32"));
        assert!(text.contains("AllowedIPs = 10.13.0.2/32, 192.168.178.0/24\n"));
        assert!(!text.contains("0.0.0.0/0"));
        assert!(client_config(&snap, &peer("new", 9, true), "k", "p", "e", 1380).is_err());
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
    fn allocation_reuses_the_lowest_free_address() {
        let pool: Ipv4Net = POOL.parse().unwrap();
        assert_eq!(allocate(pool, &[]).unwrap(), Ipv4Addr::new(10, 14, 0, 1));
        let peers = [peer("a", 1, true), peer("b", 3, true)];
        assert_eq!(allocate(pool, &peers).unwrap(), Ipv4Addr::new(10, 14, 0, 2));
        let full: Ipv4Net = "10.14.0.0/30".parse().unwrap();
        assert!(allocate(full, &[peer("a", 1, true), peer("b", 2, true)]).is_err());
    }
}
