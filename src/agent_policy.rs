//! The agent's own limits on what the server may ask of it. A compromised server can send
//! any policy; the agent applies only the part its owner allowed in the environment.

use crate::model::{AgentLimits, AgentOutboundRule, AgentPolicy, AgentVpnRule, VpnAccess};
use std::net::Ipv4Addr;

/// Whether `rule` is a link from another agent (`rift link allow`): its source is an address
/// of the agents' tunnel network other than the server's. Without the server's address or the
/// tunnel network (a server before protocol 2) nothing counts as a link.
fn is_link(rule: &AgentVpnRule, policy: &AgentPolicy, server: Option<Ipv4Addr>) -> bool {
    server.is_some_and(|server| rule.source != server)
        && policy
            .tunnel_pool
            .is_some_and(|pool| pool.contains(&rule.source))
}

fn describe_access(access: &VpnAccess) -> String {
    match access {
        VpnAccess::Server => "the host".to_string(),
        VpnAccess::Full => "the host, all protocols".to_string(),
        VpnAccess::Port { protocol, ports } => format!("{ports}/{protocol}"),
        VpnAccess::Subnet { net, .. } => format!("subnet {net}"),
        VpnAccess::Dns => "DNS (53/both)".to_string(),
    }
}

/// A rule whose source is the server's tunnel address, or lies outside the VPN pool and is no
/// link, comes from the server itself: a host grant (`rift host allow`) or RIFT's name server
/// asking the agent's DNS server.
fn describe_rule(rule: &AgentVpnRule, policy: &AgentPolicy, server: Option<Ipv4Addr>) -> String {
    let what = describe_access(&rule.access);
    if is_link(rule, policy, server) {
        format!("link from the agent {} to {what}", rule.source)
    } else if Some(rule.source) == server
        || policy
            .vpn_pool
            .is_some_and(|pool| !pool.contains(&rule.source))
    {
        format!("access of the server host ({}) to {what}", rule.source)
    } else {
        format!("VPN grant for {} to {what}", rule.source)
    }
}

/// Why the agent does not open this link, as far as the policy alone tells: it must lead to
/// another address of a private tunnel network that holds the server, never into the VPN pool.
/// `Kernel::apply_agent` also checks that no network of the host overlaps it, so a server can
/// never route the agent's own LAN or anything else into the tunnel.
pub fn refuse_outbound(
    rule: &AgentOutboundRule,
    policy: &AgentPolicy,
    server: Option<Ipv4Addr>,
) -> Option<String> {
    let Some(pool) = policy.tunnel_pool else {
        return Some("the server sent no tunnel network".to_string());
    };
    let Some(server) = server else {
        return Some("the server's tunnel address is not known yet".to_string());
    };
    if !(8..=29).contains(&pool.prefix_len()) || !pool.network().is_private() {
        return Some(format!("{pool} is no private /8../29 tunnel network"));
    }
    if !pool.contains(&server) {
        return Some(format!(
            "the tunnel network {pool} does not hold the server's address {server}"
        ));
    }
    let destination = rule.destination;
    if !pool.contains(&destination) {
        return Some(format!(
            "{destination} lies outside the tunnel network {pool}"
        ));
    }
    if destination == server || destination == pool.network() || destination == pool.broadcast() {
        return Some(format!("{destination} is no agent address"));
    }
    if policy
        .vpn_pool
        .is_some_and(|vpn| vpn.contains(&destination))
    {
        return Some(format!("{destination} lies in the VPN pool"));
    }
    if matches!(rule.access, VpnAccess::Subnet { .. } | VpnAccess::Dns) {
        return Some("a link reaches only the other agent: server, full or a port".to_string());
    }
    None
}

/// Returns the part of `policy` the agent's limits permit, and one refusal text per dropped
/// entry. The server leaves refused entries out itself once it knows the limits, so refusals
/// normally only appear before the first sync or from a server that ignores them. `server` is
/// the server's tunnel address, which tells links from other agents apart from the server host.
pub fn restrict(
    policy: &AgentPolicy,
    limits: &AgentLimits,
    server: Option<Ipv4Addr>,
) -> (AgentPolicy, Vec<String>) {
    let mut refusals = Vec::new();
    let mut forwards = Vec::new();
    for f in &policy.forwards {
        match limits.refuse_forward(f) {
            None => forwards.push(f.clone()),
            Some(why) => refusals.push(format!(
                "forward {} to {}/{} refused: {why}",
                f.id, f.target_ports, f.protocol
            )),
        }
    }
    let mut vpn = Vec::new();
    for rule in &policy.vpn {
        let links = is_link(rule, policy, server)
            .then(|| limits.refuse_links())
            .flatten();
        match links.or_else(|| limits.refuse_access(&rule.access)) {
            None => vpn.push(rule.clone()),
            Some(why) => refusals.push(format!(
                "{} refused: {why}",
                describe_rule(rule, policy, server)
            )),
        }
    }
    let mut outbound = Vec::new();
    for rule in &policy.outbound {
        match limits
            .refuse_links()
            .or_else(|| refuse_outbound(rule, policy, server))
        {
            None => outbound.push(rule.clone()),
            Some(why) => refusals.push(format!(
                "link to the agent {} ({}) refused: {why}",
                rule.destination,
                describe_access(&rule.access)
            )),
        }
    }
    let exit = match (&policy.exit, limits.refuse_exit()) {
        (Some(_), Some(why)) => {
            refusals.push(format!("internet exit refused: {why}"));
            None
        }
        (exit, _) => exit.clone(),
    };
    (
        AgentPolicy {
            generation: policy.generation,
            forwards,
            vpn_pool: policy.vpn_pool,
            vpn,
            exit,
            tunnel_pool: policy.tunnel_pool,
            outbound,
        },
        refusals,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn links_policy() -> AgentPolicy {
        let mut p = policy(
            vec![],
            vec![
                AgentVpnRule {
                    source: Ipv4Addr::new(10, 13, 0, 3),
                    access: VpnAccess::Server,
                },
                AgentVpnRule {
                    source: Ipv4Addr::new(10, 13, 0, 1),
                    access: VpnAccess::Server,
                },
                rule(VpnAccess::Server),
            ],
        );
        p.vpn_pool = Some("10.14.0.0/24".parse().unwrap());
        p.tunnel_pool = Some("10.13.0.0/24".parse().unwrap());
        p.outbound = vec![AgentOutboundRule {
            destination: Ipv4Addr::new(10, 13, 0, 3),
            access: VpnAccess::Server,
        }];
        p
    }

    #[test]
    fn links_pass_unless_the_owner_turns_them_off_and_only_links() {
        let p = links_policy();
        let (out, refusals) = restrict_(&p, &cfg("", ""));
        assert!(refusals.is_empty(), "{refusals:?}");
        assert_eq!((out.vpn.len(), out.outbound.len()), (3, 1));
        assert_eq!(out.tunnel_pool, p.tunnel_pool);
        let mut closed = cfg("", "");
        closed.no_links = true;
        let (out, refusals) = restrict_(&p, &closed);
        // The link from 10.13.0.3 and the one to it go; the server host and the device stay.
        assert_eq!(
            out.vpn
                .iter()
                .map(|r| r.source.to_string())
                .collect::<Vec<_>>(),
            ["10.13.0.1", "10.14.0.2"]
        );
        assert!(out.outbound.is_empty());
        assert_eq!(refusals.len(), 2, "{refusals:?}");
        assert!(refusals[0].starts_with("link from the agent 10.13.0.3 to the host refused"));
        assert!(refusals[1].starts_with("link to the agent 10.13.0.3 (the host) refused"));
        assert!(refusals
            .iter()
            .all(|r| r.contains("RIFT_AGENT_ALLOW_LINKS=false")));
        // The target's ports apply to a link as to every grant.
        let (_, refusals) = restrict_(&p, &cfg("22/tcp", ""));
        assert!(
            refusals[0].starts_with("link from the agent 10.13.0.3"),
            "{refusals:?}"
        );
        assert!(refusals[1].starts_with("access of the server host (10.13.0.1)"));
        assert!(refusals[2].starts_with("VPN grant for 10.14.0.2"));
    }

    #[test]
    fn a_server_can_route_nothing_but_other_agents_into_the_tunnel() {
        let p = links_policy();
        let server = Some(Ipv4Addr::new(10, 13, 0, 1));
        let to = |destination: [u8; 4], access: VpnAccess| AgentOutboundRule {
            destination: destination.into(),
            access,
        };
        let ok = to([10, 13, 0, 3], VpnAccess::Full);
        assert_eq!(refuse_outbound(&ok, &p, server), None);
        for (rule, why) in [
            (
                to([192, 168, 178, 10], VpnAccess::Full),
                "outside the tunnel network",
            ),
            (
                to([8, 8, 8, 8], VpnAccess::Full),
                "outside the tunnel network",
            ),
            (to([10, 13, 0, 1], VpnAccess::Full), "no agent address"),
            (to([10, 13, 0, 0], VpnAccess::Full), "no agent address"),
            (to([10, 13, 0, 255], VpnAccess::Full), "no agent address"),
            (
                to([10, 13, 0, 3], subnet("192.168.178.0/24")),
                "only the other agent",
            ),
        ] {
            let got = refuse_outbound(&rule, &p, server).unwrap_or_default();
            assert!(got.contains(why), "{rule:?}: {got}");
        }
        assert!(refuse_outbound(&ok, &p, None).is_some(), "server unknown");
        let mut wide = p.clone();
        wide.tunnel_pool = Some("0.0.0.0/0".parse().unwrap());
        assert!(
            refuse_outbound(&to([192, 168, 1, 1], VpnAccess::Full), &wide, server)
                .unwrap()
                .contains("no private /8../29")
        );
        let mut public = p.clone();
        public.tunnel_pool = Some("203.0.113.0/24".parse().unwrap());
        assert!(refuse_outbound(&to([203, 0, 113, 5], VpnAccess::Full), &public, server).is_some());
        let mut elsewhere = p.clone();
        elsewhere.tunnel_pool = Some("192.168.178.0/24".parse().unwrap());
        assert!(refuse_outbound(
            &to([192, 168, 178, 10], VpnAccess::Full),
            &elsewhere,
            server
        )
        .unwrap()
        .contains("does not hold the server"));
        let mut overlapping = p.clone();
        overlapping.vpn_pool = Some("10.13.0.0/25".parse().unwrap());
        assert!(refuse_outbound(&ok, &overlapping, server)
            .unwrap()
            .contains("VPN pool"));
        let mut old_server = p;
        old_server.tunnel_pool = None;
        assert!(refuse_outbound(&ok, &old_server, server).is_some());
        // Without the server's address nothing counts as a link, so nothing is dropped as one.
        let mut closed = cfg("", "");
        closed.no_links = true;
        let (out, _) = restrict(&links_policy(), &closed, None);
        assert_eq!(out.vpn.len(), 3);
        assert!(out.outbound.is_empty());
    }
    use crate::{
        config::{parse_port_allow, parse_subnet_allow},
        model::{Family, Forward, ForwardMode, Ingress, PortRange, Protocol},
    };
    use std::net::Ipv4Addr;

    fn pr(a: u16, b: u16) -> PortRange {
        PortRange { start: a, end: b }
    }
    fn forward(id: u64, protocol: Protocol, target: PortRange, generation: u64) -> Forward {
        Forward {
            id,
            agent_id: "a".into(),
            listen_ip: "203.0.113.1".parse().unwrap(),
            listen_ports: target,
            target_ports: target,
            protocol,
            mode: ForwardMode::Transparent,
            ingress: Ingress::Public,
            target_family: Family::V4,
            enabled: true,
            generation,
            purpose: crate::model::Purpose::User,
            allow_from: Vec::new(),
        }
    }
    fn rule(access: VpnAccess) -> AgentVpnRule {
        AgentVpnRule {
            source: Ipv4Addr::new(10, 14, 0, 2),
            access,
        }
    }
    fn cfg(ports: &str, subnets: &str) -> AgentLimits {
        AgentLimits {
            ports: parse_port_allow(ports).unwrap(),
            subnets: parse_subnet_allow(subnets).unwrap(),
            exit: false,
            no_links: false,
        }
    }
    /// `restrict` with the default server address.
    fn restrict_(p: &AgentPolicy, limits: &AgentLimits) -> (AgentPolicy, Vec<String>) {
        restrict(p, limits, Some(Ipv4Addr::new(10, 13, 0, 1)))
    }
    fn policy(forwards: Vec<Forward>, vpn: Vec<AgentVpnRule>) -> AgentPolicy {
        AgentPolicy {
            generation: 9,
            forwards,
            vpn_pool: None,
            vpn,
            exit: None,
            tunnel_pool: None,
            outbound: vec![],
        }
    }
    fn subnet(net: &str) -> VpnAccess {
        VpnAccess::Subnet {
            net: net.parse().unwrap(),
            snat: false,
        }
    }

    #[test]
    fn forwards_follow_the_port_allowlist() {
        let p = policy(
            vec![
                forward(1, Protocol::Tcp, pr(22, 22), 3),
                forward(2, Protocol::Tcp, pr(23, 23), 4),
                forward(3, Protocol::Udp, pr(22, 22), 5),
                forward(4, Protocol::Tcp, pr(27015, 27025), 6),
                forward(5, Protocol::Udp, pr(27016, 27018), 7),
                forward(6, Protocol::Tcp, pr(80, 80), 8),
            ],
            vec![],
        );
        let (out, refusals) = restrict_(&p, &cfg("22/tcp,80,27015-27020/udp", ""));
        let ids: Vec<u64> = out.forwards.iter().map(|f| f.id).collect();
        assert_eq!(ids, [1, 5, 6]);
        assert_eq!(refusals.len(), 3);
        assert!(refusals[0].contains("forward 2"));
        assert!(refusals[0].contains("add 23/tcp"), "{}", refusals[0]);
        assert_eq!(
            out.generation, 9,
            "refusals do not hold the generation back"
        );
    }

    fn exit_forward(id: u64) -> Forward {
        Forward {
            protocol: Protocol::Udp,
            purpose: crate::model::Purpose::Exit,
            ..forward(id, Protocol::Udp, pr(51821, 51821), 3)
        }
    }
    fn exit_policy() -> crate::model::ExitPolicy {
        crate::model::ExitPolicy {
            listen_port: 51821,
            gateway_v4: Ipv4Addr::new(10, 14, 0, 1),
            gateway_v6: "fd88:5249:4655::1".parse().unwrap(),
            peers: vec![],
        }
    }

    #[test]
    fn the_exit_needs_the_agents_own_permission_and_implies_its_udp_port() {
        let mut p = policy(
            vec![
                exit_forward(1),
                forward(2, Protocol::Udp, pr(51821, 51821), 3),
            ],
            vec![],
        );
        p.exit = Some(exit_policy());
        // Allowed: the exit forward passes although RIFT_AGENT_ALLOW_PORTS names other ports;
        // a user forward to the same port is still checked against the list.
        let mut limits = cfg("22/tcp", "");
        limits.exit = true;
        let (out, refusals) = restrict_(&p, &limits);
        assert_eq!(out.forwards.iter().map(|f| f.id).collect::<Vec<_>>(), [1]);
        assert_eq!(out.exit, Some(exit_policy()));
        assert_eq!(refusals.len(), 1);
        assert!(refusals[0].contains("forward 2"), "{refusals:?}");
        // Refused: neither the exit nor its forward is applied, and the owner is told why.
        let (out, refusals) = restrict_(&p, &cfg("", ""));
        assert!(out.forwards.iter().all(|f| f.id != 1));
        assert!(out.exit.is_none());
        assert!(
            refusals
                .iter()
                .any(|r| r.contains("internet exit refused")
                    && r.contains("RIFT_AGENT_ALLOW_EXIT=true")),
            "{refusals:?}"
        );
        assert!(refusals.iter().any(|r| r.contains("forward 1")));
        // Nothing to refuse without an exit in the policy.
        let (_, refusals) = restrict_(&policy(vec![], vec![]), &cfg("", ""));
        assert!(refusals.is_empty());
    }

    #[test]
    fn no_allowlist_keeps_everything_and_the_generation() {
        let p = policy(
            vec![forward(1, Protocol::Tcp, pr(1, 65535), 3)],
            vec![rule(VpnAccess::Server), rule(VpnAccess::Full)],
        );
        let (out, refusals) = restrict_(&p, &cfg("", ""));
        assert!(refusals.is_empty());
        assert_eq!(out.forwards.len(), 1);
        assert_eq!(out.vpn.len(), 2);
        assert_eq!(out.generation, 9);
    }

    #[test]
    fn vpn_port_grants_follow_the_allowlist_and_whole_host_grants_are_dropped() {
        let p = policy(
            vec![],
            vec![
                rule(VpnAccess::Port {
                    protocol: Protocol::Tcp,
                    ports: pr(443, 443),
                }),
                rule(VpnAccess::Port {
                    protocol: Protocol::Udp,
                    ports: pr(443, 443),
                }),
                rule(VpnAccess::Port {
                    protocol: Protocol::Tcp,
                    ports: pr(440, 450),
                }),
                rule(VpnAccess::Server),
                rule(VpnAccess::Full),
            ],
        );
        let (out, refusals) = restrict_(&p, &cfg("443/tcp", ""));
        assert_eq!(out.vpn.len(), 1);
        assert_eq!(refusals.len(), 4);
        assert!(refusals[2].contains("every port"));
        assert!(refusals[3].contains("every port"));
        assert_eq!(out.generation, 9);
    }

    #[test]
    fn refusals_name_the_server_host_for_sources_outside_the_vpn_pool() {
        let mut p = policy(
            vec![],
            vec![
                rule(VpnAccess::Full),
                AgentVpnRule {
                    source: Ipv4Addr::new(10, 13, 0, 1),
                    access: VpnAccess::Full,
                },
            ],
        );
        p.vpn_pool = Some("10.14.0.0/24".parse().unwrap());
        let (_, refusals) = restrict_(&p, &cfg("22/tcp", ""));
        assert!(
            refusals[0].starts_with("VPN grant for 10.14.0.2"),
            "{refusals:?}"
        );
        assert!(
            refusals[1].starts_with("access of the server host (10.13.0.1) to the host"),
            "{refusals:?}"
        );
    }

    #[test]
    fn subnet_grants_need_a_listed_network_and_are_refused_by_default() {
        let p = policy(
            vec![],
            vec![
                rule(subnet("192.168.178.0/24")),
                rule(subnet("192.168.178.64/26")),
                rule(subnet("192.168.0.0/16")),
                rule(subnet("10.0.0.0/24")),
            ],
        );
        let (out, refusals) = restrict_(&p, &cfg("", "192.168.178.0/24"));
        let nets: Vec<_> = out.vpn.iter().map(|r| r.access.clone()).collect();
        assert_eq!(
            nets,
            [subnet("192.168.178.0/24"), subnet("192.168.178.64/26")]
        );
        assert_eq!(refusals.len(), 2);
        assert!(refusals[0].contains("RIFT_AGENT_ALLOW_SUBNETS"));
        let (out, refusals) = restrict_(&p, &AgentLimits::default());
        assert!(out.vpn.is_empty());
        assert_eq!(refusals.len(), 4);
    }
}
