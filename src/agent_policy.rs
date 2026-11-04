//! The agent's own limits on what the server may ask of it. A compromised server can send
//! any policy; the agent applies only the part its owner allowed in the environment.

use crate::model::{AgentLimits, AgentPolicy, AgentVpnRule, VpnAccess};

fn describe_rule(rule: &AgentVpnRule) -> String {
    let what = match &rule.access {
        VpnAccess::Server => "the host".to_string(),
        VpnAccess::Full => "the host, all protocols".to_string(),
        VpnAccess::Port { protocol, ports } => format!("{ports}/{protocol}"),
        VpnAccess::Subnet { net, .. } => format!("subnet {net}"),
        VpnAccess::Dns => "DNS (53/both)".to_string(),
    };
    format!("VPN grant for {} to {what}", rule.source)
}

/// Returns the part of `policy` the agent's limits permit, and one refusal text per dropped
/// entry. The server leaves refused entries out itself once it knows the limits, so refusals
/// normally only appear before the first sync or from a server that ignores them.
pub fn restrict(policy: &AgentPolicy, limits: &AgentLimits) -> (AgentPolicy, Vec<String>) {
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
        match limits.refuse_access(&rule.access) {
            None => vpn.push(rule.clone()),
            Some(why) => refusals.push(format!("{} refused: {why}", describe_rule(rule))),
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
        },
        refusals,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
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
        }
    }
    fn policy(forwards: Vec<Forward>, vpn: Vec<AgentVpnRule>) -> AgentPolicy {
        AgentPolicy {
            generation: 9,
            forwards,
            vpn_pool: None,
            vpn,
            exit: None,
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
        let (out, refusals) = restrict(&p, &cfg("22/tcp,80,27015-27020/udp", ""));
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
        let (out, refusals) = restrict(&p, &limits);
        assert_eq!(out.forwards.iter().map(|f| f.id).collect::<Vec<_>>(), [1]);
        assert_eq!(out.exit, Some(exit_policy()));
        assert_eq!(refusals.len(), 1);
        assert!(refusals[0].contains("forward 2"), "{refusals:?}");
        // Refused: neither the exit nor its forward is applied, and the owner is told why.
        let (out, refusals) = restrict(&p, &cfg("", ""));
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
        let (_, refusals) = restrict(&policy(vec![], vec![]), &cfg("", ""));
        assert!(refusals.is_empty());
    }

    #[test]
    fn no_allowlist_keeps_everything_and_the_generation() {
        let p = policy(
            vec![forward(1, Protocol::Tcp, pr(1, 65535), 3)],
            vec![rule(VpnAccess::Server), rule(VpnAccess::Full)],
        );
        let (out, refusals) = restrict(&p, &cfg("", ""));
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
        let (out, refusals) = restrict(&p, &cfg("443/tcp", ""));
        assert_eq!(out.vpn.len(), 1);
        assert_eq!(refusals.len(), 4);
        assert!(refusals[2].contains("every port"));
        assert!(refusals[3].contains("every port"));
        assert_eq!(out.generation, 9);
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
        let (out, refusals) = restrict(&p, &cfg("", "192.168.178.0/24"));
        let nets: Vec<_> = out.vpn.iter().map(|r| r.access.clone()).collect();
        assert_eq!(
            nets,
            [subnet("192.168.178.0/24"), subnet("192.168.178.64/26")]
        );
        assert_eq!(refusals.len(), 2);
        assert!(refusals[0].contains("RIFT_AGENT_ALLOW_SUBNETS"));
        let (out, refusals) = restrict(&p, &AgentLimits::default());
        assert!(out.vpn.is_empty());
        assert_eq!(refusals.len(), 4);
    }
}
