//! The UDP forward behind an agent's internet exit.
//!
//! A device that exits through an agent runs a second WireGuard tunnel to that agent. The
//! packets of that tunnel reach the agent as an ordinary transparent UDP forward: the VPS
//! listens on the exit port of the agent and passes it to the same port on the agent's tunnel
//! address. The forward belongs to RIFT, not to the user: it exists exactly as long as an
//! enabled device uses the agent as its exit, and `rift remove forward` refuses to touch it.
//! Everything here is pure; `daemon.rs` applies it before every reconcile.

use crate::model::*;
use anyhow::{bail, Result};
use std::{collections::BTreeSet, net::IpAddr, ops::RangeInclusive};

pub struct Settings<'a> {
    pub public_ips: &'a [IpAddr],
    /// The ports exits may use, `exit_port_min..=exit_port_max`.
    pub ports: RangeInclusive<u16>,
    pub wg_port: u16,
}

/// Agents that an enabled device uses as its internet exit.
fn used_agents(snap: &StateSnapshot) -> BTreeSet<String> {
    snap.agents
        .iter()
        .filter(|a| a.status == AgentStatus::Active)
        .filter(|a| !crate::vpn::agent_exit_peers(snap, &a.id).is_empty())
        .map(|a| a.id.clone())
        .collect()
}

/// Gives every agent in use an exit port and makes the exit forwards match: one per listen
/// address, created where missing, removed where no device needs them. Ports stay with an
/// agent once assigned. Returns whether the snapshot changed.
pub fn sync(snap: &mut StateSnapshot, settings: &Settings<'_>) -> bool {
    let mut changed = false;
    let used = used_agents(snap);
    let user_udp: Vec<PortRange> = snap
        .forwards
        .iter()
        .filter(|f| f.purpose == Purpose::User && f.protocol == Protocol::Udp)
        .map(|f| f.listen_ports)
        .collect();
    let blocked = |port: u16| {
        port == settings.wg_port || user_udp.iter().any(|r| r.start <= port && port <= r.end)
    };
    for id in &used {
        let taken: BTreeSet<u16> = snap
            .agents
            .iter()
            .filter(|a| a.id != *id)
            .filter_map(|a| a.exit_port)
            .collect();
        let Some(agent) = snap.agents.iter_mut().find(|a| a.id == *id) else {
            continue;
        };
        let keep = agent
            .exit_port
            .is_some_and(|p| settings.ports.contains(&p) && !blocked(p));
        if !keep {
            let pick = settings
                .ports
                .clone()
                .find(|p| !blocked(*p) && !taken.contains(p));
            if agent.exit_port != pick {
                agent.exit_port = pick;
                changed = true;
            }
        }
    }
    let first = |v6: bool| {
        settings
            .public_ips
            .iter()
            .copied()
            .find(|ip| ip.is_ipv6() == v6)
    };
    let listen_ips: Vec<IpAddr> = [first(false), first(true)].into_iter().flatten().collect();
    let mut wanted: BTreeSet<(String, IpAddr, u16)> = BTreeSet::new();
    for agent in snap.agents.iter().filter(|a| used.contains(&a.id)) {
        if let Some(port) = agent.exit_port {
            for ip in &listen_ips {
                wanted.insert((agent.id.clone(), *ip, port));
            }
        }
    }
    let before = snap.forwards.len();
    snap.forwards.retain(|f| {
        f.purpose != Purpose::Exit
            || wanted.contains(&(f.agent_id.clone(), f.listen_ip, f.listen_ports.start))
    });
    changed |= snap.forwards.len() != before;
    let generation = snap.generation + 1;
    for (agent_id, listen_ip, port) in wanted {
        let present = snap.forwards.iter().any(|f| {
            f.purpose == Purpose::Exit
                && f.agent_id == agent_id
                && f.listen_ip == listen_ip
                && f.listen_ports.start == port
        });
        if present {
            continue;
        }
        let ports = PortRange {
            start: port,
            end: port,
        };
        let id = crate::state::lowest_free_id(snap.forwards.iter().map(|f| f.id));
        snap.forwards.push(Forward {
            id,
            agent_id,
            listen_ip,
            listen_ports: ports,
            target_ports: ports,
            protocol: Protocol::Udp,
            mode: ForwardMode::Transparent,
            ingress: Ingress::Public,
            target_family: Family::of(listen_ip),
            enabled: true,
            generation,
            purpose: Purpose::Exit,
        });
        changed = true;
    }
    changed
}

/// Refuses to change a forward that RIFT manages for an internet exit.
pub fn ensure_user_forward(snap: &StateSnapshot, id: u64) -> Result<()> {
    if snap
        .forwards
        .iter()
        .any(|f| f.id == id && f.purpose == Purpose::Exit)
    {
        bail!(
            "forward {id} carries an internet exit and is managed by RIFT; it disappears when no device uses that exit (rift vpn deny DEVICE AGENT internet)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn agent(id: &str) -> AgentRecord {
        AgentRecord {
            id: id.into(),
            name: id.into(),
            public_key: format!("k-{id}"),
            tunnel_ipv4: Ipv4Addr::new(10, 13, 0, 2),
            tunnel_ipv6: Ipv6Addr::LOCALHOST,
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
    fn device(name: &str, exit: Exit) -> VpnPeer {
        VpnPeer {
            name: name.into(),
            public_key: format!("k-{name}"),
            ipv4: Ipv4Addr::new(10, 14, 0, 2),
            enabled: true,
            created_at: 0,
            panel: false,
            ipv6: Ipv6Addr::LOCALHOST,
            exit,
        }
    }
    fn settings(ips: &[IpAddr]) -> Settings<'_> {
        Settings {
            public_ips: ips,
            ports: 51821..=51823,
            wg_port: 51820,
        }
    }
    fn ips() -> Vec<IpAddr> {
        vec![
            "203.0.113.10".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
        ]
    }
    fn snapshot(exit: Exit) -> StateSnapshot {
        StateSnapshot {
            generation: 7,
            agents: vec![agent("home")],
            vpn_peers: vec![device("phone", exit)],
            ..Default::default()
        }
    }
    fn exits(snap: &StateSnapshot) -> Vec<&Forward> {
        snap.forwards
            .iter()
            .filter(|f| f.purpose == Purpose::Exit)
            .collect()
    }

    #[test]
    fn a_used_exit_gets_one_udp_forward_per_listen_address() {
        let ips = ips();
        let mut snap = snapshot(Exit::Agent("home".into()));
        assert!(sync(&mut snap, &settings(&ips)));
        assert_eq!(snap.agents[0].exit_port, Some(51821));
        let forwards = exits(&snap);
        assert_eq!(forwards.len(), 2, "first IPv4 and first IPv6");
        for f in &forwards {
            assert_eq!(
                (f.protocol, f.mode, f.enabled, f.generation),
                (Protocol::Udp, ForwardMode::Transparent, true, 8)
            );
            assert_eq!(f.listen_ports, f.target_ports);
            assert_eq!(f.listen_ports.start, 51821);
            assert_eq!(f.target_family, Family::of(f.listen_ip));
        }
        // Nothing to do the second time: IDs and generations stay.
        let before = snap.forwards.clone();
        assert!(!sync(&mut snap, &settings(&ips)));
        assert_eq!(snap.forwards, before);
        // Without an IPv6 address on the server only the IPv4 listener exists.
        let mut v4 = snapshot(Exit::Agent("home".into()));
        sync(&mut v4, &settings(&ips[..1]));
        assert_eq!(exits(&v4).len(), 1);
    }

    #[test]
    fn the_forward_goes_when_no_enabled_device_uses_the_exit_but_the_port_stays() {
        let ips = ips();
        let mut snap = snapshot(Exit::Agent("home".into()));
        sync(&mut snap, &settings(&ips));
        snap.vpn_peers[0].enabled = false;
        assert!(sync(&mut snap, &settings(&ips)));
        assert!(exits(&snap).is_empty());
        assert_eq!(
            snap.agents[0].exit_port,
            Some(51821),
            "kept for the configs"
        );
        snap.vpn_peers[0].enabled = true;
        sync(&mut snap, &settings(&ips));
        assert_eq!(exits(&snap).len(), 2);
        snap.vpn_peers[0].exit = Exit::Server;
        sync(&mut snap, &settings(&ips));
        assert!(exits(&snap).is_empty());
        snap.vpn_peers[0].exit = Exit::None;
        assert!(!sync(&mut snap, &settings(&ips)));
    }

    #[test]
    fn ports_differ_per_agent_and_avoid_user_forwards_and_the_wireguard_port() {
        let ips = ips();
        let mut snap = snapshot(Exit::Agent("home".into()));
        snap.agents.push(agent("cabin"));
        snap.vpn_peers
            .push(device("tablet", Exit::Agent("cabin".into())));
        snap.vpn_peers[1].ipv4 = Ipv4Addr::new(10, 14, 0, 3);
        snap.forwards.push(Forward {
            id: 1,
            agent_id: "home".into(),
            listen_ip: ips[0],
            listen_ports: PortRange {
                start: 51821,
                end: 51821,
            },
            target_ports: PortRange {
                start: 51821,
                end: 51821,
            },
            protocol: Protocol::Udp,
            mode: ForwardMode::Transparent,
            ingress: Ingress::Public,
            target_family: Family::V4,
            enabled: true,
            generation: 1,
            purpose: Purpose::User,
        });
        sync(&mut snap, &settings(&ips));
        let port = |snap: &StateSnapshot, id: &str| {
            snap.agents.iter().find(|a| a.id == id).unwrap().exit_port
        };
        // 51821 belongs to a user forward; the two agents share the rest.
        let mut ports = [port(&snap, "home"), port(&snap, "cabin")];
        ports.sort();
        assert_eq!(ports, [Some(51822), Some(51823)]);
        // A user forward that takes an assigned port moves the exit away from it.
        snap.forwards.retain(|f| f.purpose == Purpose::User);
        snap.forwards[0].listen_ports = PortRange {
            start: 51822,
            end: 51822,
        };
        let before = port(&snap, "home");
        sync(&mut snap, &settings(&ips));
        // The agent whose port the user forward took moves to the freed one; the other stays.
        let moved = [port(&snap, "home"), port(&snap, "cabin")];
        assert!(moved.contains(&Some(51821)) && !moved.contains(&Some(51822)));
        if before != Some(51822) {
            assert_eq!(port(&snap, "home"), before);
        }
        // Used up: no port, hence no forward for that agent.
        let mut full = snapshot(Exit::Agent("home".into()));
        let small = Settings {
            ports: 51820..=51820,
            ..settings(&ips)
        };
        sync(&mut full, &small);
        assert_eq!(full.agents[0].exit_port, None);
        assert!(exits(&full).is_empty());
    }

    #[test]
    fn inactive_agents_have_no_exit_forward_and_managed_forwards_are_protected() {
        let ips = ips();
        let mut snap = snapshot(Exit::Agent("home".into()));
        sync(&mut snap, &settings(&ips));
        let id = exits(&snap)[0].id;
        assert!(ensure_user_forward(&snap, id).is_err());
        assert!(ensure_user_forward(&snap, 99).is_ok());
        snap.agents[0].status = AgentStatus::Disabled;
        sync(&mut snap, &settings(&ips));
        assert!(exits(&snap).is_empty());
    }
}
