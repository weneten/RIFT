//! UFW drops stay in force beside the RIFT table. An accept in `inet rift` does not
//! override a drop in another filter base chain, so this module installs one owned jump
//! into the UFW user chains. Grant checks remain in the RIFT table.

use crate::model::{AgentVpnRule, Family, Forward};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

pub const CHAIN_IN: &str = "rift-host-in";
pub const CHAIN_FWD: &str = "rift-host-fwd";
const JUMP_COMMENT: &str = "rift:jump";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainRef {
    pub family: String,
    pub table: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct JumpRef {
    family: String,
    table: String,
    chain: String,
    target: String,
    handle: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Observation {
    pub input: Vec<ChainRef>,
    pub forward: Vec<ChainRef>,
    owned: BTreeSet<(String, String, String)>,
    jumps: Vec<JumpRef>,
    pub forward_policy_drop: bool,
    pub input_policy_drop: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub create: String,
    pub fill: String,
    pub jumps: String,
    pub summary: String,
}

pub struct ServerSpec<'a> {
    pub interface: &'a str,
    pub server_v4: Ipv4Addr,
    pub server_v6: Ipv6Addr,
    pub control_port: u16,
    pub wg_port: u16,
    pub enrollment: Option<SocketAddr>,
    pub uplinks: &'a [String],
    pub local_ingress: bool,
    /// VPN peers reach agents through `rift0` and leave by `rift0` again.
    pub vpn: bool,
    /// Some device exits to the internet through the VPS: forward `rift0` to the uplinks.
    pub exit: bool,
    /// The web panel's TCP port, when it is on. Who may connect is decided in the RIFT
    /// table and by the panel itself; UFW only has to let the port through.
    pub panel: Option<PanelSpec>,
}

#[derive(Clone, Copy, Debug)]
pub struct PanelSpec {
    pub port: u16,
    /// Also open the port on the uplinks, not only on the tunnel address.
    pub public: bool,
}

pub struct AgentSpec<'a> {
    pub interface: &'a str,
    pub tunnel_v4: Ipv4Addr,
    pub tunnel_v6: Ipv6Addr,
    pub forwards: &'a [&'a Forward],
    pub vpn: &'a [AgentVpnRule],
    /// Set while the agent runs an internet exit.
    pub exit: Option<ExitSpec<'a>>,
}

/// The exit interface of an agent and the interfaces its traffic leaves by.
pub struct ExitSpec<'a> {
    pub interface: &'a str,
    /// Interfaces with the host's default routes; empty means any other interface.
    pub uplinks: &'a [String],
}

pub struct DoctorReport {
    pub status: Value,
    pub warnings: Vec<String>,
}

pub fn observe(document: &Value) -> Result<Observation> {
    let entries = document
        .get("nftables")
        .and_then(Value::as_array)
        .context("nftables JSON has no nftables array")?;
    let mut obs = Observation::default();
    for entry in entries {
        if let Some(chain) = entry.get("chain") {
            observe_chain(&mut obs, chain);
        }
        if let Some(rule) = entry.get("rule") {
            observe_rule(&mut obs, rule);
        }
    }
    Ok(obs)
}

pub fn uplinks(addresses: &Value, public_ips: &[IpAddr]) -> Result<Vec<String>> {
    let links = addresses
        .as_array()
        .context("ip address JSON must be an array")?;
    let mut found = Vec::new();
    for link in links {
        let Some(name) = link.get("ifname").and_then(Value::as_str) else {
            continue;
        };
        if !valid_ifname(name) {
            continue;
        }
        let Some(entries) = link.get("addr_info").and_then(Value::as_array) else {
            continue;
        };
        let owns_public = entries.iter().any(|entry| {
            entry
                .get("local")
                .and_then(Value::as_str)
                .and_then(|value| value.parse::<IpAddr>().ok())
                .is_some_and(|ip| public_ips.contains(&ip))
        });
        if owns_public && !found.iter().any(|have| have == name) {
            found.push(name.to_string());
        }
    }
    Ok(found)
}

pub fn plan_server(obs: &Observation, spec: &ServerSpec<'_>) -> Result<Plan> {
    require_ifname(spec.interface)?;
    for uplink in spec.uplinks {
        require_ifname(uplink)?;
    }
    let mut plan = Plan::default();
    for chain in &obs.input {
        let mut rules = Vec::new();
        if chain.family == "ip" || chain.family == "inet" {
            rules.push(format!(
                "iifname \"{}\" ip daddr {} tcp dport {} accept comment \"rift:control\"",
                spec.interface, spec.server_v4, spec.control_port
            ));
        }
        if chain.family == "ip6" || chain.family == "inet" {
            rules.push(format!(
                "iifname \"{}\" ip6 daddr {} tcp dport {} accept comment \"rift:control\"",
                spec.interface, spec.server_v6, spec.control_port
            ));
        }
        if let Some(panel) = spec.panel {
            if chain.family == "ip" || chain.family == "inet" {
                rules.push(format!(
                    "iifname \"{}\" ip daddr {} tcp dport {} accept comment \"rift:panel\"",
                    spec.interface, spec.server_v4, panel.port
                ));
            }
        }
        for prefix in iface_prefixes(spec.uplinks) {
            if let Some(panel) = spec.panel.filter(|panel| panel.public) {
                rules.push(format!(
                    "{prefix}tcp dport {} accept comment \"rift:panel\"",
                    panel.port
                ));
            }
            rules.push(format!(
                "{prefix}udp dport {} accept comment \"rift:wireguard\"",
                spec.wg_port
            ));
            if let Some(bind) = spec.enrollment {
                if let Some(matchers) = enrollment_match(&chain.family, bind) {
                    rules.push(format!(
                        "{prefix}{matchers}accept comment \"rift:enrollment\""
                    ));
                }
            }
        }
        push_chain(&mut plan, obs, chain, CHAIN_IN, &rules);
    }
    for chain in &obs.forward {
        let mut rules = Vec::new();
        for uplink in spec.uplinks {
            rules.push(format!(
                "iifname \"{uplink}\" oifname \"{}\" accept comment \"rift:forward\"",
                spec.interface
            ));
            rules.push(format!(
                "iifname \"{}\" oifname \"{uplink}\" accept comment \"rift:return\"",
                spec.interface
            ));
        }
        if spec.local_ingress {
            ensure!(
                !spec.uplinks.is_empty(),
                "local ingress needs a public uplink"
            );
            let mut excluded: Vec<String> = spec
                .uplinks
                .iter()
                .map(|name| format!("iifname != \"{name}\""))
                .collect();
            excluded.push(format!("iifname != \"{}\"", spec.interface));
            rules.push(format!(
                "{} oifname \"{}\" accept comment \"rift:local\"",
                excluded.join(" "),
                spec.interface
            ));
        }
        if spec.vpn {
            rules.push(format!(
                "iifname \"{0}\" oifname \"{0}\" accept comment \"rift:vpn\"",
                spec.interface
            ));
        }
        if spec.exit {
            rules.extend(exit_rules(spec.interface, spec.uplinks));
        }
        push_chain(&mut plan, obs, chain, CHAIN_FWD, &rules);
    }
    plan.summary = format!(
        "host firewall updated for control {} and {} uplink(s)",
        spec.control_port,
        spec.uplinks.len()
    );
    Ok(plan)
}

pub fn plan_agent(obs: &Observation, spec: &AgentSpec<'_>) -> Result<Plan> {
    require_ifname(spec.interface)?;
    let mut plan = Plan::default();
    for chain in &obs.input {
        let mut rules = Vec::new();
        for forward in spec.forwards.iter().filter(|forward| forward.enabled) {
            if forward.target_ports.is_empty() {
                continue;
            }
            let (family, address) = match forward.target_family {
                Family::V4 => ("ip", IpAddr::V4(spec.tunnel_v4)),
                Family::V6 => ("ip6", IpAddr::V6(spec.tunnel_v6)),
            };
            if chain.family != family && chain.family != "inet" {
                continue;
            }
            rules.push(format!(
                "iifname \"{}\" {family} daddr {address} {} dport {} accept comment \"rift:grant\"",
                spec.interface, forward.protocol, forward.target_ports
            ));
        }
        if chain.family == "ip" || chain.family == "inet" {
            for rule in spec.vpn {
                rules.push(format!(
                    "iifname \"{}\" {}accept comment \"rift:vpn\"",
                    spec.interface,
                    crate::vpn::flow_match(rule.source, spec.tunnel_v4, &rule.access)
                ));
            }
        }
        push_chain(&mut plan, obs, chain, CHAIN_IN, &rules);
    }
    for chain in &obs.forward {
        let mut rules = vec![
            format!(
                "iifname \"{}\" accept comment \"rift:ingress\"",
                spec.interface
            ),
            format!(
                "oifname \"{}\" accept comment \"rift:egress\"",
                spec.interface
            ),
        ];
        if let Some(exit) = &spec.exit {
            require_ifname(exit.interface)?;
            for uplink in exit.uplinks {
                require_ifname(uplink)?;
            }
            rules.extend(exit_rules(exit.interface, exit.uplinks));
        }
        push_chain(&mut plan, obs, chain, CHAIN_FWD, &rules);
    }
    plan.summary = format!(
        "host firewall updated for {} granted agent port range(s)",
        spec.forwards
            .iter()
            .filter(|forward| forward.enabled)
            .count()
    );
    Ok(plan)
}

/// Forwarding between an exit interface and the uplinks: out freely, back only for replies.
fn exit_rules(interface: &str, uplinks: &[String]) -> Vec<String> {
    if uplinks.is_empty() {
        return vec![
            format!("iifname \"{interface}\" oifname != \"{interface}\" accept comment \"rift:exit\""),
            format!("iifname != \"{interface}\" oifname \"{interface}\" ct state established,related accept comment \"rift:exit\""),
        ];
    }
    uplinks
        .iter()
        .flat_map(|uplink| {
            [
                format!("iifname \"{interface}\" oifname \"{uplink}\" accept comment \"rift:exit\""),
                format!("iifname \"{uplink}\" oifname \"{interface}\" ct state established,related accept comment \"rift:exit\""),
            ]
        })
        .collect()
}

pub fn plan_remove(obs: &Observation) -> String {
    let mut script = String::new();
    for jump in &obs.jumps {
        script.push_str(&format!(
            "delete rule {} {} {} handle {}\n",
            jump.family, jump.table, jump.chain, jump.handle
        ));
    }
    let mut chains: Vec<_> = obs.owned.iter().collect();
    chains.sort();
    for (family, table, name) in chains {
        script.push_str(&format!("flush chain {family} {table} {name}\n"));
        script.push_str(&format!("delete chain {family} {table} {name}\n"));
    }
    script
}

pub fn report(
    mode: &str,
    obs: &Observation,
    uplinks: &[String],
    public_ips_configured: bool,
) -> DoctorReport {
    let backend = if obs.input.is_empty() && obs.forward.is_empty() {
        "none"
    } else {
        "ufw"
    };
    let uplinks_missing = public_ips_configured && uplinks.is_empty() && !obs.forward.is_empty();
    let mut warnings = Vec::new();
    if obs.forward_policy_drop && obs.forward.is_empty() {
        warnings.push(
            "Host filter drops forwarded packets and has no UFW user chain RIFT can extend."
                .to_string(),
        );
    }
    if obs.input_policy_drop && obs.input.is_empty() {
        warnings.push(
            "Host filter drops input and has no UFW user chain RIFT can extend. Tunnel control stays blocked."
                .to_string(),
        );
    }
    if mode == "off" && backend == "ufw" && (obs.input_policy_drop || obs.forward_policy_drop) {
        warnings.push(
            "host_firewall is off, so UFW can still drop tunnel control traffic and published forwards."
                .to_string(),
        );
    }
    if mode == "auto" && uplinks_missing {
        warnings.push(
            "No local interface owns a configured public IP, so UFW forwarding was not opened."
                .to_string(),
        );
    }
    DoctorReport {
        status: json!({
            "mode": mode,
            "backend": backend,
            "uplinks": uplinks,
            "input_chains": obs.input.len(),
            "forward_chains": obs.forward.len(),
            "forward_policy_drop": obs.forward_policy_drop,
            "input_policy_drop": obs.input_policy_drop,
        }),
        warnings,
    }
}

fn observe_chain(obs: &mut Observation, chain: &Value) {
    let Some(reference) = chain_ref(chain) else {
        return;
    };
    match reference.name.as_str() {
        "ufw-user-input" | "ufw6-user-input" => obs.input.push(reference.clone()),
        "ufw-user-forward" | "ufw6-user-forward" => obs.forward.push(reference.clone()),
        CHAIN_IN | CHAIN_FWD => {
            obs.owned.insert((
                reference.family.clone(),
                reference.table.clone(),
                reference.name.clone(),
            ));
        }
        _ => {}
    }
    if chain.get("hook").is_some() {
        let policy = chain.get("policy").and_then(Value::as_str).unwrap_or("");
        let hook = chain.get("hook").and_then(Value::as_str).unwrap_or("");
        if policy == "drop" && hook == "forward" {
            obs.forward_policy_drop = true;
        }
        if policy == "drop" && hook == "input" {
            obs.input_policy_drop = true;
        }
    }
}

fn observe_rule(obs: &mut Observation, rule: &Value) {
    let Some(reference) = chain_ref(rule) else {
        return;
    };
    let target = jump_target(rule);
    let comment = rule_comment(rule);
    let owned_jump =
        comment == Some(JUMP_COMMENT) || target == Some(CHAIN_IN) || target == Some(CHAIN_FWD);
    if !owned_jump {
        return;
    }
    let Some(handle) = rule.get("handle").and_then(Value::as_u64) else {
        return;
    };
    let Some(target) = target else {
        return;
    };
    if obs
        .jumps
        .iter()
        .any(|jump| jump.handle == handle && jump.chain == reference.name)
    {
        return;
    }
    obs.jumps.push(JumpRef {
        family: reference.family,
        table: reference.table,
        chain: reference.name,
        target: target.to_string(),
        handle,
    });
}

fn push_chain(plan: &mut Plan, obs: &Observation, chain: &ChainRef, owned: &str, rules: &[String]) {
    let key = (chain.family.clone(), chain.table.clone(), owned.to_string());
    if !obs.owned.contains(&key) {
        plan.create.push_str(&format!(
            "add chain {} {} {owned}\n",
            chain.family, chain.table
        ));
    }
    plan.fill.push_str(&format!(
        "flush chain {} {} {owned}\n",
        chain.family, chain.table
    ));
    for rule in rules {
        plan.fill.push_str(&format!(
            "add rule {} {} {owned} {rule}\n",
            chain.family, chain.table
        ));
    }
    let already = obs
        .jumps
        .iter()
        .any(|jump| jump.chain == chain.name && jump.target == owned);
    if !already {
        plan.jumps.push_str(&format!(
            "insert rule {} {} {} jump {owned} comment \"{JUMP_COMMENT}\"\n",
            chain.family, chain.table, chain.name
        ));
    }
}

fn iface_prefixes(uplinks: &[String]) -> Vec<String> {
    if uplinks.is_empty() {
        vec![String::new()]
    } else {
        uplinks
            .iter()
            .map(|name| format!("iifname \"{name}\" "))
            .collect()
    }
}

fn enrollment_match(family: &str, bind: SocketAddr) -> Option<String> {
    match (family, bind.ip()) {
        ("ip" | "inet", IpAddr::V4(ip)) if ip.is_unspecified() => {
            Some(format!("tcp dport {} ", bind.port()))
        }
        ("ip" | "inet", IpAddr::V4(ip)) => {
            Some(format!("ip daddr {ip} tcp dport {} ", bind.port()))
        }
        // The server also listens on IPv6 when it binds 0.0.0.0.
        ("ip6", IpAddr::V4(ip)) if ip.is_unspecified() => {
            Some(format!("tcp dport {} ", bind.port()))
        }
        ("ip6" | "inet", IpAddr::V6(ip)) if ip.is_unspecified() => {
            Some(format!("tcp dport {} ", bind.port()))
        }
        ("ip6" | "inet", IpAddr::V6(ip)) => {
            Some(format!("ip6 daddr {ip} tcp dport {} ", bind.port()))
        }
        _ => None,
    }
}

fn chain_ref(value: &Value) -> Option<ChainRef> {
    let family = value.get("family")?.as_str()?;
    let table = value.get("table")?.as_str()?;
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .or_else(|| value.get("chain").and_then(Value::as_str))?;
    if !valid_ident(family) || !valid_ident(table) || !valid_ident(name) {
        return None;
    }
    Some(ChainRef {
        family: family.to_string(),
        table: table.to_string(),
        name: name.to_string(),
    })
}

fn jump_target(rule: &Value) -> Option<&str> {
    rule.get("expr")?
        .as_array()?
        .iter()
        .find_map(|expr| expr.get("jump")?.get("target")?.as_str())
}

fn rule_comment(rule: &Value) -> Option<&str> {
    rule.get("comment").and_then(Value::as_str).or_else(|| {
        rule.get("expr")?.as_array()?.iter().find_map(|expr| {
            expr.get("comment")
                .and_then(Value::as_str)
                .or_else(|| expr.as_str())
        })
    })
}

fn require_ifname(name: &str) -> Result<()> {
    ensure!(valid_ifname(name), "invalid interface name {name}");
    Ok(())
}

pub(crate) fn valid_ifname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn valid_ident(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ForwardMode, Protocol};
    use std::net::Ipv4Addr;

    fn ruleset() -> Value {
        json!({"nftables": [
            {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "hook": "input", "policy": "drop"}},
            {"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "hook": "forward", "policy": "drop"}},
            {"chain": {"family": "ip", "table": "filter", "name": "ufw-user-input"}},
            {"chain": {"family": "ip", "table": "filter", "name": "ufw-user-forward"}},
            {"chain": {"family": "ip", "table": "filter", "name": "rift-host-in"}},
            {"chain": {"family": "ip6", "table": "filter", "name": "ufw6-user-input"}},
            {"chain": {"family": "ip6", "table": "filter", "name": "ufw6-user-forward"}},
            {"rule": {
                "family": "ip",
                "table": "filter",
                "chain": "ufw-user-input",
                "handle": 7,
                "comment": "rift:jump",
                "expr": [{"jump": {"target": CHAIN_IN}}]
            }}
        ]})
    }

    fn server_spec<'a>(uplinks: &'a [String]) -> ServerSpec<'a> {
        ServerSpec {
            interface: "rift0",
            server_v4: "10.88.0.1".parse().unwrap(),
            server_v6: "fd88:5249:4654::1".parse().unwrap(),
            control_port: 8444,
            wg_port: 51820,
            enrollment: Some("0.0.0.0:8443".parse().unwrap()),
            uplinks,
            local_ingress: false,
            vpn: false,
            panel: None,
            exit: false,
        }
    }

    #[test]
    fn server_plan_opens_control_and_forward_without_a_second_jump() {
        let obs = observe(&ruleset()).unwrap();
        let uplinks = vec!["eth0".to_string()];
        let plan = plan_server(&obs, &server_spec(&uplinks)).unwrap();
        assert!(plan.fill.contains(
            "iifname \"rift0\" ip daddr 10.88.0.1 tcp dport 8444 accept comment \"rift:control\""
        ));
        assert!(plan.fill.contains(
            "iifname \"rift0\" ip6 daddr fd88:5249:4654::1 tcp dport 8444 accept comment \"rift:control\""
        ));
        assert!(plan
            .fill
            .contains("iifname \"eth0\" udp dport 51820 accept comment \"rift:wireguard\""));
        assert!(plan
            .fill
            .contains("iifname \"eth0\" tcp dport 8443 accept comment \"rift:enrollment\""));
        assert!(plan
            .fill
            .contains("iifname \"eth0\" oifname \"rift0\" accept comment \"rift:forward\""));
        assert!(plan
            .fill
            .contains("iifname \"rift0\" oifname \"eth0\" accept comment \"rift:return\""));
        assert!(!plan.fill.contains("iifname \"eth0\" tcp dport 8444"));
        assert!(!plan.fill.contains("rift:local"));
        assert!(!plan.jumps.contains("ufw-user-input"));
        assert!(plan.jumps.contains("ufw-user-forward"));
        assert!(plan.jumps.contains("ufw6-user-input"));
        assert!(plan.create.contains("add chain ip6 filter rift-host-in"));
        // Enrollment on 0.0.0.0 also listens on IPv6, so the IPv6 chain opens it too.
        assert!(plan.fill.contains(
            "add rule ip6 filter rift-host-in iifname \"eth0\" tcp dport 8443 accept comment \"rift:enrollment\""
        ));
        assert!(!plan.create.contains("add chain ip filter rift-host-in"));
    }

    #[test]
    fn the_panel_port_opens_on_the_tunnel_and_only_in_public_mode_on_the_uplink() {
        let obs = observe(&ruleset()).unwrap();
        let uplinks = vec!["eth0".to_string()];
        let mut spec = server_spec(&uplinks);
        assert!(!plan_server(&obs, &spec)
            .unwrap()
            .fill
            .contains("rift:panel"));
        spec.panel = Some(PanelSpec {
            port: 8090,
            public: false,
        });
        let private = plan_server(&obs, &spec).unwrap();
        assert!(private.fill.contains(
            "iifname \"rift0\" ip daddr 10.88.0.1 tcp dport 8090 accept comment \"rift:panel\""
        ));
        assert!(!private.fill.contains("iifname \"eth0\" tcp dport 8090"));
        spec.panel = Some(PanelSpec {
            port: 8090,
            public: true,
        });
        let public = plan_server(&obs, &spec).unwrap();
        assert!(public
            .fill
            .contains("iifname \"eth0\" tcp dport 8090 accept comment \"rift:panel\""));
    }

    #[test]
    fn local_ingress_accepts_forwarding_that_did_not_arrive_on_the_uplink() {
        let obs = observe(&ruleset()).unwrap();
        let uplinks = vec!["eth0".to_string()];
        let mut spec = server_spec(&uplinks);
        spec.local_ingress = true;
        let plan = plan_server(&obs, &spec).unwrap();
        assert!(plan.fill.contains(
            "iifname != \"eth0\" iifname != \"rift0\" oifname \"rift0\" accept comment \"rift:local\""
        ));
        assert!(plan
            .fill
            .contains("iifname \"eth0\" oifname \"rift0\" accept comment \"rift:forward\""));
        spec.uplinks = &[];
        spec.local_ingress = true;
        assert!(plan_server(&obs, &spec).is_err());
    }

    #[test]
    fn agent_plan_allows_only_granted_tunnel_ports() {
        let obs = observe(&ruleset()).unwrap();
        let forward = Forward {
            id: 1,
            agent_id: "core".into(),
            listen_ip: "203.0.113.1".parse().unwrap(),
            listen_ports: "18080".parse().unwrap(),
            target_ports: "8000".parse().unwrap(),
            protocol: Protocol::Tcp,
            mode: ForwardMode::Transparent,
            ingress: crate::model::Ingress::Public,
            target_family: Family::V4,
            enabled: true,
            generation: 1,
            purpose: crate::model::Purpose::User,
        };
        let plan = plan_agent(
            &obs,
            &AgentSpec {
                interface: "rift0",
                tunnel_v4: Ipv4Addr::new(10, 88, 0, 2),
                tunnel_v6: "fd88:5249:4654::2".parse().unwrap(),
                forwards: &[&forward],
                vpn: &[],
                exit: None,
            },
        )
        .unwrap();
        assert!(plan.fill.contains(
            "iifname \"rift0\" ip daddr 10.88.0.2 tcp dport 8000 accept comment \"rift:grant\""
        ));
        assert!(!plan.fill.contains("8444"));
        assert!(plan
            .fill
            .contains("iifname \"rift0\" accept comment \"rift:ingress\""));
        assert!(plan
            .fill
            .contains("oifname \"rift0\" accept comment \"rift:egress\""));
    }

    #[test]
    fn vpn_rules_open_ufw_only_when_a_grant_exists() {
        let obs = observe(&ruleset()).unwrap();
        let uplinks = vec!["eth0".to_string()];
        let mut spec = server_spec(&uplinks);
        let plain = plan_server(&obs, &spec).unwrap();
        assert!(!plain.fill.contains("rift:vpn"));
        spec.vpn = true;
        let plan = plan_server(&obs, &spec).unwrap();
        assert!(plan
            .fill
            .contains("iifname \"rift0\" oifname \"rift0\" accept comment \"rift:vpn\""));

        let rule = AgentVpnRule {
            source: Ipv4Addr::new(10, 14, 0, 2),
            access: crate::model::VpnAccess::Server,
        };
        let plan = plan_agent(
            &obs,
            &AgentSpec {
                interface: "rift0",
                tunnel_v4: Ipv4Addr::new(10, 88, 0, 2),
                tunnel_v6: "fd88:5249:4654::2".parse().unwrap(),
                forwards: &[],
                vpn: &[rule],
                exit: None,
            },
        )
        .unwrap();
        assert!(plan.fill.contains("iifname \"rift0\" ip saddr 10.14.0.2 ip daddr 10.88.0.2 meta l4proto { tcp, udp, icmp } accept comment \"rift:vpn\""));
    }

    #[test]
    fn ufw_forwards_exit_traffic_only_while_a_device_exits_through_this_host() {
        let obs = observe(&ruleset()).unwrap();
        let uplinks = vec!["eth0".to_string()];
        let mut spec = server_spec(&uplinks);
        assert!(!plan_server(&obs, &spec).unwrap().fill.contains("rift:exit"));
        spec.exit = true;
        let plan = plan_server(&obs, &spec).unwrap();
        assert!(plan
            .fill
            .contains("iifname \"rift0\" oifname \"eth0\" accept comment \"rift:exit\""));
        assert!(plan.fill.contains(
            "iifname \"eth0\" oifname \"rift0\" ct state established,related accept comment \"rift:exit\""
        ));
        // Without a known uplink, any other interface will do.
        spec.uplinks = &[];
        let plan = plan_server(&obs, &spec).unwrap();
        assert!(plan
            .fill
            .contains("iifname \"rift0\" oifname != \"rift0\" accept comment \"rift:exit\""));
    }

    #[test]
    fn agent_ufw_forwards_the_exit_interface_to_the_uplinks() {
        let obs = observe(&ruleset()).unwrap();
        let uplinks = vec!["enp3s0".to_string()];
        let spec = |exit| AgentSpec {
            interface: "rift0",
            tunnel_v4: Ipv4Addr::new(10, 88, 0, 2),
            tunnel_v6: "fd88:5249:4654::2".parse().unwrap(),
            forwards: &[],
            vpn: &[],
            exit,
        };
        assert!(!plan_agent(&obs, &spec(None))
            .unwrap()
            .fill
            .contains("rift:exit"));
        let plan = plan_agent(
            &obs,
            &spec(Some(ExitSpec {
                interface: "rift-exit",
                uplinks: &uplinks,
            })),
        )
        .unwrap();
        assert!(plan
            .fill
            .contains("iifname \"rift-exit\" oifname \"enp3s0\" accept comment \"rift:exit\""));
        assert!(plan.fill.contains(
            "iifname \"enp3s0\" oifname \"rift-exit\" ct state established,related accept comment \"rift:exit\""
        ));
        let bad = vec!["eth0;drop".to_string()];
        assert!(plan_agent(
            &obs,
            &spec(Some(ExitSpec {
                interface: "rift-exit",
                uplinks: &bad
            }))
        )
        .is_err());
    }

    #[test]
    fn removal_deletes_jump_and_owned_chain() {
        let mut obs = observe(&ruleset()).unwrap();
        obs.owned
            .insert(("ip".into(), "filter".into(), CHAIN_IN.into()));
        let script = plan_remove(&obs);
        assert!(script.contains("delete rule ip filter ufw-user-input handle 7"));
        assert!(script.contains("delete chain ip filter rift-host-in"));
    }

    #[test]
    fn public_address_selects_its_interface() {
        let addresses = json!([
            {"ifname": "eth0;drop", "addr_info": [{"local": "203.0.113.1"}]},
            {"ifname": "eth0", "addr_info": [{"local": "203.0.113.1"}, {"local": "127.0.0.1"}]},
            {"ifname": "docker0", "addr_info": [{"local": "172.17.0.1"}]}
        ]);
        let public = vec!["203.0.113.1".parse().unwrap()];
        assert_eq!(uplinks(&addresses, &public).unwrap(), vec!["eth0"]);
    }

    #[test]
    fn dropped_forward_without_ufw_is_reported() {
        let obs = observe(&json!({"nftables": [
            {"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "hook": "forward", "policy": "drop"}}
        ]}))
        .unwrap();
        let report = report("auto", &obs, &[], false);
        assert_eq!(report.status["backend"], "none");
        assert_eq!(report.warnings.len(), 1);
    }
}
