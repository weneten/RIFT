//! Drops of another firewall stay in force beside the RIFT table: an accept in `inet rift`
//! does not override a drop in another filter base chain. So this module installs one owned
//! jump where that firewall decides: into the UFW user chains, or without UFW into each
//! foreign input/forward base chain that drops (a drop policy, or a final reject as on Oracle
//! Cloud images and Docker's forward policy). Grant checks remain in the RIFT table.

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
    /// Filter base chains (family, table, name) of other tables hooked at input or forward,
    /// with that hook.
    hooked: Vec<(String, String, String, String)>,
    /// Those of them that drop: by policy or by a final reject/drop without matches.
    dropping: BTreeSet<(String, String, String)>,
    /// Where the jumps go: `"ufw"`, `"nftables"` (other dropping chains) or `"none"`.
    pub backend: &'static str,
    /// The tunnel interface is accepted on input / forwarded in / forwarded out by a rule of
    /// another table (for example `iptables -I INPUT -i rift0 -j ACCEPT`).
    pub input_open: bool,
    pub forward_in_open: bool,
    pub forward_out_open: bool,
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
    /// TLS proxies in front of the panel (RIFT_WEBPANEL_PROXIES), for example a proxy in a
    /// Docker network: they reach the panel on the server's tunnel address.
    pub panel_proxies: &'a [ipnet::IpNet],
    /// The name server's port (`RIFT_NAMES_PORT`), opened on the tunnel while `vpn` is set.
    pub names_port: u16,
    /// Devices that may reach the VPS itself (`rift vpn allow DEVICE rs`): the source is the
    /// device. RIFT's own ports stay closed in the RIFT table.
    pub server_grants: &'a [AgentVpnRule],
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
    /// Links this agent opens to other agents: their replies come in on the tunnel.
    pub outbound: &'a [crate::model::AgentOutboundRule],
    /// RIFT's name server, while the agent's host resolves the names of linked agents.
    pub names: Option<std::net::SocketAddr>,
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
    observe_for(document, "rift0")
}

/// Like `observe`, and also notes catch-all rejects (as on Oracle Cloud images) and rules of
/// other tables that already accept `interface`.
pub fn observe_for(document: &Value, interface: &str) -> Result<Observation> {
    let entries = document
        .get("nftables")
        .and_then(Value::as_array)
        .context("nftables JSON has no nftables array")?;
    let mut obs = Observation::default();
    for entry in entries {
        if let Some(chain) = entry.get("chain") {
            observe_chain(&mut obs, chain);
        }
    }
    for entry in entries {
        if let Some(rule) = entry.get("rule") {
            observe_rule(&mut obs, rule);
            observe_base_rule(&mut obs, rule, interface);
        }
    }
    let ufw = !obs.input.is_empty() || !obs.forward.is_empty();
    if !ufw {
        for (family, table, name, hook) in &obs.hooked {
            if !obs
                .dropping
                .contains(&(family.clone(), table.clone(), name.clone()))
            {
                continue;
            }
            let chain = ChainRef {
                family: family.clone(),
                table: table.clone(),
                name: name.clone(),
            };
            match hook.as_str() {
                "input" => obs.input.push(chain),
                _ => obs.forward.push(chain),
            }
        }
    }
    obs.backend = if ufw {
        "ufw"
    } else if obs.input.is_empty() && obs.forward.is_empty() {
        "none"
    } else {
        "nftables"
    };
    Ok(obs)
}

/// A rule in a hooked input/forward chain of another table: a final `reject`/`drop` without
/// matches counts like a drop policy; an `accept` matching the tunnel interface opens it.
fn observe_base_rule(obs: &mut Observation, rule: &Value, interface: &str) {
    let Some(reference) = chain_ref(rule) else {
        return;
    };
    if reference.table == "rift" {
        return;
    }
    let Some(hook) = obs
        .hooked
        .iter()
        .find(|(f, t, n, _)| {
            *f == reference.family && *t == reference.table && *n == reference.name
        })
        .map(|(_, _, _, hook)| hook.clone())
    else {
        return;
    };
    let Some(expr) = rule.get("expr").and_then(Value::as_array) else {
        return;
    };
    let has = |key: &str| expr.iter().any(|e| e.get(key).is_some());
    let matches_iface = |key: &str| {
        expr.iter().any(|e| {
            e.get("match").is_some_and(|m| {
                m["left"]["meta"]["key"] == key && m["right"] == interface && m["op"] == "=="
            })
        })
    };
    let plain = !has("match");
    if plain && (has("reject") || has("drop")) {
        obs.dropping
            .insert((reference.family, reference.table, reference.name));
        match hook.as_str() {
            "input" => obs.input_policy_drop = true,
            "forward" => obs.forward_policy_drop = true,
            _ => {}
        }
    }
    if has("accept") && expr.iter().filter(|e| e.get("match").is_some()).count() == 1 {
        match hook.as_str() {
            "input" if matches_iface("iifname") => obs.input_open = true,
            "forward" if matches_iface("iifname") => obs.forward_in_open = true,
            "forward" if matches_iface("oifname") => obs.forward_out_open = true,
            _ => {}
        }
    }
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
        // VPN devices that use RIFT's names send DNS to port 53 of the server's tunnel address;
        // nftables redirects it to the name server's port, which is what this chain sees.
        if spec.vpn && (chain.family == "ip" || chain.family == "inet") {
            for protocol in ["udp", "tcp"] {
                rules.push(format!(
                    "iifname \"{}\" ip daddr {} {protocol} dport {} accept comment \"rift:names\"",
                    spec.interface, spec.server_v4, spec.names_port
                ));
            }
        }
        if chain.family == "ip" || chain.family == "inet" {
            for rule in spec.server_grants {
                rules.extend(vpn_accepts(
                    spec.interface,
                    spec.server_v4,
                    rule,
                    "rift:server",
                ));
            }
        }
        if let Some(panel) = spec.panel {
            if chain.family == "ip" || chain.family == "inet" {
                rules.push(format!(
                    "iifname \"{}\" ip daddr {} tcp dport {} accept comment \"rift:panel\"",
                    spec.interface, spec.server_v4, panel.port
                ));
                for net in spec.panel_proxies.iter().filter(|net| net.addr().is_ipv4()) {
                    rules.push(format!(
                        "ip saddr {net} ip daddr {} tcp dport {} accept comment \"rift:panel\"",
                        spec.server_v4, panel.port
                    ));
                }
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
            // Uplink traffic to the tunnel is already accepted above, so one negated match is
            // enough; iptables, which reads these tables too, keeps only one `-i` per rule.
            rules.push(format!(
                "iifname != \"{0}\" oifname \"{0}\" accept comment \"rift:local\"",
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
                rules.extend(vpn_accepts(
                    spec.interface,
                    spec.tunnel_v4,
                    rule,
                    "rift:vpn",
                ));
            }
            // Replies of links this agent opened. That they are replies is enforced in the
            // RIFT table; a `ct` match here would make the table unreadable for iptables.
            for rule in spec.outbound {
                let from = format!(
                    "iifname \"{}\" ip saddr {} ip daddr {}",
                    spec.interface, rule.destination, spec.tunnel_v4
                );
                match &rule.access {
                    crate::model::VpnAccess::Port { protocol, ports } => rules.push(format!(
                        "{from} meta l4proto {protocol} {protocol} sport {ports} accept comment \"rift:link\""
                    )),
                    crate::model::VpnAccess::Server => {
                        for protocol in ["tcp", "udp", "icmp"] {
                            rules.push(format!(
                                "{from} meta l4proto {protocol} accept comment \"rift:link\""
                            ));
                        }
                    }
                    _ => rules.push(format!("{from} accept comment \"rift:link\"")),
                }
            }
            if let Some(std::net::SocketAddr::V4(server)) = spec.names {
                for protocol in ["udp", "tcp"] {
                    rules.push(format!(
                        "iifname \"{}\" ip saddr {} ip daddr {} meta l4proto {protocol} {protocol} sport {} accept comment \"rift:names\"",
                        spec.interface,
                        server.ip(),
                        spec.tunnel_v4,
                        server.port()
                    ));
                }
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

/// Accepts for one grant of a device on `address`. iptables has no protocol sets, so the
/// whole-host grant becomes one rule per protocol.
fn vpn_accepts(
    interface: &str,
    address: Ipv4Addr,
    rule: &AgentVpnRule,
    comment: &str,
) -> Vec<String> {
    if rule.access == crate::model::VpnAccess::Server {
        return ["tcp", "udp", "icmp"]
            .iter()
            .map(|protocol| {
                format!(
                    "iifname \"{interface}\" ip saddr {} ip daddr {address} meta l4proto {protocol} accept comment \"{comment}\"",
                    rule.source
                )
            })
            .collect();
    }
    vec![format!(
        "iifname \"{interface}\" {}accept comment \"{comment}\"",
        crate::vpn::flow_match(rule.source, address, &rule.access)
    )]
}

/// Forwarding between an exit interface and the uplinks. Only replies may come back, but
/// that is enforced in the RIFT table: these rules sit in tables that `iptables` also reads
/// (UFW, `iptables-nft`), and a native `ct state` match makes such a table unreadable for it.
fn exit_rules(interface: &str, uplinks: &[String]) -> Vec<String> {
    if uplinks.is_empty() {
        return vec![
            format!(
                "iifname \"{interface}\" oifname != \"{interface}\" accept comment \"rift:exit\""
            ),
            format!(
                "iifname != \"{interface}\" oifname \"{interface}\" accept comment \"rift:exit\""
            ),
        ];
    }
    uplinks
        .iter()
        .flat_map(|uplink| {
            [
                format!(
                    "iifname \"{interface}\" oifname \"{uplink}\" accept comment \"rift:exit\""
                ),
                format!(
                    "iifname \"{uplink}\" oifname \"{interface}\" accept comment \"rift:exit\""
                ),
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
    let mut warnings = Vec::new();
    let blocks = (obs.input_policy_drop && !obs.input_open)
        || (obs.forward_policy_drop && !(obs.forward_in_open && obs.forward_out_open));
    if mode == "off" && blocks {
        warnings.push(
            "host_firewall is off and another firewall drops tunnel, WireGuard or forwarded traffic; set host_firewall = \"auto\" or open it yourself."
                .to_string(),
        );
    }
    if mode == "auto" && public_ips_configured && uplinks.is_empty() && !obs.forward.is_empty() {
        warnings.push(
            "No local interface owns a configured public IP, so the host firewall was opened only on the tunnel."
                .to_string(),
        );
    }
    DoctorReport {
        status: json!({
            "mode": mode,
            "backend": obs.backend,
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
        let filter = chain
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("filter")
            == "filter";
        let family_ok = matches!(reference.family.as_str(), "ip" | "ip6" | "inet");
        if (hook == "input" || hook == "forward")
            && filter
            && family_ok
            && reference.table != "rift"
        {
            obs.hooked.push((
                reference.family.clone(),
                reference.table.clone(),
                reference.name.clone(),
                hook.to_string(),
            ));
            if policy == "drop" {
                obs.dropping.insert((
                    reference.family.clone(),
                    reference.table.clone(),
                    reference.name.clone(),
                ));
            }
        }
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

    #[test]
    fn agent_ufw_lets_in_the_replies_of_links_this_agent_opens() {
        let obs = observe(&ruleset()).unwrap();
        let outbound = [
            crate::model::AgentOutboundRule {
                destination: Ipv4Addr::new(10, 88, 0, 3),
                access: crate::model::VpnAccess::Port {
                    protocol: crate::model::Protocol::Tcp,
                    ports: crate::model::PortRange { start: 22, end: 22 },
                },
            },
            crate::model::AgentOutboundRule {
                destination: Ipv4Addr::new(10, 88, 0, 4),
                access: crate::model::VpnAccess::Server,
            },
        ];
        let plan = plan_agent(
            &obs,
            &AgentSpec {
                interface: "rift0",
                tunnel_v4: Ipv4Addr::new(10, 88, 0, 2),
                tunnel_v6: "fd88:5249:4654::2".parse().unwrap(),
                forwards: &[],
                vpn: &[],
                outbound: &outbound,
                names: Some("10.88.0.1:53053".parse().unwrap()),
                exit: None,
            },
        )
        .unwrap();
        assert!(plan.fill.contains("iifname \"rift0\" ip saddr 10.88.0.3 ip daddr 10.88.0.2 meta l4proto tcp tcp sport 22 accept comment \"rift:link\""), "{}", plan.fill);
        for protocol in ["tcp", "udp", "icmp"] {
            assert!(plan.fill.contains(&format!("iifname \"rift0\" ip saddr 10.88.0.4 ip daddr 10.88.0.2 meta l4proto {protocol} accept comment \"rift:link\"")), "{}", plan.fill);
        }
        assert!(
            !plan.fill.contains("ct state"),
            "iptables must still read the table"
        );
    }
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
            panel_proxies: &[],
            names_port: 53053,
            server_grants: &[],
            exit: false,
        }
    }

    fn oracle_like(input_accepts_rift0: bool, forward_open: bool) -> Value {
        let chain = |name: &str, hook: &str| json!({"chain": {"family": "ip", "table": "filter", "name": name, "hook": hook, "policy": "accept"}});
        let accept = |chain: &str, key: &str| {
            json!({"rule": {"family": "ip", "table": "filter", "chain": chain, "expr": [
                {"match": {"op": "==", "left": {"meta": {"key": key}}, "right": "rift0"}},
                {"counter": {"packets": 0, "bytes": 0}},
                {"accept": null}
            ]}})
        };
        let reject = |chain: &str| {
            json!({"rule": {"family": "ip", "table": "filter", "chain": chain, "expr": [
                {"counter": {"packets": 0, "bytes": 0}},
                {"reject": {"type": "icmp", "expr": "host-prohibited"}}
            ]}})
        };
        let mut entries = vec![chain("INPUT", "input"), chain("FORWARD", "forward")];
        if input_accepts_rift0 {
            entries.push(accept("INPUT", "iifname"));
        }
        if forward_open {
            entries.push(accept("FORWARD", "iifname"));
            entries.push(accept("FORWARD", "oifname"));
        }
        entries.push(reject("INPUT"));
        entries.push(reject("FORWARD"));
        json!({"nftables": entries})
    }

    #[test]
    fn without_ufw_the_jumps_go_in_front_of_a_final_reject() {
        let obs = observe_for(&oracle_like(false, false), "rift0").unwrap();
        assert_eq!(obs.backend, "nftables");
        let uplinks = vec!["ens3".to_string()];
        let plan = plan_server(&obs, &server_spec(&uplinks)).unwrap();
        assert!(plan.create.contains("add chain ip filter rift-host-in"));
        assert!(plan.create.contains("add chain ip filter rift-host-fwd"));
        assert!(plan
            .jumps
            .contains("insert rule ip filter INPUT jump rift-host-in comment \"rift:jump\""));
        assert!(plan
            .jumps
            .contains("insert rule ip filter FORWARD jump rift-host-fwd comment \"rift:jump\""));
        assert!(plan
            .fill
            .contains("iifname \"ens3\" udp dport 51820 accept comment \"rift:wireguard\""));
        assert!(report("auto", &obs, &uplinks, true).warnings.is_empty());
        // With the firewall integration off, the block is reported instead.
        assert_eq!(report("off", &obs, &uplinks, true).warnings.len(), 1);
    }

    #[test]
    fn plans_use_only_matches_that_iptables_can_read() {
        // UFW and iptables-nft read these tables back; a native conntrack match ("ct ...")
        // makes the whole table unreadable for iptables.
        let obs = observe_for(&oracle_like(false, false), "rift0").unwrap();
        let uplinks = vec!["ens3".to_string()];
        let mut spec = server_spec(&uplinks);
        spec.vpn = true;
        spec.exit = true;
        spec.local_ingress = true;
        spec.panel = Some(PanelSpec {
            port: 8090,
            public: true,
        });
        let server = plan_server(&obs, &spec).unwrap();
        let vpn = [AgentVpnRule {
            source: "10.14.0.2".parse().unwrap(),
            access: crate::model::VpnAccess::Server,
        }];
        let agent = plan_agent(
            &obs,
            &AgentSpec {
                interface: "rift0",
                tunnel_v4: "10.88.0.2".parse().unwrap(),
                tunnel_v6: "fd88:5249:4654::2".parse().unwrap(),
                forwards: &[],
                vpn: &vpn,
                outbound: &[],
                names: None,
                exit: Some(ExitSpec {
                    interface: "rift-exit",
                    uplinks: &uplinks,
                }),
            },
        )
        .unwrap();
        for plan in [&server, &agent] {
            let all = format!("{}{}{}", plan.create, plan.fill, plan.jumps);
            assert!(!all.contains(" ct ") && !all.contains('{'), "{all}");
            for line in all.lines() {
                assert!(line.matches("iifname").count() <= 1, "{line}");
                assert!(line.matches("oifname").count() <= 1, "{line}");
            }
        }
        if let Ok(path) = std::env::var("RIFT_DUMP_PLAN") {
            let agent = agent
                .fill
                .replace("rift-host-in", "agent-in")
                .replace("rift-host-fwd", "agent-fwd");
            let dump = format!(
                "{}{}{}add chain ip filter agent-in\nadd chain ip filter agent-fwd\n{agent}",
                server.create, server.fill, server.jumps
            );
            std::fs::write(path, dump).unwrap();
        }
    }

    #[test]
    fn chains_that_do_not_drop_and_nat_chains_are_left_alone() {
        let obs = observe(&json!({"nftables": [
            {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "type": "filter", "hook": "input", "policy": "accept"}},
            {"chain": {"family": "ip", "table": "nat", "name": "INPUT", "type": "nat", "hook": "input", "policy": "drop"}},
            {"chain": {"family": "inet", "table": "rift", "name": "input", "type": "filter", "hook": "input", "policy": "drop"}}
        ]}))
        .unwrap();
        assert_eq!(obs.backend, "none");
        assert!(obs.input.is_empty() && obs.forward.is_empty());
    }

    #[test]
    fn ufw_wins_over_its_own_base_chains() {
        let obs = observe(&ruleset()).unwrap();
        assert_eq!(obs.backend, "ufw");
        assert!(obs.input.iter().all(|c| c.name.starts_with("ufw")));
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
        // A proxy in a Docker network reaches the private panel on the tunnel address only.
        let proxies = ["10.255.13.0/24".parse().unwrap()];
        spec.panel_proxies = &proxies;
        spec.panel = Some(PanelSpec {
            port: 8090,
            public: false,
        });
        let proxied = plan_server(&obs, &spec).unwrap();
        assert!(proxied.fill.contains(
            "ip saddr 10.255.13.0/24 ip daddr 10.88.0.1 tcp dport 8090 accept comment \"rift:panel\""
        ));
        assert!(!proxied.fill.contains("iifname \"eth0\" tcp dport 8090"));
    }

    #[test]
    fn vpn_devices_reach_the_name_server_through_a_closed_firewall() {
        let obs = observe(&ruleset()).unwrap();
        let uplinks = vec!["eth0".to_string()];
        let mut spec = server_spec(&uplinks);
        assert!(!plan_server(&obs, &spec)
            .unwrap()
            .fill
            .contains("rift:names"));
        spec.vpn = true;
        let plan = plan_server(&obs, &spec).unwrap();
        for protocol in ["udp", "tcp"] {
            assert!(
                plan.fill.contains(&format!(
                    "iifname \"rift0\" ip daddr 10.88.0.1 {protocol} dport 53053 accept comment \"rift:names\""
                )),
                "{}",
                plan.fill
            );
        }
        // Only through the tunnel: the uplink stays closed.
        assert!(!plan.fill.contains("iifname \"eth0\" udp dport 53053"));
    }

    #[test]
    fn local_ingress_accepts_forwarding_that_did_not_arrive_on_the_uplink() {
        let obs = observe(&ruleset()).unwrap();
        let uplinks = vec!["eth0".to_string()];
        let mut spec = server_spec(&uplinks);
        spec.local_ingress = true;
        let plan = plan_server(&obs, &spec).unwrap();
        assert!(plan
            .fill
            .contains("iifname != \"rift0\" oifname \"rift0\" accept comment \"rift:local\""));
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
            agent_id: "node1".into(),
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
            allow_from: Vec::new(),
        };
        let plan = plan_agent(
            &obs,
            &AgentSpec {
                interface: "rift0",
                tunnel_v4: Ipv4Addr::new(10, 88, 0, 2),
                tunnel_v6: "fd88:5249:4654::2".parse().unwrap(),
                forwards: &[&forward],
                vpn: &[],
                outbound: &[],
                names: None,
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
    fn devices_reach_the_vps_itself_through_a_closed_firewall_only_as_granted() {
        let obs = observe(&ruleset()).unwrap();
        let uplinks = vec!["eth0".to_string()];
        let grants = [
            AgentVpnRule {
                source: Ipv4Addr::new(10, 14, 0, 2),
                access: crate::model::VpnAccess::Port {
                    protocol: crate::model::Protocol::Tcp,
                    ports: crate::model::PortRange { start: 22, end: 22 },
                },
            },
            AgentVpnRule {
                source: Ipv4Addr::new(10, 14, 0, 3),
                access: crate::model::VpnAccess::Server,
            },
        ];
        let mut spec = server_spec(&uplinks);
        assert!(!plan_server(&obs, &spec)
            .unwrap()
            .fill
            .contains("rift:server"));
        spec.server_grants = &grants;
        let plan = plan_server(&obs, &spec).unwrap();
        assert!(plan.fill.contains("iifname \"rift0\" ip saddr 10.14.0.2 ip daddr 10.88.0.1 meta l4proto tcp tcp dport 22 accept comment \"rift:server\""), "{}", plan.fill);
        for protocol in ["tcp", "udp", "icmp"] {
            assert!(plan.fill.contains(&format!("iifname \"rift0\" ip saddr 10.14.0.3 ip daddr 10.88.0.1 meta l4proto {protocol} accept comment \"rift:server\"")), "{}", plan.fill);
        }
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
                outbound: &[],
                names: None,
                exit: None,
            },
        )
        .unwrap();
        for protocol in ["tcp", "udp", "icmp"] {
            assert!(plan.fill.contains(&format!("iifname \"rift0\" ip saddr 10.14.0.2 ip daddr 10.88.0.2 meta l4proto {protocol} accept comment \"rift:vpn\"")));
        }
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
        assert!(plan
            .fill
            .contains("iifname \"eth0\" oifname \"rift0\" accept comment \"rift:exit\""));
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
            outbound: &[],
            names: None,
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
        assert!(plan
            .fill
            .contains("iifname \"enp3s0\" oifname \"rift-exit\" accept comment \"rift:exit\""));
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
    fn a_dropping_forward_chain_without_ufw_gets_the_jump() {
        let obs = observe(&json!({"nftables": [
            {"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "hook": "forward", "policy": "drop"}}
        ]}))
        .unwrap();
        let report = report("auto", &obs, &[], false);
        assert_eq!(report.status["backend"], "nftables");
        assert!(report.warnings.is_empty());
        assert_eq!(obs.forward.len(), 1);
        assert!(obs.input.is_empty());
    }
}
