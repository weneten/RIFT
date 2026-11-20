//! Settings that can be moved between installations: export, import and the repair of
//! forwards whose server address no longer exists. Everything here is pure; `daemon.rs`
//! applies the result.
//!
//! An export holds no keys, tokens or IDs. Agents are named, never created: they need their
//! own enrollment, so an import only fills agents that already exist and are active.

use crate::{config::validate_name, model::*, vpn};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::IpAddr};

/// Version of the export file. A file with another number is refused.
pub const FORMAT: u32 = 2;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportForward {
    pub agent: String,
    pub listen_ip: IpAddr,
    pub listen_ports: PortRange,
    pub target_ports: PortRange,
    pub protocol: Protocol,
    pub mode: ForwardMode,
    pub ingress: Ingress,
    pub target_family: Family,
    pub enabled: bool,
    /// Client addresses that may use the forward; empty means every client.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_from: Vec<ipnet::IpNet>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportGrant {
    pub agent: String,
    pub access: VpnAccess,
}
/// A link between two agents, by name (`rift link allow FROM TO TARGET`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportLink {
    pub from: String,
    pub to: String,
    pub access: VpnAccess,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportDevice {
    pub name: String,
    pub enabled: bool,
    pub panel: bool,
    pub grants: Vec<ExportGrant>,
    /// The main profile sends all traffic through the server.
    pub server_exit: bool,
    /// Names of the agents that each end an extra profile.
    pub agent_exits: Vec<String>,
    /// The device does not use RIFT's names (`rift vpn names device NAME off`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub names_off: bool,
}
/// Added by the host helper; the server process knows nothing about sites.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportSite {
    pub agent: String,
    pub host: String,
    pub port: u16,
    pub proxy: String,
    /// Client addresses the proxy lets through; empty means every client.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_from: Vec<ipnet::IpNet>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Export {
    pub format: u32,
    pub agents: Vec<String>,
    /// Agents with names on (`NAME.internal`). Older export files have none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub named_agents: Vec<String>,
    pub forwards: Vec<ExportForward>,
    pub devices: Vec<ExportDevice>,
    pub sites: Vec<ExportSite>,
    /// What the server host itself may reach on agents (`rift host allow`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_grants: Vec<ExportGrant>,
    /// What agents may reach on other agents (`rift link allow`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<ExportLink>,
}
impl Export {
    /// Reads an export file; refuses any other format.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: serde_json::Value =
            serde_json::from_slice(bytes).context("this is not a RIFT export file (not JSON)")?;
        match value.get("format").and_then(serde_json::Value::as_u64) {
            Some(n) if n == u64::from(FORMAT) => {}
            Some(n) => bail!(
                "this file has export format {n}, but this rift reads format {FORMAT}; export again with the same rift version"
            ),
            None => bail!("this is not a RIFT export file (no \"format\" field)"),
        }
        serde_json::from_value(value).context("the export file is damaged or incomplete")
    }
}

/// The settings of this installation. Pending agents have no identity yet and are left out.
pub fn export(snap: &StateSnapshot) -> Export {
    let name = |id: &str| {
        snap.agents
            .iter()
            .find(|a| a.id == id)
            .map(|a| a.name.clone())
    };
    // The forwards of internet exits follow from the devices and are not exported.
    let mut forwards: Vec<_> = snap
        .forwards
        .iter()
        .filter(|f| f.purpose == Purpose::User)
        .collect();
    forwards.sort_by_key(|f| f.id);
    Export {
        format: FORMAT,
        agents: snap
            .agents
            .iter()
            .filter(|a| a.status != AgentStatus::Pending)
            .map(|a| a.name.clone())
            .collect(),
        named_agents: snap
            .agents
            .iter()
            .filter(|a| a.status != AgentStatus::Pending && a.names)
            .map(|a| a.name.clone())
            .collect(),
        forwards: forwards
            .into_iter()
            .filter_map(|f| {
                Some(ExportForward {
                    agent: name(&f.agent_id)?,
                    listen_ip: f.listen_ip,
                    listen_ports: f.listen_ports,
                    target_ports: f.target_ports,
                    protocol: f.protocol,
                    mode: f.mode,
                    ingress: f.ingress,
                    target_family: f.target_family,
                    enabled: f.enabled,
                    allow_from: f.allow_from.clone(),
                })
            })
            .collect(),
        devices: snap
            .vpn_peers
            .iter()
            .map(|p| ExportDevice {
                name: p.name.clone(),
                enabled: p.enabled,
                panel: p.panel,
                grants: snap
                    .vpn_grants
                    .iter()
                    .filter(|g| g.peer == p.name)
                    .filter_map(|g| {
                        Some(ExportGrant {
                            agent: name(&g.agent_id)?,
                            access: g.access.clone(),
                        })
                    })
                    .collect(),
                server_exit: p.server_exit,
                agent_exits: p.agent_exits.iter().filter_map(|id| name(id)).collect(),
                names_off: p.names_off,
            })
            .collect(),
        sites: Vec::new(),
        host_grants: snap
            .host_grants
            .iter()
            .filter_map(|g| {
                Some(ExportGrant {
                    agent: name(&g.agent_id)?,
                    access: g.access.clone(),
                })
            })
            .collect(),
        links: snap
            .agent_links
            .iter()
            .filter_map(|l| {
                Some(ExportLink {
                    from: name(&l.from_agent_id)?,
                    to: name(&l.to_agent_id)?,
                    access: l.access.clone(),
                })
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------------------
// Server addresses

/// `ip` itself when the server has it, else the first configured address of the same IP
/// version; `None` when there is no such address.
pub fn remap_listen_ip(ip: IpAddr, public_ips: &[IpAddr]) -> Option<IpAddr> {
    if public_ips.contains(&ip) {
        return Some(ip);
    }
    public_ips
        .iter()
        .find(|candidate| candidate.is_ipv4() == ip.is_ipv4())
        .copied()
}

pub struct ListenMove {
    pub id: u64,
    pub from: IpAddr,
    pub to: IpAddr,
}
#[derive(Default)]
pub struct ListenFix {
    pub moves: Vec<ListenMove>,
    /// Forwards that would collide with another forward on the new address; they stay put.
    pub blocked: Vec<u64>,
}

/// Which forwards listen on an address the server does not have any more (a new VPS) and
/// where they can go. A forward that finds no address of its family, or whose ports are
/// taken there, stays where it is.
pub fn fix_listen_ips(forwards: &[Forward], public_ips: &[IpAddr]) -> ListenFix {
    let mut fix = ListenFix::default();
    if public_ips.is_empty() {
        return fix;
    }
    // (id, ip) of every forward as it will be after the moves decided so far.
    let mut current: Vec<(u64, IpAddr)> = forwards.iter().map(|f| (f.id, f.listen_ip)).collect();
    for forward in forwards
        .iter()
        .filter(|f| !public_ips.contains(&f.listen_ip))
    {
        let Some(to) = remap_listen_ip(forward.listen_ip, public_ips) else {
            continue;
        };
        let taken = forwards.iter().any(|other| {
            other.id != forward.id
                && current.iter().any(|(id, ip)| *id == other.id && *ip == to)
                && other.protocol == forward.protocol
                && other.listen_ports.overlaps(forward.listen_ports)
        });
        if taken {
            fix.blocked.push(forward.id);
            continue;
        }
        if let Some(entry) = current.iter_mut().find(|(id, _)| *id == forward.id) {
            entry.1 = to;
        }
        fix.moves.push(ListenMove {
            id: forward.id,
            from: forward.listen_ip,
            to,
        });
    }
    fix
}

/// The snapshot without forwards on addresses the server does not have. Applying them would
/// fail the whole configuration.
pub fn without_inapplicable(mut snap: StateSnapshot, public_ips: &[IpAddr]) -> StateSnapshot {
    if public_ips.is_empty() {
        return snap;
    }
    snap.forwards.retain(|f| public_ips.contains(&f.listen_ip));
    let forwards: BTreeSet<u64> = snap.forwards.iter().map(|f| f.id).collect();
    snap.bans.retain(|b| forwards.contains(&b.forward_id));
    snap
}

// ---------------------------------------------------------------------------------------
// Import

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ImportOptions {
    /// Only these agents (names after `map`); empty means all.
    pub agents: Vec<String>,
    /// Leave these agents out (names after `map`).
    pub skip_agents: Vec<String>,
    /// OLD to NEW: put the entries of agent OLD on agent NEW.
    pub map: Vec<(String, String)>,
    pub dry_run: bool,
}
impl ImportOptions {
    /// The agent name an entry ends up with.
    pub fn target<'a>(&'a self, name: &'a str) -> &'a str {
        self.map
            .iter()
            .rev()
            .find(|(old, _)| old == name)
            .map_or(name, |(_, new)| new)
    }
    /// Why the options leave this (already mapped) agent out, if they do.
    pub fn filtered(&self, mapped: &str) -> Option<String> {
        if !self.agents.is_empty() && !self.agents.iter().any(|a| a == mapped) {
            return Some("not selected with --agent".into());
        }
        self.skip_agents
            .iter()
            .any(|a| a == mapped)
            .then(|| "left out with --skip-agent".into())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Created,
    Present,
    Skipped,
    Failed,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Item {
    pub status: Status,
    pub what: String,
    pub detail: Option<String>,
}
impl Item {
    pub fn new(status: Status, what: impl Into<String>, detail: Option<String>) -> Self {
        Self {
            status,
            what: what.into(),
            detail,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub dry_run: bool,
    pub items: Vec<Item>,
}

pub enum Op {
    Forward(Forward),
    Device(String),
    Flags {
        name: String,
        enabled: Option<bool>,
        panel: Option<bool>,
        server_exit: Option<bool>,
        names_off: Option<bool>,
    },
    /// Turns on the names (`NAME.internal`) of this agent (by ID).
    AgentNames(String),
    Grant(VpnGrant),
    HostGrant(HostGrant),
    Link(AgentLink),
    /// Adds the exit profile through this agent (by ID) to the device.
    AgentExit {
        name: String,
        agent_id: String,
    },
}
/// Something the import will create. `daemon.rs` checks it against the machine, then applies.
pub struct Step {
    pub op: Op,
    pub what: String,
    pub detail: Option<String>,
}
#[derive(Default)]
pub struct Plan {
    pub steps: Vec<Step>,
    /// Outcomes that need no further work: already present, skipped, failed.
    pub items: Vec<Item>,
}

pub struct World<'a> {
    pub snap: &'a StateSnapshot,
    pub public_ips: &'a [IpAddr],
    pub panel_enabled: bool,
}

enum Resolved {
    Agent { id: String, name: String },
    Filtered { name: String, why: String },
    Unavailable { name: String, why: String },
}

/// Skipped entries counted per agent and reason, in order of first appearance.
#[derive(Default)]
struct Skips(Vec<(String, String, usize)>);
impl Skips {
    fn add(&mut self, agent: &str, why: &str) {
        match self.0.iter_mut().find(|(a, w, _)| a == agent && w == why) {
            Some(entry) => entry.2 += 1,
            None => self.0.push((agent.into(), why.into(), 1)),
        }
    }
    fn items(self) -> Vec<Item> {
        self.0
            .into_iter()
            .map(|(agent, why, n)| {
                Item::new(
                    Status::Skipped,
                    format!(
                        "{n} {} for agent {agent}",
                        if n == 1 { "entry" } else { "entries" }
                    ),
                    Some(why),
                )
            })
            .collect()
    }
}

fn resolve(options: &ImportOptions, ctx: &World, old: &str) -> Resolved {
    let name = options.target(old).to_string();
    if let Some(why) = options.filtered(&name) {
        return Resolved::Filtered { name, why };
    }
    let why = match ctx.snap.agents.iter().find(|a| a.name == name) {
        None => Some(format!(
            "no such agent; create it with `rift add agent {name}` or use --map {old}=NAME"
        )),
        Some(a) if a.status == AgentStatus::Pending => Some(format!(
            "its invitation is still open; run the import again once `rift list agents` shows {name} as active"
        )),
        Some(a) if a.status == AgentStatus::Disabled => Some(format!(
            "the agent is disabled; enable it with `rift enable agent {name}`"
        )),
        Some(_) => None,
    };
    match (why, ctx.snap.agents.iter().find(|a| a.name == name)) {
        (None, Some(agent)) => Resolved::Agent {
            id: agent.id.clone(),
            name,
        },
        (why, _) => Resolved::Unavailable {
            name,
            why: why.unwrap_or_default(),
        },
    }
}

pub fn describe_access(access: &VpnAccess) -> String {
    match access {
        VpnAccess::Server => "server".into(),
        VpnAccess::Full => "full".into(),
        VpnAccess::Port { protocol, ports } => format!("{ports}/{protocol}"),
        VpnAccess::Subnet { net, snat } => {
            format!("{net}{}", if *snat { " (snat)" } else { "" })
        }
        VpnAccess::Dns => "dns".into(),
    }
}
pub fn describe_forward(agent: &str, f: &Forward) -> String {
    let ports = if f.listen_ports == f.target_ports {
        f.listen_ports.to_string()
    } else {
        format!("{}:{}", f.listen_ports, f.target_ports)
    };
    let mut text = format!("forward {agent} {ports}/{} on {}", f.protocol, f.listen_ip);
    if f.mode == ForwardMode::Translate {
        text.push_str(", translated");
    }
    if f.ingress == Ingress::Local {
        text.push_str(", local ingress");
    }
    if !f.allow_from.is_empty() {
        let from: Vec<String> = f.allow_from.iter().map(ToString::to_string).collect();
        text.push_str(&format!(", from {}", from.join(" ")));
    }
    if !f.enabled {
        text.push_str(", disabled");
    }
    text
}

fn same_forward(a: &Forward, b: &Forward) -> bool {
    a.agent_id == b.agent_id
        && a.listen_ip == b.listen_ip
        && a.listen_ports == b.listen_ports
        && a.target_ports == b.target_ports
        && a.protocol == b.protocol
        && a.mode == b.mode
        && a.ingress == b.ingress
        && a.target_family == b.target_family
        && a.allow_from == b.allow_from
}

/// Decides what an import does: what it creates, what is there already, what it skips and
/// what cannot work. Nothing is changed.
pub fn plan(data: &Export, options: &ImportOptions, ctx: &World) -> Plan {
    let mut plan = Plan::default();
    let mut skips = Skips::default();
    let agent_name = |id: &str| -> String {
        ctx.snap
            .agents
            .iter()
            .find(|a| a.id == id)
            .map_or_else(|| id.to_string(), |a| a.name.clone())
    };
    let mut forwards: Vec<Forward> = ctx.snap.forwards.clone();
    for entry in &data.forwards {
        let (agent_id, agent) = match resolve(options, ctx, &entry.agent) {
            Resolved::Agent { id, name } => (id, name),
            Resolved::Filtered { name, why } | Resolved::Unavailable { name, why } => {
                skips.add(&name, &why);
                continue;
            }
        };
        let label = |ip: IpAddr| {
            format!(
                "forward {agent} {}:{}/{} on {ip}",
                entry.listen_ports, entry.target_ports, entry.protocol
            )
        };
        let Some(listen_ip) = remap_listen_ip(entry.listen_ip, ctx.public_ips) else {
            plan.items.push(Item::new(
                Status::Skipped,
                label(entry.listen_ip),
                Some(format!(
                    "the server has no {} address in RIFT_PUBLIC_IPS",
                    if entry.listen_ip.is_ipv4() {
                        "IPv4"
                    } else {
                        "IPv6"
                    }
                )),
            ));
            continue;
        };
        let forward = Forward {
            id: 0,
            agent_id,
            listen_ip,
            listen_ports: entry.listen_ports,
            target_ports: entry.target_ports,
            protocol: entry.protocol,
            mode: entry.mode,
            ingress: entry.ingress,
            target_family: entry.target_family,
            enabled: entry.enabled,
            generation: 0,
            purpose: Purpose::User,
            allow_from: entry.allow_from.clone(),
        };
        let what = describe_forward(&agent, &forward);
        if let Err(error) = forward.validate() {
            plan.items
                .push(Item::new(Status::Failed, what, Some(error.to_string())));
            continue;
        }
        if forwards.iter().any(|old| same_forward(old, &forward)) {
            plan.items.push(Item::new(Status::Present, what, None));
            continue;
        }
        if let Some(old) = forwards.iter().find(|old| {
            old.listen_ip == listen_ip
                && old.protocol == forward.protocol
                && old.listen_ports.overlaps(forward.listen_ports)
        }) {
            let other = if old.id == 0 {
                "another forward of this file".to_string()
            } else {
                format!("forward {}", old.id)
            };
            plan.items.push(Item::new(
                Status::Failed,
                what,
                Some(format!("the public port range overlaps {other}")),
            ));
            continue;
        }
        let detail = (listen_ip != entry.listen_ip).then(|| {
            format!(
                "the server has no address {}; used {listen_ip}",
                entry.listen_ip
            )
        });
        forwards.push(forward.clone());
        plan.steps.push(Step {
            op: Op::Forward(forward),
            what,
            detail,
        });
    }

    // Devices and their grants.
    let mut planned_grants: Vec<VpnGrant> = ctx.snap.vpn_grants.clone();
    for device in &data.devices {
        let what = format!("device {}", device.name);
        if let Err(error) = validate_name(&device.name) {
            plan.items
                .push(Item::new(Status::Failed, what, Some(error.to_string())));
            continue;
        }
        let resolved: Vec<Resolved> = device
            .grants
            .iter()
            .map(|g| resolve(options, ctx, &g.agent))
            .collect();
        let resolved_exits: Vec<Resolved> = device
            .agent_exits
            .iter()
            .map(|a| resolve(options, ctx, a))
            .collect();
        if !(resolved.is_empty() && resolved_exits.is_empty())
            && resolved
                .iter()
                .chain(&resolved_exits)
                .all(|r| matches!(r, Resolved::Filtered { .. }))
        {
            plan.items.push(Item::new(
                Status::Skipped,
                what,
                Some(
                    "all its grants and exits are for agents left out by --agent or --skip-agent"
                        .into(),
                ),
            ));
            continue;
        }
        let existing = ctx.snap.vpn_peers.iter().find(|p| p.name == device.name);
        let (enabled, panel, server_exit, names_off) = match existing {
            Some(p) => (
                (p.enabled != device.enabled).then_some(device.enabled),
                (p.panel != device.panel).then_some(device.panel),
                (p.server_exit != device.server_exit).then_some(device.server_exit),
                (p.names_off != device.names_off).then_some(device.names_off),
            ),
            None => (
                (!device.enabled).then_some(false),
                device.panel.then_some(true),
                device.server_exit.then_some(true),
                device.names_off.then_some(true),
            ),
        };
        let panel = if panel == Some(true) && !ctx.panel_enabled {
            plan.items.push(Item::new(
                Status::Failed,
                format!("device {}: panel access", device.name),
                Some("the web panel is off; set RIFT_WEBPANEL=true in the server .env".into()),
            ));
            None
        } else {
            panel
        };
        if existing.is_none() {
            plan.steps.push(Step {
                op: Op::Device(device.name.clone()),
                what: what.clone(),
                detail: Some(format!(
                    "new keys; re-import the device config: rift vpn config {}",
                    device.name
                )),
            });
        }
        if enabled.is_some() || panel.is_some() || server_exit.is_some() || names_off.is_some() {
            let mut changes = Vec::new();
            if let Some(on) = enabled {
                changes.push(if on { "enabled" } else { "disabled" });
            }
            if let Some(on) = panel {
                changes.push(if on {
                    "panel access on"
                } else {
                    "panel access off"
                });
            }
            if let Some(on) = server_exit {
                changes.push(if on {
                    "exit via this server on"
                } else {
                    "exit via this server off"
                });
            }
            if let Some(off) = names_off {
                changes.push(if off { "names off" } else { "names on" });
            }
            plan.steps.push(Step {
                op: Op::Flags {
                    name: device.name.clone(),
                    enabled,
                    panel,
                    server_exit,
                    names_off,
                },
                what: format!("{what}: {}", changes.join(", ")),
                detail: None,
            });
        } else if existing.is_some() {
            plan.items
                .push(Item::new(Status::Present, what.clone(), None));
        }
        for (grant, resolved) in device.grants.iter().zip(resolved) {
            let (agent_id, agent) = match resolved {
                Resolved::Agent { id, name } => (id, name),
                Resolved::Filtered { name, why } | Resolved::Unavailable { name, why } => {
                    skips.add(&name, &why);
                    continue;
                }
            };
            let what = format!(
                "grant {} to {agent}: {}",
                device.name,
                describe_access(&grant.access)
            );
            let candidate = VpnGrant {
                peer: device.name.clone(),
                agent_id,
                access: grant.access.clone(),
            };
            if planned_grants.contains(&candidate) {
                plan.items.push(Item::new(Status::Present, what, None));
                continue;
            }
            if let Err(error) = vpn::validate_access(&candidate.access) {
                plan.items
                    .push(Item::new(Status::Failed, what, Some(error.to_string())));
                continue;
            }
            if let VpnAccess::Subnet { net, .. } = &candidate.access {
                let clash = planned_grants.iter().find_map(|g| match &g.access {
                    VpnAccess::Subnet { net: o, .. }
                        if g.agent_id != candidate.agent_id
                            && (net.contains(o) || o.contains(net)) =>
                    {
                        Some((agent_name(&g.agent_id), *o))
                    }
                    _ => None,
                });
                if let Some((other_agent, other)) = clash {
                    plan.items.push(Item::new(
                        Status::Failed,
                        what,
                        Some(format!(
                            "the network overlaps {other}, which is granted behind agent {other_agent}"
                        )),
                    ));
                    continue;
                }
            }
            planned_grants.push(candidate.clone());
            plan.steps.push(Step {
                op: Op::Grant(candidate),
                what,
                detail: None,
            });
        }
        let mut planned_exits: Vec<String> =
            existing.map(|p| p.agent_exits.clone()).unwrap_or_default();
        for resolved in resolved_exits {
            let (agent_id, agent) = match resolved {
                Resolved::Agent { id, name } => (id, name),
                Resolved::Filtered { name, why } | Resolved::Unavailable { name, why } => {
                    skips.add(&name, &why);
                    continue;
                }
            };
            let what = format!("exit of {} via {agent}", device.name);
            if planned_exits.contains(&agent_id) {
                plan.items.push(Item::new(Status::Present, what, None));
                continue;
            }
            planned_exits.push(agent_id.clone());
            plan.steps.push(Step {
                op: Op::AgentExit {
                    name: device.name.clone(),
                    agent_id,
                },
                what,
                detail: Some(format!(
                    "import the extra profile: rift vpn config {} {agent}",
                    device.name
                )),
            });
        }
    }
    for entry in &data.named_agents {
        let (agent_id, agent) = match resolve(options, ctx, entry) {
            Resolved::Agent { id, name } => (id, name),
            Resolved::Filtered { name, why } | Resolved::Unavailable { name, why } => {
                skips.add(&name, &why);
                continue;
            }
        };
        let what = format!("names of agent {agent}");
        let Some(label) = vpn::dns_label(&agent) else {
            plan.items.push(Item::new(
                Status::Failed,
                what,
                Some("the name is not usable as a DNS name; rename the agent".into()),
            ));
            continue;
        };
        if ctx.snap.agents.iter().any(|a| a.id == agent_id && a.names) {
            plan.items.push(Item::new(Status::Present, what, None));
            continue;
        }
        plan.steps.push(Step {
            op: Op::AgentNames(agent_id),
            what,
            detail: Some(format!("{label}.{}", vpn::names_suffix())),
        });
    }
    let mut planned_host: Vec<HostGrant> = ctx.snap.host_grants.clone();
    for entry in &data.host_grants {
        let (agent_id, agent) = match resolve(options, ctx, &entry.agent) {
            Resolved::Agent { id, name } => (id, name),
            Resolved::Filtered { name, why } | Resolved::Unavailable { name, why } => {
                skips.add(&name, &why);
                continue;
            }
        };
        let what = format!("host access to {agent}: {}", describe_access(&entry.access));
        let candidate = HostGrant {
            agent_id,
            access: entry.access.clone(),
        };
        if planned_host.contains(&candidate) {
            plan.items.push(Item::new(Status::Present, what, None));
            continue;
        }
        let valid = matches!(
            candidate.access,
            VpnAccess::Server | VpnAccess::Full | VpnAccess::Port { .. }
        )
        .then(|| vpn::validate_access(&candidate.access))
        .unwrap_or_else(|| Err(anyhow::anyhow!("a host grant is server, full or a port")));
        if let Err(error) = valid {
            plan.items
                .push(Item::new(Status::Failed, what, Some(error.to_string())));
            continue;
        }
        planned_host.push(candidate.clone());
        plan.steps.push(Step {
            op: Op::HostGrant(candidate),
            what,
            detail: None,
        });
    }
    let mut planned_links: Vec<AgentLink> = ctx.snap.agent_links.clone();
    for entry in &data.links {
        let ends: Vec<(String, String)> = [&entry.from, &entry.to]
            .into_iter()
            .filter_map(|end| match resolve(options, ctx, end) {
                Resolved::Agent { id, name } => Some((id, name)),
                Resolved::Filtered { name, why } | Resolved::Unavailable { name, why } => {
                    skips.add(&name, &why);
                    None
                }
            })
            .collect();
        let Ok([(from_id, from), (to_id, to)]) = <[(String, String); 2]>::try_from(ends) else {
            continue;
        };
        let what = format!("link {from} -> {to}: {}", describe_access(&entry.access));
        let candidate = AgentLink {
            from_agent_id: from_id,
            to_agent_id: to_id,
            access: entry.access.clone(),
        };
        if planned_links.contains(&candidate) {
            plan.items.push(Item::new(Status::Present, what, None));
            continue;
        }
        let valid = if candidate.from_agent_id == candidate.to_agent_id {
            Err(anyhow::anyhow!("an agent needs no link to itself"))
        } else if matches!(
            candidate.access,
            VpnAccess::Server | VpnAccess::Full | VpnAccess::Port { .. }
        ) {
            vpn::validate_access(&candidate.access)
        } else {
            Err(anyhow::anyhow!("a link is server, full or a port"))
        };
        if let Err(error) = valid {
            plan.items
                .push(Item::new(Status::Failed, what, Some(error.to_string())));
            continue;
        }
        planned_links.push(candidate.clone());
        plan.steps.push(Step {
            op: Op::Link(candidate),
            what,
            detail: None,
        });
    }
    plan.items.extend(skips.items());
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn agent(name: &str, status: AgentStatus, n: u8) -> AgentRecord {
        AgentRecord {
            protocol: 0,
            rift_version: String::new(),
            names: false,
            id: format!("id-{name}"),
            name: name.into(),
            public_key: format!("key-{name}"),
            tunnel_ipv4: Ipv4Addr::new(10, 13, 0, n),
            tunnel_ipv6: Ipv6Addr::new(0xfd88, 0x5249, 0x4654, 0, 0, 0, 0, n.into()),
            status,
            attempt_id: format!("attempt-{name}"),
            generation: 0,
            applied_generation: 0,
            last_error: None,
            created_at: 0,
            pending_deadline: None,
            limits: None,
            exit: None,
            exit_port: None,
        }
    }
    fn entry(agent: &str, listen: u16, target: u16) -> ExportForward {
        ExportForward {
            agent: agent.into(),
            listen_ip: ip("203.0.113.10"),
            listen_ports: PortRange {
                start: listen,
                end: listen,
            },
            target_ports: PortRange {
                start: target,
                end: target,
            },
            protocol: Protocol::Tcp,
            mode: ForwardMode::Transparent,
            ingress: Ingress::Public,
            target_family: Family::V4,
            enabled: true,
            allow_from: Vec::new(),
        }
    }
    fn device(name: &str, grants: Vec<(&str, VpnAccess)>) -> ExportDevice {
        ExportDevice {
            names_off: false,
            name: name.into(),
            enabled: true,
            panel: false,
            grants: grants
                .into_iter()
                .map(|(agent, access)| ExportGrant {
                    agent: agent.into(),
                    access,
                })
                .collect(),
            server_exit: false,
            agent_exits: Vec::new(),
        }
    }
    fn file(forwards: Vec<ExportForward>, devices: Vec<ExportDevice>) -> Export {
        Export {
            named_agents: Vec::new(),
            format: FORMAT,
            agents: vec![],
            forwards,
            devices,
            sites: vec![],
            host_grants: vec![],
            links: vec![],
        }
    }
    fn world() -> StateSnapshot {
        StateSnapshot {
            agents: vec![
                agent("node1", AgentStatus::Active, 2),
                agent("node6", AgentStatus::Disabled, 3),
                agent("new", AgentStatus::Pending, 4),
            ],
            ..Default::default()
        }
    }
    fn run(data: &Export, options: &ImportOptions, snap: &StateSnapshot) -> Plan {
        plan(
            data,
            options,
            &World {
                snap,
                public_ips: &[ip("203.0.113.10"), ip("2001:db8::10")],
                panel_enabled: true,
            },
        )
    }
    fn count(plan: &Plan, status: Status) -> usize {
        plan.items.iter().filter(|i| i.status == status).count()
    }
    fn server() -> VpnAccess {
        VpnAccess::Server
    }

    #[test]
    fn export_names_agents_and_leaves_out_pending_ones_and_secrets() {
        let mut snap = world();
        snap.forwards.push(Forward {
            id: 7,
            agent_id: "id-node1".into(),
            listen_ip: ip("203.0.113.10"),
            listen_ports: "2222".parse().unwrap(),
            target_ports: "22".parse().unwrap(),
            protocol: Protocol::Tcp,
            mode: ForwardMode::Transparent,
            ingress: Ingress::Public,
            target_family: Family::V4,
            enabled: true,
            generation: 5,
            purpose: Purpose::User,
            allow_from: Vec::new(),
        });
        snap.vpn_peers.push(VpnPeer {
            names_off: false,
            name: "phone".into(),
            public_key: "SECRET-PUBLIC".into(),
            ipv4: Ipv4Addr::new(10, 14, 0, 2),
            enabled: false,
            created_at: 1,
            panel: true,
            server_exit: false,
            agent_exits: Vec::new(),
            ipv6: std::net::Ipv6Addr::LOCALHOST,
        });
        snap.vpn_grants.push(VpnGrant {
            peer: "phone".into(),
            agent_id: "id-node1".into(),
            access: server(),
        });
        let out = export(&snap);
        assert_eq!(out.agents, vec!["node1", "node6"]);
        assert_eq!(out.forwards.len(), 1);
        assert_eq!(out.forwards[0].agent, "node1");
        assert_eq!(out.devices[0].grants[0].agent, "node1");
        assert!(!out.devices[0].enabled && out.devices[0].panel);
        assert!(!out.devices[0].server_exit && out.devices[0].agent_exits.is_empty());
        let text = serde_json::to_string(&out).unwrap();
        for secret in [
            "SECRET-PUBLIC",
            "id-node1",
            "key-node1",
            "attempt",
            "10.14.0.2",
        ] {
            assert!(!text.contains(secret), "{secret} leaked into {text}");
        }
        let again = Export::parse(text.as_bytes()).unwrap();
        assert_eq!(again, out);
    }

    #[test]
    fn links_survive_an_export_and_an_import_round_trip_by_name() {
        let ssh = VpnAccess::Port {
            protocol: Protocol::Tcp,
            ports: "22".parse().unwrap(),
        };
        let mut snap = world();
        snap.agents.push(agent("node2", AgentStatus::Active, 5));
        snap.agent_links.push(AgentLink {
            from_agent_id: "id-node1".into(),
            to_agent_id: "id-node2".into(),
            access: ssh.clone(),
        });
        let out = export(&snap);
        assert_eq!(
            out.links,
            [ExportLink {
                from: "node1".into(),
                to: "node2".into(),
                access: ssh.clone()
            }]
        );
        let text = serde_json::to_string(&out).unwrap();
        assert!(!text.contains("id-node"), "{text}");
        assert_eq!(Export::parse(text.as_bytes()).unwrap(), out);

        let mut target = world();
        target.agents.push(agent("node2", AgentStatus::Active, 5));
        let planned = run(&out, &ImportOptions::default(), &target);
        assert!(planned.steps.iter().any(|s| matches!(
            &s.op,
            Op::Link(l) if l.from_agent_id == "id-node1" && l.to_agent_id == "id-node2" && l.access == ssh
        )));
        let again = run(&out, &ImportOptions::default(), &snap);
        assert!(again.steps.iter().all(|s| !matches!(s.op, Op::Link(_))));
        // An end that is missing or disabled skips the link and names why.
        let without = run(&out, &ImportOptions::default(), &world());
        assert!(without.steps.iter().all(|s| !matches!(s.op, Op::Link(_))));
        let mut to_disabled = out.clone();
        to_disabled.links[0].to = "node6".into();
        assert!(run(&to_disabled, &ImportOptions::default(), &target)
            .steps
            .iter()
            .all(|s| !matches!(s.op, Op::Link(_))));
        // A network or a link to itself is never a link, whatever the file says.
        for bad in [
            ExportLink {
                from: "node1".into(),
                to: "node2".into(),
                access: VpnAccess::Subnet {
                    net: "192.168.178.0/24".parse().unwrap(),
                    snat: false,
                },
            },
            ExportLink {
                from: "node1".into(),
                to: "node1".into(),
                access: VpnAccess::Server,
            },
        ] {
            let mut file = out.clone();
            file.links = vec![bad];
            let plan = run(&file, &ImportOptions::default(), &target);
            assert_eq!(count(&plan, Status::Failed), 1);
        }
        // Files without the field still parse.
        let mut old: serde_json::Value = serde_json::from_str(&text).unwrap();
        old.as_object_mut().unwrap().remove("links");
        assert!(Export::parse(old.to_string().as_bytes())
            .unwrap()
            .links
            .is_empty());
    }

    #[test]
    fn host_grants_survive_an_export_and_an_import_round_trip() {
        let ssh = VpnAccess::Port {
            protocol: Protocol::Tcp,
            ports: "22".parse().unwrap(),
        };
        let mut snap = world();
        snap.host_grants.push(HostGrant {
            agent_id: "id-node1".into(),
            access: ssh.clone(),
        });
        let out = export(&snap);
        assert_eq!(
            out.host_grants,
            [ExportGrant {
                agent: "node1".into(),
                access: ssh.clone()
            }]
        );
        let text = serde_json::to_string(&out).unwrap();
        assert!(!text.contains("id-node1"), "{text}");
        assert_eq!(Export::parse(text.as_bytes()).unwrap(), out);

        let planned = run(&out, &ImportOptions::default(), &world());
        assert!(planned.steps.iter().any(|s| matches!(
            &s.op,
            Op::HostGrant(g) if g.agent_id == "id-node1" && g.access == ssh
        )));
        let again = run(&out, &ImportOptions::default(), &snap);
        assert!(again.steps.is_empty() && count(&again, Status::Present) == 1);
        // A network is never a host grant, whatever the file says.
        let mut bad = out.clone();
        bad.host_grants[0].access = VpnAccess::Subnet {
            net: "192.168.178.0/24".parse().unwrap(),
            snat: false,
        };
        assert_eq!(
            count(
                &run(&bad, &ImportOptions::default(), &world()),
                Status::Failed
            ),
            1
        );
        // Files without the field still parse.
        let mut old: serde_json::Value = serde_json::from_str(&text).unwrap();
        old.as_object_mut().unwrap().remove("host_grants");
        assert!(Export::parse(old.to_string().as_bytes())
            .unwrap()
            .host_grants
            .is_empty());
    }

    #[test]
    fn names_survive_an_export_and_an_import_round_trip() {
        let mut snap = world();
        snap.agents[0].names = true;
        snap.vpn_peers.push(VpnPeer {
            names_off: true,
            name: "tablet".into(),
            public_key: "k".into(),
            ipv4: Ipv4Addr::new(10, 14, 0, 3),
            enabled: true,
            created_at: 1,
            panel: false,
            server_exit: false,
            agent_exits: Vec::new(),
            ipv6: std::net::Ipv6Addr::LOCALHOST,
        });
        let out = export(&snap);
        assert_eq!(out.named_agents, ["node1"]);
        assert!(out.devices[0].names_off);
        let text = serde_json::to_string(&out).unwrap();
        assert_eq!(Export::parse(text.as_bytes()).unwrap(), out);

        // Into an installation where node1 has names off and the device does not exist.
        let planned = run(&out, &ImportOptions::default(), &world());
        assert!(planned
            .steps
            .iter()
            .any(|s| matches!(&s.op, Op::AgentNames(id) if id == "id-node1")));
        assert!(planned.steps.iter().any(|s| matches!(
            &s.op,
            Op::Flags {
                names_off: Some(true),
                ..
            }
        )));
        // Where node1 already has names on: reported as present.
        let planned = run(&out, &ImportOptions::default(), &snap);
        assert!(!planned
            .steps
            .iter()
            .any(|s| matches!(&s.op, Op::AgentNames(_))));
        assert!(planned
            .items
            .iter()
            .any(|i| i.status == Status::Present && i.what.contains("names of agent node1")));
        // An export file from before names has neither field.
        let old = br#"{"format":2,"agents":["node1"],"forwards":[],"devices":[{"name":"p","enabled":true,"panel":false,"grants":[],"server_exit":false,"agent_exits":[]}],"sites":[]}"#;
        let parsed = Export::parse(old).unwrap();
        assert!(parsed.named_agents.is_empty() && !parsed.devices[0].names_off);
    }

    #[test]
    fn exits_survive_an_export_and_an_import_round_trip() {
        let mut snap = world();
        snap.agents.push(agent("node2", AgentStatus::Active, 5));
        snap.vpn_peers.push(VpnPeer {
            names_off: false,
            name: "phone".into(),
            public_key: "k".into(),
            ipv4: Ipv4Addr::new(10, 14, 0, 2),
            enabled: true,
            created_at: 1,
            panel: false,
            server_exit: true,
            agent_exits: vec!["id-node1".into(), "id-node2".into()],
            ipv6: std::net::Ipv6Addr::LOCALHOST,
        });
        let out = export(&snap);
        assert!(out.devices[0].server_exit);
        assert_eq!(out.devices[0].agent_exits, ["node1", "node2"]);
        let text = serde_json::to_string(&out).unwrap();
        assert!(!text.contains("id-node1"), "IDs stay out: {text}");
        assert_eq!(Export::parse(text.as_bytes()).unwrap(), out);

        // Into an installation without the device: it is created with all three exits.
        let mut target = world();
        target.agents.push(agent("node2", AgentStatus::Active, 5));
        let planned = run(&out, &ImportOptions::default(), &target);
        let flags = planned
            .steps
            .iter()
            .find_map(|s| match &s.op {
                Op::Flags { server_exit, .. } => Some(*server_exit),
                _ => None,
            })
            .unwrap();
        assert_eq!(flags, Some(true));
        let added: Vec<_> = planned
            .steps
            .iter()
            .filter_map(|s| match &s.op {
                Op::AgentExit { agent_id, .. } => Some(agent_id.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(added, ["id-node1", "id-node2"]);
        assert!(planned.steps.iter().any(|s| {
            s.detail
                .as_deref()
                .is_some_and(|d| d.contains("rift vpn config phone node2"))
        }));
        // Mapped, filtered and missing agents.
        let options = ImportOptions {
            map: vec![("node2".into(), "node1".into())],
            ..Default::default()
        };
        let planned = run(&out, &options, &target);
        let added = planned
            .steps
            .iter()
            .filter(|s| matches!(s.op, Op::AgentExit { .. }))
            .count();
        assert_eq!(added, 1, "both exits land on node1, which is added once");
        let options = ImportOptions {
            skip_agents: vec!["node2".into()],
            ..Default::default()
        };
        let planned = run(&out, &options, &target);
        assert_eq!(
            planned
                .steps
                .iter()
                .filter(|s| matches!(s.op, Op::AgentExit { .. }))
                .count(),
            1
        );
        assert!(planned
            .items
            .iter()
            .any(|i| i.what == "1 entry for agent node2"));
        let planned = run(&out, &ImportOptions::default(), &world());
        assert!(planned
            .items
            .iter()
            .any(|i| i.what == "1 entry for agent node2" && i.status == Status::Skipped));
        // Into one that has the device with the same exits: nothing to do for them.
        let mut same = target.clone();
        same.vpn_peers = snap.vpn_peers.clone();
        let planned = run(&out, &ImportOptions::default(), &same);
        assert!(planned.steps.is_empty(), "{:?}", planned.steps.len());
        assert_eq!(count(&planned, Status::Present), 3);
        // A device whose exits are all for left-out agents is skipped as a whole.
        let only = file(
            vec![],
            vec![ExportDevice {
                agent_exits: vec!["node2".into()],
                ..device("tablet", vec![])
            }],
        );
        let options = ImportOptions {
            skip_agents: vec!["node2".into()],
            ..Default::default()
        };
        let planned = run(&only, &options, &target);
        assert!(planned.steps.is_empty());
        assert!(planned
            .items
            .iter()
            .any(|i| i.what == "device tablet" && i.status == Status::Skipped));
    }

    #[test]
    fn other_formats_and_foreign_files_are_refused() {
        let error = Export::parse(br#"{"format":3,"agents":[]}"#).unwrap_err();
        assert!(error.to_string().contains("format 3"), "{error}");
        // Files of the single-exit version are refused with the way forward.
        let error =
            Export::parse(br#"{"format":1,"agents":[],"forwards":[],"devices":[]}"#).unwrap_err();
        assert!(
            error.to_string().contains("format 1") && error.to_string().contains("export again"),
            "{error}"
        );
        assert!(Export::parse(b"{}").is_err());
        assert!(Export::parse(b"not json").is_err());
        assert!(Export::parse(br#"{"format":2,"agents":[],"forwards":[],"devices":[]}"#).is_err());
        assert!(Export::parse(
            br#"{"format":2,"agents":[],"forwards":[],"devices":[],"sites":[]}"#
        )
        .is_ok());
    }

    #[test]
    fn unknown_and_inactive_agents_are_skipped_with_a_way_forward() {
        let data = file(
            vec![
                entry("node2", 80, 80),
                entry("node2", 81, 81),
                entry("node2", 82, 82),
                entry("node6", 90, 90),
                entry("new", 91, 91),
                entry("node1", 2222, 22),
            ],
            vec![],
        );
        let planned = run(&data, &ImportOptions::default(), &world());
        assert_eq!(planned.steps.len(), 1);
        let missing = planned
            .items
            .iter()
            .find(|i| i.what == "3 entries for agent node2")
            .expect("aggregated");
        let why = missing.detail.as_deref().unwrap();
        assert!(why.contains("rift add agent node2") && why.contains("--map node2=NAME"));
        assert!(planned.items.iter().any(|i| i
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("rift enable agent node6"))));
        assert!(planned
            .items
            .iter()
            .any(|i| i.what == "1 entry for agent new"));
    }

    #[test]
    fn map_retargets_and_filters_see_the_mapped_name() {
        let data = file(vec![entry("node2", 80, 80), entry("node1", 81, 81)], vec![]);
        let mapped = ImportOptions {
            map: vec![("node2".into(), "node1".into())],
            ..Default::default()
        };
        assert_eq!(run(&data, &mapped, &world()).steps.len(), 2);
        let only = ImportOptions {
            agents: vec!["node1".into()],
            map: vec![("node2".into(), "node6".into())],
            ..Default::default()
        };
        let planned = run(&data, &only, &world());
        assert_eq!(
            planned.steps.len(),
            1,
            "node2 became node6, which is not selected"
        );
        assert!(planned.items[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("--agent"));
        let skip = ImportOptions {
            skip_agents: vec!["node1".into()],
            map: vec![("node2".into(), "node1".into())],
            ..Default::default()
        };
        assert_eq!(run(&data, &skip, &world()).steps.len(), 0);
        // The last mapping of an agent wins.
        let twice = ImportOptions {
            map: vec![("a".into(), "b".into()), ("a".into(), "node1".into())],
            ..Default::default()
        };
        assert_eq!(twice.target("a"), "node1");
        assert_eq!(twice.target("z"), "z");
    }

    #[test]
    fn identical_forwards_are_present_and_conflicts_fail_one_by_one() {
        let mut snap = world();
        let mut old = entry("node1", 2222, 22);
        snap.forwards.push(Forward {
            id: 1,
            agent_id: "id-node1".into(),
            listen_ip: old.listen_ip,
            listen_ports: old.listen_ports,
            target_ports: old.target_ports,
            protocol: old.protocol,
            mode: old.mode,
            ingress: old.ingress,
            target_family: old.target_family,
            enabled: false,
            generation: 1,
            purpose: Purpose::User,
            allow_from: Vec::new(),
        });
        old.enabled = true;
        let clash = entry("node1", 2222, 23);
        let data = file(
            vec![
                old,
                clash,
                entry("node1", 8080, 80),
                entry("node1", 8080, 81),
            ],
            vec![],
        );
        let planned = run(&data, &ImportOptions::default(), &snap);
        assert_eq!(
            count(&planned, Status::Present),
            1,
            "same ports, enabled flag ignored"
        );
        assert_eq!(count(&planned, Status::Failed), 2);
        assert_eq!(planned.steps.len(), 1);
        let failures: Vec<_> = planned
            .items
            .iter()
            .filter(|i| i.status == Status::Failed)
            .map(|i| i.detail.clone().unwrap())
            .collect();
        assert!(failures[0].contains("forward 1"), "{failures:?}");
        assert!(
            failures[1].contains("another forward of this file"),
            "{failures:?}"
        );
        // The file twice is the same as once.
        let twice = file(
            vec![entry("node1", 8080, 80), entry("node1", 8080, 80)],
            vec![],
        );
        let planned = run(&twice, &ImportOptions::default(), &world());
        assert_eq!(
            (planned.steps.len(), count(&planned, Status::Present)),
            (1, 1)
        );
    }

    #[test]
    fn listen_addresses_follow_the_servers_addresses() {
        let ips = [ip("198.51.100.5"), ip("2001:db8::5"), ip("198.51.100.6")];
        assert_eq!(
            remap_listen_ip(ip("198.51.100.6"), &ips),
            Some(ip("198.51.100.6"))
        );
        assert_eq!(
            remap_listen_ip(ip("203.0.113.10"), &ips),
            Some(ip("198.51.100.5"))
        );
        assert_eq!(
            remap_listen_ip(ip("2001:db8::1"), &ips),
            Some(ip("2001:db8::5"))
        );
        assert_eq!(remap_listen_ip(ip("2001:db8::1"), &ips[..1]), None);
        assert_eq!(remap_listen_ip(ip("203.0.113.10"), &[]), None);

        let mut v6 = entry("node1", 443, 443);
        v6.listen_ip = ip("2001:db8::ff");
        v6.target_family = Family::V6;
        let data = file(vec![entry("node1", 80, 80), v6], vec![]);
        let planned = plan(
            &data,
            &ImportOptions::default(),
            &World {
                snap: &world(),
                public_ips: &[ip("198.51.100.5")],
                panel_enabled: true,
            },
        );
        assert_eq!(planned.steps.len(), 1);
        let Op::Forward(f) = &planned.steps[0].op else {
            panic!()
        };
        assert_eq!(f.listen_ip, ip("198.51.100.5"));
        assert!(planned.steps[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("used 198.51.100.5"));
        assert_eq!(count(&planned, Status::Skipped), 1);
        assert!(planned.items[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("no IPv6"));
    }

    #[test]
    fn existing_forwards_move_unless_the_new_address_is_taken() {
        let forward = |id: u64, ip: &str, port: u16| Forward {
            id,
            agent_id: "id-node1".into(),
            listen_ip: ip.parse().unwrap(),
            listen_ports: PortRange {
                start: port,
                end: port,
            },
            target_ports: PortRange {
                start: port,
                end: port,
            },
            protocol: Protocol::Tcp,
            mode: ForwardMode::Transparent,
            ingress: Ingress::Public,
            target_family: Family::V4,
            enabled: true,
            generation: 1,
            purpose: Purpose::User,
            allow_from: Vec::new(),
        };
        let ips = [ip("198.51.100.5"), ip("2001:db8::5")];
        let forwards = vec![
            forward(1, "203.0.113.10", 80),
            forward(2, "203.0.113.10", 443),
            forward(3, "198.51.100.5", 443),
            forward(4, "198.51.100.5", 22),
            forward(5, "203.0.113.11", 22),
            forward(6, "2001:db8::99", 80),
        ];
        let fix = fix_listen_ips(&forwards, &ips);
        let moved: Vec<_> = fix.moves.iter().map(|m| (m.id, m.to)).collect();
        assert_eq!(moved, vec![(1, ip("198.51.100.5")), (6, ip("2001:db8::5"))]);
        assert_eq!(fix.blocked, vec![2, 5]);
        assert!(fix_listen_ips(&forwards, &[]).moves.is_empty());
        let left = without_inapplicable(
            StateSnapshot {
                forwards,
                ..Default::default()
            },
            &ips,
        );
        assert_eq!(
            left.forwards.iter().map(|f| f.id).collect::<Vec<_>>(),
            vec![3, 4]
        );
    }

    #[test]
    fn devices_are_created_with_flags_and_grants() {
        let mut phone = device("phone", vec![("node1", server()), ("node2", server())]);
        phone.panel = true;
        phone.enabled = false;
        let data = file(vec![], vec![phone]);
        let planned = run(&data, &ImportOptions::default(), &world());
        let kinds: Vec<_> = planned
            .steps
            .iter()
            .map(|s| match &s.op {
                Op::Device(_) => "device",
                Op::Flags { .. } => "flags",
                Op::AgentNames(_) => "names",
                Op::Grant(_) => "grant",
                Op::Forward(_) => "forward",
                Op::AgentExit { .. } => "exit",
                Op::HostGrant(_) => "host",
                Op::Link(_) => "link",
            })
            .collect();
        assert_eq!(kinds, vec!["device", "flags", "grant"]);
        assert!(planned.steps[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("rift vpn config phone"));
        assert!(planned.steps[1].what.contains("disabled, panel access on"));
        assert_eq!(count(&planned, Status::Skipped), 1, "node2 does not exist");
    }

    #[test]
    fn existing_devices_only_get_what_is_missing() {
        let mut snap = world();
        snap.vpn_peers.push(VpnPeer {
            names_off: false,
            name: "phone".into(),
            public_key: "k".into(),
            ipv4: Ipv4Addr::new(10, 14, 0, 2),
            enabled: true,
            created_at: 0,
            panel: false,
            server_exit: false,
            agent_exits: Vec::new(),
            ipv6: std::net::Ipv6Addr::LOCALHOST,
        });
        snap.vpn_grants.push(VpnGrant {
            peer: "phone".into(),
            agent_id: "id-node1".into(),
            access: server(),
        });
        let port = VpnAccess::Port {
            protocol: Protocol::Tcp,
            ports: "22".parse().unwrap(),
        };
        let data = file(
            vec![],
            vec![device("phone", vec![("node1", server()), ("node1", port)])],
        );
        let planned = run(&data, &ImportOptions::default(), &snap);
        assert_eq!(
            count(&planned, Status::Present),
            2,
            "device and server grant"
        );
        assert_eq!(planned.steps.len(), 1);
        assert!(matches!(planned.steps[0].op, Op::Grant(_)));
        // Panel access without the panel is reported, the rest continues.
        let mut panel = device("phone", vec![]);
        panel.panel = true;
        let planned = plan(
            &file(vec![], vec![panel]),
            &ImportOptions::default(),
            &World {
                snap: &snap,
                public_ips: &[],
                panel_enabled: false,
            },
        );
        assert_eq!(count(&planned, Status::Failed), 1);
        assert_eq!(count(&planned, Status::Present), 1);
    }

    #[test]
    fn filters_apply_to_devices_and_grants() {
        let data = file(
            vec![],
            vec![
                device("only-node2", vec![("node2", server())]),
                device("both", vec![("node2", server()), ("node1", server())]),
                device("bare", vec![]),
            ],
        );
        let options = ImportOptions {
            skip_agents: vec!["node2".into()],
            ..Default::default()
        };
        let planned = run(&data, &options, &world());
        let created: Vec<_> = planned
            .steps
            .iter()
            .filter_map(|s| match &s.op {
                Op::Device(n) => Some(n.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(created, vec!["both", "bare"]);
        assert!(planned
            .items
            .iter()
            .any(|i| i.what == "device only-node2" && i.status == Status::Skipped));
        assert!(planned
            .items
            .iter()
            .any(|i| i.what == "1 entry for agent node2"));
    }

    #[test]
    fn a_network_behind_two_agents_is_refused() {
        let mut snap = world();
        snap.agents.push(agent("home2", AgentStatus::Active, 5));
        let net = |agent: &str| {
            (
                agent.to_string(),
                VpnAccess::Subnet {
                    net: "192.168.178.0/24".parse().unwrap(),
                    snat: false,
                },
            )
        };
        let data = file(
            vec![],
            vec![
                device("a", vec![(&net("node1").0, net("node1").1)]),
                device("b", vec![(&net("home2").0, net("home2").1)]),
            ],
        );
        let planned = run(&data, &ImportOptions::default(), &snap);
        assert_eq!(count(&planned, Status::Failed), 1);
        assert!(planned.items.iter().any(|i| i
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("behind agent node1"))));
    }
}
