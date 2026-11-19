//! Human-readable output of the CLI, shared with the terminal UI.
use crate::model::Exit;
use crate::protocol::AdminRequest;
use serde_json::Value;
use std::collections::HashMap;

fn text(value: &Value) -> String {
    match value {
        Value::Null => "-".into(),
        Value::String(s) => s.clone(),
        _ => value.to_string(),
    }
}

fn field(value: &Value, name: &str) -> String {
    text(&value[name])
}

/// The daemon added the entry, but the agent's own limits (RIFT_AGENT_ALLOW_*) refuse it.
fn refused(data: &Value) -> bool {
    data["warning"]
        .as_str()
        .is_some_and(|w| w.contains("will refuse it"))
}

/// A ban's expiry (Unix seconds) as a UTC date and time, for example `2026-11-16 10:00:00`.
fn ban_expiry(value: &Value) -> String {
    match value.as_i64().and_then(|t| u64::try_from(t).ok()) {
        Some(seconds) => {
            let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds);
            humantime::format_rfc3339_seconds(at)
                .to_string()
                .trim_end_matches('Z')
                .replacen('T', " ", 1)
        }
        None => text(value),
    }
}

/// What `rift add agent` prints: one block on stdout, because `docker exec` passes stdout and
/// stderr on separately and would mix up the order of hints and commands.
/// The checkout an agent host needs before `deploy/join`.
pub const CHECKOUT: &str = "git clone https://github.com/weneten/RIFT.git\ncd RIFT";

pub fn invitation(data: &Value) -> String {
    let (server, name, token) = (
        data["server"].as_str().unwrap_or_default(),
        data["name"].as_str().unwrap_or_default(),
        data["token"].as_str().unwrap_or_default(),
    );
    let minutes =
        ((data["expires_at"].as_i64().unwrap_or(0) - crate::model::now()).max(0) + 59) / 60;
    let mut out = vec![format!(
        "Invitation for agent \"{name}\": works once, valid for {minutes} min. The token is a secret."
    )];
    if data["replaces"].as_bool() == Some(true) {
        out.push(format!("{name} already exists: the install that uses this invitation takes over its key and keeps its addresses, forwards, grants and exits. The old install stops working then."));
    }
    out.push(String::new());
    out.push("Set up the agent: on the agent host, with Docker installed, run".into());
    out.push(String::new());
    for line in CHECKOUT.lines() {
        out.push(format!("  {line}"));
    }
    out.push(format!(
        "  {}",
        crate::enrollment::join_command(server, name, token)
    ));
    out.push(String::new());
    out.push(
        "Or set it up by hand (README, \"Manual setup of an agent\") with these lines in".into(),
    );
    out.push("the agent's .env:".into());
    out.push(String::new());
    out.push(format!("RIFT_SERVER={server}"));
    out.push(format!("RIFT_AGENT_NAME={name}"));
    out.push(format!("RIFT_ENROLLMENT_TOKEN={token}"));
    if data["enrollment"].as_str() == Some("auto") {
        out.push(String::new());
        out.push("The enrollment port is open until the agent is active or the invitation expires or is cancelled.".into());
    }
    out.join("\n")
}

fn table(headers: &[&str], rows: Vec<Vec<String>>, empty: &str) -> String {
    if rows.is_empty() {
        return empty.into();
    }
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let line = |cells: &[String]| {
        cells
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                if i + 1 == cells.len() {
                    cell.clone()
                } else {
                    format!("{cell}{}", " ".repeat(widths[i] - cell.chars().count() + 2))
                }
            })
            .collect::<String>()
    };
    let mut lines = vec![line(
        &headers.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    )];
    lines.extend(rows.iter().map(|row| line(row)));
    lines.join("\n")
}

fn names(agents: Option<&Value>) -> HashMap<String, String> {
    agents
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|a| {
            Some((
                a["id"].as_str()?.to_string(),
                a["name"].as_str()?.to_string(),
            ))
        })
        .collect()
}

fn agent_name(id: &Value, names: &HashMap<String, String>) -> String {
    let id = text(id);
    names.get(&id).cloned().unwrap_or(id)
}

fn range(value: &Value) -> String {
    let start = field(value, "start");
    let end = field(value, "end");
    if start == end {
        start
    } else {
        format!("{start}-{end}")
    }
}

fn endpoint(ip: &str, ports: &str) -> String {
    if ip.contains(':') {
        format!("[{ip}]:{ports}")
    } else {
        format!("{ip}:{ports}")
    }
}

fn forwards(data: &Value, names: &HashMap<String, String>) -> String {
    let rows = data
        .as_array()
        .into_iter()
        .flatten()
        .map(|f| {
            vec![
                field(f, "id"),
                agent_name(&f["agent_id"], names),
                field(f, "protocol").to_uppercase(),
                endpoint(&field(f, "listen_ip"), &range(&f["listen_ports"])),
                range(&f["target_ports"]),
                field(f, "target_family"),
                field(f, "ingress"),
                allowed_sources(&f["allow_from"]),
                field(f, "mode"),
                match f["purpose"].as_str() {
                    Some("exit") => "exit".into(),
                    _ => "user".into(),
                },
                match f["state"].as_str() {
                    Some(state) => state.into(),
                    None if f["enabled"].as_bool() == Some(true) => "enabled".into(),
                    None => "disabled".into(),
                },
            ]
        })
        .collect();
    table(
        &[
            "ID", "AGENT", "PROTO", "LISTEN", "TARGET", "FAMILY", "INGRESS", "FROM", "MODE",
            "PURPOSE", "STATE",
        ],
        rows,
        "No forwards configured.",
    )
}

/// The clients a forward accepts: `any`, or its allowed addresses and networks.
fn allowed_sources(value: &Value) -> String {
    match value.as_array() {
        Some(nets) if !nets.is_empty() => nets
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(","),
        _ => "any".into(),
    }
}

/// The devices whose main profile a change touched, and how to get the new one onto them.
/// Exits name their profiles in their own message.
pub fn reimport_note(request: &AdminRequest, data: &Value) -> Option<String> {
    if matches!(
        request,
        AdminRequest::VpnExit { .. } | AdminRequest::VpnExitClear { .. }
    ) {
        return None;
    }
    let devices: Vec<&str> = data["reimport"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if devices.is_empty() {
        return None;
    }
    let commands: Vec<String> = devices
        .iter()
        .map(|d| format!("rift vpn config {d}"))
        .collect();
    Some(format!(
        "The configuration of {} changed; import it again on the device: {}",
        devices.join(", "),
        commands.join(", ")
    ))
}

/// Whether release `a` is older than `b` (both like 0.2.1). Unknown versions are not.
fn older(a: &str, b: &str) -> bool {
    let parse = |v: &str| -> Option<Vec<u64>> { v.split('.').map(|p| p.parse().ok()).collect() };
    match (parse(a), parse(b)) {
        (Some(a), Some(b)) => a < b,
        _ => false,
    }
}

fn agents(data: &Value) -> String {
    let rows = data
        .as_array()
        .into_iter()
        .flatten()
        .map(|a| {
            let dns = match (
                a["names"].as_bool(),
                a["name"].as_str().and_then(crate::vpn::dns_label),
            ) {
                (Some(true), Some(label)) => format!("{label}.{}", crate::vpn::names_suffix()),
                _ => "-".into(),
            };
            let version = a["rift_version"]
                .as_str()
                .filter(|v| !v.is_empty())
                .unwrap_or("-");
            vec![
                field(a, "name"),
                field(a, "status"),
                version.into(),
                field(a, "tunnel_ipv4"),
                dns,
                field(a, "tunnel_ipv6"),
                field(a, "id"),
            ]
        })
        .collect();
    table(
        &[
            "NAME",
            "STATE",
            "VERSION",
            "TUNNEL IPv4",
            "DNS NAME",
            "TUNNEL IPv6",
            "ID",
        ],
        rows,
        "No agents configured.",
    )
}

fn pairs(value: &Value, depth: usize, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                match value {
                    Value::Object(_) | Value::Array(_) => {
                        out.push(format!("{}{key}:", "  ".repeat(depth)));
                        pairs(value, depth + 1, out);
                    }
                    _ => out.push(format!("{}{key}: {}", "  ".repeat(depth), text(value))),
                }
            }
        }
        Value::Array(items) if items.is_empty() => {
            out.push(format!("{}(none)", "  ".repeat(depth)))
        }
        Value::Array(items) => {
            for item in items {
                if item.is_object() || item.is_array() {
                    out.push(format!("{}-", "  ".repeat(depth)));
                    pairs(item, depth + 1, out);
                } else {
                    out.push(format!("{}- {}", "  ".repeat(depth), text(item)));
                }
            }
        }
        _ => out.push(format!("{}{}", "  ".repeat(depth), text(value))),
    }
}

pub fn doctor(data: &Value) -> String {
    let checks: Vec<&Value> = data["checks"].as_array().into_iter().flatten().collect();
    let width = checks
        .iter()
        .map(|c| field(c, "check").chars().count())
        .max()
        .unwrap_or(0);
    let mut lines = Vec::new();
    let (mut warnings, mut failures) = (0, 0);
    for check in &checks {
        let mark = match check["status"].as_str() {
            Some("ok") => "✓",
            Some("fail") => {
                failures += 1;
                "✗"
            }
            _ => {
                warnings += 1;
                "!"
            }
        };
        let name = field(check, "check");
        let pad = " ".repeat(width - name.chars().count());
        lines.push(format!("{mark} {name}{pad}  {}", field(check, "detail")));
    }
    lines.push(String::new());
    lines.push(match (failures, warnings) {
        (0, 0) => "Everything looks fine.".into(),
        (0, w) => format!("{w} warning(s); RIFT works, but see above."),
        (f, _) => format!("{f} problem(s) to fix, see ✗ above."),
    });
    lines.push("Raw details: rift --json doctor".into());
    lines.join("\n")
}

/// The result of `rift import`: what was created, what was there, what was skipped and what
/// failed. The host command prints the same layout after adding the sites.
pub fn import_report(data: &Value) -> anyhow::Result<String> {
    use crate::portable::{Report, Status};
    let report: Report = serde_json::from_value(data.clone())?;
    let mut lines = Vec::new();
    if report.dry_run {
        lines.push("Dry run: nothing was changed.".to_string());
    }
    let groups = [
        (
            Status::Created,
            if report.dry_run {
                "Would create"
            } else {
                "Created"
            },
        ),
        (Status::Present, "Already present"),
        (Status::Skipped, "Skipped"),
        (Status::Failed, "Failed"),
    ];
    for (status, title) in groups {
        let items: Vec<_> = report.items.iter().filter(|i| i.status == status).collect();
        if items.is_empty() {
            continue;
        }
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push(format!("{title} ({})", items.len()));
        for item in items {
            lines.push(match (&item.detail, status) {
                (Some(detail), Status::Created) => format!("  {} ({detail})", item.what),
                (Some(detail), _) => format!("  {}: {detail}", item.what),
                (None, _) => format!("  {}", item.what),
            });
        }
    }
    if report.items.is_empty() {
        lines.push("Nothing to import.".into());
    }
    Ok(lines.join("\n"))
}

fn status(data: &Value) -> String {
    if let Some(snapshot) = data.get("snapshot") {
        let mut lines = vec![format!(
            "Server: configuration {}",
            if data["fully_applied"].as_bool() == Some(true) {
                "applied"
            } else {
                "pending or failed"
            }
        )];
        if !data["apply_error"].is_null() {
            lines.push(format!("Apply error: {}", text(&data["apply_error"])));
        }
        if let Some(pending) = data["pending_forwards"]
            .as_array()
            .filter(|p| !p.is_empty())
        {
            lines.push(format!(
                "Pending forward IDs: {}",
                pending.iter().map(text).collect::<Vec<_>>().join(", ")
            ));
        }
        let server = data["rift_version"].as_str().unwrap_or_default();
        for agent in data["snapshot"]["agents"].as_array().into_iter().flatten() {
            let version = agent["rift_version"].as_str().unwrap_or_default();
            if older(version, server) {
                lines.push(format!(
                    "Agent {} runs RIFT {version}, the server {server}: update the agent (git pull, sudo sh deploy/install-cli, docker compose pull && docker compose up -d).",
                    field(agent, "name")
                ));
            }
        }
        for refused in data["refused_forwards"].as_array().into_iter().flatten() {
            lines.push(format!(
                "Forward {} refused by its agent: {}",
                field(refused, "id"),
                field(refused, "reason")
            ));
        }
        for moved in data["moved_forwards"].as_array().into_iter().flatten() {
            lines.push(format!(
                "Forward {} moved from {} to {}: the server no longer has the first address (RIFT_PUBLIC_IPS).",
                field(moved, "id"),
                field(moved, "from"),
                field(moved, "to")
            ));
        }
        for stuck in data["inapplicable_forwards"]
            .as_array()
            .into_iter()
            .flatten()
        {
            lines.push(format!(
                "Forward {} not applicable: {}",
                field(stuck, "id"),
                field(stuck, "reason")
            ));
        }
        let rows = data["agent_health"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|a| {
                vec![
                    field(a, "name"),
                    if a["online"].as_bool() == Some(true) {
                        "online"
                    } else {
                        "offline"
                    }
                    .into(),
                    if a["configuration_ready"].as_bool() == Some(true) {
                        "ready"
                    } else {
                        "pending"
                    }
                    .into(),
                ]
            })
            .collect();
        lines.push(table(
            &["AGENT", "CONNECTION", "CONFIG"],
            rows,
            "No agents configured.",
        ));
        for a in data["agent_health"].as_array().into_iter().flatten() {
            if let Some(error) = a["last_error"].as_str() {
                lines.push(format!("Agent {}: {error}", field(a, "name")));
            }
        }
        if let Some(enrollment) = data.get("enrollment") {
            let port = field(enrollment, "bind");
            let open = enrollment["open"].as_bool() == Some(true);
            lines.push(match (field(enrollment, "mode").as_str(), open) {
                ("off", _) => "Enrollment: off.".into(),
                ("always", true) => format!("Enrollment: {port} always open."),
                ("auto", true) => format!("Enrollment: {port} open while an invitation is open."),
                ("auto", false) => {
                    "Enrollment: closed; opens with the next 'rift add agent'.".into()
                }
                (_, false) => {
                    format!("Enrollment: {port} should be open but is not; see the logs.")
                }
                (mode, true) => format!("Enrollment: {port} open ({mode})."),
            });
        }
        let invites: Vec<String> = data["invites"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|i| {
                let left = i["expires_at"].as_i64().unwrap_or(0) - crate::model::now();
                format!("{} ({}m left)", field(i, "name"), (left.max(0) + 59) / 60)
            })
            .collect();
        if !invites.is_empty() {
            lines.push(format!("Open invitations: {}", invites.join(", ")));
        }
        lines.push(format!(
            "Forwards: {} total. Use 'rift list forwards' for details.",
            snapshot["forwards"].as_array().map_or(0, Vec::len)
        ));
        lines.push("Use 'rift --json status' for full diagnostics.".into());
        lines.join("\n")
    } else if data.get("identity").is_some() {
        let id = &data["identity"];
        let connected = data["peers"].as_array().into_iter().flatten().any(|p| {
            let handshake = p["last_handshake"].as_i64().unwrap_or(0);
            handshake > 0 && crate::model::now().saturating_sub(handshake) <= 180
        });
        format!("Agent: {}\nEnrollment: {}\nConnection: {}\nTunnel: {} / {}\nUse 'rift --json status' for full diagnostics.",
            field(&id["welcome"], "name"), if id["active"].as_bool() == Some(true) { "active" } else { "pending" },
            if connected { "online" } else { "no recent handshake" },
            field(&id["welcome"], "tunnel_ipv4"), field(&id["welcome"], "tunnel_ipv6"))
    } else {
        let mut lines = Vec::new();
        pairs(data, 0, &mut lines);
        lines.join("\n")
    }
}

pub fn vpn_access(value: &Value) -> String {
    match value {
        Value::String(kind) => kind.clone(),
        _ if value["port"].is_object() => format!(
            "port {}/{}",
            range(&value["port"]["ports"]),
            field(&value["port"], "protocol")
        ),
        _ if value["subnet"].is_object() => format!(
            "subnet {}{}",
            field(&value["subnet"], "net"),
            if value["subnet"]["snat"].as_bool() == Some(true) {
                " (snat)"
            } else {
                ""
            }
        ),
        _ => text(value),
    }
}

/// "exit via server" or "exit via node1 (refused by agent)", one per exit of a device.
fn vpn_exits(exits: &Value) -> Vec<String> {
    exits
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|exit| match exit["via"].as_str()? {
            "server" => Some("exit via server".to_string()),
            "agent" => {
                let note = match exit["state"].as_str() {
                    Some("refused") => " (refused by agent)",
                    Some("waiting") => " (waiting for the agent)",
                    _ => "",
                };
                Some(format!("exit via {}{note}", field(exit, "agent")))
            }
            _ => None,
        })
        .collect()
}

/// The confirmation of an added internet exit, with the profile to import.
fn exit_added(peer: &str, exit: &Exit, data: &Value) -> String {
    let mut lines = Vec::new();
    let profile = match exit {
        Exit::Server => {
            lines.push(format!(
                "{peer} can now send its internet traffic through this server (its main profile)."
            ));
            if data["ipv6"].as_bool() == Some(false) {
                lines.push("This server has no IPv6 address in RIFT_PUBLIC_IPS: the device's IPv6 traffic is dropped, not leaked.".into());
            }
            format!("rift vpn config {peer}")
        }
        Exit::Agent(agent) => {
            let agent = data["agent"].as_str().unwrap_or(agent);
            lines.push(format!(
                "{peer} can now send its internet traffic through agent {agent} (a profile of its own)."
            ));
            if let Some(waiting) = data["waiting"].as_str() {
                lines.push(format!("Not ready yet: {waiting}"));
            }
            if data["ipv6"].as_bool() == Some(false) {
                lines.push("The agent host has no global IPv6 address: the device's IPv6 traffic is dropped, not leaked.".into());
            }
            lines.push("That profile reaches neither the web panel nor other RIFT grants; switch to the main profile for those.".into());
            format!("rift vpn config {peer} {agent}")
        }
    };
    lines.push(format!("Import the profile: {profile}"));
    lines.join("\n")
}

/// The confirmation of a removed internet exit, with what the user still has to do.
fn exit_removed(peer: &str, agent: Option<&str>) -> String {
    match agent {
        None => format!(
            "{peer} no longer exits through this server.\nImport the main profile again: rift vpn config {peer}"
        ),
        Some(agent) => format!(
            "{peer} no longer exits through agent {agent}.\nDelete the profile for {agent} in the WireGuard app; it does not work any more."
        ),
    }
}

fn vpn_peers(data: &Value) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let rows = data
        .as_array()
        .into_iter()
        .flatten()
        .map(|p| {
            let seen = match p["last_handshake"].as_i64() {
                Some(t) if t > 0 => format!("{}s ago", (now - t).max(0)),
                _ => "never".into(),
            };
            let mut grants = p["grants"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|g| {
                    let refused = if g["refused"].is_string() {
                        " (refused by agent)"
                    } else {
                        ""
                    };
                    format!(
                        "{}: {}{refused}",
                        field(g, "agent"),
                        vpn_access(&g["access"])
                    )
                })
                .collect::<Vec<_>>();
            if p["panel"].as_bool() == Some(true) {
                grants.insert(0, "web panel".into());
            }
            grants.extend(vpn_exits(&p["exits"]));
            if p["names_off"].as_bool() == Some(true) {
                grants.push("names off".into());
            } else {
                let names: Vec<&str> = p["names"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect();
                if !names.is_empty() {
                    grants.push(format!("names: {}", names.join(", ")));
                }
            }
            vec![
                field(p, "name"),
                field(p, "ipv4"),
                if p["enabled"].as_bool() == Some(true) {
                    "enabled"
                } else {
                    "disabled"
                }
                .into(),
                seen,
                if grants.is_empty() {
                    "none".into()
                } else {
                    grants.join("; ")
                },
            ]
        })
        .collect();
    table(
        &["NAME", "ADDRESS", "STATE", "HANDSHAKE", "ACCESS"],
        rows,
        "No VPN devices registered.",
    )
}

fn panel_status(data: &Value) -> String {
    if data["enabled"].as_bool() != Some(true) {
        return format!("Web panel is off. To turn it on, {}.", field(data, "hint"));
    }
    let mut lines = vec![format!(
        "Web panel is on ({} access, port {}).",
        field(data, "access"),
        field(data, "port")
    )];
    if let Some(error) = data["error"].as_str() {
        lines.push(format!("It does not run: {error}."));
    }
    for url in data["urls"].as_array().into_iter().flatten() {
        lines.push(format!("  {}  {}", field(url, "url"), field(url, "via")));
    }
    let devices: Vec<String> = data["devices"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|d| {
            if d["enabled"].as_bool() == Some(true) {
                field(d, "name")
            } else {
                format!("{} (disabled)", field(d, "name"))
            }
        })
        .collect();
    lines.push(format!(
        "Devices with panel access: {}",
        if devices.is_empty() {
            "none (add one with rift panel connect NAME)".into()
        } else {
            devices.join(", ")
        }
    ));
    let allow: Vec<String> = data["allow"]
        .as_array()
        .into_iter()
        .flatten()
        .map(text)
        .collect();
    if !allow.is_empty() {
        lines.push(format!("Allowed addresses: {}", allow.join(", ")));
    }
    lines.push(format!("Password: {}", field(data, "password")));
    lines.join("\n")
}

pub fn render(request: &AdminRequest, data: &Value, agents_data: Option<&Value>) -> String {
    let names = names(agents_data);
    match request {
        AdminRequest::ForwardsList => forwards(data, &names),
        AdminRequest::ForwardAdd(_) if refused(data) => format!("Forward stored (ID {}), but not published: the agent refuses it (see the warning). It becomes active once the agent allows the port.\n{}", field(data, "id"), forwards(&Value::Array(vec![data.clone()]), &names)),
        AdminRequest::ForwardAdd(_) => format!("Forward created (ID {}).\n{}\nThe agent may need a moment to apply it; check 'rift status'.", field(data, "id"), forwards(&Value::Array(vec![data.clone()]), &names)),
        AdminRequest::ForwardRemove { id } => format!("Forward {id} removed."),
        AdminRequest::ForwardEnable { id, enabled } => format!("Forward {id} {}.{}", if *enabled { "enabled" } else { "disabled" }, if *enabled { " The agent may need a moment to apply it." } else { "" }),
        AdminRequest::AgentsList => agents(data),
        AdminRequest::AgentsShow { .. } => { let mut lines = Vec::new(); pairs(data, 0, &mut lines); lines.join("\n") },
        AdminRequest::AgentRemove { name } => format!("Agent {name} removed."),
        AdminRequest::AgentDisable { name } => format!("Agent {name} disabled."),
        AdminRequest::AgentEnable { name } => format!("Agent {name} enabled."),
        AdminRequest::AgentNames { name, on: true } => format!("Devices with a grant on {name} now reach it as {}.", field(data, "dns_name")),
        AdminRequest::AgentNames { on: false, .. } => format!("{} no longer resolves.", field(data, "dns_name")),
        AdminRequest::VpnPeerNames { name, on: true } => format!("{name} uses RIFT's names for the agents it reaches that have them on."),
        AdminRequest::VpnPeerNames { name, on: false } => format!("{name} no longer uses RIFT's names; it reaches agents by address."),
        AdminRequest::AgentRename { name, new_name } => format!("Agent {name} renamed to {new_name}."),
        AdminRequest::AgentRotate { name } => format!("Key rotation requested for {name}. It will occur on the next control sync.\nRotation ID: {}", field(data, "rotation_id")),
        AdminRequest::CancelInvite { name } => format!("Invitation for {name} cancelled."),
        AdminRequest::Ban { ip, forward_id, .. } => format!("Address {ip} banned for forward {forward_id}."),
        AdminRequest::BansList => {
            let rows = data.as_array().into_iter().flatten().map(|b| vec![field(b, "id"), field(b, "forward_id"), field(b, "ip"), ban_expiry(&b["expires_at"])]).collect();
            table(&["ID", "FORWARD", "ADDRESS", "EXPIRES (UTC)"], rows, "No active bans.")
        },
        AdminRequest::VpnPeerAdd { name } => format!("VPN device {name} registered with addresses {} and {}.\nNext: rift vpn allow {name} AGENT 22/tcp (or server), then rift vpn config {name}\nFor an internet exit, which is a profile of its own: rift vpn allow {name} exit (this server) or rift vpn allow {name} AGENT exit, then rift vpn config {name} [AGENT]", field(data, "ipv4"), field(data, "ipv6")),
        AdminRequest::VpnPeerList => vpn_peers(data),
        AdminRequest::VpnPeerEnable { name, enabled } => format!("VPN device {name} {}.", if *enabled { "enabled" } else { "disabled; it can no longer connect" }),
        AdminRequest::VpnPeerRevoke { name } => format!("VPN device {name} revoked. Its key and grants are gone."),
        AdminRequest::VpnAllow { peer, agent, access } if refused(data) => format!("Grant stored, but {peer} cannot reach {agent}: {} yet: {agent} refuses it (see the warning). It works once {agent} allows it.", vpn_access(&serde_json::to_value(access).unwrap_or_default())),
        AdminRequest::VpnAllow { peer, agent, access } => format!("{peer} may now reach {agent}: {}.", vpn_access(&serde_json::to_value(access).unwrap_or_default())),
        AdminRequest::VpnDeny { peer, agent, .. } => {
            let mut text = format!("Access of {peer} to {agent} withdrawn.");
            if data["exit_removed"].as_bool() == Some(true) {
                text.push_str(&format!("\nThe exit via {agent} is gone too: delete that profile of {peer} in the WireGuard app."));
            }
            text
        }
        AdminRequest::VpnDns { peer, agent: Some(agent) } if refused(data) => format!("DNS of {peer} stored, but {agent} refuses port 53 (see the warning): names will not resolve while the tunnel is on until {agent} allows it."),
        AdminRequest::VpnDns { peer, agent: Some(agent) } => format!("{peer} now uses {agent} as its DNS server (port 53 on {agent} is allowed)."),
        AdminRequest::VpnDns { peer, agent: None } => format!("{peer} uses the default DNS again."),
        AdminRequest::VpnExit { peer, exit } => exit_added(peer, exit, data),
        AdminRequest::VpnExitClear { peer, agent } => exit_removed(peer, agent.as_deref()),
        AdminRequest::PanelStatus => panel_status(data),
        AdminRequest::PanelPassword => field(data, "password"),
        AdminRequest::PanelTwoFactorStatus => {
            let mode = field(data, "mode");
            let state = if data["enabled"].as_bool() == Some(true) { "on" } else { "off" };
            let note = match (state, mode.as_str()) {
                ("off", "required") => " Logins are refused until it is set up: rift panel 2fa setup",
                ("off", _) => " Set it up with rift panel 2fa setup, or in the panel.",
                _ => "",
            };
            format!("Two-factor panel login is {state} (mode: {mode}).{note}")
        }
        AdminRequest::PanelTwoFactorSetup => field(data, "uri"),
        AdminRequest::PanelTwoFactorConfirm { .. } => "Two-factor panel login is now on.".into(),
        AdminRequest::PanelTwoFactorReset => "Two-factor panel login is off. The secret is deleted and all panel sessions have ended.".into(),
        AdminRequest::PanelAllow { name, allowed: true } => {
            let url = data["urls"].as_array().and_then(|u| u.get(1)).map(|u| field(u, "url")).unwrap_or_default();
            format!("{name} may now open the web panel at {url}.")
        }
        AdminRequest::PanelAllow { name, allowed: false } => format!("{name} can no longer open the web panel."),
        AdminRequest::Reload => "Configuration reconciled.".into(),
        AdminRequest::Status => status(data),
        AdminRequest::Logs { .. } => {
            let lines = data["lines"].as_array().into_iter().flatten().map(text).collect::<Vec<_>>();
            if lines.is_empty() { "No recent log entries. Container logs may contain more information.".into() } else { lines.join("\n") }
        },
        _ => { let mut lines = Vec::new(); pairs(data, 0, &mut lines); lines.join("\n") },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PortRange, Protocol, VpnAccess};
    use serde_json::json;

    #[test]
    fn an_invitation_lists_clone_cd_and_join_once_and_the_env_lines_once() {
        let data = json!({"name":"core","token":"v1.TOKEN","server":"rift.example.net:8443",
            "expires_at": crate::model::now() + 900, "enrollment":"auto","replaces":false});
        let text = invitation(&data);
        let clone = text
            .find("  git clone https://github.com/weneten/RIFT.git")
            .unwrap();
        let cd = text.find("\n  cd RIFT\n").unwrap();
        let join = text
            .find("  sudo sh deploy/join rift.example.net:8443 core v1.TOKEN")
            .unwrap();
        let env = text
            .find("\nRIFT_SERVER=rift.example.net:8443\nRIFT_AGENT_NAME=core\nRIFT_ENROLLMENT_TOKEN=v1.TOKEN")
            .unwrap();
        assert!(clone < cd && cd < join && join < env, "{text}");
        assert_eq!(text.matches("v1.TOKEN").count(), 2, "{text}");
        assert!(text.contains("valid for 15 min"), "{text}");
        assert!(text.contains("enrollment port is open"), "{text}");
        assert!(!text.contains("takes over its key"), "{text}");
        let again = invitation(&json!({"name":"core","replaces":true,"enrollment":"off"}));
        assert!(again.contains("core already exists"), "{again}");
        assert!(!again.contains("enrollment port"), "{again}");
    }

    #[test]
    fn a_refused_grant_or_forward_is_not_reported_as_working() {
        let access = VpnAccess::Port {
            protocol: Protocol::Tcp,
            ports: PortRange {
                start: 3030,
                end: 3030,
            },
        };
        let request = AdminRequest::VpnAllow {
            peer: "handy".into(),
            agent: "node2".into(),
            access,
        };
        let refused = json!({"warning": "the grant was added, but agent node2 will refuse it: the agent allows only ports 3000"});
        let text = render(&request, &refused, None);
        assert!(!text.contains("may now reach"), "{text}");
        assert!(text.contains("cannot reach node2"), "{text}");
        let ok = render(&request, &json!({"warning": null}), None);
        assert!(ok.contains("handy may now reach node2"), "{ok}");
    }

    #[test]
    fn older_agents_are_named_in_the_status() {
        assert!(older("0.1.9", "0.2.0") && older("0.2.0", "1.0.0") && older("1.9.0", "1.10.0"));
        assert!(!older("0.2.0", "0.2.0") && !older("", "0.2.0") && !older("1.0.0", "0.9.9"));
        let data = json!({"rift_version": "0.3.0", "snapshot": {"agents": [
            {"name": "node2", "rift_version": "0.2.0"}, {"name": "node1", "rift_version": "0.3.0"}]}});
        let text = status(&data);
        assert!(
            text.contains("Agent node2 runs RIFT 0.2.0, the server 0.3.0"),
            "{text}"
        );
        assert!(!text.contains("Agent node1"), "{text}");
    }

    #[test]
    fn bans_show_their_expiry_as_utc_time() {
        let data = json!([{"id":1,"forward_id":4,"ip":"198.51.100.7","expires_at":1_794_823_200}]);
        let output = render(&AdminRequest::BansList, &data, None);
        assert!(output.contains("EXPIRES (UTC)"), "{output}");
        assert!(output.contains("2026-11-16 10:00:00"), "{output}");
    }

    #[test]
    fn forwards_show_names_ranges_ipv6_and_fallback_ids() {
        let data = json!([
            {"id":5,"agent_id":"agent-uuid","protocol":"tcp","listen_ip":"2001:db8::1", "listen_ports":{"start":25001,"end":25003},"target_ports":{"start":5201,"end":5203},"target_family":"v6","ingress":"local","mode":"transparent","enabled":true},
            {"id":6,"agent_id":"unknown-uuid","protocol":"udp","listen_ip":"198.51.100.1", "listen_ports":{"start":80,"end":80},"target_ports":{"start":80,"end":80},"target_family":"v4","ingress":"public","mode":"transparent","enabled":false}
        ]);
        let agents = json!([{"id":"agent-uuid","name":"node1"}]);
        let output = render(&AdminRequest::ForwardsList, &data, Some(&agents));
        for expected in [
            "node1",
            "unknown-uuid",
            "[2001:db8::1]:25001-25003",
            "5201-5203",
            "UDP",
            "disabled",
        ] {
            assert!(output.contains(expected), "missing {expected}: {output}");
        }
        assert_eq!(
            render(&AdminRequest::ForwardsList, &json!([]), None),
            "No forwards configured."
        );
    }

    #[test]
    fn devices_show_their_exits_and_forwards_their_purpose() {
        let devices = json!([
            {"name":"iphone","ipv4":"10.14.0.2","enabled":true,"panel":false,"last_handshake":null,"grants":[],"exits":[{"via":"server"}]},
            {"name":"ipad","ipv4":"10.14.0.3","enabled":true,"panel":true,"last_handshake":null,"grants":[{"agent":"node1","access":"server","refused":null}],"exits":[{"via":"server"},{"via":"agent","agent":"node1","state":"ok","reason":null},{"via":"agent","agent":"node2","state":"waiting","reason":"x"}]},
            {"name":"mac","ipv4":"10.14.0.4","enabled":true,"panel":false,"last_handshake":null,"grants":[],"exits":[{"via":"agent","agent":"node5","state":"refused","reason":"no"}]},
            {"name":"tv","ipv4":"10.14.0.5","enabled":true,"panel":false,"last_handshake":null,"grants":[],"exits":[]}
        ]);
        let output = render(&AdminRequest::VpnPeerList, &devices, None);
        for expected in [
            "exit via server",
            "web panel; node1: server; exit via server; exit via node1; exit via node2 (waiting for the agent)",
            "exit via node5 (refused by agent)",
        ] {
            assert!(output.contains(expected), "missing {expected}: {output}");
        }
        assert!(output.lines().last().unwrap().contains("none"), "{output}");
        let forwards = json!([
            {"id":1,"agent_id":"a","protocol":"udp","listen_ip":"203.0.113.1","listen_ports":{"start":51821,"end":51821},"target_ports":{"start":51821,"end":51821},"target_family":"v4","ingress":"public","mode":"transparent","enabled":true,"purpose":"exit","state":"enabled"},
            {"id":2,"agent_id":"a","protocol":"tcp","listen_ip":"203.0.113.1","listen_ports":{"start":22,"end":22},"target_ports":{"start":22,"end":22},"target_family":"v4","ingress":"public","mode":"transparent","enabled":true,"purpose":"user","state":"enabled"}
        ]);
        let table = render(&AdminRequest::ForwardsList, &forwards, None);
        let mut rows = table.lines().skip(1);
        assert!(rows.next().unwrap().contains(" exit "), "{table}");
        assert!(rows.next().unwrap().contains(" user "), "{table}");
        assert!(table.lines().next().unwrap().contains("PURPOSE"));
    }
    #[test]
    fn exit_changes_say_which_profile_to_import() {
        let add = |exit, data| {
            render(
                &AdminRequest::VpnExit {
                    peer: "iphone".into(),
                    exit,
                },
                &data,
                None,
            )
        };
        let server = add(Exit::Server, json!({"ipv6":false,"warning":null}));
        assert!(
            server.contains("through this server") && server.contains("IPv6 traffic is dropped")
        );
        assert!(server.contains("Import the profile: rift vpn config iphone"));
        assert!(!server.contains("config iphone node1"));
        let agent = add(
            Exit::Agent("node1".into()),
            json!({"agent":"node1","ipv6":true,"waiting":"agent node1 has not reported"}),
        );
        assert!(agent.contains("through agent node1") && agent.contains("Not ready yet"));
        assert!(agent.contains("main profile") && !agent.contains("dropped"));
        assert!(agent.contains("Import the profile: rift vpn config iphone node1"));
        let removed = |agent: Option<&str>| {
            render(
                &AdminRequest::VpnExitClear {
                    peer: "iphone".into(),
                    agent: agent.map(Into::into),
                },
                &json!({}),
                None,
            )
        };
        let server = removed(None);
        assert!(server.contains("no longer exits through this server"));
        assert!(server.contains("Import the main profile again: rift vpn config iphone"));
        let agent = removed(Some("node1"));
        assert!(agent.contains("Delete the profile for node1") && !agent.contains("vpn config"));
    }
    #[test]
    fn doctor_prints_a_checklist_and_a_verdict() {
        let data = json!({"checks": [
            {"status": "ok", "check": "wg command", "detail": "available"},
            {"status": "warn", "check": "Reverse-path filter", "detail": "strict"},
        ]});
        let out = doctor(&data);
        assert!(out.contains("✓ wg command           available"), "{out}");
        assert!(out.contains("! Reverse-path filter  strict"), "{out}");
        assert!(out.contains("1 warning(s)"));
        let failed = doctor(&json!({"checks": [{"status": "fail", "check": "x", "detail": "y"}]}));
        assert!(failed.contains("✗ x  y") && failed.contains("1 problem(s)"));
        assert!(doctor(&json!({"checks": []})).contains("Everything looks fine."));
    }

    #[test]
    fn the_import_report_is_grouped_and_a_dry_run_says_so() {
        let data = json!({"dry_run": true, "items": [
            {"status": "created", "what": "forward node1 22/tcp on 1.2.3.4", "detail": null},
            {"status": "created", "what": "device phone", "detail": "new keys"},
            {"status": "present", "what": "device tv", "detail": null},
            {"status": "skipped", "what": "3 entries for agent node2", "detail": "no such agent"},
            {"status": "failed", "what": "forward node1 80/tcp", "detail": "overlaps forward 1"},
        ]});
        let out = import_report(&data).unwrap();
        for expected in [
            "Dry run: nothing was changed.",
            "Would create (2)\n  forward node1 22/tcp on 1.2.3.4\n  device phone (new keys)",
            "Already present (1)\n  device tv",
            "Skipped (1)\n  3 entries for agent node2: no such agent",
            "Failed (1)\n  forward node1 80/tcp: overlaps forward 1",
        ] {
            assert!(out.contains(expected), "missing {expected:?} in\n{out}");
        }
        let done = import_report(&json!({"dry_run": false, "items": []})).unwrap();
        assert_eq!(done, "Nothing to import.");
    }

    #[test]
    fn status_shows_moved_and_inapplicable_forwards() {
        let data = json!({"snapshot":{"generation":2,"forwards":[]},"fully_applied":true,
            "moved_forwards":[{"id":3,"from":"203.0.113.10","to":"198.51.100.5"}],
            "inapplicable_forwards":[{"id":4,"listen_ip":"2001:db8::1","reason":"the server has no IPv6 address 2001:db8::1"}],
            "agent_health":[]});
        let output = render(&AdminRequest::Status, &data, None);
        assert!(
            output.contains("Forward 3 moved from 203.0.113.10 to 198.51.100.5"),
            "{output}"
        );
        assert!(
            output.contains("Forward 4 not applicable: the server has no IPv6"),
            "{output}"
        );
    }

    #[test]
    fn confirmations_and_status_do_not_hide_pending_errors() {
        assert_eq!(
            render(
                &AdminRequest::ForwardRemove { id: 5 },
                &json!({"removed":5}),
                None
            ),
            "Forward 5 removed."
        );
        let data = json!({"snapshot":{"generation":2,"forwards":[]},"fully_applied":false,"apply_error":"network failed","pending_forwards":[5],"agent_health":[{"name":"node1","online":false,"configuration_ready":false}]});
        let output = render(&AdminRequest::Status, &data, None);
        for expected in [
            "network failed",
            "Pending forward IDs: 5",
            "node1",
            "offline",
            "pending",
        ] {
            assert!(output.contains(expected), "missing {expected}: {output}");
        }
    }
}
