use rift::protocol::AdminRequest;
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
                field(f, "mode"),
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
            "ID", "AGENT", "PROTO", "LISTEN", "TARGET", "FAMILY", "INGRESS", "MODE", "STATE",
        ],
        rows,
        "No forwards configured.",
    )
}

fn agents(data: &Value) -> String {
    let rows = data
        .as_array()
        .into_iter()
        .flatten()
        .map(|a| {
            vec![
                field(a, "name"),
                field(a, "status"),
                field(a, "tunnel_ipv4"),
                field(a, "tunnel_ipv6"),
                field(a, "id"),
            ]
        })
        .collect();
    table(
        &["NAME", "STATE", "TUNNEL IPv4", "TUNNEL IPv6", "ID"],
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
        for refused in data["refused_forwards"].as_array().into_iter().flatten() {
            lines.push(format!(
                "Forward {} refused by its agent: {}",
                field(refused, "id"),
                field(refused, "reason")
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
                let left = i["expires_at"].as_i64().unwrap_or(0) - rift::model::now();
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
            handshake > 0 && rift::model::now().saturating_sub(handshake) <= 180
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

fn vpn_access(value: &Value) -> String {
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
        AdminRequest::ForwardAdd(_) => format!("Forward created (ID {}).\n{}\nThe agent may need a moment to apply it; check 'rift status'.", field(data, "id"), forwards(&Value::Array(vec![data.clone()]), &names)),
        AdminRequest::ForwardRemove { id } => format!("Forward {id} removed."),
        AdminRequest::ForwardEnable { id, enabled } => format!("Forward {id} {}.{}", if *enabled { "enabled" } else { "disabled" }, if *enabled { " The agent may need a moment to apply it." } else { "" }),
        AdminRequest::AgentsList => agents(data),
        AdminRequest::AgentsShow { .. } => { let mut lines = Vec::new(); pairs(data, 0, &mut lines); lines.join("\n") },
        AdminRequest::AgentRemove { name } => format!("Agent {name} removed."),
        AdminRequest::AgentDisable { name } => format!("Agent {name} disabled."),
        AdminRequest::AgentEnable { name } => format!("Agent {name} enabled."),
        AdminRequest::AgentRename { name, new_name } => format!("Agent {name} renamed to {new_name}."),
        AdminRequest::AgentRotate { name } => format!("Key rotation requested for {name}. It will occur on the next control sync.\nRotation ID: {}", field(data, "rotation_id")),
        AdminRequest::CancelInvite { name } => format!("Invitation for {name} cancelled."),
        AdminRequest::Ban { ip, forward_id, .. } => format!("Address {ip} banned for forward {forward_id}."),
        AdminRequest::BansList => {
            let rows = data.as_array().into_iter().flatten().map(|b| vec![field(b, "id"), field(b, "forward_id"), field(b, "ip"), field(b, "expires_at")]).collect();
            table(&["ID", "FORWARD", "ADDRESS", "EXPIRES (UNIX)"], rows, "No active bans.")
        },
        AdminRequest::VpnPeerAdd { name } => format!("VPN device {name} registered with address {}.\nNext: rift vpn allow {name} AGENT 22/tcp (or server), then rift vpn config qr {name}", field(data, "ipv4")),
        AdminRequest::VpnPeerList => vpn_peers(data),
        AdminRequest::VpnPeerEnable { name, enabled } => format!("VPN device {name} {}.", if *enabled { "enabled" } else { "disabled; it can no longer connect" }),
        AdminRequest::VpnPeerRevoke { name } => format!("VPN device {name} revoked. Its key and grants are gone."),
        AdminRequest::VpnAllow { peer, agent, access } => format!("{peer} may now reach {agent}: {}.", vpn_access(&serde_json::to_value(access).unwrap_or_default())),
        AdminRequest::VpnDeny { peer, agent, .. } => format!("Access of {peer} to {agent} withdrawn."),
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
            format!("{name} may now open the web panel at {url}.\nIf the device was set up before, re-import its configuration: rift vpn config qr {name}")
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
    use serde_json::json;

    #[test]
    fn forwards_show_names_ranges_ipv6_and_fallback_ids() {
        let data = json!([
            {"id":5,"agent_id":"agent-uuid","protocol":"tcp","listen_ip":"2001:db8::1", "listen_ports":{"start":25001,"end":25003},"target_ports":{"start":5201,"end":5203},"target_family":"v6","ingress":"local","mode":"transparent","enabled":true},
            {"id":6,"agent_id":"unknown-uuid","protocol":"udp","listen_ip":"198.51.100.1", "listen_ports":{"start":80,"end":80},"target_ports":{"start":80,"end":80},"target_family":"v4","ingress":"public","mode":"transparent","enabled":false}
        ]);
        let agents = json!([{"id":"agent-uuid","name":"core"}]);
        let output = render(&AdminRequest::ForwardsList, &data, Some(&agents));
        for expected in [
            "core",
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
    fn confirmations_and_status_do_not_hide_pending_errors() {
        assert_eq!(
            render(
                &AdminRequest::ForwardRemove { id: 5 },
                &json!({"removed":5}),
                None
            ),
            "Forward 5 removed."
        );
        let data = json!({"snapshot":{"generation":2,"forwards":[]},"fully_applied":false,"apply_error":"network failed","pending_forwards":[5],"agent_health":[{"name":"core","online":false,"configuration_ready":false}]});
        let output = render(&AdminRequest::Status, &data, None);
        for expected in [
            "network failed",
            "Pending forward IDs: 5",
            "core",
            "offline",
            "pending",
        ] {
            assert!(output.contains(expected), "missing {expected}: {output}");
        }
    }
}
