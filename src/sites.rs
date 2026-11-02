//! The web panel's side of the site bridge.
//!
//! Sites need the host: root, Docker and the reverse proxy's files. The server container
//! therefore only reads the helper's records (`/var/lib/rift-site`, mounted read-only) and
//! queues requests as small JSON files in a separate directory (`/var/lib/rift-site-queue`,
//! mounted read-write). A systemd path unit on the host runs `rift-site process-queue`, which
//! validates every request again and writes `<id>.result.json` next to it. A request can only
//! add or remove one site, with the parameters checked here.

use crate::config::validate_name;
use anyhow::{bail, ensure, Context, Result};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    path::Path,
};

pub const SITES_DIR: &str = "/var/lib/rift-site";
pub const QUEUE_DIR: &str = "/var/lib/rift-site-queue";
/// Requests that may wait for the host at the same time.
pub const MAX_PENDING: usize = 20;
const PROXIES: [&str; 4] = ["traefik", "caddy", "nginx", "npm"];
const MAX_STATE: u64 = 1024 * 1024;
const MAX_RESULT: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Request {
    Add {
        id: String,
        agent: String,
        host: String,
        port: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        proxy: Option<String>,
    },
    Remove {
        id: String,
        host: String,
    },
}

pub fn validate_host(host: &str) -> Result<()> {
    ensure!(
        !host.is_empty() && host.len() <= 253,
        "the domain must have 1..253 characters"
    );
    for label in host.split('.') {
        let bytes = label.as_bytes();
        ensure!(
            (1..=63).contains(&bytes.len())
                && bytes
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
                && bytes[0] != b'-'
                && bytes[bytes.len() - 1] != b'-',
            "{host:?} is not a valid domain name"
        );
    }
    Ok(())
}

pub fn validate_id(id: &str) -> Result<()> {
    ensure!(
        id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "malformed request id"
    );
    Ok(())
}

fn new_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A validated request to publish `host` through `agent`'s `port`.
pub fn add(agent: &str, host: &str, port: u32, proxy: Option<&str>) -> Result<Request> {
    validate_name(agent)?;
    validate_host(host)?;
    let port = u16::try_from(port)
        .ok()
        .filter(|p| *p != 0)
        .context("the port must be in 1..65535")?;
    if let Some(proxy) = proxy {
        ensure!(
            PROXIES.contains(&proxy),
            "the proxy must be traefik, caddy, nginx or npm"
        );
    }
    Ok(Request::Add {
        id: new_id(),
        agent: agent.into(),
        host: host.into(),
        port,
        proxy: proxy.map(String::from),
    })
}

pub fn remove(host: &str) -> Result<Request> {
    validate_host(host)?;
    Ok(Request::Remove {
        id: new_id(),
        host: host.into(),
    })
}

impl Request {
    pub fn id(&self) -> &str {
        match self {
            Self::Add { id, .. } | Self::Remove { id, .. } => id,
        }
    }
}

fn is_request_file(name: &str) -> bool {
    name.strip_suffix(".json")
        .is_some_and(|id| validate_id(id).is_ok())
}

/// How many requests wait for the host.
pub fn pending(queue: &Path) -> Result<usize> {
    let mut count = 0;
    for entry in
        std::fs::read_dir(queue).with_context(|| format!("cannot read {}", queue.display()))?
    {
        if is_request_file(&entry?.file_name().to_string_lossy()) {
            count += 1;
        }
    }
    Ok(count)
}

/// Queues the request for the host service and returns its id. The file appears atomically.
pub fn enqueue(queue: &Path, request: &Request) -> Result<String> {
    ensure!(
        queue.is_dir(),
        "sites are managed on the host; install the host command (sudo sh deploy/vps/install-cli) and recreate the server container"
    );
    if pending(queue)? >= MAX_PENDING {
        bail!("{MAX_PENDING} site requests are already waiting; the host service is not processing them (is rift-site-queue.path active?)");
    }
    let id = request.id();
    let temporary = queue.join(format!("{id}.json.tmp"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .with_context(|| format!("cannot write to {}", queue.display()))?;
    let written = file
        .write_all(&serde_json::to_vec(request)?)
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) =
        written.and_then(|()| std::fs::rename(&temporary, queue.join(format!("{id}.json"))))
    {
        let _ = std::fs::remove_file(&temporary);
        return Err(e.into());
    }
    Ok(id.into())
}

/// The host's answer to a request, once there is one.
pub fn result(queue: &Path, id: &str) -> Result<Value> {
    validate_id(id)?;
    let path = queue.join(format!("{id}.result.json"));
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(json!({"done": false})),
        Err(e) => return Err(e.into()),
    };
    let mut text = String::new();
    file.take(MAX_RESULT).read_to_string(&mut text)?;
    // The host writes the file in one rename; a partial one is treated as not there yet.
    let Ok(answer) = serde_json::from_str::<Value>(&text) else {
        return Ok(json!({"done": false}));
    };
    Ok(json!({
        "done": true,
        "ok": answer["ok"].as_bool().unwrap_or(false),
        "message": answer["message"].as_str().unwrap_or_default(),
    }))
}

fn forward_state(site: &Value, forwards: &[Value]) -> (&'static str, Value) {
    let Some(forward) = forwards
        .iter()
        .find(|f| !site["forward_id"].is_null() && f["id"] == site["forward_id"])
    else {
        return ("missing", Value::Null);
    };
    let listen = site["listen"].as_u64().unwrap_or(0);
    let ports = &forward["listen_ports"];
    let start = ports["start"].as_u64().unwrap_or(0);
    let end = ports["end"].as_u64().unwrap_or(start);
    let target = forward["target_ports"]["start"].as_u64().unwrap_or(0);
    if start == 0
        || !(start..=end).contains(&listen)
        || target != site["target"].as_u64().unwrap_or(0)
    {
        return ("missing", Value::Null);
    }
    match forward["refused"].as_str() {
        Some(reason) => ("refused", reason.into()),
        None => ("ok", Value::Null),
    }
}

/// The sites card: the helper's records with the state of their forwards. `forwards` is the
/// panel's own forward list (agent names resolved).
pub fn overview(sites: &Path, queue: &Path, forwards: &[Value]) -> Value {
    let queue_ready = queue.is_dir();
    let path = sites.join("sites.json");
    let document = std::fs::File::open(path).ok().and_then(|f| {
        let mut text = String::new();
        f.take(MAX_STATE).read_to_string(&mut text).ok()?;
        serde_json::from_str::<Value>(&text).ok()
    });
    let Some(document) = document else {
        return json!({"available": false, "queue": queue_ready, "sites": []});
    };
    let mut list: Vec<Value> = document["sites"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(host, site)| {
            let (state, reason) = forward_state(site, forwards);
            json!({
                "host": host,
                "agent": site["agent"],
                "target": site["target"],
                "listen": site["listen"],
                "proxy": site["proxy"],
                "forward_id": site["forward_id"],
                "forward": state,
                "reason": reason,
            })
        })
        .collect();
    list.sort_by(|a, b| a["host"].as_str().cmp(&b["host"].as_str()));
    json!({"available": true, "queue": queue_ready, "sites": list})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_validated_before_they_are_written() {
        assert!(add("core", "app.example.net", 8080, Some("caddy")).is_ok());
        assert!(add("core_1", "a", 1, None).is_ok());
        assert!(add("core", "app.example.net", 65535, None).is_ok());
        for agent in ["", "a b", "a;id", "../x", &"a".repeat(64)] {
            assert!(
                add(agent, "app.example.net", 80, None).is_err(),
                "{agent:?}"
            );
        }
        let long = format!("{}.net", "a".repeat(64));
        let too_long = vec!["a"; 130].join(".");
        for host in [
            "", "-a.net", "a-.net", "a..net", "a b.net", "a/b", "a;rm.net", "app.net.", "ä.net",
            &long, &too_long,
        ] {
            assert!(add("core", host, 80, None).is_err(), "{host:?}");
            assert!(remove(host).is_err(), "{host:?}");
        }
        for port in [0, 65536, 70000] {
            assert!(
                add("core", "app.example.net", port, None).is_err(),
                "{port}"
            );
        }
        for proxy in ["", "apache", "Traefik", "caddy "] {
            assert!(
                add("core", "app.example.net", 80, Some(proxy)).is_err(),
                "{proxy:?}"
            );
        }
        assert!(remove("app.example.net").is_ok());
    }

    #[test]
    fn a_request_file_holds_exactly_the_checked_parameters() {
        let dir = tempfile::tempdir().unwrap();
        let request = add("core", "app.example.net", 8080, None).unwrap();
        let id = enqueue(dir.path(), &request).unwrap();
        validate_id(&id).unwrap();
        let text = std::fs::read_to_string(dir.path().join(format!("{id}.json"))).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            value,
            json!({"id": id, "action": "add", "agent": "core", "host": "app.example.net", "port": 8080})
        );
        let request = remove("app.example.net").unwrap();
        let id = enqueue(dir.path(), &request).unwrap();
        let text = std::fs::read_to_string(dir.path().join(format!("{id}.json"))).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            value,
            json!({"id": id, "action": "remove", "host": "app.example.net"})
        );
        // No temporary file is left behind.
        assert!(std::fs::read_dir(dir.path()).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
    }

    #[test]
    fn the_queue_is_limited_and_results_do_not_count() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(format!("{}.result.json", "a".repeat(32))),
            "{}",
        )
        .unwrap();
        for _ in 0..MAX_PENDING {
            let request = remove("app.example.net").unwrap();
            enqueue(dir.path(), &request).unwrap();
        }
        assert_eq!(pending(dir.path()).unwrap(), MAX_PENDING);
        let error = enqueue(dir.path(), &remove("app.example.net").unwrap()).unwrap_err();
        assert!(error.to_string().contains("already waiting"), "{error}");
        let missing = dir.path().join("missing");
        let error = enqueue(&missing, &remove("app.example.net").unwrap()).unwrap_err();
        assert!(error.to_string().contains("install-cli"), "{error}");
    }

    #[test]
    fn a_result_is_read_by_a_checked_id_only() {
        let dir = tempfile::tempdir().unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(result(dir.path(), id).unwrap(), json!({"done": false}));
        std::fs::write(
            dir.path().join(format!("{id}.result.json")),
            r#"{"id":"x","ok":false,"message":"no such agent"}"#,
        )
        .unwrap();
        assert_eq!(
            result(dir.path(), id).unwrap(),
            json!({"done": true, "ok": false, "message": "no such agent"})
        );
        for bad in [
            "",
            "../etc/passwd",
            "ABCDEF0123456789abcdef0123456789",
            "abc",
        ] {
            assert!(result(dir.path(), bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn sites_are_listed_with_the_state_of_their_forward() {
        let dir = tempfile::tempdir().unwrap();
        let queue = tempfile::tempdir().unwrap();
        let forwards = vec![
            json!({"id": 1, "listen_ports": {"start": 20000, "end": 20000}, "target_ports": {"start": 8080, "end": 8080}, "refused": null}),
            json!({"id": 2, "listen_ports": {"start": 20001, "end": 20001}, "target_ports": {"start": 9000, "end": 9000}, "refused": "port not allowed"}),
            json!({"id": 4, "listen_ports": {"start": 20003, "end": 20003}, "target_ports": {"start": 1, "end": 1}, "refused": null}),
        ];
        let none = overview(dir.path(), queue.path(), &forwards);
        assert_eq!(none["available"], false);
        assert_eq!(none["queue"], true);
        std::fs::write(
            dir.path().join("sites.json"),
            json!({"proxy": "traefik", "sites": {
                "b.example.net": {"agent": "core", "target": 9000, "listen": 20001, "proxy": "caddy", "forward_id": 2},
                "a.example.net": {"agent": "core", "target": 8080, "listen": 20000, "proxy": "traefik", "forward_id": 1},
                "c.example.net": {"agent": "core", "target": 80, "listen": 20002, "proxy": "nginx", "forward_id": 3},
                "d.example.net": {"agent": "core", "target": 80, "listen": 20003, "proxy": "nginx", "forward_id": 4},
            }})
            .to_string(),
        )
        .unwrap();
        let view = overview(dir.path(), queue.path(), &forwards);
        assert_eq!(view["available"], true);
        let states: Vec<(&str, &str)> = view["sites"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| (s["host"].as_str().unwrap(), s["forward"].as_str().unwrap()))
            .collect();
        assert_eq!(
            states,
            [
                ("a.example.net", "ok"),
                ("b.example.net", "refused"),
                ("c.example.net", "missing"),
                ("d.example.net", "missing"),
            ]
        );
        assert_eq!(view["sites"][1]["reason"], "port not allowed");
        std::fs::write(dir.path().join("sites.json"), "not json").unwrap();
        assert_eq!(
            overview(dir.path(), queue.path(), &forwards)["available"],
            false
        );
    }
}
