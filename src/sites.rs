//! The web panel's side of the site bridge.
//!
//! Sites need the host: root, Docker and the reverse proxy's files. The server container
//! therefore only reads the helper's records (`/var/lib/rift-site`, mounted read-only) and
//! queues requests as small JSON files in a separate directory (`/var/lib/rift-site-queue`,
//! mounted read-write). A systemd path unit on the host runs `rift-site process-queue`, which
//! validates every request again and writes `<id>.result.json` next to it. A request adds or
//! removes one site, or runs `rift export`, `rift import` or `rift backup` on the host; the
//! host leaves their file as `<id>.data`, which the panel fetches once. With `keep` (the terminal
//! UI, which cannot write host files) the host saves an export or backup in `FILES_DIR`
//! instead; the container sees that directory read-only and lists it with [`files`].

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
/// Exports and backups saved on the host (rift-site FILES_DIR), read-only in the container.
pub const FILES_DIR: &str = "/var/lib/rift-site/files";
/// Requests that may wait for the host at the same time.
pub const MAX_PENDING: usize = 20;
const PROXIES: [&str; 4] = ["traefik", "caddy", "nginx", "npm"];
const MAX_STATE: u64 = 1024 * 1024;
const MAX_RESULT: u64 = 64 * 1024;
/// The largest import the host takes (its QUEUE_MAX_IMPORT), with room for the request itself.
pub const MAX_IMPORT: usize = 500 * 1024;
/// The largest file the panel fetches from the host (a backup).
const MAX_DATA: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Request {
    Add {
        id: String,
        agent: String,
        host: String,
        port: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        proxy: Option<String>,
        /// Client addresses or networks the proxy lets through; empty means everyone.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        allow_from: Vec<String>,
    },
    Remove {
        id: String,
        host: String,
    },
    /// `rift export` on the host, with its sites. `keep` saves it in `FILES_DIR`.
    Export {
        id: String,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        keep: bool,
    },
    /// `rift backup` on the host: every key of the server. `keep` saves it in `FILES_DIR`.
    Backup {
        id: String,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        keep: bool,
    },
    /// `rift import` on the host; `map` holds `OLD=NEW` agent names.
    Import {
        id: String,
        document: Value,
        dry_run: bool,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        map: Vec<String>,
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
pub fn add(
    agent: &str,
    host: &str,
    port: u32,
    proxy: Option<&str>,
    allow_from: &[ipnet::IpNet],
) -> Result<Request> {
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
        allow_from: allow_from.iter().map(ToString::to_string).collect(),
    })
}

pub fn remove(host: &str) -> Result<Request> {
    validate_host(host)?;
    Ok(Request::Remove {
        id: new_id(),
        host: host.into(),
    })
}

pub fn export() -> Request {
    Request::Export {
        id: new_id(),
        keep: false,
    }
}

pub fn backup() -> Request {
    Request::Backup {
        id: new_id(),
        keep: false,
    }
}

/// An export the host saves in `FILES_DIR` instead of handing it over.
pub fn export_kept() -> Request {
    Request::Export {
        id: new_id(),
        keep: true,
    }
}

/// A backup the host saves in `FILES_DIR` instead of handing it over.
pub fn backup_kept() -> Request {
    Request::Backup {
        id: new_id(),
        keep: true,
    }
}

/// The files in `dir` (FILES_DIR), newest first: name, size, modification time and kind
/// (`export` for JSON files, `backup` for archives). Hidden files (partial writes) and
/// anything but regular files are left out.
pub fn files(dir: &Path) -> Vec<Value> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut list: Vec<Value> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_string();
            let meta = entry.metadata().ok()?;
            if name.starts_with('.') || !entry.file_type().ok()?.is_file() {
                return None;
            }
            let modified = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            let kind = if name.ends_with(".json") {
                "export"
            } else if name.ends_with(".tar.gz") {
                "backup"
            } else {
                "other"
            };
            Some(json!({"name": name, "size": meta.len(), "modified": modified, "kind": kind}))
        })
        .collect();
    list.sort_by(|a, b| {
        b["modified"]
            .as_u64()
            .cmp(&a["modified"].as_u64())
            .then_with(|| b["name"].as_str().cmp(&a["name"].as_str()))
    });
    list
}

/// Reads an export file from `dir` for an import: only a plain name of a regular file there,
/// at most `MAX_IMPORT` bytes, parsed as JSON.
pub fn read_export(dir: &Path, name: &str) -> Result<Value> {
    ensure!(
        !name.is_empty() && !name.starts_with('.') && !name.contains('/'),
        "not a file name: {name:?}"
    );
    let path = dir.join(name);
    let meta = std::fs::symlink_metadata(&path).with_context(|| format!("{}", path.display()))?;
    ensure!(meta.is_file(), "{} is not a regular file", path.display());
    ensure!(
        meta.len() <= MAX_IMPORT as u64,
        "{name} is larger than {} KB; import it with sudo rift import on the server",
        MAX_IMPORT / 1024
    );
    let text = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&text).with_context(|| format!("{name} is not a JSON export file"))
}

/// An import of `document` (an export file); `map` is `OLD=NEW` agent names, separated by
/// commas or spaces.
pub fn import(document: Value, dry_run: bool, map: &str) -> Result<Request> {
    ensure!(
        document.is_object() && document.get("format").is_some(),
        "this is not a RIFT export file (no \"format\" field)"
    );
    let mut pairs = Vec::new();
    for pair in map
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|p| !p.is_empty())
    {
        let (old, new) = pair
            .split_once('=')
            .with_context(|| format!("{pair}: use OLD=NEW, for example node2=node1"))?;
        validate_name(old).with_context(|| format!("{pair}: {old} is not an agent name"))?;
        validate_name(new).with_context(|| format!("{pair}: {new} is not an agent name"))?;
        pairs.push(format!("{old}={new}"));
    }
    let request = Request::Import {
        id: new_id(),
        document,
        dry_run,
        map: pairs,
    };
    ensure!(
        serde_json::to_vec(&request)?.len() <= MAX_IMPORT,
        "the export file is too large for the panel; use `rift import` on the server"
    );
    Ok(request)
}

impl Request {
    pub fn id(&self) -> &str {
        match self {
            Self::Add { id, .. }
            | Self::Remove { id, .. }
            | Self::Export { id, .. }
            | Self::Backup { id, .. }
            | Self::Import { id, .. } => id,
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
        "sites are managed on the host; install the host command (sudo sh deploy/install-cli) and recreate the server container"
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
    let mut out = json!({
        "done": true,
        "ok": answer["ok"].as_bool().unwrap_or(false),
        "message": answer["message"].as_str().unwrap_or_default(),
    });
    if let Some(file) = answer["file"].as_str() {
        out["file"] = file.into();
    }
    Ok(out)
}

/// The host's answer with the file it left for the request (export, import report or
/// backup): `{"done": false}` until it exists, then the answer with `file` (its name) and
/// `data` (its bytes). The file and the answer are removed once read, so a backup leaves the
/// host only once.
pub fn fetch(queue: &Path, id: &str) -> Result<(Value, Option<Vec<u8>>)> {
    let answer = result(queue, id)?;
    if answer["done"] != true {
        return Ok((answer, None));
    }
    let path = queue.join(format!("{id}.data"));
    let data = if answer["file"].is_string() {
        let file = std::fs::File::open(&path)
            .with_context(|| "the host's file is gone; it is kept for 15 minutes, so ask again")?;
        let mut data = Vec::new();
        file.take(MAX_DATA + 1).read_to_end(&mut data)?;
        ensure!(
            data.len() as u64 <= MAX_DATA,
            "the host's file is too large"
        );
        Some(data)
    } else {
        None
    };
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(queue.join(format!("{id}.result.json")));
    Ok((answer, data))
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
        return json!({"available": false, "queue": queue_ready, "sites": [], "proxy": Value::Null});
    };
    let proxy = proxy_of(&document);
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
                "allow_from": site.get("allow_from").cloned().unwrap_or_else(|| json!([])),
                "forward": state,
                "reason": reason,
            })
        })
        .collect();
    list.sort_by(|a, b| a["host"].as_str().cmp(&b["host"].as_str()));
    json!({"available": true, "queue": queue_ready, "sites": list, "proxy": proxy})
}

/// The proxy `rift add site` uses by default, as `rift proxy` shows it, and where Caddy runs.
fn proxy_of(document: &Value) -> Value {
    let name = document["proxy"].as_str().unwrap_or("traefik");
    let caddy = &document["caddy"];
    let reload: Vec<&str> = caddy["reload"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let container = match reload.as_slice() {
        ["docker", "exec", container, ..] => Some(*container),
        _ => None,
    };
    json!({
        "name": name,
        "caddy_container": container,
        "caddy_sites_dir": caddy["sites_dir"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_validated_before_they_are_written() {
        assert!(add("node1", "app.example.net", 8080, Some("caddy"), &[]).is_ok());
        assert!(add("node1_1", "a", 1, None, &[]).is_ok());
        assert!(add("node1", "app.example.net", 65535, None, &[]).is_ok());
        for agent in ["", "a b", "a;id", "../x", &"a".repeat(64)] {
            assert!(
                add(agent, "app.example.net", 80, None, &[]).is_err(),
                "{agent:?}"
            );
        }
        let long = format!("{}.net", "a".repeat(64));
        let too_long = vec!["a"; 130].join(".");
        for host in [
            "", "-a.net", "a-.net", "a..net", "a b.net", "a/b", "a;rm.net", "app.net.", "ä.net",
            &long, &too_long,
        ] {
            assert!(add("node1", host, 80, None, &[]).is_err(), "{host:?}");
            assert!(remove(host).is_err(), "{host:?}");
        }
        for port in [0, 65536, 70000] {
            assert!(
                add("node1", "app.example.net", port, None, &[]).is_err(),
                "{port}"
            );
        }
        for proxy in ["", "apache", "Traefik", "caddy "] {
            assert!(
                add("node1", "app.example.net", 80, Some(proxy), &[]).is_err(),
                "{proxy:?}"
            );
        }
        assert!(remove("app.example.net").is_ok());
    }

    #[test]
    fn allowed_sources_travel_with_the_request() {
        let nets = crate::model::parse_allow_from(&["203.0.113.7, 198.51.100.0/24"]).unwrap();
        let request = add("node1", "app.example.net", 8080, None, &nets).unwrap();
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(
            value["allow_from"],
            json!(["203.0.113.7/32", "198.51.100.0/24"])
        );
    }

    #[test]
    fn a_request_file_holds_exactly_the_checked_parameters() {
        let dir = tempfile::tempdir().unwrap();
        let request = add("node1", "app.example.net", 8080, None, &[]).unwrap();
        let id = enqueue(dir.path(), &request).unwrap();
        validate_id(&id).unwrap();
        let text = std::fs::read_to_string(dir.path().join(format!("{id}.json"))).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            value,
            json!({"id": id, "action": "add", "agent": "node1", "host": "app.example.net", "port": 8080})
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
                "b.example.net": {"agent": "node1", "target": 9000, "listen": 20001, "proxy": "caddy", "forward_id": 2},
                "a.example.net": {"agent": "node1", "target": 8080, "listen": 20000, "proxy": "traefik", "forward_id": 1},
                "c.example.net": {"agent": "node1", "target": 80, "listen": 20002, "proxy": "nginx", "forward_id": 3},
                "d.example.net": {"agent": "node1", "target": 80, "listen": 20003, "proxy": "nginx", "forward_id": 4},
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

    #[test]
    fn keep_is_sent_only_when_asked_for() {
        let plain = serde_json::to_value(export()).unwrap();
        assert_eq!(plain["action"], "export");
        assert!(
            plain.get("keep").is_none(),
            "the panel's requests stay as they were"
        );
        let kept = serde_json::to_value(backup_kept()).unwrap();
        assert_eq!(
            (kept["action"].as_str(), kept["keep"].as_bool()),
            (Some("backup"), Some(true))
        );
    }

    #[test]
    fn saved_files_are_listed_newest_first_and_read_for_imports() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rift-export-a.json"), br#"{"format":2}"#).unwrap();
        std::fs::write(dir.path().join("rift-backup-b.tar.gz"), b"x").unwrap();
        std::fs::write(dir.path().join(".partial"), b"x").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(dir.path().join("rift-export-a.json"))
            .unwrap()
            .set_modified(old)
            .unwrap();
        let list = files(dir.path());
        let names: Vec<&str> = list.iter().map(|f| f["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["rift-backup-b.tar.gz", "rift-export-a.json"]);
        assert_eq!(list[1]["kind"], "export");
        assert_eq!(list[0]["kind"], "backup");
        assert!(files(&dir.path().join("missing")).is_empty());

        assert_eq!(
            read_export(dir.path(), "rift-export-a.json").unwrap()["format"],
            2
        );
        for bad in [
            "",
            "../etc/passwd",
            ".partial",
            "sub",
            "missing.json",
            "rift-backup-b.tar.gz",
        ] {
            assert!(read_export(dir.path(), bad).is_err(), "{bad:?}");
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/hostname", dir.path().join("link.json")).unwrap();
            assert!(read_export(dir.path(), "link.json").is_err());
        }
    }

    #[test]
    fn the_overview_names_the_proxy_and_where_caddy_runs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("sites.json"),
            json!({"proxy": "caddy", "caddy": {"sites_dir": "/opt/caddy/sites", "reload": ["docker", "exec", "rift-caddy", "caddy", "reload"]}, "sites": {}}).to_string(),
        )
        .unwrap();
        let proxy = &overview(dir.path(), dir.path(), &[])["proxy"];
        assert_eq!(proxy["name"], "caddy");
        assert_eq!(proxy["caddy_container"], "rift-caddy");
        assert_eq!(proxy["caddy_sites_dir"], "/opt/caddy/sites");
        std::fs::write(dir.path().join("sites.json"), r#"{"sites": {}}"#).unwrap();
        let proxy = &overview(dir.path(), dir.path(), &[])["proxy"];
        assert_eq!(
            (proxy["name"].as_str(), proxy["caddy_container"].is_null()),
            (Some("traefik"), true)
        );
    }
}
