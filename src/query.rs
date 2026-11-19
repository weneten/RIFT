//! Filtering and sorting of forwards, shared by `rift list forwards` and the terminal UI.
//!
//! A filter is a list of words that must all match. `agent:NAME`, `port:N`, `proto:tcp|udp`
//! and `state:WORD` match one field; a bare number matches the forward's ID or a listen or
//! target port (ranges included); any other word matches part of the agent name, an address,
//! the protocol, mode, ingress, state or the allowed clients. Several `agent:` words match
//! any of those agents.

use anyhow::{bail, Result};
use serde_json::Value;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ForwardSort {
    #[default]
    Id,
    Agent,
    Port,
    State,
}
impl ForwardSort {
    pub const ALL: [ForwardSort; 4] = [Self::Id, Self::Agent, Self::Port, Self::State];
    pub fn name(self) -> &'static str {
        match self {
            Self::Id => "id",
            Self::Agent => "agent",
            Self::Port => "port",
            Self::State => "state",
        }
    }
    pub fn next(self) -> Self {
        let i = Self::ALL.iter().position(|s| *s == self).unwrap_or(0);
        Self::ALL[(i + 1) % Self::ALL.len()]
    }
}
impl std::str::FromStr for ForwardSort {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|v| v.name() == s)
            .ok_or_else(|| "sort by id, agent, port or state".into())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ForwardQuery {
    /// Agent names; a forward of any of them matches. Empty: every agent.
    pub agents: Vec<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub state: Option<String>,
    /// Free words, each must match somewhere.
    pub words: Vec<String>,
    pub sort: ForwardSort,
}

impl ForwardQuery {
    /// Parses filter words as typed in the terminal UI or given to `rift list forwards`.
    pub fn parse(text: &str) -> Result<Self> {
        let mut query = Self::default();
        for word in text
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter(|w| !w.is_empty())
        {
            query.add(word)?;
        }
        Ok(query)
    }

    pub fn add(&mut self, word: &str) -> Result<()> {
        match word.split_once(':') {
            Some(("agent", name)) if !name.is_empty() => self.agents.push(name.to_lowercase()),
            Some(("port", port)) => match port.parse() {
                Ok(port) => self.port = Some(port),
                Err(_) => bail!("port:{port} is not a port number"),
            },
            Some(("proto" | "protocol", protocol)) => match protocol {
                "tcp" | "udp" => self.protocol = Some(protocol.into()),
                _ => bail!("proto:{protocol}: use proto:tcp or proto:udp"),
            },
            Some(("state", state)) if !state.is_empty() => self.state = Some(state.to_lowercase()),
            // Anything else with a colon is an IPv6 address or part of one.
            _ => self.words.push(word.to_lowercase()),
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
            && self.port.is_none()
            && self.protocol.is_none()
            && self.state.is_none()
            && self.words.is_empty()
    }

    /// The forwards that match, sorted. `agent` gives a forward's agent name.
    pub fn apply(&self, forwards: &[Value], agent: impl Fn(&Value) -> String) -> Vec<Value> {
        let mut out: Vec<(String, Value)> = forwards
            .iter()
            .map(|f| (agent(f).to_lowercase(), f))
            .filter(|(name, f)| self.matches(f, name))
            .map(|(name, f)| (name, f.clone()))
            .collect();
        let id = |f: &Value| f["id"].as_u64().unwrap_or(0);
        let port = |f: &Value| f["listen_ports"]["start"].as_u64().unwrap_or(0);
        match self.sort {
            ForwardSort::Id => out.sort_by_key(|(_, f)| id(f)),
            ForwardSort::Agent => out.sort_by(|(a, x), (b, y)| {
                a.cmp(b).then(port(x).cmp(&port(y))).then(id(x).cmp(&id(y)))
            }),
            ForwardSort::Port => out.sort_by_key(|(_, f)| (port(f), id(f))),
            ForwardSort::State => out.sort_by(|(_, x), (_, y)| {
                state_rank(x).cmp(&state_rank(y)).then(id(x).cmp(&id(y)))
            }),
        }
        out.into_iter().map(|(_, f)| f).collect()
    }

    fn matches(&self, f: &Value, agent: &str) -> bool {
        if !self.agents.is_empty() && !self.agents.iter().any(|a| a == agent) {
            return false;
        }
        if self.port.is_some_and(|p| !has_port(f, p)) {
            return false;
        }
        if self
            .protocol
            .as_deref()
            .is_some_and(|p| f["protocol"].as_str() != Some(p))
        {
            return false;
        }
        if self
            .state
            .as_deref()
            .is_some_and(|s| !state(f).starts_with(s))
        {
            return false;
        }
        self.words.iter().all(|word| {
            if let Ok(n) = word.parse::<u64>() {
                return f["id"].as_u64() == Some(n)
                    || u16::try_from(n).is_ok_and(|p| has_port(f, p));
            }
            let text = |key: &str| f[key].as_str().unwrap_or_default().to_lowercase();
            let allow = f["allow_from"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ");
            [
                agent.to_string(),
                text("listen_ip"),
                text("protocol"),
                text("mode"),
                text("ingress"),
                text("purpose"),
                state(f),
                allow.to_lowercase(),
            ]
            .iter()
            .any(|field| field.contains(word.as_str()))
        })
    }
}

/// Whether every word appears (ignoring case) in some text or number anywhere in `value`.
/// The filter of the other lists: agents, devices, sites, bans.
pub fn matches_words(value: &Value, words: &[String]) -> bool {
    let mut text = String::new();
    collect(value, &mut text);
    words.iter().all(|w| text.contains(&w.to_lowercase()))
}

fn collect(value: &Value, out: &mut String) {
    match value {
        Value::String(s) => {
            out.push_str(&s.to_lowercase());
            out.push('\n');
        }
        Value::Number(n) => {
            out.push_str(&n.to_string());
            out.push('\n');
        }
        Value::Array(list) => list.iter().for_each(|v| collect(v, out)),
        Value::Object(map) => map.values().for_each(|v| collect(v, out)),
        _ => {}
    }
}

/// Filter words as typed: separated by spaces or commas.
pub fn words(text: &str) -> Vec<String> {
    text.split(|c: char| c.is_whitespace() || c == ',')
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// Whether a VPN device reaches `agent`: a grant on it or an exit through it.
pub fn device_uses(device: &Value, agent: &str) -> bool {
    let named = |v: &Value| {
        v["agent"]
            .as_str()
            .is_some_and(|a| a.eq_ignore_ascii_case(agent))
    };
    ["grants", "exits"]
        .iter()
        .any(|key| device[*key].as_array().into_iter().flatten().any(named))
}

/// Working first, then waiting, then failing, then switched off.
fn state_rank(f: &Value) -> u8 {
    match state(f).as_str() {
        "active" | "enabled" => 0,
        "pending" => 1,
        "refused" | "not applicable" => 2,
        "disabled" => 3,
        _ => 4,
    }
}

/// Whether a listen or target port range of the forward contains `port`.
fn has_port(f: &Value, port: u16) -> bool {
    ["listen_ports", "target_ports"].iter().any(|key| {
        let start = f[key]["start"].as_u64().unwrap_or(0);
        let end = f[key]["end"].as_u64().unwrap_or(start);
        (start..=end).contains(&u64::from(port))
    })
}

/// The state word of a forward, from `rift list forwards` (`state`) or the panel's overview
/// (`enabled`, `pending`, `refused`).
pub fn state(f: &Value) -> String {
    if let Some(state) = f["state"].as_str() {
        return state.to_lowercase();
    }
    if !f["refused"].is_null() {
        "refused".into()
    } else if f["enabled"] != true {
        "disabled".into()
    } else if f["pending"] == true {
        "pending".into()
    } else {
        "active".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn forward(id: u64, agent: &str, proto: &str, listen: (u16, u16), target: u16) -> Value {
        json!({"id": id, "agent": agent, "protocol": proto, "listen_ip": "203.0.113.10",
            "listen_ports": {"start": listen.0, "end": listen.1},
            "target_ports": {"start": target, "end": target + (listen.1 - listen.0)},
            "mode": "transparent", "ingress": "public", "enabled": true})
    }
    fn ids(list: &[Value]) -> Vec<u64> {
        list.iter().map(|f| f["id"].as_u64().unwrap()).collect()
    }
    fn list() -> Vec<Value> {
        let mut disabled = forward(4, "nas", "tcp", (2222, 2222), 22);
        disabled["enabled"] = false.into();
        let mut pending = forward(3, "nas", "udp", (27015, 27020), 27015);
        pending["pending"] = true.into();
        vec![
            pending,
            forward(1, "homelab", "tcp", (8080, 8080), 80),
            disabled,
            forward(2, "Homelab", "udp", (53, 53), 53),
        ]
    }
    fn run(text: &str) -> Vec<u64> {
        ids(&ForwardQuery::parse(text)
            .unwrap()
            .apply(&list(), |f| f["agent"].as_str().unwrap().into()))
    }

    #[test]
    fn words_and_fields_narrow_the_list() {
        assert_eq!(run(""), [1, 2, 3, 4]);
        assert_eq!(run("agent:homelab"), [1, 2], "names ignore case");
        assert_eq!(run("agent:nas agent:homelab proto:udp"), [2, 3]);
        assert_eq!(run("27017"), [3], "a port inside a range");
        assert_eq!(run("80"), [1], "a target port");
        assert_eq!(run("4"), [4], "an ID");
        assert_eq!(run("port:22"), [4]);
        assert_eq!(run("state:dis"), [4]);
        assert_eq!(run("state:pend"), [3]);
        assert_eq!(run("home tcp"), [1], "every word must match");
        assert_eq!(run("203.0.113"), [1, 2, 3, 4]);
        assert!(run("nothing").is_empty());
        assert!(ForwardQuery::parse("port:x").is_err());
        assert!(ForwardQuery::parse("proto:icmp").is_err());
    }

    #[test]
    fn sorting_by_each_key() {
        let sorted = |sort| {
            let query = ForwardQuery {
                sort,
                ..Default::default()
            };
            ids(&query.apply(&list(), |f| f["agent"].as_str().unwrap().into()))
        };
        assert_eq!(sorted(ForwardSort::Id), [1, 2, 3, 4]);
        assert_eq!(sorted(ForwardSort::Agent), [2, 1, 4, 3]);
        assert_eq!(sorted(ForwardSort::Port), [2, 4, 1, 3]);
        assert_eq!(
            sorted(ForwardSort::State),
            [1, 2, 3, 4],
            "active before disabled"
        );
        assert_eq!(ForwardSort::State.next(), ForwardSort::Id);
        assert_eq!("port".parse::<ForwardSort>(), Ok(ForwardSort::Port));
    }

    #[test]
    fn other_lists_match_words_anywhere() {
        let device = json!({"name": "Phone", "ipv4": "10.14.0.2",
            "grants": [{"agent": "nas", "access": {"port": {"protocol": "tcp", "ports": {"start": 22, "end": 22}}}}],
            "exits": [{"via": "agent", "agent": "Homelab"}]});
        assert!(matches_words(&device, &words("phone")));
        assert!(matches_words(&device, &words("10.14 nas, 22")));
        assert!(!matches_words(&device, &words("phone laptop")));
        assert!(device_uses(&device, "nas") && device_uses(&device, "homelab"));
        assert!(!device_uses(&device, "core"));
    }

    #[test]
    fn the_state_comes_from_either_shape() {
        assert_eq!(state(&json!({"state": "Pending"})), "pending");
        assert_eq!(state(&json!({"enabled": true, "refused": "no"})), "refused");
        assert_eq!(state(&json!({"enabled": true, "pending": true})), "pending");
        assert_eq!(state(&json!({"enabled": false})), "disabled");
        assert_eq!(state(&json!({"enabled": true})), "active");
    }
}
