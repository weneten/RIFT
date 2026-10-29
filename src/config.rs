use anyhow::{bail, ensure, Context, Result};
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum HostFirewall {
    #[default]
    Auto,
    Off,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub state_dir: PathBuf,
    pub interface: String,
    pub public_endpoint: String,
    pub public_ips: Vec<IpAddr>,
    pub wg_port: u16,
    pub enrollment_bind: SocketAddr,
    pub enrollment_enabled: bool,
    pub control_port: u16,
    pub ipv4_pool: Ipv4Net,
    pub ipv6_pool: Ipv6Net,
    pub server_ipv4: Ipv4Addr,
    pub server_ipv6: Ipv6Addr,
    pub route_table: u32,
    pub rule_priority: u32,
    pub mark: u32,
    pub mark_mask: u32,
    pub keepalive: u16,
    pub mtu: u16,
    pub handshake_timeout: u64,
    pub poll_seconds: u64,
    /// `auto` extends UFW user chains when they exist. `off` leaves the host firewall untouched.
    pub host_firewall: HostFirewall,
    pub agent_name: Option<String>,
    pub server_address: Option<String>,
    #[serde(skip)]
    pub enrollment_token: Option<String>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub tls_ca: Option<PathBuf>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            state_dir: "/var/lib/rift".into(),
            interface: "rift0".into(),
            public_endpoint: "".into(),
            public_ips: vec![],
            wg_port: 51820,
            enrollment_bind: "0.0.0.0:8443".parse().unwrap(),
            enrollment_enabled: true,
            control_port: 8444,
            ipv4_pool: "10.88.0.0/24".parse().unwrap(),
            ipv6_pool: "fd88:5249:4654::/64".parse().unwrap(),
            server_ipv4: "10.88.0.1".parse().unwrap(),
            server_ipv6: "fd88:5249:4654::1".parse().unwrap(),
            route_table: 51888,
            rule_priority: 11000,
            mark: 0x52490000,
            mark_mask: 0xffff0000,
            keepalive: 25,
            mtu: 1380,
            handshake_timeout: 180,
            poll_seconds: 10,
            host_firewall: HostFirewall::Auto,
            agent_name: None,
            server_address: None,
            enrollment_token: None,
            tls_cert: None,
            tls_key: None,
            tls_ca: None,
        }
    }
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let mut config: Self = toml::from_str(
            &std::fs::read_to_string(path)
                .with_context(|| format!("read config {}", path.display()))?,
        )?;
        macro_rules! env_string {
            ($key:literal,$field:ident) => {
                if let Ok(v) = std::env::var($key) {
                    if !v.is_empty() {
                        config.$field = v;
                    }
                }
            };
        }
        env_string!("RIFT_PUBLIC_ENDPOINT", public_endpoint);
        if let Ok(v) = std::env::var("RIFT_STATE_DIR") {
            config.state_dir = v.into();
        }
        if let Ok(v) = std::env::var("RIFT_PUBLIC_IPS") {
            config.public_ips = v
                .split(',')
                .filter(|x| !x.trim().is_empty())
                .map(|x| x.trim().parse())
                .collect::<std::result::Result<_, _>>()?;
        }
        if let Ok(v) = std::env::var("RIFT_ENROLLMENT_BIND") {
            if !v.is_empty() {
                config.enrollment_bind = v.parse()?;
            }
        }
        if let Ok(v) = std::env::var("RIFT_ENROLLMENT_ENABLED") {
            if !v.is_empty() {
                config.enrollment_enabled = v.parse()?;
            }
        }
        macro_rules! env_parse {
            ($key:literal,$field:ident) => {
                if let Ok(v) = std::env::var($key) {
                    if !v.trim().is_empty() {
                        config.$field = v
                            .trim()
                            .parse()
                            .with_context(|| format!("invalid {}", $key))?;
                    }
                }
            };
        }
        env_parse!("RIFT_IPV4_POOL", ipv4_pool);
        env_parse!("RIFT_IPV6_POOL", ipv6_pool);
        env_parse!("RIFT_SERVER_IPV4", server_ipv4);
        env_parse!("RIFT_SERVER_IPV6", server_ipv6);
        if let Ok(v) = std::env::var("RIFT_HOST_FIREWALL") {
            if !v.is_empty() {
                config.host_firewall = match v.to_ascii_lowercase().as_str() {
                    "auto" => HostFirewall::Auto,
                    "off" => HostFirewall::Off,
                    _ => bail!("RIFT_HOST_FIREWALL must be auto or off"),
                };
            }
        }
        for (key, slot) in [
            ("RIFT_AGENT_NAME", &mut config.agent_name),
            ("RIFT_SERVER", &mut config.server_address),
            ("RIFT_ENROLLMENT_TOKEN", &mut config.enrollment_token),
        ] {
            if let Ok(v) = std::env::var(key) {
                if !v.is_empty() {
                    *slot = Some(v);
                }
            }
        }
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        if !self.public_endpoint.is_empty() {
            ensure!(self.public_endpoint.parse::<IpAddr>().is_ok() || (self.public_endpoint.len()<=253 && self.public_endpoint.split('.').all(|part| !part.is_empty() && part.len()<=63 && !part.starts_with('-') && !part.ends_with('-') && part.chars().all(|c|c.is_ascii_alphanumeric() || c=='-'))),"public_endpoint must be a DNS hostname or IP address without port, brackets or scheme");
        }
        ensure!(
            !self.interface.is_empty()
                && self.interface.len() <= 15
                && self
                    .interface
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "invalid interface name"
        );
        ensure!(
            self.ipv4_pool.prefix_len() >= 8 && self.ipv4_pool.prefix_len() <= 29,
            "IPv4 pool prefix must be /8../29"
        );
        ensure!(
            self.ipv4_pool.network().is_private(),
            "IPv4 pool must be private"
        );
        ensure!(
            (u128::from(self.ipv6_pool.network()) >> 121) == 0x7e
                && self.ipv6_pool.prefix_len() <= 120,
            "IPv6 pool must be ULA with room for agents"
        );
        ensure!(
            self.ipv4_pool.contains(&self.server_ipv4)
                && self.ipv6_pool.contains(&self.server_ipv6),
            "server tunnel addresses must belong to pools"
        );
        ensure!(
            self.server_ipv4 != self.ipv4_pool.network()
                && self.server_ipv4 != self.ipv4_pool.broadcast(),
            "server IPv4 must be a usable host address"
        );
        ensure!(
            self.route_table > 255 && self.rule_priority > 0 && self.rule_priority < 32764,
            "reserved routing table / priority invalid"
        );
        ensure!(
            self.mark != 0 && self.mark_mask != 0 && self.mark & !self.mark_mask == 0,
            "mark must fit nonzero mask"
        );
        ensure!(
            self.wg_port != 0 && self.control_port != 0 && self.enrollment_bind.port() != 0,
            "ports must be nonzero"
        );
        ensure!(
            self.control_port != self.enrollment_bind.port(),
            "control and enrollment ports must differ"
        );
        ensure!((1280..=1420).contains(&self.mtu), "MTU must be 1280..1420");
        ensure!(
            self.keepalive > 0 && self.poll_seconds >= 2,
            "keepalive must be positive and polling at least 2s"
        );
        let tls_count = usize::from(self.tls_cert.is_some())
            + usize::from(self.tls_key.is_some())
            + usize::from(self.tls_ca.is_some());
        ensure!(
            tls_count == 0 || tls_count == 3,
            "TLS certificate, key and CA must be configured together"
        );
        for ip in &self.public_ips {
            ensure!(
                !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback(),
                "public IP allowlist contains invalid address"
            );
        }
        if let Some(name) = &self.agent_name {
            validate_name(name)?;
        }
        Ok(())
    }
    pub fn socket_path(&self) -> PathBuf {
        self.state_dir.join("admin.sock")
    }
    pub fn private_key_path(&self) -> PathBuf {
        self.state_dir.join("wireguard.key")
    }
    pub fn identity_path(&self) -> PathBuf {
        self.state_dir.join("identity.json")
    }
}
pub fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 63
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "name must contain 1..63 ASCII letters, digits, '-' or '_'"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_valid() {
        Config::default().validate().unwrap();
    }
    #[test]
    fn rejects_unsafe_interface() {
        let c = Config {
            interface: "rift0;id".into(),
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }
    #[test]
    fn host_firewall_defaults_to_auto_and_parses_off() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.host_firewall, HostFirewall::Auto);
        let config: Config = toml::from_str("host_firewall = \"off\"\n").unwrap();
        assert_eq!(config.host_firewall, HostFirewall::Off);
    }
    #[test]
    fn rejects_non_ula() {
        let c = Config {
            ipv6_pool: "2001:db8::/64".parse().unwrap(),
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }
}
