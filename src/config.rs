use anyhow::{bail, ensure, Context, Result};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
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

/// When the enrollment port listens. `auto` opens it only while an invitation is open and
/// closes it again on activation, expiry or cancellation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum EnrollmentMode {
    #[default]
    Auto,
    Always,
    Off,
}
impl std::str::FromStr for EnrollmentMode {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim() {
            "auto" => Ok(Self::Auto),
            "always" => Ok(Self::Always),
            "off" => Ok(Self::Off),
            _ => bail!("enrollment must be auto, always or off"),
        }
    }
}
impl std::fmt::Display for EnrollmentMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Auto => "auto",
            Self::Always => "always",
            Self::Off => "off",
        })
    }
}

/// Whether panel sessions may change anything. `private` allows changes only from loopback
/// without proxy headers and from VPN devices granted the panel; `off` makes it read-only.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum PanelControl {
    #[default]
    Private,
    Off,
}
impl std::str::FromStr for PanelControl {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim() {
            "private" => Ok(Self::Private),
            "off" => Ok(Self::Off),
            _ => bail!("web panel control must be private or off"),
        }
    }
}

/// Who can open the web panel. `private` listens on the VPS's loopback and its tunnel
/// address only; `public` listens on every address.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum PanelAccess {
    #[default]
    Private,
    Public,
}
impl std::str::FromStr for PanelAccess {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim() {
            "private" => Ok(Self::Private),
            "public" => Ok(Self::Public),
            _ => bail!("web panel access must be private or public"),
        }
    }
}
impl std::fmt::Display for PanelAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Private => "private",
            Self::Public => "public",
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub state_dir: PathBuf,
    pub interface: String,
    pub public_endpoint: String,
    pub public_ips: Vec<IpAddr>,
    /// For clouds that NAT the public address to a private one on the VM (e.g. Oracle Cloud):
    /// lets `public_ips` hold the private interface address. Loopback, link-local, multicast
    /// and unspecified addresses stay forbidden.
    pub allow_private_listeners: bool,
    pub wg_port: u16,
    pub enrollment_bind: SocketAddr,
    pub enrollment: EnrollmentMode,
    pub control_port: u16,
    pub ipv4_pool: Ipv4Net,
    pub ipv6_pool: Ipv6Net,
    pub server_ipv4: Ipv4Addr,
    pub server_ipv6: Ipv6Addr,
    /// Addresses for private VPN peers (phones, laptops). Must not overlap `ipv4_pool`.
    pub vpn_pool: Ipv4Net,
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
    /// Server only. Serves the web panel; off unless enabled.
    pub webpanel: bool,
    pub webpanel_access: PanelAccess,
    pub webpanel_port: u16,
    pub webpanel_control: PanelControl,
    /// Extra source addresses that may open the panel besides loopback and the VPN devices
    /// granted with `rift panel allow`. In public mode a non-empty list restricts the panel to it.
    pub webpanel_allow: Vec<IpNet>,
    /// From the environment only. Without it a generated password lives in the state directory.
    #[serde(skip)]
    pub webpanel_password: Option<String>,
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
            allow_private_listeners: false,
            wg_port: 51820,
            enrollment_bind: "0.0.0.0:8443".parse().unwrap(),
            enrollment: EnrollmentMode::Auto,
            control_port: 8444,
            ipv4_pool: "10.13.0.0/24".parse().unwrap(),
            ipv6_pool: "fd88:5249:4654::/64".parse().unwrap(),
            server_ipv4: "10.13.0.1".parse().unwrap(),
            server_ipv6: "fd88:5249:4654::1".parse().unwrap(),
            vpn_pool: "10.14.0.0/24".parse().unwrap(),
            route_table: 51888,
            rule_priority: 11000,
            mark: 0x52490000,
            mark_mask: 0xffff0000,
            keepalive: 25,
            mtu: 1380,
            handshake_timeout: 180,
            poll_seconds: 10,
            host_firewall: HostFirewall::Auto,
            webpanel: false,
            webpanel_access: PanelAccess::Private,
            webpanel_port: 8090,
            webpanel_control: PanelControl::Private,
            webpanel_allow: vec![],
            webpanel_password: None,
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
        env_parse!("RIFT_ENROLLMENT", enrollment);
        env_parse!("RIFT_ALLOW_PRIVATE_LISTENERS", allow_private_listeners);
        env_parse!("RIFT_WG_PORT", wg_port);
        env_parse!("RIFT_IPV4_POOL", ipv4_pool);
        env_parse!("RIFT_IPV6_POOL", ipv6_pool);
        env_parse!("RIFT_SERVER_IPV4", server_ipv4);
        env_parse!("RIFT_SERVER_IPV6", server_ipv6);
        env_parse!("RIFT_VPN_POOL", vpn_pool);
        env_parse!("RIFT_WEBPANEL", webpanel);
        env_parse!("RIFT_WEBPANEL_ACCESS", webpanel_access);
        env_parse!("RIFT_WEBPANEL_PORT", webpanel_port);
        env_parse!("RIFT_WEBPANEL_CONTROL", webpanel_control);
        if let Ok(v) = std::env::var("RIFT_WEBPANEL_ALLOW") {
            config.webpanel_allow = parse_allow_list(&v).context("invalid RIFT_WEBPANEL_ALLOW")?;
        }
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
            ("RIFT_WEBPANEL_PASSWORD", &mut config.webpanel_password),
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
            self.vpn_pool.prefix_len() >= 8
                && self.vpn_pool.prefix_len() <= 29
                && self.vpn_pool.network().is_private(),
            "VPN pool must be a private /8../29 network"
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
            let in_tunnel_pool = match ip {
                IpAddr::V4(v) => self.ipv4_pool.contains(v),
                IpAddr::V6(v) => self.ipv6_pool.contains(v),
            };
            ensure!(
                !in_tunnel_pool,
                "public IP {ip} lies inside a tunnel pool; choose different tunnel pools"
            );
        }
        if let Some(name) = &self.agent_name {
            validate_name(name)?;
        }
        if self.webpanel {
            ensure!(
                self.webpanel_port != 0
                    && self.webpanel_port != self.control_port
                    && self.webpanel_port != self.enrollment_bind.port(),
                "web panel port must be nonzero and differ from the control and enrollment ports"
            );
            if let Some(password) = &self.webpanel_password {
                ensure!(
                    password.chars().count() >= 12,
                    "RIFT_WEBPANEL_PASSWORD must have at least 12 characters"
                );
            }
        }
        Ok(())
    }
    /// Checked only once VPN peers exist, so a deployment that never uses the VPN is not
    /// affected by the default pool overlapping a pool it chose itself.
    pub fn check_vpn_pool(&self) -> Result<()> {
        ensure!(
            !self.vpn_pool.contains(&self.ipv4_pool.network())
                && !self.ipv4_pool.contains(&self.vpn_pool.network())
                && self.public_ips.iter().all(|ip| !matches!(ip, IpAddr::V4(v) if self.vpn_pool.contains(v))),
            "VPN pool {} overlaps the IPv4 tunnel pool or a public IP; set RIFT_VPN_POOL (restart required)",
            self.vpn_pool
        );
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
/// Comma-separated addresses or networks; a bare address means that single host.
pub fn parse_allow_list(text: &str) -> Result<Vec<IpNet>> {
    text.split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(|x| {
            x.parse::<IpNet>()
                .or_else(|_| x.parse::<IpAddr>().map(IpNet::from))
                .map(|net| net.trunc())
                .with_context(|| format!("{x:?} is not an address or network"))
        })
        .collect()
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
    fn private_listeners_are_off_by_default_and_never_inside_a_tunnel_pool() {
        let config: Config = toml::from_str("").unwrap();
        assert!(!config.allow_private_listeners);
        let config: Config = toml::from_str("allow_private_listeners = true\n").unwrap();
        assert!(config.allow_private_listeners);
        let ok = Config {
            allow_private_listeners: true,
            public_ips: vec!["10.0.0.45".parse().unwrap()],
            ..Default::default()
        };
        ok.validate().unwrap();
        let inside = Config {
            allow_private_listeners: true,
            public_ips: vec!["10.13.0.7".parse().unwrap()],
            ..Default::default()
        };
        assert!(inside.validate().is_err());
    }
    #[test]
    fn host_firewall_defaults_to_auto_and_parses_off() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.host_firewall, HostFirewall::Auto);
        let config: Config = toml::from_str("host_firewall = \"off\"\n").unwrap();
        assert_eq!(config.host_firewall, HostFirewall::Off);
    }
    #[test]
    fn vpn_pool_is_private_and_checked_against_the_tunnel_pool_on_use() {
        let overlapping = Config {
            vpn_pool: "10.13.0.128/25".parse().unwrap(),
            ..Default::default()
        };
        overlapping.validate().unwrap();
        assert!(overlapping.check_vpn_pool().is_err());
        Config::default().check_vpn_pool().unwrap();
        let public = Config {
            vpn_pool: "203.0.113.0/24".parse().unwrap(),
            ..Default::default()
        };
        assert!(public.validate().is_err());
    }
    #[test]
    fn webpanel_is_off_and_private_by_default() {
        let config: Config = toml::from_str("").unwrap();
        assert!(!config.webpanel);
        assert_eq!(config.webpanel_access, PanelAccess::Private);
        assert!("everyone".parse::<PanelAccess>().is_err());
        let clash = Config {
            webpanel: true,
            webpanel_port: 8444,
            ..Default::default()
        };
        assert!(clash.validate().is_err());
        let short = Config {
            webpanel: true,
            webpanel_password: Some("short".into()),
            ..Default::default()
        };
        assert!(short.validate().is_err());
    }
    #[test]
    fn settings_accept_exactly_their_documented_values() {
        assert_eq!(Config::default().enrollment, EnrollmentMode::Auto);
        let parse = |text: &str| toml::from_str::<Config>(text).map(|c| c.enrollment);
        assert_eq!(
            parse("enrollment = \"always\"").unwrap(),
            EnrollmentMode::Always
        );
        assert_eq!(parse("enrollment = \"off\"").unwrap(), EnrollmentMode::Off);
        assert!(parse("enrollment = true").is_err());
        assert!(parse("enrollment_enabled = true").is_err());
        assert_eq!(
            "always".parse::<EnrollmentMode>().unwrap(),
            EnrollmentMode::Always
        );
        assert!("true".parse::<EnrollmentMode>().is_err());
        assert_eq!("off".parse::<PanelControl>().unwrap(), PanelControl::Off);
        assert!("none".parse::<PanelControl>().is_err());
        assert_eq!(
            "public".parse::<PanelAccess>().unwrap(),
            PanelAccess::Public
        );
        assert!("all".parse::<PanelAccess>().is_err());
    }
    #[test]
    fn allow_list_accepts_hosts_and_networks() {
        let list = parse_allow_list(" 10.14.0.5, 192.168.1.7/24 ,,2001:db8::1").unwrap();
        let shown: Vec<_> = list.iter().map(ToString::to_string).collect();
        assert_eq!(shown, ["10.14.0.5/32", "192.168.1.0/24", "2001:db8::1/128"]);
        assert!(parse_allow_list("example.net").is_err());
        assert!(parse_allow_list("").unwrap().is_empty());
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
