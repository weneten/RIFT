use crate::model::{AgentLimits, PortAllow};
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
/// without proxy headers and from VPN devices granted the panel; `off` makes it read-only;
/// `public` also allows changes through a TLS proxy (`X-Forwarded-Proto: https` from loopback
/// or `RIFT_WEBPANEL_PROXIES`), where a password, and a code if two-factor login is on, is all
/// that stands between the internet and the network.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum PanelControl {
    #[default]
    Private,
    Off,
    Public,
}
impl std::str::FromStr for PanelControl {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim() {
            "private" => Ok(Self::Private),
            "off" => Ok(Self::Off),
            "public" => Ok(Self::Public),
            _ => bail!("web panel control must be private, public or off"),
        }
    }
}

/// Whether the web panel's login needs a one-time code. `optional`: only once someone turned
/// it on; `required`: no login at all until a secret is set up with `rift panel 2fa setup`.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum PanelTwoFactor {
    #[default]
    Optional,
    Required,
}
impl std::str::FromStr for PanelTwoFactor {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim() {
            "optional" => Ok(Self::Optional),
            "required" => Ok(Self::Required),
            _ => bail!("web panel two-factor login must be optional or required"),
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

/// Comma-separated `PORT`, `PORT-PORT`, optionally with `/tcp`, `/udp` or `/both`.
/// Empty means no restriction.
pub fn parse_port_allow(text: &str) -> Result<Option<Vec<PortAllow>>> {
    let list = text
        .split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::parse)
        .collect::<Result<Vec<PortAllow>>>()?;
    Ok((!list.is_empty()).then_some(list))
}
/// Comma-separated private IPv4 networks without host bits.
pub fn parse_subnet_allow(text: &str) -> Result<Vec<Ipv4Net>> {
    text.split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(|x| {
            let net: Ipv4Net = x
                .parse()
                .with_context(|| format!("{x:?} is not an IPv4 network"))?;
            check_allowed_subnet(&net)?;
            Ok(net)
        })
        .collect()
}
fn check_allowed_subnet(net: &Ipv4Net) -> Result<()> {
    ensure!(
        net.addr() == net.network(),
        "subnet {net} has host bits set; write it as {}",
        net.trunc()
    );
    ensure!(
        net.prefix_len() >= 8 && net.addr().is_private(),
        "allowed subnet {net} must be a private network of at least /8"
    );
    Ok(())
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
    /// The first host is the internet exit's gateway address and is never handed out.
    pub vpn_pool: Ipv4Net,
    /// The IPv6 addresses of VPN peers: a ULA network that does not overlap `ipv6_pool`.
    pub vpn_pool6: Ipv6Net,
    /// DNS servers written into the configuration of devices that have an internet exit.
    pub vpn_dns: Vec<IpAddr>,
    /// UDP ports the server assigns to the internet exits of agents.
    pub exit_port_min: u16,
    pub exit_port_max: u16,
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
    pub webpanel_2fa: PanelTwoFactor,
    /// Extra source addresses that may open the panel besides loopback and the VPN devices
    /// granted with `rift panel allow`. In public mode a non-empty list restricts the panel to it.
    pub webpanel_allow: Vec<IpNet>,
    /// TLS reverse proxies in front of a public panel: from these, a request with
    /// `X-Forwarded-Proto: https` may log in.
    pub webpanel_proxies: Vec<IpNet>,
    /// Allows the password over plain HTTP in public mode. Off: only HTTPS, the VPS itself, an
    /// SSH tunnel or a VPN device may log in.
    pub webpanel_insecure: bool,
    /// From the environment only. Without it a generated password lives in the state directory.
    #[serde(skip)]
    pub webpanel_password: Option<String>,
    /// Server only. The port RIFT's name server (`NAME.internal` for VPN devices) listens on,
    /// on the server's tunnel address; devices reach it as port 53 through a redirect.
    pub names_port: u16,
    /// Server only. The suffix of the agents' names (`RIFT_NAMES_SUFFIX`): `NAME.internal` by
    /// default; `home.arpa` or a domain of your own work too (see `vpn::validate_suffix`).
    pub names_suffix: String,
    /// Whether `rift` without a command opens the terminal UI (`RIFT_TUI`). On by default:
    /// it runs only through `docker exec` on the host, with the same rights as the CLI.
    pub tui: bool,
    pub agent_name: Option<String>,
    /// Agent only. When set, the agent refuses forwards and VPN port grants outside these
    /// ports, and VPN grants of the whole host, whatever the server asks for.
    pub agent_allow_ports: Option<Vec<PortAllow>>,
    /// Agent only. Networks behind the agent that VPN subnet grants may reach. Empty means
    /// the agent refuses every subnet grant.
    pub agent_allow_subnets: Vec<Ipv4Net>,
    /// Agent only. Whether the agent offers its internet connection as an exit for VPN devices.
    pub agent_allow_exit: bool,
    /// Agent only. Whether this agent opens and accepts links to and from other agents
    /// (`rift link allow`). On by default: a link still needs the server's grant, and the
    /// target's port limits apply.
    pub agent_allow_links: bool,
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
            vpn_pool6: "fd88:5249:4655::/64".parse().unwrap(),
            vpn_dns: vec!["9.9.9.9".parse().unwrap(), "2620:fe::fe".parse().unwrap()],
            exit_port_min: 51821,
            exit_port_max: 51899,
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
            webpanel_2fa: PanelTwoFactor::Optional,
            webpanel_allow: vec![],
            webpanel_proxies: vec![],
            webpanel_insecure: false,
            webpanel_password: None,
            names_port: crate::names::DNS_PORT,
            names_suffix: crate::vpn::NAMES_SUFFIX.into(),
            tui: true,
            agent_name: None,
            agent_allow_ports: None,
            agent_allow_subnets: vec![],
            agent_allow_exit: false,
            agent_allow_links: true,
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
        env_parse!("RIFT_VPN_POOL6", vpn_pool6);
        env_parse!("RIFT_AGENT_ALLOW_EXIT", agent_allow_exit);
        env_parse!("RIFT_AGENT_ALLOW_LINKS", agent_allow_links);
        if let Ok(v) = std::env::var("RIFT_VPN_DNS") {
            if !v.trim().is_empty() {
                config.vpn_dns = parse_dns_list(&v).context("invalid RIFT_VPN_DNS")?;
            }
        }
        env_parse!("RIFT_WEBPANEL", webpanel);
        env_parse!("RIFT_WEBPANEL_ACCESS", webpanel_access);
        env_parse!("RIFT_WEBPANEL_PORT", webpanel_port);
        env_parse!("RIFT_WEBPANEL_CONTROL", webpanel_control);
        env_parse!("RIFT_WEBPANEL_2FA", webpanel_2fa);
        env_parse!("RIFT_WEBPANEL_INSECURE", webpanel_insecure);
        env_parse!("RIFT_TUI", tui);
        env_parse!("RIFT_NAMES_PORT", names_port);
        if let Ok(v) = std::env::var("RIFT_NAMES_SUFFIX") {
            let v = v.trim().trim_matches('.').to_ascii_lowercase();
            if !v.is_empty() {
                config.names_suffix = v;
            }
        }
        if let Ok(v) = std::env::var("RIFT_WEBPANEL_PROXIES") {
            config.webpanel_proxies =
                parse_allow_list(&v).context("invalid RIFT_WEBPANEL_PROXIES")?;
        }
        if let Ok(v) = std::env::var("RIFT_WEBPANEL_ALLOW") {
            config.webpanel_allow = parse_allow_list(&v).context("invalid RIFT_WEBPANEL_ALLOW")?;
        }
        if let Ok(v) = std::env::var("RIFT_AGENT_ALLOW_PORTS") {
            if !v.trim().is_empty() {
                config.agent_allow_ports =
                    parse_port_allow(&v).context("invalid RIFT_AGENT_ALLOW_PORTS")?;
            }
        }
        if let Ok(v) = std::env::var("RIFT_AGENT_ALLOW_SUBNETS") {
            if !v.trim().is_empty() {
                config.agent_allow_subnets =
                    parse_subnet_allow(&v).context("invalid RIFT_AGENT_ALLOW_SUBNETS")?;
            }
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
        crate::vpn::set_names_suffix(&config.names_suffix);
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
            (u128::from(self.vpn_pool6.network()) >> 121) == 0x7e
                && self.vpn_pool6.prefix_len() <= 120,
            "VPN IPv6 pool must be a ULA network (fd00::/8) with room for devices"
        );
        ensure!(
            !self.vpn_pool6.contains(&self.ipv6_pool.network())
                && !self.ipv6_pool.contains(&self.vpn_pool6.network()),
            "VPN IPv6 pool {} overlaps the IPv6 tunnel pool {}; set RIFT_VPN_POOL6",
            self.vpn_pool6,
            self.ipv6_pool
        );
        ensure!(
            self.exit_port_min >= 1024
                && self.exit_port_min <= self.exit_port_max
                && !(self.exit_port_min..=self.exit_port_max).contains(&self.wg_port)
                && !(self.exit_port_min..=self.exit_port_max).contains(&self.control_port)
                && !(self.exit_port_min..=self.exit_port_max).contains(&self.enrollment_bind.port()),
            "the exit port range must start at 1024 or above, be ordered and not contain the WireGuard, control or enrollment port"
        );
        check_dns_list(&self.vpn_dns)?;
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
        if let Some(list) = &self.agent_allow_ports {
            ensure!(
                !list.is_empty(),
                "agent_allow_ports must not be an empty list"
            );
            for entry in list {
                entry.ports.validate()?;
            }
        }
        for net in &self.agent_allow_subnets {
            check_allowed_subnet(net)?;
        }
        crate::vpn::validate_suffix(&self.names_suffix)?;
        // The name server needs no capability: a port from 1024, apart from RIFT's other ports.
        ensure!(
            self.names_port >= 1024
                && self.names_port != self.control_port
                && self.names_port != self.enrollment_bind.port()
                && self.names_port != self.wg_port
                && !(self.exit_port_min..=self.exit_port_max).contains(&self.names_port)
                && !(self.webpanel && self.names_port == self.webpanel_port),
            "RIFT_NAMES_PORT must be 1024 or higher and differ from the control, enrollment, WireGuard, exit and panel ports"
        );
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
        ensure!(
            self.public_ips
                .iter()
                .all(|ip| !matches!(ip, IpAddr::V6(v) if self.vpn_pool6.contains(v))),
            "VPN IPv6 pool {} contains a public IP; set RIFT_VPN_POOL6 (restart required)",
            self.vpn_pool6
        );
        Ok(())
    }
    /// What this agent's owner allows the server to open here.
    pub fn agent_limits(&self) -> AgentLimits {
        AgentLimits {
            ports: self.agent_allow_ports.clone(),
            subnets: self.agent_allow_subnets.clone(),
            exit: self.agent_allow_exit,
            no_links: !self.agent_allow_links,
        }
    }
    /// Private key of the agent's `rift-exit` interface.
    pub fn exit_key_path(&self) -> PathBuf {
        self.state_dir.join("exit.key")
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
/// Comma-separated IP addresses of DNS servers.
pub fn parse_dns_list(text: &str) -> Result<Vec<IpAddr>> {
    let list = text
        .split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(|x| {
            x.parse::<IpAddr>()
                .with_context(|| format!("{x:?} is not an IP address"))
        })
        .collect::<Result<Vec<_>>>()?;
    check_dns_list(&list)?;
    Ok(list)
}
fn check_dns_list(list: &[IpAddr]) -> Result<()> {
    ensure!(
        list.iter()
            .all(|ip| !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback()),
        "DNS servers must be unicast addresses"
    );
    ensure!(
        list.iter().any(IpAddr::is_ipv4),
        "the DNS servers need at least one IPv4 address, for exits without IPv6"
    );
    Ok(())
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
    use crate::model::{PortRange, Protocol};
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
    fn the_name_server_port_is_free_of_rifts_other_ports() {
        assert_eq!(Config::default().names_port, 53053);
        let config: Config = toml::from_str("names_port = 5353\n").unwrap();
        assert_eq!(config.names_port, 5353);
        config.validate().unwrap();
        let with = |names_port, webpanel| Config {
            names_port,
            webpanel,
            ..Default::default()
        };
        for port in [53, 1023, 8444, 8443, 51820, 51850] {
            assert!(with(port, false).validate().is_err(), "{port}");
        }
        assert!(with(8090, false).validate().is_ok());
        assert!(with(8090, true).validate().is_err(), "the panel's port");
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
        assert_eq!(
            "public".parse::<PanelControl>().unwrap(),
            PanelControl::Public
        );
        assert!("none".parse::<PanelControl>().is_err());
        assert_eq!(
            "required".parse::<PanelTwoFactor>().unwrap(),
            PanelTwoFactor::Required
        );
        assert!("on".parse::<PanelTwoFactor>().is_err());
        assert_eq!(Config::default().webpanel_2fa, PanelTwoFactor::Optional);
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
    fn agent_port_allowlist_parses_strictly() {
        assert_eq!(parse_port_allow("").unwrap(), None);
        assert_eq!(parse_port_allow(" , ").unwrap(), None);
        let list = parse_port_allow("22/tcp, 80,443/both,27015-27020/udp")
            .unwrap()
            .unwrap();
        let pr = |a, b| PortRange { start: a, end: b };
        let entry = |ports, protocol| PortAllow { ports, protocol };
        assert_eq!(
            list,
            [
                entry(pr(22, 22), Some(Protocol::Tcp)),
                entry(pr(80, 80), None),
                entry(pr(443, 443), None),
                entry(pr(27015, 27020), Some(Protocol::Udp)),
            ]
        );
        for bad in [
            "0", "70000", "90-80", "22/TCP", "22/icmp", "tcp", "22/", "a-b", "22:80", "-5", "22 80",
        ] {
            assert!(parse_port_allow(bad).is_err(), "{bad} must be rejected");
        }
    }
    #[test]
    fn agent_subnet_allowlist_parses_strictly() {
        assert!(Config::default().agent_allow_subnets.is_empty());
        assert!(Config::default().agent_allow_ports.is_none());
        assert!(parse_subnet_allow("").unwrap().is_empty());
        let nets = parse_subnet_allow("192.168.178.0/24, 10.0.0.0/8").unwrap();
        assert_eq!(nets.len(), 2);
        for bad in [
            "192.168.178.5/24",
            "8.8.8.0/24",
            "192.168.0.1",
            "fd00::/64",
            "10.0.0.0/7",
            "lan",
        ] {
            assert!(parse_subnet_allow(bad).is_err(), "{bad} must be rejected");
        }
    }
    #[test]
    fn vpn_ipv6_pool_is_a_ula_network_apart_from_the_tunnel_pool() {
        let pool = |text: &str| Config {
            vpn_pool6: text.parse().unwrap(),
            ..Default::default()
        };
        assert_eq!(
            Config::default().vpn_pool6.to_string(),
            "fd88:5249:4655::/64"
        );
        pool("fd00:1::/64").validate().unwrap();
        assert!(pool("2001:db8::/64").validate().is_err(), "not a ULA");
        assert!(
            pool("fd88:5249:4654::/64").validate().is_err(),
            "tunnel pool"
        );
        assert!(
            pool("fd88:5249:4654:0:8000::/65").validate().is_err(),
            "inside it"
        );
        assert!(pool("fd00:1::/125").validate().is_err(), "room for devices");
        let public = Config {
            public_ips: vec!["fd00:1::5".parse().unwrap()],
            allow_private_listeners: true,
            ..pool("fd00:1::/64")
        };
        assert!(public.check_vpn_pool().is_err());
    }
    #[test]
    fn dns_defaults_to_quad9_and_needs_an_ipv4_server() {
        assert_eq!(
            parse_dns_list("9.9.9.9, 2620:fe::fe").unwrap(),
            Config::default().vpn_dns
        );
        assert!(parse_dns_list("2620:fe::fe").is_err());
        assert!(parse_dns_list("dns.example").is_err());
        assert!(parse_dns_list("0.0.0.0").is_err());
        assert!(parse_dns_list("").is_err());
    }
    #[test]
    fn exit_ports_stay_clear_of_the_other_ports() {
        let range = |a, b| Config {
            exit_port_min: a,
            exit_port_max: b,
            ..Default::default()
        };
        range(51821, 51899).validate().unwrap();
        assert!(range(51820, 51899).validate().is_err(), "WireGuard port");
        assert!(range(51899, 51821).validate().is_err(), "order");
        assert!(range(80, 90).validate().is_err(), "privileged ports");
        assert!(!Config::default().agent_allow_exit);
        assert!(Config::default().agent_allow_links);
        assert!(!Config::default().agent_limits().no_links);
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
