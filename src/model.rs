use anyhow::{bail, Context};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
}
impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}
impl std::str::FromStr for Protocol {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            _ => Err("protocol must be tcp or udp".into()),
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ForwardMode {
    Transparent,
    Translate,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Ingress {
    #[default]
    Public,
    Local,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    V4,
    V6,
}
impl Family {
    pub fn of(ip: IpAddr) -> Self {
        if ip.is_ipv4() {
            Self::V4
        } else {
            Self::V6
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}
impl PortRange {
    pub fn len(&self) -> u32 {
        if self.is_empty() {
            0
        } else {
            u32::from(self.end) - u32::from(self.start) + 1
        }
    }
    pub fn is_empty(&self) -> bool {
        self.start == 0 || self.end < self.start
    }
    pub fn overlaps(&self, other: Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.is_empty(),
            "ports must be in 1..65535 with start <= end"
        );
        Ok(())
    }
}
impl std::fmt::Display for PortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}
impl std::str::FromStr for PortRange {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (a, b) = s.split_once('-').unwrap_or((s, s));
        let result = Self {
            start: a.parse()?,
            end: b.parse()?,
        };
        result.validate()?;
        Ok(result)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Pending,
    Active,
    Disabled,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentRecord {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub tunnel_ipv4: Ipv4Addr,
    pub tunnel_ipv6: Ipv6Addr,
    pub status: AgentStatus,
    pub attempt_id: String,
    pub generation: u64,
    pub applied_generation: u64,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub pending_deadline: Option<i64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Forward {
    pub id: u64,
    pub agent_id: String,
    pub listen_ip: IpAddr,
    pub listen_ports: PortRange,
    pub target_ports: PortRange,
    pub protocol: Protocol,
    pub mode: ForwardMode,
    /// `local` DNATs only packets that did not arrive on a public-address NIC.
    pub ingress: Ingress,
    pub target_family: Family,
    pub enabled: bool,
    pub generation: u64,
}
impl Forward {
    pub fn target_ip(&self, agent: &AgentRecord) -> IpAddr {
        match self.target_family {
            Family::V4 => agent.tunnel_ipv4.into(),
            Family::V6 => agent.tunnel_ipv6.into(),
        }
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        self.listen_ports.validate()?;
        self.target_ports.validate()?;
        anyhow::ensure!(
            self.listen_ports.len() == self.target_ports.len(),
            "listen and target ranges must have equal length"
        );
        anyhow::ensure!(
            self.listen_ports.len() <= 4096,
            "a forward may contain at most 4096 ports"
        );
        anyhow::ensure!(
            !self.listen_ip.is_unspecified() && !self.listen_ip.is_multicast(),
            "listen IP must be an explicit unicast VPS address"
        );
        anyhow::ensure!(
            self.mode != ForwardMode::Transparent
                || Family::of(self.listen_ip) == self.target_family,
            "cross-family forwarding requires explicit translation mode"
        );
        anyhow::ensure!(
            self.mode != ForwardMode::Translate || Family::of(self.listen_ip) != self.target_family,
            "translation requires different address families"
        );
        anyhow::ensure!(
            self.ingress != Ingress::Local || self.mode == ForwardMode::Transparent,
            "local ingress applies only to transparent forwards"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ban {
    pub id: u64,
    pub agent_id: String,
    pub forward_id: u64,
    pub ip: IpAddr,
    pub expires_at: i64,
}
/// A roaming device (phone, laptop) that reaches the home side through the VPS.
/// The private key lives in a mode-0600 file, never in the snapshot.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnPeer {
    pub name: String,
    pub public_key: String,
    pub ipv4: Ipv4Addr,
    pub enabled: bool,
    pub created_at: i64,
    /// May open the web panel on the VPS's tunnel address.
    pub panel: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VpnAccess {
    /// TCP, UDP and ping to the agent's own tunnel address.
    Server,
    /// Every IP protocol to the agent's own tunnel address, still not its LAN.
    Full,
    /// One protocol and port range on the agent's own tunnel address.
    Port {
        protocol: Protocol,
        ports: PortRange,
    },
    /// An explicitly named network behind the agent. `snat` masquerades the peer's address
    /// on the agent, for LANs whose router has no route back to the VPN pool.
    Subnet {
        net: Ipv4Net,
        #[serde(default)]
        snat: bool,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnGrant {
    pub peer: String,
    pub agent_id: String,
    pub access: VpnAccess,
}
/// What an agent needs to know about one granted peer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentVpnRule {
    pub source: Ipv4Addr,
    pub access: VpnAccess,
}
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct StateSnapshot {
    pub generation: u64,
    pub agents: Vec<AgentRecord>,
    pub forwards: Vec<Forward>,
    pub bans: Vec<Ban>,
    pub vpn_peers: Vec<VpnPeer>,
    pub vpn_grants: Vec<VpnGrant>,
}
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AgentPolicy {
    pub generation: u64,
    pub forwards: Vec<Forward>,
    /// None only in the empty policy an agent applies before its first sync.
    pub vpn_pool: Option<Ipv4Net>,
    pub vpn: Vec<AgentVpnRule>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Welcome {
    pub agent_id: String,
    pub name: String,
    pub attempt_id: String,
    pub server_public_key: String,
    pub server_endpoint: String,
    pub server_ipv4: Ipv4Addr,
    pub server_ipv6: Ipv6Addr,
    pub tunnel_ipv4: Ipv4Addr,
    pub tunnel_ipv6: Ipv6Addr,
    pub keepalive: u16,
    pub control_port: u16,
    pub mtu: u16,
}
// No private key or invitation is stored in this file. wireguard.key is separate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub id: String,
    pub attempt_id: String,
    pub public_key: String,
    pub welcome: Option<Welcome>,
    pub active: bool,
    pub applied_generation: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PeerStats {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub last_handshake: i64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}
/// Which server addresses a forward listens on: the first IPv4 address (`v4`, the default),
/// the first IPv6 address (`v6`) or one of each (`all`), taken from `public_ips`.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ListenOn {
    V4,
    V6,
    All,
}

/// One port mapping of a `forwards add`. `on` is `None` when the spec did not name one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForwardPlan {
    pub listen: PortRange,
    pub target: PortRange,
    pub protocol: Protocol,
    pub on: Option<ListenOn>,
}

/// Parses `LISTEN[:TARGET]/tcp|udp|both[/v4|v6|all]` specs; `both` adds a TCP and a UDP forward.
/// The protocol is mandatory so a forward never silently becomes TCP.
pub fn parse_forward_specs(specs: &[String]) -> anyhow::Result<Vec<ForwardPlan>> {
    let mut plans = Vec::new();
    for spec in specs {
        let mut parts = spec.split('/');
        let ports = parts.next().unwrap_or_default();
        let proto = parts.next().with_context(|| {
            format!("{spec:?} needs a protocol: {spec}/tcp, {spec}/udp or {spec}/both")
        })?;
        let on = match parts.next() {
            None => None,
            Some("v4") => Some(ListenOn::V4),
            Some("v6") => Some(ListenOn::V6),
            Some("all") => Some(ListenOn::All),
            Some(_) => bail!("the address in {spec:?} must be /v4, /v6 or /all"),
        };
        anyhow::ensure!(parts.next().is_none(), "{spec:?} has too many parts");
        let (listen, target) = ports.split_once(':').unwrap_or((ports, ports));
        let listen: PortRange = listen
            .parse()
            .with_context(|| format!("invalid listen port in {spec:?}"))?;
        let target: PortRange = target
            .parse()
            .with_context(|| format!("invalid target port in {spec:?}"))?;
        let protocols = match proto {
            "tcp" => vec![Protocol::Tcp],
            "udp" => vec![Protocol::Udp],
            "both" => vec![Protocol::Tcp, Protocol::Udp],
            _ => bail!("protocol in {spec:?} must be tcp, udp or both"),
        };
        for protocol in protocols {
            plans.push(ForwardPlan {
                listen,
                target,
                protocol,
                on,
            });
        }
    }
    Ok(plans)
}

/// Choices of one `forwards add` that apply to all its forwards. `None` means automatic.
#[derive(Clone, Copy, Debug, Default)]
pub struct ForwardOptions {
    /// An explicit server address instead of `/v4`, `/v6` or `/all`.
    pub listen_ip: Option<IpAddr>,
    /// The addresses for specs that name none; `v4` when this is `None` as well.
    pub on: Option<ListenOn>,
    pub mode: Option<ForwardMode>,
    pub target_family: Option<Family>,
    pub ingress: Ingress,
}

/// The forwards one `forwards add` creates, validated, with IDs still to be assigned.
///
/// Without an explicit mode an IPv4 listener forwards transparently to the agent's IPv4
/// address. A public IPv6 listener translates to the agent's IPv4 address, because most
/// services listen on IPv4; the service then sees the VPS tunnel address instead of the
/// client's. `--mode transparent` keeps the client address but needs the service to accept
/// IPv6 on the agent's tunnel address.
pub fn build_forwards(
    agent: &str,
    plans: &[ForwardPlan],
    public_ips: &[IpAddr],
    options: ForwardOptions,
) -> anyhow::Result<Vec<Forward>> {
    let first = |v6: bool| public_ips.iter().copied().find(|ip| ip.is_ipv6() == v6);
    let v4 = || first(false).context("RIFT_PUBLIC_IPS has no IPv4 address; use /v6");
    let v6 = || {
        first(true).context("RIFT_PUBLIC_IPS has no IPv6 address; add the server's IPv6 address")
    };
    let mut out = Vec::new();
    for plan in plans {
        let ips = match (options.listen_ip, plan.on) {
            (Some(_), Some(_)) => bail!("/v4, /v6 or /all cannot be combined with --listen-ip"),
            (Some(ip), None) => vec![ip],
            (None, on) => match on.or(options.on).unwrap_or(ListenOn::V4) {
                ListenOn::V4 => vec![v4()?],
                ListenOn::V6 => vec![v6()?],
                ListenOn::All => vec![v4()?, v6()?],
            },
        };
        for listen_ip in ips {
            let own = Family::of(listen_ip);
            let other = match own {
                Family::V4 => Family::V6,
                Family::V6 => Family::V4,
            };
            let (mode, target_family) = match (options.mode, options.target_family) {
                (Some(mode), Some(family)) => (mode, family),
                (Some(ForwardMode::Transparent), None) => (ForwardMode::Transparent, own),
                (Some(ForwardMode::Translate), None) => (ForwardMode::Translate, other),
                (None, Some(family)) if family == own => (ForwardMode::Transparent, own),
                (None, Some(family)) => (ForwardMode::Translate, family),
                (None, None) if own == Family::V6 && options.ingress == Ingress::Public => {
                    (ForwardMode::Translate, Family::V4)
                }
                (None, None) => (ForwardMode::Transparent, own),
            };
            let forward = Forward {
                id: 0,
                agent_id: agent.into(),
                listen_ip,
                listen_ports: plan.listen,
                target_ports: plan.target,
                protocol: plan.protocol,
                mode,
                ingress: options.ingress,
                target_family,
                enabled: true,
                generation: 0,
            };
            forward.validate()?;
            out.push(forward);
        }
    }
    Ok(out)
}
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips() -> Vec<IpAddr> {
        vec![
            "203.0.113.10".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
        ]
    }
    fn build(spec: &str, ips: &[IpAddr], options: ForwardOptions) -> anyhow::Result<Vec<Forward>> {
        build_forwards("home", &parse_forward_specs(&[spec.into()])?, ips, options)
    }

    #[test]
    fn short_form_defaults_to_ipv4_and_takes_v6_or_all() {
        let v4 = build("8080:80/tcp", &ips(), Default::default()).unwrap();
        assert_eq!(v4.len(), 1);
        assert_eq!(v4[0].listen_ip, ips()[0]);
        assert_eq!(v4[0].mode, ForwardMode::Transparent);
        assert_eq!(v4[0].target_family, Family::V4);
        assert_eq!(
            build("80/tcp/v4", &ips(), Default::default()).unwrap(),
            v4_of(80)
        );

        let v6 = build("80/tcp/v6", &ips(), Default::default()).unwrap();
        assert_eq!(v6[0].listen_ip, ips()[1]);
        assert_eq!(
            (v6[0].mode, v6[0].target_family),
            (ForwardMode::Translate, Family::V4)
        );

        let all = build("53/both/all", &ips(), Default::default()).unwrap();
        assert_eq!(all.len(), 4, "TCP and UDP on each address");
        // An explicit transparent mode keeps the IPv6 client address.
        let keep = ForwardOptions {
            mode: Some(ForwardMode::Transparent),
            ..Default::default()
        };
        let v6 = build("80/tcp/v6", &ips(), keep).unwrap();
        assert_eq!(
            (v6[0].mode, v6[0].target_family),
            (ForwardMode::Transparent, Family::V6)
        );
    }

    fn v4_of(port: u16) -> Vec<Forward> {
        build(&format!("{port}/tcp"), &ips(), Default::default()).unwrap()
    }

    #[test]
    fn missing_addresses_and_conflicting_choices_are_errors() {
        let only_v4 = &ips()[..1];
        assert!(build("80/tcp/v6", only_v4, Default::default()).is_err());
        assert!(build("80/tcp/all", only_v4, Default::default()).is_err());
        assert!(build("80/tcp", &ips()[1..], Default::default()).is_err());
        let explicit = ForwardOptions {
            listen_ip: Some(ips()[1]),
            ..Default::default()
        };
        assert_eq!(
            build("80/tcp", &ips(), explicit).unwrap()[0].listen_ip,
            ips()[1]
        );
        assert!(build("80/tcp/v4", &ips(), explicit).is_err());
        assert!(parse_forward_specs(&["80/tcp/v5".into()]).is_err());
        assert!(parse_forward_specs(&["80/tcp/v4/x".into()]).is_err());
        // A form default applies only where the spec names nothing.
        let form = ForwardOptions {
            on: Some(ListenOn::V6),
            ..Default::default()
        };
        assert_eq!(
            build("80/tcp", &ips(), form).unwrap()[0].listen_ip,
            ips()[1]
        );
        assert_eq!(
            build("80/tcp/v4", &ips(), form).unwrap()[0].listen_ip,
            ips()[0]
        );
    }
}
