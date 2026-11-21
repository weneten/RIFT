use anyhow::{bail, Context};
use ipnet::{IpNet, Ipv4Net};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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
/// One entry of an agent's `RIFT_AGENT_ALLOW_PORTS`. `protocol` None means TCP and UDP.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortAllow {
    pub ports: PortRange,
    pub protocol: Option<Protocol>,
}
impl PortAllow {
    /// Whether `ports` over `protocol` lies entirely inside this entry.
    pub fn covers(&self, protocol: Protocol, ports: PortRange) -> bool {
        self.protocol.is_none_or(|p| p == protocol)
            && self.ports.start <= ports.start
            && ports.end <= self.ports.end
    }
}
impl std::str::FromStr for PortAllow {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> anyhow::Result<Self> {
        let s = s.trim();
        let (ports, protocol) = match s.split_once('/') {
            None => (s, None),
            Some((p, "tcp")) => (p, Some(Protocol::Tcp)),
            Some((p, "udp")) => (p, Some(Protocol::Udp)),
            Some((p, "both")) => (p, None),
            Some(_) => anyhow::bail!("{s:?}: protocol must be /tcp, /udp or /both"),
        };
        anyhow::ensure!(
            !ports.is_empty() && ports.chars().all(|c| c.is_ascii_digit() || c == '-'),
            "{s:?} is not a port or port range"
        );
        Ok(Self {
            ports: ports
                .parse()
                .with_context(|| format!("invalid ports in {s:?}"))?,
            protocol,
        })
    }
}
impl std::fmt::Display for PortAllow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.protocol {
            Some(protocol) => write!(f, "{}/{protocol}", self.ports),
            None => write!(f, "{}", self.ports),
        }
    }
}

/// What an agent's owner allows the server to open there (`RIFT_AGENT_ALLOW_PORTS`,
/// `RIFT_AGENT_ALLOW_SUBNETS`, `RIFT_AGENT_ALLOW_EXIT`). The agent enforces it and reports it
/// with every sync, so the server can warn about and leave out what the agent would refuse
/// anyway.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentLimits {
    /// `None` means any port.
    pub ports: Option<Vec<PortAllow>>,
    /// Networks behind the agent that subnet grants may reach; empty means none.
    pub subnets: Vec<Ipv4Net>,
    /// Whether the agent offers its internet connection as an exit for VPN devices. The UDP
    /// port of that exit is implied by this and needs no entry in `ports`.
    pub exit: bool,
    /// `RIFT_AGENT_ALLOW_LINKS=false`: the agent neither opens nor accepts links to and from
    /// other agents (`rift link allow`). Absent in reports of agents before links existed.
    #[serde(default)]
    pub no_links: bool,
}
impl AgentLimits {
    fn ports_allowed(&self, protocol: Protocol, ports: PortRange) -> bool {
        self.ports
            .as_ref()
            .is_none_or(|list| list.iter().any(|entry| entry.covers(protocol, ports)))
    }
    fn port_list(&self) -> String {
        self.ports
            .iter()
            .flatten()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
    /// Why the agent refuses to be an internet exit, if it does.
    pub fn refuse_exit(&self) -> Option<String> {
        (!self.exit).then(|| {
            "the agent does not offer an internet exit; set RIFT_AGENT_ALLOW_EXIT=true on the agent"
                .to_string()
        })
    }
    /// Why the agent refuses links to or from other agents, if it does.
    pub fn refuse_links(&self) -> Option<String> {
        self.no_links.then(|| {
            "the agent allows no links to or from other agents (RIFT_AGENT_ALLOW_LINKS=false)"
                .to_string()
        })
    }
    /// Why the agent refuses this forward, if it does. The forward of an internet exit is
    /// allowed by `RIFT_AGENT_ALLOW_EXIT` alone, whatever `RIFT_AGENT_ALLOW_PORTS` says.
    pub fn refuse_forward(&self, forward: &Forward) -> Option<String> {
        if forward.purpose == Purpose::Exit {
            return self.refuse_exit();
        }
        (!self.ports_allowed(forward.protocol, forward.target_ports)).then(|| {
            format!(
                "the agent allows only ports {} (RIFT_AGENT_ALLOW_PORTS); add {}/{}",
                self.port_list(),
                forward.target_ports,
                forward.protocol
            )
        })
    }
    /// Why the agent refuses this VPN grant, if it does.
    pub fn refuse_access(&self, access: &VpnAccess) -> Option<String> {
        match access {
            VpnAccess::Server | VpnAccess::Full => self.ports.is_some().then(|| {
                format!(
                    "it reaches every port, but the agent allows only ports {} (RIFT_AGENT_ALLOW_PORTS); grant single ports instead",
                    self.port_list()
                )
            }),
            VpnAccess::Dns => [Protocol::Udp, Protocol::Tcp]
                .into_iter()
                .any(|protocol| !self.ports_allowed(protocol, PortRange { start: 53, end: 53 }))
                .then(|| {
                    format!(
                        "the agent allows only ports {} (RIFT_AGENT_ALLOW_PORTS); add 53/both",
                        self.port_list()
                    )
                }),
            VpnAccess::Port { protocol, ports } => {
                (!self.ports_allowed(*protocol, *ports)).then(|| {
                    format!(
                        "the agent allows only ports {} (RIFT_AGENT_ALLOW_PORTS); add {ports}/{protocol}",
                        self.port_list()
                    )
                })
            }
            VpnAccess::Subnet { net, .. } => {
                (!self.subnets.iter().any(|allowed| allowed.contains(net))).then(|| {
                    if self.subnets.is_empty() {
                        format!("the agent allows no LAN access; add {net} to RIFT_AGENT_ALLOW_SUBNETS")
                    } else {
                        format!(
                            "the agent allows only {} (RIFT_AGENT_ALLOW_SUBNETS); add {net}",
                            self.subnets
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(",")
                        )
                    }
                })
            }
        }
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
    /// The agent's own limits as of its last sync; `None` before the first one.
    pub limits: Option<AgentLimits>,
    /// What the agent last reported about its exit interface; `None` when it has none.
    pub exit: Option<ExitReport>,
    /// The UDP port the server assigned to this agent's exit. Kept once assigned, so the
    /// configurations of devices stay valid while the exit is switched off and on.
    pub exit_port: Option<u16>,
    /// VPN devices with a grant on this agent resolve `NAME.internal` to its tunnel address
    /// (`rift vpn names agent NAME on`).
    #[serde(default)]
    pub names: bool,
    /// The DNS label chosen for the agent (`rift vpn names agent NAME on LABEL`); `None` uses
    /// its name (`vpn::agent_label`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_label: Option<String>,
    /// The protocol and release the agent reported with its last sync; 0 and empty before.
    #[serde(default)]
    pub protocol: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rift_version: String,
}
/// What an agent that offers an internet exit tells the server with every sync.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitReport {
    /// Public key of the agent's `rift-exit` interface; devices connect to it.
    pub public_key: String,
    /// The port `rift-exit` listens on right now; `None` until the agent applied the exit.
    pub listen_port: Option<u16>,
    /// Whether the agent host has a global IPv6 address, so the exit can carry IPv6.
    pub ipv6: bool,
}
/// Why a forward exists. The forward of an internet exit is managed by RIFT.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    #[default]
    User,
    Exit,
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
    pub purpose: Purpose,
    /// Client addresses or networks that may use the forward, all of the listener's family.
    /// Empty means every client.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_from: Vec<IpNet>,
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
        anyhow::ensure!(
            self.allow_from.is_empty() || self.ingress == Ingress::Public,
            "--allow-from applies to public forwards only; a local forward is reached through the proxy on the server"
        );
        anyhow::ensure!(
            self.allow_from.len() <= MAX_ALLOW_FROM,
            "--allow-from takes at most {MAX_ALLOW_FROM} addresses or networks"
        );
        for net in &self.allow_from {
            anyhow::ensure!(
                Family::of(net.addr()) == Family::of(self.listen_ip),
                "allowed source {net} does not match the address family of listener {}",
                self.listen_ip
            );
            anyhow::ensure!(
                *net == net.trunc(),
                "allowed source {net} has host bits set"
            );
        }
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
    pub ipv6: Ipv6Addr,
    /// The main profile routes all traffic through the VPS.
    pub server_exit: bool,
    /// Agents (by ID) that each end an extra profile with the same keys and addresses.
    pub agent_exits: Vec<String>,
    /// This device does not use RIFT's names even when an agent it reaches has them on
    /// (`rift vpn names device NAME off`).
    #[serde(default)]
    pub names_off: bool,
}
/// One internet exit of a device in requests: the VPS or the agent that the name gives.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Exit {
    Server,
    Agent(String),
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
    Subnet { net: Ipv4Net, snat: bool },
    /// DNS (port 53, UDP and TCP) on the agent's tunnel address, which the device's main
    /// profile also uses as its DNS server. At most one per device.
    Dns,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpnGrant {
    pub peer: String,
    pub agent_id: String,
    pub access: VpnAccess,
}
/// The VPS host itself may reach the agent's tunnel address (`rift host allow`): a connection
/// the host opens to the agent, from the server's own tunnel address. Only `Server`, `Full`
/// and `Port` make sense here; the agent sees it as a VPN rule whose source is the server.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostGrant {
    pub agent_id: String,
    pub access: VpnAccess,
}
/// A device may reach the VPS itself on its tunnel address (`rift vpn allow DEVICE rs ...`):
/// services of the VPS host such as SSH. Only `Server`, `Full` and `Port`; RIFT's own ports
/// (control, panel, name server) stay closed whatever the grant says.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerGrant {
    pub peer: String,
    pub access: VpnAccess,
}
/// One agent may open connections to another agent's tunnel address (`rift link allow`),
/// through the server. Directional: `to` cannot open connections back unless a link of its
/// own allows it. Only `Server`, `Full` and `Port`; the target sees it as a VPN rule whose
/// source is the tunnel address of `from`, the source as an outbound rule.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentLink {
    pub from_agent_id: String,
    pub to_agent_id: String,
    pub access: VpnAccess,
}
/// What the agent that opens a link needs: a route to the other agent's tunnel address and
/// the replies of the connections it opens there.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentOutboundRule {
    pub destination: Ipv4Addr,
    pub access: VpnAccess,
}
/// What an agent needs to know about one granted peer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentVpnRule {
    pub source: Ipv4Addr,
    pub access: VpnAccess,
}
/// The internet exit an agent is asked to run on its `rift-exit` interface.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitPolicy {
    pub listen_port: u16,
    /// Addresses of the interface itself: the first host of the VPN pools.
    pub gateway_v4: Ipv4Addr,
    pub gateway_v6: Ipv6Addr,
    pub peers: Vec<ExitPeer>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitPeer {
    pub public_key: String,
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
}
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct StateSnapshot {
    pub generation: u64,
    pub agents: Vec<AgentRecord>,
    pub forwards: Vec<Forward>,
    pub bans: Vec<Ban>,
    pub vpn_peers: Vec<VpnPeer>,
    pub vpn_grants: Vec<VpnGrant>,
    /// What the VPS host itself may reach on agents; absent in snapshots written before it existed.
    #[serde(default)]
    pub host_grants: Vec<HostGrant>,
    /// What agents may reach on other agents (`rift link allow`); absent before it existed.
    #[serde(default)]
    pub agent_links: Vec<AgentLink>,
    /// What devices may reach on the VPS itself (`rift vpn allow DEVICE rs ...`).
    #[serde(default)]
    pub server_grants: Vec<ServerGrant>,
    /// The DNS label of the VPS for devices with a server grant (`rift vpn names rs on
    /// LABEL`); `None` while its name is off. It has no default: the operator chooses it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_label: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AgentPolicy {
    pub generation: u64,
    pub forwards: Vec<Forward>,
    /// None only in the empty policy an agent applies before its first sync.
    pub vpn_pool: Option<Ipv4Net>,
    pub vpn: Vec<AgentVpnRule>,
    /// Present while a device uses this agent as its internet exit.
    pub exit: Option<ExitPolicy>,
    /// The agents' tunnel network (`RIFT_IPV4_POOL`). The agent installs outbound routes only
    /// inside it. Absent from servers before protocol 2.
    #[serde(default)]
    pub tunnel_pool: Option<Ipv4Net>,
    /// Links this agent opens to other agents (protocol 2).
    #[serde(default)]
    pub outbound: Vec<AgentOutboundRule>,
    /// The names of the agents this agent links to, for its host's resolver (protocol 2).
    #[serde(default)]
    pub names: Option<AgentNames>,
}
/// RIFT's name server and the names it answers for an agent's host: those of the agents the
/// agent opens links to that have names on (`node2.internal`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentNames {
    /// The server's tunnel address and `RIFT_NAMES_PORT`.
    pub server: SocketAddr,
    pub domains: Vec<String>,
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
/// The format of an agent's identity.json; see `daemon::read_identity`.
pub const IDENTITY_VERSION: u32 = 1;
// No private key or invitation is stored in this file. wireguard.key is separate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// The file's format; 0 in files written before formats were numbered (builds before 1.0).
    #[serde(default)]
    pub version: u32,
    pub id: String,
    pub attempt_id: String,
    pub public_key: String,
    pub welcome: Option<Welcome>,
    pub active: bool,
    pub applied_generation: u64,
    /// SHA-256 of the enrollment CA of the server this agent enrolled with, so a token of
    /// another server (one set up again) is recognised. Missing for agents enrolled before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ca: Option<String>,
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

/// One port mapping of a `add forward`. `on` is `None` when the spec did not name one.
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

/// Choices of one `add forward` that apply to all its forwards. `None` means automatic.
#[derive(Clone, Debug, Default)]
pub struct ForwardOptions {
    /// An explicit server address instead of `/v4`, `/v6` or `/all`.
    pub listen_ip: Option<IpAddr>,
    /// The addresses for specs that name none; `v4` when this is `None` as well.
    pub on: Option<ListenOn>,
    pub mode: Option<ForwardMode>,
    pub target_family: Option<Family>,
    pub ingress: Ingress,
    /// Client addresses that may connect; each forward keeps those of its listener's family.
    pub allow_from: Vec<IpNet>,
}

/// The most sources one forward or site may name.
pub const MAX_ALLOW_FROM: usize = 64;

/// Parses `--allow-from` values: addresses or networks, separated by commas or spaces, for
/// example `198.51.100.7, 203.0.113.0/24, 2001:db8::/48`. A bare address means that one host.
/// Host bits are cleared and duplicates removed.
pub fn parse_allow_from<S: AsRef<str>>(values: &[S]) -> anyhow::Result<Vec<IpNet>> {
    let mut out: Vec<IpNet> = Vec::new();
    for value in values {
        for word in value
            .as_ref()
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|w| !w.is_empty())
        {
            let net = match word.parse::<IpNet>() {
                Ok(net) => net.trunc(),
                Err(_) => IpNet::from(word.parse::<IpAddr>().with_context(|| {
                    format!(
                        "{word:?} is not an address or network like 203.0.113.7 or 198.51.100.0/24"
                    )
                })?),
            };
            if !out.contains(&net) {
                out.push(net);
            }
        }
    }
    anyhow::ensure!(
        out.len() <= MAX_ALLOW_FROM,
        "--allow-from takes at most {MAX_ALLOW_FROM} addresses or networks"
    );
    Ok(out)
}

/// The forwards one `add forward` creates, validated, with IDs still to be assigned.
///
/// Without an explicit mode every forward is transparent: it reaches the agent's tunnel
/// address of the listener's family and the service sees the client's address. `translate`
/// bridges families, for example an IPv6 listener to a service that only listens on IPv4.
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
                purpose: Purpose::User,
                allow_from: options
                    .allow_from
                    .iter()
                    .copied()
                    .filter(|net| Family::of(net.addr()) == own)
                    .collect(),
            };
            anyhow::ensure!(
                options.allow_from.is_empty() || !forward.allow_from.is_empty(),
                "--allow-from names no {} source for the listener {listen_ip}; add one or choose {}",
                match own { Family::V4 => "IPv4", Family::V6 => "IPv6" },
                match own { Family::V4 => "/v6", Family::V6 => "/v4" },
            );
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
        build_forwards("node4", &parse_forward_specs(&[spec.into()])?, ips, options)
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
            (ForwardMode::Transparent, Family::V6)
        );

        let all = build("53/both/all", &ips(), Default::default()).unwrap();
        assert_eq!(all.len(), 4, "TCP and UDP on each address");
        // Translation to an IPv4-only service is explicit.
        let translate = ForwardOptions {
            mode: Some(ForwardMode::Translate),
            ..Default::default()
        };
        let v6 = build("80/tcp/v6", &ips(), translate).unwrap();
        assert_eq!(
            (v6[0].mode, v6[0].target_family),
            (ForwardMode::Translate, Family::V4)
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
            build("80/tcp", &ips(), explicit.clone()).unwrap()[0].listen_ip,
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
            build("80/tcp", &ips(), form.clone()).unwrap()[0].listen_ip,
            ips()[1]
        );
        assert_eq!(
            build("80/tcp/v4", &ips(), form).unwrap()[0].listen_ip,
            ips()[0]
        );
    }

    #[test]
    fn allowed_sources_split_by_family_and_are_checked() {
        let nets = parse_allow_from(&["203.0.113.7, 198.51.100.9/24", "2001:db8::/48 203.0.113.7"])
            .unwrap();
        assert_eq!(
            nets,
            vec![
                "203.0.113.7/32".parse::<IpNet>().unwrap(),
                "198.51.100.0/24".parse().unwrap(),
                "2001:db8::/48".parse().unwrap(),
            ],
            "host bits cleared, duplicates dropped, order kept"
        );
        assert!(parse_allow_from(&["example.net"]).is_err());
        assert!(parse_allow_from(&["10.0.0.0/33"]).is_err());
        let many: Vec<String> = (0..=MAX_ALLOW_FROM)
            .map(|i| format!("10.0.{i}.0/24"))
            .collect();
        assert!(parse_allow_from(&many).is_err());

        let options = ForwardOptions {
            allow_from: nets.clone(),
            ..Default::default()
        };
        let all = build("22/tcp/all", &ips(), options.clone()).unwrap();
        assert_eq!(all[0].allow_from, nets[..2]);
        assert_eq!(all[1].allow_from, nets[2..]);
        // A listener whose family the list does not name would be open to no one.
        let only_v4 = ForwardOptions {
            allow_from: nets[..2].to_vec(),
            ..Default::default()
        };
        let error = build("22/tcp/all", &ips(), only_v4.clone()).unwrap_err();
        assert!(error.to_string().contains("no IPv6 source"), "{error}");
        // A local forward is reached through the proxy, whose address is the source.
        let local = ForwardOptions {
            ingress: Ingress::Local,
            ..only_v4
        };
        assert!(build("22/tcp", &ips(), local).is_err());
        let mut forward = build("22/tcp", &ips(), Default::default())
            .unwrap()
            .remove(0);
        forward.allow_from = vec!["2001:db8::/48".parse().unwrap()];
        assert!(
            forward.validate().is_err(),
            "family must match the listener"
        );
    }
}
