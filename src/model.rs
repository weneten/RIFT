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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Forward {
    pub id: u64,
    pub agent_id: String,
    pub listen_ip: IpAddr,
    pub listen_ports: PortRange,
    pub target_ports: PortRange,
    pub protocol: Protocol,
    pub mode: ForwardMode,
    /// `local` DNATs only packets that did not arrive on a public-address NIC.
    /// Missing on older state means `public`.
    #[serde(default)]
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
    #[serde(default)]
    pub vpn_peers: Vec<VpnPeer>,
    #[serde(default)]
    pub vpn_grants: Vec<VpnGrant>,
}
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AgentPolicy {
    pub generation: u64,
    pub forwards: Vec<Forward>,
    /// Missing on policies from older servers, which means no VPN access.
    #[serde(default)]
    pub vpn_pool: Option<Ipv4Net>,
    #[serde(default)]
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
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
