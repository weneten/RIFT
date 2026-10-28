use crate::{
    config::Config,
    model::{
        AgentPolicy, AgentStatus, Family, Forward, ForwardMode, Ingress, PeerStats, PortRange,
        Protocol, StateSnapshot, Welcome,
    },
};
use anyhow::{bail, ensure, Context, Result};
use ipnet::IpNet;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    sync::OnceLock,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{io::AsyncWriteExt, process::Command, sync::Mutex};

const ROUTE_PROTOCOL: &str = "242"; // RIFT-owned custom route protocol; 186 is RTPROT_BGP.
const OWNER_VERSION: &str = "rift-net-v1";
static APPLY_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// The Linux dataplane adapter. Every command is executed directly (never through a shell).
pub struct Kernel {
    config: Config,
    endpoint_refresh: Mutex<Option<(Instant, SocketAddr)>>,
}

impl Kernel {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            endpoint_refresh: Mutex::new(None),
        }
    }

    pub async fn apply_server(
        &self,
        snapshot: &StateSnapshot,
        private_key_path: &Path,
    ) -> Result<()> {
        let _apply = APPLY_LOCK.get_or_init(|| Mutex::new(())).lock().await;
        self.config.validate()?;
        self.preflight_forwarding().await?;
        self.check_tunnel_overlap(&[
            self.config.server_ipv4.into(),
            self.config.server_ipv6.into(),
        ])
        .await?;
        let active: BTreeMap<String, _> = snapshot
            .agents
            .iter()
            .filter(|a| a.status == AgentStatus::Active)
            .map(|a| (a.id.clone(), a))
            .collect();
        let peers: BTreeMap<String, _> = snapshot
            .agents
            .iter()
            .filter(|a| a.status != AgentStatus::Disabled)
            .map(|a| (a.id.clone(), a))
            .collect();
        let forwards: Vec<&Forward> = snapshot
            .forwards
            .iter()
            .filter(|f| {
                f.enabled
                    && f.mode == ForwardMode::Transparent
                    && active
                        .get(&f.agent_id)
                        .is_some_and(|agent| f.generation <= agent.applied_generation)
            })
            .collect();
        for f in &forwards {
            f.validate()?;
            ensure!(
                self.config.public_ips.contains(&f.listen_ip),
                "forward {} listen IP {} is not in public_ips",
                f.id,
                f.listen_ip
            );
            ensure!(is_public_unicast(f.listen_ip), "forward {} cannot publish a private, local, link-local, shared, ULA, or multicast address", f.id);
            let agent = active
                .get(&f.agent_id)
                .context("forward references inactive or unknown agent")?;
            ensure!(
                Family::of(f.target_ip(agent)) == Family::of(f.listen_ip),
                "transparent forward {} crosses address families",
                f.id
            );
        }
        let mut peer_keys = BTreeSet::new();
        let mut peer_ips = BTreeSet::new();
        for agent in peers.values() {
            ensure!(
                peer_keys.insert(agent.public_key.clone()),
                "duplicate WireGuard public key in active/pending agents"
            );
            ensure!(
                peer_ips.insert(IpAddr::V4(agent.tunnel_ipv4)),
                "duplicate agent IPv4 tunnel address"
            );
            ensure!(
                peer_ips.insert(IpAddr::V6(agent.tunnel_ipv6)),
                "duplicate agent IPv6 tunnel address"
            );
        }
        let private_key = read_private_key(private_key_path).await?;
        let public_key = wg_public_key(&private_key).await?;
        self.ensure_interface(&public_key, private_key_path).await?;
        self.set_listen_port_if_needed().await?;
        self.configure_interface_addresses(
            Some(self.config.server_ipv4.into()),
            Some(self.config.server_ipv6.into()),
        )
        .await?;
        self.set_rp_filter().await?;
        self.ensure_routing_ownership().await?;

        let existing = self.wg_dump().await?;
        for agent in peers.values() {
            let allowed = format!("{}/32,{}/128", agent.tunnel_ipv4, agent.tunnel_ipv6);
            let keepalive = self.config.keepalive.to_string();
            run_ok(
                "wg",
                [
                    "set",
                    self.interface(),
                    "peer",
                    &agent.public_key,
                    "allowed-ips",
                    &allowed,
                    "persistent-keepalive",
                    &keepalive,
                ],
            )
            .await
            .with_context(|| format!("configure WireGuard peer {}", agent.id))?;
            self.add_peer_routes(agent.tunnel_ipv4.into(), agent.tunnel_ipv6.into())
                .await?;
        }
        for peer in existing {
            if !peer_keys.contains(&peer.public_key) {
                run_ok(
                    "wg",
                    ["set", self.interface(), "peer", &peer.public_key, "remove"],
                )
                .await
                .with_context(|| format!("remove inactive peer {}", peer.public_key))?;
            }
            for ip in peer.allowed_ips {
                if self.is_managed_agent_ip(ip) && !peer_ips.contains(&ip) {
                    self.delete_peer_route(ip).await?;
                }
            }
        }

        self.ensure_nft_ownership().await?;
        let local_ingress = forwards
            .iter()
            .any(|forward| forward.ingress == Ingress::Local);
        let uplinks = if local_ingress {
            let found = crate::host_firewall::uplinks(
                &self.address_json().await?,
                &self.config.public_ips,
            )?;
            ensure!(
                !found.is_empty(),
                "local ingress needs a NIC that owns a configured public IP"
            );
            found
        } else {
            Vec::new()
        };
        let rules = render_server_rules(
            self.interface(),
            self.config.mark,
            self.config.mark_mask,
            self.config.control_port,
            self.config.server_ipv4,
            self.config.server_ipv6,
            &forwards,
            &peers,
            &uplinks,
        )?;
        self.replace_nft_table(&rules).await?;
        self.sync_server_host_firewall(local_ingress).await?;
        Ok(())
    }

    pub async fn apply_agent(
        &self,
        welcome: &Welcome,
        policy: &AgentPolicy,
        private_key_path: &Path,
    ) -> Result<()> {
        let _apply = APPLY_LOCK.get_or_init(|| Mutex::new(())).lock().await;
        self.config.validate()?;
        self.preflight_forwarding().await?;
        self.check_tunnel_overlap(&[
            welcome.tunnel_ipv4.into(),
            welcome.tunnel_ipv6.into(),
            welcome.server_ipv4.into(),
            welcome.server_ipv6.into(),
        ])
        .await?;
        ensure!(welcome.keepalive > 0, "server keepalive must be nonzero");
        for f in policy.forwards.iter().filter(|f| f.enabled) {
            f.validate()?;
            ensure!(
                f.generation <= policy.generation,
                "forward {} is newer than the received policy",
                f.id
            );
        }
        let forwards: Vec<&Forward> = policy.forwards.iter().filter(|f| f.enabled).collect();
        let private_key = read_private_key(private_key_path).await?;
        let public_key = wg_public_key(&private_key).await?;
        self.ensure_interface(&public_key, private_key_path).await?;
        self.configure_interface_addresses(
            Some(welcome.tunnel_ipv4.into()),
            Some(welcome.tunnel_ipv6.into()),
        )
        .await?;
        self.set_rp_filter().await?;
        self.ensure_routing_ownership().await?;
        self.install_agent_routes(welcome).await?;

        let peers = self.wg_dump().await?;
        let peer = peers
            .iter()
            .find(|p| p.public_key == welcome.server_public_key);
        let candidates = match resolve_endpoints(&welcome.server_endpoint).await {
            Ok(addresses) => addresses,
            Err(error) => {
                let cached = peer
                    .and_then(|p| p.endpoint.as_deref())
                    .and_then(|s| s.parse::<SocketAddr>().ok());
                if let Some(cached) = cached {
                    tracing::warn!(
                        "endpoint DNS unavailable; keeping the learned endpoint: {error}"
                    );
                    vec![cached]
                } else {
                    return Err(error);
                }
            }
        };
        let endpoint = choose_endpoint(&candidates, peer, self.config.handshake_timeout);
        let allowed = "0.0.0.0/0,::/0";
        let keepalive = welcome.keepalive.to_string();
        run_ok(
            "wg",
            [
                "set",
                self.interface(),
                "peer",
                &welcome.server_public_key,
                "allowed-ips",
                allowed,
                "persistent-keepalive",
                &keepalive,
            ],
        )
        .await
        .context("configure VPS WireGuard peer")?;
        self.maybe_refresh_endpoint(welcome, endpoint, peer).await?;

        self.ensure_nft_ownership().await?;
        let rules = render_agent_rules(
            self.interface(),
            self.config.mark,
            self.config.mark_mask,
            welcome,
            &forwards,
        )?;
        self.replace_nft_table(&rules).await?;
        self.sync_agent_host_firewall(welcome, &forwards).await?;
        Ok(())
    }

    pub async fn stats(&self) -> Result<Vec<PeerStats>> {
        let mut stats = Vec::new();
        for peer in self.wg_dump().await? {
            stats.push(PeerStats {
                public_key: peer.public_key,
                endpoint: peer.endpoint,
                last_handshake: peer.latest_handshake,
                rx_bytes: peer.rx_bytes,
                tx_bytes: peer.tx_bytes,
            });
        }
        Ok(stats)
    }

    pub async fn doctor(&self) -> Result<Value> {
        let commands = BTreeMap::from([
            ("ip", command_version("ip", ["-Version"]).await),
            ("wg", command_version("wg", ["--version"]).await),
            ("nft", command_version("nft", ["--version"]).await),
        ]);
        let sysctls = BTreeMap::from([
            (
                "ipv4_forward",
                inspect_sysctl("/proc/sys/net/ipv4/ip_forward").await,
            ),
            (
                "ipv6_forward",
                inspect_sysctl("/proc/sys/net/ipv6/conf/all/forwarding").await,
            ),
            (
                "rp_filter_all",
                inspect_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter").await,
            ),
            (
                "src_valid_mark_all",
                inspect_sysctl("/proc/sys/net/ipv4/conf/all/src_valid_mark").await,
            ),
        ]);
        let link = run_output("ip", ["link", "show", "dev", self.interface()]).await;
        let nft_owned = self.is_nft_owned().await;
        let interface_owned = self.is_interface_owned().await;
        let host = self.host_firewall_doctor().await;
        let mut warnings = vec![
            "Global forwarding sysctls are inspected but never changed by RIFT.".to_string(),
            "IPv6 wildcard UDP services should bind the WireGuard address or use IPV6_PKTINFO for replies."
                .to_string(),
        ];
        warnings.extend(host.warnings);
        Ok(json!({
            "interface": self.interface(),
            "interface_present": link.as_ref().is_ok_and(|s| !s.is_empty()),
            "interface_owned": interface_owned,
            "nft_table_owned": nft_owned,
            "commands": commands,
            "sysctls": sysctls,
            "route_table": self.config.route_table,
            "rule_priority": self.config.rule_priority,
            "mark": format!("{:#x}/{:#x}", self.config.mark, self.config.mark_mask),
            "public_ips": self.config.public_ips,
            "host_firewall": host.status,
            "warnings": warnings
        }))
    }

    pub async fn check_port(&self, ip: IpAddr, ports: PortRange, protocol: Protocol) -> Result<()> {
        ensure!(
            is_public_unicast(ip),
            "published listener must be a public unicast VPS address"
        );
        ports.validate()?;
        ensure!(ports.len() <= 4096, "port range is too large to preflight");
        check_foreign_nft_nat_conflict(ip, ports, protocol).await?;
        let domain = if ip.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let ty = match protocol {
            Protocol::Tcp => socket2::Type::STREAM,
            Protocol::Udp => socket2::Type::DGRAM,
        };
        let proto = match protocol {
            Protocol::Tcp => Some(socket2::Protocol::TCP),
            Protocol::Udp => Some(socket2::Protocol::UDP),
        };
        for port in ports.start..=ports.end {
            let socket = socket2::Socket::new(domain, ty, proto)
                .with_context(|| format!("create socket for {ip}:{port}/{protocol}"))?;
            if ip.is_ipv6() {
                socket.set_only_v6(true)?;
            }
            let addr = socket2::SockAddr::from(SocketAddr::new(ip, port));
            socket
                .bind(&addr)
                .with_context(|| format!("{ip}:{port}/{protocol} is unavailable"))?;
        }
        Ok(())
    }

    pub async fn cleanup(&self) -> Result<()> {
        let _apply = APPLY_LOCK.get_or_init(|| Mutex::new(())).lock().await;
        self.remove_host_firewall().await?;
        if self.is_nft_owned().await {
            if nft_table_exists().await? {
                run_ok("nft", ["delete", "table", "inet", "rift"])
                    .await
                    .context("remove owned nft table")?;
            }
            remove_owner_file(&self.owner_path("nft")).await?;
        }
        if self.is_route_owned().await {
            self.delete_all_agent_rules().await?;
            self.delete_agent_routes().await?;
            remove_owner_file(&self.owner_path("routes")).await?;
        }
        if self.is_interface_owned().await {
            run_ok("ip", ["link", "delete", "dev", self.interface()])
                .await
                .context("delete owned WireGuard interface")?;
            remove_owner_file(&self.owner_path("interface")).await?;
        }
        Ok(())
    }

    async fn maybe_refresh_endpoint(
        &self,
        welcome: &Welcome,
        desired: SocketAddr,
        peer: Option<&WgPeer>,
    ) -> Result<()> {
        let current = peer
            .and_then(|p| p.endpoint.as_deref())
            .and_then(|s| s.parse::<SocketAddr>().ok());
        let Some(peer) = peer else {
            set_endpoint(self.interface(), &welcome.server_public_key, desired).await?;
            *self.endpoint_refresh.lock().await = Some((Instant::now(), desired));
            return Ok(());
        };
        if current == Some(desired) {
            return Ok(());
        }
        let now = unix_now();
        let stale = peer.latest_handshake == 0
            || now.saturating_sub(peer.latest_handshake as u64) >= self.config.handshake_timeout;
        let cooldown_ok = self
            .endpoint_refresh
            .lock()
            .await
            .as_ref()
            .is_none_or(|(last, _)| {
                last.elapsed() >= Duration::from_secs(self.config.poll_seconds)
            });
        if stale && cooldown_ok {
            set_endpoint(self.interface(), &welcome.server_public_key, desired).await?;
            *self.endpoint_refresh.lock().await = Some((Instant::now(), desired));
        }
        Ok(())
    }

    async fn sync_server_host_firewall(&self, local_ingress: bool) -> Result<()> {
        if self.config.host_firewall == crate::config::HostFirewall::Off {
            return self.remove_host_firewall().await;
        }
        let obs = crate::host_firewall::observe(&self.nft_ruleset().await?)?;
        if obs.input.is_empty() && obs.forward.is_empty() {
            return Ok(());
        }
        let uplinks =
            crate::host_firewall::uplinks(&self.address_json().await?, &self.config.public_ips)?;
        if !self.config.public_ips.is_empty() && uplinks.is_empty() && !obs.forward.is_empty() {
            bail!(
                "configured public IPs are not assigned on this host; not opening UFW forwarding"
            );
        }
        let plan = crate::host_firewall::plan_server(
            &obs,
            &crate::host_firewall::ServerSpec {
                interface: self.interface(),
                server_v4: self.config.server_ipv4,
                server_v6: self.config.server_ipv6,
                control_port: self.config.control_port,
                wg_port: self.config.wg_port,
                enrollment: self
                    .config
                    .enrollment_enabled
                    .then_some(self.config.enrollment_bind),
                uplinks: &uplinks,
                local_ingress,
            },
        )?;
        self.apply_host_plan(&plan).await
    }

    async fn sync_agent_host_firewall(
        &self,
        welcome: &Welcome,
        forwards: &[&Forward],
    ) -> Result<()> {
        if self.config.host_firewall == crate::config::HostFirewall::Off {
            return self.remove_host_firewall().await;
        }
        let obs = crate::host_firewall::observe(&self.nft_ruleset().await?)?;
        if obs.input.is_empty() && obs.forward.is_empty() {
            return Ok(());
        }
        let plan = crate::host_firewall::plan_agent(
            &obs,
            &crate::host_firewall::AgentSpec {
                interface: self.interface(),
                tunnel_v4: welcome.tunnel_ipv4,
                tunnel_v6: welcome.tunnel_ipv6,
                forwards,
            },
        )?;
        self.apply_host_plan(&plan).await
    }

    async fn apply_host_plan(&self, plan: &crate::host_firewall::Plan) -> Result<()> {
        for script in [&plan.create, &plan.fill, &plan.jumps] {
            if !script.trim().is_empty() {
                nft_batch(script).await?;
            }
        }
        if !plan.summary.is_empty()
            && (!plan.fill.trim().is_empty() || !plan.jumps.trim().is_empty())
        {
            tracing::info!("{}", plan.summary);
        }
        Ok(())
    }

    async fn remove_host_firewall(&self) -> Result<()> {
        let obs = crate::host_firewall::observe(&self.nft_ruleset().await?)?;
        let script = crate::host_firewall::plan_remove(&obs);
        if script.trim().is_empty() {
            return Ok(());
        }
        nft_batch(&script)
            .await
            .context("remove RIFT host-firewall jumps")
    }

    async fn host_firewall_doctor(&self) -> crate::host_firewall::DoctorReport {
        let mode = match self.config.host_firewall {
            crate::config::HostFirewall::Auto => "auto",
            crate::config::HostFirewall::Off => "off",
        };
        let ruleset = match self.nft_ruleset().await {
            Ok(ruleset) => ruleset,
            Err(error) => {
                return crate::host_firewall::DoctorReport {
                    status: json!({ "mode": mode, "error": error.to_string() }),
                    warnings: vec![format!("host firewall inspection failed: {error}")],
                };
            }
        };
        let obs = match crate::host_firewall::observe(&ruleset) {
            Ok(obs) => obs,
            Err(error) => {
                return crate::host_firewall::DoctorReport {
                    status: json!({ "mode": mode, "error": error.to_string() }),
                    warnings: vec![format!("host firewall inspection failed: {error}")],
                };
            }
        };
        let uplinks = match self.address_json().await {
            Ok(addresses) => crate::host_firewall::uplinks(&addresses, &self.config.public_ips)
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        crate::host_firewall::report(mode, &obs, &uplinks, !self.config.public_ips.is_empty())
    }

    async fn nft_ruleset(&self) -> Result<Value> {
        let text = run_output("nft", ["-j", "list", "ruleset"]).await?;
        serde_json::from_str(&text).context("parse nftables JSON ruleset")
    }

    async fn address_json(&self) -> Result<Value> {
        let text = run_output("ip", ["-j", "address", "show"]).await?;
        serde_json::from_str(&text).context("parse ip address JSON")
    }

    async fn preflight_forwarding(&self) -> Result<()> {
        for path in [
            "/proc/sys/net/ipv4/ip_forward",
            "/proc/sys/net/ipv6/conf/all/forwarding",
        ] {
            let value = read_sysctl(path)
                .await
                .with_context(|| format!("read required forwarding sysctl {path}"))?;
            ensure!(
                value.trim() == "1",
                "{path} must be 1. On the host run `sudo sh deploy/prepare-host`; RIFT does not change global forwarding sysctls"
            );
        }
        Ok(())
    }

    async fn check_tunnel_overlap(&self, addresses: &[IpAddr]) -> Result<()> {
        let links: Value =
            serde_json::from_str(&run_output("ip", ["-j", "address", "show"]).await?)?;
        for link in links.as_array().context("invalid ip address JSON")? {
            if link["ifname"].as_str() == Some(self.interface()) {
                continue;
            }
            if let Some(entries) = link["addr_info"].as_array() {
                for entry in entries {
                    if let (Some(local), Some(prefix)) =
                        (entry["local"].as_str(), entry["prefixlen"].as_u64())
                    {
                        let network = IpNet::new(local.parse()?, prefix as u8)?;
                        ensure!(!addresses.iter().any(|ip|network.contains(ip)),"WireGuard addresses overlap existing host interface {}; choose different tunnel pools on the VPS",link["ifname"]);
                    }
                }
            }
        }
        for family in ["-4", "-6"] {
            let routes: Value = serde_json::from_str(
                &run_output("ip", ["-N", family, "-j", "route", "show", "table", "main"]).await?,
            )?;
            for route in routes.as_array().context("invalid ip route JSON")? {
                if route["dev"].as_str() == Some(self.interface()) {
                    continue;
                }
                let Some(destination) = route["dst"].as_str().filter(|s| *s != "default") else {
                    continue;
                };
                let network = destination.parse::<IpNet>().or_else(|_| {
                    destination
                        .parse::<IpAddr>()
                        .map(|ip| IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 }).unwrap())
                });
                if let Ok(network) = network {
                    ensure!(!addresses.iter().any(|ip|network.contains(ip)),"WireGuard addresses overlap existing route {destination}; choose different VPS tunnel pools");
                }
            }
        }
        Ok(())
    }
    async fn set_rp_filter(&self) -> Result<()> {
        let path = format!("/proc/sys/net/ipv4/conf/{}/rp_filter", self.interface());
        let all_path = "/proc/sys/net/ipv4/conf/all/rp_filter";
        let all: u8 = read_sysctl(all_path)
            .await?
            .parse()
            .context("parse global rp_filter")?;
        let current: u8 = read_sysctl(&path)
            .await?
            .parse()
            .context("parse interface rp_filter")?;
        if all.max(current) == 1 {
            tokio::fs::write(&path, b"2\n").await.with_context(|| format!(
                "strict rp_filter is active and per-interface setting {path} is not writable; on the host run `sudo sh deploy/prepare-host`"
            ))?;
            let actual: u8 = read_sysctl(&path)
                .await?
                .parse()
                .context("parse updated interface rp_filter")?;
            ensure!(all.max(actual) == 2, "strict rp_filter remains effective on {}; on the host run `sudo sh deploy/prepare-host`", self.interface());
        }
        Ok(())
    }

    async fn ensure_interface(&self, expected_public: &str, private_key_path: &Path) -> Result<()> {
        let marker_path = self.owner_path("interface");
        let mut exists = interface_exists(self.interface()).await?;
        let mut owner = read_owner_file(&marker_path).await?;
        let mut live_public = None;
        if exists && owner.is_none() {
            let alias = match interface_alias(self.interface()).await {
                Ok(alias) => alias,
                Err(error)
                    if error
                        .to_string()
                        .contains("did not return the interface alias") =>
                {
                    String::new()
                }
                Err(error) => return Err(error),
            };
            if rift_interface_alias(&alias) {
                tracing::warn!(
                    interface = self.interface(),
                    alias,
                    "replacing orphaned RIFT WireGuard interface; its ownership marker is gone"
                );
                run_ok("ip", ["link", "delete", "dev", self.interface()])
                    .await
                    .context("delete orphaned RIFT WireGuard interface")?;
                exists = false;
            }
        }
        if exists {
            let saved = owner.as_deref().context("WireGuard interface already exists but has no persistent RIFT ownership marker; refusing to take it over")?;
            ensure!(
                saved.starts_with(&format!("{OWNER_VERSION}\ninterface\n")),
                "interface ownership marker is invalid"
            );
            let live = run_output("wg", ["show", self.interface(), "public-key"])
                .await
                .context("existing interface is not a WireGuard interface")?;
            let token = saved
                .lines()
                .nth(3)
                .context("interface ownership marker has no alias token")?;
            ensure!(
                interface_alias(self.interface()).await? == token,
                "existing interface alias does not match its persistent RIFT ownership token"
            );
            live_public = Some(live.trim().to_string());
        } else {
            if owner.is_none() {
                let token = format!("rift:{}", uuid::Uuid::new_v4());
                owner = Some(format!("{OWNER_VERSION}\ninterface\npending\n{token}\n"));
                write_owner_new(&marker_path, owner.as_deref().unwrap()).await?;
            } else {
                ensure!(
                    owner
                        .as_deref()
                        .unwrap()
                        .starts_with(&format!("{OWNER_VERSION}\ninterface\n")),
                    "interface ownership marker is invalid"
                );
            }
            if let Err(e) = run_ok(
                "ip",
                ["link", "add", "dev", self.interface(), "type", "wireguard"],
            )
            .await
            {
                if !interface_exists(self.interface()).await.unwrap_or(true) {
                    remove_owner_file(&marker_path).await.ok();
                }
                return Err(e).context("create WireGuard interface");
            }
            let token = owner
                .as_deref()
                .and_then(|v| v.lines().nth(3))
                .context("interface ownership marker has no alias token")?;
            run_ok(
                "ip",
                ["link", "set", "dev", self.interface(), "alias", token],
            )
            .await
            .context("tag RIFT-owned WireGuard interface")?;
        }
        if live_public.as_deref() != Some(expected_public) {
            run_ok(
                "wg",
                [
                    "set",
                    self.interface(),
                    "private-key",
                    private_key_path.to_string_lossy().as_ref(),
                ],
            )
            .await
            .context("set WireGuard private key")?;
        }
        let live_public = run_output("wg", ["show", self.interface(), "public-key"]).await?;
        ensure!(
            live_public.trim() == expected_public,
            "WireGuard returned an unexpected interface public key"
        );
        let token = owner
            .as_deref()
            .and_then(|v| v.lines().nth(3))
            .context("interface ownership marker has no alias token")?;
        let expected_marker = format!("{OWNER_VERSION}\ninterface\n{}\n{token}\n", expected_public);
        if owner.as_deref() != Some(expected_marker.as_str()) {
            write_owner_replace(&marker_path, &expected_marker).await?;
        }
        run_ok(
            "ip",
            [
                "link",
                "set",
                "dev",
                self.interface(),
                "mtu",
                &self.config.mtu.to_string(),
            ],
        )
        .await
        .context("set WireGuard MTU")?;
        run_ok("ip", ["link", "set", "dev", self.interface(), "up"])
            .await
            .context("bring WireGuard interface up")?;
        Ok(())
    }

    async fn set_listen_port_if_needed(&self) -> Result<()> {
        let current = run_output("wg", ["show", self.interface(), "listen-port"]).await?;
        let wanted = self.config.wg_port.to_string();
        if current.trim() != wanted {
            run_ok("wg", ["set", self.interface(), "listen-port", &wanted])
                .await
                .context("set WireGuard listen port")?;
        }
        Ok(())
    }

    async fn configure_interface_addresses(
        &self,
        v4: Option<IpAddr>,
        v6: Option<IpAddr>,
    ) -> Result<()> {
        if let Some(ip) = v4 {
            run_ok(
                "ip",
                [
                    "-4",
                    "address",
                    "replace",
                    &format!("{ip}/32"),
                    "dev",
                    self.interface(),
                ],
            )
            .await?;
        }
        if let Some(ip) = v6 {
            run_ok(
                "ip",
                [
                    "-6",
                    "address",
                    "replace",
                    &format!("{ip}/128"),
                    "dev",
                    self.interface(),
                ],
            )
            .await?;
        }
        Ok(())
    }

    async fn ensure_routing_ownership(&self) -> Result<()> {
        let path = self.owner_path("routes");
        let expected = format!(
            "{OWNER_VERSION}\nroutes\n{}\n{}\n{}\n{:#x}/{:#x}\n",
            self.interface(),
            self.config.route_table,
            self.config.rule_priority,
            self.config.mark,
            self.config.mark_mask
        );
        if let Some(saved) = read_owner_file(&path).await? {
            ensure!(saved == expected, "RIFT routing settings differ from existing ownership marker; refusing to reuse the table");
            return Ok(());
        }
        let v4 = read_route_table("-4", self.config.route_table).await?;
        let v6 = read_route_table("-6", self.config.route_table).await?;
        let rules_v4 = run_output("ip", ["-4", "rule", "show"]).await?;
        let rules_v6 = run_output("ip", ["-6", "rule", "show"]).await?;
        match routing_claim(
            &[&v4, &v6],
            &[&rules_v4, &rules_v6],
            &RoutingReservation {
                interface: self.interface(),
                table: self.config.route_table,
                priority: self.config.rule_priority,
                mark: self.config.mark,
                mask: self.config.mark_mask,
                v4_pool: self.config.ipv4_pool,
                v6_pool: self.config.ipv6_pool,
            },
        ) {
            RoutingClaim::Foreign => bail!(
                "routing table {} is already populated; refusing to claim it",
                self.config.route_table
            ),
            RoutingClaim::Orphan => {
                tracing::warn!(
                    table = self.config.route_table,
                    "replacing orphaned RIFT routes and policy rules; their ownership marker is gone"
                );
                self.delete_all_agent_rules().await?;
                self.delete_agent_routes().await?;
            }
            RoutingClaim::Empty => {}
        }
        self.ensure_rule_slots_available().await?;
        write_owner_new(&path, &expected).await?;
        Ok(())
    }

    async fn ensure_rule_slots_available(&self) -> Result<()> {
        let pref = self.config.rule_priority.to_string();
        let mark_pref = (self.config.rule_priority + 1).to_string();
        for fam in ["-4", "-6"] {
            let rules = run_output("ip", [fam, "rule", "show"]).await?;
            for line in rules.lines() {
                let p = line.split(':').next().unwrap_or("").trim();
                if p == pref || p == mark_pref {
                    bail!("ip {fam} rule priority {p} is already occupied: {line}");
                }
                if let Some((value, mask)) = parse_rule_fwmark(line) {
                    let common = mask & self.config.mark_mask;
                    if p.parse::<u32>()
                        .is_ok_and(|priority| priority < self.config.rule_priority + 1)
                        && (value & common) == (self.config.mark & common)
                    {
                        bail!(
                            "ip {fam} rule mark overlaps RIFT mark at an earlier priority: {line}"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    async fn install_agent_routes(&self, welcome: &Welcome) -> Result<()> {
        let table = self.config.route_table.to_string();
        let iface = self.interface();
        for fam in ["-4", "-6"] {
            let current = read_route_table(fam, self.config.route_table).await?;
            for line in current.lines() {
                ensure!(
                    is_agent_default_route(line, iface),
                    "RIFT routing table {} contains an unexpected route: {line}",
                    self.config.route_table
                );
            }
            run_ok(
                "ip",
                [
                    fam,
                    "route",
                    "replace",
                    "unreachable",
                    "default",
                    "metric",
                    "42760",
                    "table",
                    &table,
                ],
            )
            .await?;
            run_ok(
                "ip",
                [
                    fam, "route", "replace", "default", "dev", iface, "metric", "10", "table",
                    &table,
                ],
            )
            .await?;
        }
        // The agent uses /32 and /128 interface addresses, so add explicit host routes
        // for the control sockets bound to the VPS tunnel addresses. These also pin the
        // control connection source to this agent's WireGuard address.
        run_ok(
            "ip",
            [
                "-4",
                "route",
                "replace",
                &format!("{}/32", welcome.server_ipv4),
                "dev",
                iface,
                "src",
                &welcome.tunnel_ipv4.to_string(),
                "proto",
                ROUTE_PROTOCOL,
                "table",
                "main",
            ],
        )
        .await?;
        run_ok(
            "ip",
            [
                "-6",
                "route",
                "replace",
                &format!("{}/128", welcome.server_ipv6),
                "dev",
                iface,
                "src",
                &welcome.tunnel_ipv6.to_string(),
                "proto",
                ROUTE_PROTOCOL,
                "table",
                "main",
            ],
        )
        .await?;
        let source_pref = self.config.rule_priority.to_string();
        let mark_pref = (self.config.rule_priority + 1).to_string();
        let source_v4 = format!("{}/32", welcome.tunnel_ipv4);
        let source_v6 = format!("{}/128", welcome.tunnel_ipv6);
        ensure_rule("-4", &source_pref, &["from", source_v4.as_str()], &table).await?;
        ensure_rule("-6", &source_pref, &["from", source_v6.as_str()], &table).await?;
        let fwmark = format!("{:#x}/{:#x}", self.config.mark, self.config.mark_mask);
        ensure_rule("-4", &mark_pref, &["fwmark", &fwmark], &table).await?;
        ensure_rule("-6", &mark_pref, &["fwmark", &fwmark], &table).await?;
        Ok(())
    }

    async fn add_peer_routes(&self, v4: IpAddr, v6: IpAddr) -> Result<()> {
        for (family, ip, prefix) in [("-4", v4, 32), ("-6", v6, 128)] {
            let destination = format!("{ip}/{prefix}");
            let existing = run_output(
                "ip",
                [
                    "-N",
                    family,
                    "route",
                    "show",
                    "exact",
                    &destination,
                    "table",
                    "main",
                ],
            )
            .await?;
            if !existing.trim().is_empty() {
                ensure!(existing.lines().all(|l| l.contains(self.interface()) && l.contains(ROUTE_PROTOCOL)), "route {destination} already exists outside the RIFT route protocol; refusing to replace it");
            }
            run_ok(
                "ip",
                [
                    family,
                    "route",
                    "replace",
                    &destination,
                    "dev",
                    self.interface(),
                    "proto",
                    ROUTE_PROTOCOL,
                    "table",
                    "main",
                ],
            )
            .await?;
        }
        Ok(())
    }

    async fn delete_peer_route(&self, ip: IpAddr) -> Result<()> {
        let (family, prefix) = if ip.is_ipv4() {
            ("-4", 32)
        } else {
            ("-6", 128)
        };
        run_ok_allow_missing(
            "ip",
            [
                family,
                "route",
                "del",
                &format!("{ip}/{prefix}"),
                "dev",
                self.interface(),
                "proto",
                ROUTE_PROTOCOL,
                "table",
                "main",
            ],
        )
        .await
    }

    fn is_managed_agent_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self.config.ipv4_pool.contains(&ip),
            IpAddr::V6(ip) => self.config.ipv6_pool.contains(&ip),
        }
    }

    async fn wg_dump(&self) -> Result<Vec<WgPeer>> {
        let output = run_output("wg", ["show", self.interface(), "dump"]).await?;
        parse_wg_dump(&output)
    }

    async fn ensure_nft_ownership(&self) -> Result<()> {
        let path = self.owner_path("nft");
        let expected = format!("{OWNER_VERSION}\nnft\ninet rift\n");
        let table_exists = nft_table_exists().await?;
        match read_owner_file(&path).await? {
            Some(saved) => ensure!(saved == expected, "nft ownership marker is invalid"),
            None => {
                if table_exists {
                    tracing::warn!(
                        "replacing orphaned nft table inet rift; its ownership marker is gone"
                    );
                }
                write_owner_new(&path, &expected).await?;
            }
        }
        Ok(())
    }

    async fn replace_nft_table(&self, rules: &str) -> Result<()> {
        let exists = nft_table_exists().await?;
        let mut batch = String::new();
        if exists {
            batch.push_str("delete table inet rift\n");
        }
        batch.push_str("add table inet rift\n");
        batch.push_str(rules);
        nft_batch(&batch)
            .await
            .context("atomically install RIFT nftables table")
    }

    async fn is_nft_owned(&self) -> bool {
        read_owner_file(&self.owner_path("nft"))
            .await
            .ok()
            .flatten()
            .is_some_and(|s| s == format!("{OWNER_VERSION}\nnft\ninet rift\n"))
    }
    async fn is_interface_owned(&self) -> bool {
        let Some(saved) = read_owner_file(&self.owner_path("interface"))
            .await
            .ok()
            .flatten()
        else {
            return false;
        };
        if !saved.starts_with(&format!("{OWNER_VERSION}\ninterface\n")) {
            return false;
        }
        let Some(token) = saved.lines().nth(3) else {
            return false;
        };
        let Ok(true) = interface_exists(self.interface()).await else {
            return false;
        };
        interface_alias(self.interface())
            .await
            .is_ok_and(|alias| alias == token)
    }
    async fn is_route_owned(&self) -> bool {
        read_owner_file(&self.owner_path("routes"))
            .await
            .ok()
            .flatten()
            .is_some_and(|s| s.starts_with(&format!("{OWNER_VERSION}\nroutes\n")))
    }

    async fn delete_all_agent_rules(&self) -> Result<()> {
        let pref = self.config.rule_priority.to_string();
        let mark_pref = (self.config.rule_priority + 1).to_string();
        for family in ["-4", "-6"] {
            // Remove only rules whose selectors and table exactly match this RIFT configuration.
            let rules = run_output("ip", [family, "rule", "show"]).await?;
            for line in rules.lines() {
                if line.starts_with(&format!("{pref}:"))
                    && line.contains(&format!("lookup {}", self.config.route_table))
                    && line.contains("from")
                {
                    if let Some(from) = line
                        .split("from ")
                        .nth(1)
                        .and_then(|s| s.split_whitespace().next())
                    {
                        let managed = selector_is_managed_tunnel(
                            from,
                            self.config.ipv4_pool,
                            self.config.ipv6_pool,
                        );
                        if managed {
                            run_ok_allow_missing(
                                "ip",
                                [
                                    family,
                                    "rule",
                                    "del",
                                    "priority",
                                    &pref,
                                    "from",
                                    from,
                                    "table",
                                    &self.config.route_table.to_string(),
                                ],
                            )
                            .await?;
                        }
                    }
                }
                if line.starts_with(&format!("{mark_pref}:"))
                    && line.contains(&format!("lookup {}", self.config.route_table))
                    && line.contains("fwmark")
                {
                    run_ok_allow_missing(
                        "ip",
                        [
                            family,
                            "rule",
                            "del",
                            "priority",
                            &mark_pref,
                            "fwmark",
                            &format!("{:#x}/{:#x}", self.config.mark, self.config.mark_mask),
                            "table",
                            &self.config.route_table.to_string(),
                        ],
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }

    async fn delete_agent_routes(&self) -> Result<()> {
        let table = self.config.route_table.to_string();
        for family in ["-4", "-6"] {
            run_ok_allow_missing(
                "ip",
                [
                    family,
                    "route",
                    "del",
                    "default",
                    "dev",
                    self.interface(),
                    "metric",
                    "10",
                    "table",
                    &table,
                ],
            )
            .await?;
            run_ok_allow_missing(
                "ip",
                [
                    family,
                    "route",
                    "del",
                    "unreachable",
                    "default",
                    "metric",
                    "42760",
                    "table",
                    &table,
                ],
            )
            .await?;
        }
        Ok(())
    }

    fn owner_path(&self, resource: &str) -> PathBuf {
        self.config
            .state_dir
            .join(format!("kernel-owner-{}-{resource}", self.interface()))
    }
    fn interface(&self) -> &str {
        &self.config.interface
    }
}

pub async fn generate_keypair() -> Result<(String, String)> {
    let private = run_output("wg", ["genkey"])
        .await
        .context("generate WireGuard private key")?;
    let public = run_stdin("wg", ["pubkey"], format!("{}\n", private.trim()).as_bytes())
        .await
        .context("derive WireGuard public key")?;
    Ok((private.trim().to_string(), public.trim().to_string()))
}

async fn read_private_key(path: &Path) -> Result<String> {
    let value = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("read WireGuard private key {}", path.display()))?;
    ensure!(
        !value.trim().is_empty(),
        "WireGuard private key file is empty"
    );
    Ok(value.trim().to_string())
}
pub(crate) async fn wg_public_key(private: &str) -> Result<String> {
    let output = run_stdin("wg", ["pubkey"], format!("{private}\n").as_bytes()).await?;
    ensure!(!output.trim().is_empty(), "wg pubkey returned an empty key");
    Ok(output.trim().to_string())
}
async fn set_endpoint(interface: &str, peer: &str, endpoint: SocketAddr) -> Result<()> {
    run_ok(
        "wg",
        [
            "set",
            interface,
            "peer",
            peer,
            "endpoint",
            &endpoint.to_string(),
        ],
    )
    .await
}
async fn resolve_endpoints(endpoint: &str) -> Result<Vec<SocketAddr>> {
    let addresses: Vec<_> = tokio::net::lookup_host(endpoint)
        .await
        .with_context(|| format!("resolve WireGuard endpoint {endpoint}"))?
        .take(32)
        .collect();
    ensure!(
        !addresses.is_empty(),
        "WireGuard endpoint {endpoint} resolved to no addresses"
    );
    Ok(addresses)
}
fn choose_endpoint(addresses: &[SocketAddr], peer: Option<&WgPeer>, timeout: u64) -> SocketAddr {
    let current = peer
        .and_then(|p| p.endpoint.as_deref())
        .and_then(|s| s.parse::<SocketAddr>().ok());
    if let Some(peer) = peer {
        if peer.latest_handshake > 0
            && unix_now().saturating_sub(peer.latest_handshake as u64) < timeout
        {
            if let Some(current) = current {
                return current;
            }
        }
    }
    if let Some(index) = current.and_then(|current| addresses.iter().position(|a| *a == current)) {
        addresses[(index + 1) % addresses.len()]
    } else {
        addresses[0]
    }
}
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug)]
struct WgPeer {
    public_key: String,
    endpoint: Option<String>,
    allowed_ips: Vec<IpAddr>,
    latest_handshake: i64,
    rx_bytes: u64,
    tx_bytes: u64,
}
fn parse_wg_dump(output: &str) -> Result<Vec<WgPeer>> {
    let mut peers = Vec::new();
    for line in output
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
    {
        let columns: Vec<&str> = line.split('\t').collect();
        ensure!(columns.len() >= 8, "unexpected wg show dump peer row");
        let endpoint = match columns[2] {
            "(none)" | "" => None,
            v => Some(v.to_string()),
        };
        let allowed_ips = columns[3]
            .split(',')
            .filter(|v| !v.is_empty() && *v != "(none)")
            .filter_map(|v| v.parse::<IpNet>().ok())
            .map(|n| n.addr())
            .collect();
        peers.push(WgPeer {
            public_key: columns[0].to_string(),
            endpoint,
            allowed_ips,
            latest_handshake: columns[4]
                .parse()
                .context("parse WireGuard handshake time")?,
            rx_bytes: columns[5]
                .parse()
                .context("parse WireGuard received bytes")?,
            tx_bytes: columns[6]
                .parse()
                .context("parse WireGuard transmitted bytes")?,
        });
    }
    Ok(peers)
}

fn ingress_clause(tunnel: &str, forward: &Forward, uplinks: &[String]) -> Result<String> {
    let mut clause = format!("iifname != \"{tunnel}\"");
    if forward.ingress != Ingress::Local {
        return Ok(clause);
    }
    ensure!(
        !uplinks.is_empty(),
        "local ingress forward {} has no public uplink to exclude",
        forward.id
    );
    for name in uplinks {
        ensure!(
            crate::host_firewall::valid_ifname(name),
            "invalid uplink interface {name}"
        );
        clause.push_str(&format!(" iifname != \"{name}\""));
    }
    Ok(clause)
}

// Keep meta l4proto before conntrack port comparisons in both renderers.
// nftables 1.0.6 needs this context to infer the transport-port datatype.
#[allow(clippy::too_many_arguments)] // Explicit kernel renderer inputs, shared by server and renderer tests.
fn render_server_rules(
    interface: &str,
    mark: u32,
    mask: u32,
    control_port: u16,
    server_v4: std::net::Ipv4Addr,
    server_v6: std::net::Ipv6Addr,
    forwards: &[&Forward],
    agents: &BTreeMap<String, &crate::model::AgentRecord>,
    uplinks: &[String],
) -> Result<String> {
    let mut out = "add chain inet rift prerouting_mark { type filter hook prerouting priority mangle; policy accept; }\n\
         add chain inet rift prerouting_nat { type nat hook prerouting priority dstnat; policy accept; }\n\
         add chain inet rift forward { type filter hook forward priority filter; policy accept; }\n\
         add chain inet rift input { type filter hook input priority filter; policy accept; }\n".to_string();
    out.push_str(&format!(
        "add rule inet rift input iifname \"{interface}\" ip daddr {server_v4} tcp dport {control_port} accept\n\
         add rule inet rift input iifname \"{interface}\" ip6 daddr {server_v6} tcp dport {control_port} accept\n\
         add rule inet rift input iifname \"{interface}\" ct state established,related accept\n\
         add rule inet rift input iifname \"{interface}\" drop\n"
    ));
    for f in forwards {
        let agent = agents
            .get(&f.agent_id)
            .context("forward references unknown active peer")?;
        for offset in 0..f.listen_ports.len() {
            let listen_port = f.listen_ports.start + offset as u16;
            let target_port = f.target_ports.start + offset as u16;
            let (addr_family, addr) = nft_addr(f.listen_ip);
            let agent_ip = f.target_ip(agent);
            let (target_family, target_ip) = nft_addr(agent_ip);
            let proto = f.protocol.to_string();
            let target = nft_nat_target(f.target_ip(agent), target_port);
            let iif = ingress_clause(interface, f, uplinks)?;
            out.push_str(&format!(
                "add rule inet rift prerouting_mark {iif} {addr_family} daddr {addr} {proto} dport {listen_port} ct direction original ct mark set (ct mark & {:#x}) | {:#x}\n",
                !mask, mark
            ));
            out.push_str(&format!(
                "add rule inet rift prerouting_nat {iif} {addr_family} daddr {addr} {proto} dport {listen_port} dnat {target_family} to {target}\n"
            ));
            // A missing MSS option must not skip the separate grant accept.
            if f.protocol == Protocol::Tcp {
                out.push_str(&format!(
                    "add rule inet rift forward {iif} oifname \"{interface}\" ct direction original ct status dnat ct mark & {mask:#x} == {mark:#x} ct original {addr_family} daddr {addr} ct original protocol tcp meta l4proto tcp ct original proto-dst {listen_port} {target_family} daddr {target_ip} tcp dport {target_port} meta l4proto tcp tcp flags & syn == syn tcp option maxseg size set rt mtu\n\
                     add rule inet rift forward iifname \"{interface}\" oifname != \"{interface}\" ct direction reply ct status dnat ct mark & {mask:#x} == {mark:#x} ct original {addr_family} daddr {addr} ct original protocol tcp meta l4proto tcp ct original proto-dst {listen_port} ct reply {target_family} saddr {target_ip} meta l4proto tcp ct reply proto-src {target_port} meta l4proto tcp tcp flags & syn == syn tcp option maxseg size set rt mtu\n"
                ));
            }
            out.push_str(&format!(
                "add rule inet rift forward {iif} oifname \"{interface}\" ct direction original ct status dnat ct mark & {mask:#x} == {mark:#x} ct original {addr_family} daddr {addr} ct original protocol {proto} meta l4proto {proto} ct original proto-dst {listen_port} {target_family} daddr {target_ip} {proto} dport {target_port} accept\n\
                 add rule inet rift forward iifname \"{interface}\" oifname != \"{interface}\" ct direction reply ct status dnat ct mark & {mask:#x} == {mark:#x} ct original {addr_family} daddr {addr} ct original protocol {proto} meta l4proto {proto} ct original proto-dst {listen_port} ct reply {target_family} saddr {target_ip} meta l4proto {proto} ct reply proto-src {target_port} accept\n"
            ));
        }
    }
    out.push_str(&format!(
        "add rule inet rift forward oifname \"{interface}\" drop\n\
         add rule inet rift forward iifname \"{interface}\" drop\n"
    ));
    Ok(out)
}

fn render_agent_rules(
    interface: &str,
    mark: u32,
    mask: u32,
    welcome: &Welcome,
    forwards: &[&Forward],
) -> Result<String> {
    let mut out = "add chain inet rift prerouting_mark { type filter hook prerouting priority mangle; policy accept; }\n\
         add chain inet rift output_route { type route hook output priority mangle; policy accept; }\n\
         add chain inet rift input { type filter hook input priority filter; policy accept; }\n\
         add chain inet rift forward { type filter hook forward priority filter; policy accept; }\n\
         add chain inet rift output_guard { type filter hook output priority filter; policy accept; }\n".to_string();
    for f in forwards {
        let dest = match f.target_family {
            Family::V4 => IpAddr::V4(welcome.tunnel_ipv4),
            Family::V6 => IpAddr::V6(welcome.tunnel_ipv6),
        };
        let (dest_family, dest_ip) = nft_addr(dest);
        for port in f.target_ports.start..=f.target_ports.end {
            let src_clause = if f.mode == ForwardMode::Translate {
                let src = match f.target_family {
                    Family::V4 => IpAddr::V4(welcome.server_ipv4),
                    Family::V6 => IpAddr::V6(welcome.server_ipv6),
                };
                let (sf, si) = nft_addr(src);
                format!("ct original {sf} saddr {si} ")
            } else {
                String::new()
            };
            if f.protocol == Protocol::Tcp {
                out.push_str(&format!(
                    "add rule inet rift forward iifname \"{interface}\" oifname != \"{interface}\" ct direction original ct mark & {mask:#x} == {mark:#x} {src_clause}ct original {dest_family} daddr {dest_ip} ct original protocol tcp meta l4proto tcp ct original proto-dst {port} meta l4proto tcp tcp flags & syn == syn tcp option maxseg size set rt mtu\n\
                     add rule inet rift forward iifname != \"{interface}\" oifname \"{interface}\" ct direction reply ct mark & {mask:#x} == {mark:#x} {src_clause}ct original {dest_family} daddr {dest_ip} ct original protocol tcp meta l4proto tcp ct original proto-dst {port} meta l4proto tcp tcp flags & syn == syn tcp option maxseg size set rt mtu\n"
                ));
            }
            out.push_str(&format!(
                "add rule inet rift prerouting_mark iifname \"{interface}\" ct direction original {src_clause}ct original {dest_family} daddr {dest_ip} ct original protocol {} meta l4proto {} ct original proto-dst {port} ct mark set (ct mark & {:#x}) | {:#x}\n\
                 add rule inet rift input iifname \"{interface}\" ct direction original ct mark & {mask:#x} == {mark:#x} {src_clause}ct original {dest_family} daddr {dest_ip} ct original protocol {} meta l4proto {} ct original proto-dst {port} accept\n\
                 add rule inet rift forward iifname \"{interface}\" oifname != \"{interface}\" ct direction original ct mark & {mask:#x} == {mark:#x} {src_clause}ct original {dest_family} daddr {dest_ip} ct original protocol {} meta l4proto {} ct original proto-dst {port} accept\n\
                 add rule inet rift forward iifname != \"{interface}\" oifname \"{interface}\" ct direction reply ct mark & {mask:#x} == {mark:#x} {src_clause}ct original {dest_family} daddr {dest_ip} ct original protocol {} meta l4proto {} ct original proto-dst {port} accept\n",
                f.protocol,
                f.protocol,
                !mask,
                mark,
                f.protocol,
                f.protocol,
                f.protocol,
                f.protocol,
                f.protocol,
                f.protocol
            ));
        }
    }
    out.push_str(&format!(
        "add rule inet rift prerouting_mark ct direction reply ct mark & {mask:#x} == {mark:#x} meta mark set (meta mark & {:#x}) | {mark:#x}\n\
         add rule inet rift output_route ct direction reply ct mark & {mask:#x} == {mark:#x} meta mark set (meta mark & {:#x}) | {mark:#x}\n\
         add rule inet rift input iifname \"{interface}\" ct direction reply ct state established ct original ip saddr {agent_v4} ct original ip daddr {server_v4} ct original protocol tcp meta l4proto tcp ct original proto-dst {control_port} accept\n\
         add rule inet rift input iifname \"{interface}\" ct direction reply ct state established ct original ip6 saddr {agent_v6} ct original ip6 daddr {server_v6} ct original protocol tcp meta l4proto tcp ct original proto-dst {control_port} accept\n\
         add rule inet rift input iifname \"{interface}\" drop\n\
         add rule inet rift forward oifname \"{interface}\" drop\n\
         add rule inet rift forward iifname \"{interface}\" drop\n\
         add rule inet rift output_guard ip saddr {agent_v4} oifname != \"{interface}\" drop\n\
         add rule inet rift output_guard ip6 saddr {agent_v6} oifname != \"{interface}\" drop\n\
         add rule inet rift output_guard ct mark & {mask:#x} == {mark:#x} oifname != \"{interface}\" drop\n",
        !mask,
        !mask,
        agent_v4 = welcome.tunnel_ipv4,
        agent_v6 = welcome.tunnel_ipv6,
        server_v4 = welcome.server_ipv4,
        server_v6 = welcome.server_ipv6,
        control_port = welcome.control_port
    ));
    Ok(out)
}

fn nft_addr(ip: IpAddr) -> (&'static str, String) {
    match ip {
        IpAddr::V4(v) => ("ip", v.to_string()),
        IpAddr::V6(v) => ("ip6", v.to_string()),
    }
}
fn is_public_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let octets = v.octets();
            !v.is_private()
                && !v.is_loopback()
                && !v.is_link_local()
                && !v.is_unspecified()
                && !v.is_multicast()
                && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        IpAddr::V6(v) => {
            !v.is_loopback()
                && !v.is_unspecified()
                && !v.is_multicast()
                && !v.is_unique_local()
                && !v.is_unicast_link_local()
        }
    }
}
fn nft_nat_target(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v) => format!("{v}:{port}"),
        IpAddr::V6(v) => format!("[{v}]:{port}"),
    }
}

async fn run_ok<const N: usize>(program: &str, args: [&str; N]) -> Result<()> {
    run_output(program, args).await.map(|_| ())
}
async fn run_ok_vec(program: &str, args: &[String]) -> Result<()> {
    let out = Command::new(program)
        .kill_on_drop(true)
        .args(args)
        .output()
        .await
        .with_context(|| format!("execute {program}"))?;
    ensure!(
        out.status.success(),
        "{program} {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(())
}
async fn ensure_rule(family: &str, priority: &str, selectors: &[&str], table: &str) -> Result<()> {
    let rules = run_output("ip", ["-N", family, "rule", "show"]).await?;
    let prefix = format!("{priority}:");
    let at_priority: Vec<&str> = rules
        .lines()
        .filter(|line| line.starts_with(&prefix))
        .collect();
    let wanted_priority = priority
        .parse::<u32>()
        .context("parse RIFT rule priority")?;
    for line in rules.lines() {
        let Some(existing_priority) = line
            .split(':')
            .next()
            .and_then(|v| v.trim().parse::<u32>().ok())
        else {
            continue;
        };
        if existing_priority >= wanted_priority {
            continue;
        }
        if selectors.first() == Some(&"fwmark") {
            let wanted = selectors
                .get(1)
                .and_then(|value| parse_rule_fwmark(&format!("fwmark {value}")));
            if let (Some((wanted_value, wanted_mask)), Some((value, mask))) =
                (wanted, parse_rule_fwmark(line))
            {
                let common = wanted_mask & mask;
                if common != 0 && wanted_value & common == value & common {
                    bail!("earlier ip {family} rule overlaps the RIFT packet mark: {line}");
                }
            }
        } else if selectors.first() == Some(&"from") {
            if let Some(wanted_ip) = selectors
                .get(1)
                .and_then(|s| s.split('/').next())
                .and_then(|s| s.parse::<IpAddr>().ok())
            {
                if let Some(from) = line
                    .split("from ")
                    .nth(1)
                    .and_then(|s| s.split_whitespace().next())
                {
                    if from != "all" && source_prefix_covers(from, wanted_ip) {
                        bail!("earlier ip {family} source rule covers the RIFT tunnel address: {line}");
                    }
                }
            }
        }
    }
    if let Some(line) = at_priority.first() {
        let exact = at_priority.len() == 1 && rule_matches_selectors(line, selectors, table);
        ensure!(
            exact,
            "ip {family} rule priority {priority} is occupied by a different rule: {line}"
        );
        return Ok(());
    }
    let mut args = vec![
        family.to_string(),
        "rule".into(),
        "add".into(),
        "priority".into(),
        priority.to_string(),
    ];
    args.extend(selectors.iter().map(|s| (*s).to_string()));
    args.extend(["table".into(), table.to_string()]);
    run_ok_vec("ip", &args).await
}
fn rule_matches_selectors(line: &str, selectors: &[&str], table: &str) -> bool {
    if !line.split_whitespace().any(|token| token == "lookup")
        || !line
            .split_whitespace()
            .skip_while(|token| *token != "lookup")
            .nth(1)
            .is_some_and(|lookup| lookup == table)
    {
        return false;
    }
    let mut index = 0;
    while index < selectors.len() {
        let selector = selectors[index];
        match selector {
            "from" => {
                let Some(wanted) = selectors.get(index + 1) else {
                    return false;
                };
                let wanted_ip = wanted
                    .split('/')
                    .next()
                    .and_then(|value| value.parse::<IpAddr>().ok());
                let actual = line
                    .split_whitespace()
                    .skip_while(|token| *token != "from")
                    .nth(1)
                    .and_then(|value| value.split('/').next())
                    .and_then(|value| value.parse::<IpAddr>().ok());
                if wanted_ip.is_none() || wanted_ip != actual {
                    return false;
                }
                index += 2;
            }
            "fwmark" => {
                let Some(wanted) = selectors.get(index + 1) else {
                    return false;
                };
                if parse_rule_fwmark(&format!("fwmark {wanted}")) != parse_rule_fwmark(line) {
                    return false;
                }
                index += 2;
            }
            other => {
                if !line.split_whitespace().any(|token| token == other) {
                    return false;
                }
                index += 1;
            }
        }
    }
    true
}
fn parse_rule_fwmark(line: &str) -> Option<(u32, u32)> {
    let token = line
        .split_whitespace()
        .skip_while(|v| *v != "fwmark")
        .nth(1)?;
    let (value, mask) = token.split_once('/').unwrap_or((token, "0xffffffff"));
    Some((parse_u32(value)?, parse_u32(mask)?))
}
fn parse_u32(value: &str) -> Option<u32> {
    let value = value.trim_start_matches("0x");
    if value.len() == 8
        || value
            .chars()
            .any(|c| c.is_ascii_hexdigit() && !c.is_ascii_digit())
    {
        u32::from_str_radix(value, 16).ok()
    } else {
        value.parse().ok()
    }
}
fn source_prefix_covers(prefix: &str, address: IpAddr) -> bool {
    prefix
        .parse::<IpNet>()
        .map(|net| net.contains(&address))
        .or_else(|_| prefix.parse::<IpAddr>().map(|ip| ip == address))
        .unwrap_or(false)
}
async fn run_output<const N: usize>(program: &str, args: [&str; N]) -> Result<String> {
    let out = Command::new(program)
        .kill_on_drop(true)
        .args(args)
        .output()
        .await
        .with_context(|| format!("execute {program}"))?;
    ensure!(
        out.status.success(),
        "{program} failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
enum RoutingClaim {
    Empty,
    Orphan,
    Foreign,
}

struct RoutingReservation<'a> {
    interface: &'a str,
    table: u32,
    priority: u32,
    mark: u32,
    mask: u32,
    v4_pool: ipnet::Ipv4Net,
    v6_pool: ipnet::Ipv6Net,
}

fn routing_claim(
    routes: &[&str],
    rules: &[&str],
    reserved: &RoutingReservation<'_>,
) -> RoutingClaim {
    let mut owned = false;
    for text in routes {
        for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            if is_agent_default_route(line, reserved.interface) {
                owned = true;
            } else {
                return RoutingClaim::Foreign;
            }
        }
    }
    for text in rules {
        for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            let Some(existing) = line.split(':').next().and_then(|v| v.trim().parse().ok()) else {
                continue;
            };
            let mentions_table = lookup_is(line, reserved.table);
            let mentions_priority =
                existing == reserved.priority || existing == reserved.priority.saturating_add(1);
            if !mentions_table && !mentions_priority {
                continue;
            }
            if rule_is_rift(line, existing, reserved) {
                owned = true;
            } else {
                return RoutingClaim::Foreign;
            }
        }
    }
    if owned {
        RoutingClaim::Orphan
    } else {
        RoutingClaim::Empty
    }
}

fn rule_is_rift(line: &str, existing: u32, reserved: &RoutingReservation<'_>) -> bool {
    if !lookup_is(line, reserved.table) {
        return false;
    }
    if existing == reserved.priority {
        return line
            .split("from ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .is_some_and(|from| {
                from != "all"
                    && selector_is_managed_tunnel(from, reserved.v4_pool, reserved.v6_pool)
            });
    }
    existing == reserved.priority.saturating_add(1)
        && parse_rule_fwmark(line) == Some((reserved.mark, reserved.mask))
}

fn lookup_is(line: &str, table: u32) -> bool {
    line.split_whitespace()
        .skip_while(|token| *token != "lookup")
        .nth(1)
        .is_some_and(|value| value == table.to_string())
}

fn selector_is_managed_tunnel(
    from: &str,
    v4_pool: ipnet::Ipv4Net,
    v6_pool: ipnet::Ipv6Net,
) -> bool {
    if let Ok(net) = from.parse::<IpNet>() {
        return match net.addr() {
            IpAddr::V4(ip) => net.prefix_len() == 32 && v4_pool.contains(&ip),
            IpAddr::V6(ip) => net.prefix_len() == 128 && v6_pool.contains(&ip),
        };
    }
    from.parse::<IpAddr>().is_ok_and(|ip| match ip {
        IpAddr::V4(ip) => v4_pool.contains(&ip),
        IpAddr::V6(ip) => v6_pool.contains(&ip),
    })
}

fn is_agent_default_route(line: &str, interface: &str) -> bool {
    let fields: Vec<_> = line.split_whitespace().collect();
    let metric = fields
        .windows(2)
        .find(|pair| pair[0] == "metric")
        .map(|pair| pair[1]);
    // ip -N renders RTN_UNREACHABLE as 7 instead of its symbolic name.
    if matches!(fields.as_slice(), ["7" | "unreachable", "default", ..]) {
        return metric == Some("42760");
    }
    matches!(fields.as_slice(), ["default", "dev", device, ..] if *device == interface)
        && metric == Some("10")
}
async fn read_route_table(family: &str, table: u32) -> Result<String> {
    let out = Command::new("ip")
        .kill_on_drop(true)
        .env("LC_ALL", "C")
        .args(["-N", family, "route", "show", "table", &table.to_string()])
        .output()
        .await
        .context("read routing table")?;
    route_table_output(
        family,
        table,
        out.status.code(),
        &String::from_utf8_lossy(&out.stdout),
        &String::from_utf8_lossy(&out.stderr),
    )
}
fn route_table_output(
    family: &str,
    table: u32,
    code: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> Result<String> {
    if code == Some(0) {
        return Ok(stdout.trim().to_string());
    }
    // The kernel creates each family's FIB table lazily, on its first route.
    let missing = match family {
        "-4" => "Error: ipv4: FIB table does not exist.",
        "-6" => "Error: ipv6: FIB table does not exist.",
        _ => bail!("unsupported routing address family {family}"),
    };
    if code == Some(2)
        && stdout.trim().is_empty()
        && stderr.trim() == format!("{missing}\nDump terminated")
    {
        return Ok(String::new());
    }
    bail!(
        "ip {family} route show table {table} failed (exit {code:?}): {}",
        stderr.trim()
    )
}
async fn run_stdin<const N: usize>(program: &str, args: [&str; N], input: &[u8]) -> Result<String> {
    let mut child = Command::new(program)
        .kill_on_drop(true)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("execute {program}"))?;
    child
        .stdin
        .take()
        .context("open child stdin")?
        .write_all(input)
        .await?;
    let out = child.wait_with_output().await?;
    ensure!(
        out.status.success(),
        "{program} failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
async fn nft_batch(batch: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .kill_on_drop(true)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("execute nft")?;
    child
        .stdin
        .take()
        .context("open nft stdin")?
        .write_all(batch.as_bytes())
        .await?;
    let out = child.wait_with_output().await?;
    ensure!(
        out.status.success(),
        "nft batch rejected: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(())
}
async fn check_foreign_nft_nat_conflict(
    ip: IpAddr,
    ports: PortRange,
    protocol: Protocol,
) -> Result<()> {
    let output = run_output("nft", ["-j", "list", "ruleset"])
        .await
        .context("inspect nftables for published-port conflicts")?;
    let document: Value = serde_json::from_str(&output).context("parse nftables JSON ruleset")?;
    let entries = document
        .get("nftables")
        .and_then(Value::as_array)
        .context("nftables JSON has no nftables array")?;
    let wanted_protocol = protocol.to_string();
    for entry in entries {
        let Some(rule) = entry.get("rule") else {
            continue;
        };
        if rule.get("family").and_then(Value::as_str) == Some("inet")
            && rule.get("table").and_then(Value::as_str) == Some("rift")
        {
            continue;
        }
        let Some(exprs) = rule.get("expr").and_then(Value::as_array) else {
            continue;
        };
        let has_nat = exprs
            .iter()
            .any(|expr| expr.get("dnat").is_some() || expr.get("redirect").is_some());
        if !has_nat {
            continue;
        }
        let mut protocol_matches = false;
        let mut port_matches = false;
        let mut address_match: Option<IpAddr> = None;
        for expr in exprs {
            let Some(m) = expr.get("match") else { continue };
            let left = &m["left"];
            let right = &m["right"];
            let payload = &left["payload"];
            if payload["field"].as_str() == Some("dport")
                && payload["protocol"].as_str() == Some(wanted_protocol.as_str())
            {
                protocol_matches = true;
                port_matches |= if m["op"].as_str() == Some("==") {
                    json_port_overlaps(right, ports)
                } else {
                    true
                };
            }
            if payload["field"].as_str() == Some("daddr") && m["op"].as_str() == Some("==") {
                let parsed = right.as_str().and_then(|s| s.parse::<IpAddr>().ok());
                if parsed.is_some() {
                    address_match = parsed;
                }
            }
        }
        if protocol_matches
            && port_matches
            && address_match.is_none_or(|addr| addr == ip || addr.is_unspecified())
        {
            let table = rule
                .get("table")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            let chain = rule
                .get("chain")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            bail!(
                "requested {ip}/{} port {} overlaps a foreign nft NAT rule in {table}/{chain}",
                protocol,
                ports
            );
        }
    }
    for family in ["iptables-save", "ip6tables-save"] {
        let wanted_family_is_v4 = family == "iptables-save";
        if wanted_family_is_v4 != ip.is_ipv4() {
            continue;
        }
        let result = Command::new(family)
            .kill_on_drop(true)
            .args(["-t", "nat"])
            .output()
            .await;
        let output = match result {
            Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).to_string(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Ok(out) => bail!(
                "{family} could not inspect legacy NAT rules: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            Err(error) => return Err(error).with_context(|| format!("execute {family}")),
        };
        for line in output
            .lines()
            .filter(|line| line.starts_with("-A ") && line.contains("-j DNAT"))
        {
            if legacy_nat_rule_overlaps(line, ip, ports, protocol) {
                bail!(
                    "requested {ip}/{} port {} overlaps a legacy iptables NAT rule: {line}",
                    protocol,
                    ports
                );
            }
        }
    }
    Ok(())
}
fn legacy_nat_rule_overlaps(
    line: &str,
    wanted_ip: IpAddr,
    wanted_ports: PortRange,
    wanted_protocol: Protocol,
) -> bool {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let protocol = fields
        .windows(2)
        .find(|w| w[0] == "-p" || w[0] == "--protocol")
        .map(|w| w[1]);
    let wanted_protocol_text = wanted_protocol.to_string();
    if protocol != Some(wanted_protocol_text.as_str()) {
        return false;
    }
    let destination = fields
        .windows(2)
        .find(|w| w[0] == "-d" || w[0] == "--destination")
        .and_then(|w| {
            w[1].parse::<IpNet>().ok().or_else(|| {
                w[1].parse::<IpAddr>().ok().map(|ip| {
                    if ip.is_ipv4() {
                        IpNet::new(ip, 32).ok().unwrap()
                    } else {
                        IpNet::new(ip, 128).ok().unwrap()
                    }
                })
            })
        });
    if let Some(destination) = destination {
        if !destination.contains(&wanted_ip) {
            return false;
        }
    }
    let Some(port_value) = fields
        .windows(2)
        .find(|w| w[0] == "--dport" || w[0] == "--destination-port" || w[0] == "--dports")
        .map(|w| w[1])
    else {
        return true;
    };
    port_value.split(',').any(|item| {
        let (a, b) = item
            .split_once(':')
            .or_else(|| item.split_once('-'))
            .unwrap_or((item, item));
        let start = a.parse::<u16>().ok();
        let end = b.parse::<u16>().ok();
        start
            .zip(end)
            .is_some_and(|(a, b)| wanted_ports.start <= b && a <= wanted_ports.end)
    })
}
fn json_port_overlaps(value: &Value, wanted: PortRange) -> bool {
    if let Some(port) = value.as_u64().and_then(|v| u16::try_from(v).ok()) {
        return wanted.start <= port && port <= wanted.end;
    }
    if let Some(values) = value.as_array() {
        return values.iter().any(|v| json_port_overlaps(v, wanted));
    }
    if let Some(range) = value.get("range") {
        if let Some(bounds) = range.as_array() {
            if bounds.len() == 2 {
                let start = bounds[0].as_u64().and_then(|v| u16::try_from(v).ok());
                let end = bounds[1].as_u64().and_then(|v| u16::try_from(v).ok());
                return start
                    .zip(end)
                    .is_some_and(|(a, b)| wanted.start <= b && a <= wanted.end);
            }
        }
    }
    false
}
async fn nft_table_exists() -> Result<bool> {
    let out = Command::new("nft")
        .kill_on_drop(true)
        .args(["list", "table", "inet", "rift"])
        .output()
        .await
        .context("execute nft")?;
    if out.status.success() {
        return Ok(true);
    }
    let err = String::from_utf8_lossy(&out.stderr).to_ascii_lowercase();
    if err.contains("no such file") || err.contains("does not exist") || err.contains("not found") {
        return Ok(false);
    }
    bail!("nft table preflight failed: {}", err.trim())
}
async fn interface_exists(interface: &str) -> Result<bool> {
    let out = Command::new("ip")
        .kill_on_drop(true)
        .args(["link", "show", "dev", interface])
        .output()
        .await
        .context("execute ip")?;
    if out.status.success() {
        return Ok(true);
    }
    let err = String::from_utf8_lossy(&out.stderr).to_ascii_lowercase();
    if err.contains("does not exist")
        || err.contains("cannot find device")
        || err.contains("not found")
    {
        return Ok(false);
    }
    bail!("ip link preflight failed: {}", err.trim())
}
fn rift_interface_alias(alias: &str) -> bool {
    let Some(token) = alias.strip_prefix("rift:") else {
        return false;
    };
    !token.is_empty()
        && token.len() <= 64
        && token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
}
async fn interface_alias(interface: &str) -> Result<String> {
    let output = run_output("ip", ["-j", "link", "show", "dev", interface]).await?;
    let value: Value = serde_json::from_str(&output).context("parse ip link JSON")?;
    value
        .as_array()
        .and_then(|links| links.first())
        .and_then(|link| link.get("ifalias"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .context("ip link JSON did not return the interface alias")
}
async fn command_version<const N: usize>(program: &str, args: [&str; N]) -> Value {
    match run_output(program, args).await {
        Ok(v) => json!({"available": true, "version": v}),
        Err(e) => json!({"available": false, "error": e.to_string()}),
    }
}
async fn read_sysctl(path: &str) -> Result<String> {
    tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("read {path}"))
        .map(|v| v.trim().to_string())
}
async fn inspect_sysctl(path: &str) -> Value {
    match read_sysctl(path).await {
        Ok(value) => json!({"value": value}),
        Err(error) => json!({"error": error.to_string()}),
    }
}
async fn read_owner_file(path: &Path) -> Result<Option<String>> {
    match tokio::fs::read_to_string(path).await {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read ownership marker {}", path.display())),
    }
}
async fn write_owner_new(path: &Path, value: &str) -> Result<()> {
    tokio::fs::create_dir_all(path.parent().context("ownership path has no parent")?).await?;
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await
        .with_context(|| format!("create persistent ownership marker {}", path.display()))?;
    file.write_all(value.as_bytes()).await?;
    file.sync_all().await?;
    Ok(())
}
async fn write_owner_replace(path: &Path, value: &str) -> Result<()> {
    let parent = path.parent().context("ownership path has no parent")?;
    tokio::fs::create_dir_all(parent).await?;
    let tmp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    tokio::fs::write(&tmp, value.as_bytes()).await?;
    tokio::fs::rename(&tmp, path)
        .await
        .with_context(|| format!("replace ownership marker {}", path.display()))?;
    Ok(())
}
async fn remove_owner_file(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("remove ownership marker {}", path.display())),
    }
}
async fn run_ok_allow_missing<const N: usize>(program: &str, args: [&str; N]) -> Result<()> {
    match run_ok(program, args).await {
        Ok(()) => Ok(()),
        Err(error) if missing_cleanup_object(program, &args, &error.to_string()) => Ok(()),
        Err(error) => Err(error),
    }
}

fn missing_cleanup_object(program: &str, args: &[&str], error: &str) -> bool {
    let message = error.to_ascii_lowercase();
    message.contains("no such process")
        || message.contains("not found")
        || message.contains("cannot find")
        || message.contains("no such file")
        // `ip route del` reports this when the FIB table was never created.
        || (program == "ip"
            && matches!(args, ["-4" | "-6", "route", "del", ..])
            && message.trim() == "ip failed: error: fib table does not exist.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AgentRecord, AgentStatus};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn cleanup_accepts_missing_fib_only_for_route_deletion() {
        let missing = "ip failed: Error: FIB table does not exist.";
        assert!(missing_cleanup_object(
            "ip",
            &["-4", "route", "del", "default"],
            missing
        ));
        assert!(missing_cleanup_object(
            "ip",
            &["-6", "route", "del", "default"],
            missing
        ));
        assert!(!missing_cleanup_object(
            "ip",
            &["-4", "rule", "del"],
            missing
        ));
        assert!(!missing_cleanup_object(
            "ip",
            &["-4", "route", "del"],
            "ip failed: Operation not permitted"
        ));
        assert!(!missing_cleanup_object(
            "ip",
            &["-4", "route", "del"],
            "ip failed: Error: FIB table does not exist.\nUnexpected error"
        ));
    }

    #[test]
    fn agent_route_validation_accepts_numeric_and_symbolic_unreachable_defaults() {
        for route in [
            "7 default metric 42760",
            "unreachable default metric 42760",
            "7 default dev lo metric 42760 pref medium",
            "default dev rift0 scope 253 metric 10",
            "default dev rift0 metric 10 pref medium",
        ] {
            assert!(is_agent_default_route(route, "rift0"), "{route}");
        }
        for route in [
            "7 default metric 427600",
            "7 192.0.2.0/24 metric 42760",
            "8 default metric 42760",
            "default dev rift01 metric 10",
            "default dev rift0 metric 100",
            "192.0.2.0/24 dev rift0 metric 10",
            "default via 192.0.2.1 dev eth0 metric 10",
            "",
        ] {
            assert!(!is_agent_default_route(route, "rift0"), "{route}");
        }
    }

    #[test]
    fn absent_fib_tables_are_empty_for_each_address_family() {
        for (family, name) in [("-4", "ipv4"), ("-6", "ipv6")] {
            let stderr = format!("Error: {name}: FIB table does not exist.\nDump terminated\n");
            assert_eq!(
                route_table_output(family, 51888, Some(2), "", &stderr).unwrap(),
                ""
            );
        }
    }

    #[test]
    fn route_table_reads_preserve_existing_routes_and_fail_on_other_errors() {
        let route = "default dev foreign0 metric 10\n";
        assert_eq!(
            route_table_output("-4", 51888, Some(0), route, "").unwrap(),
            route.trim()
        );
        assert_eq!(
            route_table_output("-6", 51888, Some(0), "", "").unwrap(),
            ""
        );
        let missing = "Error: ipv4: FIB table does not exist.\nDump terminated\n";
        for (family, code, stdout, stderr) in [
            (
                "-4",
                Some(2),
                "",
                "RTNETLINK answers: Operation not permitted\nDump terminated\n",
            ),
            ("-4", Some(2), "", "Dump terminated\n"),
            ("-4", Some(1), "", missing),
            ("-4", None, "", missing),
            ("-4", Some(2), route, missing),
            ("-6", Some(2), "", missing),
            (
                "-4",
                Some(2),
                "",
                "Error: ipv4: FIB table does not exist.\nDump terminated\nUnexpected error\n",
            ),
        ] {
            assert!(route_table_output(family, 51888, code, stdout, stderr).is_err());
        }
    }

    fn agent() -> AgentRecord {
        AgentRecord {
            id: "a1".into(),
            name: "agent".into(),
            public_key: "pub".into(),
            tunnel_ipv4: Ipv4Addr::new(10, 88, 0, 2),
            tunnel_ipv6: "fd88:5249:4654::2".parse().unwrap(),
            status: AgentStatus::Active,
            attempt_id: "x".into(),
            generation: 1,
            applied_generation: 1,
            last_error: None,
            created_at: 0,
            pending_deadline: None,
        }
    }
    fn forward(mode: ForwardMode) -> Forward {
        Forward {
            id: 1,
            agent_id: "a1".into(),
            listen_ip: "203.0.113.1".parse().unwrap(),
            listen_ports: PortRange { start: 80, end: 81 },
            target_ports: PortRange {
                start: 8080,
                end: 8081,
            },
            protocol: Protocol::Tcp,
            mode,
            ingress: crate::model::Ingress::Public,
            target_family: Family::V4,
            enabled: true,
            generation: 1,
        }
    }
    #[test]
    fn server_renderer_expands_port_ranges_without_snat() {
        let a = agent();
        let agents = BTreeMap::from([(a.id.clone(), &a)]);
        let f = forward(ForwardMode::Transparent);
        let mut udp = f.clone();
        udp.protocol = Protocol::Udp;
        let rendered = render_server_rules(
            "rift0",
            0x52490000,
            0xffff0000,
            8444,
            Ipv4Addr::new(10, 88, 0, 1),
            "fd88:5249:4654::1".parse().unwrap(),
            &[&f, &udp],
            &agents,
            &[],
        )
        .unwrap();
        assert!(rendered.contains("tcp dport 80 dnat ip to 10.88.0.2:8080"));
        assert!(rendered.contains("tcp dport 81 dnat ip to 10.88.0.2:8081"));
        assert!(rendered.contains("ct original ip daddr 203.0.113.1 ct original protocol tcp meta l4proto tcp ct original proto-dst 80 ip daddr 10.88.0.2 tcp dport 8080 accept"));
        assert!(rendered.contains("ct direction reply ct status dnat ct mark & 0xffff0000 == 0x52490000 ct original ip daddr 203.0.113.1 ct original protocol tcp meta l4proto tcp ct original proto-dst 80 ct reply ip saddr 10.88.0.2 meta l4proto tcp ct reply proto-src 8080 accept"));
        assert!(rendered.contains("ct original ip daddr 203.0.113.1 ct original protocol udp meta l4proto udp ct original proto-dst 80 ip daddr 10.88.0.2 udp dport 8080 accept"));
        assert!(rendered.contains("ct original ip daddr 203.0.113.1 ct original protocol tcp meta l4proto tcp ct original proto-dst 80 ip daddr 10.88.0.2 tcp dport 8080 meta l4proto tcp tcp flags & syn == syn tcp option maxseg size set rt mtu"));
        assert!(rendered.contains("ct direction reply ct status dnat ct mark & 0xffff0000 == 0x52490000 ct original ip daddr 203.0.113.1 ct original protocol tcp meta l4proto tcp ct original proto-dst 80 ct reply ip saddr 10.88.0.2 meta l4proto tcp ct reply proto-src 8080 meta l4proto tcp tcp flags & syn == syn tcp option maxseg size set rt mtu"));
        assert!(rendered
            .lines()
            .filter(|line| line.contains("maxseg size set rt mtu"))
            .all(|line| !line.contains("udp") && !line.ends_with("accept")));
        assert!(!rendered.contains("forward iifname \"rift0\" oifname != \"rift0\" ct mark & 0xffff0000 == 0x52490000 accept"));
        assert!(!rendered.contains("snat"));
        assert!(!rendered.contains("masquerade"));
        assert!(!rendered.contains("iifname != \"eth0\""));
    }
    #[test]
    fn local_ingress_excludes_the_public_uplink_on_dnat_and_the_original_forward() {
        let a = agent();
        let agents = BTreeMap::from([(a.id.clone(), &a)]);
        let mut f = forward(ForwardMode::Transparent);
        f.ingress = Ingress::Local;
        f.listen_ports = PortRange { start: 80, end: 80 };
        f.target_ports = PortRange {
            start: 8080,
            end: 8080,
        };
        let uplinks = vec!["eth0".to_string()];
        let rendered = render_server_rules(
            "rift0",
            0x52490000,
            0xffff0000,
            8444,
            Ipv4Addr::new(10, 88, 0, 1),
            "fd88:5249:4654::1".parse().unwrap(),
            &[&f],
            &agents,
            &uplinks,
        )
        .unwrap();
        let excluded = "iifname != \"rift0\" iifname != \"eth0\"";
        assert!(rendered.contains(&format!(
            "prerouting_nat {excluded} ip daddr 203.0.113.1 tcp dport 80 dnat ip to 10.88.0.2:8080"
        )));
        assert!(rendered.contains(&format!(
            "forward {excluded} oifname \"rift0\" ct direction original"
        )));
        assert!(
            rendered.contains("forward iifname \"rift0\" oifname != \"rift0\" ct direction reply")
        );
        assert!(render_server_rules(
            "rift0",
            0x52490000,
            0xffff0000,
            8444,
            Ipv4Addr::new(10, 88, 0, 1),
            "fd88:5249:4654::1".parse().unwrap(),
            &[&f],
            &agents,
            &[],
        )
        .is_err());
    }
    #[test]
    fn orphan_rift_routes_are_reclaimed_and_foreign_routes_are_refused() {
        let reserved = RoutingReservation {
            interface: "rift0",
            table: 51888,
            priority: 11000,
            mark: 0x52490000,
            mask: 0xffff0000,
            v4_pool: "10.88.0.0/24".parse().unwrap(),
            v6_pool: "fd88:5249:4654::/64".parse().unwrap(),
        };
        let routes = [
            "unreachable default metric 42760",
            "7 default dev lo metric 42760 pref medium",
        ];
        let rules = [
            "11000:\tfrom 10.88.0.2 lookup 51888",
            "11001:\tfrom all fwmark 0x52490000/0xffff0000 lookup 51888",
            "11000:\tfrom fd88:5249:4654::2 lookup 51888",
        ];
        assert!(matches!(
            routing_claim(&routes, &rules, &reserved),
            RoutingClaim::Orphan
        ));
        assert!(matches!(
            routing_claim(&[""], &[""], &reserved),
            RoutingClaim::Empty
        ));
        assert!(matches!(
            routing_claim(&["192.0.2.0/24 dev eth0 metric 10"], &rules, &reserved),
            RoutingClaim::Foreign
        ));
        assert!(matches!(
            routing_claim(
                &routes,
                &["11000:\tfrom 192.0.2.10 lookup 51888"],
                &reserved
            ),
            RoutingClaim::Foreign
        ));
        assert!(matches!(
            routing_claim(&routes, &["11002:\tfrom 10.88.0.2 lookup 51888"], &reserved),
            RoutingClaim::Foreign
        ));
    }
    #[test]
    fn rift_alias_identifies_an_orphaned_interface() {
        assert!(rift_interface_alias(
            "rift:dfc1f76d-be1c-4475-96d9-75036e592ed7"
        ));
        assert!(!rift_interface_alias(""));
        assert!(!rift_interface_alias("rift:"));
        assert!(!rift_interface_alias("wg0"));
        assert!(!rift_interface_alias("rift:not a token"));
    }
    #[test]
    fn forward_without_ingress_stays_public() {
        let raw = r#"{"id":1,"agent_id":"a","listen_ip":"203.0.113.1","listen_ports":{"start":80,"end":80},"target_ports":{"start":80,"end":80},"protocol":"tcp","mode":"transparent","target_family":"v4","enabled":true,"generation":1}"#;
        let parsed: Forward = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.ingress, Ingress::Public);
        parsed.validate().unwrap();
    }
    #[test]
    fn agent_renderer_classifies_translate_only_from_vps_tunnel_source() {
        let w = Welcome {
            agent_id: "a1".into(),
            name: "agent".into(),
            attempt_id: "x".into(),
            server_public_key: "pub".into(),
            server_endpoint: "example.test:51820".into(),
            server_ipv4: Ipv4Addr::new(10, 88, 0, 1),
            server_ipv6: "fd88:5249:4654::1".parse::<Ipv6Addr>().unwrap(),
            tunnel_ipv4: Ipv4Addr::new(10, 88, 0, 2),
            tunnel_ipv6: "fd88:5249:4654::2".parse().unwrap(),
            keepalive: 25,
            control_port: 8444,
            mtu: 1380,
        };
        let f = forward(ForwardMode::Translate);
        let mut udp = f.clone();
        udp.protocol = Protocol::Udp;
        let rendered =
            render_agent_rules("rift0", 0x52490000, 0xffff0000, &w, &[&f, &udp]).unwrap();
        assert!(rendered.contains("ip saddr 10.88.0.1"));
        assert!(rendered.contains("ct direction original"));
        assert!(rendered.contains("ct mark & 0xffff0000 == 0x52490000"));
        assert!(rendered.contains("ct original ip daddr 10.88.0.2 ct original protocol tcp meta l4proto tcp ct original proto-dst 8080 accept"));
        assert!(rendered.contains("ct original ip daddr 10.88.0.2 ct original protocol udp meta l4proto udp ct original proto-dst 8080 accept"));
        assert!(rendered.contains("iifname \"rift0\" oifname != \"rift0\" ct direction original ct mark & 0xffff0000 == 0x52490000 ct original ip saddr 10.88.0.1 ct original ip daddr 10.88.0.2 ct original protocol tcp meta l4proto tcp ct original proto-dst 8080 meta l4proto tcp tcp flags & syn == syn tcp option maxseg size set rt mtu"));
        assert!(rendered.contains("iifname != \"rift0\" oifname \"rift0\" ct direction reply ct mark & 0xffff0000 == 0x52490000 ct original ip saddr 10.88.0.1 ct original ip daddr 10.88.0.2 ct original protocol tcp meta l4proto tcp ct original proto-dst 8080 meta l4proto tcp tcp flags & syn == syn tcp option maxseg size set rt mtu"));
        assert!(rendered
            .lines()
            .filter(|line| line.contains("maxseg size set rt mtu"))
            .all(|line| !line.contains("udp") && !line.ends_with("accept")));
        assert!(rendered.contains("ct original ip saddr 10.88.0.2 ct original ip daddr 10.88.0.1 ct original protocol tcp meta l4proto tcp ct original proto-dst 8444 accept"));
        assert!(rendered.contains("iifname != \"rift0\" oifname \"rift0\" ct direction reply ct mark & 0xffff0000 == 0x52490000 ct original ip saddr 10.88.0.1 ct original ip daddr 10.88.0.2"));
        assert!(
            !rendered.contains("input iifname \"rift0\" ct mark & 0xffff0000 == 0x52490000 accept")
        );
        assert!(rendered.contains("oifname != \"rift0\" drop"));
    }

    #[test]
    fn policy_rule_match_accepts_kernel_elided_host_prefixes() {
        assert!(rule_matches_selectors(
            "100: from 10.88.0.2 lookup 100",
            &["from", "10.88.0.2/32"],
            "100"
        ));
        assert!(rule_matches_selectors(
            "100: from fd88:5249:4654::2 lookup 100",
            &["from", "fd88:5249:4654::2/128"],
            "100"
        ));
        assert!(!rule_matches_selectors(
            "100: from 10.88.0.3 lookup 100",
            &["from", "10.88.0.2/32"],
            "100"
        ));
    }

    #[test]
    fn policy_rule_match_compares_fwmark_value_and_mask() {
        assert!(rule_matches_selectors(
            "101: from all fwmark 0x52490000/0xffff0000 lookup 100",
            &["fwmark", "0x52490000/0xffff0000"],
            "100"
        ));
        assert!(!rule_matches_selectors(
            "101: from all fwmark 0x52490000/0xff000000 lookup 100",
            &["fwmark", "0x52490000/0xffff0000"],
            "100"
        ));
    }
    #[test]
    fn stale_endpoint_tries_other_families_without_overwriting_fresh_roaming() {
        let a: SocketAddr = "192.0.2.1:51820".parse().unwrap();
        let b: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
        let mut peer = WgPeer {
            public_key: "test".into(),
            endpoint: Some(a.to_string()),
            allowed_ips: vec![],
            latest_handshake: 0,
            rx_bytes: 0,
            tx_bytes: 0,
        };
        assert_eq!(choose_endpoint(&[a, b], Some(&peer), 180), b);
        peer.latest_handshake = unix_now() as i64;
        assert_eq!(choose_endpoint(&[b], Some(&peer), 180), a);
    }
}
