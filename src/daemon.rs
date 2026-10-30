#![cfg_attr(not(unix), allow(dead_code))]
use crate::{
    agent_policy,
    config::{validate_name, Config, EnrollmentMode},
    enrollment,
    model::*,
    net::{self, Kernel},
    protocol::{self, *},
    state::StateStore,
    translation::TranslationManager,
};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde::Serialize;
use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore},
    time::timeout,
};

struct Server {
    config: tokio::sync::RwLock<Config>,
    config_path: PathBuf,
    state: Arc<StateStore>,
    kernel: Arc<Mutex<Kernel>>,
    translation: Mutex<TranslationManager>,
    server_public_key: String,
    /// Set when the web panel is on.
    panel_password: Option<String>,
    two_factor: Arc<crate::totp::TwoFactor>,
    /// The running enrollment listener, if any. Shared with the kernel for the host firewall.
    enrollment: Mutex<Option<tokio::task::JoinHandle<()>>>,
    enrollment_open: Arc<std::sync::atomic::AtomicBool>,
}

/// The web panel acts through the same admin requests as the CLI.
struct PanelBackend(Arc<Server>);
impl crate::webpanel::Backend for PanelBackend {
    async fn admin(&self, request: AdminRequest) -> Result<serde_json::Value> {
        admin_call_impl(&self.0, request)
            .await
            .map_err(|e| anyhow!(sanitize_error(&e.to_string())))
    }
    fn panel_peers(&self) -> Vec<IpAddr> {
        self.0
            .state
            .snapshot()
            .map(|snap| {
                snap.vpn_peers
                    .iter()
                    .filter(|p| p.enabled && p.panel)
                    .map(|p| IpAddr::V4(p.ipv4))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg_attr(not(unix), allow(clippy::let_unit_value))]
pub async fn run_server(config: Config, config_path: PathBuf) -> Result<()> {
    let mut config = config;
    config.validate()?;
    secure_dir(&config.state_dir)?;
    if config.enrollment != EnrollmentMode::Off {
        crate::tls_material::prepare(&mut config)?;
        let _ = enrollment::server_tls(&config)?;
    }
    let (server_public_key, _private_path) = ensure_server_keypair(&config).await?;
    let state = Arc::new(StateStore::open(&config.state_dir.join("state.db"))?);
    let panel_password = if config.webpanel {
        Some(crate::webpanel::password(&config)?)
    } else {
        None
    };
    let kernel = Kernel::new(config.clone());
    let enrollment_open = kernel.enrollment_open.clone();
    let server = Arc::new(Server {
        config: tokio::sync::RwLock::new(config.clone()),
        config_path: config_path.clone(),
        state,
        kernel: Arc::new(Mutex::new(kernel)),
        translation: Mutex::new(TranslationManager::new()),
        server_public_key,
        panel_password,
        two_factor: Arc::new(crate::totp::TwoFactor::new(crate::totp::path(&config))),
        enrollment: Mutex::new(None),
        enrollment_open,
    });
    reconcile(&server).await?;
    let admin = bind_admin(config.socket_path()).await?;
    let s = server.clone();
    let mut tasks = vec![tokio::spawn(async move {
        if let Err(e) = serve_admin(admin, s).await {
            tracing::error!("admin socket stopped: {e:#}");
        }
    })];
    let control4 = TcpListener::bind(SocketAddr::new(
        config.server_ipv4.into(),
        config.control_port,
    ))
    .await
    .context("bind IPv4 WireGuard control address")?;
    let control6 = TcpListener::bind(SocketAddr::new(
        config.server_ipv6.into(),
        config.control_port,
    ))
    .await
    .context("bind IPv6 WireGuard control address")?;
    let s = server.clone();
    tasks.push(tokio::spawn(
        async move { accept_control(control4, s).await },
    ));
    let s = server.clone();
    tasks.push(tokio::spawn(
        async move { accept_control(control6, s).await },
    ));
    if config.enrollment == EnrollmentMode::Always {
        anyhow::ensure!(
            server.enrollment_open.load(Ordering::SeqCst),
            "enrollment endpoint {} could not be opened",
            config.enrollment_bind
        );
    }
    if let Some(password) = &server.panel_password {
        // The tunnel and forwards must not depend on the panel: without its port, run without it.
        let listeners = match crate::webpanel::bind(&config).await {
            Ok(listeners) => listeners,
            Err(error) => {
                tracing::error!("web panel not started: {error:#}; RIFT runs without it. Free the port or set RIFT_WEBPANEL_PORT, then recreate the container");
                Vec::new()
            }
        };
        let panel = Arc::new(crate::webpanel::Panel::new(
            PanelBackend(server.clone()),
            config.clone(),
            password,
            server.two_factor.clone(),
        ));
        for listener in listeners {
            let address = listener.local_addr()?;
            tracing::info!(
                "web panel ({}) listening on {address}",
                config.webpanel_access
            );
            tasks.push(tokio::spawn(panel.clone().serve(listener)));
        }
        if config.webpanel_access == crate::config::PanelAccess::Public {
            tracing::warn!("the web panel is public over plain HTTP; its password crosses the network unencrypted unless a TLS proxy is in front of it");
        }
    }
    tracing::info!("RIFT server ready; config={}", config_path.display());
    let poll = Duration::from_secs(config.poll_seconds);
    #[cfg(unix)]
    let terminate_future = {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        async move {
            let _ = signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate_future = async { std::future::pending::<()>().await };
    tokio::pin!(terminate_future);
    loop {
        tokio::select! {_ = tokio::signal::ctrl_c()=>break,_=&mut terminate_future=>break,
        _=tokio::time::sleep(poll)=>{if let Err(e)=expire_and_reconcile(&server).await{tracing::error!("reconcile failed: {e:#}");}}}
    }
    // Wait for an in-flight reconciliation before stopping request handlers.
    // Keep this lock until cleanup finishes so no handler can apply new state.
    let kernel = server.kernel.lock().await;
    if let Some(task) = server.enrollment.lock().await.take() {
        task.abort();
    }
    for task in &tasks {
        task.abort();
    }
    let _ = timeout(Duration::from_secs(3), async {
        for task in tasks {
            let _ = task.await;
        }
    })
    .await;
    kernel.cleanup().await.context("clean up server networking")
}

async fn ensure_server_keypair(config: &Config) -> Result<(String, PathBuf)> {
    let private = config.private_key_path();
    let public = config.state_dir.join("wireguard.pub");
    if !private.exists() {
        let (secret, pubkey) = net::generate_keypair().await?;
        atomic_write(&private, secret.as_bytes(), 0o600)?;
        atomic_write(&public, pubkey.as_bytes(), 0o644)?;
    }
    anyhow::ensure!(private.exists(), "server WireGuard private key is missing");
    if !public.exists() {
        let private_text = std::fs::read_to_string(&private)?;
        let pubkey = net::wg_public_key(private_text.trim()).await?;
        atomic_write(&public, pubkey.as_bytes(), 0o644)?;
    }
    Ok((std::fs::read_to_string(public)?.trim().into(), private))
}

/// Opens or closes the enrollment listener. `always` keeps it open, `auto` only while an
/// invitation is open (until activation, expiry or cancellation), `off` never.
async fn sync_enrollment(s: &Server) -> Result<()> {
    let config = s.config.read().await.clone();
    let wanted = match config.enrollment {
        EnrollmentMode::Always => true,
        EnrollmentMode::Off => false,
        EnrollmentMode::Auto => !s.state.open_invites()?.is_empty(),
    };
    let mut running = s.enrollment.lock().await;
    let is_running = running.as_ref().is_some_and(|task| !task.is_finished());
    if wanted && !is_running {
        let listener = TcpListener::bind(config.enrollment_bind)
            .await
            .with_context(|| format!("bind enrollment endpoint {}", config.enrollment_bind))?;
        // 0.0.0.0 also listens on IPv6, so agents with only IPv6 can enroll. A host without
        // IPv6 simply lacks that listener.
        let listener6 = match config.enrollment_bind.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => {
                ipv6_only_listener(config.enrollment_bind.port()).ok()
            }
            _ => None,
        };
        let serve = |listener| {
            enrollment::serve(
                listener,
                s.state.clone(),
                config.clone(),
                s.server_public_key.clone(),
                s.kernel.clone(),
            )
        };
        let (v4, v6) = (serve(listener), listener6.map(serve));
        *running = Some(tokio::spawn(async move {
            let result = match v6 {
                Some(v6) => tokio::try_join!(v4, v6).map(|_| ()),
                None => v4.await,
            };
            if let Err(e) = result {
                tracing::error!("enrollment endpoint stopped: {e:#}");
            }
        }));
        s.enrollment_open.store(true, Ordering::SeqCst);
        tracing::info!(
            "enrollment endpoint {} open ({})",
            config.enrollment_bind,
            config.enrollment
        );
    } else if !wanted {
        if let Some(task) = running.take() {
            task.abort();
            tracing::info!(
                "enrollment endpoint {} closed; no invitation is open",
                config.enrollment_bind
            );
        }
        s.enrollment_open.store(false, Ordering::SeqCst);
    }
    Ok(())
}

fn ipv6_only_listener(port: u16) -> Result<TcpListener> {
    use socket2::{Domain, Socket, Type};
    let socket = Socket::new(Domain::IPV6, Type::STREAM, None)?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), port).into())?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    Ok(TcpListener::from_std(socket.into())?)
}

async fn reconcile(s: &Server) -> Result<()> {
    // A failed bind must not stop forwards from being applied; status reports the port state.
    if let Err(error) = sync_enrollment(s).await {
        tracing::error!("enrollment endpoint: {error:#}");
    }
    let config = s.config.read().await.clone();
    let k = s.kernel.lock().await;
    let snapshot = without_refused(s.state.snapshot()?);
    let result = async {
        k.apply_server(&snapshot, &config.private_key_path())
            .await?;
        s.translation.lock().await.reconcile(&snapshot).await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    match result {
        Ok(()) => s.state.mark_applied(&snapshot),
        Err(error) => {
            if let Some(previous) = s.state.last_applied()? {
                let rollback = safe_rollback(previous, &s.state.snapshot()?);
                if let Err(restore) = async {
                    k.apply_server(&rollback, &config.private_key_path())
                        .await?;
                    s.translation.lock().await.reconcile(&rollback).await
                }
                .await
                {
                    tracing::error!("RIFT rollback failed: {restore:#}");
                }
            }
            s.state
                .mark_failed(snapshot.generation, &sanitize_error(&error.to_string()))?;
            Err(error.context("desired configuration not applied; retained safe previously confirmed grants where possible"))
        }
    }
}
// Rollback never reinstalls revoked agents, ports or superseded keys.
fn safe_rollback(mut previous: StateSnapshot, desired: &StateSnapshot) -> StateSnapshot {
    previous.agents.retain(|old| {
        desired.agents.iter().any(|new| {
            new.id == old.id
                && new.status != AgentStatus::Disabled
                && new.public_key == old.public_key
        })
    });
    previous.forwards.retain(|old| {
        previous.agents.iter().any(|a| a.id == old.agent_id)
            && desired.forwards.iter().any(|new| {
                new.id == old.id
                    && new.enabled
                    && serde_json::to_value(old).ok() == serde_json::to_value(new).ok()
            })
    });
    // Neither a revoked or disabled device nor a withdrawn grant comes back.
    previous.vpn_peers.retain(|old| {
        desired.vpn_peers.iter().any(|new| {
            new.enabled
                && new
                    == &VpnPeer {
                        enabled: true,
                        ..old.clone()
                    }
        })
    });
    previous.vpn_grants.retain(|old| {
        desired.vpn_grants.contains(old) && previous.vpn_peers.iter().any(|p| p.name == old.peer)
    });
    previous.bans = desired
        .bans
        .iter()
        .filter(|b| previous.forwards.iter().any(|f| f.id == b.forward_id))
        .cloned()
        .collect();
    previous
}
async fn expire_and_reconcile(s: &Server) -> Result<()> {
    let _ = s.state.expire_staging()?;
    let result = reconcile(s).await;
    let timeout = s.config.read().await.handshake_timeout;
    if let Ok(peers) = s.kernel.lock().await.stats().await {
        s.state.observe_health(&peers, timeout)?;
    }
    result
}
async fn reload_config(s: &Server) -> Result<u64> {
    let current = s.config.read().await.clone();
    let mut next = Config::load(&s.config_path)?;
    // Auto-generated trust material is held in the state directory, not duplicated in TOML.
    if next.tls_cert.is_none() {
        next.tls_cert = current.tls_cert.clone();
        next.tls_key = current.tls_key.clone();
        next.tls_ca = current.tls_ca.clone();
    }
    let immutable_changed = next.state_dir != current.state_dir
        || next.interface != current.interface
        || next.public_endpoint != current.public_endpoint
        || next.wg_port != current.wg_port
        || next.enrollment_bind != current.enrollment_bind
        || next.enrollment != current.enrollment
        || next.control_port != current.control_port
        || next.ipv4_pool != current.ipv4_pool
        || next.ipv6_pool != current.ipv6_pool
        || next.server_ipv4 != current.server_ipv4
        || next.server_ipv6 != current.server_ipv6
        || next.vpn_pool != current.vpn_pool
        || next.webpanel != current.webpanel
        || next.webpanel_access != current.webpanel_access
        || next.webpanel_port != current.webpanel_port
        || next.webpanel_control != current.webpanel_control
        || next.webpanel_2fa != current.webpanel_2fa
        || next.webpanel_allow != current.webpanel_allow
        || next.route_table != current.route_table
        || next.rule_priority != current.rule_priority
        || next.mark != current.mark
        || next.mark_mask != current.mark_mask
        || next.tls_cert != current.tls_cert
        || next.tls_key != current.tls_key
        || next.tls_ca != current.tls_ca;
    anyhow::ensure!(!immutable_changed,"configuration change requires a service restart (interface, endpoint, pools, ports, routing, web panel, or TLS identity)");
    let kernel = |config| {
        let mut kernel = Kernel::new(config);
        kernel.enrollment_open = s.enrollment_open.clone();
        kernel
    };
    *s.config.write().await = next.clone();
    *s.kernel.lock().await = kernel(next);
    if let Err(error) = reconcile(s).await {
        *s.config.write().await = current.clone();
        *s.kernel.lock().await = kernel(current);
        let _ = reconcile(s).await;
        return Err(error.context("reload rejected; previous runtime configuration restored"));
    }
    Ok(s.state.snapshot()?.generation)
}

async fn accept_control(listener: TcpListener, s: Arc<Server>) {
    let permits = Arc::new(Semaphore::new(128));
    let mut requests = tokio::task::JoinSet::new();
    loop {
        while requests.try_join_next().is_some() {}
        let accepted = listener.accept().await;
        let (stream, remote) = match accepted {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("control accept: {e}");
                continue;
            }
        };
        let permit = match permits.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let s = s.clone();
        requests.spawn(async move {
            let _permit = permit;
            if let Err(e) = timeout(
                Duration::from_secs(12),
                handle_control(stream, remote.ip(), s),
            )
            .await
            .unwrap_or_else(|_| Err(anyhow!("control request timed out")))
            {
                tracing::debug!("control request rejected: {e:#}");
            }
        });
    }
}

async fn handle_control(mut stream: TcpStream, source: IpAddr, s: Arc<Server>) -> Result<()> {
    let request: ControlRequest = protocol::receive(&mut stream).await?;
    let agent = s
        .state
        .snapshot()?
        .agents
        .into_iter()
        .find(|a| a.tunnel_ipv4 == source || a.tunnel_ipv6 == source)
        .ok_or_else(|| anyhow!("source is not an assigned tunnel address"))?;
    if agent.status == AgentStatus::Disabled {
        bail!("agent is disabled")
    }
    let response = match request {
        ControlRequest::Activate {
            version,
            agent_id,
            attempt_id,
        } => {
            anyhow::ensure!(
                version == VERSION && agent_id == agent.id,
                "identity mismatch"
            );
            let snap = s.state.activate(&agent.id, &attempt_id, source)?;
            reconcile(&s).await?;
            ControlResponse::Active {
                generation: snap.generation,
            }
        }
        ControlRequest::Sync {
            version,
            agent_id,
            applied_generation,
            error,
            limits,
        } => {
            anyhow::ensure!(
                version == VERSION && agent_id == agent.id,
                "identity mismatch"
            );
            if agent.status != AgentStatus::Active {
                bail!("agent has not completed activation")
            }
            let changed_limits = agent.limits.as_ref() != Some(&limits);
            let previous = agent.applied_generation;
            let _ = s
                .state
                .update_agent_sync(&agent.id, applied_generation, error, limits)?;
            if previous != applied_generation || changed_limits {
                reconcile(&s).await?;
            }
            let pool = s.config.read().await.vpn_pool;
            if let Some((rotation_id, _, committed)) = s.state.rotation(&agent.id)? {
                if !committed {
                    ControlResponse::RotateRequested { rotation_id }
                } else {
                    ControlResponse::Policy(policy_for(&s.state.snapshot()?, &agent.id, pool))
                }
            } else {
                ControlResponse::Policy(policy_for(&s.state.snapshot()?, &agent.id, pool))
            }
        }
        ControlRequest::Ban {
            version,
            agent_id,
            forward_id,
            ip,
            ttl_seconds,
        } => {
            anyhow::ensure!(
                version == VERSION && agent_id == agent.id,
                "identity mismatch"
            );
            anyhow::ensure!(
                (1..=86400).contains(&ttl_seconds),
                "ban TTL must be at most one day"
            );
            s.state.mutate("agent-ban", |snap| {
                let f = snap
                    .forwards
                    .iter()
                    .find(|f| {
                        f.id == forward_id
                            && f.agent_id == agent.id
                            && f.mode == ForwardMode::Translate
                            && f.enabled
                    })
                    .ok_or_else(|| {
                        anyhow!("ban is limited to this agent's active translated forwards")
                    })?;
                let _ = f;
                let next = snap.bans.iter().map(|b| b.id).max().unwrap_or(0) + 1;
                snap.bans.retain(|b| {
                    !(b.agent_id == agent.id && b.forward_id == forward_id && b.ip == ip)
                });
                snap.bans.push(Ban {
                    id: next,
                    agent_id: agent.id.clone(),
                    forward_id,
                    ip,
                    expires_at: now() + ttl_seconds as i64,
                });
                Ok(())
            })?;
            reconcile(&s).await?;
            ControlResponse::Ok
        }
        ControlRequest::RotateKey {
            version,
            agent_id,
            rotation_id,
            public_key,
        } => {
            anyhow::ensure!(
                version == VERSION && agent_id == agent.id,
                "identity mismatch"
            );
            anyhow::ensure!(
                public_key.len() <= 64
                    && base64::engine::general_purpose::STANDARD
                        .decode(&public_key)?
                        .len()
                        == 32,
                "invalid WireGuard public key"
            );
            let existing = s
                .state
                .rotation(&agent.id)?
                .ok_or_else(|| anyhow!("no rotation requested"))?;
            anyhow::ensure!(existing.0 == rotation_id, "rotation id mismatch");
            let snap = s
                .state
                .commit_rotation(&agent.id, &rotation_id, &public_key)?;
            reconcile(&s).await?;
            ControlResponse::RotateCommitted {
                generation: snap.generation,
            }
        }
    };
    protocol::send(&mut stream, &response).await?;
    Ok(())
}
/// Why the agent behind `forward` refuses it, by the limits it last reported.
fn forward_refusal(snap: &StateSnapshot, forward: &Forward) -> Option<String> {
    let agent = snap.agents.iter().find(|a| a.id == forward.agent_id)?;
    agent.limits.as_ref()?.refuse_forward(forward)
}
fn grant_refusal(snap: &StateSnapshot, grant: &VpnGrant) -> Option<String> {
    let agent = snap.agents.iter().find(|a| a.id == grant.agent_id)?;
    agent.limits.as_ref()?.refuse_access(&grant.access)
}
/// The snapshot without what agents refuse. Publishing a forward the agent drops would open
/// a public port nothing answers on; the agent enforces its limits anyway.
fn without_refused(snap: StateSnapshot) -> StateSnapshot {
    let mut out = snap.clone();
    out.forwards.retain(|f| forward_refusal(&snap, f).is_none());
    out.vpn_grants.retain(|g| grant_refusal(&snap, g).is_none());
    out.bans
        .retain(|b| out.forwards.iter().any(|f| f.id == b.forward_id));
    out
}
/// enabled, disabled, pending (not applied by the agent yet) or refused (outside its limits).
fn forward_state(snap: &StateSnapshot, forward: &Forward) -> (&'static str, Option<String>) {
    if !forward.enabled {
        return ("disabled", None);
    }
    if let Some(why) = forward_refusal(snap, forward) {
        return ("refused", Some(why));
    }
    let applied = snap.agents.iter().any(|a| {
        a.id == forward.agent_id
            && a.status == AgentStatus::Active
            && a.applied_generation >= forward.generation
    });
    (if applied { "enabled" } else { "pending" }, None)
}
fn forward_json(snap: &StateSnapshot, forward: &Forward) -> Result<serde_json::Value> {
    let (state, refusal) = forward_state(snap, forward);
    let mut value = serde_json::to_value(forward)?;
    value["state"] = state.into();
    value["refused"] = refusal.into();
    Ok(value)
}
fn policy_for(snapshot: &StateSnapshot, id: &str, vpn_pool: ipnet::Ipv4Net) -> AgentPolicy {
    let snapshot = &without_refused(snapshot.clone());
    AgentPolicy {
        generation: snapshot.generation,
        forwards: snapshot
            .forwards
            .iter()
            .filter(|f| f.agent_id == id && f.enabled)
            .cloned()
            .collect(),
        vpn_pool: Some(vpn_pool),
        vpn: crate::vpn::agent_rules(snapshot, id),
    }
}

#[cfg(unix)]
async fn bind_admin(path: PathBuf) -> Result<tokio::net::UnixListener> {
    use std::os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::UnixStream as StdUnixStream,
    };
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        if !meta.file_type().is_socket() {
            bail!("admin socket path exists and is not a socket")
        }
        if StdUnixStream::connect(&path).is_ok() {
            bail!("admin socket is already active")
        };
        std::fs::remove_file(&path)?;
    }
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let listener = tokio::net::UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}
#[cfg(not(unix))]
async fn bind_admin(_path: PathBuf) -> Result<()> {
    bail!("RIFT admin socket is supported on Unix only")
}

#[cfg(unix)]
async fn serve_admin(listener: tokio::net::UnixListener, s: Arc<Server>) -> Result<()> {
    let permits = Arc::new(Semaphore::new(32));
    let mut requests = tokio::task::JoinSet::new();
    loop {
        while requests.try_join_next().is_some() {}
        let (mut stream, _) = listener.accept().await?;
        if !admin_peer_allowed(&stream) {
            continue;
        };
        let permit = match permits.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let s = s.clone();
        requests.spawn(async move {
            let _p = permit;
            let result = timeout(Duration::from_secs(15), async {
                let req: AdminRequest = protocol::receive(&mut stream).await?;
                let response = match admin_call_impl(&s, req).await {
                    Ok(v) => AdminResponse::success(v),
                    Err(e) => AdminResponse::error(sanitize_error(&e.to_string())),
                };
                protocol::send_admin(&mut stream, &response).await
            })
            .await;
            if let Err(e) = result.unwrap_or_else(|_| Err(anyhow!("admin request timed out"))) {
                tracing::warn!("admin socket request failed: {e}");
            }
        });
    }
}
#[cfg(unix)]
fn admin_peer_allowed(stream: &tokio::net::UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    let mut cred = unsafe { std::mem::zeroed::<libc::ucred>() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut _,
            &mut len,
        )
    };
    rc == 0 && (cred.uid == 0 || cred.uid == unsafe { libc::geteuid() })
}
#[cfg(not(unix))]
async fn serve_admin(_listener: (), _s: Arc<Server>) -> Result<()> {
    bail!("RIFT admin socket is supported on Unix only")
}
fn sanitize_error(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(300).collect()
}

#[cfg(unix)]
pub async fn admin_call(config: &Config, request: AdminRequest) -> Result<AdminResponse> {
    let mut stream = timeout(
        Duration::from_secs(4),
        tokio::net::UnixStream::connect(config.socket_path()),
    )
    .await??;
    protocol::send(&mut stream, &request).await?;
    timeout(
        Duration::from_secs(10),
        protocol::receive_admin(&mut stream),
    )
    .await?
}
#[cfg(not(unix))]
pub async fn admin_call(_config: &Config, _request: AdminRequest) -> Result<AdminResponse> {
    bail!("admin socket is supported on Unix only")
}

async fn admin_call_impl(s: &Server, r: AdminRequest) -> Result<serde_json::Value> {
    let snap = s.state.snapshot()?;
    let data = match r {
        AdminRequest::Status => {
            let k = s.kernel.lock().await;
            let peers = k.stats().await?;
            let doctor = k.doctor().await?;
            let applied = s.state.last_applied()?.map(|s| s.generation);
            let error = s.state.apply_error()?;
            let health:Vec<_>=snap.agents.iter().map(|a|{
                let peer=peers.iter().find(|p|p.public_key==a.public_key);
                let online=peer.is_some_and(|p|p.last_handshake>0 && now().saturating_sub(p.last_handshake)<=180);
                serde_json::json!({"id":a.id,"name":a.name,"online":online,"configuration_ready":a.applied_generation>=a.generation,"last_error":a.last_error,"last_handshake":peer.map(|p|p.last_handshake)})
            }).collect();
            let pending_forwards: Vec<_> = snap
                .forwards
                .iter()
                .filter(|f| forward_state(&snap, f).0 == "pending")
                .map(|f| f.id)
                .collect();
            let refused_forwards: Vec<_> = snap
                .forwards
                .iter()
                .filter_map(|f| match forward_state(&snap, f) {
                    ("refused", why) => Some(serde_json::json!({"id":f.id,"reason":why})),
                    _ => None,
                })
                .collect();
            let fully_applied =
                error.is_none() && applied == Some(snap.generation) && pending_forwards.is_empty();
            let cfg = s.config.read().await.clone();
            let invites: Vec<_> = s
                .state
                .open_invites()?
                .into_iter()
                .map(|(name, expires_at)| serde_json::json!({"name":name,"expires_at":expires_at}))
                .collect();
            let enrollment = serde_json::json!({"mode":cfg.enrollment,"open":s.enrollment_open.load(Ordering::SeqCst),"bind":cfg.enrollment_bind});
            serde_json::json!({"snapshot":snap,"enrollment":enrollment,"invites":invites,"peers":peers,"doctor":doctor,"applied_generation":applied,"apply_error":error,"agent_health":health,"pending_forwards":pending_forwards,"refused_forwards":refused_forwards,"fully_applied":fully_applied,"connection_history":s.state.health()?})
        }
        AdminRequest::AgentsList => serde_json::to_value(snap.agents)?,
        AdminRequest::AgentsShow { name } => {
            let a = snap
                .agents
                .iter()
                .find(|a| a.name == name || a.id == name)
                .ok_or_else(|| anyhow!("agent not found"))?;
            serde_json::to_value(a)?
        }
        AdminRequest::Invite { name, ttl_seconds } => {
            let cfg = s.config.read().await.clone();
            validate_name(&name)?;
            anyhow::ensure!(
                cfg.enrollment != EnrollmentMode::Off,
                "enrollment is off; set RIFT_ENROLLMENT=auto in the server .env and recreate the container"
            );
            let token = enrollment::create_invite(&cfg, &s.state, &name, ttl_seconds)?;
            sync_enrollment(s)
                .await
                .context("invitation created, but the enrollment port could not be opened")?;
            reconcile(s).await?;
            serde_json::json!({"name":name,"token":token,"expires_at":now()+ttl_seconds as i64,"server":host_port(&cfg.public_endpoint,cfg.enrollment_bind.port()),"enrollment":cfg.enrollment})
        }
        AdminRequest::CancelInvite { name } => {
            s.state.cancel_invite(&name)?;
            reconcile(s).await?;
            serde_json::json!({"cancelled":name})
        }
        AdminRequest::AgentRemove { name } => {
            let id = find_agent(&snap, &name)?.id.clone();
            s.state.remove_agent(&id)?;
            reconcile(s).await?;
            serde_json::json!({"removed":id})
        }
        AdminRequest::AgentDisable { name } => {
            let id = find_agent(&snap, &name)?.id.clone();
            s.state.mutate("agent-disable", |x| {
                let a = x
                    .agents
                    .iter_mut()
                    .find(|a| a.id == id)
                    .ok_or_else(|| anyhow!("agent not found"))?;
                anyhow::ensure!(
                    a.status == AgentStatus::Active,
                    "only an active agent can be disabled; cancel pending invitation instead"
                );
                a.status = AgentStatus::Disabled;
                Ok(())
            })?;
            reconcile(s).await?;
            serde_json::json!({"disabled":id})
        }
        AdminRequest::AgentEnable { name } => {
            let id = find_agent(&snap, &name)?.id.clone();
            s.state.mutate("agent-enable", |x| {
                let a = x
                    .agents
                    .iter_mut()
                    .find(|a| a.id == id)
                    .ok_or_else(|| anyhow!("agent not found"))?;
                anyhow::ensure!(
                    a.status == AgentStatus::Disabled,
                    "only a disabled, previously activated agent can be enabled"
                );
                a.status = AgentStatus::Active;
                Ok(())
            })?;
            reconcile(s).await?;
            serde_json::json!({"enabled":id})
        }
        AdminRequest::AgentRename { name, new_name } => {
            validate_name(&new_name)?;
            let id = find_agent(&snap, &name)?.id.clone();
            s.state.mutate("agent-rename", |x| {
                if x.agents.iter().any(|a| a.id != id && a.name == new_name) {
                    bail!("agent name already exists")
                };
                let a = x
                    .agents
                    .iter_mut()
                    .find(|a| a.id == id)
                    .ok_or_else(|| anyhow!("agent not found"))?;
                anyhow::ensure!(
                    a.status != AgentStatus::Pending,
                    "pending enrollment cannot be renamed"
                );
                a.name = new_name.clone();
                Ok(())
            })?;
            serde_json::json!({"id":id,"name":new_name})
        }
        AdminRequest::AgentRotate { name } => {
            let id = find_agent(&snap, &name)?.id.clone();
            let rotation = uuid::Uuid::new_v4().to_string();
            s.state.request_rotation(&id, &rotation)?;
            serde_json::json!({"agent":id,"rotation_id":rotation,"status":"requested; agent will rotate on next WireGuard control sync"})
        }
        AdminRequest::ForwardsList => serde_json::Value::Array(
            snap.forwards
                .iter()
                .map(|f| forward_json(&snap, f))
                .collect::<Result<_>>()?,
        ),
        AdminRequest::ForwardAdd(mut f) => {
            f.validate()?;
            let cfg = s.config.read().await.clone();
            anyhow::ensure!(
                cfg.public_ips.contains(&f.listen_ip),
                "listen IP is not in config.public_ips"
            );
            let target = find_agent(&snap, &f.agent_id)?;
            anyhow::ensure!(
                target.status == AgentStatus::Active,
                "forward target agent must be active"
            );
            f.agent_id = target.id.clone();
            s.kernel
                .lock()
                .await
                .check_port(f.listen_ip, f.listen_ports, f.protocol)
                .await?;
            for old in &snap.forwards {
                if old.enabled
                    && old.listen_ip == f.listen_ip
                    && old.protocol == f.protocol
                    && old.listen_ports.overlaps(f.listen_ports)
                {
                    bail!("public port range overlaps forward {}", old.id)
                }
            }
            s.state.mutate("forward-add", |x| {
                f.id = crate::state::lowest_free_id(x.forwards.iter().map(|f| f.id));
                f.generation = x.generation + 1;
                x.forwards.push(f.clone());
                Ok(())
            })?;
            reconcile(s).await?;
            let mut value = forward_json(&s.state.snapshot()?, &f)?;
            if let Some(why) = value["refused"].as_str().map(String::from) {
                value["warning"] = format!(
                    "forward {} was added, but agent {} will refuse it: {why}",
                    f.id, target.name
                )
                .into();
            }
            value
        }
        AdminRequest::ForwardRemove { id } => {
            s.state.mutate("forward-remove", |x| {
                let n = x.forwards.len();
                x.forwards.retain(|f| f.id != id);
                anyhow::ensure!(n != x.forwards.len(), "forward not found");
                x.bans.retain(|b| b.forward_id != id);
                Ok(())
            })?;
            reconcile(s).await?;
            serde_json::json!({"removed":id})
        }
        AdminRequest::ForwardEnable { id, enabled } => {
            let grant = snap
                .forwards
                .iter()
                .find(|f| f.id == id)
                .ok_or_else(|| anyhow!("forward not found"))?;
            if enabled && !grant.enabled {
                s.kernel
                    .lock()
                    .await
                    .check_port(grant.listen_ip, grant.listen_ports, grant.protocol)
                    .await?;
            }
            s.state.mutate("forward-enable", |x| {
                let generation = x.generation + 1;
                let f = x
                    .forwards
                    .iter_mut()
                    .find(|f| f.id == id)
                    .ok_or_else(|| anyhow!("forward not found"))?;
                f.enabled = enabled;
                if enabled {
                    f.generation = generation;
                }
                Ok(())
            })?;
            reconcile(s).await?;
            serde_json::json!({"id":id,"enabled":enabled})
        }
        AdminRequest::Ban {
            agent,
            forward_id,
            ip,
            ttl_seconds,
        } => {
            anyhow::ensure!(
                (1..=86400).contains(&ttl_seconds),
                "ban TTL must be at most one day"
            );
            let a = find_agent(&snap, &agent)?;
            let f = snap
                .forwards
                .iter()
                .find(|f| {
                    f.id == forward_id && f.agent_id == a.id && f.mode == ForwardMode::Translate
                })
                .ok_or_else(|| anyhow!("ban requires this agent's translated forward"))?;
            let _ = f;
            s.state.mutate("ban", |x| {
                let id = x.bans.iter().map(|b| b.id).max().unwrap_or(0) + 1;
                x.bans.push(Ban {
                    id,
                    agent_id: a.id.clone(),
                    forward_id,
                    ip,
                    expires_at: now() + ttl_seconds as i64,
                });
                Ok(())
            })?;
            reconcile(s).await?;
            serde_json::json!({"banned":ip,"forward_id":forward_id})
        }
        AdminRequest::BansList => serde_json::to_value(snap.bans)?,
        AdminRequest::Reload => {
            let generation = reload_config(s).await?;
            serde_json::json!({"generation":generation,"reconciled":true})
        }
        AdminRequest::Logs { lines } => {
            serde_json::json!({"lines":crate::audit::recent(lines.min(1000)),"persistent":false,"source":"process-local ring; Docker/journald retains container or service logs"})
        }
        AdminRequest::PanelStatus => {
            let cfg = s.config.read().await.clone();
            if !cfg.webpanel {
                serde_json::json!({"enabled":false,"hint":"set RIFT_WEBPANEL=true in the server .env and recreate the container"})
            } else {
                let devices: Vec<_> = snap
                    .vpn_peers
                    .iter()
                    .filter(|p| p.panel)
                    .map(|p| serde_json::json!({"name":p.name,"ipv4":p.ipv4,"enabled":p.enabled}))
                    .collect();
                serde_json::json!({"enabled":true,"access":cfg.webpanel_access,"port":cfg.webpanel_port,"urls":crate::webpanel::urls(&cfg),"allow":cfg.webpanel_allow,"devices":devices,"password":if cfg.webpanel_password.is_some() {"RIFT_WEBPANEL_PASSWORD"} else {"generated; show it with `rift panel password`"}})
            }
        }
        AdminRequest::PanelPassword => {
            let password = s.panel_password.clone().ok_or_else(|| anyhow!("the web panel is off; set RIFT_WEBPANEL=true in the server .env and recreate the container"))?;
            serde_json::json!({"password":password})
        }
        AdminRequest::PanelTwoFactorStatus => {
            let cfg = s.config.read().await.clone();
            serde_json::json!({"panel":cfg.webpanel,"enabled":s.two_factor.enabled(),"mode":cfg.webpanel_2fa})
        }
        AdminRequest::PanelTwoFactorSetup => {
            let cfg = s.config.read().await.clone();
            anyhow::ensure!(cfg.webpanel, "the web panel is off; set RIFT_WEBPANEL=true in the server .env and recreate the container");
            let setup = s.two_factor.setup(crate::totp::host(&cfg))?;
            serde_json::json!({"secret":setup.secret,"uri":setup.uri})
        }
        AdminRequest::PanelTwoFactorConfirm { code } => {
            s.two_factor.confirm(&code, now())?;
            serde_json::json!({"enabled":true})
        }
        AdminRequest::PanelTwoFactorReset => {
            s.two_factor.reset()?;
            serde_json::json!({"enabled":false})
        }
        vpn_request => vpn_admin(s, &snap, vpn_request).await?,
    };
    Ok(data)
}

fn vpn_key_path(config: &Config, public_key: &str) -> PathBuf {
    use sha2::{Digest, Sha256};
    let digest = format!("{:x}", Sha256::digest(public_key.as_bytes()));
    config
        .state_dir
        .join("vpn")
        .join(format!("{}.key", &digest[..16]))
}

async fn vpn_admin(s: &Server, snap: &StateSnapshot, r: AdminRequest) -> Result<serde_json::Value> {
    let cfg = s.config.read().await.clone();
    let find_peer = |name: &str| {
        snap.vpn_peers
            .iter()
            .find(|p| p.name == name)
            .ok_or_else(|| anyhow!("VPN peer not found"))
    };
    let data = match r {
        AdminRequest::VpnPeerAdd { name } => {
            validate_name(&name)?;
            cfg.check_vpn_pool()?;
            anyhow::ensure!(
                !snap.vpn_peers.iter().any(|p| p.name == name),
                "VPN peer {name} already exists"
            );
            let (private, public) = net::generate_keypair().await?;
            let key_path = vpn_key_path(&cfg, &public);
            if let Some(dir) = key_path.parent() {
                secure_dir(dir)?;
            }
            atomic_write(&key_path, private.as_bytes(), 0o600)?;
            let added = s.state.mutate("vpn-peer-add", |x| {
                let ipv4 = crate::vpn::allocate(cfg.vpn_pool, &x.vpn_peers)?;
                x.vpn_peers.push(VpnPeer {
                    name: name.clone(),
                    public_key: public.clone(),
                    ipv4,
                    enabled: true,
                    created_at: now(),
                    panel: false,
                });
                Ok(())
            });
            let added = match added {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    let _ = std::fs::remove_file(&key_path);
                    return Err(error);
                }
            };
            reconcile(s).await?;
            let peer = added.vpn_peers.iter().find(|p| p.name == name);
            serde_json::json!({"name":name,"ipv4":peer.map(|p| p.ipv4),"public_key":public,"next":"grant access with `rift vpn allow`, then `rift vpn config export`"})
        }
        AdminRequest::VpnPeerList => {
            let stats = s.kernel.lock().await.stats().await.unwrap_or_default();
            let rows: Vec<_> = snap.vpn_peers.iter().map(|p| {
                let handshake = stats.iter().find(|x| x.public_key == p.public_key).map(|x| x.last_handshake);
                let grants: Vec<_> = snap.vpn_grants.iter().filter(|g| g.peer == p.name).map(|g| {
                    let agent = snap.agents.iter().find(|a| a.id == g.agent_id).map(|a| a.name.clone());
                    serde_json::json!({"agent":agent,"access":g.access,"refused":grant_refusal(snap, g)})
                }).collect();
                serde_json::json!({"name":p.name,"ipv4":p.ipv4,"enabled":p.enabled,"panel":p.panel,"public_key":p.public_key,"last_handshake":handshake,"grants":grants})
            }).collect();
            serde_json::Value::Array(rows)
        }
        AdminRequest::VpnPeerEnable { name, enabled } => {
            find_peer(&name)?;
            s.state.mutate("vpn-peer-enable", |x| {
                x.vpn_peers
                    .iter_mut()
                    .filter(|p| p.name == name)
                    .for_each(|p| p.enabled = enabled);
                Ok(())
            })?;
            reconcile(s).await?;
            serde_json::json!({"name":name,"enabled":enabled})
        }
        AdminRequest::VpnPeerRevoke { name } => {
            let key_path = vpn_key_path(&cfg, &find_peer(&name)?.public_key);
            s.state.mutate("vpn-peer-revoke", |x| {
                x.vpn_peers.retain(|p| p.name != name);
                x.vpn_grants.retain(|g| g.peer != name);
                Ok(())
            })?;
            let _ = std::fs::remove_file(key_path);
            reconcile(s).await?;
            serde_json::json!({"revoked":name})
        }
        AdminRequest::VpnAllow {
            peer,
            agent,
            access,
        } => {
            find_peer(&peer)?;
            crate::vpn::validate_access(&access)?;
            let target = find_agent(snap, &agent)?;
            anyhow::ensure!(target.status == AgentStatus::Active, "agent must be active");
            let agent_id = target.id.clone();
            if let VpnAccess::Subnet { net, .. } = &access {
                anyhow::ensure!(
                    !(net.contains(&cfg.vpn_pool.network())
                        || cfg.vpn_pool.contains(&net.network())
                        || net.contains(&cfg.ipv4_pool.network())
                        || cfg.ipv4_pool.contains(&net.network())),
                    "subnet {net} overlaps a RIFT address pool"
                );
                s.kernel.lock().await.check_vpn_subnet(*net).await?;
            }
            s.state.mutate("vpn-allow", |x| {
                x.vpn_grants.retain(|g| {
                    !(g.peer == peer
                        && g.agent_id == agent_id
                        && crate::vpn::same_target(&g.access, &access))
                });
                x.vpn_grants.push(VpnGrant {
                    peer: peer.clone(),
                    agent_id: agent_id.clone(),
                    access: access.clone(),
                });
                Ok(())
            })?;
            reconcile(s).await?;
            let refused = grant_refusal(
                &s.state.snapshot()?,
                &VpnGrant {
                    peer: peer.clone(),
                    agent_id: agent_id.clone(),
                    access: access.clone(),
                },
            );
            let warning = refused
                .map(|why| format!("the grant was added, but agent {agent} will refuse it: {why}"));
            serde_json::json!({"peer":peer,"agent":agent,"access":access,"warning":warning})
        }
        AdminRequest::VpnDeny {
            peer,
            agent,
            access,
        } => {
            find_peer(&peer)?;
            let agent_id = find_agent(snap, &agent)?.id.clone();
            s.state.mutate("vpn-deny", |x| {
                let before = x.vpn_grants.len();
                x.vpn_grants.retain(|g| {
                    !(g.peer == peer
                        && g.agent_id == agent_id
                        && access
                            .as_ref()
                            .is_none_or(|a| crate::vpn::same_target(&g.access, a)))
                });
                anyhow::ensure!(before != x.vpn_grants.len(), "no matching grant");
                Ok(())
            })?;
            reconcile(s).await?;
            serde_json::json!({"peer":peer,"agent":agent,"denied":true})
        }
        AdminRequest::VpnConfig { name } => {
            let peer = find_peer(&name)?;
            anyhow::ensure!(
                !cfg.public_endpoint.is_empty(),
                "public_endpoint is not configured"
            );
            let private = std::fs::read_to_string(vpn_key_path(&cfg, &peer.public_key))
                .context("read the peer's private key")?;
            let config = crate::vpn::client_config(
                snap,
                peer,
                private.trim(),
                &s.server_public_key,
                &host_port(&cfg.public_endpoint, cfg.wg_port),
                cfg.mtu,
                cfg.webpanel.then_some(cfg.server_ipv4),
            )?;
            serde_json::json!({"name":name,"config":config})
        }
        AdminRequest::PanelAllow { name, allowed } => {
            find_peer(&name)?;
            anyhow::ensure!(
                cfg.webpanel || !allowed,
                "the web panel is off; set RIFT_WEBPANEL=true in the server .env and recreate the container"
            );
            s.state.mutate("panel-allow", |x| {
                x.vpn_peers
                    .iter_mut()
                    .filter(|p| p.name == name)
                    .for_each(|p| p.panel = allowed);
                Ok(())
            })?;
            reconcile(s).await?;
            serde_json::json!({"name":name,"panel":allowed,"urls":if allowed {crate::webpanel::urls(&cfg)} else {Vec::new()}})
        }
        _ => unreachable!("not a VPN request"),
    };
    Ok(data)
}
fn find_agent<'a>(snap: &'a StateSnapshot, name: &str) -> Result<&'a AgentRecord> {
    snap.agents
        .iter()
        .find(|a| a.id == name || a.name == name)
        .ok_or_else(|| anyhow!("agent not found"))
}
fn host_port(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

async fn run_agent_inner(
    config: Config,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    config.validate()?;
    secure_dir(&config.state_dir)?;
    let id_path = config.identity_path();
    let key_path = config.private_key_path();
    let mut identity = if id_path.exists() {
        serde_json::from_slice::<AgentIdentity>(&std::fs::read(&id_path)?)?
    } else {
        let (private, public) = net::generate_keypair().await?;
        atomic_write(&key_path, private.as_bytes(), 0o600)?;
        let id = AgentIdentity {
            id: uuid::Uuid::new_v4().to_string(),
            attempt_id: uuid::Uuid::new_v4().to_string(),
            public_key: public,
            welcome: None,
            active: false,
            applied_generation: 0,
        };
        atomic_json(&id_path, &id)?;
        id
    };
    anyhow::ensure!(
        key_path.exists(),
        "agent WireGuard key is missing from persistent state volume"
    );
    if !identity.active {
        let welcome = if let Some(w) = identity.welcome.clone() {
            w
        } else {
            let w = enrollment::enroll_agent(&config, &mut identity).await?;
            atomic_json(&id_path, &identity)?;
            w
        };
        let k = Kernel::new(config.clone());
        k.apply_agent(&welcome, &AgentPolicy::default(), &key_path)
            .await?;
        match activate_agent(&welcome, &identity).await {
            Ok(generation) => {
                identity.active = true;
                identity.applied_generation = generation;
                atomic_json(&id_path, &identity)?;
            }
            Err(error) => {
                // Recover an expired staging lease using the same durable identity. If
                // activation already committed and its ACK was lost, keep the saved
                // welcome and retry over WireGuard even though TLS rejects the used token.
                if config.enrollment_token.is_some()
                    && enrollment::enroll_agent(&config, &mut identity)
                        .await
                        .is_ok()
                {
                    atomic_json(&id_path, &identity)?;
                }
                return Err(error);
            }
        }
    } else if config.enrollment_token.is_some() {
        tracing::debug!("ignoring enrollment token for an already active identity");
    }
    // Rebuild the local kernel after every process or host restart before opening control.
    let policy_path = config.state_dir.join("agent-policy.json");
    let cached_policy = if policy_path.exists() {
        load_agent_policy(&config)?
    } else {
        identity.applied_generation = 0;
        AgentPolicy::default()
    };
    let welcome = identity
        .welcome
        .as_ref()
        .ok_or_else(|| anyhow!("agent identity has no saved server welcome"))?;
    let kernel = Kernel::new(config.clone());
    kernel
        .apply_agent(welcome, &cached_policy, &key_path)
        .await?;
    let poll = Duration::from_secs(config.poll_seconds);
    let mut failures = 0u32;
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let welcome = identity
            .welcome
            .clone()
            .ok_or_else(|| anyhow!("active identity lacks server welcome"))?;
        // Repair routes and refresh an unreachable DNS endpoint BEFORE trying control.
        // Control cannot repair its own transport when its connection is already down.
        let current_policy = if policy_path.exists() {
            load_agent_policy(&config)?
        } else {
            AgentPolicy::default()
        };
        let result = timeout(Duration::from_secs(30), async {
            kernel
                .apply_agent(&welcome, &current_policy, &key_path)
                .await?;
            agent_sync(&config, &mut identity, &welcome, &key_path).await
        })
        .await
        .unwrap_or_else(|_| Err(anyhow!("agent reconciliation timed out")));
        match result {
            Ok(()) => failures = 0,
            Err(e) => {
                failures = failures.saturating_add(1);
                tracing::warn!("control sync failed; retrying: {e:#}");
            }
        }
        let retry = if failures == 0 {
            poll
        } else {
            let base = (2_u64.saturating_pow(failures.min(5))).min(30);
            Duration::from_secs(base + rand::random::<u64>() % (base / 2 + 1))
        };
        tokio::select! {
            _ = tokio::time::sleep(retry) => {},
            _ = shutdown.changed() => return Ok(()),
        }
    }
}
pub async fn run_agent(config: Config) -> Result<()> {
    config.validate()?;
    secure_dir(&config.state_dir)?;
    #[cfg(unix)]
    let admin_task = {
        let listener = bind_admin(config.socket_path()).await?;
        let cfg = config.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_agent_admin(listener, cfg).await {
                tracing::error!("agent admin socket stopped: {error:#}");
            }
        })
    };
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let work = async {
        let mut attempt = 0u32;
        loop {
            if *shutdown_rx.borrow() {
                return Ok(());
            }
            match run_agent_inner(config.clone(), &mut shutdown_rx).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    attempt = attempt.saturating_add(1);
                    let base = 1u64.checked_shl(attempt.min(6)).unwrap_or(60).min(60);
                    let jitter = rand::random::<u64>() % (base / 2 + 1);
                    tracing::warn!(
                        attempt,
                        "agent startup/control failed; retrying with backoff: {e:#}"
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(base + jitter)) => {},
                        _ = shutdown_rx.changed() => return Ok(()),
                    }
                }
            }
        }
    };
    tokio::pin!(work);
    let result: Result<()> = tokio::select! {
        result = &mut work => result,
        _ = shutdown_signal() => {
            let _ = shutdown_tx.send(true);
            work.await
        }
    };
    #[cfg(unix)]
    admin_task.abort();
    result?;
    Kernel::new(config.clone())
        .cleanup()
        .await
        .context("clean up agent networking")
}

#[cfg(unix)]
async fn serve_agent_admin(listener: tokio::net::UnixListener, config: Config) -> Result<()> {
    let permits = Arc::new(Semaphore::new(16));
    loop {
        let (mut stream, _) = listener.accept().await?;
        if !admin_peer_allowed(&stream) {
            continue;
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let config = config.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = timeout(Duration::from_secs(15), async {
                let request: AdminRequest = protocol::receive(&mut stream).await?;
                let response = match agent_admin_request(&config, request).await {
                    Ok(data) => AdminResponse::success(data),
                    Err(error) => AdminResponse::error(sanitize_error(&error.to_string())),
                };
                protocol::send_admin(&mut stream, &response).await
            })
            .await;
        });
    }
}

#[cfg(unix)]
async fn agent_admin_request(config: &Config, request: AdminRequest) -> Result<serde_json::Value> {
    if let AdminRequest::Logs { lines } = request {
        return Ok(serde_json::json!({"lines":crate::audit::recent(lines),"persistent":false}));
    }
    let identity: AgentIdentity = serde_json::from_slice(
        &std::fs::read(config.identity_path()).context("agent is still initializing")?,
    )?;
    let welcome = identity
        .welcome
        .as_ref()
        .ok_or_else(|| anyhow!("agent has not enrolled yet"))?;
    match request {
        AdminRequest::Status => {
            let k = Kernel::new(config.clone());
            Ok(
                serde_json::json!({"identity":identity,"peers":k.stats().await?,"doctor":k.doctor().await?}),
            )
        }
        AdminRequest::ForwardsList => {
            let policy: AgentPolicy = serde_json::from_slice(&std::fs::read(
                config.state_dir.join("agent-policy.json"),
            )?)?;
            Ok(serde_json::to_value(policy.forwards)?)
        }
        AdminRequest::Ban {
            agent,
            forward_id,
            ip,
            ttl_seconds,
        } => {
            anyhow::ensure!(
                identity.active
                    && (agent == identity.id
                        || agent == welcome.name
                        || config.agent_name.as_deref() == Some(&agent)),
                "ban must name this active agent"
            );
            let mut control = connect_control(welcome).await?;
            protocol::send(
                &mut control,
                &ControlRequest::Ban {
                    version: VERSION,
                    agent_id: identity.id,
                    forward_id,
                    ip,
                    ttl_seconds,
                },
            )
            .await?;
            match timeout(Duration::from_secs(10), protocol::receive(&mut control)).await?? {
                ControlResponse::Ok => Ok(
                    serde_json::json!({"banned":ip,"forward_id":forward_id,"ttl_seconds":ttl_seconds}),
                ),
                ControlResponse::Error { message } => bail!("ban refused: {message}"),
                _ => bail!("unexpected ban response"),
            }
        }
        _ => bail!("this operation requires the VPS local admin socket"),
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _=tokio::signal::ctrl_c()=>{}, _=term.recv()=>{} }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

async fn activate_agent(w: &Welcome, identity: &AgentIdentity) -> Result<u64> {
    timeout(Duration::from_secs(12), async {
        let mut stream = connect_control(w).await?;
        protocol::send(
            &mut stream,
            &ControlRequest::Activate {
                version: VERSION,
                agent_id: identity.id.clone(),
                attempt_id: identity.attempt_id.clone(),
            },
        )
        .await?;
        match protocol::receive(&mut stream).await? {
            ControlResponse::Active { generation } => Ok(generation),
            ControlResponse::Error { message } => bail!("activation failed: {message}"),
            _ => bail!("unexpected activation response"),
        }
    })
    .await?
}

async fn connect_control(w: &Welcome) -> Result<TcpStream> {
    let mut last = None;
    for ip in [IpAddr::V4(w.server_ipv4), IpAddr::V6(w.server_ipv6)] {
        match timeout(
            Duration::from_secs(5),
            TcpStream::connect(SocketAddr::new(ip, w.control_port)),
        )
        .await
        {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = Some(e.into()),
            Err(e) => last = Some(e.into()),
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("no WireGuard control address")))
}
/// Refusal text for the next sync, so the server shows it as the agent's last error.
static AGENT_REFUSALS: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
/// Remembers the refusals for the next sync and logs them only when they change.
fn note_refusals(refusals: &[String]) {
    let text = (!refusals.is_empty()).then(|| {
        format!(
            "agent refused {} server request(s): {}",
            refusals.len(),
            refusals.join("; ")
        )
    });
    if let Ok(mut current) = AGENT_REFUSALS.lock() {
        if *current != text {
            for r in refusals {
                tracing::warn!("{r}");
            }
            if text.is_none() {
                tracing::info!("the server no longer asks for anything the agent refuses");
            }
            *current = text;
        }
    }
}
/// The cached policy, narrowed again by the current allowlists so a tightened `.env`
/// takes effect on restart without waiting for the server.
fn load_agent_policy(config: &Config) -> Result<AgentPolicy> {
    let cached: AgentPolicy =
        serde_json::from_slice(&std::fs::read(config.state_dir.join("agent-policy.json"))?)?;
    Ok(agent_policy::restrict(&cached, &config.agent_limits()).0)
}
async fn agent_sync(
    config: &Config,
    identity: &mut AgentIdentity,
    w: &Welcome,
    key_path: &Path,
) -> Result<()> {
    let journal = config.state_dir.join("rotation.json");
    if journal.exists() {
        return drive_rotation(config, identity, w, key_path).await;
    }
    let mut stream = connect_control(w).await?;
    protocol::send(
        &mut stream,
        &ControlRequest::Sync {
            version: VERSION,
            agent_id: identity.id.clone(),
            applied_generation: identity.applied_generation,
            error: AGENT_REFUSALS.lock().ok().and_then(|r| r.clone()),
            limits: config.agent_limits(),
        },
    )
    .await?;
    match protocol::receive::<ControlResponse, _>(&mut stream).await? {
        ControlResponse::Policy(policy) => {
            let (policy, refusals) = agent_policy::restrict(&policy, &config.agent_limits());
            note_refusals(&refusals);
            let k = Kernel::new(config.clone());
            k.apply_agent(w, &policy, key_path).await?;
            atomic_json(&config.state_dir.join("agent-policy.json"), &policy)?;
            identity.applied_generation = policy.generation;
            atomic_json(&config.identity_path(), identity)?;
            Ok(())
        }
        ControlResponse::RotateRequested { rotation_id } => {
            rotate_agent(config, identity, w, key_path, &rotation_id).await
        }
        ControlResponse::Error { message } => bail!("control rejected: {message}"),
        _ => bail!("unexpected control response"),
    }
}
async fn rotate_agent(
    config: &Config,
    identity: &mut AgentIdentity,
    w: &Welcome,
    key_path: &Path,
    rotation_id: &str,
) -> Result<()> {
    let pending = key_path.with_extension("rotation");
    let old = key_path.with_extension("rotation-old");
    let state = config.state_dir.join("rotation.json");
    if !state.exists() {
        let old_bytes = std::fs::read(key_path)?;
        atomic_write(&old, &old_bytes, 0o600)?;
        let (private, public) = net::generate_keypair().await?;
        atomic_write(&pending, private.as_bytes(), 0o600)?;
        atomic_json(
            &state,
            &serde_json::json!({"rotation_id":rotation_id,"public_key":public,"old_public_key":identity.public_key}),
        )?;
    }
    drive_rotation(config, identity, w, key_path).await
}

async fn drive_rotation(
    config: &Config,
    identity: &mut AgentIdentity,
    w: &Welcome,
    key_path: &Path,
) -> Result<()> {
    let state = config.state_dir.join("rotation.json");
    let pending = key_path.with_extension("rotation");
    let old = key_path.with_extension("rotation-old");
    let journal: serde_json::Value = serde_json::from_slice(&std::fs::read(&state)?)?;
    let rotation_id = journal["rotation_id"]
        .as_str()
        .ok_or_else(|| anyhow!("bad local rotation journal"))?
        .to_string();
    let public = journal["public_key"]
        .as_str()
        .ok_or_else(|| anyhow!("bad local rotation key"))?
        .to_string();
    let old_public = journal["old_public_key"]
        .as_str()
        .ok_or_else(|| anyhow!("bad local old rotation key"))?
        .to_string();
    let pending_private = std::fs::read(&pending)?;
    let old_private = std::fs::read(&old)?;
    let policy_path = config.state_dir.join("agent-policy.json");
    let policy = if policy_path.exists() {
        load_agent_policy(config)?
    } else {
        AgentPolicy::default()
    };
    // First try the new key: this is the recovery path when the server committed but its ACK was lost.
    atomic_write(key_path, &pending_private, 0o600)?;
    let k = Kernel::new(config.clone());
    let new_ready = k.apply_agent(w, &policy, key_path).await.is_ok();
    if new_ready {
        if let Ok(mut stream) = connect_control(w).await {
            if send_rotate(&mut stream, &identity.id, &rotation_id, &public)
                .await
                .is_ok()
            {
                identity.public_key = public.clone();
                if let Ok(ControlResponse::RotateCommitted { .. }) =
                    timeout(Duration::from_secs(5), protocol::receive(&mut stream)).await?
                {
                    identity.applied_generation = policy.generation;
                    atomic_json(&config.identity_path(), identity)?;
                    let k = Kernel::new(config.clone());
                    k.apply_agent(w, &policy, key_path).await?;
                    cleanup_rotation(&state, &pending, &old);
                    return Ok(());
                }
            }
        }
    }
    // If the server has not committed yet, the old peer still works and can safely retry the same transaction.
    atomic_write(key_path, &old_private, 0o600)?;
    identity.public_key = old_public;
    let k = Kernel::new(config.clone());
    k.apply_agent(w, &policy, key_path).await?;
    let mut stream = connect_control(w).await?;
    send_rotate(&mut stream, &identity.id, &rotation_id, &public).await?;
    match timeout(
        Duration::from_secs(8),
        protocol::receive::<ControlResponse, _>(&mut stream),
    )
    .await??
    {
        ControlResponse::RotateCommitted { .. } => {
            identity.public_key = public;
            identity.applied_generation = policy.generation;
            atomic_json(&config.identity_path(), identity)?;
            atomic_write(key_path, &pending_private, 0o600)?;
            let k = Kernel::new(config.clone());
            k.apply_agent(w, &policy, key_path).await?;
            cleanup_rotation(&state, &pending, &old);
            Ok(())
        }
        ControlResponse::Error { message } => bail!("rotation rejected: {message}"),
        _ => bail!("unexpected rotation response"),
    }
}
async fn send_rotate(stream: &mut TcpStream, id: &str, rotation: &str, public: &str) -> Result<()> {
    protocol::send(
        stream,
        &ControlRequest::RotateKey {
            version: VERSION,
            agent_id: id.into(),
            rotation_id: rotation.into(),
            public_key: public.into(),
        },
    )
    .await
}
fn cleanup_rotation(state: &Path, pending: &Path, old: &Path) {
    let _ = std::fs::remove_file(state);
    let _ = std::fs::remove_file(pending);
    let _ = std::fs::remove_file(old);
}

fn secure_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
pub(crate) fn atomic_write(path: &Path, data: &[u8], _mode: u32) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("secret path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".rift-tmp-{}", uuid::Uuid::new_v4()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(_mode);
    }
    let mut file = opts.open(&tmp)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)?;
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}
fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    atomic_write(path, &serde_json::to_vec(value)?, 0o600)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(name: &str, enabled: bool) -> VpnPeer {
        VpnPeer {
            name: name.into(),
            public_key: format!("key-{name}"),
            ipv4: "10.14.0.2".parse().unwrap(),
            enabled,
            created_at: 0,
            panel: false,
        }
    }
    fn grant(name: &str, access: VpnAccess) -> VpnGrant {
        VpnGrant {
            peer: name.into(),
            agent_id: "home".into(),
            access,
        }
    }

    #[test]
    fn forwards_and_grants_outside_the_agent_limits_are_refused_and_left_out() {
        let forward = |id: u64, port: &str| Forward {
            id,
            agent_id: "home".into(),
            listen_ip: "203.0.113.10".parse().unwrap(),
            listen_ports: port.parse().unwrap(),
            target_ports: port.parse().unwrap(),
            protocol: Protocol::Tcp,
            mode: ForwardMode::Transparent,
            ingress: Ingress::Public,
            target_family: Family::V4,
            enabled: true,
            generation: 2,
        };
        let mut agent = AgentRecord {
            id: "home".into(),
            name: "core".into(),
            public_key: "k".into(),
            tunnel_ipv4: "10.13.0.2".parse().unwrap(),
            tunnel_ipv6: "fd88:5249:4654::2".parse().unwrap(),
            status: AgentStatus::Active,
            attempt_id: "a".into(),
            generation: 2,
            applied_generation: 2,
            last_error: None,
            created_at: 0,
            pending_deadline: None,
            limits: None,
        };
        let snap = |agent: &AgentRecord| StateSnapshot {
            generation: 2,
            agents: vec![agent.clone()],
            forwards: vec![forward(1, "8081"), forward(2, "3001")],
            vpn_peers: vec![peer("phone", true)],
            vpn_grants: vec![
                grant("phone", VpnAccess::Server),
                grant(
                    "phone",
                    VpnAccess::Port {
                        protocol: Protocol::Tcp,
                        ports: "3001".parse().unwrap(),
                    },
                ),
            ],
            ..Default::default()
        };
        // Before the first sync nothing is known, so nothing is refused.
        let unknown = snap(&agent);
        assert_eq!(forward_state(&unknown, &unknown.forwards[0]).0, "enabled");
        assert_eq!(without_refused(unknown.clone()).forwards.len(), 2);

        agent.limits = Some(AgentLimits {
            ports: crate::config::parse_port_allow("3001,1337,8090").unwrap(),
            subnets: vec![],
        });
        let limited = snap(&agent);
        let (state, why) = forward_state(&limited, &limited.forwards[0]);
        assert_eq!(state, "refused");
        assert!(why.unwrap().contains("add 8081/tcp"));
        assert_eq!(forward_state(&limited, &limited.forwards[1]).0, "enabled");
        let applied = without_refused(limited.clone());
        assert_eq!(
            applied.forwards.iter().map(|f| f.id).collect::<Vec<_>>(),
            [2]
        );
        assert_eq!(
            applied.vpn_grants.len(),
            1,
            "the whole-host grant is left out"
        );
        let policy = policy_for(&limited, "home", "10.14.0.0/24".parse().unwrap());
        assert_eq!(policy.forwards.len(), 1);
        assert_eq!(
            policy.generation, 2,
            "the agent can acknowledge everything it got"
        );

        let mut stale = limited.clone();
        stale.forwards[1].generation = 3;
        assert_eq!(forward_state(&stale, &stale.forwards[1]).0, "pending");
    }

    #[test]
    fn rollback_never_restores_revoked_peers_or_withdrawn_grants() {
        let previous = StateSnapshot {
            vpn_peers: vec![
                peer("kept", true),
                peer("revoked", true),
                peer("disabled", true),
            ],
            vpn_grants: vec![
                grant("kept", VpnAccess::Server),
                grant("kept", VpnAccess::Full),
                grant("revoked", VpnAccess::Server),
                grant("disabled", VpnAccess::Server),
            ],
            ..Default::default()
        };
        let desired = StateSnapshot {
            vpn_peers: vec![
                peer("kept", true),
                peer("disabled", false),
                peer("new", true),
            ],
            vpn_grants: vec![
                grant("kept", VpnAccess::Server),
                grant("disabled", VpnAccess::Server),
                grant("new", VpnAccess::Server),
            ],
            ..Default::default()
        };
        let rolled = safe_rollback(previous, &desired);
        let names: Vec<_> = rolled.vpn_peers.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["kept"]);
        assert_eq!(rolled.vpn_grants, [grant("kept", VpnAccess::Server)]);
    }

    #[test]
    fn private_key_files_are_named_by_public_key_not_by_device_name() {
        let config = Config::default();
        let path = vpn_key_path(&config, "PUBLIC+KEY/=");
        assert!(path.starts_with(config.state_dir.join("vpn")));
        let file = path.file_name().unwrap().to_str().unwrap();
        assert!(
            file.ends_with(".key") && file.chars().all(|c| c.is_ascii_alphanumeric() || c == '.')
        );
    }
}
