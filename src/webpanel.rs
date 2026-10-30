//! Optional web panel on the VPS. Off unless `RIFT_WEBPANEL=true`.
//!
//! Access is layered. `private` listens only on loopback and the VPS's tunnel address, so it
//! is reached on the VPS itself, through an SSH tunnel, or from a VPN device granted with
//! `rift panel allow`. `public` listens on every address. In both modes the source address
//! is checked again here, the RIFT table only lets granted tunnel sources reach the port,
//! and every request past the login needs the panel password.
//!
//! The HTTP server is deliberately small: one request per connection, bounded headers and
//! bodies, no keep-alive. Panel actions go through the same admin requests as the CLI.
//!
//! Login needs the password and, once two-factor login is on, a current one-time code
//! (`crate::totp`). `RIFT_WEBPANEL_2FA=required` refuses every login until a secret exists.
//! Ten failed logins in a row lock all logins for 15 minutes.
//!
//! Every logged-in session may read. Changes, and anything that reveals a secret (an
//! invitation token, a device's private key), additionally need a trusted connection: loopback
//! without proxy headers or a panel VPN device, and `RIFT_WEBPANEL_CONTROL=private`.

use crate::{
    config::{Config, PanelAccess, PanelControl, PanelTwoFactor},
    model::*,
    protocol::AdminRequest,
    totp::TwoFactor,
};
use anyhow::{bail, ensure, Context, Result};
use ipnet::{IpNet, Ipv4Net};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    future::Future,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::Semaphore,
    time::timeout,
};

const INDEX: &str = include_str!("webpanel/index.html");
const APP_JS: &str = include_str!("webpanel/app.js");
const APP_CSS: &str = include_str!("webpanel/app.css");

const MAX_HEAD: usize = 8 * 1024;
const MAX_BODY: usize = 16 * 1024;
const SESSION_SECONDS: i64 = 12 * 3600;
const MAX_SESSIONS: usize = 32;
const COOKIE: &str = "rift_panel";
/// Panel requests that change state must carry this header. A cross-site page cannot set
/// it without a CORS preflight, which the panel never answers.
const CSRF_HEADER: &str = "x-rift-panel";

/// What the panel needs from the running server.
pub trait Backend: Send + Sync + 'static {
    fn admin(&self, request: AdminRequest) -> impl Future<Output = Result<Value>> + Send;
    /// Tunnel addresses of enabled VPN devices that may open the panel.
    fn panel_peers(&self) -> Vec<IpAddr>;
}

/// The password from `RIFT_WEBPANEL_PASSWORD`, or one generated once and kept in the state
/// directory (mode 0600). `rift panel password` shows it.
pub fn password(config: &Config) -> Result<String> {
    if let Some(password) = &config.webpanel_password {
        return Ok(password.clone());
    }
    let path = password_path(config);
    if let Ok(text) = std::fs::read_to_string(&path) {
        let text = text.trim();
        if !text.is_empty() {
            return Ok(text.into());
        }
    }
    use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
    let generated: String = OsRng
        .sample_iter(&Alphanumeric)
        .take(24)
        .map(char::from)
        .collect();
    crate::daemon::atomic_write(&path, generated.as_bytes(), 0o600)
        .context("store the generated web panel password")?;
    Ok(generated)
}

pub fn password_path(config: &Config) -> std::path::PathBuf {
    config.state_dir.join("webpanel.password")
}

/// Addresses the panel can be opened at, with how each one is reached.
pub fn urls(config: &Config) -> Vec<Value> {
    let port = config.webpanel_port;
    let mut out = vec![
        json!({"url": format!("http://127.0.0.1:{port}"), "via": "on the VPS itself or through an SSH tunnel"}),
        json!({"url": format!("http://{}:{port}", config.server_ipv4), "via": "from a VPN device granted with rift panel allow"}),
    ];
    if config.webpanel_access == PanelAccess::Public {
        let hosts: Vec<String> = if config.public_endpoint.is_empty() {
            config.public_ips.iter().map(|ip| host(*ip)).collect()
        } else {
            vec![config.public_endpoint.clone()]
        };
        for name in hosts {
            out.push(json!({"url": format!("http://{name}:{port}"), "via": "public, from any allowed address"}));
        }
    }
    out
}

fn host(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => format!("[{v6}]"),
        IpAddr::V4(v4) => v4.to_string(),
    }
}

/// Whether a connection from `source` may talk to the panel at all.
pub fn source_allowed(config: &Config, panel_peers: &[IpAddr], source: IpAddr) -> bool {
    let source = source.to_canonical();
    source.is_loopback()
        || panel_peers.contains(&source)
        || config
            .webpanel_allow
            .iter()
            .any(|net| net.contains(&source))
        || (config.webpanel_access == PanelAccess::Public && config.webpanel_allow.is_empty())
}

/// RIFT table input rules that let granted tunnel sources reach the panel port. They must
/// precede the rule that drops VPN peers on their way to the VPS, and the final tunnel drop.
pub fn input_rules(config: &Config, snap: &StateSnapshot) -> String {
    if !config.webpanel {
        return String::new();
    }
    let (interface, port) = (&config.interface, config.webpanel_port);
    let mut v4: BTreeSet<Ipv4Net> = snap
        .vpn_peers
        .iter()
        .filter(|p| p.enabled && p.panel)
        .map(|p| Ipv4Net::from(p.ipv4))
        .collect();
    let mut v6 = BTreeSet::new();
    for net in &config.webpanel_allow {
        match net {
            IpNet::V4(net) => {
                v4.insert(*net);
            }
            IpNet::V6(net) => {
                v6.insert(*net);
            }
        }
    }
    let mut out = String::new();
    for net in v4 {
        out.push_str(&format!(
            "add rule inet rift input iifname \"{interface}\" ip saddr {net} ip daddr {} tcp dport {port} accept\n",
            config.server_ipv4
        ));
    }
    // Only a public panel listens on the tunnel's IPv6 address.
    if config.webpanel_access == PanelAccess::Public {
        for net in v6 {
            out.push_str(&format!(
                "add rule inet rift input iifname \"{interface}\" ip6 saddr {net} ip6 daddr {} tcp dport {port} accept\n",
                config.server_ipv6
            ));
        }
    }
    out
}

/// Opens the panel's listeners. Call after the tunnel address is configured.
pub async fn bind(config: &Config) -> Result<Vec<TcpListener>> {
    let port = config.webpanel_port;
    let mut out = Vec::new();
    match config.webpanel_access {
        PanelAccess::Private => {
            for ip in [IpAddr::from([127, 0, 0, 1]), config.server_ipv4.into()] {
                let address = SocketAddr::new(ip, port);
                out.push(
                    TcpListener::bind(address)
                        .await
                        .with_context(|| format!("bind web panel to {address}"))?,
                );
            }
            // Browsers try ::1 first for `localhost`; a host without IPv6 simply lacks it.
            if let Ok(listener) = TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await {
                out.push(listener);
            }
        }
        PanelAccess::Public => {
            let listener = match dual_stack(port) {
                Ok(listener) => listener,
                Err(_) => TcpListener::bind(("0.0.0.0", port))
                    .await
                    .with_context(|| format!("bind web panel to port {port}"))?,
            };
            out.push(listener);
        }
    }
    Ok(out)
}

fn dual_stack(port: u16) -> Result<TcpListener> {
    use socket2::{Domain, Socket, Type};
    let socket = Socket::new(Domain::IPV6, Type::STREAM, None)?;
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port).into())?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    Ok(TcpListener::from_std(socket.into())?)
}

pub struct Panel<B> {
    backend: B,
    config: Config,
    password: [u8; 32],
    sessions: std::sync::Mutex<HashMap<String, i64>>,
    /// Serialises logins, so a wrong password costs every guesser the same second.
    login: tokio::sync::Mutex<()>,
    two_factor: Arc<TwoFactor>,
    /// The `two_factor` epoch the sessions belong to; a reset or disable ends them all.
    epoch: std::sync::atomic::AtomicU64,
    /// How long a failed login waits before it is answered.
    penalty: Duration,
}

impl<B: Backend> Panel<B> {
    pub fn new(backend: B, config: Config, password: &str, two_factor: Arc<TwoFactor>) -> Self {
        Self {
            backend,
            config,
            password: Sha256::digest(password.as_bytes()).into(),
            sessions: Default::default(),
            login: Default::default(),
            epoch: two_factor.epoch().into(),
            two_factor,
            penalty: Duration::from_secs(1),
        }
    }

    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        let permits = Arc::new(Semaphore::new(64));
        let mut connections = tokio::task::JoinSet::new();
        loop {
            while connections.try_join_next().is_some() {}
            let (stream, remote) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("web panel accept: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                continue;
            };
            let panel = self.clone();
            connections.spawn(async move {
                let _permit = permit;
                let mut stream = stream;
                let _ = timeout(
                    Duration::from_secs(30),
                    panel.connection(&mut stream, remote.ip()),
                )
                .await;
            });
        }
    }

    async fn connection<S: AsyncRead + AsyncWrite + Unpin>(&self, stream: &mut S, source: IpAddr) {
        let response = match timeout(Duration::from_secs(10), read_request(stream)).await {
            Ok(Ok(request)) => {
                if source_allowed(&self.config, &self.backend.panel_peers(), source) {
                    self.handle(request, source).await
                } else {
                    tracing::warn!("web panel refused {source}: address not allowed");
                    Response::text(403, "This address may not open the RIFT panel.\n")
                }
            }
            Ok(Err(e)) => Response::text(400, &format!("{e}\n")),
            Err(_) => return,
        };
        let _ = stream.write_all(&response.to_bytes()).await;
        let _ = stream.shutdown().await;
    }

    async fn handle(&self, request: Request, source: IpAddr) -> Response {
        let secure = request.header("x-forwarded-proto") == Some("https");
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/" | "/index.html") => Response::asset("text/html", INDEX),
            ("GET", "/app.js") => Response::asset("text/javascript", APP_JS),
            ("GET", "/app.css") => Response::asset("text/css", APP_CSS),
            ("GET", "/api/session") => Response::json(
                200,
                &json!({"authenticated": self.session(&request), "can_write": self.trusted(&request, source), "two_factor": self.two_factor.enabled()}),
            ),
            ("POST", path) if request.header(CSRF_HEADER) != Some("1") => {
                tracing::warn!("web panel refused {path} from {source}: missing {CSRF_HEADER}");
                Response::error(403, "missing request header")
            }
            ("POST", "/api/login") => self.login(&request, source, secure).await,
            ("POST", "/api/logout") => {
                if let Some(token) = request.cookie(COOKIE) {
                    self.lock_sessions().remove(token);
                }
                let mut response = Response::json(200, &json!({"authenticated": false}));
                response.cookie = Some(cookie("", 0, secure));
                response
            }
            (_, "/api/overview" | "/api/action") if !self.session(&request) => {
                Response::error(401, "log in first")
            }
            ("GET", "/api/overview") => match self.overview(self.trusted(&request, source)).await {
                Ok(data) => Response::json(200, &data),
                Err(e) => Response::error(500, &e.to_string()),
            },
            ("POST", "/api/action") => {
                let action: Action = match serde_json::from_slice(&request.body) {
                    Ok(action) => action,
                    Err(e) => {
                        return Response::error(400, &format!("unknown or malformed action: {e}"))
                    }
                };
                if action.writes() && !self.trusted(&request, source) {
                    tracing::warn!(
                        "web panel refused a change from {source}: read-only connection"
                    );
                    return Response::error(403, READ_ONLY);
                }
                if action.writes() {
                    tracing::info!("web panel action from {source}: {action:?}");
                }
                match action.run(self).await {
                    Ok(data) => Response::json(200, &data),
                    Err(e) => Response::error(400, &format!("{e:#}")),
                }
            }
            (
                _,
                "/" | "/index.html" | "/app.js" | "/app.css" | "/api/session" | "/api/login"
                | "/api/logout" | "/api/overview" | "/api/action",
            ) => Response::error(405, "method not allowed"),
            _ => Response::error(404, "not found"),
        }
    }

    /// Changes need an encrypted, local path: loopback without proxy headers (the VPS itself
    /// or an SSH tunnel) or a VPN device granted the panel. A reverse proxy on the same host
    /// also connects from loopback, so any proxy header makes the request read-only.
    fn trusted(&self, request: &Request, source: IpAddr) -> bool {
        let source = source.to_canonical();
        self.config.webpanel_control == PanelControl::Private
            && !PROXY_HEADERS.iter().any(|h| request.header(h).is_some())
            && (source.is_loopback() || self.backend.panel_peers().contains(&source))
    }

    fn lock_sessions(&self) -> std::sync::MutexGuard<'_, HashMap<String, i64>> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let epoch = self.two_factor.epoch();
        if self.epoch.swap(epoch, std::sync::atomic::Ordering::SeqCst) != epoch {
            sessions.clear();
        }
        sessions
    }

    fn session(&self, request: &Request) -> bool {
        let Some(token) = request.cookie(COOKIE) else {
            return false;
        };
        let mut sessions = self.lock_sessions();
        sessions.retain(|_, expires| *expires > now());
        sessions.contains_key(token)
    }

    async fn login(&self, request: &Request, source: IpAddr, secure: bool) -> Response {
        #[derive(Deserialize)]
        struct Login {
            password: String,
            #[serde(default)]
            code: String,
        }
        let Ok(login) = serde_json::from_slice::<Login>(&request.body) else {
            return Response::error(400, "expected {\"password\": ..., \"code\": ...}");
        };
        let _serial = self.login.lock().await;
        if self.two_factor.locked(now()) {
            return Response::error(429, "too many failed logins; try again later");
        }
        if self.config.webpanel_2fa == PanelTwoFactor::Required && !self.two_factor.enabled() {
            return Response::error(
                403,
                "two-factor login is required; set it up with `rift panel 2fa setup`",
            );
        }
        let given: [u8; 32] = Sha256::digest(login.password.as_bytes()).into();
        // Compare digests without an early exit.
        let mismatch = given
            .iter()
            .zip(self.password.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        // The code is only checked, and its step only used up, after the right password.
        let code_ok = !self.two_factor.enabled()
            || (mismatch == 0 && self.two_factor.verify_login(&login.code, now()));
        if mismatch != 0 || !code_ok {
            tracing::warn!("web panel login failed from {source}");
            if self.two_factor.failed(now()) {
                tracing::warn!(
                    "web panel: {} failed logins in a row, all logins are locked for {} minutes",
                    crate::totp::MAX_FAILURES,
                    crate::totp::LOCKOUT_SECONDS / 60
                );
            }
            tokio::time::sleep(self.penalty).await;
            return Response::error(401, "wrong password or code");
        }
        self.two_factor.succeeded();
        let token = {
            use rand::{rngs::OsRng, RngCore};
            let mut bytes = [0u8; 32];
            OsRng.fill_bytes(&mut bytes);
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        {
            let mut sessions = self.lock_sessions();
            sessions.retain(|_, expires| *expires > now());
            while sessions.len() >= MAX_SESSIONS {
                let oldest = sessions
                    .iter()
                    .min_by_key(|(_, expires)| **expires)
                    .map(|(token, _)| token.clone());
                match oldest {
                    Some(token) => sessions.remove(&token),
                    None => break,
                };
            }
            sessions.insert(token.clone(), now() + SESSION_SECONDS);
        }
        tracing::info!("web panel login from {source}");
        let mut response = Response::json(200, &json!({"authenticated": true}));
        response.cookie = Some(cookie(&token, SESSION_SECONDS, secure));
        response
    }

    async fn overview(&self, can_write: bool) -> Result<Value> {
        let status = self.backend.admin(AdminRequest::Status).await?;
        let peers = self.backend.admin(AdminRequest::VpnPeerList).await?;
        let panel = self.backend.admin(AdminRequest::PanelStatus).await?;
        let mut overview = compose_overview(&status, &peers, &panel);
        overview["can_write"] = can_write.into();
        overview["public_ips"] = json!(self.config.public_ips);
        overview["two_factor"] = json!({
            "enabled": self.two_factor.enabled(),
            "required": self.config.webpanel_2fa == PanelTwoFactor::Required,
        });
        Ok(overview)
    }

    async fn admin(&self, request: AdminRequest) -> Result<Value> {
        self.backend.admin(request).await
    }
}

const READ_ONLY: &str =
    "read-only connection: changes need the VPS itself, an SSH tunnel or a panel VPN device";
const PROXY_HEADERS: [&str; 5] = [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
];

fn default_lines() -> usize {
    200
}
fn seconds(text: &str) -> Result<u64> {
    let seconds = humantime::parse_duration(text.trim())
        .with_context(|| format!("invalid duration {text:?}; use e.g. 15m or 1h"))?
        .as_secs();
    ensure!(seconds > 0, "duration must be positive");
    Ok(seconds)
}
fn words(text: &str) -> Vec<String> {
    text.split(|c: char| c.is_whitespace() || c == ',')
        .filter(|w| !w.is_empty())
        .map(String::from)
        .collect()
}

/// What the panel can do: the CLI's commands except printing the panel password. Reads are
/// open to every logged-in session; everything else needs a trusted connection.
#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    Logs {
        #[serde(default = "default_lines")]
        lines: usize,
    },
    Diagnostics,
    Reload,
    AgentInvite {
        name: String,
        ttl: String,
    },
    AgentCancelInvite {
        name: String,
    },
    AgentRemove {
        name: String,
    },
    AgentEnable {
        name: String,
        enabled: bool,
    },
    AgentRename {
        name: String,
        new_name: String,
    },
    AgentRotate {
        name: String,
    },
    /// `specs` uses the CLI's short form: `LISTEN[:TARGET]/tcp|udp|both[/v4|v6|all]`;
    /// `on` applies to specs that name no address.
    ForwardAdd {
        agent: String,
        specs: String,
        #[serde(default)]
        on: Option<ListenOn>,
        #[serde(default)]
        mode: Option<ForwardMode>,
        #[serde(default)]
        ingress: Ingress,
    },
    ForwardEnable {
        id: u64,
        enabled: bool,
    },
    ForwardRemove {
        id: u64,
    },
    BanAdd {
        agent: String,
        forward_id: u64,
        ip: IpAddr,
        ttl: String,
    },
    VpnPeerAdd {
        name: String,
        #[serde(default)]
        panel: bool,
    },
    VpnPeerEnable {
        name: String,
        enabled: bool,
    },
    VpnPeerRevoke {
        name: String,
    },
    /// The selectors of `rift vpn allow`; `ports` and `subnets` may hold several entries.
    VpnAllow {
        peer: String,
        agent: String,
        #[serde(default)]
        server: bool,
        #[serde(default)]
        full: bool,
        #[serde(default)]
        ports: String,
        #[serde(default)]
        subnets: String,
        #[serde(default)]
        snat: bool,
    },
    /// Without `access`, withdraws everything the device has on that agent.
    VpnDeny {
        peer: String,
        agent: String,
        #[serde(default)]
        access: Option<VpnAccess>,
    },
    /// Contains the device's private key, so it counts as a change.
    VpnConfig {
        name: String,
    },
    PanelAllow {
        name: String,
        allowed: bool,
    },
    /// Starts turning two-factor login on: a new pending secret to scan.
    TwoFactorSetup,
    TwoFactorConfirm {
        code: Code,
    },
    /// Needs a current code; refused when `RIFT_WEBPANEL_2FA=required`.
    TwoFactorDisable {
        code: Code,
    },
}

/// A one-time code, kept out of the action log.
#[derive(Deserialize)]
#[serde(transparent)]
struct Code(String);
impl std::fmt::Debug for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

impl Action {
    fn writes(&self) -> bool {
        !matches!(self, Self::Logs { .. } | Self::Diagnostics)
    }

    async fn run<B: Backend>(self, panel: &Panel<B>) -> Result<Value> {
        Ok(match self {
            Self::Logs { lines } => {
                panel
                    .admin(AdminRequest::Logs {
                        lines: lines.min(1000),
                    })
                    .await?
            }
            Self::Diagnostics => {
                let status = panel.admin(AdminRequest::Status).await?;
                json!({"doctor": status["doctor"], "peers": status["peers"], "connection_history": status["connection_history"]})
            }
            Self::Reload => panel.admin(AdminRequest::Reload).await?,
            Self::AgentInvite { name, ttl } => {
                let mut data = panel
                    .admin(AdminRequest::Invite {
                        name,
                        ttl_seconds: seconds(&ttl)?,
                    })
                    .await?;
                data["lines"] = format!(
                    "RIFT_SERVER={}\nRIFT_AGENT_NAME={}\nRIFT_ENROLLMENT_TOKEN={}\n",
                    data["server"].as_str().unwrap_or_default(),
                    data["name"].as_str().unwrap_or_default(),
                    data["token"].as_str().unwrap_or_default()
                )
                .into();
                data
            }
            Self::AgentCancelInvite { name } => {
                panel.admin(AdminRequest::CancelInvite { name }).await?
            }
            Self::AgentRemove { name } => panel.admin(AdminRequest::AgentRemove { name }).await?,
            Self::AgentEnable {
                name,
                enabled: true,
            } => panel.admin(AdminRequest::AgentEnable { name }).await?,
            Self::AgentEnable {
                name,
                enabled: false,
            } => panel.admin(AdminRequest::AgentDisable { name }).await?,
            Self::AgentRename { name, new_name } => {
                panel
                    .admin(AdminRequest::AgentRename { name, new_name })
                    .await?
            }
            Self::AgentRotate { name } => panel.admin(AdminRequest::AgentRotate { name }).await?,
            Self::ForwardAdd {
                agent,
                specs,
                on,
                mode,
                ingress,
            } => {
                let specs = words(&specs);
                ensure!(
                    !specs.is_empty(),
                    "name at least one port with its protocol, for example 8080:80/tcp"
                );
                let options = ForwardOptions {
                    on,
                    mode,
                    ingress,
                    ..Default::default()
                };
                let forwards = build_forwards(
                    &agent,
                    &parse_forward_specs(&specs)?,
                    &panel.config.public_ips,
                    options,
                )?;
                let mut created = Vec::new();
                for forward in forwards {
                    match panel.admin(AdminRequest::ForwardAdd(forward)).await {
                        Ok(data) => created.push(data),
                        Err(e) if created.is_empty() => return Err(e),
                        Err(e) => {
                            let ids: Vec<String> =
                                created.iter().map(|f| f["id"].to_string()).collect();
                            bail!("{e} (forwards {} were already created)", ids.join(", "))
                        }
                    }
                }
                Value::Array(created)
            }
            Self::ForwardEnable { id, enabled } => {
                panel
                    .admin(AdminRequest::ForwardEnable { id, enabled })
                    .await?
            }
            Self::ForwardRemove { id } => panel.admin(AdminRequest::ForwardRemove { id }).await?,
            Self::BanAdd {
                agent,
                forward_id,
                ip,
                ttl,
            } => {
                panel
                    .admin(AdminRequest::Ban {
                        agent,
                        forward_id,
                        ip,
                        ttl_seconds: seconds(&ttl)?,
                    })
                    .await?
            }
            Self::VpnPeerAdd { name, panel: grant } => {
                let data = panel
                    .admin(AdminRequest::VpnPeerAdd { name: name.clone() })
                    .await?;
                if grant {
                    panel
                        .admin(AdminRequest::PanelAllow {
                            name,
                            allowed: true,
                        })
                        .await
                        .context("device created, but panel access was not granted")?;
                }
                data
            }
            Self::VpnPeerEnable { name, enabled } => {
                panel
                    .admin(AdminRequest::VpnPeerEnable { name, enabled })
                    .await?
            }
            Self::VpnPeerRevoke { name } => {
                panel.admin(AdminRequest::VpnPeerRevoke { name }).await?
            }
            Self::VpnAllow {
                peer,
                agent,
                server,
                full,
                ports,
                subnets,
                snat,
            } => {
                let subnets = words(&subnets)
                    .iter()
                    .map(|s| {
                        s.parse()
                            .with_context(|| format!("{s:?} is not an IPv4 network"))
                    })
                    .collect::<Result<Vec<ipnet::Ipv4Net>>>()?;
                ensure!(
                    !snat || !subnets.is_empty(),
                    "SNAT applies only to a subnet"
                );
                let accesses = crate::vpn::accesses(server, full, &words(&ports), &subnets, snat)?;
                ensure!(
                    !accesses.is_empty(),
                    "choose what to allow: host, all protocols, ports or a subnet"
                );
                for access in accesses {
                    panel
                        .admin(AdminRequest::VpnAllow {
                            peer: peer.clone(),
                            agent: agent.clone(),
                            access,
                        })
                        .await?;
                }
                json!({"peer": peer, "agent": agent})
            }
            Self::VpnDeny {
                peer,
                agent,
                access,
            } => {
                panel
                    .admin(AdminRequest::VpnDeny {
                        peer,
                        agent,
                        access,
                    })
                    .await?
            }
            Self::VpnConfig { name } => {
                let mut data = panel.admin(AdminRequest::VpnConfig { name }).await?;
                let text = data["config"].as_str().unwrap_or_default().to_string();
                data["qr_svg"] = crate::vpn::qr_svg(&text)?.into();
                data
            }
            Self::PanelAllow { name, allowed } => {
                panel
                    .admin(AdminRequest::PanelAllow { name, allowed })
                    .await?
            }
            Self::TwoFactorSetup => {
                let setup = panel.two_factor.setup(crate::totp::host(&panel.config))?;
                json!({"secret": setup.secret, "uri": setup.uri, "qr_svg": crate::vpn::qr_svg(&setup.uri)?})
            }
            Self::TwoFactorConfirm { code } => {
                panel.two_factor.confirm(&code.0, now())?;
                json!({"enabled": true})
            }
            Self::TwoFactorDisable { code } => {
                ensure!(
                    panel.config.webpanel_2fa != PanelTwoFactor::Required,
                    "two-factor login is required by the server; only `rift panel 2fa reset` on the server turns it off"
                );
                panel.two_factor.disable(&code.0, now())?;
                json!({"enabled": false})
            }
        })
    }
}

/// The subset of status the panel shows, with agent names resolved.
fn compose_overview(status: &Value, peers: &Value, panel: &Value) -> Value {
    let snapshot = &status["snapshot"];
    let empty = Vec::new();
    let health = status["agent_health"].as_array().unwrap_or(&empty);
    let agent_list = snapshot["agents"].as_array().unwrap_or(&empty);
    let name_of = |id: &Value| {
        agent_list
            .iter()
            .find(|a| a["id"] == *id)
            .map(|a| a["name"].clone())
            .unwrap_or_else(|| id.clone())
    };
    let agents: Vec<Value> = agent_list
        .iter()
        .map(|a| {
            let h = health.iter().find(|h| h["id"] == a["id"]);
            json!({
                "id": a["id"],
                "name": a["name"],
                "status": a["status"],
                "tunnel_ipv4": a["tunnel_ipv4"],
                "tunnel_ipv6": a["tunnel_ipv6"],
                "online": h.map(|h| h["online"].clone()).unwrap_or(Value::Bool(false)),
                "configuration_ready": h.map(|h| h["configuration_ready"].clone()).unwrap_or(Value::Bool(false)),
                "last_handshake": h.map(|h| h["last_handshake"].clone()).unwrap_or(Value::Null),
                "last_error": a["last_error"],
            })
        })
        .collect();
    let pending = status["pending_forwards"].as_array().unwrap_or(&empty);
    let forwards: Vec<Value> = snapshot["forwards"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .map(|f| {
            json!({
                "id": f["id"],
                "agent": name_of(&f["agent_id"]),
                "protocol": f["protocol"],
                "listen_ip": f["listen_ip"],
                "listen_ports": f["listen_ports"],
                "target_ports": f["target_ports"],
                "target_family": f["target_family"],
                "mode": f["mode"],
                "ingress": f["ingress"],
                "enabled": f["enabled"],
                "pending": pending.contains(&f["id"]),
            })
        })
        .collect();
    let bans: Vec<Value> = snapshot["bans"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .map(|b| json!({"id": b["id"], "agent": name_of(&b["agent_id"]), "forward_id": b["forward_id"], "ip": b["ip"], "expires_at": b["expires_at"]}))
        .collect();
    json!({
        "generation": snapshot["generation"],
        "fully_applied": status["fully_applied"],
        "apply_error": status["apply_error"],
        "enrollment": status["enrollment"],
        "invites": status["invites"],
        "bans": bans,
        "agents": agents,
        "forwards": forwards,
        "vpn_peers": peers,
        "panel": panel,
        "time": now(),
    })
}

fn cookie(token: &str, max_age: i64, secure: bool) -> String {
    format!(
        "{COOKIE}={token}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Strict{}",
        if secure { "; Secure" } else { "" }
    )
}

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}
impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
    fn cookie(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n == "cookie")
            .flat_map(|(_, v)| v.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
            .find(|(n, v)| *n == name && !v.is_empty())
            .map(|(_, v)| v)
    }
}

async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Request> {
    let mut buffer = Vec::with_capacity(1024);
    let head_end = loop {
        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break end;
        }
        ensure!(buffer.len() < MAX_HEAD, "request header too large");
        let mut chunk = [0u8; 2048];
        let n = stream.read(&mut chunk).await?;
        ensure!(n > 0, "connection closed before the request ended");
        buffer.extend_from_slice(&chunk[..n]);
    };
    ensure!(head_end <= MAX_HEAD, "request header too large");
    let head = std::str::from_utf8(&buffer[..head_end]).context("request header is not UTF-8")?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (first.next(), first.next(), first.next(), first.next())
    else {
        bail!("malformed request line");
    };
    ensure!(version.starts_with("HTTP/1."), "unsupported HTTP version");
    let path = target.split(['?', '#']).next().unwrap_or("/").to_string();
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':').context("malformed header")?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
    let mut request = Request {
        method: method.to_string(),
        path,
        headers,
        body: Vec::new(),
    };
    ensure!(
        request.header("transfer-encoding").is_none(),
        "chunked bodies are not supported"
    );
    let length: usize = match request.header("content-length") {
        Some(value) => value.parse().context("invalid content length")?,
        None => 0,
    };
    ensure!(length <= MAX_BODY, "request body too large");
    let mut body = buffer.split_off(head_end + 4);
    ensure!(body.len() <= length, "more data than the content length");
    let already = body.len();
    body.resize(length, 0);
    stream.read_exact(&mut body[already..]).await?;
    request.body = body;
    Ok(request)
}

struct Response {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
    cookie: Option<String>,
    cache: bool,
}
impl Response {
    fn asset(content_type: &'static str, body: &str) -> Self {
        Self {
            status: 200,
            content_type,
            body: body.as_bytes().to_vec(),
            cookie: None,
            cache: true,
        }
    }
    fn text(status: u16, body: &str) -> Self {
        Self {
            status,
            content_type: "text/plain",
            body: body.as_bytes().to_vec(),
            cookie: None,
            cache: false,
        }
    }
    fn json(status: u16, value: &Value) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: serde_json::to_vec(value).unwrap_or_default(),
            cookie: None,
            cache: false,
        }
    }
    fn error(status: u16, message: &str) -> Self {
        let message: String = message
            .chars()
            .filter(|c| !c.is_control())
            .take(300)
            .collect();
        Self::json(status, &json!({"error": message}))
    }
    fn to_bytes(&self) -> Vec<u8> {
        let reason = match self.status {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            429 => "Too Many Requests",
            _ => "Internal Server Error",
        };
        let mut head = format!(
            "HTTP/1.1 {} {reason}\r\n\
             Content-Type: {}; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: {}\r\n\
             X-Content-Type-Options: nosniff\r\n\
             X-Frame-Options: DENY\r\n\
             Referrer-Policy: no-referrer\r\n\
             Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n",
            self.status,
            self.content_type,
            self.body.len(),
            if self.cache { "no-cache" } else { "no-store" },
        );
        if let Some(cookie) = &self.cookie {
            head.push_str(&format!("Set-Cookie: {cookie}\r\n"));
        }
        head.push_str("\r\n");
        let mut out = head.into_bytes();
        out.extend_from_slice(&self.body);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        peers: Vec<IpAddr>,
        calls: std::sync::Mutex<Vec<String>>,
        dir: tempfile::TempDir,
    }
    impl Backend for Arc<Fake> {
        async fn admin(&self, request: AdminRequest) -> Result<Value> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{:?}", serde_json::to_value(&request)?));
            Ok(match request {
                AdminRequest::Status => json!({
                    "snapshot": {"generation": 7, "agents": [{"id": "a1", "name": "home", "status": "active", "tunnel_ipv4": "10.13.0.2"}],
                                 "forwards": [{"id": 3, "agent_id": "a1", "protocol": "tcp", "enabled": true}]},
                    "agent_health": [{"id": "a1", "online": true, "configuration_ready": true, "last_handshake": 100}],
                    "pending_forwards": [3], "fully_applied": false, "apply_error": null
                }),
                AdminRequest::VpnPeerList => json!([]),
                AdminRequest::PanelStatus => json!({"enabled": true}),
                AdminRequest::Invite { name, .. } => {
                    json!({"name": name, "token": "TOKEN", "server": "rift.example.net:8443"})
                }
                AdminRequest::VpnConfig { .. } => {
                    json!({"config": "[Interface]\nPrivateKey = K\n"})
                }
                AdminRequest::ForwardAdd(f) => json!({"id": f.listen_ports.start}),
                _ => json!({"ok": true}),
            })
        }
        fn panel_peers(&self) -> Vec<IpAddr> {
            self.peers.clone()
        }
    }

    fn config(access: PanelAccess, allow: &str) -> Config {
        Config {
            webpanel: true,
            webpanel_access: access,
            webpanel_allow: crate::config::parse_allow_list(allow).unwrap(),
            ..Default::default()
        }
    }

    fn panel(config: Config) -> (Panel<Arc<Fake>>, Arc<Fake>) {
        let fake = Arc::new(Fake {
            peers: vec!["10.14.0.2".parse().unwrap()],
            calls: Default::default(),
            dir: tempfile::tempdir().unwrap(),
        });
        let two_factor = Arc::new(TwoFactor::new(fake.dir.path().join("webpanel.totp")));
        let mut panel = Panel::new(fake.clone(), config, "correct horse battery", two_factor);
        panel.penalty = Duration::ZERO;
        (panel, fake)
    }

    async fn exchange(panel: &Panel<Arc<Fake>>, source: &str, raw: &str) -> String {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        client.write_all(raw.as_bytes()).await.unwrap();
        panel.connection(&mut server, source.parse().unwrap()).await;
        drop(server);
        let mut out = String::new();
        client.read_to_string(&mut out).await.unwrap();
        out
    }

    fn post(path: &str, body: &str, extra: &str) -> String {
        format!(
            "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}\r\n{body}",
            body.len()
        )
    }

    fn session_cookie(response: &str) -> String {
        let line = response
            .lines()
            .find(|l| l.starts_with("Set-Cookie: "))
            .expect("a session cookie");
        line["Set-Cookie: ".len()..]
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    #[test]
    fn private_mode_admits_loopback_granted_devices_and_the_allow_list_only() {
        let peers = ["10.14.0.2".parse().unwrap()];
        let private = config(PanelAccess::Private, "10.14.0.9");
        for ok in [
            "127.0.0.1",
            "::1",
            "10.14.0.2",
            "10.14.0.9",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                source_allowed(&private, &peers, ok.parse().unwrap()),
                "{ok}"
            );
        }
        for bad in ["10.14.0.3", "10.13.0.2", "203.0.113.7"] {
            assert!(
                !source_allowed(&private, &peers, bad.parse().unwrap()),
                "{bad}"
            );
        }
        let open = config(PanelAccess::Public, "");
        assert!(source_allowed(&open, &[], "203.0.113.7".parse().unwrap()));
        let restricted = config(PanelAccess::Public, "198.51.100.0/24");
        assert!(source_allowed(
            &restricted,
            &[],
            "198.51.100.20".parse().unwrap()
        ));
        assert!(!source_allowed(
            &restricted,
            &[],
            "203.0.113.7".parse().unwrap()
        ));
        assert!(source_allowed(
            &restricted,
            &peers,
            "10.14.0.2".parse().unwrap()
        ));
    }

    #[test]
    fn nft_rules_name_only_granted_devices_and_the_allow_list() {
        let mut cfg = config(PanelAccess::Private, "10.13.0.5, fd00::/64");
        let peer = |name: &str, last: u8, enabled: bool, panel: bool| VpnPeer {
            name: name.into(),
            public_key: format!("k-{name}"),
            ipv4: std::net::Ipv4Addr::new(10, 14, 0, last),
            enabled,
            created_at: 0,
            panel,
        };
        let snap = StateSnapshot {
            vpn_peers: vec![
                peer("laptop", 2, true, true),
                peer("phone", 3, true, false),
                peer("old", 4, false, true),
            ],
            ..Default::default()
        };
        let rules = input_rules(&cfg, &snap);
        assert!(rules.contains(
            "input iifname \"rift0\" ip saddr 10.14.0.2/32 ip daddr 10.13.0.1 tcp dport 8090 accept"
        ));
        assert!(rules.contains("ip saddr 10.13.0.5/32 ip daddr 10.13.0.1 tcp dport 8090 accept"));
        assert!(!rules.contains("10.14.0.3") && !rules.contains("10.14.0.4"));
        assert!(
            !rules.contains("ip6"),
            "a private panel has no IPv6 tunnel listener"
        );
        cfg.webpanel_access = PanelAccess::Public;
        assert!(input_rules(&cfg, &snap)
            .contains("ip6 saddr fd00::/64 ip6 daddr fd88:5249:4654::1 tcp dport 8090 accept"));
        cfg.webpanel = false;
        assert!(input_rules(&cfg, &snap).is_empty());
    }

    #[tokio::test]
    async fn refused_sources_get_nothing_but_a_403() {
        let (panel, fake) = panel(config(PanelAccess::Private, ""));
        let out = exchange(&panel, "203.0.113.7", "GET /api/overview HTTP/1.1\r\n\r\n").await;
        assert!(out.starts_with("HTTP/1.1 403"), "{out}");
        assert!(fake.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_api_needs_a_session_and_actions_need_the_header() {
        let (panel, fake) = panel(config(PanelAccess::Private, ""));
        let out = exchange(&panel, "127.0.0.1", "GET /api/overview HTTP/1.1\r\n\r\n").await;
        assert!(out.starts_with("HTTP/1.1 401"), "{out}");
        let index = exchange(&panel, "127.0.0.1", "GET / HTTP/1.1\r\n\r\n").await;
        assert!(index.starts_with("HTTP/1.1 200") && index.contains("<title>"));
        assert!(index.contains("Content-Security-Policy: default-src 'none'"));

        let login = r#"{"password":"correct horse battery"}"#;
        let refused = exchange(&panel, "127.0.0.1", &post("/api/login", login, "")).await;
        assert!(refused.starts_with("HTTP/1.1 403"), "{refused}");
        let wrong = exchange(
            &panel,
            "127.0.0.1",
            &post(
                "/api/login",
                r#"{"password":"nope"}"#,
                "X-Rift-Panel: 1\r\n",
            ),
        )
        .await;
        assert!(wrong.starts_with("HTTP/1.1 401") && !wrong.contains("Set-Cookie"));
        assert!(wrong.contains("wrong password or code"));
        let ok = exchange(
            &panel,
            "127.0.0.1",
            &post("/api/login", login, "X-Rift-Panel: 1\r\n"),
        )
        .await;
        assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
        assert!(ok.contains("HttpOnly; SameSite=Strict"));
        let cookie = session_cookie(&ok);

        let overview = exchange(
            &panel,
            "10.14.0.2",
            &format!("GET /api/overview HTTP/1.1\r\nCookie: theme=dark; {cookie}\r\n\r\n"),
        )
        .await;
        assert!(overview.starts_with("HTTP/1.1 200"), "{overview}");
        let body: Value = serde_json::from_str(overview.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body["agents"][0]["online"], true);
        assert_eq!(body["forwards"][0]["agent"], "home");
        assert_eq!(body["forwards"][0]["pending"], true);

        let action = r#"{"action":"forward_enable","id":3,"enabled":false}"#;
        let no_header = exchange(
            &panel,
            "127.0.0.1",
            &post("/api/action", action, &format!("Cookie: {cookie}\r\n")),
        )
        .await;
        assert!(no_header.starts_with("HTTP/1.1 403"), "{no_header}");
        let done = exchange(
            &panel,
            "127.0.0.1",
            &post(
                "/api/action",
                action,
                &format!("Cookie: {cookie}\r\nX-Rift-Panel: 1\r\n"),
            ),
        )
        .await;
        assert!(done.starts_with("HTTP/1.1 200"), "{done}");
        assert!(fake
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.contains("ForwardEnable")));
        let unknown = exchange(
            &panel,
            "127.0.0.1",
            &post(
                "/api/action",
                r#"{"action":"panel_password"}"#,
                &format!("Cookie: {cookie}\r\nX-Rift-Panel: 1\r\n"),
            ),
        )
        .await;
        assert!(unknown.starts_with("HTTP/1.1 400"), "{unknown}");

        let logout = exchange(
            &panel,
            "127.0.0.1",
            &post(
                "/api/logout",
                "",
                &format!("Cookie: {cookie}\r\nX-Rift-Panel: 1\r\n"),
            ),
        )
        .await;
        assert!(logout.contains("Max-Age=0"));
        let after = exchange(
            &panel,
            "127.0.0.1",
            &format!("GET /api/overview HTTP/1.1\r\nCookie: {cookie}\r\n\r\n"),
        )
        .await;
        assert!(after.starts_with("HTTP/1.1 401"), "{after}");
    }

    async fn logged_in(panel: &Panel<Arc<Fake>>) -> String {
        let login = r#"{"password":"correct horse battery"}"#;
        let ok = exchange(
            panel,
            "127.0.0.1",
            &post("/api/login", login, "X-Rift-Panel: 1\r\n"),
        )
        .await;
        session_cookie(&ok)
    }

    async fn act(
        panel: &Panel<Arc<Fake>>,
        source: &str,
        cookie: &str,
        body: &str,
        extra: &str,
    ) -> String {
        exchange(
            panel,
            source,
            &post(
                "/api/action",
                body,
                &format!("Cookie: {cookie}\r\nX-Rift-Panel: 1\r\n{extra}"),
            ),
        )
        .await
    }

    #[tokio::test]
    async fn changes_need_loopback_without_a_proxy_or_a_panel_device() {
        let (panel, fake) = panel(config(PanelAccess::Public, ""));
        let cookie = logged_in(&panel).await;
        let change = r#"{"action":"forward_remove","id":3}"#;
        let read = r#"{"action":"logs","lines":10}"#;
        // A public address may read but not change.
        let refused = act(&panel, "203.0.113.7", &cookie, change, "").await;
        assert!(
            refused.starts_with("HTTP/1.1 403") && refused.contains("read-only"),
            "{refused}"
        );
        assert!(act(&panel, "203.0.113.7", &cookie, read, "")
            .await
            .starts_with("HTTP/1.1 200"));
        // Loopback behind a reverse proxy is public too.
        let proxied = act(
            &panel,
            "127.0.0.1",
            &cookie,
            change,
            "X-Forwarded-For: 203.0.113.7\r\n",
        )
        .await;
        assert!(proxied.starts_with("HTTP/1.1 403"), "{proxied}");
        // The VPS itself and a panel device may change.
        assert!(act(&panel, "127.0.0.1", &cookie, change, "")
            .await
            .starts_with("HTTP/1.1 200"));
        assert!(act(&panel, "10.14.0.2", &cookie, change, "")
            .await
            .starts_with("HTTP/1.1 200"));
        let removals = fake
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.contains("ForwardRemove"))
            .count();
        assert_eq!(removals, 2);
        // The session endpoint tells the page which one it is.
        let session = exchange(&panel, "203.0.113.7", "GET /api/session HTTP/1.1\r\n\r\n").await;
        assert!(session.contains("\"can_write\":false"), "{session}");
        let session = exchange(&panel, "10.14.0.2", "GET /api/session HTTP/1.1\r\n\r\n").await;
        assert!(session.contains("\"can_write\":true"), "{session}");
        // Private keys count as a change.
        let config = r#"{"action":"vpn_config","name":"laptop"}"#;
        assert!(act(&panel, "203.0.113.7", &cookie, config, "")
            .await
            .starts_with("HTTP/1.1 403"));
        let shown = act(&panel, "127.0.0.1", &cookie, config, "").await;
        assert!(
            shown.contains("<svg") && shown.contains("PrivateKey"),
            "{shown}"
        );
    }

    #[tokio::test]
    async fn control_off_makes_every_connection_read_only() {
        let mut cfg = config(PanelAccess::Private, "");
        cfg.webpanel_control = PanelControl::Off;
        let (panel, _) = panel(cfg);
        let cookie = logged_in(&panel).await;
        let change = r#"{"action":"reload"}"#;
        assert!(act(&panel, "127.0.0.1", &cookie, change, "")
            .await
            .starts_with("HTTP/1.1 403"));
    }

    #[tokio::test]
    async fn forwards_use_the_short_form_and_invites_return_the_env_lines() {
        let mut cfg = config(PanelAccess::Private, "");
        cfg.public_ips = vec!["203.0.113.10".parse().unwrap()];
        let (panel, fake) = panel(cfg);
        let cookie = logged_in(&panel).await;
        let added = act(
            &panel,
            "127.0.0.1",
            &cookie,
            r#"{"action":"forward_add","agent":"home","specs":"53/both, 8080:80/tcp"}"#,
            "",
        )
        .await;
        assert!(added.starts_with("HTTP/1.1 200"), "{added}");
        let calls = fake.calls.lock().unwrap().clone();
        let adds: Vec<_> = calls.iter().filter(|c| c.contains("ForwardAdd")).collect();
        assert_eq!(adds.len(), 3, "{adds:?}");
        assert!(adds
            .iter()
            .all(|c| c.contains("203.0.113.10") && c.contains("transparent")));
        let bad = act(
            &panel,
            "127.0.0.1",
            &cookie,
            r#"{"action":"forward_add","agent":"home","specs":"80"}"#,
            "",
        )
        .await;
        assert!(
            bad.starts_with("HTTP/1.1 400") && bad.contains("needs a protocol"),
            "{bad}"
        );
        let invite = act(
            &panel,
            "127.0.0.1",
            &cookie,
            r#"{"action":"agent_invite","name":"node2","ttl":"15m"}"#,
            "",
        )
        .await;
        assert!(invite.contains("RIFT_ENROLLMENT_TOKEN=TOKEN"), "{invite}");
        assert!(calls.iter().all(|c| !c.contains("PanelPassword")));
        let grant = act(
            &panel,
            "127.0.0.1",
            &cookie,
            r#"{"action":"vpn_allow","peer":"phone","agent":"home","ports":"22/tcp 53/both","subnets":"192.168.178.0/24"}"#,
            "",
        )
        .await;
        assert!(grant.starts_with("HTTP/1.1 200"), "{grant}");
        let allows = fake
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.contains("VpnAllow"))
            .count();
        assert_eq!(allows, 4);
    }

    #[tokio::test]
    async fn oversized_and_malformed_requests_are_rejected() {
        let (panel, _) = panel(config(PanelAccess::Private, ""));
        let huge = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD));
        assert!(exchange(&panel, "127.0.0.1", &huge)
            .await
            .starts_with("HTTP/1.1 400"));
        let body = post("/api/login", "{}", "").replace(
            "Content-Length: 2",
            &format!("Content-Length: {}", MAX_BODY + 1),
        );
        assert!(exchange(&panel, "127.0.0.1", &body)
            .await
            .starts_with("HTTP/1.1 400"));
        assert!(exchange(&panel, "127.0.0.1", "GARBAGE\r\n\r\n")
            .await
            .starts_with("HTTP/1.1 400"));
        assert!(exchange(&panel, "127.0.0.1", "GET /nope HTTP/1.1\r\n\r\n")
            .await
            .starts_with("HTTP/1.1 404"));
    }

    /// Turns two-factor login on directly and returns the secret.
    fn enable_two_factor(panel: &Panel<Arc<Fake>>) -> Vec<u8> {
        let setup = panel.two_factor.setup("server").unwrap();
        let secret = crate::totp::base32_decode(&setup.secret).unwrap();
        let step = crate::totp::step_at(now());
        let code = format!("{:06}", crate::totp::code_at(&secret, step));
        panel.two_factor.confirm(&code, now()).unwrap();
        secret
    }

    fn code_for(secret: &[u8], offset: u64) -> String {
        format!(
            "{:06}",
            crate::totp::code_at(secret, crate::totp::step_at(now()) + offset)
        )
    }

    async fn try_login(panel: &Panel<Arc<Fake>>, password: &str, code: Option<&str>) -> String {
        let body = match code {
            Some(code) => json!({"password": password, "code": code}),
            None => json!({"password": password}),
        };
        exchange(
            panel,
            "127.0.0.1",
            &post("/api/login", &body.to_string(), "X-Rift-Panel: 1\r\n"),
        )
        .await
    }

    const PASSWORD: &str = "correct horse battery";

    #[tokio::test]
    async fn login_needs_the_code_once_two_factor_is_on() {
        let (panel, _fake) = panel(config(PanelAccess::Private, ""));
        let session = exchange(&panel, "127.0.0.1", "GET /api/session HTTP/1.1\r\n\r\n").await;
        assert!(session.contains("\"two_factor\":false"), "{session}");
        assert!(try_login(&panel, PASSWORD, None)
            .await
            .starts_with("HTTP/1.1 200"));

        let secret = enable_two_factor(&panel);
        let session = exchange(&panel, "127.0.0.1", "GET /api/session HTTP/1.1\r\n\r\n").await;
        assert!(session.contains("\"two_factor\":true"), "{session}");
        for (password, code) in [
            (PASSWORD, None),
            (PASSWORD, Some("000000")),
            ("nope", Some(code_for(&secret, 1).as_str())),
        ] {
            let out = try_login(&panel, password, code).await;
            assert!(
                out.starts_with("HTTP/1.1 401") && out.contains("wrong password or code"),
                "{out}"
            );
            assert!(!out.contains("Set-Cookie"));
        }
        // A wrong password does not use the code up.
        let good = code_for(&secret, 1);
        let ok = try_login(&panel, PASSWORD, Some(&good)).await;
        assert!(
            ok.starts_with("HTTP/1.1 200") && ok.contains("Set-Cookie"),
            "{ok}"
        );
        // The same code cannot log in twice.
        assert!(try_login(&panel, PASSWORD, Some(&good))
            .await
            .starts_with("HTTP/1.1 401"));
    }

    #[tokio::test]
    async fn ten_failed_logins_lock_everyone_out() {
        let (panel, _fake) = panel(config(PanelAccess::Private, ""));
        for _ in 0..9 {
            assert!(try_login(&panel, "nope", None)
                .await
                .starts_with("HTTP/1.1 401"));
        }
        // A success resets the count.
        assert!(try_login(&panel, PASSWORD, None)
            .await
            .starts_with("HTTP/1.1 200"));
        for _ in 0..10 {
            assert!(try_login(&panel, "nope", None)
                .await
                .starts_with("HTTP/1.1 401"));
        }
        let locked = try_login(&panel, PASSWORD, None).await;
        assert!(
            locked.starts_with("HTTP/1.1 429") && locked.contains("try again later"),
            "{locked}"
        );
        assert!(!locked.contains("Set-Cookie"));
    }

    #[tokio::test]
    async fn required_two_factor_refuses_logins_until_a_secret_exists() {
        let mut cfg = config(PanelAccess::Private, "");
        cfg.webpanel_2fa = PanelTwoFactor::Required;
        let (panel, _fake) = panel(cfg);
        let refused = try_login(&panel, PASSWORD, None).await;
        assert!(
            refused.starts_with("HTTP/1.1 403") && refused.contains("rift panel 2fa setup"),
            "{refused}"
        );
        let secret = enable_two_factor(&panel);
        assert!(try_login(&panel, PASSWORD, None)
            .await
            .starts_with("HTTP/1.1 401"));
        let ok = try_login(&panel, PASSWORD, Some(&code_for(&secret, 1))).await;
        assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
        // The panel cannot turn a required factor off, and the overview says so.
        let cookie = session_cookie(&ok);
        let disable = format!(
            r#"{{"action":"two_factor_disable","code":"{}"}}"#,
            code_for(&secret, 2)
        );
        let out = act(&panel, "127.0.0.1", &cookie, &disable, "").await;
        assert!(
            out.starts_with("HTTP/1.1 400") && out.contains("required"),
            "{out}"
        );
        assert!(panel.two_factor.enabled());
        let overview = exchange(
            &panel,
            "127.0.0.1",
            &format!("GET /api/overview HTTP/1.1\r\nCookie: {cookie}\r\n\r\n"),
        )
        .await;
        assert!(
            overview.contains(r#""two_factor":{"enabled":true,"required":true}"#),
            "{overview}"
        );
    }

    #[tokio::test]
    async fn two_factor_setup_and_disable_run_from_a_trusted_connection() {
        let (panel, _fake) = panel(config(PanelAccess::Public, ""));
        let cookie = logged_in(&panel).await;
        let setup = r#"{"action":"two_factor_setup"}"#;
        // Reading the status is open; changing it is not.
        let refused = act(&panel, "203.0.113.7", &cookie, setup, "").await;
        assert!(refused.starts_with("HTTP/1.1 403"), "{refused}");
        assert!(act(
            &panel,
            "127.0.0.1",
            &cookie,
            setup,
            "X-Real-IP: 1.2.3.4\r\n"
        )
        .await
        .starts_with("HTTP/1.1 403"));
        let shown = act(&panel, "127.0.0.1", &cookie, setup, "").await;
        assert!(
            shown.starts_with("HTTP/1.1 200")
                && shown.contains("<svg")
                && shown.contains("otpauth://totp/RIFT:server?secret="),
            "{shown}"
        );
        let body: Value = serde_json::from_str(shown.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        let secret = crate::totp::base32_decode(body["secret"].as_str().unwrap()).unwrap();

        let confirm =
            |code: String| format!(r#"{{"action":"two_factor_confirm","code":"{code}"}}"#);
        let wrong = act(&panel, "127.0.0.1", &cookie, &confirm("000000".into()), "").await;
        assert!(
            wrong.starts_with("HTTP/1.1 400") && wrong.contains("wrong code"),
            "{wrong}"
        );
        assert!(!panel.two_factor.enabled());
        let good = confirm(code_for(&secret, 0));
        assert!(act(&panel, "203.0.113.7", &cookie, &good, "")
            .await
            .starts_with("HTTP/1.1 403"));
        assert!(!panel.two_factor.enabled());
        let done = act(&panel, "10.14.0.2", &cookie, &good, "").await;
        assert!(done.starts_with("HTTP/1.1 200"), "{done}");
        assert!(panel.two_factor.enabled());

        let disable = format!(
            r#"{{"action":"two_factor_disable","code":"{}"}}"#,
            code_for(&secret, 1)
        );
        assert!(act(&panel, "203.0.113.7", &cookie, &disable, "")
            .await
            .starts_with("HTTP/1.1 403"));
        assert!(panel.two_factor.enabled());
        let wrong = r#"{"action":"two_factor_disable","code":"000000"}"#;
        assert!(act(&panel, "127.0.0.1", &cookie, wrong, "")
            .await
            .starts_with("HTTP/1.1 400"));
        assert!(act(&panel, "127.0.0.1", &cookie, &disable, "")
            .await
            .starts_with("HTTP/1.1 200"));
        assert!(!panel.two_factor.enabled());
        // Turning it off ends every session.
        let after = exchange(
            &panel,
            "127.0.0.1",
            &format!("GET /api/overview HTTP/1.1\r\nCookie: {cookie}\r\n\r\n"),
        )
        .await;
        assert!(after.starts_with("HTTP/1.1 401"), "{after}");
    }

    #[tokio::test]
    async fn a_reset_from_the_cli_ends_the_sessions() {
        let (panel, _fake) = panel(config(PanelAccess::Private, ""));
        let secret = enable_two_factor(&panel);
        let ok = try_login(&panel, PASSWORD, Some(&code_for(&secret, 1))).await;
        let cookie = session_cookie(&ok);
        let overview = format!("GET /api/overview HTTP/1.1\r\nCookie: {cookie}\r\n\r\n");
        assert!(exchange(&panel, "127.0.0.1", &overview)
            .await
            .starts_with("HTTP/1.1 200"));
        panel.two_factor.reset().unwrap();
        assert!(exchange(&panel, "127.0.0.1", &overview)
            .await
            .starts_with("HTTP/1.1 401"));
    }

    #[test]
    fn a_generated_password_is_kept_private_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
            state_dir: dir.path().into(),
            ..Default::default()
        };
        let first = password(&cfg).unwrap();
        assert_eq!(first.len(), 24);
        assert_eq!(password(&cfg).unwrap(), first);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(password_path(&cfg))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let set = Config {
            webpanel_password: Some("from the environment".into()),
            ..cfg
        };
        assert_eq!(password(&set).unwrap(), "from the environment");
    }
}
