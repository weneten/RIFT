use crate::{
    config::{validate_name, Config},
    model::*,
    net::Kernel,
    protocol::{self, EnrollmentRequest, EnrollmentResponse},
    state::StateStore,
};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use rustls::{pki_types::ServerName, RootCertStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::BufReader,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const TOKEN_PREFIX: &str = "v1.";
const MAX_INVITE: usize = 48 * 1024;
const ENROLL_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Serialize, Deserialize)]
struct InviteBundle {
    version: u8,
    secret: String,
    ca_pem: String,
}

pub fn create_invite(
    config: &Config,
    state: &StateStore,
    name: &str,
    ttl_seconds: u64,
) -> Result<String> {
    validate_name(name)?;
    // An invitation for an existing agent re-enrolls it: whoever uses it takes over the
    // agent's key and keeps its addresses, forwards, grants and exits.
    if let Some(agent) = state
        .snapshot()?
        .agents
        .iter()
        .find(|agent| agent.name == name)
    {
        anyhow::ensure!(
            agent.status == AgentStatus::Active,
            "agent {name} is {}; only an active agent can be invited again (enable it first, or wait for its enrollment)",
            match agent.status {
                AgentStatus::Pending => "still enrolling",
                _ => "disabled",
            }
        );
    }
    anyhow::ensure!(
        (60..=30 * 24 * 3600).contains(&ttl_seconds),
        "invitation TTL must be 60 seconds to 30 days"
    );
    let ca_path = config.tls_ca.as_ref().ok_or_else(|| {
        anyhow!("tls_ca is required so the invite can bootstrap standard TLS verification")
    })?;
    let ca_pem = std::fs::read_to_string(ca_path)
        .with_context(|| format!("read TLS trust anchor {}", ca_path.display()))?;
    let mut random = [0u8; 32];
    OsRng.fill_bytes(&mut random);
    let secret = URL_SAFE_NO_PAD.encode(random);
    let bundle = InviteBundle {
        version: 1,
        secret: secret.clone(),
        ca_pem,
    };
    let raw = serde_json::to_vec(&bundle)?;
    let invite = format!("{}{}", TOKEN_PREFIX, URL_SAFE_NO_PAD.encode(raw));
    anyhow::ensure!(
        invite.len() <= MAX_INVITE,
        "trust anchor makes invite too large"
    );
    state.invite(
        name,
        &StateStore::invite_hash(&secret),
        now() + ttl_seconds as i64,
    )?;
    Ok(invite)
}

fn parse_invite(value: &str) -> Result<InviteBundle> {
    anyhow::ensure!(value.len() <= MAX_INVITE, "invitation is too large");
    let encoded = value
        .strip_prefix(TOKEN_PREFIX)
        .ok_or_else(|| anyhow!("unsupported invitation version"))?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
    let bundle: InviteBundle = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
        bundle.version == 1 && bundle.secret.len() >= 40,
        "invalid invitation payload"
    );
    Ok(bundle)
}

pub fn server_tls(config: &Config) -> Result<Arc<rustls::ServerConfig>> {
    let cert_path = config
        .tls_cert
        .as_ref()
        .ok_or_else(|| anyhow!("tls_cert is required when enrollment is enabled"))?;
    let key_path = config
        .tls_key
        .as_ref()
        .ok_or_else(|| anyhow!("tls_key is required when enrollment is enabled"))?;
    let cert_file = std::fs::File::open(cert_path)?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    anyhow::ensure!(
        !certs.is_empty(),
        "TLS certificate file contains no certificates"
    );
    let key_file = std::fs::File::open(key_path)?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))?
        .ok_or_else(|| anyhow!("TLS key file contains no supported private key"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Arc::new(cfg))
}

pub async fn serve(
    listener: TcpListener,
    state: Arc<StateStore>,
    config: Config,
    server_public_key: String,
    kernel: Arc<tokio::sync::Mutex<Kernel>>,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(server_tls(&config)?);
    let permits = Arc::new(Semaphore::new(64));
    let limits = Arc::new(StdMutex::new(HashMap::<IpAddr, (Instant, u8)>::new()));
    let mut requests = tokio::task::JoinSet::new();
    loop {
        while requests.try_join_next().is_some() {}
        let (tcp, peer) = listener.accept().await?;
        if !allow_ip(&limits, peer.ip()) {
            tracing::warn!("enrollment rate limit from {peer}");
            continue;
        };
        let permit = match permits.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!("enrollment connection limit reached from {peer}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let state = state.clone();
        let config = config.clone();
        let public = server_public_key.clone();
        let kernel = kernel.clone();
        requests.spawn(async move {
            let _permit = permit;
            if let Err(e) = timeout(
                ENROLL_TIMEOUT,
                handle_tls(tcp, acceptor, state, config, public, kernel),
            )
            .await
            .unwrap_or_else(|_| Err(anyhow!("enrollment deadline exceeded")))
            {
                tracing::warn!("enrollment request from {peer} rejected: {e:#}");
            }
        });
    }
}

fn allow_ip(limits: &StdMutex<HashMap<IpAddr, (Instant, u8)>>, ip: IpAddr) -> bool {
    let Ok(mut map) = limits.lock() else {
        return false;
    };
    let now = Instant::now();
    map.retain(|_, (at, _)| now.duration_since(*at) < Duration::from_secs(60));
    if !map.contains_key(&ip) && map.len() >= 4096 {
        return false;
    }
    let entry = map.entry(ip).or_insert((now, 0));
    if now.duration_since(entry.0) >= Duration::from_secs(60) {
        *entry = (now, 0)
    }
    if entry.1 >= 10 {
        return false;
    }
    entry.1 += 1;
    true
}

async fn handle_tls(
    tcp: TcpStream,
    acceptor: TlsAcceptor,
    state: Arc<StateStore>,
    config: Config,
    server_public_key: String,
    kernel: Arc<tokio::sync::Mutex<Kernel>>,
) -> Result<()> {
    let mut tls = acceptor.accept(tcp).await?;
    let request: EnrollmentRequest = protocol::receive(&mut tls).await?;
    let reply = match enroll(&request, &state, &config, &server_public_key) {
        Ok(w) => {
            let kernel = kernel.lock().await;
            match kernel
                .apply_server(&state.snapshot()?, &config.private_key_path())
                .await
            {
                Ok(()) => EnrollmentResponse::Welcome(w),
                Err(e) => EnrollmentResponse::Error {
                    message: sanitize(&format!("staging setup failed: {e}")),
                },
            }
        }
        Err(e) => EnrollmentResponse::Error {
            message: sanitize(&e.to_string()),
        },
    };
    protocol::send(&mut tls, &reply).await?;
    Ok(())
}

fn enroll(
    req: &EnrollmentRequest,
    state: &StateStore,
    config: &Config,
    server_public_key: &str,
) -> Result<Welcome> {
    anyhow::ensure!(
        req.version == protocol::VERSION,
        "unsupported enrollment protocol version"
    );
    validate_name(&req.name)?;
    let id = uuid::Uuid::parse_str(&req.identity_id)?.to_string();
    let attempt = uuid::Uuid::parse_str(&req.attempt_id)?.to_string();
    let key = base64::engine::general_purpose::STANDARD.decode(&req.public_key)?;
    anyhow::ensure!(key.len() == 32, "WireGuard public key must be 32 bytes");
    let bundle = parse_invite(&req.token)?;
    let configured = config
        .tls_ca
        .as_ref()
        .ok_or_else(|| anyhow!("server CA is not configured"))?;
    let ca = std::fs::read(configured)?;
    anyhow::ensure!(
        Sha256::digest(&ca).as_slice() == Sha256::digest(bundle.ca_pem.as_bytes()).as_slice(),
        "invitation trust anchor does not match server configuration"
    );
    let hash = StateStore::invite_hash(&bundle.secret);
    let agent = state.reserve_enrollment(
        &hash,
        &req.name,
        &id,
        &attempt,
        &req.public_key,
        config.ipv4_pool,
        config.ipv6_pool,
        config.server_ipv4,
        config.server_ipv6,
        120,
    )?;
    Ok(Welcome {
        agent_id: agent.id,
        name: agent.name,
        attempt_id: agent.attempt_id,
        server_public_key: server_public_key.into(),
        server_endpoint: host_port(&config.public_endpoint, config.wg_port),
        server_ipv4: config.server_ipv4,
        server_ipv6: config.server_ipv6,
        tunnel_ipv4: agent.tunnel_ipv4,
        tunnel_ipv6: agent.tunnel_ipv6,
        keepalive: config.keepalive,
        control_port: config.control_port,
        mtu: config.mtu,
    })
}
fn host_port(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn sanitize(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(256).collect()
}

pub async fn enroll_agent(config: &Config, identity: &mut AgentIdentity) -> Result<Welcome> {
    let token = config
        .enrollment_token
        .as_deref()
        .ok_or_else(|| anyhow!("RIFT_ENROLLMENT_TOKEN is required before first activation"))?;
    let bundle = parse_invite(token)?;
    let (host, addresses) = server_addr(
        config
            .server_address
            .as_deref()
            .ok_or_else(|| anyhow!("RIFT_SERVER is required"))?,
    )
    .await?;
    let mut roots = RootCertStore::empty();
    let mut reader = BufReader::new(bundle.ca_pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut reader) {
        roots.add(cert?)?;
    }
    anyhow::ensure!(!roots.is_empty(), "invitation has no TLS trust anchor");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let mut connected = None;
    for addr in addresses {
        if let Ok(Ok(stream)) = timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            connected = Some(stream);
            break;
        }
    }
    let tcp =
        connected.ok_or_else(|| anyhow!("no resolved VPS enrollment address was reachable"))?;
    let server_name = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        ServerName::IpAddress(ip.into())
    } else {
        ServerName::try_from(host.clone())
            .map_err(|_| anyhow!("invalid RIFT_SERVER DNS hostname"))?
    };
    let mut tls = timeout(ENROLL_TIMEOUT, connector.connect(server_name, tcp)).await??;
    let req = EnrollmentRequest {
        version: protocol::VERSION,
        token: token.into(),
        name: config
            .agent_name
            .clone()
            .ok_or_else(|| anyhow!("RIFT_AGENT_NAME is required"))?,
        identity_id: identity.id.clone(),
        attempt_id: identity.attempt_id.clone(),
        public_key: identity.public_key.clone(),
    };
    timeout(ENROLL_TIMEOUT, protocol::send(&mut tls, &req)).await??;
    match timeout(
        ENROLL_TIMEOUT,
        protocol::receive::<EnrollmentResponse, _>(&mut tls),
    )
    .await??
    {
        EnrollmentResponse::Welcome(w) => {
            // A re-enrollment keeps the agent's existing ID on the server.
            identity.id = w.agent_id.clone();
            identity.welcome = Some(w.clone());
            Ok(w)
        }
        EnrollmentResponse::Error { message } => bail!("enrollment refused: {message}"),
    }
}

/// Host and port of `RIFT_SERVER`. A bare host or address means the enrollment port 8443.
fn split_server(value: &str) -> Result<(String, u16)> {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let i = rest
            .find(']')
            .ok_or_else(|| anyhow!("invalid bracketed IPv6 server address"))?;
        let host = &rest[..i];
        let port = rest[i + 1..].strip_prefix(':').unwrap_or("8443");
        (host.to_string(), port.parse::<u16>()?)
    } else if value.parse::<IpAddr>().is_ok() {
        (value.to_string(), 8443)
    } else if let Some((h, p)) = value.rsplit_once(':') {
        (h.to_string(), p.parse::<u16>()?)
    } else {
        (value.to_string(), 8443)
    };
    anyhow::ensure!(!host.is_empty(), "RIFT_SERVER hostname is empty");
    Ok((host, port))
}

async fn server_addr(value: &str) -> Result<(String, Vec<SocketAddr>)> {
    let (host, port) = split_server(value)?;
    let addresses: Vec<_> = timeout(
        Duration::from_secs(10),
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await??
    .collect();
    anyhow::ensure!(!addresses.is_empty(), "RIFT_SERVER did not resolve");
    Ok((host, addresses))
}

/// The WireGuard endpoint an agent dials. It is the one the server announced at enrollment
/// (`HOST:PORT`), except that a `RIFT_SERVER` in the agent's `.env` with another host wins
/// for the host, with the stored WireGuard port. After a move of the server to a new address,
/// editing `RIFT_SERVER` is then all the agent needs.
pub fn wireguard_endpoint(stored: &str, server_address: Option<&str>) -> String {
    let Some(configured) = server_address.and_then(|v| split_server(v).ok()) else {
        return stored.to_string();
    };
    let Some((stored_host, port)) = stored.rsplit_once(':') else {
        return stored.to_string();
    };
    let stored_host = stored_host.trim_start_matches('[').trim_end_matches(']');
    if configured.0.eq_ignore_ascii_case(stored_host) {
        return stored.to_string();
    }
    match port.parse::<u16>() {
        Ok(port) => host_port(&configured.0, port),
        Err(_) => stored.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invite_payload_is_versioned_and_round_trips() {
        let b = InviteBundle {
            version: 1,
            secret: "a".repeat(43),
            ca_pem: "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----".into(),
        };
        let token = format!(
            "{TOKEN_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&b).unwrap())
        );
        let parsed = parse_invite(&token).unwrap();
        assert_eq!(parsed.secret, b.secret);
        assert_eq!(parsed.ca_pem, b.ca_pem);
    }
    #[test]
    fn invite_payload_rejects_unknown_versions_and_oversize() {
        assert!(parse_invite("v2.deadbeef").is_err());
        assert!(parse_invite(&format!("v1.{}", "x".repeat(MAX_INVITE))).is_err());
    }
    #[test]
    fn a_changed_server_host_in_the_env_replaces_the_stored_endpoint_host() {
        let stored = "vps.example.net:51820";
        // No setting, the same host, or the same host with another case: nothing changes.
        assert_eq!(wireguard_endpoint(stored, None), stored);
        assert_eq!(
            wireguard_endpoint(stored, Some("vps.example.net:8443")),
            stored
        );
        assert_eq!(wireguard_endpoint(stored, Some("VPS.example.net")), stored);
        // A different host or address wins; the WireGuard port stays the stored one.
        assert_eq!(
            wireguard_endpoint(stored, Some("203.0.113.9:8443")),
            "203.0.113.9:51820"
        );
        assert_eq!(
            wireguard_endpoint(stored, Some("203.0.113.9")),
            "203.0.113.9:51820"
        );
        assert_eq!(
            wireguard_endpoint(stored, Some("[2001:db8::9]:8443")),
            "[2001:db8::9]:51820"
        );
        assert_eq!(
            wireguard_endpoint("[2001:db8::1]:51820", Some("[2001:db8::1]:8443")),
            "[2001:db8::1]:51820"
        );
        assert_eq!(
            wireguard_endpoint("203.0.113.9:40000", Some("new.example.net:9000")),
            "new.example.net:40000"
        );
        // An unusable setting never breaks a working endpoint.
        assert_eq!(wireguard_endpoint(stored, Some("host:notaport")), stored);
        assert_eq!(wireguard_endpoint(stored, Some("")), stored);
    }

    const TEST_CA: &str = "-----BEGIN CERTIFICATE-----\ntest-ca\n-----END CERTIFICATE-----\n";

    fn enrollment_fixture() -> (tempfile::TempDir, Config, StateStore) {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("tls-ca.crt");
        std::fs::write(&ca, TEST_CA).unwrap();
        let config = Config {
            state_dir: dir.path().to_path_buf(),
            public_endpoint: "rift.example.net".into(),
            tls_ca: Some(ca),
            ..Config::default()
        };
        let state = StateStore::open(&dir.path().join("state.db")).unwrap();
        (dir, config, state)
    }

    fn request(token: &str, name: &str) -> EnrollmentRequest {
        EnrollmentRequest {
            version: protocol::VERSION,
            token: token.into(),
            name: name.into(),
            identity_id: uuid::Uuid::new_v4().to_string(),
            attempt_id: uuid::Uuid::new_v4().to_string(),
            public_key: base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
        }
    }

    #[test]
    fn an_expired_invitation_is_refused_and_creates_no_agent() {
        let (_dir, config, state) = enrollment_fixture();
        // An invitation exactly as `create_invite` builds it, stored with an expiry one second
        // in the past, as if its TTL had just run out.
        let secret = "s".repeat(43);
        let bundle = InviteBundle {
            version: 1,
            secret: secret.clone(),
            ca_pem: TEST_CA.into(),
        };
        let token = format!(
            "{TOKEN_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&bundle).unwrap())
        );
        state
            .invite("late", &StateStore::invite_hash(&secret), now() - 1)
            .unwrap();
        let error = enroll(&request(&token, "late"), &state, &config, "server-key")
            .expect_err("an expired invitation was accepted");
        assert!(
            error.to_string().contains("expired"),
            "unexpected error: {error:#}"
        );
        assert!(
            !state
                .snapshot()
                .unwrap()
                .agents
                .iter()
                .any(|a| a.name == "late"),
            "an expired invitation created an agent"
        );
        // The same steps with an invitation that is still valid succeed, so the refusal above
        // comes from the expiry and not from the fixture.
        let fresh = create_invite(&config, &state, "early", 60).unwrap();
        let welcome = enroll(&request(&fresh, "early"), &state, &config, "server-key").unwrap();
        assert_eq!(welcome.name, "early");
    }

    #[test]
    fn the_invitation_secret_is_never_stored_in_plain_text() {
        let (dir, config, state) = enrollment_fixture();
        let token = create_invite(&config, &state, "node1", 600).unwrap();
        let secret = parse_invite(&token).unwrap().secret;
        enroll(&request(&token, "node1"), &state, &config, "server-key").unwrap();
        drop(state);
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let path = entry.unwrap().path();
            let bytes = std::fs::read(&path).unwrap();
            for needle in [&secret, &token] {
                assert!(
                    !bytes
                        .windows(needle.len())
                        .any(|window| window == needle.as_bytes()),
                    "{} holds the invitation secret in plain text",
                    path.display()
                );
            }
        }
    }
}
