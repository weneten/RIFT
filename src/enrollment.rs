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
    anyhow::ensure!(
        !state
            .snapshot()?
            .agents
            .iter()
            .any(|agent| agent.name == name),
        "agent name already exists"
    );
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
    loop {
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
        tokio::spawn(async move {
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
            identity.welcome = Some(w.clone());
            Ok(w)
        }
        EnrollmentResponse::Error { message } => bail!("enrollment refused: {message}"),
    }
}

async fn server_addr(value: &str) -> Result<(String, Vec<SocketAddr>)> {
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
    let addresses: Vec<_> = timeout(
        Duration::from_secs(10),
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await??
    .collect();
    anyhow::ensure!(!addresses.is_empty(), "RIFT_SERVER did not resolve");
    Ok((host, addresses))
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
}
