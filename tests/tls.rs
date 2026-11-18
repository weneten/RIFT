use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rift::{
    config::Config,
    enrollment,
    model::AgentIdentity,
    protocol::{self, EnrollmentRequest, EnrollmentResponse},
};
use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tempfile::TempDir;
use tokio::{net::TcpListener, time::timeout};
use tokio_rustls::TlsAcceptor;

const TEST_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Serialize)]
struct InviteBundle<'a> {
    version: u8,
    secret: String,
    ca_pem: &'a str,
}

struct CertFiles {
    _dir: TempDir,
    cert: PathBuf,
    key: PathBuf,
    ca_path: PathBuf,
    ca: String,
}

fn cert_files(ca_label: &str, sans: Vec<String>, expired: bool) -> Result<CertFiles> {
    let dir = tempfile::tempdir()?;
    let mut root_params = CertificateParams::default();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    root_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, ca_label);
    root_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    root_params.not_after = rcgen::date_time_ymd(2040, 1, 1);
    let root_key = KeyPair::generate()?;
    let root_cert = root_params.self_signed(&root_key)?;

    let mut leaf_params = CertificateParams::new(sans)?;
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    if expired {
        leaf_params.not_before = rcgen::date_time_ymd(2018, 1, 1);
        leaf_params.not_after = rcgen::date_time_ymd(2020, 1, 1);
    } else {
        leaf_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        leaf_params.not_after = rcgen::date_time_ymd(2030, 1, 1);
    }
    let leaf_key = KeyPair::generate()?;
    let leaf_cert = leaf_params.signed_by(&leaf_key, &root_cert, &root_key)?;

    let cert = dir.path().join("server.crt");
    let key = dir.path().join("server.key");
    let ca_path = dir.path().join("ca.crt");
    let ca = root_cert.pem();
    std::fs::write(&cert, leaf_cert.pem())?;
    std::fs::write(&key, leaf_key.serialize_pem())?;
    std::fs::write(&ca_path, &ca)?;
    Ok(CertFiles {
        _dir: dir,
        cert,
        key,
        ca_path,
        ca,
    })
}

fn invite(ca_pem: &str) -> Result<String> {
    let payload = InviteBundle {
        version: 1,
        secret: URL_SAFE_NO_PAD.encode([0xA7; 32]),
        ca_pem,
    };
    Ok(format!(
        "v1.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?)
    ))
}

fn server_config(files: &CertFiles) -> Config {
    Config {
        tls_cert: Some(files.cert.clone()),
        tls_key: Some(files.key.clone()),
        tls_ca: Some(files.ca_path.clone()),
        ..Config::default()
    }
}

fn agent_config(address: String, token: String) -> Config {
    Config {
        agent_name: Some("tls-test-agent".into()),
        server_address: Some(address),
        enrollment_token: Some(token),
        ..Config::default()
    }
}

/// Minimal frame handler for transport tests. Counting a decoded request marks the point at
/// which the application token handler would begin; this intentionally does not emulate state,
/// Kernel, or a successful enrollment.
async fn test_frame_handler(
    listener: TcpListener,
    config: Config,
    decoded_requests: Arc<AtomicUsize>,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(enrollment::server_tls(&config)?);
    timeout(TEST_DEADLINE, async move {
        let (tcp, _) = listener.accept().await?;
        let Ok(mut tls) = acceptor.accept(tcp).await else {
            return Ok::<_, anyhow::Error>(());
        };
        let Ok(_request) = protocol::receive::<EnrollmentRequest, _>(&mut tls).await else {
            return Ok(());
        };
        decoded_requests.fetch_add(1, Ordering::SeqCst);
        protocol::send(
            &mut tls,
            &EnrollmentResponse::Error {
                message: "test handler reached".into(),
            },
        )
        .await?;
        Ok(())
    })
    .await
    .map_err(|_| anyhow!("test TLS handler deadline exceeded"))??;
    Ok(())
}

/// Dual-stack so that `localhost` works whichever family it resolves to first. A host without
/// IPv6 (some CI containers) falls back to IPv4 loopback; the TLS checks are the same there.
fn dual_stack_listener() -> Result<TcpListener> {
    let socket = match Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)) {
        Ok(socket) => socket,
        Err(error) if error.raw_os_error() == Some(libc::EAFNOSUPPORT) => {
            eprintln!("no IPv6 on this host; testing over IPv4 loopback only");
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            listener.set_nonblocking(true)?;
            return Ok(TcpListener::from_std(listener)?);
        }
        Err(error) => return Err(error.into()),
    };
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&"[::]:0".parse::<SocketAddr>()?.into())?;
    socket.listen(16)?;
    Ok(TcpListener::from_std(socket.into())?)
}

async fn run_case(
    server: CertFiles,
    token_ca: String,
    address_name: &str,
) -> Result<(Result<rift::model::Welcome, String>, usize)> {
    let listener = dual_stack_listener()?;
    let address: SocketAddr = listener.local_addr()?;
    let server_cfg = server_config(&server);
    let seen = Arc::new(AtomicUsize::new(0));
    let handler_seen = seen.clone();
    let handler = tokio::spawn(test_frame_handler(listener, server_cfg, handler_seen));
    let agent_cfg = agent_config(
        format!("{address_name}:{}", address.port()),
        invite(&token_ca)?,
    );
    let mut identity = AgentIdentity {
        version: rift::model::IDENTITY_VERSION,
        id: uuid::Uuid::new_v4().to_string(),
        attempt_id: uuid::Uuid::new_v4().to_string(),
        public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        welcome: None,
        active: false,
        applied_generation: 0,
        server_ca: None,
    };
    let response = timeout(
        TEST_DEADLINE,
        enrollment::enroll_agent(&agent_cfg, &mut identity),
    )
    .await
    .map_err(|_| anyhow!("enroll_agent TLS deadline exceeded"))?;
    timeout(TEST_DEADLINE, handler)
        .await
        .map_err(|_| anyhow!("test TLS handler did not finish"))??
        .context("test TLS handler failed")?;
    let seen = seen.load(Ordering::SeqCst);
    let mapped = match response {
        Ok(welcome) => Ok(welcome),
        Err(error) => Err(error.to_string()),
    };
    Ok((mapped, seen))
}

#[tokio::test]
async fn valid_ca_and_dns_or_ip_san_reach_the_enrollment_frame_handler() -> Result<()> {
    for address_name in ["localhost", "127.0.0.1"] {
        let server = cert_files(
            "RIFT TLS integration test root",
            vec!["localhost".into(), "127.0.0.1".into()],
            false,
        )?;
        let ca = server.ca.clone();
        let (response, seen) = run_case(server, ca, address_name).await?;
        let error = response.expect_err("test frame handler should reject the enrollment request");
        assert!(
            error.contains("test handler reached"),
            "unexpected error: {error}"
        );
        assert_eq!(seen, 1, "valid TLS must reach the decoded enrollment frame");
    }
    Ok(())
}

#[tokio::test]
async fn wrong_ca_wrong_hostname_and_expired_certificate_are_rejected_before_enrollment(
) -> Result<()> {
    // An unrelated trust anchor must fail chain validation before any enrollment frame is read.
    let server = cert_files("server root", vec!["localhost".into()], false)?;
    let wrong_ca = cert_files("different root", vec!["localhost".into()], false)?.ca;
    let (response, seen) = run_case(server, wrong_ca, "localhost").await?;
    assert!(response.is_err());
    assert_eq!(seen, 0);

    // The certificate is trusted, but its DNS SAN does not cover the IP address in RIFT_SERVER.
    let server = cert_files("server root", vec!["localhost".into()], false)?;
    let ca = server.ca.clone();
    let (response, seen) = run_case(server, ca, "127.0.0.1").await?;
    assert!(response.is_err());
    assert_eq!(seen, 0);

    // A valid chain and SAN still fail the normal TLS validity-time check for an expired leaf.
    let server = cert_files("server root", vec!["localhost".into()], true)?;
    let ca = server.ca.clone();
    let (response, seen) = run_case(server, ca, "localhost").await?;
    assert!(response.is_err());
    assert_eq!(seen, 0);
    Ok(())
}
