//! Crash-safe automatic TLS material preparation for the enrollment endpoint.
//!
//! The JSON bundle is the durable source of truth for automatically generated CA and
//! server keys. The four PEM files are atomically materialized views consumed by rustls
//! and by the versioned invitation bundle.

use crate::config::Config;
use anyhow::{anyhow, bail, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::{
    client::{danger::ServerCertVerifier, WebPkiServerVerifier},
    pki_types::{ServerName, UnixTime},
    RootCertStore,
};
use serde::{Deserialize, Serialize};
use std::{
    io::BufReader,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

const BUNDLE_VERSION: u8 = 1;

#[derive(Serialize, Deserialize)]
struct TlsBundle {
    version: u8,
    ca_key_pem: String,
    ca_cert_pem: String,
    server_key_pem: String,
    server_cert_pem: String,
}

#[derive(Clone)]
struct MaterialPaths {
    bundle: PathBuf,
    ca_key: PathBuf,
    ca_cert: PathBuf,
    server_key: PathBuf,
    server_cert: PathBuf,
}

impl MaterialPaths {
    fn in_dir(dir: &Path) -> Self {
        Self {
            bundle: dir.join("tls-bundle.json"),
            ca_key: dir.join("tls-ca.key"),
            ca_cert: dir.join("tls-ca.crt"),
            server_key: dir.join("tls-server.key"),
            server_cert: dir.join("tls-server.crt"),
        }
    }

    fn derived(&self) -> [(&Path, &str, u32); 4] {
        [
            (&self.ca_key, "ca_key_pem", 0o600),
            (&self.ca_cert, "ca_cert_pem", 0o644),
            (&self.server_key, "server_key_pem", 0o600),
            (&self.server_cert, "server_cert_pem", 0o644),
        ]
    }
}

/// Prepare TLS file paths on `config`.
///
/// A complete external cert/key/CA trio is left untouched. A partially configured trio is
/// an error. With no external TLS paths, an automatic CA and leaf certificate are generated
/// once, durably committed to `tls-bundle.json`, then materialized idempotently to PEM files.
pub fn prepare(config: &mut Config) -> Result<()> {
    match (&config.tls_cert, &config.tls_key, &config.tls_ca) {
        (Some(_), Some(_), Some(_)) => return Ok(()),
        (None, None, None) => {}
        _ => bail!("configure tls_cert, tls_key, and tls_ca together, or leave all unset for automatic TLS material"),
    }

    ensure_state_dir(&config.state_dir)?;
    let paths = MaterialPaths::in_dir(&config.state_dir);

    let bundle = if path_is_file(&paths.bundle)? {
        read_bundle(&paths.bundle)?
    } else {
        let existing = existing_derived_count(&paths)?;
        if existing == 4 {
            // Upgrade a previous complete four-file installation only after validating its
            // CA, certificate chain, endpoint SAN, current validity, and TLS key pair.
            let adopted = bundle_from_files(&paths)?;
            validate_bundle(&adopted, &config.public_endpoint)?;
            create_bundle_once(&paths.bundle, &serde_json::to_vec(&adopted)?)?;
            read_bundle(&paths.bundle)?
        } else if existing != 0 {
            bail!("partial automatic TLS files exist without tls-bundle.json; preserving them rather than overwriting unknown material")
        } else {
            let generated = generate_bundle(&config.public_endpoint)?;
            validate_bundle(&generated, &config.public_endpoint)?;
            // Competing starts may both generate. create_once never replaces an existing
            // bundle; the loser loads and validates the winner below.
            create_bundle_once(&paths.bundle, &serde_json::to_vec(&generated)?)?;
            read_bundle(&paths.bundle)?
        }
    };

    let bundle = renew_if_needed(&paths, bundle, &config.public_endpoint)?;
    validate_bundle(&bundle, &config.public_endpoint)?;
    materialize(&paths, &bundle)?;
    config.tls_ca = Some(paths.ca_cert);
    config.tls_key = Some(paths.server_key);
    config.tls_cert = Some(paths.server_cert);
    Ok(())
}

fn ensure_state_dir(path: &Path) -> Result<()> {
    anyhow::ensure!(
        path != Path::new("/"),
        "TLS state directory cannot be the filesystem root"
    );
    std::fs::create_dir_all(path)
        .with_context(|| format!("create TLS state directory {}", path.display()))?;
    let meta = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        meta.file_type().is_dir(),
        "TLS state directory must be a real directory, not a symlink or file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn path_is_file(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            anyhow::ensure!(
                meta.file_type().is_file(),
                "{} must be a regular file, not a symlink",
                path.display()
            );
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn existing_derived_count(paths: &MaterialPaths) -> Result<usize> {
    let mut count = 0;
    for path in [
        &paths.ca_key,
        &paths.ca_cert,
        &paths.server_key,
        &paths.server_cert,
    ] {
        count += usize::from(path_is_file(path)?);
    }
    Ok(count)
}

fn read_bundle(path: &Path) -> Result<TlsBundle> {
    let bytes =
        std::fs::read(path).with_context(|| format!("read TLS bundle {}", path.display()))?;
    let bundle: TlsBundle = serde_json::from_slice(&bytes).context("parse automatic TLS bundle")?;
    anyhow::ensure!(
        bundle.version == BUNDLE_VERSION,
        "unsupported automatic TLS bundle version"
    );
    Ok(bundle)
}

fn bundle_from_files(paths: &MaterialPaths) -> Result<TlsBundle> {
    let read = |p: &Path| {
        std::fs::read_to_string(p).with_context(|| format!("read TLS material {}", p.display()))
    };
    Ok(TlsBundle {
        version: BUNDLE_VERSION,
        ca_key_pem: read(&paths.ca_key)?,
        ca_cert_pem: read(&paths.ca_cert)?,
        server_key_pem: read(&paths.server_key)?,
        server_cert_pem: read(&paths.server_cert)?,
    })
}

fn materialize(paths: &MaterialPaths, bundle: &TlsBundle) -> Result<()> {
    let contents = [
        bundle.ca_key_pem.as_str(),
        bundle.ca_cert_pem.as_str(),
        bundle.server_key_pem.as_str(),
        bundle.server_cert_pem.as_str(),
    ];
    for ((path, _, mode), expected) in paths.derived().into_iter().zip(contents) {
        match path_is_file(path)? {
            true => {
                let actual = std::fs::read(path)
                    .with_context(|| format!("read TLS material {}", path.display()))?;
                anyhow::ensure!(
                    actual == expected.as_bytes(),
                    "{} differs from tls-bundle.json; preserving existing material",
                    path.display()
                );
                set_file_mode(path, mode)?;
            }
            false => create_once(path, expected.as_bytes(), mode)?,
        }
    }
    sync_dir(
        paths
            .bundle
            .parent()
            .context("TLS bundle directory is missing")?,
    )?;
    Ok(())
}

/// Renews the automatic certificate if needed while the server runs; true when it did, so a
/// running enrollment listener must reload it. External TLS material is left alone.
pub fn refresh(config: &Config) -> Result<bool> {
    let paths = MaterialPaths::in_dir(&config.state_dir);
    if config.tls_cert.as_ref() != Some(&paths.server_cert) || !path_is_file(&paths.bundle)? {
        return Ok(false);
    }
    let bundle = read_bundle(&paths.bundle)?;
    let before = bundle.server_cert_pem.clone();
    Ok(renew_if_needed(&paths, bundle, &config.public_endpoint)?.server_cert_pem != before)
}

/// Days of validity left at which the automatic server certificate is renewed.
const RENEW_DAYS: i64 = 30;

/// Re-issues the automatic server certificate from the same CA when `public_endpoint` changed
/// (for example after a restore onto a server with a new name) or when it expires within
/// `RENEW_DAYS`. Agents trust the CA, which stays, so nothing changes for them.
fn renew_if_needed(
    paths: &MaterialPaths,
    bundle: TlsBundle,
    public_endpoint: &str,
) -> Result<TlsBundle> {
    let soon = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        UnixTime::now().as_secs() + RENEW_DAYS as u64 * 86400,
    ));
    if leaf_verifies(&bundle, public_endpoint, soon).unwrap_or(false) {
        return Ok(bundle);
    }
    let renewed = TlsBundle {
        server_key_pem: String::new(),
        server_cert_pem: String::new(),
        ..bundle
    };
    let renewed = issue_leaf(renewed, public_endpoint)?;
    validate_bundle(&renewed, public_endpoint)?;
    replace_file(&paths.bundle, &serde_json::to_vec(&renewed)?, 0o600)?;
    replace_file(&paths.server_key, renewed.server_key_pem.as_bytes(), 0o600)?;
    replace_file(
        &paths.server_cert,
        renewed.server_cert_pem.as_bytes(),
        0o644,
    )?;
    tracing::info!(
        "issued a new enrollment certificate for {public_endpoint} from the existing RIFT CA"
    );
    Ok(renewed)
}

/// Whether the bundle's server certificate verifies for `public_endpoint` at `at`.
fn leaf_verifies(bundle: &TlsBundle, public_endpoint: &str, at: UnixTime) -> Result<bool> {
    let ca = parse_certs(bundle.ca_cert_pem.as_bytes())?;
    let leaf = parse_certs(bundle.server_cert_pem.as_bytes())?;
    anyhow::ensure!(!ca.is_empty() && !leaf.is_empty(), "empty certificate");
    let mut roots = RootCertStore::empty();
    roots.add(ca[0].clone())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build()?;
    let host = endpoint_host(public_endpoint)?;
    let name = match host.parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(host).map_err(|_| anyhow!("invalid public_endpoint"))?,
    };
    Ok(verifier
        .verify_server_cert(&leaf[0], &leaf[1..], &name, &[], at)
        .is_ok())
}

fn ca_params() -> CertificateParams {
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "RIFT local enrollment CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params
}

/// A new server key and certificate for `public_endpoint`, signed with the bundle's CA key.
/// The issuer is rebuilt from the same name and key, so the stored CA certificate verifies it.
fn issue_leaf(bundle: TlsBundle, public_endpoint: &str) -> Result<TlsBundle> {
    let host = endpoint_host(public_endpoint)?;
    let now = time::OffsetDateTime::now_utc();
    let ca_key = KeyPair::from_pem(&bundle.ca_key_pem).context("parse automatic CA private key")?;
    let issuer = ca_params().self_signed(&ca_key)?;
    let mut leaf_params = CertificateParams::new(vec![host])?;
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = now - time::Duration::minutes(5);
    leaf_params.not_after = now + time::Duration::days(365);
    let leaf_key = KeyPair::generate()?;
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer, &ca_key)?;
    Ok(TlsBundle {
        server_key_pem: leaf_key.serialize_pem(),
        server_cert_pem: leaf_cert.pem(),
        ..bundle
    })
}

fn replace_file(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let tmp = path.with_extension("rift-tmp");
    let _ = std::fs::remove_file(&tmp);
    create_once(&tmp, data, mode)?;
    std::fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))?;
    sync_dir(path.parent().context("TLS file has no directory")?)
}

fn generate_bundle(public_endpoint: &str) -> Result<TlsBundle> {
    let now = time::OffsetDateTime::now_utc();
    let mut params = ca_params();
    params.not_before = now - time::Duration::minutes(5);
    params.not_after = now + time::Duration::days(365 * 10);
    let ca_key = KeyPair::generate()?;
    let ca_cert = params.self_signed(&ca_key)?;
    issue_leaf(
        TlsBundle {
            version: BUNDLE_VERSION,
            ca_key_pem: ca_key.serialize_pem(),
            ca_cert_pem: ca_cert.pem(),
            server_key_pem: String::new(),
            server_cert_pem: String::new(),
        },
        public_endpoint,
    )
}

fn endpoint_host(endpoint: &str) -> Result<String> {
    anyhow::ensure!(
        !endpoint.contains("://") && !endpoint.contains('/'),
        "public_endpoint must be a host or IP without scheme or path"
    );
    let host = if let Some(rest) = endpoint.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| anyhow!("invalid bracketed IPv6 public_endpoint"))?;
        rest[..close].to_string()
    } else if endpoint.parse::<IpAddr>().is_ok() {
        endpoint.to_string()
    } else {
        endpoint
            .split_once(':')
            .map(|(name, _)| name)
            .unwrap_or(endpoint)
            .to_string()
    };
    anyhow::ensure!(
        !host.is_empty(),
        "public_endpoint is required to issue a matching TLS certificate"
    );
    Ok(host)
}

fn validate_bundle(bundle: &TlsBundle, public_endpoint: &str) -> Result<()> {
    anyhow::ensure!(
        bundle.version == BUNDLE_VERSION,
        "unsupported automatic TLS bundle version"
    );
    let _ca_key =
        KeyPair::from_pem(&bundle.ca_key_pem).context("parse automatic CA private key")?;
    let ca_certs = parse_certs(bundle.ca_cert_pem.as_bytes())?;
    anyhow::ensure!(
        ca_certs.len() == 1,
        "automatic CA bundle must contain exactly one certificate"
    );
    let leaf_certs = parse_certs(bundle.server_cert_pem.as_bytes())?;
    anyhow::ensure!(
        !leaf_certs.is_empty(),
        "automatic server certificate is empty"
    );
    let leaf_key = parse_private_key(bundle.server_key_pem.as_bytes())?;

    // This config construction checks that the leaf private key matches the leaf certificate.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let _server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(leaf_certs.clone(), leaf_key)?;

    // Validate chain, endpoint SAN, and certificate time using rustls' ordinary verifier.
    let mut roots = RootCertStore::empty();
    roots.add(ca_certs[0].clone())?;
    let verifier =
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build()?;
    let host = endpoint_host(public_endpoint)?;
    let server_name = if let Ok(ip) = host.parse::<IpAddr>() {
        ServerName::IpAddress(ip.into())
    } else {
        ServerName::try_from(host).map_err(|_| anyhow!("invalid public_endpoint DNS name"))?
    };
    verifier.verify_server_cert(
        &leaf_certs[0],
        &leaf_certs[1..],
        &server_name,
        &[],
        UnixTime::now(),
    )?;
    Ok(())
}

/// Days until the enrollment certificate stops verifying for `public_endpoint` (negative once
/// it has), or `None` when there is no certificate yet. Uses the same verifier as enrollment.
pub fn days_left(config: &Config) -> Result<Option<i64>> {
    let paths = MaterialPaths::in_dir(&config.state_dir);
    let cert = config.tls_cert.clone().unwrap_or(paths.server_cert);
    let ca = config.tls_ca.clone().unwrap_or(paths.ca_cert);
    if !cert.exists() || !ca.exists() || config.public_endpoint.is_empty() {
        return Ok(None);
    }
    let leaf = parse_certs(&std::fs::read(&cert)?)?;
    let roots_pem = parse_certs(&std::fs::read(&ca)?)?;
    anyhow::ensure!(
        !leaf.is_empty() && !roots_pem.is_empty(),
        "empty certificate file"
    );
    let mut roots = RootCertStore::empty();
    for root in roots_pem {
        roots.add(root)?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build()?;
    let host = endpoint_host(&config.public_endpoint)?;
    let name = match host.parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(host).map_err(|_| anyhow!("invalid public_endpoint"))?,
    };
    let now = UnixTime::now().as_secs();
    let valid_after = |days: i64| {
        let at = now.saturating_add_signed(days * 86400);
        verifier
            .verify_server_cert(
                &leaf[0],
                &leaf[1..],
                &name,
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::from_secs(at)),
            )
            .is_ok()
    };
    if !valid_after(0) {
        return Ok(Some(-1));
    }
    // The largest day count that still verifies; certificates here last at most ten years.
    let (mut low, mut high) = (0i64, 3660i64);
    while low < high {
        let mid = (low + high + 1) / 2;
        if valid_after(mid) {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    Ok(Some(low))
}

fn parse_certs(pem: &[u8]) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut BufReader::new(pem))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse TLS certificate PEM")
}

fn parse_private_key(pem: &[u8]) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut BufReader::new(pem))?
        .ok_or_else(|| anyhow!("TLS private key PEM is empty"))
}

fn create_once(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("file path has no parent")?;
    let tmp = parent.join(format!(".rift-tls-{}.tmp", uuid::Uuid::new_v4()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options.open(&tmp)?;
    use std::io::Write;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    match std::fs::hard_link(&tmp, path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = std::fs::read(path)?;
            anyhow::ensure!(
                existing == data,
                "{} already exists with different contents; preserving it",
                path.display()
            );
        }
        Err(e) => return Err(e).with_context(|| format!("create TLS file {}", path.display())),
    }
    let _ = std::fs::remove_file(&tmp);
    set_file_mode(path, mode)?;
    sync_dir(parent)?;
    Ok(())
}

/// Atomically create the authoritative bundle if absent. If another start wins the race,
/// leave its bundle intact; the caller reads and validates that winner before materializing.
fn create_bundle_once(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().context("TLS bundle path has no parent")?;
    let tmp = parent.join(format!(".rift-tls-bundle-{}.tmp", uuid::Uuid::new_v4()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    use std::io::Write;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    match std::fs::hard_link(&tmp, path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("create TLS bundle {}", path.display())),
    }
    let _ = std::fs::remove_file(&tmp);
    set_file_mode(path, 0o600)?;
    sync_dir(parent)?;
    Ok(())
}

fn set_file_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    std::fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path; // Deployment durability guarantees target Linux directories.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn config(dir: &Path) -> Config {
        Config {
            state_dir: dir.to_path_buf(),
            public_endpoint: "localhost".into(),
            ..Config::default()
        }
    }

    #[test]
    fn the_ca_expiry_does_not_matter_only_the_server_certificate_does() {
        // rustls/webpki keep a trust anchor as name and key only, so agents enroll against a
        // CA past its end date as long as the server certificate is valid; that one renews
        // itself. The CA therefore never needs replacing.
        let now = time::OffsetDateTime::now_utc();
        let mut params = ca_params();
        params.not_before = now - time::Duration::days(4000);
        params.not_after = now - time::Duration::days(1);
        let ca_key = KeyPair::generate().unwrap();
        let expired_ca = issue_leaf(
            TlsBundle {
                version: BUNDLE_VERSION,
                ca_key_pem: ca_key.serialize_pem(),
                ca_cert_pem: params.self_signed(&ca_key).unwrap().pem(),
                server_key_pem: String::new(),
                server_cert_pem: String::new(),
            },
            "localhost",
        )
        .unwrap();
        validate_bundle(&expired_ca, "localhost").unwrap();
    }

    #[test]
    fn a_new_endpoint_gets_a_new_certificate_from_the_same_ca() {
        let temp = tempdir().unwrap();
        let mut first = config(temp.path());
        prepare(&mut first).unwrap();
        let ca = std::fs::read(first.tls_ca.as_ref().unwrap()).unwrap();
        let old_cert = std::fs::read(first.tls_cert.as_ref().unwrap()).unwrap();

        let mut moved = Config {
            public_endpoint: "rift.example.net".into(),
            ..config(temp.path())
        };
        prepare(&mut moved).unwrap();
        assert_eq!(
            std::fs::read(moved.tls_ca.as_ref().unwrap()).unwrap(),
            ca,
            "the CA stays"
        );
        assert_ne!(
            std::fs::read(moved.tls_cert.as_ref().unwrap()).unwrap(),
            old_cert
        );
        // The new certificate verifies against the CA agents already trust.
        assert!(days_left(&moved).unwrap().unwrap() >= 363);
        // A further start keeps it.
        let renewed = std::fs::read(moved.tls_cert.as_ref().unwrap()).unwrap();
        let mut again = Config {
            public_endpoint: "rift.example.net".into(),
            ..config(temp.path())
        };
        prepare(&mut again).unwrap();
        assert_eq!(std::fs::read(again.tls_cert.unwrap()).unwrap(), renewed);
    }

    #[test]
    fn the_generated_certificate_has_about_a_year_left() {
        let temp = tempdir().unwrap();
        assert_eq!(days_left(&config(temp.path())).unwrap(), None);
        let mut prepared = config(temp.path());
        prepare(&mut prepared).unwrap();
        // Both the automatic paths and the configured ones point at the same files.
        for cfg in [config(temp.path()), prepared] {
            let days = days_left(&cfg).unwrap().unwrap();
            assert!((363..=365).contains(&days), "{days}");
        }
    }

    #[test]
    fn bundle_recovers_missing_derived_files_without_rotating_keys() {
        let temp = tempdir().unwrap();
        let mut first = config(temp.path());
        prepare(&mut first).unwrap();
        let cert = std::fs::read(first.tls_cert.as_ref().unwrap()).unwrap();
        let ca = std::fs::read(first.tls_ca.as_ref().unwrap()).unwrap();
        std::fs::remove_file(first.tls_cert.unwrap()).unwrap();
        std::fs::remove_file(first.tls_ca.unwrap()).unwrap();

        let mut restarted = config(temp.path());
        prepare(&mut restarted).unwrap();
        assert_eq!(std::fs::read(restarted.tls_cert.unwrap()).unwrap(), cert);
        assert_eq!(std::fs::read(restarted.tls_ca.unwrap()).unwrap(), ca);
    }

    #[test]
    fn unknown_partial_files_without_bundle_are_preserved_and_rejected() {
        let temp = tempdir().unwrap();
        std::fs::create_dir_all(temp.path()).unwrap();
        let foreign_path = temp.path().join("tls-server.crt");
        let foreign = b"foreign certificate material";
        std::fs::write(&foreign_path, foreign).unwrap();

        let mut config = config(temp.path());
        let error = prepare(&mut config).unwrap_err();
        assert!(error.to_string().contains("without tls-bundle.json"));
        assert_eq!(std::fs::read(foreign_path).unwrap(), foreign);
    }

    #[test]
    fn conflicting_derived_file_is_not_overwritten_when_bundle_exists() {
        let temp = tempdir().unwrap();
        let mut initial = config(temp.path());
        prepare(&mut initial).unwrap();
        let cert_path = initial.tls_cert.unwrap();
        let foreign = b"unexpected replacement";
        std::fs::write(&cert_path, foreign).unwrap();

        let mut restarted = config(temp.path());
        assert!(prepare(&mut restarted).is_err());
        assert_eq!(std::fs::read(cert_path).unwrap(), foreign);
    }
}
