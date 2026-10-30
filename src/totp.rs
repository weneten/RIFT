//! Time-based one-time passwords (RFC 6238: SHA-1, 6 digits, 30 s steps) for the web panel's
//! second login factor, and the state around them.
//!
//! The confirmed secret lives in `webpanel.totp` in the state directory; two-factor login is on
//! exactly while that file exists. A secret that is shown but not yet confirmed exists only in
//! memory. The CLI and the panel share one [`TwoFactor`].

use crate::config::Config;
use anyhow::{bail, ensure, Context, Result};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

const STEP_SECONDS: i64 = 30;
const DIGITS: u32 = 6;
const SECRET_BYTES: usize = 20;
/// Consecutive failed logins that lock every login out.
pub const MAX_FAILURES: u32 = 10;
pub const LOCKOUT_SECONDS: i64 = 15 * 60;
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for byte in data {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[((buffer >> bits) & 31) as usize] as char);
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Decodes base32 in either case; spaces and `=` padding are ignored.
pub fn base32_decode(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for c in text.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let value = BASE32
            .iter()
            .position(|b| *b as char == c.to_ascii_uppercase())
            .with_context(|| format!("{c:?} is not a base32 character"))?;
        buffer = (buffer << 5) | value as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = (hash[19] & 0xf) as usize;
    let value = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    value % 10u32.pow(digits)
}

/// The 6-digit code for a 30-second step (`unix time / 30`).
pub fn code_at(secret: &[u8], step: u64) -> u32 {
    hotp(secret, step, DIGITS)
}

pub fn step_at(unix: i64) -> u64 {
    (unix.max(0) / STEP_SECONDS) as u64
}

/// The step `code` is valid for among the current one and its neighbours, if it is newer than
/// `last_used`. Replays of an accepted step are refused.
pub fn verify(secret: &[u8], code: &str, now_step: u64, last_used: Option<u64>) -> Option<u64> {
    let code = code.trim().replace(' ', "");
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut found = None;
    // Check every step, so the timing does not show which one matched.
    for step in now_step.saturating_sub(1)..=now_step + 1 {
        let expected = format!("{:06}", code_at(secret, step));
        let equal = expected
            .bytes()
            .zip(code.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
        if equal && last_used.is_none_or(|last| step > last) {
            found = Some(step);
        }
    }
    found
}

/// The `otpauth://` link authenticator apps import (also what the QR code holds).
pub fn uri(secret: &[u8], host: &str) -> String {
    let label: String = host
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b':' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect();
    format!(
        "otpauth://totp/RIFT:{label}?secret={}&issuer=RIFT&algorithm=SHA1&digits=6&period=30",
        base32_encode(secret)
    )
}

pub fn path(config: &Config) -> PathBuf {
    config.state_dir.join("webpanel.totp")
}

/// The label for a new secret in the authenticator app.
pub fn host(config: &Config) -> &str {
    if config.public_endpoint.is_empty() {
        "server"
    } else {
        &config.public_endpoint
    }
}

pub struct Setup {
    pub secret: String,
    pub uri: String,
}

#[derive(Default)]
struct Inner {
    pending: Option<Vec<u8>>,
    last_step: Option<u64>,
    failures: u32,
    locked_until: i64,
}

/// Second-factor state shared by the panel and the admin socket.
pub struct TwoFactor {
    path: PathBuf,
    inner: Mutex<Inner>,
    /// Bumped whenever sessions must end; the panel drops its sessions when it changes.
    epoch: AtomicU64,
}

impl TwoFactor {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            inner: Default::default(),
            epoch: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn enabled(&self) -> bool {
        self.path.exists()
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    fn secret(&self) -> Result<Vec<u8>> {
        let text = std::fs::read_to_string(&self.path).context("read the two-factor secret")?;
        base32_decode(text.trim())
    }

    /// Replaces any pending secret with a new one. Refused while two-factor login is on.
    pub fn setup(&self, host: &str) -> Result<Setup> {
        ensure!(
            !self.enabled(),
            "two-factor login is already on; reset it first (`rift panel 2fa reset`)"
        );
        use rand::{rngs::OsRng, RngCore};
        let mut secret = vec![0u8; SECRET_BYTES];
        OsRng.fill_bytes(&mut secret);
        let setup = Setup {
            secret: base32_encode(&secret),
            uri: uri(&secret, host),
        };
        self.lock().pending = Some(secret);
        Ok(setup)
    }

    /// Turns two-factor login on if `code` matches the pending secret.
    pub fn confirm(&self, code: &str, now: i64) -> Result<()> {
        let mut inner = self.lock();
        let Some(secret) = inner.pending.clone() else {
            bail!("no setup in progress; start with `rift panel 2fa setup`");
        };
        let Some(step) = verify(&secret, code, step_at(now), inner.last_step) else {
            bail!("wrong code");
        };
        crate::daemon::atomic_write(
            &self.path,
            format!("{}\n", base32_encode(&secret)).as_bytes(),
            0o600,
        )
        .context("store the two-factor secret")?;
        inner.pending = None;
        inner.last_step = Some(step);
        Ok(())
    }

    /// Checks a login code against the confirmed secret and uses its step up.
    pub fn verify_login(&self, code: &str, now: i64) -> bool {
        let Ok(secret) = self.secret() else {
            return false;
        };
        let mut inner = self.lock();
        match verify(&secret, code, step_at(now), inner.last_step) {
            Some(step) => {
                inner.last_step = Some(step);
                true
            }
            None => false,
        }
    }

    /// Turns two-factor login off after a valid code, and ends all sessions.
    pub fn disable(&self, code: &str, now: i64) -> Result<()> {
        ensure!(self.enabled(), "two-factor login is not on");
        ensure!(self.verify_login(code, now), "wrong code");
        self.reset()
    }

    /// Deletes the secret and any pending one, and ends all sessions.
    pub fn reset(&self) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context("delete the two-factor secret"),
        }
        let mut inner = self.lock();
        inner.pending = None;
        inner.last_step = None;
        self.epoch.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    pub fn locked(&self, now: i64) -> bool {
        self.lock().locked_until > now
    }

    /// Counts a failed login; returns true when it triggered the lockout.
    pub fn failed(&self, now: i64) -> bool {
        let mut inner = self.lock();
        inner.failures += 1;
        if inner.failures >= MAX_FAILURES {
            inner.failures = 0;
            inner.locked_until = now + LOCKOUT_SECONDS;
            return true;
        }
        false
    }

    pub fn succeeded(&self) {
        self.lock().failures = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC: &[u8] = b"12345678901234567890";

    fn code(secret: &[u8], step: u64) -> String {
        format!("{:06}", code_at(secret, step))
    }

    #[test]
    fn matches_the_rfc_6238_sha1_vectors() {
        for (time, expected) in [
            (59u64, 94287082u32),
            (1111111109, 7081804),
            (1111111111, 14050471),
            (1234567890, 89005924),
            (2000000000, 69279037),
            (20000000000, 65353130),
        ] {
            assert_eq!(hotp(RFC, time / 30, 8), expected, "T={time}");
            // The 6-digit code is the last six digits.
            assert_eq!(code_at(RFC, time / 30), expected % 1_000_000, "T={time}");
        }
        assert_eq!(code_at(RFC, 1), 287082);
    }

    #[test]
    fn base32_round_trips_and_matches_rfc_4648() {
        for (plain, coded) in [
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32_encode(plain.as_bytes()), coded);
            assert_eq!(base32_decode(coded).unwrap(), plain.as_bytes());
        }
        assert_eq!(base32_decode("mzxw 6ytb=").unwrap(), b"fooba");
        assert!(base32_decode("MZXW1").is_err());
        let secret: Vec<u8> = (0..=255).collect();
        assert_eq!(base32_decode(&base32_encode(&secret)).unwrap(), secret);
    }

    #[test]
    fn accepts_the_neighbouring_steps_only() {
        let now = 1000;
        for (step, ok) in [
            (now - 2, false),
            (now - 1, true),
            (now, true),
            (now + 1, true),
            (now + 2, false),
        ] {
            assert_eq!(
                verify(RFC, &code(RFC, step), now, None).is_some(),
                ok,
                "step {step}"
            );
        }
        assert!(verify(RFC, "12345", now, None).is_none());
        assert!(verify(RFC, "abcdef", now, None).is_none());
        let spaced = code(RFC, now);
        let spaced = format!(" {} {} ", &spaced[..3], &spaced[3..]);
        assert!(verify(RFC, &spaced, now, None).is_some());
    }

    #[test]
    fn a_used_step_and_older_ones_are_refused() {
        let now = 1000;
        let current = code(RFC, now);
        assert_eq!(verify(RFC, &current, now, None), Some(now));
        assert_eq!(verify(RFC, &current, now, Some(now)), None);
        assert_eq!(verify(RFC, &code(RFC, now - 1), now, Some(now)), None);
        assert_eq!(
            verify(RFC, &code(RFC, now + 1), now, Some(now)),
            Some(now + 1)
        );
    }

    #[test]
    fn the_uri_carries_the_secret_and_a_safe_label() {
        assert_eq!(
            uri(RFC, "rift.example.net:8443"),
            "otpauth://totp/RIFT:rift.example.net:8443?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=RIFT&algorithm=SHA1&digits=6&period=30"
        );
        assert!(uri(RFC, "a b&c").contains("RIFT:a%20b%26c?"));
    }

    #[test]
    fn setup_confirm_login_and_disable() {
        let dir = tempfile::tempdir().unwrap();
        let tf = TwoFactor::new(dir.path().join("webpanel.totp"));
        let now = 30_000;
        assert!(!tf.enabled());
        assert!(tf.confirm("000000", now).is_err(), "nothing pending");
        let setup = tf.setup("server").unwrap();
        let secret = base32_decode(&setup.secret).unwrap();
        assert!(setup.uri.contains(&setup.secret));
        assert!(tf.confirm("000000", now).is_err());
        assert!(!tf.enabled(), "a wrong code enables nothing");
        let first = code(&secret, step_at(now));
        tf.confirm(&first, now).unwrap();
        assert!(tf.enabled());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("webpanel.totp"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(tf.setup("server").is_err(), "reset first");
        // The code that enabled it cannot log in again; the next step's can.
        assert!(!tf.verify_login(&first, now));
        assert!(tf.verify_login(&code(&secret, step_at(now) + 1), now));
        let epoch = tf.epoch();
        assert!(tf.disable("000000", now + 60).is_err());
        tf.disable(&code(&secret, step_at(now) + 2), now + 60)
            .unwrap();
        assert!(!tf.enabled());
        assert!(tf.epoch() > epoch);
        tf.reset().unwrap();
    }

    #[test]
    fn ten_failures_lock_logins_for_fifteen_minutes() {
        let tf = TwoFactor::new(PathBuf::from("/nonexistent/webpanel.totp"));
        for _ in 0..MAX_FAILURES - 1 {
            assert!(!tf.failed(100));
        }
        tf.succeeded();
        for _ in 0..MAX_FAILURES - 1 {
            assert!(!tf.failed(100));
        }
        assert!(!tf.locked(100));
        assert!(tf.failed(100));
        assert!(tf.locked(100 + LOCKOUT_SECONDS - 1));
        assert!(!tf.locked(100 + LOCKOUT_SECONDS));
    }
}
