//! `rift backup`: the server state directory as one tar.gz stream.
//!
//! A live SQLite database in WAL mode cannot be copied as a file. `VACUUM INTO` writes a
//! consistent copy from one read transaction while the server keeps running; the other
//! files in the directory are written atomically and change rarely. The database copy is
//! taken first, so every key file a restored database refers to is in the archive too.
//!
//! Members are named `server/...`, so the host command can add its own parts next to them.

use crate::config::Config;
use anyhow::{bail, Context, Result};
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const STAGING: &str = ".backup-tmp";

/// Where the archive goes: a file, or standard output for `-`.
pub fn write(config: &Config, destination: Option<&Path>) -> Result<()> {
    let state_dir = &config.state_dir;
    let db = state_dir.join("state.db");
    if !db.exists() {
        bail!(
            "there is no state to back up in {}; run this where the RIFT server runs",
            state_dir.display()
        );
    }
    let staging = state_dir.join(STAGING);
    let _ = std::fs::remove_dir_all(&staging);
    create_private_dir(&staging)?;
    let result = archive(state_dir, &db, &staging, destination);
    let _ = std::fs::remove_dir_all(&staging);
    result
}

fn archive(state_dir: &Path, db: &Path, staging: &Path, destination: Option<&Path>) -> Result<()> {
    copy_database(db, &staging.join("state.db"))?;
    let (stdout, partial) = match destination {
        Some(path) if path != Path::new("-") => {
            let partial = partial_name(path);
            (Stdio::from(create_private_file(&partial)?), Some(partial))
        }
        _ => {
            use std::io::IsTerminal;
            if std::io::stdout().is_terminal() {
                bail!("refusing to write an archive to the terminal; give a file name or redirect the output");
            }
            (Stdio::inherit(), None)
        }
    };
    let status = Command::new("tar")
        .args(["--create", "--gzip", "--numeric-owner", "--anchored"])
        .args([
            "--exclude=./admin.sock",
            "--exclude=./state.db",
            "--exclude=./state.db-wal",
            "--exclude=./state.db-shm",
            "--exclude=./.backup-tmp",
            "--transform=s,^\\./,server/,",
            "--transform=s,^state\\.db$,server/state.db,",
        ])
        .arg("-C")
        .arg(state_dir)
        .arg(".")
        .arg("-C")
        .arg(staging)
        .arg("state.db")
        .stdout(stdout)
        .stderr(Stdio::inherit())
        .status()
        .context("run tar")?;
    // 1 means a file changed while it was read: the files are replaced atomically, so the
    // copy is still whole, but the operator should know.
    match status.code() {
        Some(0) => {}
        Some(1) => eprintln!("warning: a file in the state directory changed while it was read"),
        _ => {
            if let Some(partial) = &partial {
                let _ = std::fs::remove_file(partial);
            }
            bail!("tar failed ({status})");
        }
    }
    if let (Some(partial), Some(path)) = (partial, destination) {
        std::fs::rename(&partial, path).with_context(|| format!("write {}", path.display()))?;
    }
    Ok(())
}

/// A consistent copy of the running database.
fn copy_database(db: &Path, to: &Path) -> Result<()> {
    let connection = rusqlite::Connection::open(db)
        .with_context(|| format!("open state database {}", db.display()))?;
    connection.busy_timeout(std::time::Duration::from_secs(30))?;
    connection
        .execute("VACUUM INTO ?1", [to.to_string_lossy().as_ref()])
        .context("copy the state database")?;
    Ok(())
}

fn partial_name(path: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(".");
    name.push(path.file_name().unwrap_or_default());
    name.push(".partial");
    path.with_file_name(name)
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {}", path.display()))
}
#[cfg(not(unix))]
fn create_private_file(path: &Path) -> Result<std::fs::File> {
    std::fs::File::create(path).with_context(|| format!("create {}", path.display()))
}
#[cfg(unix)]
fn create_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .with_context(|| format!("create {}", path.display()))
}
#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir(path).with_context(|| format!("create {}", path.display()))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn the_archive_holds_a_consistent_database_and_the_key_files_but_no_socket() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        std::fs::create_dir_all(state.join("vpn")).unwrap();
        // A database in WAL mode with an open writer, as the server leaves it.
        let live = rusqlite::Connection::open(state.join("state.db")).unwrap();
        live.pragma_update(None, "journal_mode", "WAL").unwrap();
        live.execute_batch("CREATE TABLE t(v TEXT); INSERT INTO t VALUES('kept');")
            .unwrap();
        std::fs::write(state.join("wireguard.key"), "private").unwrap();
        std::fs::write(state.join("vpn/a.key"), "device").unwrap();
        let _socket = std::os::unix::net::UnixListener::bind(state.join("admin.sock")).unwrap();
        let config = Config {
            state_dir: state.clone(),
            ..Default::default()
        };
        let out = dir.path().join("backup.tar.gz");
        write(&config, Some(&out)).unwrap();
        assert!(!state.join(STAGING).exists(), "staging is cleaned up");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let restored = dir.path().join("restored");
        std::fs::create_dir(&restored).unwrap();
        let status = Command::new("tar")
            .arg("-xzf")
            .arg(&out)
            .arg("-C")
            .arg(&restored)
            .status()
            .unwrap();
        assert!(status.success());
        let server = restored.join("server");
        assert_eq!(
            std::fs::read_to_string(server.join("wireguard.key")).unwrap(),
            "private"
        );
        assert_eq!(
            std::fs::read_to_string(server.join("vpn/a.key")).unwrap(),
            "device"
        );
        assert!(!server.join("admin.sock").exists());
        assert!(!server.join("state.db-wal").exists());
        let copy = rusqlite::Connection::open(server.join("state.db")).unwrap();
        let value: String = copy.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(value, "kept");
    }

    #[test]
    fn a_missing_state_is_explained() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            state_dir: dir.path().to_path_buf(),
            ..Default::default()
        };
        let error = write(&config, Some(&dir.path().join("x.tar.gz"))).unwrap_err();
        assert!(error.to_string().contains("no state to back up"));
    }
}
