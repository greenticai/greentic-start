//! Machine-wide shared tunnel state.
//!
//! Quick tunnels (cloudflared, ngrok) front exactly one local port, so one
//! tunnel per (machine, service, port) is both necessary and sufficient.
//! Historically each boot arm kept its own pidfile namespace
//! (`pids/<tenant>.<team>/`, `pids/env.<env_id>/`) and greentic-setup kept no
//! record at all, so concurrent boots could not recognise each other's
//! tunnels and fell back to machine-wide `pkill`, killing healthy tunnels and
//! minting a fresh public URL every time. This module gives every process one
//! shared on-disk record to honour instead:
//!
//! - pidfile:   `<root>/state/pids/shared.<service>-<port>/<service>.pid`
//! - URL cache: `<root>/state/runtime/shared.<service>-<port>/public_base_url.txt`
//! - log:       `<root>/logs/shared.<service>-<port>/<service>.log`
//! - spawn lock: `<root>/state/<service>-<port>.lock`
//!
//! `<root>` is `~/.greentic/tunnel` (override: `GREENTIC_TUNNEL_STATE_DIR`).
//! The layout reuses [`RuntimePaths`] with tenant `shared` and team
//! `<service>-<port>`, so the supervisor's pidfile plumbing works unchanged.
//! greentic-setup implements the same file protocol (it does not depend on
//! this crate); changing these paths is a cross-repo protocol change.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::runtime_state::RuntimePaths;

/// Tenant slot of shared tunnel records. Never collides with bundle-rooted
/// `<tenant>.<team>` keys (those live under a bundle's own state dir) or
/// env-rooted `env.<env_id>` keys.
const SHARED_TENANT: &str = "shared";

/// A lock file untouched for this long belongs to a crashed process and may
/// be reclaimed. Spawn + URL discovery + reuse probing hold the lock for well
/// under a minute.
const LOCK_STALE_AFTER: Duration = Duration::from_secs(120);

/// Root of the shared tunnel state tree: `$GREENTIC_TUNNEL_STATE_DIR` or
/// `~/.greentic/tunnel`.
pub(crate) fn tunnel_state_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("GREENTIC_TUNNEL_STATE_DIR") {
        return PathBuf::from(dir);
    }
    home_dir().join(".greentic").join("tunnel")
}

fn home_dir() -> PathBuf {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

fn state_dir(root: &Path) -> PathBuf {
    root.join("state")
}

fn shared_key(service: &str, port: u16) -> String {
    format!("{service}-{port}")
}

/// [`RuntimePaths`] for the shared record of `service` fronting `port`.
pub(crate) fn shared_runtime_paths(service: &str, port: u16) -> RuntimePaths {
    shared_runtime_paths_at(&tunnel_state_root(), service, port)
}

fn shared_runtime_paths_at(root: &Path, service: &str, port: u16) -> RuntimePaths {
    RuntimePaths::new(state_dir(root), SHARED_TENANT, shared_key(service, port))
}

/// Lock file guarding the check-then-spawn critical section for `service` on
/// `port`, so two racing boots cannot double-spawn a tunnel.
pub(crate) fn lock_path(service: &str, port: u16) -> PathBuf {
    state_dir(&tunnel_state_root()).join(format!("{}.lock", shared_key(service, port)))
}

/// Every existing shared record for `service`, across all ports. Used by stop
/// paths, which run without knowledge of the port the tunnel was keyed on.
pub(crate) fn existing_shared_paths(service: &str) -> Vec<RuntimePaths> {
    existing_shared_records(service)
        .into_iter()
        .map(|(_, paths)| paths)
        .collect()
}

/// Every existing shared record for `service`, paired with the local port it
/// fronts, ordered by port. Callers that must reason across ports — rather than
/// look one up — need the port back: a tunnel whose public identity is NOT its
/// port (gtunnel, keyed by tunnel id) can be claimed by records under several
/// ports at once, and only one of them may hold it. See
/// `gtunnel::evict_foreign_claimants`.
pub(crate) fn existing_shared_records(service: &str) -> Vec<(u16, RuntimePaths)> {
    existing_shared_records_at(&tunnel_state_root(), service)
}

fn existing_shared_records_at(root: &Path, service: &str) -> Vec<(u16, RuntimePaths)> {
    let pids_root = state_dir(root).join("pids");
    let prefix = format!("{SHARED_TENANT}.{service}-");
    let Ok(entries) = std::fs::read_dir(&pids_root) else {
        return Vec::new();
    };
    let mut records = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        // Require the suffix to parse as a port. A bare prefix match would also
        // accept a longer service name sharing this prefix (`gtunnel-agent-…`).
        let Some(port) = name
            .strip_prefix(&prefix)
            .and_then(|port| port.parse::<u16>().ok())
        else {
            continue;
        };
        records.push((
            port,
            RuntimePaths::new(state_dir(root), SHARED_TENANT, shared_key(service, port)),
        ));
    }
    records.sort_by_key(|(port, _)| *port);
    records
}

/// Advisory file lock: exists while held, reclaimed when stale. Dropping
/// releases it.
#[derive(Debug)]
pub(crate) struct TunnelLock {
    path: PathBuf,
}

impl TunnelLock {
    pub(crate) fn acquire(path: &Path, wait: Duration) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let deadline = Instant::now() + wait;
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
            {
                Ok(mut file) => {
                    let _ = write!(file, "{}", std::process::id());
                    return Ok(Self {
                        path: path.to_path_buf(),
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    if lock_is_stale(path) {
                        let _ = std::fs::remove_file(path);
                        continue;
                    }
                    if Instant::now() >= deadline {
                        return Err(anyhow::anyhow!(
                            "timed out waiting for tunnel spawn lock {} (remove it if no other greentic process is starting a tunnel)",
                            path.display()
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(err) => return Err(err.into()),
            }
        }
    }
}

fn lock_is_stale(path: &Path) -> bool {
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .is_some_and(|age| age > LOCK_STALE_AFTER)
}

impl Drop for TunnelLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn shared_paths_key_by_service_and_port() {
        let paths = shared_runtime_paths_at(Path::new("/tunnel-root"), "cloudflared", 8443);
        assert_eq!(
            paths.pid_path("cloudflared"),
            Path::new("/tunnel-root/state/pids/shared.cloudflared-8443/cloudflared.pid")
        );
        assert_eq!(
            paths.log_path("cloudflared"),
            Path::new("/tunnel-root/logs/shared.cloudflared-8443/cloudflared.log")
        );
    }

    #[test]
    fn shared_records_return_ports_and_ignore_non_port_keys() {
        let dir = tempdir().expect("tempdir");
        let pids = dir.path().join("state").join("pids");
        for key in [
            "shared.gtunnel-8080",
            "shared.gtunnel-55662",
            // Not this service.
            "shared.cloudflared-8080",
            // Prefix-matches `gtunnel-` but is not a port.
            "shared.gtunnel-agent",
            // Not a shared record at all.
            "default.default",
        ] {
            std::fs::create_dir_all(pids.join(key)).expect("mkdir");
        }

        let records = existing_shared_records_at(dir.path(), "gtunnel");

        let ports: Vec<u16> = records.iter().map(|(port, _)| *port).collect();
        assert_eq!(ports, vec![8080, 55662], "ports parsed and sorted");
        assert_eq!(
            records[0].1.pid_path("gtunnel"),
            dir.path()
                .join("state/pids/shared.gtunnel-8080/gtunnel.pid")
        );
    }

    #[test]
    fn lock_acquire_release_and_contention() {
        let dir = tempdir().expect("tempdir");
        let lock_path = dir.path().join("cloudflared-8080.lock");

        let lock = TunnelLock::acquire(&lock_path, Duration::from_millis(50)).expect("acquire");
        assert!(lock_path.exists());

        let err = TunnelLock::acquire(&lock_path, Duration::from_millis(120))
            .expect_err("second acquire must time out while held");
        assert!(err.to_string().contains("tunnel spawn lock"));

        drop(lock);
        assert!(!lock_path.exists(), "drop must release the lock");
        let _relock =
            TunnelLock::acquire(&lock_path, Duration::from_millis(50)).expect("reacquire");
    }

    #[test]
    fn stale_lock_is_reclaimed() {
        let dir = tempdir().expect("tempdir");
        let lock_path = dir.path().join("cloudflared-8080.lock");
        std::fs::write(&lock_path, "12345").expect("plant lock");
        let stale = std::time::SystemTime::now() - (LOCK_STALE_AFTER + Duration::from_secs(60));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&lock_path)
            .expect("open lock");
        file.set_modified(stale).expect("age lock");
        drop(file);

        let _lock = TunnelLock::acquire(&lock_path, Duration::from_millis(50))
            .expect("stale lock must be reclaimed");
    }
}
