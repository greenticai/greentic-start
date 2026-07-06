//! Cloudflare quick-tunnel lifecycle against the machine-wide shared record
//! (see [`crate::tunnel_state`]).
//!
//! One tunnel per (machine, port): every boot first consults the shared
//! pidfile + URL cache under `~/.greentic/tunnel`, verifies the recorded
//! tunnel still serves, and only spawns when nothing healthy exists. Kills
//! are strictly pidfile-scoped — a cloudflared this code did not record is
//! never touched (no `pgrep`/`pkill`), so setup-owned tunnels and other
//! tenants' tunnels survive concurrent boots.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::runtime_state::{RuntimePaths, atomic_write};
use crate::supervisor::{self, ServiceId, ServiceSpec};
use crate::tunnel_state;

const SERVICE_ID: &str = "cloudflared";
const URL_SUFFIX: &str = ".trycloudflare.com";

/// How long a boot waits for another process racing through the
/// check-then-spawn critical section. Spawn + URL discovery hold the lock for
/// ~20s worst case.
const LOCK_WAIT: Duration = Duration::from_secs(45);

/// Probe budget when deciding whether a recorded tunnel still serves. Short
/// on purpose: a dead edge fails fast, and a false negative only costs a
/// restart (fresh URL), which is what pre-shared-record boots always did.
const REUSE_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct CloudflaredConfig {
    pub binary: PathBuf,
    pub local_port: u16,
    pub extra_args: Vec<String>,
    pub restart: bool,
}

pub struct CloudflaredHandle {
    pub url: String,
    pub pid: u32,
    pub log_path: PathBuf,
}

/// Acquire the shared quick tunnel for `config.local_port`: reuse the
/// recorded one when it is alive and reachable, otherwise spawn a fresh
/// cloudflared under the shared record. The caller's tenant-scoped
/// `public_base_url.txt` (under `paths`) is updated either way, so existing
/// readers (`startup_contract`, webhook updater) are unaffected.
pub fn start_quick_tunnel(
    paths: &RuntimePaths,
    config: &CloudflaredConfig,
) -> anyhow::Result<CloudflaredHandle> {
    let shared = tunnel_state::shared_runtime_paths(SERVICE_ID, config.local_port);
    let shared_pid_path = shared.pid_path(SERVICE_ID);
    let shared_url_path = public_url_path(&shared);
    let shared_log_path = shared.log_path(SERVICE_ID);
    let _lock = tunnel_state::TunnelLock::acquire(
        &tunnel_state::lock_path(SERVICE_ID, config.local_port),
        LOCK_WAIT,
    )?;

    adopt_legacy_record(paths, &shared_pid_path, &shared_url_path)?;

    if config.restart {
        let _ = supervisor::stop_pidfile(&shared_pid_path, 2_000);
        let _ = std::fs::remove_file(&shared_url_path);
    }

    // Reuse the recorded tunnel only when its process is alive AND its URL
    // still serves. A recorded-but-dead tunnel is ours (pidfile-owned), so
    // replacing it is safe.
    if let Ok(Some(pid)) = read_pid(&shared_pid_path)
        && supervisor::is_running(pid)
    {
        let recorded_url = match read_public_url(&shared_url_path)? {
            Some(url) => Some(url),
            None => discover_public_url(&shared_log_path, Duration::from_secs(10)).ok(),
        };
        if let Some(url) = recorded_url
            && probe_tunnel_alive(&url, REUSE_PROBE_TIMEOUT)
        {
            write_public_url(&shared_url_path, &url)?;
            mirror_public_url(paths, &url)?;
            return Ok(CloudflaredHandle {
                url,
                pid,
                log_path: shared_log_path,
            });
        }
        let _ = supervisor::stop_pidfile(&shared_pid_path, 2_000);
    }

    let _ = std::fs::remove_file(&shared_url_path);
    let _ = std::fs::remove_file(&shared_pid_path);
    if let Some(parent) = shared_log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Truncate: URL discovery must not read a previous tunnel's URL.
    let _ = std::fs::File::create(&shared_log_path);

    let mut argv = vec![
        config.binary.to_string_lossy().to_string(),
        "tunnel".to_string(),
        "--url".to_string(),
        format!("http://127.0.0.1:{}", config.local_port),
        "--no-autoupdate".to_string(),
    ];
    argv.extend(config.extra_args.iter().cloned());

    let spec = ServiceSpec {
        id: ServiceId::new(SERVICE_ID)?,
        argv,
        cwd: None,
        env: BTreeMap::new(),
    };
    let handle = supervisor::spawn_service(&shared, spec, Some(shared_log_path.clone()))?;
    let url = discover_public_url(&handle.log_path, Duration::from_secs(10))?;
    write_public_url(&shared_url_path, &url)?;
    mirror_public_url(paths, &url)?;
    Ok(CloudflaredHandle {
        url,
        pid: handle.pid,
        log_path: handle.log_path,
    })
}

/// Migrate a live tunnel recorded under the caller's pre-shared-record
/// namespace (`pids/<tenant>.<team>/cloudflared.pid`) into the shared record
/// instead of abandoning (or worse, racing) it. No-op when the shared record
/// already points at a live process or no legacy record exists.
fn adopt_legacy_record(
    paths: &RuntimePaths,
    shared_pid_path: &Path,
    shared_url_path: &Path,
) -> anyhow::Result<()> {
    if let Ok(Some(pid)) = read_pid(shared_pid_path)
        && supervisor::is_running(pid)
    {
        return Ok(());
    }
    let legacy_pid_path = paths.pid_path(SERVICE_ID);
    let Some(pid) = read_pid(&legacy_pid_path).unwrap_or(None) else {
        return Ok(());
    };
    if !supervisor::is_running(pid) {
        let _ = std::fs::remove_file(&legacy_pid_path);
        return Ok(());
    }
    if let Some(parent) = shared_pid_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    atomic_write(shared_pid_path, pid.to_string().as_bytes())?;
    if read_public_url(shared_url_path)?.is_none()
        && let Some(url) = read_public_url(&public_url_path(paths))?
    {
        write_public_url(shared_url_path, &url)?;
    }
    let _ = std::fs::remove_file(&legacy_pid_path);
    Ok(())
}

/// Copy the shared tunnel URL into the caller's tenant-scoped
/// `public_base_url.txt` so per-boot readers keep working.
fn mirror_public_url(paths: &RuntimePaths, url: &str) -> anyhow::Result<()> {
    let path = public_url_path(paths);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_public_url(&path, url)
}

/// Stop every shared cloudflared record (all ports) via its pidfile and clear
/// the cached URLs. Pidfile-scoped: processes this code did not record are
/// never touched. Returns the record keys that were consumed.
pub fn stop_shared_tunnels() -> Vec<String> {
    let mut stopped = Vec::new();
    for shared in tunnel_state::existing_shared_paths(SERVICE_ID) {
        let pid_path = shared.pid_path(SERVICE_ID);
        if pid_path.exists() && supervisor::stop_pidfile(&pid_path, 2_000).is_ok() {
            stopped.push(shared.key());
        }
        let _ = std::fs::remove_file(public_url_path(&shared));
    }
    stopped
}

/// One HEAD probe. `Ok(true)` = the edge routed to a live origin (2xx/3xx, or
/// any error status other than Cloudflare's 530 tunnel-down page — a 404 from
/// the origin still proves the tunnel works). `Ok(false)` = the edge answered
/// that the tunnel is down. `Err` = transport-level failure (DNS, TLS, ...).
fn head_probe(url: &str) -> Result<bool, Box<ureq::Error>> {
    match ureq::head(url).call() {
        Ok(_) => Ok(true),
        Err(ureq::Error::StatusCode(code)) => Ok(code != 530),
        Err(err) => Err(Box::new(err)),
    }
}

fn probe_tunnel_alive(url: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let mut attempt = 0u32;
    loop {
        if head_probe(url).unwrap_or(false) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        attempt += 1;
        let delay = Duration::from_millis(200 * 2u64.pow(attempt.min(3)));
        std::thread::sleep(delay.min(deadline.saturating_duration_since(Instant::now())));
    }
}

/// Verify the tunnel is reachable by making HTTP requests until one succeeds
/// or the timeout elapses.  Returns `Ok(())` on success, or an error if the
/// tunnel never became reachable within the deadline.
pub fn wait_tunnel_ready(url: &str, timeout: Duration) -> anyhow::Result<()> {
    if probe_tunnel_alive(url, timeout) {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "tunnel at {} not reachable after {:.0}s",
        url,
        timeout.as_secs_f64()
    ))
}

pub fn public_url_path(paths: &RuntimePaths) -> PathBuf {
    paths.runtime_root().join("public_base_url.txt")
}

pub fn parse_public_url(contents: &str) -> Option<String> {
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return None;
    }
    if is_clean_trycloudflare_url(trimmed) {
        return Some(trimmed.to_string());
    }
    find_url_in_text(contents)
}

fn read_public_url(path: &Path) -> anyhow::Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(path)?;
    Ok(parse_public_url(&contents))
}

fn write_public_url(path: &Path, url: &str) -> anyhow::Result<()> {
    atomic_write(path, url.as_bytes())
}

fn discover_public_url(log_path: &Path, timeout: Duration) -> anyhow::Result<String> {
    let deadline = Instant::now() + timeout;
    loop {
        if log_path.exists() {
            let contents = std::fs::read_to_string(log_path)?;
            if let Some(url) = find_url_in_text(&contents) {
                return Ok(url);
            }
        }
        if Instant::now() >= deadline {
            return Err(anyhow::anyhow!(
                "timed out waiting for cloudflared public URL in {}",
                log_path.display()
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn find_url_in_text(contents: &str) -> Option<String> {
    let mut offset = 0;
    while let Some(pos) = contents[offset..].find("https://") {
        let start = offset + pos;
        let tail = &contents[start..];
        let end_offset = tail.find(char::is_whitespace).unwrap_or(tail.len());
        let mut candidate = &contents[start..start + end_offset];
        candidate = candidate.trim_end_matches(|ch: char| {
            matches!(ch, ')' | ',' | '|' | '"' | '\'' | ']' | '>' | '<')
        });
        if candidate.ends_with(URL_SUFFIX) {
            return Some(candidate.to_string());
        }
        offset = start + "https://".len();
    }
    None
}

fn is_clean_trycloudflare_url(value: &str) -> bool {
    if !value.starts_with("https://") {
        return false;
    }
    if value.contains(char::is_whitespace) {
        return false;
    }
    value.ends_with(URL_SUFFIX)
}

fn read_pid(path: &Path) -> anyhow::Result<Option<u32>> {
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(path)?;
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed.parse()?))
}

/// Remove the cached public URL file so a fresh tunnel URL is discovered on
/// the next start.
pub fn cleanup_url_file(paths: &RuntimePaths) {
    let url_path = public_url_path(paths);
    let _ = std::fs::remove_file(&url_path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_state::RuntimePaths;
    use tempfile::tempdir;

    #[test]
    fn finds_trycloudflare_url_in_log_text() {
        let log = "INF Requesting new quick Tunnel on https://demo.trycloudflare.com";
        assert_eq!(
            find_url_in_text(log),
            Some("https://demo.trycloudflare.com".to_string())
        );
    }

    #[test]
    fn parse_public_url_accepts_clean_value_and_log_embedded_value() {
        assert_eq!(
            parse_public_url("https://demo.trycloudflare.com"),
            Some("https://demo.trycloudflare.com".to_string())
        );
        assert_eq!(
            parse_public_url("Created tunnel at https://demo.trycloudflare.com"),
            Some("https://demo.trycloudflare.com".to_string())
        );
        assert_eq!(parse_public_url(""), None);
    }

    #[test]
    fn clean_trycloudflare_url_requires_https_and_no_whitespace() {
        assert!(is_clean_trycloudflare_url("https://demo.trycloudflare.com"));
        assert!(!is_clean_trycloudflare_url("http://demo.trycloudflare.com"));
        assert!(!is_clean_trycloudflare_url(
            "https://demo.trycloudflare.com extra"
        ));
    }

    #[test]
    fn read_pid_and_public_url_handle_empty_and_missing_files() {
        let dir = tempdir().expect("tempdir");
        let pid_path = dir.path().join("cloudflared.pid");
        let url_path = dir.path().join("public_url.txt");

        assert_eq!(read_pid(&pid_path).expect("missing pid"), None);
        assert_eq!(read_public_url(&url_path).expect("missing url"), None);

        std::fs::write(&pid_path, " \n ").expect("empty pid");
        std::fs::write(&url_path, " \n ").expect("empty url");
        assert_eq!(read_pid(&pid_path).expect("empty pid"), None);
        assert_eq!(read_public_url(&url_path).expect("empty url"), None);
    }

    #[test]
    fn public_url_path_uses_runtime_root_and_write_roundtrips() {
        let dir = tempdir().expect("tempdir");
        let paths = RuntimePaths::new(dir.path().join("state"), "demo", "default");
        let url_path = public_url_path(&paths);
        assert_eq!(
            url_path,
            dir.path()
                .join("state")
                .join("runtime")
                .join("demo.default")
                .join("public_base_url.txt")
        );

        std::fs::create_dir_all(url_path.parent().expect("runtime dir")).expect("mkdir runtime");
        write_public_url(&url_path, "https://demo.trycloudflare.com").expect("write url");
        assert_eq!(
            read_public_url(&url_path).expect("read url"),
            Some("https://demo.trycloudflare.com".to_string())
        );
    }

    #[test]
    fn discover_public_url_times_out_when_no_url_is_present() {
        let dir = tempdir().expect("tempdir");
        let log_path = dir.path().join("cloudflared.log");
        std::fs::write(&log_path, "starting cloudflared without a url").expect("write log");

        let err = discover_public_url(&log_path, Duration::from_millis(1))
            .expect_err("missing url should time out");
        assert!(
            err.to_string()
                .contains("timed out waiting for cloudflared public URL")
        );
    }

    #[test]
    fn wait_tunnel_ready_returns_error_for_unreachable_url() {
        let err = wait_tunnel_ready("https://127.0.0.1:1", Duration::from_millis(200))
            .expect_err("unreachable URL should fail");
        assert!(err.to_string().contains("not reachable"));
    }

    #[test]
    fn adopt_legacy_record_moves_live_pid_and_url_into_shared_record() {
        let dir = tempdir().expect("tempdir");
        let legacy = RuntimePaths::new(dir.path().join("bundle-state"), "demo", "default");
        let shared = RuntimePaths::new(
            dir.path().join("tunnel").join("state"),
            "shared",
            "cloudflared-8080",
        );
        let shared_pid_path = shared.pid_path(SERVICE_ID);
        let shared_url_path = public_url_path(&shared);
        std::fs::create_dir_all(shared_url_path.parent().expect("runtime dir")).expect("mkdir");

        // A pid that is definitely alive: our own.
        let live_pid = std::process::id();
        let legacy_pid_path = legacy.pid_path(SERVICE_ID);
        std::fs::create_dir_all(legacy_pid_path.parent().expect("pids dir")).expect("mkdir");
        std::fs::write(&legacy_pid_path, live_pid.to_string()).expect("write legacy pid");
        let legacy_url_path = public_url_path(&legacy);
        std::fs::create_dir_all(legacy_url_path.parent().expect("runtime dir")).expect("mkdir");
        std::fs::write(&legacy_url_path, "https://demo.trycloudflare.com").expect("write url");

        adopt_legacy_record(&legacy, &shared_pid_path, &shared_url_path).expect("adopt");

        assert_eq!(
            read_pid(&shared_pid_path).expect("shared pid"),
            Some(live_pid)
        );
        assert_eq!(
            read_public_url(&shared_url_path).expect("shared url"),
            Some("https://demo.trycloudflare.com".to_string())
        );
        assert!(
            !legacy_pid_path.exists(),
            "legacy pidfile must be consumed on adoption"
        );
    }

    #[test]
    fn adopt_legacy_record_discards_dead_legacy_pid() {
        let dir = tempdir().expect("tempdir");
        let legacy = RuntimePaths::new(dir.path().join("bundle-state"), "demo", "default");
        let shared = RuntimePaths::new(
            dir.path().join("tunnel").join("state"),
            "shared",
            "cloudflared-8080",
        );
        let shared_pid_path = shared.pid_path(SERVICE_ID);
        let shared_url_path = public_url_path(&shared);

        let legacy_pid_path = legacy.pid_path(SERVICE_ID);
        std::fs::create_dir_all(legacy_pid_path.parent().expect("pids dir")).expect("mkdir");
        // u32::MAX is above every real pid_max — guaranteed not running.
        std::fs::write(&legacy_pid_path, u32::MAX.to_string()).expect("write legacy pid");

        adopt_legacy_record(&legacy, &shared_pid_path, &shared_url_path).expect("adopt");

        assert_eq!(read_pid(&shared_pid_path).expect("shared pid"), None);
        assert!(
            !legacy_pid_path.exists(),
            "dead legacy pidfile must be removed"
        );
    }

    #[test]
    fn mirror_public_url_creates_parent_dirs() {
        let dir = tempdir().expect("tempdir");
        let paths = RuntimePaths::new(dir.path().join("state"), "demo", "default");
        mirror_public_url(&paths, "https://demo.trycloudflare.com").expect("mirror");
        assert_eq!(
            read_public_url(&public_url_path(&paths)).expect("read"),
            Some("https://demo.trycloudflare.com".to_string())
        );
    }
}
