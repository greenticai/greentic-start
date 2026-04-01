use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::runtime_state::{RuntimePaths, atomic_write};
use crate::supervisor::{self, ServiceId, ServiceSpec};

const SERVICE_ID: &str = "cloudflared";
const URL_SUFFIX: &str = ".trycloudflare.com";

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

pub fn start_quick_tunnel(
    paths: &RuntimePaths,
    config: &CloudflaredConfig,
    log_path: &Path,
) -> anyhow::Result<CloudflaredHandle> {
    let pid_path = paths.pid_path(SERVICE_ID);
    let url_path = public_url_path(paths);
    if config.restart {
        let _ = supervisor::stop_pidfile(&pid_path, 2_000);
    }

    if let Some(pid) = read_pid(&pid_path)?
        && supervisor::is_running(pid)
    {
        let log_path_buf = log_path.to_path_buf();
        if let Some(url) = read_public_url(&url_path)? {
            return Ok(CloudflaredHandle {
                url,
                pid,
                log_path: log_path_buf.clone(),
            });
        }
        let url = discover_public_url(&log_path_buf, Duration::from_secs(10))?;
        write_public_url(&url_path, &url)?;
        return Ok(CloudflaredHandle {
            url,
            pid,
            log_path: log_path_buf,
        });
    }

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
    let log_path_buf = log_path.to_path_buf();
    let handle = supervisor::spawn_service(paths, spec, Some(log_path_buf.clone()))?;
    let url = discover_public_url(&handle.log_path, Duration::from_secs(10))?;
    write_public_url(&url_path, &url)?;
    Ok(CloudflaredHandle {
        url,
        pid: handle.pid,
        log_path: handle.log_path,
    })
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

/// Stop any orphaned cloudflared processes not tracked by pidfile.
pub fn stop_cloudflared() {
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("pkill")
            .args(["-9", "cloudflared"])
            .status();
    }

    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/IM", "cloudflared.exe", "/F"])
            .status();
    }
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
}
