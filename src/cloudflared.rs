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
