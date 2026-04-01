use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::runtime_state::{RuntimePaths, atomic_write};
use crate::supervisor::{self, ServiceId, ServiceSpec};

const SERVICE_ID: &str = "ngrok";

#[derive(Clone)]
pub struct NgrokConfig {
    pub binary: PathBuf,
    pub local_port: u16,
    pub extra_args: Vec<String>,
    pub restart: bool,
}

pub struct NgrokHandle {
    pub url: String,
    pub pid: u32,
    pub log_path: PathBuf,
}

pub fn start_tunnel(
    paths: &RuntimePaths,
    config: &NgrokConfig,
    log_path: &Path,
) -> anyhow::Result<NgrokHandle> {
    let pid_path = paths.pid_path(SERVICE_ID);
    let url_path = public_url_path(paths);
    if config.restart {
        let _ = supervisor::stop_pidfile(&pid_path, 2_000);
    }

    // Check for orphaned ngrok process: API responds but no valid pidfile
    // This happens when previous session crashed without cleanup
    let has_valid_pidfile = read_pid(&pid_path)
        .ok()
        .flatten()
        .is_some_and(supervisor::is_running);

    if !has_valid_pidfile && is_ngrok_running() {
        // Orphaned ngrok detected - kill it
        kill_orphaned_ngrok();
        // Clear stale URL cache so we get a fresh URL
        let _ = std::fs::remove_file(&url_path);
    }

    if let Some(pid) = read_pid(&pid_path)?
        && supervisor::is_running(pid)
    {
        let log_path_buf = log_path.to_path_buf();
        if let Some(url) = read_public_url(&url_path)? {
            return Ok(NgrokHandle {
                url,
                pid,
                log_path: log_path_buf.clone(),
            });
        }
        let url = discover_public_url(log_path, Duration::from_secs(15))?;
        write_public_url(&url_path, &url)?;
        return Ok(NgrokHandle {
            url,
            pid,
            log_path: log_path_buf,
        });
    }

    // Truncate log file to avoid reading old URLs from previous sessions
    let _ = std::fs::File::create(log_path);

    let mut argv = vec![
        config.binary.to_string_lossy().to_string(),
        "http".to_string(),
        format!("{}", config.local_port),
        "--log".to_string(),
        "stdout".to_string(),
        "--log-format".to_string(),
        "term".to_string(),
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
    let url = discover_public_url(&handle.log_path, Duration::from_secs(15))?;
    write_public_url(&url_path, &url)?;
    Ok(NgrokHandle {
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
    if is_ngrok_url(trimmed) {
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

/// Discover the public URL from ngrok log output.
///
/// ngrok logs a line like:
///   `url=https://xxxx-xx-xx-xxx-xxx.ngrok-free.app`
/// or in JSON format:
///   `"url":"https://xxxx.ngrok-free.app"`
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
            // Fall back to the ngrok local API
            if let Some(url) = try_ngrok_api() {
                return Ok(url);
            }
            return Err(anyhow::anyhow!(
                "timed out waiting for ngrok public URL in {}",
                log_path.display()
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Try to get the public URL from ngrok's local API at http://127.0.0.1:4040/api/tunnels.
fn try_ngrok_api() -> Option<String> {
    let response = std::process::Command::new("curl")
        .args(["-s", "http://127.0.0.1:4040/api/tunnels"])
        .output()
        .ok()?;
    if !response.status.success() {
        return None;
    }
    let body = String::from_utf8(response.stdout).ok()?;
    // Parse minimal JSON: look for "public_url":"https://..."
    parse_api_response(&body)
}

fn parse_api_response(body: &str) -> Option<String> {
    // ngrok API returns: {"tunnels":[{"public_url":"https://xxx.ngrok-free.app",...}]}
    // We look for the first https tunnel URL.
    let marker = "\"public_url\":\"https://";
    let pos = body.find(marker)?;
    let start = pos + "\"public_url\":\"".len();
    let tail = &body[start..];
    let end = tail.find('"')?;
    let url = &body[start..start + end];
    if is_ngrok_url(url) {
        Some(url.to_string())
    } else {
        // Accept any https URL from ngrok API (could be custom domain)
        Some(url.to_string())
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
        if is_ngrok_url(candidate) {
            return Some(candidate.to_string());
        }
        offset = start + "https://".len();
    }

    // Also look for url=https:// pattern (ngrok term format)
    let mut offset = 0;
    while let Some(pos) = contents[offset..].find("url=https://") {
        let start = offset + pos + "url=".len();
        let tail = &contents[start..];
        let end_offset = tail
            .find(|ch: char| ch.is_whitespace() || ch == '"')
            .unwrap_or(tail.len());
        let candidate = &contents[start..start + end_offset];
        if candidate.starts_with("https://") && !candidate.contains(char::is_whitespace) {
            return Some(candidate.to_string());
        }
        offset = start + "https://".len();
    }

    None
}

fn is_ngrok_url(value: &str) -> bool {
    if !value.starts_with("https://") {
        return false;
    }
    if value.contains(char::is_whitespace) {
        return false;
    }
    value.contains(".ngrok-free.app") || value.contains(".ngrok.app") || value.contains(".ngrok.io")
}

/// Check if ngrok is running by querying its local API.
fn is_ngrok_running() -> bool {
    try_ngrok_api().is_some()
}

/// Kill any orphaned ngrok processes that are running but not tracked by a pidfile.
/// This handles cases where a previous session crashed without cleanup.
fn kill_orphaned_ngrok() {
    // ngrok is running but not tracked - kill it
    #[cfg(unix)]
    {
        // Try pkill first (more reliable)
        let _ = std::process::Command::new("pkill")
            .args(["-9", "ngrok"])
            .status();
        // Wait a bit for the process to die
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/IM", "ngrok.exe", "/F"])
            .status();
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// Stop ngrok process - can be used for shutdown without pidfile.
pub fn stop_ngrok() {
    kill_orphaned_ngrok();
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_find_url_in_log_output() {
        let log = "t=2026-03-01T10:00:00+0000 lvl=info msg=\"started tunnel\" obj=tunnels name=command_line addr=//localhost:8080 url=https://abc123-1-2-3.ngrok-free.app";
        assert_eq!(
            find_url_in_text(log),
            Some("https://abc123-1-2-3.ngrok-free.app".to_string())
        );
    }

    #[test]
    fn test_find_url_ngrok_app() {
        let log = "Forwarding https://abc123.ngrok.app -> http://localhost:8080";
        assert_eq!(
            find_url_in_text(log),
            Some("https://abc123.ngrok.app".to_string())
        );
    }

    #[test]
    fn test_parse_api_response() {
        let body = r#"{"tunnels":[{"name":"command_line","public_url":"https://abc123.ngrok-free.app","proto":"https"}]}"#;
        assert_eq!(
            parse_api_response(body),
            Some("https://abc123.ngrok-free.app".to_string())
        );
    }

    #[test]
    fn test_is_ngrok_url_variants() {
        assert!(is_ngrok_url("https://abc.ngrok-free.app"));
        assert!(is_ngrok_url("https://abc.ngrok.app"));
        assert!(is_ngrok_url("https://abc.ngrok.io"));
        assert!(!is_ngrok_url("https://abc.trycloudflare.com"));
        assert!(!is_ngrok_url("http://abc.ngrok-free.app"));
    }

    #[test]
    fn test_parse_public_url_clean() {
        assert_eq!(
            parse_public_url("https://abc.ngrok-free.app"),
            Some("https://abc.ngrok-free.app".to_string())
        );
        assert_eq!(parse_public_url(""), None);
        assert_eq!(parse_public_url("  "), None);
    }

    #[test]
    fn trims_punctuation_and_ignores_non_ngrok_urls() {
        let log = r#"see tunnel ("https://abc123.ngrok.app"), but ignore https://example.com"#;
        assert_eq!(
            find_url_in_text(log),
            Some("https://abc123.ngrok.app".to_string())
        );
    }

    #[test]
    fn parse_api_response_accepts_custom_https_domain() {
        let body = r#"{"tunnels":[{"public_url":"https://chat.example.com"}]}"#;
        assert_eq!(
            parse_api_response(body),
            Some("https://chat.example.com".to_string())
        );
    }

    #[test]
    fn find_url_in_text_accepts_custom_domains_in_explicit_url_fields() {
        let log = r#"lvl=info msg="started tunnel" url=https://chat.example.com"#;
        assert_eq!(
            find_url_in_text(log),
            Some("https://chat.example.com".to_string())
        );
    }

    #[test]
    fn read_pid_and_public_url_handle_missing_and_embedded_values() {
        let dir = tempdir().expect("tempdir");
        let pid_path = dir.path().join("ngrok.pid");
        let url_path = dir.path().join("public_url.txt");

        assert_eq!(read_pid(&pid_path).expect("missing pid"), None);
        assert_eq!(read_public_url(&url_path).expect("missing url"), None);

        std::fs::write(&pid_path, " 42 ").expect("write pid");
        std::fs::write(
            &url_path,
            "started tunnel url=https://abc123.ngrok-free.app",
        )
        .expect("write url");

        assert_eq!(read_pid(&pid_path).expect("pid"), Some(42));
        assert_eq!(
            read_public_url(&url_path).expect("url"),
            Some("https://abc123.ngrok-free.app".to_string())
        );
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

        write_public_url(&url_path, "https://demo.ngrok-free.app").expect("write");
        assert_eq!(
            read_public_url(&url_path).expect("read"),
            Some("https://demo.ngrok-free.app".to_string())
        );
    }

    #[test]
    fn parse_public_url_accepts_embedded_custom_domain() {
        assert_eq!(
            parse_public_url(r#"started tunnel url=https://chat.example.com"#),
            Some("https://chat.example.com".to_string())
        );
    }

    #[test]
    fn discover_public_url_times_out_when_no_log_or_api_url_is_available() {
        let dir = tempdir().expect("tempdir");
        let log_path = dir.path().join("ngrok.log");
        std::fs::write(&log_path, "ngrok started without url").expect("write log");

        let err = discover_public_url(&log_path, Duration::from_millis(1))
            .expect_err("missing url should fail");
        assert!(
            err.to_string()
                .contains("timed out waiting for ngrok public URL")
        );
    }
}
