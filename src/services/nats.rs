#![allow(dead_code)]

use std::path::{Path, PathBuf};

use std::hash::{Hash, Hasher};
use std::str::FromStr;

use super::runner::{ProcessStatus, ServiceState, log_path, pid_path};

const NATS_CONTAINER_PREFIX: &str = "greentic-operator-nats";

pub fn start_nats(root: &Path) -> anyhow::Result<ServiceState> {
    start_nats_with_log(root, None)
}

pub fn start_nats_with_log(
    root: &Path,
    log_path_override: Option<PathBuf>,
) -> anyhow::Result<ServiceState> {
    let port = nats_port(root);
    let pid = pid_path(root, "nats");
    let log = log_path_override.unwrap_or_else(|| log_path(root, "nats"));
    let container = container_name(root);
    let args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--name".to_string(),
        container,
        "-p".to_string(),
        format!("{port}:{port}"),
        "nats:2".to_string(),
        "-js".to_string(),
    ];
    super::runner::start_process("docker", &args, &[], &pid, &log, Some(root))
}

pub fn stop_nats(root: &Path) -> anyhow::Result<ServiceState> {
    let pid = pid_path(root, "nats");
    super::runner::stop_process(&pid)
}

pub fn nats_status(root: &Path) -> anyhow::Result<ProcessStatus> {
    let pid = pid_path(root, "nats");
    super::runner::process_status(&pid)
}

pub fn tail_nats_logs(root: &Path) -> anyhow::Result<()> {
    let log = log_path(root, "nats");
    super::runner::tail_log(&log)
}

pub fn nats_url(root: &Path) -> String {
    format!("nats://127.0.0.1:{}", nats_port(root))
}

fn container_name(root: &Path) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    let mut identity = root.to_path_buf();
    if let Ok(canonical) = root.canonicalize() {
        identity = canonical;
    }
    identity.to_string_lossy().hash(&mut hasher);
    let hash = hasher.finish();
    format!("{NATS_CONTAINER_PREFIX}-{hash:08x}")
}

fn nats_port(root: &Path) -> u16 {
    if let Ok(value) = std::env::var("GREENTIC_OPERATOR_NATS_PORT")
        && let Ok(port) = u16::from_str(&value)
    {
        return port;
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    let mut identity = root.to_path_buf();
    if let Ok(canonical) = root.canonicalize() {
        identity = canonical;
    }
    identity.to_string_lossy().hash(&mut hasher);
    let hash = hasher.finish();
    4222 + (hash % 1000) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn nats_helpers_use_expected_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let url = nats_url(root);
        assert!(url.starts_with("nats://127.0.0.1:"));
        assert!(container_name(root).starts_with(NATS_CONTAINER_PREFIX));
    }

    #[test]
    fn nats_port_honors_env_override_and_is_stable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();

        unsafe {
            env::set_var("GREENTIC_OPERATOR_NATS_PORT", "4333");
        }
        assert_eq!(nats_port(root), 4333);

        unsafe {
            env::set_var("GREENTIC_OPERATOR_NATS_PORT", "invalid");
        }
        let derived = nats_port(root);
        assert_eq!(derived, nats_port(root));
        assert!((4222..=5221).contains(&derived));

        unsafe {
            env::remove_var("GREENTIC_OPERATOR_NATS_PORT");
        }
    }

    #[test]
    fn nats_status_and_stop_are_safe_without_pidfile() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            nats_status(dir.path()).expect("status"),
            ProcessStatus::NotRunning
        );
        assert_eq!(
            stop_nats(dir.path()).expect("stop"),
            ServiceState::NotRunning
        );
    }
}
