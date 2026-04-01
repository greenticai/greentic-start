#![allow(dead_code)]

use std::path::Path;

use crate::services::runner::{ProcessStatus, ServiceState, log_path, pid_path, start_process};

#[derive(Clone)]
pub struct ComponentSpec {
    pub id: String,
    pub binary: String,
    pub args: Vec<String>,
}

pub fn start_component(
    root: &Path,
    spec: &ComponentSpec,
    envs: &[(&str, String)],
) -> anyhow::Result<ServiceState> {
    let pid = pid_path(root, &spec.id);
    let log = log_path(root, &spec.id);
    start_process(&spec.binary, &spec.args, envs, &pid, &log, Some(root))
}

pub fn stop_component(root: &Path, id: &str) -> anyhow::Result<ServiceState> {
    let pid = pid_path(root, id);
    super::runner::stop_process(&pid)
}

pub fn component_status(root: &Path, id: &str) -> anyhow::Result<ProcessStatus> {
    let pid = pid_path(root, id);
    super::runner::process_status(&pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_status_is_not_running_without_pidfile() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            component_status(dir.path(), "component-a").expect("status"),
            ProcessStatus::NotRunning
        );
    }

    #[test]
    fn stop_component_is_not_running_without_pidfile() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            stop_component(dir.path(), "component-a").expect("stop"),
            ServiceState::NotRunning
        );
    }
}
