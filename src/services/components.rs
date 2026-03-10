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
