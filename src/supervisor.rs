#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sysinfo::{Pid, ProcessesToUpdate, System};

use crate::runtime_state::{RuntimePaths, read_json, write_json};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ServiceId(String);

impl ServiceId {
    pub fn new(value: impl Into<String>) -> anyhow::Result<Self> {
        let value = value.into();
        if value.is_empty() {
            return Err(anyhow::anyhow!("service id cannot be empty"));
        }
        if !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
        {
            return Err(anyhow::anyhow!(
                "invalid service id '{}'; use alphanumeric, '-' or '_'",
                value
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct ServiceSpec {
    pub id: ServiceId,
    pub argv: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct ServiceHandle {
    pub id: ServiceId,
    pub pid: u32,
    pub started_at: DateTime<Utc>,
    pub log_path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct ServiceStatus {
    pub id: ServiceId,
    pub running: bool,
    pub pid: Option<u32>,
    pub log_path: PathBuf,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedService {
    pub argv: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub log_path: Option<PathBuf>,
}

pub fn spawn_service(
    paths: &RuntimePaths,
    spec: ServiceSpec,
    log_path_override: Option<PathBuf>,
) -> anyhow::Result<ServiceHandle> {
    if spec.argv.is_empty() {
        return Err(anyhow::anyhow!("service argv cannot be empty"));
    }
    let pid_path = paths.pid_path(spec.id.as_str());
    if let Some(pid) = read_pid(&pid_path)?
        && is_running(pid)
    {
        return Err(anyhow::anyhow!(
            "service {} already running (pid {})",
            spec.id.as_str(),
            pid
        ));
    }

    let log_path = log_path_override.unwrap_or_else(|| paths.log_path(spec.id.as_str()));
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let log_err = log_file.try_clone()?;

    let mut command = Command::new(&spec.argv[0]);
    if spec.argv.len() > 1 {
        command.args(&spec.argv[1..]);
    }
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }
    command.envs(spec.env.iter());
    let child = command
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_err))
        .spawn()?;

    let pid = child.id();
    std::fs::create_dir_all(paths.pids_dir())?;
    std::fs::write(&pid_path, pid.to_string())?;

    let resolved = ResolvedService {
        argv: spec.argv.clone(),
        cwd: spec.cwd.clone(),
        env: spec.env.clone(),
        log_path: Some(log_path.clone()),
    };
    write_json(&paths.resolved_path(spec.id.as_str()), &resolved)?;

    Ok(ServiceHandle {
        id: spec.id,
        pid,
        started_at: Utc::now(),
        log_path,
    })
}

pub fn stop_service(
    paths: &RuntimePaths,
    id: &ServiceId,
    graceful_timeout_ms: u64,
) -> anyhow::Result<()> {
    let pid_path = paths.pid_path(id.as_str());
    stop_pidfile(&pid_path, graceful_timeout_ms)
}

pub fn stop_pidfile(pid_path: &Path, graceful_timeout_ms: u64) -> anyhow::Result<()> {
    let pid = match read_pid(pid_path)? {
        Some(pid) => pid,
        None => return Ok(()),
    };

    if !is_running(pid) {
        let _ = std::fs::remove_file(pid_path);
        return Ok(());
    }

    terminate_process(pid, graceful_timeout_ms)?;
    let _ = std::fs::remove_file(pid_path);
    Ok(())
}

pub fn read_status(paths: &RuntimePaths) -> anyhow::Result<Vec<ServiceStatus>> {
    let mut statuses = Vec::new();
    let pids_dir = paths.pids_dir();
    if !pids_dir.exists() {
        return Ok(statuses);
    }
    for entry in std::fs::read_dir(&pids_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("pid") {
            continue;
        }
        let file_name = entry.file_name();
        let Some(stem) = Path::new(&file_name).file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let id = ServiceId::new(stem.to_string())?;
        let pid = read_pid(&path)?;
        let running = pid.map(is_running).unwrap_or(false);
        let log_path = if let Some(resolved) = read_resolved(paths, &id)? {
            resolved
                .log_path
                .or_else(|| Some(paths.log_path(stem)))
                .unwrap()
        } else {
            paths.log_path(stem)
        };
        statuses.push(ServiceStatus {
            id,
            running,
            pid,
            log_path,
            last_error: None,
        });
    }
    Ok(statuses)
}

pub fn read_resolved(
    paths: &RuntimePaths,
    id: &ServiceId,
) -> anyhow::Result<Option<ResolvedService>> {
    read_json(&paths.resolved_path(id.as_str()))
}

pub fn is_running(pid: u32) -> bool {
    let mut system = System::new();
    let pid = Pid::from_u32(pid);
    system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    system.process(pid).is_some()
}

fn read_pid(pid_path: &Path) -> anyhow::Result<Option<u32>> {
    if !pid_path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(pid_path)?;
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed.parse()?))
}

fn terminate_process(pid: u32, graceful_timeout_ms: u64) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let _ = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_millis(graceful_timeout_ms);
        while Instant::now() < deadline {
            if !is_running(pid) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        Ok(())
    }

    #[cfg(windows)]
    {
        let _ = graceful_timeout_ms;
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .status();
        Ok(())
    }
}
