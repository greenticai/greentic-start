#![allow(dead_code)]

use std::env;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sysinfo::{Pid, ProcessesToUpdate, System};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessStatus {
    Running,
    NotRunning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Started,
    AlreadyRunning,
    Stopped,
    NotRunning,
}

pub fn start_process(
    command: &str,
    args: &[String],
    envs: &[(&str, String)],
    pid_path: &Path,
    log_path: &Path,
    cwd: Option<&Path>,
) -> anyhow::Result<ServiceState> {
    if let Some(pid) = read_pid(pid_path)? {
        if is_process_running(pid)? {
            if should_restart_for_command(pid, command)? {
                kill_process(pid)?;
                let _ = std::fs::remove_file(pid_path);
            } else {
                return Ok(ServiceState::AlreadyRunning);
            }
        } else {
            let _ = std::fs::remove_file(pid_path);
        }
    }

    if let Some(parent) = pid_path.parent() {
        ensure_dir_logged(parent, "pid directory")?;
    }
    if let Some(parent) = log_path.parent() {
        ensure_dir_logged(parent, "log directory")?;
    }
    if !log_path.exists() {
        // Ensure a log file exists before the child starts so early failures are captured.
        std::fs::File::create(log_path)?;
    }

    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    let log_file_err = log_file.try_clone()?;

    let mut command = Command::new(command);
    command.args(args);
    command.envs(envs.iter().map(|(key, value)| (*key, value)));
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EPERM) {
                        return Ok(());
                    }
                    return Err(err);
                }
                Ok(())
            });
        }
    }
    let child = command
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_err))
        .spawn()?;

    let pid = child.id();
    std::fs::write(pid_path, pid.to_string())?;

    Ok(ServiceState::Started)
}

pub fn stop_process(pid_path: &Path) -> anyhow::Result<ServiceState> {
    let pid = match read_pid(pid_path)? {
        Some(pid) => pid,
        None => return Ok(ServiceState::NotRunning),
    };

    if !is_pid_running(pid_path)? {
        let _ = std::fs::remove_file(pid_path);
        return Ok(ServiceState::NotRunning);
    }

    kill_process(pid)?;
    let _ = std::fs::remove_file(pid_path);
    Ok(ServiceState::Stopped)
}

pub fn process_status(pid_path: &Path) -> anyhow::Result<ProcessStatus> {
    if is_pid_running(pid_path)? {
        Ok(ProcessStatus::Running)
    } else {
        Ok(ProcessStatus::NotRunning)
    }
}

pub fn tail_log(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        return Err(anyhow::anyhow!(
            "Log file does not exist: {}",
            path.display()
        ));
    }

    #[cfg(unix)]
    {
        let status = Command::new("tail")
            .args(["-f", &path.display().to_string()])
            .status()?;
        if !status.success() {
            return Err(anyhow::anyhow!("tail exited with {}", status));
        }
        Ok(())
    }

    #[cfg(windows)]
    {
        let contents = std::fs::read_to_string(path)?;
        println!("{contents}");
        Ok(())
    }
}

fn ensure_dir_logged(path: &Path, description: &str) -> anyhow::Result<()> {
    if demo_debug_enabled() {
        println!("demo debug: ensuring {description} at {}", path.display());
    }
    match std::fs::create_dir_all(path) {
        Ok(()) => {
            if demo_debug_enabled() {
                println!("demo debug: ensured {description}");
            }
            Ok(())
        }
        Err(err) => {
            if demo_debug_enabled() {
                eprintln!(
                    "demo debug: failed to create {description} at {}: {err}",
                    path.display()
                );
            }
            Err(err.into())
        }
    }
}

fn demo_debug_enabled() -> bool {
    matches!(
        env::var("GREENTIC_OPERATOR_DEMO_DEBUG").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn is_pid_running(pid_path: &Path) -> anyhow::Result<bool> {
    let pid = match read_pid(pid_path)? {
        Some(pid) => pid,
        None => return Ok(false),
    };
    is_process_running(pid)
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
    let pid: u32 = trimmed.parse()?;
    Ok(Some(pid))
}

fn should_restart_for_command(pid: u32, command: &str) -> anyhow::Result<bool> {
    let command_path = Path::new(command);
    if !command_path.is_absolute() {
        return Ok(false);
    }
    let command_path =
        std::fs::canonicalize(command_path).unwrap_or_else(|_| command_path.to_path_buf());
    let Some(proc_path) = process_exe(pid) else {
        return Ok(false);
    };
    let proc_path = std::fs::canonicalize(&proc_path).unwrap_or(proc_path);
    Ok(proc_path != command_path)
}

fn process_exe(pid: u32) -> Option<PathBuf> {
    let mut system = System::new();
    let pid = Pid::from_u32(pid);
    system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    system
        .process(pid)
        .and_then(|process| process.exe())
        .map(|path| path.to_path_buf())
}

#[cfg(unix)]
fn is_process_running(pid: u32) -> anyhow::Result<bool> {
    let result = unsafe { libc::kill(pid as i32, 0) };
    if result == 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        Ok(false)
    } else {
        Err(err.into())
    }
}

#[cfg(unix)]
fn kill_process(pid: u32) -> anyhow::Result<()> {
    let pid = pid as i32;
    let result = unsafe { libc::kill(-pid, libc::SIGTERM) };
    if result == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    let fallback = unsafe { libc::kill(pid, libc::SIGTERM) };
    if fallback == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(windows)]
fn is_process_running(pid: u32) -> anyhow::Result<bool> {
    let output = Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}")])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.contains(&pid.to_string()))
}

#[cfg(windows)]
fn kill_process(pid: u32) -> anyhow::Result<()> {
    let status = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("taskkill failed for pid {}", pid))
    }
}

pub fn log_path(root: &Path, name: &str) -> PathBuf {
    root.join("logs").join(format!("{name}.log"))
}

pub fn pid_path(root: &Path, name: &str) -> PathBuf {
    root.join("state").join("pids").join(format!("{name}.pid"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[cfg(unix)]
    #[test]
    fn start_and_stop_process() {
        let temp = tempfile::tempdir().unwrap();
        let pid = pid_path(temp.path(), "sleep");
        let log = log_path(temp.path(), "sleep");
        assert_eq!(log, temp.path().join("logs").join("sleep.log"));
        let args = vec!["1".to_string()];
        let envs: Vec<(&str, String)> = Vec::new();

        let state = start_process("sleep", &args, &envs, &pid, &log, None).unwrap();
        assert!(matches!(
            state,
            ServiceState::Started | ServiceState::AlreadyRunning
        ));

        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(process_status(&pid).unwrap(), ProcessStatus::Running);

        let stop = stop_process(&pid).unwrap();
        assert!(matches!(
            stop,
            ServiceState::Stopped | ServiceState::NotRunning
        ));
    }

    #[test]
    fn process_status_and_read_pid_handle_missing_and_empty_files() {
        let temp = tempfile::tempdir().unwrap();
        let pid = pid_path(temp.path(), "missing");
        assert_eq!(process_status(&pid).unwrap(), ProcessStatus::NotRunning);
        assert_eq!(read_pid(&pid).unwrap(), None);

        std::fs::create_dir_all(pid.parent().unwrap()).unwrap();
        std::fs::write(&pid, " \n ").unwrap();
        assert_eq!(read_pid(&pid).unwrap(), None);
        assert_eq!(process_status(&pid).unwrap(), ProcessStatus::NotRunning);
    }

    #[test]
    fn ensure_dir_logged_creates_nested_directories() {
        let temp = tempfile::tempdir().unwrap();
        let nested = temp.path().join("a").join("b").join("c");
        ensure_dir_logged(&nested, "nested dir").unwrap();
        assert!(nested.is_dir());
    }

    #[test]
    fn demo_debug_env_recognizes_supported_truthy_values() {
        unsafe {
            env::remove_var("GREENTIC_OPERATOR_DEMO_DEBUG");
        }
        assert!(!demo_debug_enabled());

        unsafe {
            env::set_var("GREENTIC_OPERATOR_DEMO_DEBUG", "1");
        }
        assert!(demo_debug_enabled());

        unsafe {
            env::set_var("GREENTIC_OPERATOR_DEMO_DEBUG", "true");
        }
        assert!(demo_debug_enabled());

        unsafe {
            env::set_var("GREENTIC_OPERATOR_DEMO_DEBUG", "yes");
        }
        assert!(demo_debug_enabled());

        unsafe {
            env::set_var("GREENTIC_OPERATOR_DEMO_DEBUG", "no");
        }
        assert!(!demo_debug_enabled());

        unsafe {
            env::remove_var("GREENTIC_OPERATOR_DEMO_DEBUG");
        }
    }
}
