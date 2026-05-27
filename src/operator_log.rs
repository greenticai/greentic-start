#![allow(dead_code)]

use std::{
    fs::{File, OpenOptions},
    io,
    io::Write,
    panic::Location,
    path::{Path, PathBuf},
    sync::Mutex,
};

use anyhow::Context;
use chrono::Utc;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

struct Logger {
    writer: Mutex<File>,
    min_level: Level,
}

static LOGGER: OnceLock<Mutex<Option<Logger>>> = OnceLock::new();

fn logger_slot() -> &'static Mutex<Option<Logger>> {
    LOGGER.get_or_init(|| Mutex::new(None))
}

pub fn init(log_dir: PathBuf, min_level: Level) -> anyhow::Result<PathBuf> {
    let cwd_fallback = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("logs");
    let home_fallback = std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".greentic/logs"));

    let mut candidates = vec![log_dir.clone()];
    if cwd_fallback != log_dir {
        candidates.push(cwd_fallback);
    }
    if let Some(home) = home_fallback
        && !candidates.contains(&home)
    {
        candidates.push(home);
    }

    let mut last_error: Option<(PathBuf, io::Error)> = None;
    for candidate in candidates {
        match try_open_operator_log(&candidate) {
            Ok(file) => {
                let logger = Logger {
                    writer: Mutex::new(file),
                    min_level,
                };
                let mut slot = logger_slot()
                    .lock()
                    .map_err(|_| anyhow::anyhow!("operator logger lock poisoned"))?;
                if slot.is_some() {
                    anyhow::bail!("operator logger already initialized");
                }
                *slot = Some(logger);
                if candidate != log_dir {
                    eprintln!(
                        "unable to write operator.log at {}; falling back to {}",
                        log_dir.display(),
                        candidate.display()
                    );
                }
                return Ok(candidate);
            }
            Err(err) => {
                last_error = Some((candidate, err));
            }
        }
    }

    if let Some((path, err)) = last_error {
        Err(anyhow::anyhow!(
            "unable to open operator log at {}: {}",
            path.display(),
            err
        ))
    } else {
        anyhow::bail!("unable to initialize operator log")
    }
}

fn try_open_operator_log(log_dir: &Path) -> io::Result<File> {
    std::fs::create_dir_all(log_dir)?;
    // Unified host log: operator_log + tracing-subscriber both append here.
    let path = log_dir.join("system.log");
    OpenOptions::new().create(true).append(true).open(&path)
}

#[track_caller]
pub fn log(level: Level, target: &str, message: String) {
    log_at(Location::caller(), level, target, message);
}

fn log_at(location: &Location<'_>, level: Level, target: &str, message: String) {
    let slot = match logger_slot().lock() {
        Ok(slot) => slot,
        Err(_) => return,
    };
    let logger = match slot.as_ref() {
        Some(logger) => logger,
        None => return,
    };
    if level < logger.min_level {
        return;
    }
    let mut writer = match logger.writer.lock() {
        Ok(writer) => writer,
        Err(_) => return,
    };
    let timestamp = Utc::now().to_rfc3339();
    let file = shorten_log_path(location.file());
    let line = location.line();
    let _ = writeln!(
        *writer,
        "{timestamp} [{level:?}] {target} {file}:{line} - {message}",
        level = level,
        target = target,
        file = file,
        line = line,
        message = message
    );
    let _ = writer.flush();
}

/// Trim absolute paths emitted by `Location::caller()` down to a stable suffix
/// (after `/src/`) so log entries stay portable across machines and CI runners.
fn shorten_log_path(path: &str) -> &str {
    if let Some(idx) = path.rfind("/src/") {
        // Keep the `src/...` prefix so the path remains readable as a module reference.
        return &path[idx + 1..];
    }
    path
}

#[cfg(test)]
pub fn reset_for_tests() {
    if let Ok(mut slot) = logger_slot().lock() {
        *slot = None;
    }
}

pub fn service_log_path(log_dir: &Path, service: &str) -> PathBuf {
    log_dir.join(format!("{service}.log"))
}

pub fn reserve_service_log(log_dir: &Path, service: &str) -> anyhow::Result<PathBuf> {
    let path = service_log_path(log_dir, service);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("unable to open {} log file at {}", service, path.display()))?;
    Ok(path)
}

#[track_caller]
pub fn trace(target: &str, message: impl AsRef<str>) {
    log(Level::Trace, target, message.as_ref().to_string());
}

#[track_caller]
pub fn debug(target: &str, message: impl AsRef<str>) {
    log(Level::Debug, target, message.as_ref().to_string());
}

#[track_caller]
pub fn info(target: &str, message: impl AsRef<str>) {
    log(Level::Info, target, message.as_ref().to_string());
}

#[track_caller]
pub fn warn(target: &str, message: impl AsRef<str>) {
    log(Level::Warn, target, message.as_ref().to_string());
}

#[track_caller]
pub fn error(target: &str, message: impl AsRef<str>) {
    log(Level::Error, target, message.as_ref().to_string());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn writes_system_log_with_source_location() -> anyhow::Result<()> {
        reset_for_tests();
        let dir = tempdir()?;
        let _ = init(dir.path().to_path_buf(), Level::Info)?;
        info("tests::writes_system_log", "hello world");
        let contents = fs::read_to_string(dir.path().join("system.log"))?;
        assert!(contents.contains("hello world"));
        assert!(
            contents.contains("src/operator_log.rs:"),
            "log entry must include file:line: {contents}"
        );
        Ok(())
    }

    #[test]
    fn shorten_log_path_trims_to_src_suffix() {
        assert_eq!(
            shorten_log_path("/Users/whoever/project/crates/foo/src/bar/baz.rs"),
            "src/bar/baz.rs"
        );
        assert_eq!(shorten_log_path("relative/path.rs"), "relative/path.rs");
        assert_eq!(shorten_log_path("/no/src/marker.rs"), "src/marker.rs");
    }

    #[test]
    fn service_log_helpers_create_expected_path() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let path = service_log_path(dir.path(), "runner");
        assert_eq!(path, dir.path().join("runner.log"));

        let reserved = reserve_service_log(dir.path(), "runner")?;
        assert_eq!(reserved, path);
        assert!(reserved.exists());
        Ok(())
    }
}
