#![allow(dead_code)]

use std::{
    fs::{File, OpenOptions},
    io,
    io::Write,
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

static LOGGER: OnceLock<Logger> = OnceLock::new();

pub fn init(log_dir: PathBuf, min_level: Level) -> anyhow::Result<PathBuf> {
    let fallback = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("logs");

    let mut candidates = vec![log_dir.clone()];
    if fallback != log_dir {
        candidates.push(fallback.clone());
    }

    let mut last_error: Option<(PathBuf, io::Error)> = None;
    for candidate in candidates {
        match try_open_operator_log(&candidate) {
            Ok(file) => {
                let logger = Logger {
                    writer: Mutex::new(file),
                    min_level,
                };
                if LOGGER.set(logger).is_err() {
                    anyhow::bail!("operator logger already initialized");
                }
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
    let operator_path = log_dir.join("operator.log");
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&operator_path)
}

pub fn log(level: Level, target: &str, message: String) {
    let logger = match LOGGER.get() {
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
    let _ = writeln!(
        *writer,
        "{timestamp} [{level:?}] {target} - {message}",
        level = level,
        target = target,
        message = message
    );
    // Always flush to ensure logs are written immediately
    let _ = writer.flush();
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

pub fn trace(target: &str, message: impl AsRef<str>) {
    log(Level::Trace, target, message.as_ref().to_string());
}

pub fn debug(target: &str, message: impl AsRef<str>) {
    log(Level::Debug, target, message.as_ref().to_string());
}

pub fn info(target: &str, message: impl AsRef<str>) {
    log(Level::Info, target, message.as_ref().to_string());
}

pub fn warn(target: &str, message: impl AsRef<str>) {
    log(Level::Warn, target, message.as_ref().to_string());
}

pub fn error(target: &str, message: impl AsRef<str>) {
    log(Level::Error, target, message.as_ref().to_string());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn writes_operator_log() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let _ = init(dir.path().to_path_buf(), Level::Info)?;
        info("tests::writes_operator_log", "hello world");
        let contents = fs::read_to_string(dir.path().join("operator.log"))?;
        assert!(contents.contains("hello world"));
        Ok(())
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
