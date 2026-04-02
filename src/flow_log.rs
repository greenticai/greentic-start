//! Separate flow execution logger — writes to `logs/flow.log`.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use chrono::Utc;

struct FlowLogger {
    writer: Mutex<File>,
}

static LOGGER: OnceLock<FlowLogger> = OnceLock::new();

/// Initialize the flow logger. Call once at startup.
pub fn init(log_dir: &std::path::Path) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(log_dir)?;
    let path = log_dir.join("flow.log");
    let file = OpenOptions::new().create(true).append(true).open(&path)?;
    let _ = LOGGER.set(FlowLogger {
        writer: Mutex::new(file),
    });
    Ok(path)
}

/// Log a flow execution event.
pub fn log(level: &str, message: &str) {
    let logger = match LOGGER.get() {
        Some(l) => l,
        None => return,
    };
    let mut writer = match logger.writer.lock() {
        Ok(w) => w,
        Err(_) => return,
    };
    let ts = Utc::now().to_rfc3339();
    let _ = writeln!(*writer, "{ts} [{level}] {message}");
    let _ = writer.flush();
}

/// Lazy-init: try to create flow.log if logger not yet initialized.
fn ensure_init() {
    if LOGGER.get().is_some() {
        return;
    }
    // Try common log locations relative to working directory
    for candidate in ["logs", "."] {
        if init(std::path::Path::new(candidate)).is_ok() {
            return;
        }
    }
}

pub fn flow_start(provider: &str, flow_id: &str, tenant: &str, team: &str) {
    ensure_init();
    log(
        "START",
        &format!("provider={provider} flow={flow_id} tenant={tenant} team={team}"),
    );
}

pub fn flow_end(
    provider: &str,
    flow_id: &str,
    tenant: &str,
    team: &str,
    success: bool,
    error: Option<&str>,
) {
    let status = if success { "OK" } else { "FAIL" };
    let err_msg = error.unwrap_or("-");
    log(
        status,
        &format!("provider={provider} flow={flow_id} tenant={tenant} team={team} error={err_msg}"),
    );
}
