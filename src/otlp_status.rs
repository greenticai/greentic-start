//! Process-wide OTLP export status for `/status` (spec §3.4). `installed`
//! alone proves nothing — a typo'd endpoint installs fine — so each exporter
//! is wrapped and every `export` outcome is stamped here. `last_ok_at` means a
//! collector accepted a batch: the first fact that is evidence telemetry works.
//! No endpoint or header value is ever stored.
//!
//! Not yet wired up: later tasks in the same series feed this from exporter
//! wrappers and read it from `/status`, so `#![allow(dead_code)]` covers the
//! gap until then.
#![allow(dead_code)]

use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Signal {
    Traces,
    Logs,
    Metrics,
}

#[derive(Default, Clone)]
struct SignalState {
    last_ok_at: Option<SystemTime>,
    last_error_at: Option<SystemTime>,
    last_error: Option<String>,
}

#[derive(Default, Clone)]
struct State {
    exporter: Option<String>,
    installed: bool,
    init_error: Option<String>,
    traces: SignalState,
    logs: SignalState,
    metrics: SignalState,
}

fn state() -> &'static Mutex<State> {
    static S: OnceLock<Mutex<State>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(State::default()))
}

fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let mut guard = state().lock().unwrap_or_else(|p| p.into_inner());
    f(&mut guard)
}

pub(crate) fn record_installed(exporter: &str) {
    with(|s| {
        s.exporter = Some(exporter.to_string());
        s.installed = true;
        s.init_error = None;
    });
}

pub(crate) fn record_init_error(message: &str) {
    with(|s| {
        s.installed = false;
        s.init_error = Some(redact(message));
    });
}

pub(crate) fn record_export(signal: Signal, outcome: Result<(), String>) {
    let now = SystemTime::now();
    with(|s| {
        let slot = match signal {
            Signal::Traces => &mut s.traces,
            Signal::Logs => &mut s.logs,
            Signal::Metrics => &mut s.metrics,
        };
        match outcome {
            Ok(()) => slot.last_ok_at = Some(now),
            Err(e) => {
                slot.last_error_at = Some(now);
                slot.last_error = Some(redact(&e));
            }
        }
    });
}

pub(crate) fn redact(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(i) = rest.find("://") {
        let (head, tail) = rest.split_at(i + 3);
        out.push_str(head);
        let end = tail
            .find(|c: char| c == '/' || c.is_whitespace())
            .unwrap_or(tail.len());
        let authority = &tail[..end];
        let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        out.push_str(host);
        rest = &tail[end..];
    }
    out.push_str(rest);
    out.chars().take(200).collect()
}

fn ts(t: Option<SystemTime>) -> serde_json::Value {
    t.map(|t| {
        serde_json::Value::String(
            chrono::DateTime::<chrono::Utc>::from(t)
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
    })
    .unwrap_or(serde_json::Value::Null)
}

fn signal_json(s: &SignalState) -> serde_json::Value {
    serde_json::json!({
        "last_ok_at": ts(s.last_ok_at),
        "last_error_at": ts(s.last_error_at),
        "last_error": s.last_error,
    })
}

pub(crate) fn snapshot_json() -> serde_json::Value {
    let s = with(|s| s.clone());
    serde_json::json!({
        "exporter": s.exporter.as_deref().unwrap_or("none"),
        "installed": s.installed,
        "init_error": s.init_error,
        "signals": {
            "traces": signal_json(&s.traces),
            "logs": signal_json(&s.logs),
            "metrics": signal_json(&s.metrics),
        },
    })
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    with(|s| *s = State::default());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        static L: OnceLock<Mutex<()>> = OnceLock::new();
        L.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    #[test]
    fn nothing_installed_reads_as_none() {
        let _g = lock();
        reset_for_test();
        let s = snapshot_json();
        assert_eq!(s["exporter"], "none");
        assert_eq!(s["installed"], false);
        assert!(s["signals"]["traces"]["last_ok_at"].is_null());
    }

    #[test]
    fn an_ok_export_stamps_last_ok_and_an_error_is_redacted() {
        let _g = lock();
        reset_for_test();
        record_installed("otlp-grpc");
        record_export(Signal::Logs, Ok(()));
        record_export(
            Signal::Traces,
            Err("failed to reach http://user:s3cret@collector:4317".into()),
        );
        let s = snapshot_json();
        assert_eq!(s["installed"], true);
        assert!(s["signals"]["logs"]["last_ok_at"].is_string());
        let err = s["signals"]["traces"]["last_error"].as_str().unwrap();
        assert!(!err.contains("s3cret") && !err.contains("user:"), "{err}");
        assert!(s["signals"]["traces"]["last_error_at"].is_string());
    }

    #[test]
    fn redact_truncates_and_strips_userinfo() {
        assert_eq!(redact("https://a:b@h/x"), "https://h/x");
        assert!(redact(&"x".repeat(500)).chars().count() <= 200);
    }

    #[test]
    fn an_init_error_is_reported_and_not_installed() {
        let _g = lock();
        reset_for_test();
        record_init_error("build OTLP gRPC span exporter: bad uri http://u:p@x");
        let s = snapshot_json();
        assert_eq!(s["installed"], false);
        assert!(!s["init_error"].as_str().unwrap().contains("u:p@"));
    }
}
