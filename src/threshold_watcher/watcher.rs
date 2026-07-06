//! Poll loop for the threshold watcher.
//!
//! Mirrors `crate::timer_scheduler`'s shape: a background thread schedules
//! each watch on its own interval, sleeps to the soonest due tick, and
//! delivers crossing events via `crate::event_router::route_events`. See
//! `crate::timer_scheduler::run_scheduler_loop` for the reference loop this
//! mirrors, and `crate::runtime` (the `timer_scheduler` wiring block) for
//! the discover -> start -> store -> stop pattern this module's caller
//! follows.
//!
//! [`poll_once`] is generic over the metric-fetch and event-router calls
//! (`fetch`/`router` type parameters) purely for testability: production
//! code (the loop below, and `crate::runtime`) always passes the real
//! `fetch::fetch_metric`/`event_router::route_events`; tests substitute
//! stand-ins to drive one cycle deterministically, without a network call
//! or a running flow.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use chrono::Utc;
use serde_json::json;

use crate::ingress_types::{EventEnvelopeV1, EventScopeV1, EventSourceV1};
use crate::operator_log;
use crate::runner_host::OperatorContext;

use super::config::{MetricSource, ThresholdWatchConfig};
use super::eval::{crossing, side};
use super::fetch::fetch_metric;
use super::state::{WatchState, load_state, save_state};

/// Configuration for one running [`ThresholdWatcher`]: the bundle it
/// belongs to, where durable edge-state is persisted, and the watches to
/// poll. Mirrors `crate::timer_scheduler::TimerSchedulerConfig`.
#[derive(Clone)]
pub struct ThresholdWatcherConfig {
    pub bundle_root: PathBuf,
    pub state_dir: PathBuf,
    pub tenant: String,
    pub team: Option<String>,
    pub watches: Vec<ThresholdWatchConfig>,
}

/// Handle to the background poll-loop thread. `start`/`stop` mirror
/// `crate::timer_scheduler::TimerScheduler`.
pub struct ThresholdWatcher {
    shutdown: Option<mpsc::Sender<()>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl ThresholdWatcher {
    /// Spawn the background poll-loop thread.
    ///
    /// If the thread fails to spawn (an exceptional OS-level condition),
    /// the failure is logged and a no-op handle is returned rather than
    /// panicking the caller — mirrors the non-fatal-startup philosophy
    /// `crate::runtime` already applies to the timer scheduler and other
    /// optional pieces.
    pub fn start(config: ThresholdWatcherConfig) -> Self {
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
        match thread::Builder::new()
            .name("threshold-watcher".to_string())
            .spawn(move || run_watcher_loop(config, shutdown_rx))
        {
            Ok(handle) => Self {
                shutdown: Some(shutdown_tx),
                handle: Some(handle),
            },
            Err(err) => {
                operator_log::error(
                    module_path!(),
                    format!("failed to spawn threshold watcher thread: {err}"),
                );
                Self {
                    shutdown: None,
                    handle: None,
                }
            }
        }
    }

    /// Signal the loop to stop and wait for the thread to exit.
    pub fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take()
            && let Err(err) = handle.join()
        {
            operator_log::error(
                module_path!(),
                format!("threshold watcher thread panicked: {err:?}"),
            );
        }
    }
}

struct ScheduledWatch {
    config: ThresholdWatchConfig,
    next_tick: Instant,
}

fn run_watcher_loop(config: ThresholdWatcherConfig, rx: mpsc::Receiver<()>) {
    if config.watches.is_empty() {
        return;
    }
    let mut scheduled: Vec<ScheduledWatch> = config
        .watches
        .iter()
        .cloned()
        .map(|watch| ScheduledWatch {
            next_tick: Instant::now() + Duration::from_secs(watch.interval_seconds.max(1)),
            config: watch,
        })
        .collect();

    operator_log::info(
        module_path!(),
        format!(
            "threshold watcher started watches={} tenant={} team={}",
            scheduled.len(),
            config.tenant,
            config.team.as_deref().unwrap_or("default")
        ),
    );

    loop {
        let now = Instant::now();
        for watch in &mut scheduled {
            if now < watch.next_tick {
                continue;
            }
            poll_once(
                &config.bundle_root,
                &config.state_dir,
                &watch.config,
                fetch_metric,
                crate::event_router::route_events_to_default_flow,
            );
            watch.next_tick =
                Instant::now() + Duration::from_secs(watch.config.interval_seconds.max(1));
        }

        let sleep_for = scheduled
            .iter()
            .map(|watch| watch.next_tick.saturating_duration_since(Instant::now()))
            .min()
            .unwrap_or_else(|| Duration::from_millis(200))
            .max(Duration::from_millis(50));
        if rx.recv_timeout(sleep_for).is_ok() {
            break;
        }
    }

    operator_log::info(module_path!(), "threshold watcher stopped");
}

/// Run one poll cycle for a single watch: fetch the metric, classify its
/// side, load the prior durable side, detect a genuine edge crossing, emit
/// a crossing event on a match, and always persist the newly observed side.
///
/// Generic over `fetch`/`router` purely for testability — production calls
/// (the loop above) always pass `fetch::fetch_metric`/
/// `event_router::route_events`.
///
/// Fail-safe on a fetch error: the tick is skipped WITHOUT touching durable
/// state and without emitting an event — a transient fetch failure must
/// never fabricate a crossing. One watch's failure never panics, so it
/// cannot take down the others sharing the loop.
pub fn poll_once<F, R>(
    bundle_root: &Path,
    state_dir: &Path,
    watch: &ThresholdWatchConfig,
    fetch: F,
    router: R,
) where
    F: FnOnce(&MetricSource) -> Result<f64, String>,
    R: FnOnce(&Path, &OperatorContext, &[EventEnvelopeV1]) -> anyhow::Result<usize>,
{
    let value = match fetch(&watch.source) {
        Ok(value) => value,
        Err(err) => {
            operator_log::warn(
                module_path!(),
                format!(
                    "threshold watch '{}' (tenant={}) fetch failed, skipping tick: {err}",
                    watch.name, watch.tenant
                ),
            );
            return;
        }
    };

    let checked_at = Utc::now().to_rfc3339();
    let prior = load_state(state_dir, &watch.tenant, &watch.name);
    let current_side = side(value, watch.threshold, watch.comparator);

    if let Some(direction_label) = crossing(prior.last_side, current_side, watch.direction) {
        let event = build_crossing_event(watch, value, direction_label, &checked_at);
        let ctx = OperatorContext {
            tenant: watch.tenant.clone(),
            team: watch.team.clone(),
            correlation_id: None,
        };
        if let Err(err) = router(bundle_root, &ctx, std::slice::from_ref(&event)) {
            operator_log::error(
                module_path!(),
                format!(
                    "threshold watch '{}' failed to route crossing event: {err:#}",
                    watch.name
                ),
            );
        }
    }

    let new_state = WatchState {
        last_side: current_side,
        last_value: Some(value),
        last_checked: Some(checked_at),
    };
    if let Err(err) = save_state(state_dir, &watch.tenant, &watch.name, &new_state) {
        operator_log::warn(
            module_path!(),
            format!(
                "threshold watch '{}' failed to persist state: {err}",
                watch.name
            ),
        );
    }
}

/// Build the `EventEnvelopeV1` delivered on a genuine crossing.
///
/// `EventEnvelopeV1` (`crate::ingress_types`) has no field literally named
/// `topic` — routing (`event_router::select_target_flows`) matches on
/// `event_type`, so the watch's configured `topic` is carried there. There
/// is likewise no `source.producer` field; `source.provider` is the closest
/// analogue and is set to `"threshold:<name>"`.
pub fn build_crossing_event(
    watch: &ThresholdWatchConfig,
    value: f64,
    crossed: &str,
    checked_at: &str,
) -> EventEnvelopeV1 {
    EventEnvelopeV1 {
        event_id: uuid::Uuid::new_v4().to_string(),
        event_type: watch.topic.clone(),
        occurred_at: checked_at.to_string(),
        source: EventSourceV1 {
            domain: "threshold".to_string(),
            provider: format!("threshold:{}", watch.name),
            handler_id: Some(watch.name.clone()),
        },
        scope: EventScopeV1 {
            tenant: watch.tenant.clone(),
            team: watch.team.clone(),
        },
        correlation_id: None,
        payload: json!({
            "name": watch.name,
            "value": value,
            "threshold": watch.threshold,
            "comparator": watch.comparator,
            "direction": watch.direction,
            "crossed": crossed,
            "checked_at": checked_at,
        }),
        http: None,
        raw: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold_watcher::eval::{Comparator, EdgeDirection};

    fn sample_watch() -> ThresholdWatchConfig {
        ThresholdWatchConfig {
            name: "cpu-high".to_string(),
            tenant: "acme".to_string(),
            team: Some("ops".to_string()),
            source: MetricSource {
                url: "https://example.com/metrics".to_string(),
                json_path: "$.cpu.percent".to_string(),
                headers: Vec::new(),
            },
            comparator: Comparator::Gt,
            threshold: 90.0,
            direction: EdgeDirection::Rising,
            interval_seconds: 30,
            topic: "metric.test.crossed".to_string(),
        }
    }

    #[test]
    fn build_crossing_event_shapes_topic_producer_and_payload() {
        let watch = sample_watch();

        let event = build_crossing_event(&watch, 97.5, "rising", "2026-07-03T00:00:00Z");

        assert_eq!(
            event.event_type, watch.topic,
            "event_type carries the routing topic"
        );
        assert_eq!(event.source.provider, "threshold:cpu-high");
        assert_eq!(event.source.domain, "threshold");
        assert_eq!(event.scope.tenant, watch.tenant);
        assert_eq!(event.scope.team, watch.team);
        assert_eq!(event.occurred_at, "2026-07-03T00:00:00Z");
        assert_eq!(event.payload["name"], "cpu-high");
        assert_eq!(event.payload["value"], 97.5);
        assert_eq!(event.payload["threshold"], 90.0);
        assert_eq!(event.payload["comparator"], "gt");
        assert_eq!(event.payload["direction"], "rising");
        assert_eq!(event.payload["crossed"], "rising");
        assert_eq!(event.payload["checked_at"], "2026-07-03T00:00:00Z");
    }

    #[test]
    fn poll_once_skips_state_and_router_on_fetch_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let watch = sample_watch();
        save_state(
            temp.path(),
            &watch.tenant,
            &watch.name,
            &WatchState {
                last_side: super::super::eval::Side::Below,
                last_value: Some(10.0),
                last_checked: Some("2026-07-02T00:00:00Z".to_string()),
            },
        )
        .expect("seed state");

        let mut router_called = false;
        poll_once(
            Path::new("/nonexistent-bundle"),
            temp.path(),
            &watch,
            |_source| Err("boom".to_string()),
            |_bundle, _ctx, _events| {
                router_called = true;
                Ok(0)
            },
        );

        assert!(!router_called, "fetch error must not route an event");
        let after = load_state(temp.path(), &watch.tenant, &watch.name);
        assert_eq!(after.last_side, super::super::eval::Side::Below);
        assert_eq!(after.last_value, Some(10.0));
        assert_eq!(after.last_checked.as_deref(), Some("2026-07-02T00:00:00Z"));
    }
}
