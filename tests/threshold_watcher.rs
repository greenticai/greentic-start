//! Integration tests for the threshold watcher's poll -> eval -> crossing ->
//! route pipeline (Task 5).
//!
//! `poll_once` is exercised end-to-end with the real fetch/eval/durable-state
//! machinery (`config`, `eval`, `state`); only the HTTP fetch and the event
//! delivery are substituted, mirroring how Tasks 1-4's own tests avoid a
//! network call. The router stub performs the exact same topic-subscription
//! selection `event_router::route_events` does internally
//! (`event_router::select_target_flows`, against a fixture `AppPackInfo`
//! with a flow subscribed to `metric.test.crossed`) and records what would
//! have been routed, instead of spawning a runner binary to actually
//! execute the flow — the same tradeoff `tests/event_routing_smoke.rs`
//! documents for full `route_events` coverage ("needs a runner binary and
//! is omitted here"). Production code (`ThresholdWatcher`'s background
//! loop, wired into `runtime.rs`) always calls the real
//! `fetch::fetch_metric`/`event_router::route_events`.

use std::path::Path;
use std::sync::Mutex;

use greentic_start::event_router::select_target_flows;
use greentic_start::ingress_types::EventEnvelopeV1;
use greentic_start::messaging_app::{AppFlowInfo, AppPackInfo};
use greentic_start::threshold_watcher::config::{MetricSource, ThresholdWatchConfig};
use greentic_start::threshold_watcher::eval::{Comparator, EdgeDirection, Side};
use greentic_start::threshold_watcher::state::{WatchState, load_state, save_state};
use greentic_start::threshold_watcher::watcher::poll_once;

fn sample_watch(name: &str, tenant: &str) -> ThresholdWatchConfig {
    ThresholdWatchConfig {
        name: name.to_string(),
        tenant: tenant.to_string(),
        team: Some("default".to_string()),
        source: MetricSource {
            url: "https://example.invalid/metrics".to_string(),
            json_path: "$.value".to_string(),
            headers: Vec::new(),
        },
        comparator: Comparator::Gt,
        threshold: 90.0,
        direction: EdgeDirection::Rising,
        interval_seconds: 30,
        topic: "metric.test.crossed".to_string(),
    }
}

/// Fixture app pack with one flow subscribed to `metric.test.crossed` — the
/// same shape `route_events` resolves internally via
/// `messaging_app::load_app_pack_info` + `select_target_flows`.
fn pack_with_metric_subscriber() -> AppPackInfo {
    AppPackInfo {
        pack_id: "threshold-test-pack".to_string(),
        flows: vec![
            AppFlowInfo {
                id: "default".to_string(),
                kind: "events".to_string(),
                subscribes_to: vec![],
                node_ids: vec![],
            },
            AppFlowInfo {
                id: "on_metric_crossed".to_string(),
                kind: "events".to_string(),
                subscribes_to: vec!["metric.test.crossed".to_string()],
                node_ids: vec![],
            },
        ],
        capabilities: vec![],
    }
}

/// Resolve `events` against `pack`'s subscriptions the same way
/// `route_events` does, and record `(event_type, matched_flow_count)` for
/// each one. Used as the `router` closure body in `poll_once` calls below —
/// takes no `OperatorContext`/bundle-root so it stays independent of
/// `greentic-start`'s crate-private types.
fn record_matches(
    pack: &AppPackInfo,
    log: &Mutex<Vec<(String, usize)>>,
    events: &[EventEnvelopeV1],
) -> anyhow::Result<usize> {
    let mut total = 0usize;
    let mut entries = log.lock().expect("lock router log");
    for event in events {
        let matched = select_target_flows(pack, &event.event_type);
        entries.push((event.event_type.clone(), matched.len()));
        total += matched.len();
    }
    Ok(total)
}

const UNUSED_BUNDLE_ROOT: &str = "/threshold-watcher-tests-unused-bundle-root";

/// A poll that crosses from `below` to `above` the threshold routes exactly
/// one event, matching the flow subscribed to the watch's topic, and
/// persists the new `Above` side.
#[test]
fn crossing_below_to_above_routes_event_to_subscribed_flow() {
    let temp = tempfile::tempdir().expect("tempdir");
    let watch = sample_watch("cpu-high", "acme");
    save_state(
        temp.path(),
        &watch.tenant,
        &watch.name,
        &WatchState {
            last_side: Side::Below,
            last_value: Some(10.0),
            last_checked: Some("2026-07-01T00:00:00Z".to_string()),
        },
    )
    .expect("seed prior state");

    let pack = pack_with_metric_subscriber();
    let log: Mutex<Vec<(String, usize)>> = Mutex::new(Vec::new());

    poll_once(
        Path::new(UNUSED_BUNDLE_ROOT),
        temp.path(),
        &watch,
        |_source| Ok(97.0),
        |_bundle_root, _ctx, events| record_matches(&pack, &log, events),
    );

    let routed = log.into_inner().expect("router log");
    assert_eq!(routed.len(), 1, "exactly one crossing event routed");
    assert_eq!(routed[0].0, "metric.test.crossed");
    assert_eq!(
        routed[0].1, 1,
        "the crossing event must match the on_metric_crossed subscriber"
    );

    let after = load_state(temp.path(), &watch.tenant, &watch.name);
    assert_eq!(after.last_side, Side::Above);
    assert_eq!(after.last_value, Some(97.0));
}

/// A second poll that stays `above` the threshold must NOT fire a second
/// event (fire-once semantics) even though the value is still above T.
#[test]
fn second_poll_still_above_fires_no_second_event() {
    let temp = tempfile::tempdir().expect("tempdir");
    let watch = sample_watch("cpu-high", "acme");
    save_state(
        temp.path(),
        &watch.tenant,
        &watch.name,
        &WatchState {
            last_side: Side::Below,
            last_value: Some(10.0),
            last_checked: Some("2026-07-01T00:00:00Z".to_string()),
        },
    )
    .expect("seed prior state");

    let pack = pack_with_metric_subscriber();
    let log: Mutex<Vec<(String, usize)>> = Mutex::new(Vec::new());

    // First poll: below -> above, fires.
    poll_once(
        Path::new(UNUSED_BUNDLE_ROOT),
        temp.path(),
        &watch,
        |_source| Ok(97.0),
        |_bundle_root, _ctx, events| record_matches(&pack, &log, events),
    );
    // Second poll: still above, must not fire again.
    poll_once(
        Path::new(UNUSED_BUNDLE_ROOT),
        temp.path(),
        &watch,
        |_source| Ok(99.0),
        |_bundle_root, _ctx, events| record_matches(&pack, &log, events),
    );

    let routed = log.into_inner().expect("router log");
    assert_eq!(
        routed.len(),
        1,
        "the second still-above poll must not route a second event"
    );

    let after = load_state(temp.path(), &watch.tenant, &watch.name);
    assert_eq!(after.last_side, Side::Above);
    assert_eq!(
        after.last_value,
        Some(99.0),
        "state must still update to the latest sampled value even without firing"
    );
}

/// A poll whose fetch fails must skip the tick entirely: no event routed,
/// and the durable state left exactly as it was before the poll.
#[test]
fn fetch_error_leaves_last_side_unchanged_and_routes_nothing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let watch = sample_watch("cpu-high", "acme");
    let seeded = WatchState {
        last_side: Side::Above,
        last_value: Some(95.0),
        last_checked: Some("2026-07-01T00:00:00Z".to_string()),
    };
    save_state(temp.path(), &watch.tenant, &watch.name, &seeded).expect("seed prior state");

    let pack = pack_with_metric_subscriber();
    let log: Mutex<Vec<(String, usize)>> = Mutex::new(Vec::new());

    poll_once(
        Path::new(UNUSED_BUNDLE_ROOT),
        temp.path(),
        &watch,
        |_source| Err("upstream metrics endpoint unreachable".to_string()),
        |_bundle_root, _ctx, events| record_matches(&pack, &log, events),
    );

    let routed = log.into_inner().expect("router log");
    assert!(routed.is_empty(), "a fetch error must never route an event");

    let after = load_state(temp.path(), &watch.tenant, &watch.name);
    assert_eq!(
        after, seeded,
        "fetch error must leave durable state untouched"
    );
}
