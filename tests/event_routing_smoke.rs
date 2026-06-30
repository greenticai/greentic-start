/// Smoke tests for event_router::select_target_flows topic routing.
///
/// These tests exercise the selection layer only — no runner binary or live
/// pack required.  Full flow-run coverage (route_events) needs a runner
/// binary and is omitted here; the selection logic is the keystone that
/// Task 3 enables for time-trigger routing.
use greentic_start::event_router::select_target_flows;
use greentic_start::ingress_types::{EventEnvelopeV1, EventScopeV1, EventSourceV1};
use greentic_start::messaging_app::{AppFlowInfo, AppPackInfo};
use serde_json::json;

fn make_event(event_type: &str) -> EventEnvelopeV1 {
    EventEnvelopeV1 {
        event_id: "evt-smoke-1".to_string(),
        event_type: event_type.to_string(),
        occurred_at: "2026-06-18T00:00:00Z".to_string(),
        source: EventSourceV1 {
            domain: "events".to_string(),
            provider: "provider-timer".to_string(),
            handler_id: Some("default".to_string()),
        },
        scope: EventScopeV1 {
            tenant: "smoke-tenant".to_string(),
            team: Some("smoke-team".to_string()),
        },
        correlation_id: None,
        payload: json!({"fired": true}),
        http: None,
        raw: None,
    }
}

fn make_pack_with_timer_subscriber() -> AppPackInfo {
    AppPackInfo {
        pack_id: "smoke-pack".to_string(),
        flows: vec![
            AppFlowInfo {
                id: "default".to_string(),
                kind: "messaging".to_string(),
                subscribes_to: vec![],
            },
            AppFlowInfo {
                id: "on_timer".to_string(),
                kind: "events".to_string(),
                subscribes_to: vec!["timer.*".to_string()],
            },
        ],
        capabilities: vec![],
    }
}

/// A timer.fired event matches a flow that subscribes to "timer.*".
#[test]
fn timer_fired_matches_timer_wildcard_subscriber() {
    let event = make_event("timer.fired");
    let pack = make_pack_with_timer_subscriber();

    let matched = select_target_flows(&pack, &event.event_type);

    assert_eq!(
        matched.len(),
        1,
        "expected exactly one subscriber for timer.fired"
    );
    assert_eq!(matched[0].id, "on_timer");
}

/// An event with no matching subscriber yields an empty vec (caller falls back to default flow).
#[test]
fn no_subscriber_yields_empty_vec_for_default_fallback() {
    let event = make_event("webhook.received");
    let pack = make_pack_with_timer_subscriber();

    let matched = select_target_flows(&pack, &event.event_type);

    assert!(
        matched.is_empty(),
        "webhook.received must yield no subscribers so caller uses default flow"
    );
}

/// timer.fired must NOT match a flow that only subscribes to a different prefix.
#[test]
fn timer_fired_does_not_match_unrelated_subscriber() {
    let pack = AppPackInfo {
        pack_id: "other-pack".to_string(),
        flows: vec![AppFlowInfo {
            id: "on_order".to_string(),
            kind: "events".to_string(),
            subscribes_to: vec!["orders.*".to_string()],
        }],
        capabilities: vec![],
    };

    let matched = select_target_flows(&pack, "timer.fired");

    assert!(
        matched.is_empty(),
        "timer.fired must not bleed into orders.* subscriber"
    );
}

/// Multiple flows can subscribe to overlapping patterns; all matching ones are returned.
#[test]
fn multiple_flows_can_subscribe_to_same_timer_pattern() {
    let pack = AppPackInfo {
        pack_id: "multi-pack".to_string(),
        flows: vec![
            AppFlowInfo {
                id: "logger".to_string(),
                kind: "events".to_string(),
                subscribes_to: vec!["timer.*".to_string()],
            },
            AppFlowInfo {
                id: "on_timer".to_string(),
                kind: "events".to_string(),
                subscribes_to: vec!["timer.fired".to_string()],
            },
        ],
        capabilities: vec![],
    };

    let matched = select_target_flows(&pack, "timer.fired");
    let ids: Vec<&str> = matched.iter().map(|f| f.id.as_str()).collect();

    assert_eq!(ids, vec!["logger", "on_timer"]);
}
