//! The staged block, the off switch, and the queue's bound.

use super::event::{Surface, TurnUsage, UsageEvent};
use super::*;
use crate::interop::config::{AgentMeta, InteropConfig};
use serde_json::json;

const ENDPOINT: &str = "https://admin.example/api/v1/ingest/worker-usage";
const TOKEN: &str = "gtm_staged-usage-token";

fn metering() -> MeteringConfig {
    MeteringConfig {
        endpoint: ENDPOINT.into(),
        token: MeteringToken(TOKEN.into()),
    }
}

fn config_with(metering: Option<MeteringConfig>) -> InteropConfig {
    InteropConfig {
        a2a: true,
        tenant_slug: Some("acme".into()),
        metering,
        ..InteropConfig::default()
    }
}

#[test]
fn a_staged_block_parses() {
    let parsed = parse_metering(json!({"endpoint": ENDPOINT, "token": TOKEN}), "unit");
    assert_eq!(parsed, Some(metering()));
}

#[test]
fn a_half_or_malformed_block_switches_metering_off() {
    for value in [
        json!({"endpoint": ENDPOINT}),
        json!({"token": TOKEN}),
        json!({"endpoint": "", "token": TOKEN}),
        json!({"endpoint": ENDPOINT, "token": "   "}),
        json!("not an object"),
        json!(null),
        // NOT covered: serde reads a two-element ARRAY as this struct's
        // fields in order, so `[endpoint, token]` parses. Nothing produces
        // that shape and accepting it discloses nothing, so it is left
        // permissive rather than guarded.
    ] {
        assert!(
            parse_metering(value.clone(), "unit").is_none(),
            "{value} should not configure metering"
        );
    }
}

/// The token is a bearer credential. An endpoint that would carry it in
/// cleartext off the host switches metering off rather than disclosing it;
/// loopback http is allowed because it cannot leave the machine, which is
/// also what makes the feature testable against a stub.
#[test]
fn only_https_or_loopback_http_is_accepted() {
    for accepted in [
        "https://admin.example/ingest",
        "http://127.0.0.1:9/ingest",
        "http://localhost:9/ingest",
        "http://[::1]:9/ingest",
    ] {
        assert!(
            parse_metering(json!({"endpoint": accepted, "token": TOKEN}), "unit").is_some(),
            "{accepted} should be accepted"
        );
    }
    for refused in [
        "http://admin.example/ingest",
        "http://10.0.0.5/ingest",
        "ftp://admin.example/ingest",
        "admin.example/ingest",
        "https://",
        "",
    ] {
        assert!(
            parse_metering(json!({"endpoint": refused, "token": TOKEN}), "unit").is_none(),
            "{refused} should be refused"
        );
    }
}

/// The token must not be printable, by anything, anywhere — including a
/// `{:?}` in a crate that has never heard of this module.
#[test]
fn debug_never_prints_the_token() {
    let config = config_with(Some(metering()));
    let printed = format!("{config:?}");
    assert!(!printed.contains(TOKEN), "{printed}");
    assert!(printed.contains("redacted"), "{printed}");
    assert!(!format!("{:?}", metering().token).contains(TOKEN));
}

/// The whole off switch: no staged block, no [`TurnMetering`], so no emit
/// site has anything to call. This is every deployment that exists today.
#[test]
fn an_absent_block_builds_no_turn_metering() {
    let meter = Arc::new(Meter::inspectable());
    assert!(
        TurnMetering::for_unit(
            &meter,
            &config_with(None),
            DeploymentId::new(),
            "support-bot"
        )
        .is_none()
    );
    assert!(
        TurnMetering::for_unit(
            &meter,
            &config_with(Some(metering())),
            DeploymentId::new(),
            "support-bot"
        )
        .is_some()
    );
}

#[test]
fn a_recorded_turn_carries_the_units_identifiers() {
    let meter = Arc::new(Meter::inspectable());
    let deployment_id = DeploymentId::new();
    let turn = TurnMetering::for_unit(
        &meter,
        &config_with(Some(metering())),
        deployment_id,
        "support-bot",
    )
    .expect("metering is staged");
    turn.record(
        Surface::A2a,
        Some("c_01J"),
        TurnUsage {
            tokens_in: 11,
            tokens_out: 7,
            iterations: 3,
        },
        Duration::from_millis(420),
    );
    let queued = meter.drain();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].endpoint, ENDPOINT);
    assert_eq!(queued[0].token.expose(), TOKEN);
    let event = &queued[0].event;
    assert_eq!(event.deployment_id, deployment_id.to_string());
    assert_eq!(event.bundle_id, "support-bot");
    assert_eq!(event.tenant_slug.as_deref(), Some("acme"));
    assert_eq!(event.credential_id.as_deref(), Some("c_01J"));
    assert_eq!(event.surface, "a2a");
    assert_eq!(
        (event.tokens_in, event.tokens_out, event.iterations),
        (11, 7, 3)
    );
    assert_eq!(event.duration_ms, 420);
}

/// The runtime has no source for an agent id other than the staged one, so an
/// absent `agent.id` falls back to the unit's bundle id rather than being
/// invented.
#[test]
fn the_agent_id_is_staged_or_falls_back_to_the_bundle() {
    let meter = Arc::new(Meter::inspectable());
    let mut config = config_with(Some(metering()));
    let bundle = TurnMetering::for_unit(&meter, &config, DeploymentId::new(), "support-bot")
        .expect("metering");
    config.agent = AgentMeta {
        id: Some("support-agent".into()),
        ..AgentMeta::default()
    };
    let staged = TurnMetering::for_unit(&meter, &config, DeploymentId::new(), "support-bot")
        .expect("metering");
    let usage = TurnUsage::default();
    bundle.record(Surface::A2a, None, usage, Duration::ZERO);
    staged.record(Surface::Mcp, None, usage, Duration::ZERO);
    let queued = meter.drain();
    assert_eq!(queued[0].event.agent_id, "support-bot");
    assert_eq!(queued[1].event.agent_id, "support-agent");
    // An OAuth MCP caller has no staged credential to name.
    assert!(queued[1].event.credential_id.is_none());
}

/// A sink that cannot keep up must cost memory nothing. The queue DROPS at
/// its bound rather than growing, and says so.
#[test]
fn the_queue_drops_rather_than_growing_without_bound() {
    let meter = Meter::inspectable();
    let target = metering();
    let overshoot = 50;
    for _ in 0..QUEUE_CAPACITY + overshoot {
        meter.record(
            &target,
            UsageEvent {
                event_id: event::new_event_id(),
                occurred_at: event::now_rfc3339(),
                tenant_slug: None,
                deployment_id: "d".into(),
                bundle_id: "b".into(),
                agent_id: "a".into(),
                credential_id: None,
                surface: Surface::A2a.as_str(),
                tokens_in: 0,
                tokens_out: 0,
                iterations: 0,
                duration_ms: 0,
            },
        );
    }
    assert_eq!(meter.dropped(), overshoot as u64);
    assert_eq!(meter.drain().len(), QUEUE_CAPACITY);
}
