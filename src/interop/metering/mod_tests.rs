//! The staged block, the off switch, and the queue's bound.

use super::event::{Surface, TurnUsage, UsageEvent};
use super::*;
use crate::interop::config::{AgentMeta, InteropConfig};
use serde_json::json;

const ENDPOINT: &str = "https://admin.example/api/v1/ingest/worker-usage";
const TOKEN: &str = "gtm_staged-usage-token";
const TENANT: &str = "acme";

fn metering() -> MeteringConfig {
    MeteringConfig {
        endpoint: ENDPOINT.into(),
        token: MeteringToken(TOKEN.into()),
        tenant_slug: TENANT.into(),
    }
}

/// `resolve_metering` with a staged tenant, so only the block under test
/// varies.
fn resolve(value: serde_json::Value) -> Result<MeteringConfig, MeteringRefusal> {
    resolve_metering(value, Some(TENANT))
}

fn config_with(metering: Option<MeteringConfig>) -> InteropConfig {
    InteropConfig {
        a2a: true,
        tenant_slug: Some(TENANT.into()),
        metering,
        ..InteropConfig::default()
    }
}

/// The staged document, as JSON, with whatever top level the case needs.
fn document(extra: serde_json::Value) -> Vec<u8> {
    let mut doc = json!({
        "v": 1,
        "a2a": true,
        "credentials": [{"id": "c1",
            "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}],
        "metering": {"endpoint": ENDPOINT, "token": TOKEN},
    });
    if let (serde_json::Value::Object(doc), serde_json::Value::Object(extra)) = (&mut doc, extra) {
        doc.extend(extra);
    }
    doc.to_string().into_bytes()
}

#[test]
fn a_staged_block_parses() {
    assert_eq!(
        resolve(json!({"endpoint": ENDPOINT, "token": TOKEN})),
        Ok(metering())
    );
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
            resolve(value.clone()).is_err(),
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
            resolve(json!({"endpoint": accepted, "token": TOKEN})).is_ok(),
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
            resolve(json!({"endpoint": refused, "token": TOKEN})).is_err(),
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
    assert_eq!(event.tenant_slug, TENANT);
    assert_eq!(event.credential_id.as_deref(), Some("c_01J"));
    assert_eq!(event.surface, "a2a");
    assert_eq!(
        (event.tokens_in, event.tokens_out, event.iterations),
        (11, 7, 3)
    );
    assert_eq!(event.duration_ms, 420);
}

/// **A staged `agent.id` wins**, and an absent one falls back to the unit's
/// bundle id rather than being invented — the runtime has no other source
/// (neither the `dw.agent` node output nor the reply `Activity` carries one).
///
/// The designer is expected to stage one so a worker's id and its bundle id
/// can differ; until it does, the two are equal, which is honest rather than
/// a guess.
#[test]
fn a_staged_agent_id_wins_over_the_bundle_id_fallback() {
    let meter = Arc::new(Meter::inspectable());
    let record = |config: &InteropConfig, surface| {
        TurnMetering::for_unit(&meter, config, DeploymentId::new(), "support-bot")
            .expect("metering")
            .record(surface, None, TurnUsage::default(), Duration::ZERO);
    };
    let mut config = config_with(Some(metering()));
    record(&config, Surface::A2a);

    config.agent = AgentMeta {
        id: Some("support-agent".into()),
        ..AgentMeta::default()
    };
    record(&config, Surface::Mcp);

    // A blank staged id is not an id: it falls back rather than putting an
    // empty string on the wire.
    config.agent.id = Some("   ".into());
    record(&config, Surface::A2a);

    let queued = meter.drain();
    let ids: Vec<&str> = queued.iter().map(|q| q.event.agent_id.as_str()).collect();
    assert_eq!(ids, vec!["support-bot", "support-agent", "support-bot"]);
    // And the staged one really reaches the serialized body.
    let body = serde_json::to_value(&queued[1].event).expect("serialise");
    assert_eq!(body["agent_id"], "support-agent");
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
                tenant_slug: TENANT.into(),
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

/// **A unit whose document carries no `tenant_slug` gets NO metering.**
///
/// The admin's usage ingest declares `tenant_slug` required and compares it
/// to the token's own tenant, so an event without it is a `400` — recorded
/// nowhere, forever, with only a warn on this side. Refusing up front says
/// the same thing once, at config read, instead of per turn.
///
/// The designer's contract makes the field non-optional in the staged
/// document, so this is a hand-written or mis-staged config rather than a
/// normal deployment — which is exactly why it must be reported rather than
/// papered over.
#[test]
fn a_staged_block_with_no_tenant_slug_switches_metering_off() {
    for slug in [None, Some(""), Some("   ")] {
        assert_eq!(
            resolve_metering(json!({"endpoint": ENDPOINT, "token": TOKEN}), slug),
            Err(MeteringRefusal::NoTenantSlug),
            "slug {slug:?} must not configure metering"
        );
    }
    // And it costs one operator line, naming the cause — `parse_metering` is
    // the single warn site, so a refusal is reported once per config read
    // rather than once per turn.
    assert!(parse_metering(json!({"endpoint": ENDPOINT, "token": TOKEN}), None, "unit").is_none());
    let reported = MeteringRefusal::NoTenantSlug.message();
    assert!(reported.contains("tenant_slug"), "{reported}");
    assert!(reported.contains("metering is off"), "{reported}");
    assert!(
        !reported.contains(TOKEN),
        "a refusal must not print the token"
    );
}

/// The whole document, through the real parser: a slug-less unit keeps its
/// interop surface and loses only metering, and a unit with one gets both.
#[test]
fn a_slug_less_document_keeps_its_interop_surface_and_loses_only_metering() {
    let without = crate::interop::config::parse(&document(json!({})), "unit").expect("parses");
    assert!(without.metering.is_none(), "metering must be off");
    assert!(without.a2a, "the interop surface must survive");
    assert_eq!(without.credentials.len(), 1, "credentials must survive");

    let with = crate::interop::config::parse(&document(json!({"tenant_slug": TENANT})), "unit")
        .expect("parses");
    assert_eq!(
        with.metering.as_ref().map(|m| m.tenant_slug.as_str()),
        Some(TENANT)
    );
}

/// A configured unit ALWAYS sends the field. It is not an `Option` anywhere
/// between the staged document and the wire, so there is no path that could
/// omit it.
#[test]
fn a_configured_unit_always_sends_its_tenant_slug() {
    let meter = Arc::new(Meter::inspectable());
    let turn = TurnMetering::for_unit(
        &meter,
        &config_with(Some(metering())),
        DeploymentId::new(),
        "support-bot",
    )
    .expect("metering is staged");
    turn.record(Surface::A2a, None, TurnUsage::default(), Duration::ZERO);
    let queued = meter.drain();
    let body = serde_json::to_value(&queued[0].event).expect("serialise");
    assert_eq!(body["tenant_slug"], TENANT);

    // The slug travels with the metering config, so a document whose top
    // level disagreed could not produce an event naming the wrong tenant.
    let mut diverged = config_with(Some(metering()));
    diverged.tenant_slug = Some("someone-else".into());
    let turn = TurnMetering::for_unit(&meter, &diverged, DeploymentId::new(), "support-bot")
        .expect("metering is staged");
    turn.record(Surface::Mcp, None, TurnUsage::default(), Duration::ZERO);
    let queued = meter.drain();
    assert_eq!(queued[0].event.tenant_slug, TENANT);
}
