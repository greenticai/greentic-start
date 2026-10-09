use std::sync::Arc;

use super::*;
use crate::http_routes::RevisionScope;
use crate::triggers::schema;
use greentic_deploy_spec::{BundleId, DeploymentId, RevisionId};
use ulid::Ulid;

const META: &str = include_str!("../../tests/fixtures/triggers/triggers_v1_meta_webhook.json");
const GENERIC: &str =
    include_str!("../../tests/fixtures/triggers/triggers_v1_generic_webhook.json");
const CRON: &str = include_str!("../../tests/fixtures/triggers/triggers_v1_cron.json");

fn spec_of(fixture: &str, pack: &str) -> TriggerSpec {
    schema::parse(fixture.as_bytes(), pack)
        .expect("fixture parses")
        .triggers
        .remove(0)
}

fn loaded(spec: TriggerSpec, pack: &str) -> LoadedTrigger {
    LoadedTrigger {
        scope: RevisionScope {
            deployment_id: DeploymentId(Ulid::new()),
            bundle_id: BundleId::new("bundle"),
            revision_id: RevisionId(Ulid::new()),
        },
        tenant: "acme".into(),
        pack_id: pack.into(),
        spec: Arc::new(spec),
        unavailable: None,
    }
}

fn headers() -> Vec<(String, String)> {
    vec![
        ("Content-Type".into(), "application/json".into()),
        ("X-Hub-Signature-256".into(), "sha256=deadbeef".into()),
        ("Authorization".into(), "Bearer s3cret".into()),
        ("X-Request-Id".into(), "req-1".into()),
    ]
}

#[test]
fn per_run_gives_every_firing_its_own_session() {
    let spec = spec_of(META, "pack.acme.community");
    assert_eq!(
        session_hint(&spec, "01FIRING", None),
        "trigger:threads_replies:01FIRING"
    );
}

#[test]
fn per_key_shares_a_session_by_the_resolved_key_and_falls_back_to_per_run() {
    let spec = spec_of(GENERIC, "pack.acme.orders");
    let body = serde_json::json!({"order": {"customer_id": "c-9"}});
    let with_key = RequestView {
        headers: &[],
        query: &[],
        body: Some(&body),
    };
    assert_eq!(
        session_hint(&spec, "F1", Some(&with_key)),
        "trigger:order_created:c-9"
    );
    let without = RequestView {
        headers: &[],
        query: &[],
        body: None,
    };
    assert_eq!(
        session_hint(&spec, "F2", Some(&without)),
        "trigger:order_created:F2"
    );
}

#[test]
fn the_flow_never_sees_the_credentials_that_authenticated_the_request() {
    let spec = spec_of(GENERIC, "pack.acme.orders");
    let hs = headers();
    let body = serde_json::json!({"order": {"customer_id": "c-9"}});
    let view = RequestView {
        headers: &hs,
        query: &[],
        body: Some(&body),
    };
    let payload = webhook_payload(&spec, "F", Utc::now(), "POST", &view, b"{}");
    let passed = payload["webhook"]["headers"].as_object().unwrap();
    assert!(passed.contains_key("content-type"));
    // Named by `idempotency.key`, so the flow was promised it.
    assert!(passed.contains_key("x-request-id"));
    assert!(!passed.contains_key("authorization"), "{passed:?}");
    assert!(!passed.contains_key("x-hub-signature-256"), "{passed:?}");
    assert_eq!(payload["webhook"]["body"]["order"]["customer_id"], "c-9");
    assert!(payload["cron"].is_null());
}

#[test]
fn a_non_json_body_reaches_the_flow_as_text() {
    let spec = spec_of(META, "pack.acme.community");
    let view = RequestView {
        headers: &[],
        query: &[],
        body: None,
    };
    let payload = webhook_payload(&spec, "F", Utc::now(), "POST", &view, b"a=1&b=2");
    assert!(payload["webhook"]["body"].is_null());
    assert_eq!(payload["webhook"]["body_text"], "a=1&b=2");
}

#[test]
fn a_cron_payload_carries_the_scheduled_time_and_zone() {
    let spec = spec_of(CRON, "pack.acme.reports");
    let TriggerKind::Cron(cron) = &spec.kind else {
        panic!("cron")
    };
    let at = Utc::now();
    let payload = cron_payload(&spec, cron, "F", at, at);
    assert_eq!(payload["cron"]["timezone"], "Europe/Amsterdam");
    assert_eq!(payload["cron"]["expr"], "0 0 9 * * MON-FRI");
    assert_eq!(payload["trigger"]["kind"], "cron");
    assert!(payload["webhook"].is_null());
}

#[test]
fn the_envelope_enters_the_declared_node_of_the_declared_pack() {
    let l = loaded(spec_of(META, "pack.acme.community"), "pack.acme.community");
    let firing = Firing {
        firing_id: "01F".into(),
        session_hint: "trigger:threads_replies:01F".into(),
        payload: serde_json::json!({"x": 1}),
    };
    let env = envelope(&l, &firing);
    assert_eq!(env.entry_node.as_deref(), Some("normalize_event"));
    assert_eq!(env.pack_id.as_deref(), Some("pack.acme.community"));
    assert_eq!(env.flow_id, "main");
    assert_eq!(env.provider.as_deref(), Some("trigger"));
    assert_eq!(
        env.session_hint.as_deref(),
        Some("trigger:threads_replies:01F")
    );
    assert_eq!(env.activity_id.as_deref(), Some("01F"));
    assert!(env.messaging_endpoint_id.is_none());
}
