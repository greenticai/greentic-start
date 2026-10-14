//! The access-policy door wired end to end through the listener: a unit that
//! stages `access.door` is narrowed by the admin's answer on `/a2a` and `/mcp`
//! (and the generic ingress), and a unit that does not never calls the admin.
//!
//! `interop::policy_door::tests` covers the decisions; these fail if
//! `resolve_interop_unit` or the generic gate stop consulting the door.

use super::*;
use crate::interop::metering::testkit::StubAdmin;

fn door_body(revoked_credentials: &[&str], mechanisms: &[&str]) -> String {
    json!({
        "generation": 4,
        "policy": {
            "private_mechanisms": mechanisms,
            "public_allowed": true,
            "public_rate_per_min": 600,
            "public_burst": 600,
            "public_daily_turn_cap": null,
        },
        "revoked_credential_ids": revoked_credentials,
        "revoked_client_ids": [],
        "public": {"daily_turns_used": 0},
    })
    .to_string()
}

/// The staged unit, pointing its metering (and so its door) at `admin`, with
/// or without `access.door`.
fn door_unit(admin: &StubAdmin, door: bool) -> Store {
    let mut doc: Value = serde_json::from_slice(&staged_interop_config_with(
        true,
        true,
        None,
        Some("https://w.example/mcp"),
    ))
    .expect("staged doc");
    doc["metering"] = json!({
        "endpoint": admin.metering_worker_usage().endpoint,
        "token": "gtm_usage-token",
    });
    if door {
        doc["access"] = json!({"door": true});
    }
    Store::Custom(doc.to_string().into_bytes())
}

async fn admin_answering(body: &str) -> StubAdmin {
    StubAdmin::answering("HTTP/1.1 200 OK", "ETag: \"g4\"\r\n", body).await
}

fn door_reads(admin: &StubAdmin) -> usize {
    admin
        .received()
        .iter()
        .filter(|request| request.starts_with("GET /api/v1/ingest/access-policy"))
        .count()
}

fn a2a_call() -> String {
    post("/a2a", &[AUTH], &send_message_body("ctx-1"))
}

fn mcp_call() -> String {
    post(
        "/mcp",
        &mcp_headers("tools/call"),
        &tools_call("how?", Some("c-1")),
    )
}

fn reply() -> Vec<Activity> {
    vec![Activity::custom("response", json!({"reply": "ok"}))]
}

#[tokio::test]
async fn a_revoked_bearer_is_refused_on_a2a_mcp_and_the_generic_ingress() {
    let admin = admin_answering(&door_body(&["c1"], &["api_key", "oauth"])).await;
    let (activation, _) = activation_with(door_unit(&admin, true));
    let state = state_with(activation, interop_with_base_url(reply()));
    for (name, request) in [
        ("a2a", a2a_call()),
        ("mcp", mcp_call()),
        ("generic", post("/", &[AUTH], "{}")),
    ] {
        let response = exchange(&state, false, &request).await;
        assert_eq!(response.status, 401, "{name}: {}", response.body);
    }
    assert_eq!(
        door_reads(&admin),
        1,
        "one coalesced, cached fetch for all three"
    );
}

#[tokio::test]
async fn an_unrevoked_bearer_still_runs_its_turn_on_a_door_unit() {
    let admin = admin_answering(&door_body(&["someone-else"], &["api_key", "oauth"])).await;
    let (activation, _) = activation_with(door_unit(&admin, true));
    let state = state_with(activation, interop_with_base_url(reply()));
    assert_eq!(exchange(&state, false, &a2a_call()).await.status, 200);
    assert_eq!(exchange(&state, false, &mcp_call()).await.status, 200);
}

#[tokio::test]
async fn a_mechanism_the_admin_withdrew_is_refused() {
    let admin = admin_answering(&door_body(&[], &["oauth"])).await;
    let (activation, _) = activation_with(door_unit(&admin, true));
    let state = state_with(activation, interop_with_base_url(reply()));
    assert_eq!(exchange(&state, false, &a2a_call()).await.status, 401);
    assert_eq!(exchange(&state, false, &mcp_call()).await.status, 401);
}

#[tokio::test]
async fn a_door_that_is_down_keeps_the_staged_policy() {
    let admin = StubAdmin::answering("HTTP/1.1 503 Service Unavailable", "", "").await;
    let (activation, _) = activation_with(door_unit(&admin, true));
    let state = state_with(activation, interop_with_base_url(reply()));
    assert_eq!(
        exchange(&state, false, &a2a_call()).await.status,
        200,
        "an outage never denies a unit the deploy allowed"
    );
    assert_eq!(door_reads(&admin), 1);
}

#[tokio::test]
async fn a_unit_that_does_not_stage_the_door_never_calls_the_admin() {
    let admin = admin_answering(&door_body(&["c1"], &[])).await;
    let (activation, _) = activation_with(door_unit(&admin, false));
    let state = state_with(activation, interop_with_base_url(reply()));
    assert_eq!(exchange(&state, false, &a2a_call()).await.status, 200);
    assert_eq!(exchange(&state, false, &mcp_call()).await.status, 200);
    // The admin is also this unit's usage endpoint, so it does hear from the
    // turns; what it must never hear is a door read.
    assert!(
        admin
            .received()
            .iter()
            .all(|request| !request.contains("access-policy")),
        "no flag, no fetch"
    );
}
