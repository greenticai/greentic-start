//! The access-policy door against a stub admin: what it may change, what it
//! may never change, and what a door that cannot answer does.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::cache::{REFRESH_FLOOR, TTL};
use super::*;
use crate::interop::auth::authenticate;
use crate::interop::caller::Caller;
use crate::interop::config::{AccessPolicy, Credential, PublicLimits};
use crate::interop::limits::{Charge, RateLimiter};
use crate::interop::mcp::auth::McpAuth;
use crate::interop::mcp::testkit::{self, StubIssuer};
use crate::interop::metering::testkit::{StubAdmin, TEST_TOKEN};

const BEARER: &str = "gtw_staged-token";
const TENANT: &str = "acme";
const UNIT: &str = "support-bot";
const DEPLOYMENT: &str = "dep-1";
const NOW_MS: u64 = 1_800_000_000_000;

fn credential(id: &str, token: &str) -> Credential {
    Credential {
        id: id.into(),
        sha256: Sha256::digest(token.as_bytes()).into(),
        expires_at_ms: None,
        forwards_caller: false,
    }
}

fn both() -> Vec<Mechanism> {
    vec![Mechanism::ApiKey, Mechanism::Oauth]
}

fn staged(access: AccessPolicy) -> InteropConfig {
    InteropConfig {
        a2a: true,
        mcp: true,
        credentials: vec![credential("c1", BEARER), credential("c2", "gtw_other")],
        tenant_slug: Some(TENANT.into()),
        access,
        ..InteropConfig::default()
    }
}

fn public(rate: u32, burst: u32, cap: Option<u32>) -> AccessPolicy {
    AccessPolicy {
        visibility: Visibility::Public,
        mechanisms: both(),
        public: PublicLimits {
            rate_per_min: rate,
            burst,
            daily_turn_cap: cap,
        },
        generation: 3,
    }
}

fn private(mechanisms: &[Mechanism]) -> AccessPolicy {
    AccessPolicy {
        visibility: Visibility::Private,
        mechanisms: mechanisms.to_vec(),
        ..AccessPolicy::default()
    }
}

/// The documented door body, field for field (one argument per field, so a
/// test reads as the JSON it stands for).
#[allow(clippy::too_many_arguments)]
fn body(
    mechanisms: &[&str],
    public_allowed: bool,
    rate: u32,
    burst: u32,
    cap: Option<u32>,
    revoked_credentials: &[&str],
    revoked_clients: &[&str],
    used: u64,
) -> String {
    json!({
        "generation": 9,
        "policy": {
            "private_mechanisms": mechanisms,
            "public_allowed": public_allowed,
            "public_rate_per_min": rate,
            "public_burst": burst,
            "public_daily_turn_cap": cap,
        },
        "revoked_credential_ids": revoked_credentials,
        "revoked_client_ids": revoked_clients,
        "public": {"daily_turns_used": used},
    })
    .to_string()
}

/// A body that changes nothing.
fn neutral() -> String {
    body(&["api_key", "oauth"], true, 1000, 1000, None, &[], &[], 0)
}

fn ok(body: &str) -> (String, String, String) {
    ok_with_etag(body, "\"g9\"")
}

fn ok_with_etag(body: &str, etag: &str) -> (String, String, String) {
    (
        "HTTP/1.1 200 OK".to_string(),
        format!("ETag: {etag}\r\n"),
        body.to_string(),
    )
}

fn status(line: &str) -> (String, String, String) {
    (format!("HTTP/1.1 {line}"), String::new(), String::new())
}

async fn stub(responses: &[(String, String, String)]) -> StubAdmin {
    let refs: Vec<(&str, &str, &str)> = responses
        .iter()
        .map(|(a, b, c)| (a.as_str(), b.as_str(), c.as_str()))
        .collect();
    StubAdmin::answering_in_turn(&refs).await
}

/// A staged config that points at `admin` and asks for the door.
fn with_door(admin: &StubAdmin, mut config: InteropConfig) -> InteropConfig {
    config.access_door = true;
    config.metering = Some(admin.metering_worker_usage());
    config
}

fn unit() -> UnitRef<'static> {
    UnitRef {
        tenant: TENANT,
        bundle_id: UNIT,
        deployment: Some(DEPLOYMENT),
    }
}

async fn effective(door: &PolicyDoor, config: InteropConfig) -> InteropConfig {
    door.effective(config, &unit(), &RateLimiter::default(), NOW_MS)
        .await
}

// ---- parsing ---------------------------------------------------------------

#[test]
fn the_documented_body_parses() {
    let answer = parse_answer(
        body(
            &["api_key"],
            false,
            30,
            5,
            Some(100),
            &["c1"],
            &["mcpc_1"],
            12,
        )
        .as_bytes(),
    )
    .expect("parses");
    assert_eq!(answer.generation, 9);
    assert_eq!(answer.private_mechanisms, vec![Mechanism::ApiKey]);
    assert!(!answer.public_allowed);
    assert_eq!((answer.public_rate_per_min, answer.public_burst), (30, 5));
    assert_eq!(answer.public_daily_turn_cap, Some(100));
    assert!(answer.revoked_credential_ids.contains("c1"));
    assert!(answer.revoked_client_ids.contains("mcpc_1"));
    assert_eq!(answer.daily_turns_used, 12);
}

#[test]
fn a_null_or_absent_cap_is_no_cap_and_unknown_fields_are_ignored() {
    let mut doc: Value = serde_json::from_str(&neutral()).expect("json");
    doc["future_field"] = json!({"x": 1});
    doc["policy"]["another"] = json!(true);
    assert_eq!(
        parse_answer(doc.to_string().as_bytes())
            .expect("parses")
            .public_daily_turn_cap,
        None
    );
    doc["policy"]
        .as_object_mut()
        .expect("object")
        .remove("public_daily_turn_cap");
    assert!(parse_answer(doc.to_string().as_bytes()).is_ok());
}

#[test]
fn an_unknown_mechanism_name_is_dropped_alone() {
    let answer =
        parse_answer(body(&["mtls", "oauth", "oauth"], true, 1, 1, None, &[], &[], 0).as_bytes())
            .expect("parses");
    assert_eq!(answer.private_mechanisms, vec![Mechanism::Oauth]);
}

#[test]
fn a_body_this_build_cannot_use_is_refused_without_echoing_it() {
    for bad in [
        "not json".to_string(),
        "{}".to_string(),
        body(&["api_key"], true, 0, 5, None, &[], &[], 0),
        body(&["api_key"], true, 5, 0, None, &[], &[], 0),
    ] {
        parse_answer(bad.as_bytes()).expect_err(&bad);
    }
    let mut missing: Value = serde_json::from_str(&neutral()).expect("json");
    missing
        .as_object_mut()
        .expect("object")
        .remove("revoked_client_ids");
    parse_answer(missing.to_string().as_bytes()).expect_err("a documented field is missing");
    // A wrong type with a recognisable value in it: the message names a
    // position, not the value.
    let mut typed: Value = serde_json::from_str(&neutral()).expect("json");
    typed["generation"] = json!("SECRET-LOOKING-VALUE");
    let err = parse_answer(typed.to_string().as_bytes()).expect_err("typed");
    assert!(!err.contains("SECRET"), "{err}");
}

// ---- tightening ------------------------------------------------------------

fn answer(json_body: String) -> DoorAnswer {
    parse_answer(json_body.as_bytes()).expect("parses")
}

#[test]
fn mechanisms_are_intersected_and_never_widened() {
    // Narrowed.
    let narrowed = tighten(
        staged(private(&both())),
        &answer(body(&["oauth"], true, 9, 9, None, &[], &[], 0)),
    );
    assert_eq!(narrowed.access.mechanisms, vec![Mechanism::Oauth]);
    // The door lists more than the deploy staged: ignored.
    let widened = tighten(
        staged(private(&[Mechanism::Oauth])),
        &answer(body(&["api_key", "oauth"], true, 9, 9, None, &[], &[], 0)),
    );
    assert_eq!(widened.access.mechanisms, vec![Mechanism::Oauth]);
    // No overlap: deny, never a fallback.
    let denied = tighten(
        staged(private(&[Mechanism::ApiKey])),
        &answer(body(&["oauth"], true, 9, 9, None, &[], &[], 0)),
    );
    assert!(denied.access.mechanisms.is_empty());
}

#[test]
fn a_public_unit_can_be_made_private_but_a_private_one_is_never_made_public() {
    let closed = tighten(
        staged(public(60, 20, None)),
        &answer(body(&["api_key", "oauth"], false, 9, 9, None, &[], &[], 0)),
    );
    assert_eq!(closed.access.visibility, Visibility::Private);
    let open = tighten(
        staged(private(&both())),
        &answer(body(&["api_key", "oauth"], true, 9, 9, None, &[], &[], 0)),
    );
    assert_eq!(open.access.visibility, Visibility::Private);
}

#[test]
fn limits_are_the_minimum_and_a_cap_can_appear_but_never_be_lifted() {
    let lower = tighten(
        staged(public(60, 20, Some(100))),
        &answer(body(&["api_key"], true, 30, 5, Some(40), &[], &[], 0)),
    );
    assert_eq!(
        lower.access.public,
        PublicLimits {
            rate_per_min: 30,
            burst: 5,
            daily_turn_cap: Some(40)
        }
    );
    // A higher door value changes nothing.
    let higher = tighten(
        staged(public(60, 20, Some(100))),
        &answer(body(&["api_key"], true, 600, 200, Some(1000), &[], &[], 0)),
    );
    assert_eq!(
        higher.access.public,
        PublicLimits {
            rate_per_min: 60,
            burst: 20,
            daily_turn_cap: Some(100)
        }
    );
    // The door adds a cap where none was staged; it cannot remove one.
    let added = tighten(
        staged(public(60, 20, None)),
        &answer(body(&["api_key"], true, 60, 20, Some(7), &[], &[], 0)),
    );
    assert_eq!(added.access.public.daily_turn_cap, Some(7));
    let kept = tighten(
        staged(public(60, 20, Some(7))),
        &answer(body(&["api_key"], true, 60, 20, None, &[], &[], 0)),
    );
    assert_eq!(kept.access.public.daily_turn_cap, Some(7));
}

#[test]
fn a_revoked_credential_is_removed_and_the_others_stay() {
    let config = tighten(
        staged(private(&both())),
        &answer(body(
            &["api_key"],
            true,
            9,
            9,
            None,
            &["c1"],
            &["mcpc_1"],
            0,
        )),
    );
    let ids: Vec<_> = config.credentials.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, vec!["c2"]);
    assert!(config.revoked_client_ids.contains("mcpc_1"));
}

// ---- the flag --------------------------------------------------------------

#[tokio::test]
async fn a_unit_without_the_flag_is_never_fetched_for_and_comes_back_untouched() {
    let admin = stub(&[ok(&body(&["oauth"], false, 1, 1, Some(1), &["c1"], &[], 0))]).await;
    let mut config = staged(public(60, 20, None));
    config.metering = Some(admin.metering_worker_usage());
    assert!(!config.access_door);
    let door = PolicyDoor::default();
    let out = effective(&door, config.clone()).await;
    assert_eq!(out, config, "byte-identical");
    assert_eq!(admin.count(), 0, "no flag, no call");
}

#[tokio::test]
async fn a_flagged_unit_without_a_metering_block_keeps_the_staged_policy() {
    let mut config = staged(private(&both()));
    config.access_door = true;
    let door = PolicyDoor::default();
    assert_eq!(effective(&door, config.clone()).await, config);
}

#[tokio::test]
async fn a_metering_endpoint_that_is_not_worker_usage_keeps_the_staged_policy() {
    let admin = stub(&[ok(&neutral())]).await;
    let mut config = staged(private(&both()));
    config.access_door = true;
    config.metering = Some(admin.metering());
    let door = PolicyDoor::default();
    assert_eq!(effective(&door, config.clone()).await, config);
    assert_eq!(admin.count(), 0);
}

// ---- fetching --------------------------------------------------------------

#[tokio::test]
async fn the_door_tightens_and_is_asked_beside_the_metering_endpoint_with_the_unit_token() {
    let admin = stub(&[ok(&body(
        &["oauth"],
        false,
        30,
        5,
        Some(40),
        &["c1"],
        &["mcpc_1"],
        0,
    ))])
    .await;
    let door = PolicyDoor::default();
    let out = effective(&door, with_door(&admin, staged(public(60, 20, None)))).await;
    assert_eq!(out.access.mechanisms, vec![Mechanism::Oauth]);
    assert_eq!(out.access.visibility, Visibility::Private);
    assert_eq!(out.access.public.daily_turn_cap, Some(40));
    assert_eq!(out.credentials.len(), 1);
    assert!(out.revoked_client_ids.contains("mcpc_1"));

    let request = admin.received().remove(0);
    assert!(
        request.starts_with("GET /api/v1/ingest/access-policy HTTP/1.1"),
        "{request}"
    );
    assert!(
        request
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {TEST_TOKEN}").to_ascii_lowercase()),
        "{request}"
    );
}

#[tokio::test]
async fn an_answer_is_reused_inside_the_ttl_then_revalidated_with_its_etag() {
    let admin = stub(&[
        ok_with_etag(&body(&["oauth"], true, 9, 9, None, &[], &[], 0), "\"v1\""),
        status("304 Not Modified"),
    ])
    .await;
    let door = PolicyDoor::default();
    let config = with_door(&admin, staged(private(&both())));
    for _ in 0..5 {
        let out = effective(&door, config.clone()).await;
        assert_eq!(out.access.mechanisms, vec![Mechanism::Oauth]);
    }
    assert_eq!(admin.count(), 1, "inside the TTL the answer is reused");

    door.advance(TTL + Duration::from_secs(1));
    let out = effective(&door, config.clone()).await;
    assert_eq!(admin.count(), 2);
    assert_eq!(
        out.access.mechanisms,
        vec![Mechanism::Oauth],
        "a 304 keeps the answer"
    );
    let second = admin.received().remove(1);
    assert!(second.contains("\"v1\""), "If-None-Match sent: {second}");
    // The 304 restarted the TTL.
    effective(&door, config).await;
    assert_eq!(admin.count(), 2);
}

#[tokio::test]
async fn concurrent_callers_cause_one_request() {
    let admin = stub(&[ok(&neutral())]).await;
    let door = Arc::new(PolicyDoor::default());
    let config = with_door(&admin, staged(private(&both())));
    let mut tasks = Vec::new();
    for _ in 0..12 {
        let door = Arc::clone(&door);
        let config = config.clone();
        tasks.push(tokio::spawn(async move { effective(&door, config).await }));
    }
    for task in tasks {
        task.await.expect("task");
    }
    assert_eq!(admin.count(), 1);
}

#[tokio::test]
async fn a_failing_door_is_not_asked_again_before_the_refresh_floor() {
    let admin = stub(&[status("503 Service Unavailable")]).await;
    let door = PolicyDoor::default();
    let config = with_door(&admin, staged(private(&both())));
    for _ in 0..4 {
        assert_eq!(effective(&door, config.clone()).await, config);
    }
    assert_eq!(admin.count(), 1);
    door.advance(REFRESH_FLOOR + Duration::from_secs(1));
    effective(&door, config).await;
    assert_eq!(admin.count(), 2);
}

#[tokio::test]
async fn a_first_fetch_that_fails_keeps_the_staged_policy_whatever_the_failure() {
    for failure in [
        status("500 Internal Server Error"),
        status("401 Unauthorized"),
        status("403 Forbidden"),
        status("404 Not Found"),
        (
            "HTTP/1.1 200 OK".to_string(),
            String::new(),
            "{not json".to_string(),
        ),
        (
            "HTTP/1.1 200 OK".to_string(),
            String::new(),
            body(&["oauth"], false, 0, 0, None, &["c1"], &[], 0),
        ),
    ] {
        let admin = stub(std::slice::from_ref(&failure)).await;
        let door = PolicyDoor::default();
        let config = with_door(&admin, staged(public(60, 20, Some(5))));
        assert_eq!(
            effective(&door, config.clone()).await,
            config,
            "{}",
            failure.0
        );
    }
}

#[tokio::test]
async fn a_dead_door_keeps_the_staged_policy_and_a_slow_one_does_not_hang_the_request() {
    // Nothing listening.
    let closed = crate::interop::metering::testkit::closed_port().await;
    let mut config = staged(private(&both()));
    config.access_door = true;
    config.metering = Some(crate::interop::metering::testkit::metering_at(&format!(
        "http://127.0.0.1:{}/api/v1/ingest/worker-usage",
        closed.port
    )));
    let door = PolicyDoor::default();
    assert_eq!(effective(&door, config.clone()).await, config);

    // Accepts and never answers.
    let port = crate::interop::metering::testkit::silent_peer().await;
    config.metering = Some(crate::interop::metering::testkit::metering_at(&format!(
        "http://127.0.0.1:{port}/api/v1/ingest/worker-usage"
    )));
    let started = std::time::Instant::now();
    assert_eq!(
        effective(&PolicyDoor::default(), config.clone()).await,
        config
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "bounded by the request timeout"
    );
}

#[tokio::test]
async fn a_good_answer_survives_every_later_failure() {
    let admin = stub(&[
        ok(&body(&["oauth"], true, 9, 9, None, &[], &[], 0)),
        status("500 Internal Server Error"),
        status("403 Forbidden"),
        ("HTTP/1.1 200 OK".into(), String::new(), "garbage".into()),
    ])
    .await;
    let door = PolicyDoor::default();
    let config = with_door(&admin, staged(private(&both())));
    assert_eq!(
        effective(&door, config.clone()).await.access.mechanisms,
        vec![Mechanism::Oauth]
    );
    for _ in 0..3 {
        door.advance(TTL + Duration::from_secs(1));
        assert_eq!(
            effective(&door, config.clone()).await.access.mechanisms,
            vec![Mechanism::Oauth],
            "the last good answer keeps serving"
        );
    }
    assert_eq!(admin.count(), 4);
}

#[tokio::test]
async fn a_later_wider_answer_cannot_reopen_what_the_staged_policy_closed() {
    let admin = stub(&[ok(&body(
        &["api_key", "oauth"],
        true,
        9999,
        9999,
        None,
        &[],
        &[],
        0,
    ))])
    .await;
    let door = PolicyDoor::default();
    let config = with_door(&admin, staged(private(&[Mechanism::Oauth])));
    let out = effective(&door, config).await;
    assert_eq!(out.access.mechanisms, vec![Mechanism::Oauth]);
    assert_eq!(out.access.visibility, Visibility::Private);
}

// ---- the daily budget ------------------------------------------------------

#[tokio::test]
async fn the_daily_count_the_door_reports_survives_a_cold_start() {
    let admin = stub(&[ok(&body(
        &["api_key", "oauth"],
        true,
        600,
        600,
        Some(10),
        &[],
        &[],
        9,
    ))])
    .await;
    let door = PolicyDoor::default();
    // A fresh process: nothing counted locally.
    let limiter = RateLimiter::default();
    let config = with_door(&admin, staged(public(600, 600, Some(100))));
    let out = door.effective(config, &unit(), &limiter, NOW_MS).await;
    assert_eq!(
        out.access.public.daily_turn_cap,
        Some(10),
        "min(staged, door)"
    );
    assert_eq!(limiter.anonymous.daily_count(DEPLOYMENT), Some(9));

    let caller = Caller::anonymous(Some("203.0.113.9"));
    assert!(
        limiter
            .admit(&caller, &out.access, DEPLOYMENT, Charge::TURN, NOW_MS)
            .is_ok(),
        "the tenth turn of the day is the last"
    );
    assert!(
        limiter
            .admit(&caller, &out.access, DEPLOYMENT, Charge::TURN, NOW_MS)
            .is_err(),
        "the eleventh is refused: 9 used by the admin's count + 1 served here"
    );
}

#[tokio::test]
async fn reconciling_never_lowers_a_local_count_and_starts_over_on_a_new_day() {
    let limiter = RateLimiter::default();
    limiter.anonymous.reconcile_daily("d", NOW_MS, 3);
    limiter.anonymous.reconcile_daily("d", NOW_MS, 1);
    assert_eq!(limiter.anonymous.daily_count("d"), Some(3));
    limiter
        .anonymous
        .reconcile_daily("d", NOW_MS + 86_400_000, 0);
    assert_eq!(limiter.anonymous.daily_count("d"), Some(0));
}

// ---- enforcement through the gate -------------------------------------------

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

async fn gate(config: &InteropConfig, header: Option<&str>) -> McpAuth {
    authenticate(
        config,
        Some("https://w.example/a2a"),
        header,
        false,
        0,
        Some("203.0.113.7"),
    )
    .await
}

#[tokio::test]
async fn a_revoked_bearer_is_refused_and_a_public_unit_does_not_downgrade_it_to_anonymous() {
    let admin = stub(&[ok(&body(
        &["api_key", "oauth"],
        true,
        600,
        600,
        None,
        &["c1"],
        &[],
        0,
    ))])
    .await;
    let door = PolicyDoor::default();
    let config = with_door(&admin, staged(public(600, 600, None)));
    assert!(matches!(
        gate(&config, Some(&bearer(BEARER))).await,
        McpAuth::Allowed(Caller::Bearer(_))
    ));
    let out = effective(&door, config).await;
    assert_eq!(
        gate(&out, Some(&bearer(BEARER))).await,
        McpAuth::Unauthorized
    );
    assert!(
        matches!(
            gate(&out, Some(&bearer("gtw_other"))).await,
            McpAuth::Allowed(Caller::Bearer(id)) if id == "c2"
        ),
        "an unrevoked credential keeps working"
    );
}

#[tokio::test]
async fn an_empty_mechanism_intersection_refuses_every_credential() {
    let admin = stub(&[ok(&body(&["oauth"], true, 600, 600, None, &[], &[], 0))]).await;
    let door = PolicyDoor::default();
    let config = with_door(&admin, staged(private(&[Mechanism::ApiKey])));
    let out = effective(&door, config).await;
    assert!(out.access.mechanisms.is_empty());
    assert_eq!(
        gate(&out, Some(&bearer(BEARER))).await,
        McpAuth::Unauthorized
    );
    assert_eq!(gate(&out, None).await, McpAuth::Unauthorized);
}

#[tokio::test]
async fn a_revoked_service_client_is_refused_without_calling_the_issuer_even_for_an_old_jwt() {
    let issuer = StubIssuer::serving_keys(1).await;
    let resource = "https://w.example/a2a";
    let sub = "svc:mcpc_01J@acme";
    // Minted BEFORE the revocation: valid signature, valid expiry.
    let token = testkit::mint_token(&issuer.url, resource, sub, TENANT, 600);

    let mut config = staged(private(&both()));
    config.issuer = Some(issuer.url.clone());
    config.a2a_resource = Some(resource.into());
    config.revoked_client_ids = ["mcpc_01J".to_string()].into_iter().collect();
    assert_eq!(
        authenticate(
            &config,
            Some(resource),
            Some(&bearer(&token)),
            false,
            0,
            None
        )
        .await,
        McpAuth::Unauthorized
    );
    assert_eq!(
        issuer.fetches.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the issuer was not asked"
    );

    // The control: the same token with no revocation passes, so the refusal
    // above is the revocation and nothing else.
    config.revoked_client_ids.clear();
    assert!(matches!(
        authenticate(
            &config,
            Some(resource),
            Some(&bearer(&token)),
            false,
            0,
            None
        )
        .await,
        McpAuth::Allowed(Caller::Oauth(_))
    ));
}

#[tokio::test]
async fn revoking_one_client_leaves_another_clients_and_users_tokens_alone() {
    let issuer = StubIssuer::serving_keys(2).await;
    let resource = "https://w.example/a2a";
    let mut config = staged(private(&both()));
    config.issuer = Some(issuer.url.clone());
    config.a2a_resource = Some(resource.into());
    config.revoked_client_ids = ["mcpc_revoked".to_string()].into_iter().collect();
    for sub in ["svc:mcpc_other@acme", "user-1"] {
        let token = testkit::mint_token(&issuer.url, resource, sub, TENANT, 600);
        assert!(
            matches!(
                authenticate(
                    &config,
                    Some(resource),
                    Some(&bearer(&token)),
                    false,
                    0,
                    None
                )
                .await,
                McpAuth::Allowed(_)
            ),
            "{sub}"
        );
    }
}
