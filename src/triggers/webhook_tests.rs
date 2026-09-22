//! The refusal order of the trigger route, end to end through
//! [`handle_selected`] with a fake runner. Each test states the one property
//! it pins; together they are conformance checklist items 2, 3 and 7 of the
//! contract (§15).

use std::collections::HashMap;
use std::sync::Mutex;

use hmac::{Hmac, KeyInit, Mac};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use ulid::Ulid;

use super::*;
use crate::http_routes::RevisionScope;
use crate::triggers::schema;
use crate::triggers::store::InMemoryTriggerStore;
use greentic_deploy_spec::{BundleId, RevisionId};

const META: &str = include_str!("../../tests/fixtures/triggers/triggers_v1_meta_webhook.json");
const GENERIC: &str =
    include_str!("../../tests/fixtures/triggers/triggers_v1_generic_webhook.json");

const APP_SECRET: &[u8] = b"meta-app-secret";
const VERIFY_TOKEN: &[u8] = b"hub-verify-token";
const INGEST_KEY: &[u8] = b"orders-ingest-key";

struct FakeHost {
    secrets: HashMap<String, Vec<u8>>,
    fired: Mutex<Vec<Firing>>,
    /// Keep permits alive, as a still-running flow would.
    held: Mutex<Vec<OwnedSemaphorePermit>>,
}

impl FakeHost {
    fn with_secrets() -> Self {
        Self {
            secrets: HashMap::from([
                ("threads/app_secret".to_string(), APP_SECRET.to_vec()),
                ("threads/verify_token".to_string(), VERIFY_TOKEN.to_vec()),
                ("orders/ingest_key".to_string(), INGEST_KEY.to_vec()),
            ]),
            fired: Mutex::new(Vec::new()),
            held: Mutex::new(Vec::new()),
        }
    }

    fn without_secrets() -> Self {
        Self {
            secrets: HashMap::new(),
            ..Self::with_secrets()
        }
    }

    fn fired(&self) -> Vec<Firing> {
        self.fired.lock().unwrap().clone()
    }
}

#[async_trait]
impl TriggerHost for FakeHost {
    async fn read_secret(
        &self,
        _loaded: &LoadedTrigger,
        secret_ref: &str,
    ) -> anyhow::Result<Vec<u8>> {
        self.secrets
            .get(secret_ref)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no secret {secret_ref}"))
    }

    fn spawn_fire(
        &self,
        _loaded: Arc<LoadedTrigger>,
        firing: Firing,
        permit: OwnedSemaphorePermit,
    ) {
        self.fired.lock().unwrap().push(firing);
        self.held.lock().unwrap().push(permit);
    }
}

fn loaded_from(doc: &Value) -> Arc<LoadedTrigger> {
    let pack = doc["pack_id"].as_str().unwrap().to_string();
    let spec = schema::parse(doc.to_string().as_bytes(), &pack)
        .expect("fixture parses")
        .triggers
        .remove(0);
    Arc::new(LoadedTrigger {
        scope: RevisionScope {
            deployment_id: DeploymentId(Ulid::new()),
            bundle_id: BundleId::new("bundle"),
            revision_id: RevisionId(Ulid::new()),
        },
        tenant: "acme".into(),
        pack_id: pack,
        spec: Arc::new(spec),
        unavailable: None,
    })
}

fn meta() -> Value {
    serde_json::from_str(META).unwrap()
}

/// The generic fixture minus `allowed_sources`, which this host refuses to
/// serve (it cannot enforce it yet — see `table::unavailable_reason`).
fn generic() -> Value {
    let mut doc: Value = serde_json::from_str(GENERIC).unwrap();
    doc["triggers"][0]["webhook"]["allowed_sources"] = json!([]);
    doc
}

fn sign(body: &[u8]) -> String {
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(APP_SECRET).unwrap();
    mac.update(body);
    let hex: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("sha256={hex}")
}

fn request(method: &str, uri: &str, headers: &[(&str, &str)], body: &[u8]) -> Request<Full<Bytes>> {
    let mut builder = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    builder
        .body(Full::new(Bytes::copy_from_slice(body)))
        .unwrap()
}

async fn run(
    host: &FakeHost,
    store: &InMemoryTriggerStore,
    loaded: &Arc<LoadedTrigger>,
    req: Request<Full<Bytes>>,
) -> Response<Full<Bytes>> {
    handle_selected(req, host, store, "local", Arc::clone(loaded)).await
}

async fn body_text(resp: Response<Full<Bytes>>) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

const THREADS_BODY: &[u8] = br#"{"object":"threads","entry":[{"id":"1","changes":[{"field":"replies","value":{"id":"r-1","text":"hi"}}]}]}"#;

#[tokio::test]
async fn a_correctly_signed_delivery_fires_once_and_answers_200_with_no_body() {
    let (host, store, t) = (
        FakeHost::with_secrets(),
        InMemoryTriggerStore::default(),
        loaded_from(&meta()),
    );
    let sig = sign(THREADS_BODY);
    let resp = run(
        &host,
        &store,
        &t,
        request(
            "POST",
            "/trigger/threads_replies",
            &[
                ("X-Hub-Signature-256", &sig),
                ("content-type", "application/json"),
            ],
            THREADS_BODY,
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_text(resp).await, "");
    let fired = host.fired();
    assert_eq!(fired.len(), 1);
    assert!(
        fired[0]
            .session_hint
            .starts_with("trigger:threads_replies:")
    );
    assert_eq!(fired[0].payload["webhook"]["body"]["entry"][0]["id"], "1");
    // The signature authenticated the request; it is not the flow's to read.
    assert!(
        fired[0].payload["webhook"]["headers"]
            .get("x-hub-signature-256")
            .is_none()
    );
}

#[tokio::test]
async fn one_changed_body_byte_is_401_and_never_runs_the_flow() {
    let (host, store, t) = (
        FakeHost::with_secrets(),
        InMemoryTriggerStore::default(),
        loaded_from(&meta()),
    );
    let sig = sign(THREADS_BODY);
    let mut tampered = THREADS_BODY.to_vec();
    let last = tampered.len() - 3;
    tampered[last] = b'X';
    let resp = run(
        &host,
        &store,
        &t,
        request("POST", "/t", &[("X-Hub-Signature-256", &sig)], &tampered),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_text(resp).await, "", "a refusal carries no detail");
    assert!(host.fired().is_empty());
}

#[tokio::test]
async fn a_missing_signature_is_401() {
    let (host, store, t) = (
        FakeHost::with_secrets(),
        InMemoryTriggerStore::default(),
        loaded_from(&meta()),
    );
    let resp = run(&host, &store, &t, request("POST", "/t", &[], THREADS_BODY)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(host.fired().is_empty());
}

#[tokio::test]
async fn an_unreadable_secret_is_503_never_an_unverified_run() {
    let (host, store, t) = (
        FakeHost::without_secrets(),
        InMemoryTriggerStore::default(),
        loaded_from(&meta()),
    );
    let sig = sign(THREADS_BODY);
    let resp = run(
        &host,
        &store,
        &t,
        request("POST", "/t", &[("X-Hub-Signature-256", &sig)], THREADS_BODY),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(host.fired().is_empty());
}

#[tokio::test]
async fn the_hub_challenge_echoes_with_the_right_token_and_403s_with_a_wrong_one() {
    let (host, store, t) = (
        FakeHost::with_secrets(),
        InMemoryTriggerStore::default(),
        loaded_from(&meta()),
    );
    let ok = run(
        &host,
        &store,
        &t,
        request(
            "GET",
            "/t?hub.mode=subscribe&hub.verify_token=hub-verify-token&hub.challenge=1158201444",
            &[],
            b"",
        ),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(body_text(ok).await, "1158201444");

    let bad = run(
        &host,
        &store,
        &t,
        request(
            "GET",
            "/t?hub.mode=subscribe&hub.verify_token=nope&hub.challenge=1",
            &[],
            b"",
        ),
    )
    .await;
    assert_eq!(bad.status(), StatusCode::FORBIDDEN);

    let not_a_challenge = run(&host, &store, &t, request("GET", "/t", &[], b"")).await;
    assert_eq!(not_a_challenge.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(
        host.fired().is_empty(),
        "GET never fires a trigger with a challenge"
    );
}

#[tokio::test]
async fn a_method_the_trigger_does_not_declare_is_405() {
    let (host, store, t) = (
        FakeHost::with_secrets(),
        InMemoryTriggerStore::default(),
        loaded_from(&meta()),
    );
    let resp = run(&host, &store, &t, request("PUT", "/t", &[], b"{}")).await;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn a_body_over_the_limit_is_413_before_any_verification() {
    let mut doc = meta();
    doc["triggers"][0]["webhook"]["max_body_bytes"] = json!(16);
    // No secrets: if verification ran first this would be a 503.
    let (host, store, t) = (
        FakeHost::without_secrets(),
        InMemoryTriggerStore::default(),
        loaded_from(&doc),
    );
    let resp = run(&host, &store, &t, request("POST", "/t", &[], THREADS_BODY)).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn a_disabled_trigger_is_404_and_an_unavailable_one_is_503() {
    let mut doc = meta();
    doc["triggers"][0]["enabled"] = json!(false);
    let (host, store) = (FakeHost::with_secrets(), InMemoryTriggerStore::default());
    let disabled = loaded_from(&doc);
    assert_eq!(
        run(&host, &store, &disabled, request("POST", "/t", &[], b"{}"))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );

    let base = loaded_from(&meta());
    let unavailable = Arc::new(LoadedTrigger {
        unavailable: Some("test"),
        ..(*base).clone()
    });
    assert_eq!(
        run(
            &host,
            &store,
            &unavailable,
            request("POST", "/t", &[], b"{}")
        )
        .await
        .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(host.fired().is_empty());
}

#[tokio::test]
async fn a_repeated_delivery_id_answers_200_without_firing_again() {
    let (host, store, t) = (
        FakeHost::with_secrets(),
        InMemoryTriggerStore::default(),
        loaded_from(&generic()),
    );
    let auth = "Bearer orders-ingest-key";
    let body = br#"{"order":{"customer_id":"c-9"}}"#;
    for _ in 0..2 {
        let resp = run(
            &host,
            &store,
            &t,
            request(
                "POST",
                "/t",
                &[("Authorization", auth), ("X-Request-Id", "req-1")],
                body,
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
    assert_eq!(host.fired().len(), 1, "the retry is suppressed");
    let other = run(
        &host,
        &store,
        &t,
        request(
            "POST",
            "/t",
            &[("Authorization", auth), ("X-Request-Id", "req-2")],
            body,
        ),
    )
    .await;
    assert_eq!(other.status(), StatusCode::OK);
    assert_eq!(host.fired().len(), 2);
    // per_key session: both firings for customer c-9 share one session.
    assert_eq!(host.fired()[0].session_hint, "trigger:order_created:c-9");
    assert_eq!(host.fired()[1].session_hint, "trigger:order_created:c-9");
}

#[tokio::test]
async fn a_wrong_bearer_token_is_401() {
    let (host, store, t) = (
        FakeHost::with_secrets(),
        InMemoryTriggerStore::default(),
        loaded_from(&generic()),
    );
    let resp = run(
        &host,
        &store,
        &t,
        request("POST", "/t", &[("Authorization", "Bearer guess")], b"{}"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(host.fired().is_empty());
}

#[tokio::test]
async fn a_full_concurrency_limit_is_429_with_retry_after() {
    let mut doc = meta();
    doc["triggers"][0]["limits"]["max_concurrency"] = json!(1);
    let (host, store, t) = (
        FakeHost::with_secrets(),
        InMemoryTriggerStore::default(),
        loaded_from(&doc),
    );
    let sig = sign(THREADS_BODY);
    let first = run(
        &host,
        &store,
        &t,
        request("POST", "/t", &[("X-Hub-Signature-256", &sig)], THREADS_BODY),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    // The fake holds the first permit, as a still-running flow would.
    let second = run(
        &host,
        &store,
        &t,
        request("POST", "/t", &[("X-Hub-Signature-256", &sig)], THREADS_BODY),
    )
    .await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(second.headers().get(header::RETRY_AFTER).unwrap(), "5");
    assert_eq!(host.fired().len(), 1);
}

#[tokio::test]
async fn an_exhausted_hourly_budget_is_429() {
    let mut doc = meta();
    doc["triggers"][0]["limits"]["max_firings_per_hour"] = json!(1);
    let (host, store, t) = (
        FakeHost::with_secrets(),
        InMemoryTriggerStore::default(),
        loaded_from(&doc),
    );
    let sig = sign(THREADS_BODY);
    let first = run(
        &host,
        &store,
        &t,
        request("POST", "/t", &[("X-Hub-Signature-256", &sig)], THREADS_BODY),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let second = run(
        &host,
        &store,
        &t,
        request("POST", "/t", &[("X-Hub-Signature-256", &sig)], THREADS_BODY),
    )
    .await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(host.fired().len(), 1);
}

#[test]
fn the_meta_handshake_query_decodes() {
    let q = parse_query(Some(
        "hub.mode=subscribe&hub.verify_token=a%2Bb+c&hub.challenge=123",
    ));
    assert_eq!(
        q,
        vec![
            ("hub.mode".into(), "subscribe".into()),
            ("hub.verify_token".into(), "a+b c".into()),
            ("hub.challenge".into(), "123".into()),
        ]
    );
}

#[test]
fn an_absent_or_empty_query_is_empty() {
    assert!(parse_query(None).is_empty());
    assert!(parse_query(Some("")).is_empty());
}
