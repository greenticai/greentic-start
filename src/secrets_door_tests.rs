//! Tests for [`crate::secrets_door`] against a raw-TCP stub of the admin's
//! `read-all` door. Nothing leaves the loopback interface.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use greentic_secrets_lib::{Result as SecretResult, SecretError, SecretsManager};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::interop::metering::testkit::closed_port;

const TOKEN: &str = "gtm_hydrate-test-token-do-not-leak";
const ENV: &str = "local";

fn fast() -> DoorPolicy {
    DoorPolicy {
        attempts: 2,
        backoff: Duration::from_millis(1),
        request_timeout: Duration::from_secs(2),
        total_budget: Duration::from_secs(30),
    }
}

/// Writable in-memory store, keyed on the full URI. Records every write path.
#[derive(Default)]
struct MemStore {
    map: Mutex<HashMap<String, Vec<u8>>>,
    writes: Mutex<Vec<String>>,
    deletes: Mutex<Vec<String>>,
    /// When set, every read fails with an error that is NOT not-found.
    fail_reads: std::sync::atomic::AtomicBool,
}

impl MemStore {
    fn put(&self, uri: &str, value: &[u8]) {
        self.map.lock().unwrap().insert(uri.into(), value.to_vec());
    }
    fn get(&self, uri: &str) -> Option<Vec<u8>> {
        self.map.lock().unwrap().get(uri).cloned()
    }
    fn written(&self) -> Vec<String> {
        self.writes.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl SecretsManager for MemStore {
    async fn read(&self, path: &str) -> SecretResult<Vec<u8>> {
        if self.fail_reads.load(Ordering::SeqCst) {
            return Err(SecretError::Permission("store unreadable".into()));
        }
        self.get(path)
            .ok_or_else(|| SecretError::NotFound(path.to_string()))
    }
    async fn write(&self, path: &str, value: &[u8]) -> SecretResult<()> {
        self.writes.lock().unwrap().push(path.to_string());
        self.put(path, value);
        Ok(())
    }
    async fn delete(&self, path: &str) -> SecretResult<()> {
        self.deletes.lock().unwrap().push(path.to_string());
        self.map.lock().unwrap().remove(path);
        Ok(())
    }
}

/// Scripted door: answers the nth request with the nth script entry (the last
/// one repeats). Every raw request is recorded.
struct StubDoor {
    port: u16,
    hits: Arc<AtomicUsize>,
    raw: Arc<Mutex<Vec<String>>>,
}

/// `(status line, extra headers, body)`.
type Reply = (&'static str, &'static str, String);

fn ok(body: serde_json::Value) -> Reply {
    ("HTTP/1.1 200 OK", "", body.to_string())
}

async fn serve(script: Vec<Reply>) -> StubDoor {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let raw = Arc::new(Mutex::new(Vec::new()));
    let (h, r) = (Arc::clone(&hits), Arc::clone(&raw));
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let n = h.fetch_add(1, Ordering::SeqCst);
            let (status, headers, body) = script[n.min(script.len() - 1)].clone();
            let r = Arc::clone(&r);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let Ok(read) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if read == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..read]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some((head, rest)) = text.split_once("\r\n\r\n") {
                        let len = head
                            .to_lowercase()
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:").map(str::to_string))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if rest.len() >= len {
                            break;
                        }
                    }
                }
                r.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf).to_string());
                let response = format!(
                    "{status}\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            });
        }
    });
    StubDoor { port, hits, raw }
}

impl StubDoor {
    fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}/api/v1/ingest/worker-usage", self.port)
    }
    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
    fn requests(&self) -> Vec<String> {
        self.raw.lock().unwrap().clone()
    }
}

/// Stage a unit's ingress document in `store`, as the designer would.
fn stage(store: &MemStore, tenant: &str, bundle: &str, endpoint: &str, door: Option<bool>) {
    let mut doc = json!({
        "v": 1,
        "tenant_slug": "acme",
        "metering": { "endpoint": endpoint, "token": TOKEN },
    });
    if let Some(flag) = door {
        doc["secrets_door"] = json!(flag);
    }
    store.put(
        &crate::ingress_auth::ingress_secret_uri(ENV, tenant, bundle),
        doc.to_string().as_bytes(),
    );
}

async fn run(store: &MemStore, tenant: &str, bundle: &str) -> anyhow::Result<Hydration> {
    let policy = fast();
    hydrate_unit(store, ENV, tenant, bundle, &policy, &policy.budget()).await
}

fn chain(err: &anyhow::Error) -> String {
    format!("{err:#}")
}

// ---- success ----------------------------------------------------------------

#[tokio::test]
async fn a_flagged_unit_gets_every_secret_at_the_runner_address() {
    let binary = [0u8, 159, 146, 150, 255];
    let door = serve(vec![ok(json!({
        "secrets": [
            { "path": "_/mcp/crm_token", "value": "plain-token", "encoding": "utf8" },
            { "path": "ops/a2a/agent-7.unit-support_bot", "value": B64.encode(binary), "encoding": "base64" },
            { "path": "_/llm/key" , "value": "no-encoding-means-utf8" },
        ],
        "etag": "v1",
    }))])
    .await;
    let store = MemStore::default();
    stage(&store, "acme", "ok-unit", &door.endpoint(), Some(true));

    let outcome = run(&store, "acme", "ok-unit").await.expect("hydrates");

    assert_eq!(outcome, Hydration::Written(3));
    assert_eq!(
        store.get("secrets://default/acme/_/mcp/crm_token").unwrap(),
        b"plain-token"
    );
    assert_eq!(
        store
            .get("secrets://default/acme/ops/a2a/agent-7.unit-support_bot")
            .unwrap(),
        binary
    );
    assert_eq!(
        store.get("secrets://default/acme/_/llm/key").unwrap(),
        b"no-encoding-means-utf8"
    );
    assert_eq!(door.hits(), 1, "ONE call per unit");
    let request = door.requests().remove(0);
    let lower = request.to_lowercase();
    assert!(
        request.starts_with("POST /api/v1/ingest/secrets/read-all "),
        "{request}"
    );
    assert!(lower.contains(&format!("authorization: bearer {}", TOKEN.to_lowercase())));
    assert!(request.ends_with("{}"), "the request body is `{{}}`");
    assert!(!lower.contains("if-none-match"), "no ETag known yet");
}

#[tokio::test]
async fn a_second_activation_sends_the_etag_and_a_304_writes_nothing() {
    let door = serve(vec![
        (
            "HTTP/1.1 200 OK",
            "",
            json!({"secrets":[{"path":"_/mcp/t","value":"v"}],"etag":"etag-1"}).to_string(),
        ),
        ("HTTP/1.1 304 Not Modified", "", String::new()),
    ])
    .await;
    let store = MemStore::default();
    stage(&store, "acme", "etag-unit", &door.endpoint(), Some(true));

    assert_eq!(
        run(&store, "acme", "etag-unit").await.unwrap(),
        Hydration::Written(1)
    );
    let writes_after_first = store.written().len();
    assert_eq!(
        run(&store, "acme", "etag-unit").await.unwrap(),
        Hydration::Unchanged
    );

    assert_eq!(store.written().len(), writes_after_first);
    let second = door.requests().remove(1).to_lowercase();
    assert!(second.contains("if-none-match: etag-1"), "{second}");
}

#[tokio::test]
async fn a_unit_is_hydrated_once_however_many_revisions_name_it() {
    let door = serve(vec![ok(
        json!({"secrets":[{"path":"_/mcp/t","value":"v"}],"etag":"e"}),
    )])
    .await;
    let store = MemStore::default();
    stage(&store, "acme", "dedupe-unit", &door.endpoint(), Some(true));
    hydrate_for_activation(
        &store,
        ENV,
        [("acme", "dedupe-unit"), ("acme", "dedupe-unit")],
        &fast(),
    )
    .await
    .expect("hydrates");
    assert_eq!(door.hits(), 1);
}

// ---- no flag, no call -------------------------------------------------------

#[tokio::test]
async fn without_the_flag_the_door_is_never_called() {
    for (bundle, flag) in [("flag-false", Some(false)), ("flag-absent", None)] {
        let door = serve(vec![ok(json!({"secrets":[],"etag":"e"}))]).await;
        let store = MemStore::default();
        stage(&store, "acme", bundle, &door.endpoint(), flag);
        assert_eq!(
            run(&store, "acme", bundle).await.unwrap(),
            Hydration::NotRequested
        );
        assert_eq!(door.hits(), 0, "{bundle}");
        assert!(store.written().is_empty());
    }
}

#[tokio::test]
async fn a_unit_with_no_staged_document_is_left_alone() {
    let store = MemStore::default();
    assert_eq!(
        run(&store, "acme", "never-staged").await.unwrap(),
        Hydration::NotRequested
    );
}

// ---- fail closed ------------------------------------------------------------

#[tokio::test]
async fn an_absent_door_fails_the_activation_immediately() {
    let door = serve(vec![("HTTP/1.1 404 Not Found", "", String::new())]).await;
    let store = MemStore::default();
    stage(&store, "acme", "door-404", &door.endpoint(), Some(true));

    let err = run(&store, "acme", "door-404").await.unwrap_err();
    let text = chain(&err);

    assert!(text.contains("/api/v1/ingest/secrets/read-all"), "{text}");
    assert!(text.contains("absent"), "{text}");
    assert_eq!(door.hits(), 1, "a 404 is a definite answer: no retries");
    assert!(store.written().is_empty());
    assert!(!text.contains(TOKEN));
}

#[tokio::test]
async fn an_unauthorised_door_fails_the_activation() {
    for (bundle, line) in [
        ("door-401", "HTTP/1.1 401 Unauthorized"),
        ("door-403", "HTTP/1.1 403 Forbidden"),
    ] {
        let door = serve(vec![(line, "", String::new())]).await;
        let store = MemStore::default();
        stage(&store, "acme", bundle, &door.endpoint(), Some(true));
        let text = chain(&run(&store, "acme", bundle).await.unwrap_err());
        assert!(text.contains("credential"), "{text}");
        assert_eq!(door.hits(), 1, "{bundle}: a refusal is not retried");
        assert!(!text.contains(TOKEN));
    }
}

#[tokio::test]
async fn a_403_says_the_token_probably_lacks_the_secrets_purpose() {
    let door = serve(vec![("HTTP/1.1 403 Forbidden", "", String::new())]).await;
    let store = MemStore::default();
    stage(
        &store,
        "acme",
        "door-403-hint",
        &door.endpoint(),
        Some(true),
    );
    let text = chain(&run(&store, "acme", "door-403-hint").await.unwrap_err());
    assert!(text.contains("`secrets` purpose"), "{text}");
    assert!(text.contains("PATCH purposes"), "{text}");
}

#[tokio::test]
async fn a_body_this_build_cannot_use_is_not_retried() {
    let door = serve(vec![ok(json!({"unexpected": true}))]).await;
    let store = MemStore::default();
    stage(&store, "acme", "bad-shape", &door.endpoint(), Some(true));
    assert!(run(&store, "acme", "bad-shape").await.is_err());
    assert_eq!(door.hits(), 1);
}

#[tokio::test]
async fn an_empty_set_for_a_flagged_unit_fails_and_records_no_etag() {
    let door = serve(vec![
        ok(json!({"secrets": [], "etag": "empty-etag"})),
        ok(json!({"secrets": [{"path":"_/mcp/t","value":"v"}], "etag": "e2"})),
    ])
    .await;
    let store = MemStore::default();
    stage(&store, "acme", "empty-set", &door.endpoint(), Some(true));

    let text = chain(&run(&store, "acme", "empty-set").await.unwrap_err());
    assert!(text.contains("empty set"), "{text}");
    assert!(store.written().is_empty());

    // The failed answer left no ETag behind, so the next attempt asks in full.
    assert_eq!(
        run(&store, "acme", "empty-set").await.unwrap(),
        Hydration::Written(1)
    );
    let second = door.requests().remove(1).to_lowercase();
    assert!(!second.contains("if-none-match"), "{second}");
}

#[tokio::test]
async fn a_store_read_error_fails_instead_of_assuming_no_flag() {
    let store = MemStore::default();
    store.fail_reads.store(true, Ordering::SeqCst);
    let text = chain(&run(&store, "acme", "unreadable").await.unwrap_err());
    assert!(text.contains("cannot tell whether"), "{text}");
}

#[tokio::test]
async fn an_unparseable_document_counts_as_no_flag() {
    let store = MemStore::default();
    store.put(
        &crate::ingress_auth::ingress_secret_uri(ENV, "acme", "garbage-doc"),
        b"this is not json",
    );
    assert_eq!(
        run(&store, "acme", "garbage-doc").await.unwrap(),
        Hydration::NotRequested
    );
}

#[tokio::test]
async fn a_429_is_retried_honouring_retry_after() {
    let door = serve(vec![
        (
            "HTTP/1.1 429 Too Many Requests",
            "Retry-After: 0\r\n",
            String::new(),
        ),
        ok(json!({"secrets":[{"path":"_/mcp/t","value":"v"}],"etag":"e"})),
    ])
    .await;
    let store = MemStore::default();
    stage(&store, "acme", "rate-limited", &door.endpoint(), Some(true));
    assert_eq!(
        run(&store, "acme", "rate-limited").await.unwrap(),
        Hydration::Written(1)
    );
    assert_eq!(door.hits(), 2);
}

#[test]
fn retry_after_is_delta_seconds_and_capped() {
    assert_eq!(parse_retry_after("2"), Some(Duration::from_secs(2)));
    assert_eq!(parse_retry_after(" 0 "), Some(Duration::ZERO));
    assert_eq!(parse_retry_after("999999"), Some(MAX_RETRY_AFTER));
    assert_eq!(parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT"), None);
}

#[tokio::test]
async fn units_share_one_retry_budget() {
    // Unit A burns the whole budget recovering from two 503s; unit B, behind a
    // door that never answers well, then gets its first attempt and no retry.
    let policy = DoorPolicy {
        attempts: 5,
        backoff: Duration::from_millis(40),
        request_timeout: Duration::from_secs(2),
        total_budget: Duration::from_millis(100),
    };
    let a = serve(vec![
        ("HTTP/1.1 503 Service Unavailable", "", String::new()),
        ("HTTP/1.1 503 Service Unavailable", "", String::new()),
        ok(json!({"secrets":[{"path":"_/mcp/t","value":"v"}],"etag":"ea"})),
    ])
    .await;
    let b = serve(vec![(
        "HTTP/1.1 503 Service Unavailable",
        "",
        String::new(),
    )])
    .await;
    let store = MemStore::default();
    stage(&store, "acme", "budget-a", &a.endpoint(), Some(true));
    stage(&store, "acme", "budget-b", &b.endpoint(), Some(true));

    let result = hydrate_for_activation(
        &store,
        ENV,
        [("acme", "budget-a"), ("acme", "budget-b")],
        &policy,
    )
    .await;

    assert!(result.is_err(), "B's door never answers");
    assert_eq!(a.hits(), 3);
    assert_eq!(b.hits(), 1, "the budget was spent: one attempt, no retries");
}

// ---- reload behaviour -------------------------------------------------------

#[tokio::test]
async fn a_reload_with_the_door_down_keeps_the_hydrated_secrets() {
    let door = serve(vec![
        ok(json!({"secrets":[{"path":"_/mcp/t","value":"v"}],"etag":"e1"})),
        ("HTTP/1.1 503 Service Unavailable", "", String::new()),
    ])
    .await;
    let store = MemStore::default();
    stage(&store, "acme", "reload-down", &door.endpoint(), Some(true));
    assert_eq!(
        run(&store, "acme", "reload-down").await.unwrap(),
        Hydration::Written(1)
    );
    assert_eq!(
        run(&store, "acme", "reload-down").await.unwrap(),
        Hydration::KeptPrevious
    );
    assert_eq!(
        store.get("secrets://default/acme/_/mcp/t").unwrap(),
        b"v",
        "the earlier secrets still serve"
    );
}

#[tokio::test]
async fn a_cold_start_with_the_door_down_still_fails() {
    let door = serve(vec![(
        "HTTP/1.1 503 Service Unavailable",
        "",
        String::new(),
    )])
    .await;
    let store = MemStore::default();
    stage(&store, "acme", "cold-down", &door.endpoint(), Some(true));
    assert!(run(&store, "acme", "cold-down").await.is_err());
}

#[tokio::test]
async fn a_reload_refusal_is_not_masked_by_the_previous_secrets() {
    let door = serve(vec![
        ok(json!({"secrets":[{"path":"_/mcp/t","value":"v"}],"etag":"e1"})),
        ("HTTP/1.1 403 Forbidden", "", String::new()),
    ])
    .await;
    let store = MemStore::default();
    stage(&store, "acme", "reload-403", &door.endpoint(), Some(true));
    run(&store, "acme", "reload-403").await.unwrap();
    assert!(run(&store, "acme", "reload-403").await.is_err());
}

#[tokio::test]
async fn secrets_the_admin_stopped_returning_are_deleted() {
    let door = serve(vec![
        ok(json!({"secrets":[
            {"path":"_/mcp/keep","value":"1"},
            {"path":"_/mcp/drop","value":"2"},
        ],"etag":"e1"})),
        ok(json!({"secrets":[{"path":"_/mcp/keep","value":"1b"}],"etag":"e2"})),
    ])
    .await;
    let store = MemStore::default();
    stage(&store, "acme", "stale-unit", &door.endpoint(), Some(true));

    run(&store, "acme", "stale-unit").await.unwrap();
    assert!(store.get("secrets://default/acme/_/mcp/drop").is_some());
    run(&store, "acme", "stale-unit").await.unwrap();

    assert!(store.get("secrets://default/acme/_/mcp/drop").is_none());
    assert_eq!(
        store.get("secrets://default/acme/_/mcp/keep").unwrap(),
        b"1b"
    );
    assert_eq!(
        store.deletes.lock().unwrap().clone(),
        vec!["secrets://default/acme/_/mcp/drop".to_string()]
    );
}

#[test]
fn only_runner_scoped_categories_are_served_at_env_default() {
    for yes in ["mcp", "a2a", "llm", "knowledge", "sorla"] {
        assert!(is_runner_category(yes), "{yes}");
    }
    // Pack-scoped extension secrets and the webchat signing key live at the
    // revision's env and must stay in the shipped store.
    for no in [
        "messaging_webchat_gui",
        "hubspot",
        "ingress",
        "jwt_signing_key",
    ] {
        assert!(!is_runner_category(no), "{no}");
    }
}

#[tokio::test]
async fn an_unreachable_door_fails_the_activation() {
    let port = closed_port().await;
    let store = MemStore::default();
    stage(
        &store,
        "acme",
        "door-down",
        &format!("http://127.0.0.1:{port}/api/v1/ingest/worker-usage"),
        Some(true),
    );
    let text = chain(&run(&store, "acme", "door-down").await.unwrap_err());
    assert!(text.contains("did not answer"), "{text}");
    assert!(text.contains("secrets/read-all"), "{text}");
    assert!(!text.contains(TOKEN));
}

#[tokio::test]
async fn a_transient_failure_is_retried_and_then_succeeds() {
    let door = serve(vec![
        ("HTTP/1.1 503 Service Unavailable", "", String::new()),
        ok(json!({"secrets":[{"path":"_/mcp/t","value":"v"}],"etag":"e"})),
    ])
    .await;
    let store = MemStore::default();
    stage(&store, "acme", "retry-unit", &door.endpoint(), Some(true));
    assert_eq!(
        run(&store, "acme", "retry-unit").await.unwrap(),
        Hydration::Written(1)
    );
    assert_eq!(door.hits(), 2);
}

#[tokio::test]
async fn a_flag_without_a_usable_metering_block_fails_without_calling_anything() {
    let store = MemStore::default();
    store.put(
        &crate::ingress_auth::ingress_secret_uri(ENV, "acme", "no-meter"),
        json!({"v":1,"tenant_slug":"acme","secrets_door":true})
            .to_string()
            .as_bytes(),
    );
    let text = chain(&run(&store, "acme", "no-meter").await.unwrap_err());
    assert!(text.contains("metering"), "{text}");
}

#[tokio::test]
async fn a_cleartext_non_loopback_door_is_refused() {
    let store = MemStore::default();
    // The metering block itself refuses this endpoint, so the unit has no
    // usable block and the flagged unit fails rather than sending the token.
    stage(
        &store,
        "acme",
        "cleartext",
        "http://admin.example.com/api/v1/ingest/worker-usage",
        Some(true),
    );
    assert!(run(&store, "acme", "cleartext").await.is_err());
}

// ---- validation -------------------------------------------------------------

#[tokio::test]
async fn one_bad_entry_writes_nothing_at_all() {
    for (bundle, bad) in [
        ("bad-path", json!({"path":"../../other/mcp/x","value":"v"})),
        ("short-path", json!({"path":"mcp/x","value":"v"})),
        (
            "bad-b64",
            json!({"path":"_/mcp/x","value":"!!!not base64!!!","encoding":"base64"}),
        ),
        (
            "bad-enc",
            json!({"path":"_/mcp/x","value":"v","encoding":"rot13"}),
        ),
    ] {
        let door = serve(vec![ok(json!({
            "secrets": [ {"path":"_/mcp/good","value":"v"}, bad ],
            "etag": "e"
        }))])
        .await;
        let store = MemStore::default();
        stage(&store, "acme", bundle, &door.endpoint(), Some(true));
        let text = chain(&run(&store, "acme", bundle).await.unwrap_err());
        assert!(!text.is_empty());
        assert!(store.written().is_empty(), "{bundle}: nothing is written");
    }
}

#[tokio::test]
async fn an_unparseable_body_is_reported_without_echoing_the_value() {
    let door = serve(vec![ok(json!({
        "secrets": [ { "path": "_/mcp/x", "value": 987654321 } ]
    }))])
    .await;
    let store = MemStore::default();
    stage(&store, "acme", "weird-body", &door.endpoint(), Some(true));
    let text = chain(&run(&store, "acme", "weird-body").await.unwrap_err());
    assert!(text.contains("expected"), "{text}");
    assert!(!text.contains("987654321"), "{text}");
}

#[test]
fn only_three_clean_segments_are_a_valid_path() {
    for good in [
        "_/mcp/tok",
        "ops/a2a/agent.unit-x_y",
        "_/knowledge/embedding_key",
    ] {
        assert!(validate_path(good).is_ok(), "{good}");
    }
    for bad in [
        "",
        "_/mcp",
        "_/mcp/x/y",
        "_//x",
        "../mcp/x",
        "_/./x",
        "_/mcp/..",
        "_/mcp/a\\b",
        "_/mcp/a:b",
        "_/mcp/a\nb",
        " /mcp/x",
    ] {
        assert!(validate_path(bad).is_err(), "{bad:?}");
    }
}

// ---- the real dev store -----------------------------------------------------

#[tokio::test]
async fn hydrated_secrets_read_back_through_the_real_dev_store() {
    let door = serve(vec![ok(json!({
        "secrets": [
            { "path": "_/mcp/crm.unit-support_bot", "value": "real-store-value" },
        ],
        "etag": "e"
    }))])
    .await;
    let dir = tempfile::tempdir().expect("tempdir");
    let store =
        crate::secrets_client::SecretsClient::open_with_path(dir.path().join(".dev.secrets.env"))
            .expect("open dev store");
    let doc = json!({
        "v": 1, "tenant_slug": "acme", "secrets_door": true,
        "metering": { "endpoint": door.endpoint(), "token": TOKEN },
    });
    store
        .write(
            &crate::ingress_auth::ingress_secret_uri(ENV, "acme", "real-store"),
            doc.to_string().as_bytes(),
        )
        .await
        .expect("stage ingress");

    let policy = fast();
    let outcome = hydrate_unit(&store, ENV, "acme", "real-store", &policy, &policy.budget())
        .await
        .expect("hydrates");

    assert_eq!(outcome, Hydration::Written(1));
    assert_eq!(
        store
            .read("secrets://default/acme/_/mcp/crm.unit-support_bot")
            .await
            .expect("reads back"),
        b"real-store-value"
    );
}

// ---- the ingress document ---------------------------------------------------

#[test]
fn the_flag_parses_and_defaults_off() {
    let parse = |extra: serde_json::Value| {
        let mut doc = json!({"v": 1});
        doc.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        crate::interop::config::parse(doc.to_string().as_bytes(), "unit").expect("parses")
    };
    assert!(!parse(json!({})).secrets_door);
    assert!(parse(json!({"secrets_door": true})).secrets_door);
    assert!(!parse(json!({"secrets_door": false})).secrets_door);
    // Unknown fields (what a build predating `secrets_door` sees) are ignored,
    // not rejected.
    assert!(
        parse(json!({"some_future_field": {"x": 1}}))
            .credentials
            .is_empty()
    );
}
