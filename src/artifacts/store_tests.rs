use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::time_testkit::within_ceiling;
use crate::interop::metering::testkit::{StubAdmin, TEST_TOKEN, silent_peer};

use super::store::*;

pub(super) const OK: &str = "HTTP/1.1 200 OK";
pub(super) const OK_ID: &str =
    "artifact://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
pub(super) const OK_BODY: &str = r#"{"id":"artifact://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","sha256":"ff","size_bytes":3,"kind":"document","mime_type":"text/plain"}"#;

pub(super) fn client_for(url: &str) -> HttpArtifactStore {
    HttpArtifactStore::new(
        url.to_string(),
        TEST_TOKEN.to_string(),
        Duration::from_secs(2),
    )
    .unwrap()
    .with_backoff(Duration::from_millis(1))
}

pub(super) fn client(stub: &StubAdmin) -> HttpArtifactStore {
    client_for(&stub.url)
}

pub(super) fn request(bytes: &[u8]) -> PutRequest<'_> {
    PutRequest {
        name: "a.txt",
        mime: "text/plain",
        bytes,
        derived_from: None,
        conversation_id: Some("conv-1"),
    }
}

pub(super) fn kind(err: &StoreError) -> &'static str {
    match err {
        StoreError::Rejected(_) => "Rejected",
        StoreError::NotGranted => "NotGranted",
        StoreError::TooLarge => "TooLarge",
        StoreError::Unsupported => "Unsupported",
        StoreError::Quota => "Quota",
        StoreError::NotFound => "NotFound",
        StoreError::Unavailable(_) => "Unavailable",
    }
}

#[tokio::test]
async fn put_posts_to_put_with_bearer_base64_and_conversation() {
    let stub = StubAdmin::answering(OK, "", OK_BODY).await;
    let stored = client(&stub).put(request(b"hey")).await.unwrap();
    assert_eq!(stored.id, OK_ID);
    assert_eq!(stored.kind, "document");
    assert_eq!(stored.mime_type, "text/plain");
    let raw = stub.received().join("\n");
    assert!(raw.contains("POST /ingest/put HTTP/1.1"), "{raw}");
    assert!(
        raw.to_lowercase()
            .contains(&format!("authorization: bearer {TEST_TOKEN}"))
    );
    assert!(!raw.contains("\"op\""), "the door has no op field");
    assert!(raw.contains(r#""conversation_id":"conv-1""#));
    assert!(raw.contains(r#""data_base64":"aGV5""#)); // base64("hey")
    assert!(raw.contains(r#""mime_type":"text/plain""#));
    assert!(!raw.contains("derived_from"));
}

#[tokio::test]
async fn derived_from_is_sent_when_present() {
    let stub = StubAdmin::answering(OK, "", OK_BODY).await;
    let mut req = request(b"hey");
    req.derived_from = Some("artifact://parent");
    client(&stub).put(req).await.unwrap();
    assert!(
        stub.received()
            .join("\n")
            .contains(r#""derived_from":"artifact://parent""#)
    );
}

#[tokio::test]
async fn final_statuses_map_to_typed_errors_without_retry() {
    let cases = [
        ("HTTP/1.1 400 Bad Request", "Unavailable"),
        ("HTTP/1.1 401 Unauthorized", "Rejected"),
        ("HTTP/1.1 403 Forbidden", "Rejected"),
        ("HTTP/1.1 404 Not Found", "Unavailable"),
        ("HTTP/1.1 413 Payload Too Large", "TooLarge"),
        ("HTTP/1.1 415 Unsupported Media Type", "Unsupported"),
        ("HTTP/1.1 422 Unprocessable Entity", "Quota"),
        ("HTTP/1.1 500 Internal Server Error", "Unavailable"),
    ];
    for (status, want) in cases {
        let stub = StubAdmin::answering(status, "", "{}").await;
        let err = client(&stub).put(request(b"x")).await.unwrap_err();
        assert_eq!(kind(&err), want, "{status}");
        assert_eq!(stub.count(), 1, "{status} must not be retried");
    }
}

pub(super) fn coded(code: &str) -> String {
    format!(r#"{{"error":{{"code":"{code}"}}}}"#)
}

#[tokio::test]
async fn the_doors_own_error_code_decides_403_and_404() {
    let cases = [
        (
            "HTTP/1.1 403 Forbidden",
            coded("purpose_not_granted"),
            "NotGranted",
        ),
        ("HTTP/1.1 403 Forbidden", coded("forbidden"), "Rejected"),
        (
            "HTTP/1.1 403 Forbidden",
            "<html>proxy</html>".to_string(),
            "Rejected",
        ),
        ("HTTP/1.1 404 Not Found", coded("not_found"), "NotFound"),
        // A 404 the door did not write (no route, a proxy page) is not
        // "this artifact does not exist".
        ("HTTP/1.1 404 Not Found", "{}".to_string(), "Unavailable"),
        (
            "HTTP/1.1 404 Not Found",
            coded("route_not_found"),
            "Unavailable",
        ),
    ];
    for (status, body, want) in cases {
        let stub = StubAdmin::answering(status, "", &body).await;
        let err = client(&stub).put(request(b"x")).await.unwrap_err();
        assert_eq!(kind(&err), want, "{status} {body}");
        assert!(
            !format!("{err}").contains("proxy"),
            "no body text in errors"
        );
    }
}

#[tokio::test]
async fn retryable_statuses_are_retried_then_succeed() {
    for status in [
        "HTTP/1.1 503 Service Unavailable",
        "HTTP/1.1 429 Too Many Requests",
        "HTTP/1.1 408 Request Timeout",
    ] {
        let stub = StubAdmin::answering_in_turn(&[
            (status, "", r#"{"error":{"code":"artifact_busy"}}"#),
            (OK, "", OK_BODY),
        ])
        .await;
        let stored = client(&stub).put(request(b"x")).await.unwrap();
        assert_eq!(stored.id, OK_ID, "{status}");
        assert_eq!(stub.count(), 2, "{status}");
    }
}

#[tokio::test]
async fn retries_are_bounded() {
    let stub = StubAdmin::answering("HTTP/1.1 503 Service Unavailable", "", "{}").await;
    let err = client(&stub).put(request(b"x")).await.unwrap_err();
    assert_eq!(kind(&err), "Unavailable");
    assert_eq!(stub.count(), PUT_ATTEMPTS);
}

#[tokio::test]
async fn retries_back_off() {
    let stub = StubAdmin::answering("HTTP/1.1 503 Service Unavailable", "", "{}").await;
    let store = client(&stub).with_backoff(Duration::from_millis(60));
    let started = Instant::now();
    let _ = store.put(request(b"x")).await;
    // Two waits: 60 ms then 120 ms.
    assert!(
        started.elapsed() >= Duration::from_millis(180),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn redirects_are_not_followed() {
    // A redirect would carry the bearer to a host the unit never named.
    let elsewhere = StubAdmin::answering(OK, "", OK_BODY).await;
    let location = format!("Location: {}\r\n", elsewhere.url);
    let stub = StubAdmin::answering("HTTP/1.1 307 Temporary Redirect", &location, "{}").await;
    let err = client(&stub).put(request(b"x")).await.unwrap_err();
    assert_eq!(kind(&err), "Unavailable");
    assert_eq!(elsewhere.count(), 0, "the redirect target was contacted");
}

#[tokio::test]
async fn a_silent_door_times_out() {
    let port = silent_peer().await;
    let store = HttpArtifactStore::new(
        format!("http://127.0.0.1:{port}/ingest"),
        TEST_TOKEN.into(),
        Duration::from_millis(200),
    )
    .unwrap()
    .with_backoff(Duration::from_millis(1));
    let started = Instant::now();
    let err = within_ceiling(store.put(request(b"x"))).await.unwrap_err();
    assert_eq!(kind(&err), "Unavailable");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn the_token_never_appears_in_errors_or_debug() {
    let stub = StubAdmin::answering(
        "HTTP/1.1 500 Internal Server Error",
        "",
        &format!("echo {TEST_TOKEN}"),
    )
    .await;
    let store = client(&stub);
    let err = store.put(request(b"x")).await.unwrap_err();
    assert!(!format!("{err:?}{err}").contains(TEST_TOKEN));
    assert!(!format!("{store:?}").contains(TEST_TOKEN));
    let port = silent_peer().await;
    let store = HttpArtifactStore::new(
        format!("http://127.0.0.1:{port}/{TEST_TOKEN}"),
        TEST_TOKEN.into(),
        Duration::from_millis(100),
    )
    .unwrap()
    .with_backoff(Duration::from_millis(1));
    let err = within_ceiling(store.put(request(b"x"))).await.unwrap_err();
    assert!(!format!("{err:?}{err}").contains(TEST_TOKEN), "{err}");
}

#[tokio::test]
async fn an_unreadable_success_is_unavailable() {
    let stub = StubAdmin::answering(OK, "", "not json").await;
    let err = client(&stub).put(request(b"x")).await.unwrap_err();
    assert_eq!(kind(&err), "Unavailable");
}

#[tokio::test]
async fn probe_accepts_404_and_refuses_auth_failures() {
    let ok = StubAdmin::answering("HTTP/1.1 404 Not Found", "", &coded("not_found")).await;
    assert!(client(&ok).probe().await.is_ok());
    let no_route = StubAdmin::answering("HTTP/1.1 404 Not Found", "", "{}").await;
    assert!(
        client(&no_route).probe().await.is_err(),
        "a bare 404 is no door"
    );
    assert!(
        ok.received()
            .join("\n")
            .contains("POST /ingest/get HTTP/1.1")
    );
    for (status, code) in [
        ("HTTP/1.1 401 Unauthorized", 401),
        ("HTTP/1.1 403 Forbidden", 403),
    ] {
        let stub = StubAdmin::answering(status, "", "{}").await;
        assert!(matches!(client(&stub).probe().await, Err(StoreError::Rejected(c)) if c == code));
    }
    let down = StubAdmin::answering("HTTP/1.1 503 Service Unavailable", "", "{}").await;
    assert!(matches!(
        client(&down).probe().await,
        Err(StoreError::Unavailable(_))
    ));
}

#[tokio::test]
async fn at_most_two_puts_are_in_flight() {
    // The door runs at most 4 transfers per process and refuses the rest; a
    // client must not send a message's five files at once.
    let (url, max_seen) = slow_door().await;
    let store = Arc::new(client_for(&url));
    let mut tasks = Vec::new();
    for _ in 0..5 {
        let store = Arc::clone(&store);
        tasks.push(tokio::spawn(async move {
            store.put(request(b"x")).await.map(|_| ())
        }));
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    assert_eq!(max_seen.load(Ordering::SeqCst), PUT_CONCURRENCY);
}

/// A door that holds every request 150 ms and records the most it ever had
/// open at once.
async fn slow_door() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let open = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&max_seen);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let open = Arc::clone(&open);
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let now = open.fetch_add(1, Ordering::SeqCst) + 1;
                seen.fetch_max(now, Ordering::SeqCst);
                let mut buf = vec![0u8; 16384];
                let _ = stream.read(&mut buf).await;
                tokio::time::sleep(Duration::from_millis(150)).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{OK_BODY}",
                    OK_BODY.len()
                );
                open.fetch_sub(1, Ordering::SeqCst);
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    (format!("http://127.0.0.1:{port}/ingest"), max_seen)
}

// --- Artifact ids, as the admin parses them ----------------------------------

/// The admin's `media::id::parse_id`, copied verbatim (greentic-designer-admin,
/// `src/media/id.rs`): `artifact://` + exactly 64 lowercase hex characters.
fn admin_parse_id(id: &str) -> Option<&str> {
    let hex = id.strip_prefix("artifact://")?;
    (hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))).then_some(hex)
}

#[test]
fn the_probe_id_is_well_formed_for_the_admin() {
    assert!(admin_parse_id(PROBE_ID).is_some(), "{PROBE_ID}");
}

#[test]
fn the_client_id_rule_matches_the_admins() {
    let good = format!("artifact://{}", "a1".repeat(32));
    for id in [
        good.as_str(),
        PROBE_ID,
        OK_ID,
        "artifact://probe",
        "artifact://",
        &format!("artifact://{}", "A1".repeat(32)),
        &format!("artifact://{}", "a".repeat(63)),
        &format!("artifact://{}", "a".repeat(65)),
        &format!("artifact:/{}", "a".repeat(64)),
        &format!(" artifact://{}", "a".repeat(64)),
        &format!("artifact://{}é", "a".repeat(62)),
        &format!("artifact://{}g", "a".repeat(63)),
    ] {
        assert_eq!(is_artifact_id(id), admin_parse_id(id).is_some(), "{id:?}");
    }
}

#[tokio::test]
async fn the_probe_passes_a_door_that_validates_ids_like_the_admin() {
    let (url, ids) = admin_like_get_door().await;
    client_for(&url).probe().await.unwrap();
    assert_eq!(ids.lock().unwrap().as_slice(), [PROBE_ID.to_string()]);
}

#[tokio::test]
async fn a_put_answer_with_a_malformed_id_is_refused() {
    let stub = StubAdmin::answering(
        OK,
        "",
        r#"{"id":"artifact://abc","sha256":"ff","size_bytes":3,"kind":"document","mime_type":"text/plain"}"#,
    )
    .await;
    let err = client(&stub).put(request(b"x")).await.unwrap_err();
    assert_eq!(kind(&err), "Unavailable");
}

/// A `/get` door that behaves like the admin's: `400 invalid_id` for an id
/// `parse_id` refuses, `404 not_found` for a well-formed id it does not hold.
async fn admin_like_get_door() -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let ids = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = Arc::clone(&ids);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                let read = stream.read(&mut buf).await.unwrap_or(0);
                let raw = String::from_utf8_lossy(&buf[..read]).to_string();
                let body = raw.split("\r\n\r\n").nth(1).unwrap_or_default();
                let id = serde_json::from_str::<serde_json::Value>(body)
                    .ok()
                    .and_then(|v| v["id"].as_str().map(str::to_string))
                    .unwrap_or_default();
                let (status, answer) = if admin_parse_id(&id).is_some() {
                    ("404 Not Found", r#"{"error":{"code":"not_found"}}"#)
                } else {
                    ("400 Bad Request", r#"{"error":{"code":"invalid_id"}}"#)
                };
                seen.lock().unwrap().push(id);
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                    answer.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    (format!("http://127.0.0.1:{port}/ingest/artifacts"), ids)
}
