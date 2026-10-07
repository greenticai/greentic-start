use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::interop::metering::testkit::{StubAdmin, TEST_TOKEN, silent_peer};

use super::store::*;

const OK: &str = "HTTP/1.1 200 OK";
const OK_BODY: &str = r#"{"id":"artifact://abc","sha256":"ff","size_bytes":3,"kind":"document","mime_type":"text/plain"}"#;

fn client_for(url: &str) -> HttpArtifactStore {
    HttpArtifactStore::new(
        url.to_string(),
        TEST_TOKEN.to_string(),
        Duration::from_secs(2),
    )
    .unwrap()
    .with_backoff(Duration::from_millis(1))
}

fn client(stub: &StubAdmin) -> HttpArtifactStore {
    client_for(&stub.url)
}

fn request(bytes: &[u8]) -> PutRequest<'_> {
    PutRequest {
        name: "a.txt",
        mime: "text/plain",
        bytes,
        derived_from: None,
        conversation_id: Some("conv-1"),
    }
}

fn kind(err: &StoreError) -> &'static str {
    match err {
        StoreError::Rejected(_) => "Rejected",
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
    assert_eq!(stored.id, "artifact://abc");
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
        ("HTTP/1.1 404 Not Found", "NotFound"),
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
        assert_eq!(stored.id, "artifact://abc", "{status}");
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
    let err = store.put(request(b"x")).await.unwrap_err();
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
    let err = store.put(request(b"x")).await.unwrap_err();
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
    let ok = StubAdmin::answering("HTTP/1.1 404 Not Found", "", "{}").await;
    assert!(client(&ok).probe().await.is_ok());
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
