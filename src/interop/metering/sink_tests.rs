//! How each answer from the admin is read, and that a refusal really does
//! stop this runtime asking.

use super::super::QUEUE_CAPACITY;
use super::super::testkit::{StubAdmin, TEST_TOKEN, queued};
use super::*;

// ---------------------------------------------------------------------------
// classify: every arm, no server
// ---------------------------------------------------------------------------

#[test]
fn a_2xx_is_accepted() {
    for status in [StatusCode::OK, StatusCode::ACCEPTED, StatusCode::NO_CONTENT] {
        assert_eq!(classify(status, None, 0), Outcome::Accepted, "{status}");
    }
}

/// A refused or mismatched token is not fixed by asking again, so the
/// endpoint is suspended and the operator gets ONE line rather than one per
/// turn for the life of the deployment.
#[test]
fn a_401_or_403_suspends_the_endpoint() {
    for status in [StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN] {
        assert_eq!(
            classify(status, None, 0),
            Outcome::Suspend {
                window: AUTH_SUSPENSION,
                reason: "the usage token was refused"
            },
            "{status}"
        );
    }
}

#[test]
fn a_429_honours_retry_after_within_bounds() {
    let window = |raw: Option<&str>| match classify(StatusCode::TOO_MANY_REQUESTS, raw, 0) {
        Outcome::Suspend { window, .. } => window,
        other => panic!("expected a suspension, got {other:?}"),
    };
    assert_eq!(window(Some("30")), Duration::from_secs(30));
    assert_eq!(window(Some(" 45 ")), Duration::from_secs(45));
    // An absent, unreadable or HTTP-date value still backs off, briefly.
    assert_eq!(window(None), Duration::from_secs(1));
    assert_eq!(window(Some("0")), Duration::from_secs(1));
    assert_eq!(
        window(Some("Wed, 23 Sep 2026 10:00:00 GMT")),
        Duration::from_secs(1)
    );
    // A hostile value must not switch metering off for the life of the
    // process.
    assert_eq!(window(Some("999999999")), MAX_RETRY_AFTER);
}

/// A `413`, `400` or `422` is a fact about THIS event. Suspending on one
/// would hide every later event behind a single bad one.
#[test]
fn a_per_event_refusal_drops_that_event_alone() {
    for status in [
        StatusCode::PAYLOAD_TOO_LARGE,
        StatusCode::BAD_REQUEST,
        StatusCode::UNPROCESSABLE_ENTITY,
        StatusCode::NOT_FOUND,
    ] {
        assert_eq!(classify(status, None, 0), Outcome::Rejected, "{status}");
    }
}

#[test]
fn a_5xx_backs_off_exponentially_up_to_a_ceiling() {
    let window = |failures: u32| match classify(StatusCode::BAD_GATEWAY, None, failures) {
        Outcome::Suspend { window, .. } => window,
        other => panic!("expected a suspension, got {other:?}"),
    };
    assert_eq!(window(0), Duration::from_secs(1));
    assert_eq!(window(3), Duration::from_secs(8));
    assert_eq!(window(20), MAX_TRANSIENT_BACKOFF);
    // A failure count large enough to overflow the shift must still yield a
    // bounded window rather than panicking on a long-lived task.
    assert_eq!(window(u32::MAX), MAX_TRANSIENT_BACKOFF);
}

// ---------------------------------------------------------------------------
// The running sink, against a stub admin
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_accepted_event_is_posted_as_a_bearer_authenticated_json_body() {
    let stub = StubAdmin::accepting().await;
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(run(rx));
    tx.send(queued(&stub.url)).await.expect("queue");
    assert_eq!(stub.wait_for(1).await, 1);

    let raw = stub.received().pop().expect("a request");
    assert!(raw.starts_with("POST /ingest "), "{raw}");
    assert!(
        raw.to_lowercase()
            .contains(&format!("authorization: bearer {TEST_TOKEN}")),
        "the token must travel as a bearer header: {raw}"
    );
    let parsed = stub.last_body();
    assert_eq!(parsed["surface"], "a2a");
    assert_eq!(parsed["tokens_in"], 12);
    assert_eq!(parsed["tenant_slug"], "acme");
    assert!(parsed["event_id"].as_str().is_some_and(|id| id.len() == 26));
}

/// The behaviour §8's "never retrying in a hot loop" asks for: after one
/// refusal the runtime STOPS asking, so a revoked token costs one request
/// rather than one per turn for the life of the deployment.
#[tokio::test]
async fn a_401_stops_the_runtime_asking() {
    let stub = StubAdmin::answering(
        "HTTP/1.1 401 Unauthorized",
        "",
        r#"{"error":"invalid_usage_token"}"#,
    )
    .await;
    let (tx, rx) = tokio::sync::mpsc::channel(32);
    tokio::spawn(run(rx));
    for _ in 0..12 {
        tx.send(queued(&stub.url)).await.expect("queue");
    }
    assert_eq!(stub.wait_for(1).await, 1);
    // Give the sink ample time to send the other eleven if it were going to.
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        stub.count(),
        1,
        "the sink kept posting to an endpoint that refused its token"
    );
}

/// A suspension is per ENDPOINT, not per queue: one unit's broken admin must
/// not stop another unit's usage being recorded.
#[tokio::test]
async fn one_refusing_endpoint_does_not_silence_another() {
    let refusing = StubAdmin::answering("HTTP/1.1 401 Unauthorized", "", "{}").await;
    let accepting = StubAdmin::accepting().await;
    let (tx, rx) = tokio::sync::mpsc::channel(32);
    tokio::spawn(run(rx));
    for _ in 0..4 {
        tx.send(queued(&refusing.url)).await.expect("queue");
        tx.send(queued(&accepting.url)).await.expect("queue");
    }
    assert_eq!(accepting.wait_for(4).await, 4);
    assert_eq!(refusing.count(), 1);
}

/// `Retry-After` is honoured rather than ignored: with a long one, the second
/// event is dropped instead of being posted immediately.
#[tokio::test]
async fn a_429_pauses_that_endpoint_for_its_retry_after() {
    let stub = StubAdmin::answering(
        "HTTP/1.1 429 Too Many Requests",
        "Retry-After: 120\r\n",
        "{}",
    )
    .await;
    let (tx, rx) = tokio::sync::mpsc::channel(32);
    tokio::spawn(run(rx));
    for _ in 0..6 {
        tx.send(queued(&stub.url)).await.expect("queue");
    }
    assert_eq!(stub.wait_for(1).await, 1);
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(stub.count(), 1);
}

/// The queue's bound is the memory bound, and the sink is what keeps it from
/// being reached in normal operation.
#[tokio::test]
async fn the_sink_drains_the_queue_it_is_given() {
    let stub = StubAdmin::accepting().await;
    let (tx, rx) = tokio::sync::mpsc::channel(QUEUE_CAPACITY);
    tokio::spawn(run(rx));
    for _ in 0..25 {
        tx.send(queued(&stub.url)).await.expect("queue");
    }
    assert_eq!(stub.wait_for(25).await, 25);
}
