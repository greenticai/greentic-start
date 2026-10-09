//! How each answer from the admin is read, that a refusal really does stop
//! this runtime asking, and — since 2026-09-23 — that a failure an operator
//! cannot see is a failure this module does not produce.
//!
//! Every test here talks to `127.0.0.1` or to nothing at all. None of them
//! resolves a name or opens a socket that could leave the host: a test whose
//! verdict depends on the network the suite happens to run on would report
//! this module's own regressions as flakes.

use super::super::QUEUE_CAPACITY;
use super::super::testkit::{StubAdmin, TEST_TOKEN, closed_port, queued, silent_peer};
use super::*;

/// A client shaped like [`CLIENT`] but with budgets a test can wait out.
///
/// It is built the same way — same crypto provider, same two timeouts — so a
/// classification asserted here is the classification the real client
/// produces, rather than one produced by a differently-configured builder.
fn test_client(connect: Duration, overall: Duration) -> reqwest::Client {
    install_crypto_provider();
    reqwest::Client::builder()
        .timeout(overall)
        .connect_timeout(connect)
        .build()
        .expect("a client")
}

// ---------------------------------------------------------------------------
// The two budgets
// ---------------------------------------------------------------------------

/// If the request budget can elapse while the connector is still running,
/// every connect fault is reported as a slow admin and
/// [`TransportFailure::ConnectTimeout`] is unreachable — which is the whole
/// diagnosis this module was rebuilt to produce.
#[test]
fn the_connect_budget_is_strictly_inside_the_request_budget() {
    assert!(
        CONNECT_TIMEOUT < POST_TIMEOUT,
        "a connector bounded at {CONNECT_TIMEOUT:?} inside a request bounded at {POST_TIMEOUT:?} \
         can never report a connect timeout"
    );
}

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
                reason: "the usage token was refused",
                detail: None,
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
// Transport failures: which one happened, against a peer the test owns
// ---------------------------------------------------------------------------

/// The incident this module was rebuilt for: the connector spends its whole
/// budget and nothing is established. It must NOT read as a slow admin — a
/// connect timeout satisfies `is_timeout` as well as `is_connect`, so this is
/// the test that pins the order the two are read in.
///
/// Produced locally by speaking `https` to a peer that accepts the TCP
/// connection and never replies to the `ClientHello`: the TLS handshake lives
/// inside the connector, so the connect budget is what elapses.
#[tokio::test]
async fn a_handshake_that_never_completes_is_a_connect_timeout() {
    let port = silent_peer().await;
    let client = test_client(Duration::from_millis(200), Duration::from_secs(20));
    let err = client
        .post(format!("https://127.0.0.1:{port}/ingest"))
        .body("{}")
        .send()
        .await
        .expect_err("a peer that never speaks cannot complete a handshake");
    assert!(err.is_timeout() && err.is_connect(), "{err:?}");
    assert_eq!(TransportFailure::of(&err), TransportFailure::ConnectTimeout);
    assert!(
        TransportFailure::ConnectTimeout
            .reason()
            .contains("in time"),
        "the operator must be told it ran out of time, not merely that it failed"
    );
}

/// A dead admin, a wrong port, a host that resolves to nothing reachable.
/// Distinguishable from the case above because it costs no waiting at all,
/// and the detail carries the OS's own word for it.
#[tokio::test]
async fn a_refused_connection_is_a_connect_failure_and_says_so() {
    let port = closed_port().await;
    let client = test_client(Duration::from_secs(2), Duration::from_secs(5));
    let err = client
        .post(format!("http://127.0.0.1:{port}/ingest"))
        .body("{}")
        .send()
        .await
        .expect_err("nothing is listening on that port");
    assert_eq!(TransportFailure::of(&err), TransportFailure::Connect);
    assert!(!err.is_timeout(), "a refusal is instant, not a timeout");

    let detail = error_detail(err);
    assert!(
        detail.to_lowercase().contains("refused"),
        "the chain must carry the OS's own reason, not just `error sending request`: {detail}"
    );
    assert!(
        !detail.contains(&format!("127.0.0.1:{port}/ingest")),
        "the URL is stripped from the detail; `endpoint_label` is what names the endpoint: \
         {detail}"
    );
}

/// The connector succeeded and the ANSWER never came — an overloaded admin,
/// not a network fault. Plain `http`, so there is no handshake to stall and
/// the request budget is what elapses.
#[tokio::test]
async fn a_peer_that_never_answers_is_a_request_timeout() {
    let port = silent_peer().await;
    let client = test_client(Duration::from_secs(5), Duration::from_millis(250));
    let err = client
        .post(format!("http://127.0.0.1:{port}/ingest"))
        .body("{}")
        .send()
        .await
        .expect_err("a peer that never answers cannot complete a request");
    assert_eq!(TransportFailure::of(&err), TransportFailure::Timeout);
    assert!(
        !err.is_connect(),
        "the connection was established; only the answer is missing"
    );
}

/// Each failure must name a different remedy, or splitting them bought
/// nothing.
#[test]
fn every_transport_failure_reads_differently() {
    let reasons = [
        TransportFailure::ConnectTimeout,
        TransportFailure::Connect,
        TransportFailure::Timeout,
        TransportFailure::Body,
        TransportFailure::Other,
    ]
    .map(TransportFailure::reason);
    for (index, reason) in reasons.iter().enumerate() {
        assert!(!reason.is_empty());
        assert!(
            !reasons[index + 1..].contains(reason),
            "two failures read identically: {reason}"
        );
    }
}

// ---------------------------------------------------------------------------
// What the operator is told, and how much was lost
// ---------------------------------------------------------------------------

/// The one line a suspension produces has to carry the classification, the
/// endpoint, and the running cost — a line that says only "could not be
/// reached" is what this module shipped, and it is why a silent 21.3 s
/// connect went unnoticed.
#[test]
fn the_suspension_line_names_the_classification_the_endpoint_and_the_drop_count() {
    let mut sink = Sink::default();
    let now = Instant::now();
    let endpoint = "https://admin.example/api/v1/ingest";
    assert_eq!(sink.begin(endpoint, now), Some(0));

    let line = sink
        .finish(
            endpoint,
            Outcome::Suspend {
                window: Duration::from_secs(4),
                reason: TransportFailure::ConnectTimeout.reason(),
                detail: Some("tcp connect error: Network is unreachable (os error 101)".into()),
            },
            now,
        )
        .expect("a suspension owes the operator a line");

    assert!(
        line.contains(TransportFailure::ConnectTimeout.reason()),
        "{line}"
    );
    assert!(
        line.contains("https://admin.example/api/v1/ingest"),
        "{line}"
    );
    assert!(
        line.contains("Network is unreachable (os error 101)"),
        "{line}"
    );
    assert!(line.contains("not sending usage there for 4s"), "{line}");
    assert!(
        line.ends_with("usage events dropped for this endpoint so far: 1"),
        "{line}"
    );
}

/// A status-derived suspension states its whole reason in `reason`, so it
/// carries no transport detail and the line must not grow an empty bracket.
#[test]
fn a_5xx_suspension_names_the_endpoint_as_failing_with_no_transport_detail() {
    let mut sink = Sink::default();
    let now = Instant::now();
    let endpoint = "https://admin.example/ingest";
    assert_eq!(sink.begin(endpoint, now), Some(0));
    let outcome = classify(StatusCode::SERVICE_UNAVAILABLE, None, 0);
    assert_eq!(
        outcome,
        Outcome::Suspend {
            window: Duration::from_secs(1),
            reason: "the usage endpoint is failing",
            detail: None,
        }
    );

    let line = sink
        .finish(endpoint, outcome, now)
        .expect("a suspension owes the operator a line");
    assert!(line.contains("the usage endpoint is failing"), "{line}");
    assert!(
        !line.contains("()"),
        "an absent detail must not be printed: {line}"
    );
}

/// The endpoint is printed, but the two parts of a URL that can hold a
/// credential are not. Nothing validates a staged endpoint against carrying
/// either, and this is the one place a working one reaches a log.
#[test]
fn the_endpoint_label_drops_anything_that_could_be_a_credential() {
    assert_eq!(
        endpoint_label("https://user:hunter2@admin.example/ingest?token=leaked#frag"),
        "https://admin.example/ingest"
    );
    assert_eq!(
        endpoint_label("https://admin.example/ingest"),
        "https://admin.example/ingest"
    );
    assert_eq!(endpoint_label("not a url"), "an unparseable endpoint");
}

/// "Some usage was lost" is not an answer an operator can act on. Every event
/// the endpoint did not take is counted — the one that failed, and every one
/// dropped unsent during the window that failure opened.
#[test]
fn every_event_the_endpoint_did_not_take_is_counted() {
    let mut sink = Sink::default();
    let now = Instant::now();
    let endpoint = "https://admin.example/ingest";

    assert_eq!(sink.begin(endpoint, now), Some(0));
    sink.finish(endpoint, classify(StatusCode::UNAUTHORIZED, None, 0), now);
    assert_eq!(sink.dropped(endpoint), 1, "the refused event itself");

    for _ in 0..4 {
        assert_eq!(
            sink.begin(endpoint, now),
            None,
            "the endpoint is suspended, so nothing is sent"
        );
    }
    assert_eq!(
        sink.dropped(endpoint),
        5,
        "the refused event plus the four never attempted"
    );

    // Past the window the endpoint is asked again, and the next suspension
    // reports the running total rather than starting over.
    let later = now + AUTH_SUSPENSION + Duration::from_secs(1);
    assert_eq!(sink.begin(endpoint, later), Some(1));
    let line = sink
        .finish(endpoint, classify(StatusCode::UNAUTHORIZED, None, 1), later)
        .expect("a suspension owes the operator a line");
    assert!(
        line.ends_with("so far: 6"),
        "the count must accumulate across windows: {line}"
    );
}

/// A per-event refusal loses that event too, and the operator learns it from
/// the next suspension's total rather than from nothing.
#[test]
fn a_per_event_refusal_counts_as_a_drop_without_suspending() {
    let mut sink = Sink::default();
    let now = Instant::now();
    let endpoint = "https://admin.example/ingest";
    assert_eq!(sink.begin(endpoint, now), Some(0));
    assert!(sink.finish(endpoint, Outcome::Rejected, now).is_none());
    assert_eq!(sink.dropped(endpoint), 1);
    assert_eq!(
        sink.begin(endpoint, now),
        Some(0),
        "a rejected event must not stop the next one being sent"
    );
}

/// An accepted event clears the backoff and costs no drop.
#[test]
fn an_accepted_event_clears_the_failure_count() {
    let mut sink = Sink::default();
    let now = Instant::now();
    let endpoint = "https://admin.example/ingest";
    assert_eq!(sink.begin(endpoint, now), Some(0));
    sink.finish(endpoint, classify(StatusCode::BAD_GATEWAY, None, 0), now);
    let later = now + Duration::from_secs(2);
    assert_eq!(sink.begin(endpoint, later), Some(1));
    assert!(sink.finish(endpoint, Outcome::Accepted, later).is_none());
    assert_eq!(sink.begin(endpoint, later), Some(0));
    assert_eq!(sink.dropped(endpoint), 1, "only the failed event was lost");
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

/// A `5xx` is a transient fault, so the endpoint is suspended and the backoff
/// grows — the runtime must not hammer a failing admin either.
#[tokio::test]
async fn a_5xx_stops_the_runtime_asking_for_its_backoff() {
    let stub = StubAdmin::answering("HTTP/1.1 503 Service Unavailable", "", "{}").await;
    let (tx, rx) = tokio::sync::mpsc::channel(32);
    tokio::spawn(run(rx));
    for _ in 0..8 {
        tx.send(queued(&stub.url)).await.expect("queue");
    }
    assert_eq!(stub.wait_for(1).await, 1);
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(stub.count(), 1);
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
