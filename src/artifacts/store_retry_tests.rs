//! Door client: Retry-After, gateway errors, the answer cap, proxies and
//! long conversation ids. Split from `store_tests.rs` for the file-size cap.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::interop::metering::testkit::{StubAdmin, TEST_TOKEN};

use super::store::*;
use super::store_tests::{OK, OK_BODY, OK_ID, client, kind, request};

// --- Retry-After, gateway errors, body cap, proxy -----------------------------

#[tokio::test]
async fn retry_after_is_honoured() {
    let stub = StubAdmin::answering_in_turn(&[
        ("HTTP/1.1 429 Too Many Requests", "Retry-After: 1\r\n", "{}"),
        (OK, "", OK_BODY),
    ])
    .await;
    let started = Instant::now();
    client(&stub).put(request(b"x")).await.unwrap();
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(950), "{waited:?}");
    assert!(waited < Duration::from_millis(2500), "{waited:?}");
}

#[tokio::test]
async fn retry_after_is_capped_at_three_seconds() {
    let stub = StubAdmin::answering_in_turn(&[
        (
            "HTTP/1.1 429 Too Many Requests",
            "Retry-After: 120\r\n",
            "{}",
        ),
        (OK, "", OK_BODY),
    ])
    .await;
    let started = Instant::now();
    client(&stub).put(request(b"x")).await.unwrap();
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(2950), "{waited:?}");
    assert!(waited < Duration::from_millis(4500), "{waited:?}");
}

#[tokio::test]
async fn an_unreadable_retry_after_falls_back_to_the_backoff() {
    let stub = StubAdmin::answering_in_turn(&[
        (
            "HTTP/1.1 429 Too Many Requests",
            "Retry-After: Wed, 21 Oct 2015 07:28:00 GMT\r\n",
            "{}",
        ),
        (OK, "", OK_BODY),
    ])
    .await;
    let started = Instant::now();
    client(&stub).put(request(b"x")).await.unwrap();
    assert!(started.elapsed() < Duration::from_millis(500));
}

#[tokio::test]
async fn gateway_errors_are_retried_like_503() {
    for status in ["HTTP/1.1 502 Bad Gateway", "HTTP/1.1 504 Gateway Timeout"] {
        let stub = StubAdmin::answering_in_turn(&[(status, "", "{}"), (OK, "", OK_BODY)]).await;
        client(&stub).put(request(b"x")).await.unwrap();
        assert_eq!(stub.count(), 2, "{status}");
    }
}

#[tokio::test]
async fn an_oversized_success_body_is_refused() {
    let padded = padded_answer(70 * 1024);
    let stub = StubAdmin::answering(OK, "", &padded).await;
    let err = client(&stub).put(request(b"x")).await.unwrap_err();
    assert_eq!(kind(&err), "Unavailable");
}

#[tokio::test]
async fn a_success_body_under_the_cap_is_read() {
    let padded = padded_answer(32 * 1024);
    let stub = StubAdmin::answering(OK, "", &padded).await;
    assert_eq!(client(&stub).put(request(b"x")).await.unwrap().id, OK_ID);
}

#[tokio::test]
async fn the_door_client_ignores_the_proxy_environment() {
    use super::proxy_testkit::{fake_proxy, run_child_behind_proxy};
    let stub = StubAdmin::answering(OK, "", OK_BODY).await;
    let (proxy, proxied) = fake_proxy().await;
    assert!(
        run_child_behind_proxy(
            "artifacts::store_retry_tests::door_put_from_the_proxy_environment",
            &proxy,
            &stub.url,
        )
        .await,
        "the child put failed"
    );
    assert_eq!(proxied.load(Ordering::SeqCst), 0, "the proxy was used");
    assert_eq!(stub.count(), 1, "the door was not reached directly");
}

/// Child half of the test above; runs only inside its proxied environment.
#[tokio::test]
#[ignore = "run by the_door_client_ignores_the_proxy_environment"]
async fn door_put_from_the_proxy_environment() {
    let target = std::env::var(super::proxy_testkit::TARGET_ENV).unwrap();
    let store = HttpArtifactStore::new(target, TEST_TOKEN.into(), Duration::from_secs(2))
        .unwrap()
        .with_backoff(Duration::from_millis(1));
    store.put(request(b"x")).await.unwrap();
}

/// [`OK_BODY`] with a `pad` field of `n` bytes.
fn padded_answer(n: usize) -> String {
    let pad = "x".repeat(n);
    format!("{},\"pad\":\"{pad}\"}}", &OK_BODY[..OK_BODY.len() - 1])
}

// --- conversation_id: always its SHA-256, never the key itself ----------------
//
// The quota key is built from the channel, the pack, the sender and the
// session: on WhatsApp the sender is a phone number. The door only needs a
// stable, injective key, so the host sends the key's SHA-256 (64 hex
// characters, inside the door's 128-byte limit) and never the key.

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tokio::test]
async fn a_short_conversation_id_is_still_sent_hashed() {
    let id = "whatsapp\u{1f}pack\u{1f}whatsapp\u{1f}6281234567890\u{1f}whatsapp".to_string();
    let stub = StubAdmin::answering(OK, "", OK_BODY).await;
    let mut req = request(b"x");
    req.conversation_id = Some(&id);
    client(&stub).put(req).await.unwrap();
    let sent = stub.last_body()["conversation_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(sent, sha256_hex(&id));
    assert!(!stub.received().join("\n").contains("6281234567890"));
}

#[tokio::test]
async fn a_longer_conversation_id_is_sent_as_its_stable_sha256() {
    let id = format!("whatsapp:{}", "9".repeat(200));
    let stub = StubAdmin::answering(OK, "", OK_BODY).await;
    for _ in 0..2 {
        let mut req = request(b"x");
        req.conversation_id = Some(&id);
        client(&stub).put(req).await.unwrap();
        let sent = stub.last_body()["conversation_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(sent, sha256_hex(&id));
        assert_eq!(sent.len(), 64);
    }
    // A multibyte id over the byte limit but under 128 characters too.
    let wide = "é".repeat(100);
    let mut req = request(b"x");
    req.conversation_id = Some(&wide);
    client(&stub).put(req).await.unwrap();
    assert_eq!(
        stub.last_body()["conversation_id"],
        sha256_hex(&wide).as_str()
    );
}
