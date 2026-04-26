//! Integration tests for the webchat DirectLine WebSocket streaming endpoint.
//!
//! These tests spin up an in-process Hyper server (provided by
//! `greentic_start::ws_test_support`) bound to a random TCP port. They drive
//! a real `tokio_tungstenite` client through the upgrade handshake and
//! validate the downstream pump pipeline (replay + live push).
//!
//! Scope:
//! * The server skips all bundle/`HttpIngressState` plumbing — it accepts
//!   any URL ending in `.../conversations/<id>/stream`. Route-matching
//!   logic is covered separately by the `http_ingress::tests` unit tests.
//! * Tokens are signed with a hard-coded HS256 key (`b"test-key"`) that
//!   the test server is configured to accept. This mirrors the production
//!   path where the key is loaded via the secrets capability.
//! * The activity source is an in-memory store — tests append messages via
//!   `server.activities.append(...)` and the source returns them filtered
//!   by watermark, the same shape the production WASM provider returns.

use std::time::Duration;

use futures_util::StreamExt;
use greentic_start::ws_test_support::{TestServerConfig, issue_test_token, spawn_test_server};
use tokio_tungstenite::tungstenite::Message;

const TEST_KEY: &[u8] = b"test-key";
const TEST_TENANT: &str = "tenant1";
const TEST_CONV: &str = "conv1";

fn ws_url(addr: std::net::SocketAddr, conv_id: &str, token: &str, watermark: u64) -> String {
    format!(
        "ws://{addr}/v1/messaging/webchat/{TEST_TENANT}/v3/directline/conversations/{conv_id}/stream?t={token}&watermark={watermark}"
    )
}

/// Token + handshake + live push: replay yields one queued activity, then
/// publishing a `NotifyEvent` drives a second `ActivitySet` frame to the
/// client. Both frames must arrive within ~2s.
#[tokio::test(flavor = "multi_thread")]
async fn handshake_and_push_delivers_activity() {
    let server = spawn_test_server(TestServerConfig {
        signing_key: TEST_KEY.to_vec(),
        expected_tenant: TEST_TENANT.to_string(),
        ..Default::default()
    })
    .await;

    // Pre-populate one activity so the pump emits a replay frame on connect.
    let initial_watermark = server.activities.append("hello from POST");

    let token = issue_test_token(TEST_CONV, TEST_TENANT, TEST_KEY);
    let url = ws_url(server.addr, TEST_CONV, &token, 0);
    let (mut ws, response) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("ws connect");
    assert_eq!(
        response.status(),
        tokio_tungstenite::tungstenite::http::StatusCode::SWITCHING_PROTOCOLS
    );

    // First frame should be the replay payload.
    let replay = tokio::time::timeout(Duration::from_millis(2000), ws.next())
        .await
        .expect("replay timeout")
        .expect("ws closed before replay")
        .expect("ws error");
    let replay_text = expect_text(replay);
    let payload: serde_json::Value = serde_json::from_str(&replay_text).expect("json");
    let activities = payload["activities"].as_array().expect("activities array");
    assert_eq!(activities.len(), 1, "replay should contain one activity");
    assert_eq!(activities[0]["text"], "hello from POST");

    // Now publish a live event; the pump should re-fetch and forward
    // the new activity inside another `ActivitySet`.
    let new_watermark = server.activities.append("live update");
    server
        .notifier
        .publish(greentic_start::ws_test_support::NotifyEvent {
            tenant_id: TEST_TENANT.to_string(),
            conversation_id: TEST_CONV.to_string(),
            new_watermark: new_watermark + 1,
        })
        .await;

    let live = tokio::time::timeout(Duration::from_millis(2000), ws.next())
        .await
        .expect("live timeout")
        .expect("ws closed before live")
        .expect("ws error");
    let live_payload: serde_json::Value = serde_json::from_str(&expect_text(live)).expect("json");
    let live_activities = live_payload["activities"]
        .as_array()
        .expect("live activities array");
    assert!(
        live_activities
            .iter()
            .any(|activity| activity["text"] == "live update"),
        "expected live activity in {live_activities:?}",
    );

    let _ = ws.close(None).await;
    drop(server);
    let _ = initial_watermark; // keep variable name informative
}

/// Connecting without the `?t=` token must fail with HTTP 401 from
/// `refusal_response`. `tokio_tungstenite` surfaces the bad status as a
/// connect error whose Display string contains the status code.
#[tokio::test(flavor = "multi_thread")]
async fn missing_token_returns_401() {
    let server = spawn_test_server(TestServerConfig {
        signing_key: TEST_KEY.to_vec(),
        expected_tenant: TEST_TENANT.to_string(),
        ..Default::default()
    })
    .await;

    let url = format!(
        "ws://{addr}/v1/messaging/webchat/{TEST_TENANT}/v3/directline/conversations/{TEST_CONV}/stream",
        addr = server.addr,
    );
    let result = tokio_tungstenite::connect_async(&url).await;
    let err = result.expect_err("expected handshake to fail without token");
    let msg = err.to_string();
    assert!(
        msg.contains("401") || msg.to_lowercase().contains("unauthorized"),
        "expected 401 / Unauthorized in error, got: {msg}",
    );
}

fn expect_text(msg: Message) -> String {
    match msg {
        Message::Text(s) => s.to_string(),
        other => panic!("expected text frame, got {other:?}"),
    }
}
