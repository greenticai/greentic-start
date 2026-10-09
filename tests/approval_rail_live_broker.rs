//! End-to-end proof that the approval bridge actually flies over a real broker.
//!
//! The unit tests in `src/approval_rail/` exercise parsing, the ledger and the
//! click extraction against values built in memory. None of them opens a
//! socket, so none of them proves the thing this bridge exists to do: that a
//! request published by greentic-designer reaches delivery, and that a human's
//! click comes back out on the response subject with the correlation id echoed
//! and the `decision_token` intact.
//!
//! These tests need a live NATS on `GREENTIC_APPROVAL_NATS_URL` and are
//! **skipped when it is unset**, exactly like the production bridge, which is
//! only started at boot when that variable is configured. Skipping rather than
//! failing is deliberate: CI has no broker, and a test that goes red there
//! would be turned off within a week and prove nothing thereafter. It mirrors
//! greentic-designer's own `tests/approval_rail_live_broker.rs`.
//!
//! What is real and what is not:
//!
//! * **Real** — the NATS broker, the subscribe, the queue group, the request
//!   parse, the delivery ledger, the response publish and its
//!   `Greentic-Correlation-Id` header, and the `approval_request` op input this
//!   bridge builds.
//! * **Stubbed** — the WASM provider component and the Slack HTTP call. The
//!   `ApprovalDelivery` implementation here records what it was handed instead
//!   of instantiating `messaging-provider-slack` and POSTing to Slack. The
//!   click is likewise a recorded `block_actions` body rather than one Slack
//!   sent; it is the shape Slack posts (form-urlencoded `payload=<json>`) and
//!   carries the message metadata the component stamps.
//!
//! To run:
//!
//! ```text
//! docker run -d --name greentic-nats-bridge -p 4223:4222 nats:latest -js
//! GREENTIC_APPROVAL_NATS_URL=nats://127.0.0.1:4223 \
//!   cargo test -p greentic-start --test approval_rail_live_broker -- --nocapture
//! ```

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use greentic_start::approval_rail::{
    self, ApprovalRailListener, ApprovalRailListenerConfig,
    delivery::{ApprovalDelivery, approval_request_input},
    ledger::Delivery,
    request::RailRequest,
};
use greentic_types::{ChannelMessageEnvelope, EnvId, TenantCtx, TenantId};
use serde_json::{Value, json};

const REQUEST_SUBJECT: &str = "greentic.approval.request.v1";
const RESPONSE_SUBJECT: &str = "greentic.approval.response.v1";
const CORRELATION_ID_HEADER: &str = "Greentic-Correlation-Id";
const RESPONSE_EXTENSION_KEY: &str = "greentic.approval.response";

/// The one skip gate.
fn broker_url() -> Option<String> {
    match std::env::var("GREENTIC_APPROVAL_NATS_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url.trim().to_string()),
        _ => {
            eprintln!(
                "skipping: set GREENTIC_APPROVAL_NATS_URL to a live NATS to run the \
                 live-broker approval bridge tests"
            );
            None
        }
    }
}

/// What the bridge handed to delivery, instead of a Slack API call.
#[derive(Default)]
struct RecordingDelivery {
    destination: String,
    seen: Mutex<Vec<Value>>,
}

impl RecordingDelivery {
    fn inputs(&self) -> Vec<Value> {
        self.seen.lock().expect("lock").clone()
    }
}

impl ApprovalDelivery for RecordingDelivery {
    fn deliver(
        &self,
        request: &RailRequest,
        known: Option<&Delivery>,
    ) -> anyhow::Result<Option<Delivery>> {
        // The exact op input `messaging-provider-slack::approval_request` would
        // have received, built by production code.
        self.seen.lock().expect("lock").push(approval_request_input(
            request,
            &self.destination,
            known,
            None,
        ));
        Ok(None)
    }
}

/// A `block_actions` body in the shape Slack really posts for interactivity.
fn slack_click_body(correlation_id: &str, message_ts: &str) -> Vec<u8> {
    let payload = json!({
        "type": "block_actions",
        "user": {"id": "U123", "profile": {"email": "boss@acme.test"}},
        "channel": {"id": "C-APPROVERS"},
        "container": {"type": "message", "message_ts": message_ts, "channel_id": "C-APPROVERS"},
        "message": {
            "ts": message_ts,
            "metadata": {
                "event_type": "greentic_approval",
                "event_payload": {"correlation_id": correlation_id}
            }
        },
        "actions": [{
            "action_id": "greentic_approval_approve",
            "value": format!(
                "{{\"cid\":\"{correlation_id}\",\"tok\":\"LIVE-TOKEN-FOR-THIS-GATE\"}}"
            )
        }]
    });
    format!(
        "payload={}",
        urlencoding::encode(&serde_json::to_string(&payload).expect("serialize"))
    )
    .into_bytes()
}

/// The envelope `messaging-provider-slack::ingest_http` emits for that click.
fn slack_click_envelope(correlation_id: &str) -> ChannelMessageEnvelope {
    let env = EnvId::try_from("default").expect("env id");
    let tenant = TenantId::try_from("default").expect("tenant id");
    let mut envelope = ChannelMessageEnvelope {
        id: "slack-C-APPROVERS".to_string(),
        tenant: TenantCtx::new(env, tenant),
        channel: "C-APPROVERS".to_string(),
        session_id: "C-APPROVERS".to_string(),
        reply_scope: None,
        from: None,
        to: Vec::new(),
        correlation_id: None,
        text: Some("[approval:approved]".to_string()),
        attachments: Vec::new(),
        metadata: Default::default(),
        extensions: Default::default(),
    };
    envelope.extensions.insert(
        RESPONSE_EXTENSION_KEY.to_string(),
        json!({
            "subject": RESPONSE_SUBJECT,
            "headers": {CORRELATION_ID_HEADER: correlation_id},
            "body": {
                "decision": "approved",
                "resolved_by": "boss@acme.test",
                "decision_token": "LIVE-TOKEN-FOR-THIS-GATE",
                "note": null,
            },
        }),
    );
    envelope
}

fn request_body(correlation_id: &str, token: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "target": correlation_id,
        "operation": "request",
        "input": {"title": "Refund 1200 USD", "risk": 0.8},
        "routing": {
            "policy_id": "refunds",
            "tier": {"level": 1, "position": null, "chain_len": 2, "min_approvals": 2, "deadline_ms": 3600000},
            "approvers": {"role": "admin", "emails": ["boss@acme.test"]},
            "channels": ["slack"],
            "decision_token": token,
        },
    }))
    .expect("serialize")
}

/// Read from `sub` until a message for `correlation` arrives.
///
/// The subject is SHARED — every subscriber sees every other publisher's
/// traffic, which is the concrete form of the contract's §6 warning and exactly
/// why per-tenant subject-level read authorization is a deployment requirement.
/// A real subscriber filters the same way.
async fn next_for(sub: &mut async_nats::Subscriber, correlation: &str) -> async_nats::Message {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let message = sub.next().await.expect("subscription closed");
            let matches = message
                .headers
                .as_ref()
                .and_then(|headers| headers.get(CORRELATION_ID_HEADER))
                .map(|value| value.as_str() == correlation)
                .unwrap_or(false);
            if matches {
                return message;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no message for {correlation} within 5s"))
}

async fn wait_for<T>(mut probe: impl FnMut() -> Option<T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(value) = probe() {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("condition not reached within 5s")
}

/// The whole round trip, over a real broker, in one test.
///
/// One test rather than several because `ApprovalRailListener::start` installs
/// a process-wide handle and deliberately refuses a second install — two
/// bridges would hold two disjoint ledgers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_reaches_delivery_and_the_click_comes_back_on_the_response_subject() {
    let Some(url) = broker_url() else {
        return;
    };
    let gate = format!("default::run=RUN-{}::node=gate", std::process::id());

    // A separate connection standing in for greentic-designer: it publishes
    // requests and reads answers.
    let designer = async_nats::connect(&url).await.expect("designer connect");
    let mut responses = designer
        .subscribe(RESPONSE_SUBJECT)
        .await
        .expect("subscribe to responses");

    let recording = Arc::new(RecordingDelivery {
        destination: "C-APPROVERS".to_string(),
        seen: Mutex::new(Vec::new()),
    });
    let listener = ApprovalRailListener::start(ApprovalRailListenerConfig {
        nats_url: url.clone(),
        delivery: Arc::clone(&recording) as Arc<dyn ApprovalDelivery>,
    });

    // The bridge connects and subscribes on its own thread; give it a moment
    // before the first publish, or NATS drops a message nobody is listening for.
    tokio::time::sleep(Duration::from_millis(400)).await;

    // ── 1. A request published on the rail reaches delivery ────────────────
    let mut headers = async_nats::HeaderMap::new();
    headers.insert(CORRELATION_ID_HEADER, gate.as_str());
    designer
        .publish_with_headers(
            REQUEST_SUBJECT,
            headers.clone(),
            request_body(&gate, "FIRST-TOKEN-FOR-THIS-GATE").into(),
        )
        .await
        .expect("publish request");
    designer.flush().await.expect("flush");

    let first = wait_for(|| recording.inputs().into_iter().next()).await;
    assert_eq!(first["correlation_id"], gate);
    assert_eq!(first["channel"], "C-APPROVERS");
    assert!(
        first.get("message_ts").is_none(),
        "a first delivery must post, not update"
    );
    assert_eq!(
        first["request"]["routing"]["decision_token"], "FIRST-TOKEN-FOR-THIS-GATE",
        "the request body must reach the delivery component verbatim"
    );
    assert_eq!(first["request"]["input"]["title"], "Refund 1200 USD");

    // ── 2. A click produces a response on the response subject ─────────────
    let mut envelopes = vec![slack_click_envelope(&gate)];
    approval_rail::intercept_inbound(
        Some("application/x-www-form-urlencoded"),
        &slack_click_body(&gate, "1700000000.000100"),
        &mut envelopes,
    );
    assert!(
        envelopes.is_empty(),
        "the decision envelope must not go on to flow routing"
    );

    let answer = next_for(&mut responses, &gate).await;
    let body: Value = serde_json::from_slice(&answer.payload).expect("decode response");
    assert_eq!(body["decision"], "approved");
    assert_eq!(body["resolved_by"], "boss@acme.test");
    assert_eq!(
        body["decision_token"], "LIVE-TOKEN-FOR-THIS-GATE",
        "without the token the designer refuses the response and the gate stays pending"
    );

    // ── 3. The quorum republish UPDATES the outstanding message ────────────
    // The click above told the bridge where this gate's message lives; the
    // designer now mints a fresh token and republishes on the same correlation
    // id. Without the ledger this would post a SECOND approval message.
    designer
        .publish_with_headers(
            REQUEST_SUBJECT,
            headers,
            request_body(&gate, "SECOND-TOKEN-FOR-THIS-GATE").into(),
        )
        .await
        .expect("publish republish");
    designer.flush().await.expect("flush");

    let second = wait_for(|| recording.inputs().into_iter().nth(1)).await;
    assert_eq!(
        second["message_ts"], "1700000000.000100",
        "a republish for a gate whose message is known must UPDATE it, not post a second \
         approval message"
    );
    assert_eq!(
        second["request"]["routing"]["decision_token"], "SECOND-TOKEN-FOR-THIS-GATE",
        "the republish carries the fresh token the second approver answers with"
    );

    listener.stop();
}
