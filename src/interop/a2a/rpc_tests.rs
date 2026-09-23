//! Binding-level tests with a fake turn runner: no listener, no pack.

use std::sync::Mutex;

use http_body_util::BodyExt;
use serde_json::json;
use sha2::{Digest, Sha256};

use greentic_deploy_spec::ids::DeploymentId;

use super::*;
use crate::interop::a2a::{A2aContext, A2aRequest, ADAPTIVE_CARD_MEDIA_TYPE};
use crate::interop::config::{Credential, InteropConfig};
use crate::interop::limits::{RateLimiter, TurnGate};
use crate::interop::metering::testkit::{StubAdmin, unreachable_metering};
use crate::interop::metering::{Meter, TurnMetering};

const TOKEN: &str = "gtw_test-token";

/// Records every turn and answers with a fixed reply list.
struct FakeRunner {
    replies: Vec<Activity>,
    calls: Mutex<Vec<(String, String, Value)>>,
}

impl FakeRunner {
    fn replying(replies: Vec<Activity>) -> Self {
        Self {
            replies,
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<(String, String, Value)> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

#[async_trait]
impl TurnRunner for FakeRunner {
    async fn run(
        &self,
        session_hint: &str,
        user: &str,
        payload: &Value,
    ) -> Result<Vec<Activity>, TurnFailure> {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push((session_hint.to_string(), user.to_string(), payload.clone()));
        }
        Ok(self.replies.clone())
    }
}

fn config() -> InteropConfig {
    InteropConfig {
        a2a: true,
        credentials: vec![Credential {
            id: "c1".into(),
            sha256: Sha256::digest(TOKEN.as_bytes()).into(),
            expires_at_ms: None,
        }],
        ..InteropConfig::default()
    }
}

struct Fixture {
    config: InteropConfig,
    limiter: RateLimiter,
    turns: TurnGate,
    deployment_id: DeploymentId,
    meter: std::sync::Arc<Meter>,
}

impl Fixture {
    fn new(config: InteropConfig) -> Self {
        Self::with_meter(config, std::sync::Arc::new(Meter::inspectable()))
    }

    /// A fixture whose meter really runs its sink, for the tests that assert
    /// against a stub admin rather than against the queue.
    fn with_live_meter(config: InteropConfig) -> Self {
        Self::with_meter(config, std::sync::Arc::new(Meter::default()))
    }

    fn with_meter(config: InteropConfig, meter: std::sync::Arc<Meter>) -> Self {
        Self {
            config,
            limiter: RateLimiter::default(),
            turns: TurnGate::new(4),
            deployment_id: DeploymentId::new(),
            meter,
        }
    }

    fn ctx(&self) -> A2aContext<'_> {
        A2aContext {
            config: &self.config,
            base_url: Some("https://w.example"),
            tenant: "default",
            bundle_id: "support-bot",
            deployment_id: self.deployment_id,
            limiter: &self.limiter,
            turns: &self.turns,
            now_ms: 0,
            metering: TurnMetering::for_unit(
                &self.meter,
                &self.config,
                self.deployment_id,
                "support-bot",
            ),
        }
    }
}

fn request(body: &[u8]) -> A2aRequest<'_> {
    A2aRequest {
        version_header: None,
        query: None,
        if_none_match: None,
        body,
    }
}

async fn body_json(response: HttpResponse) -> Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

fn rpc(method: &str, params: Value) -> Vec<u8> {
    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        .to_string()
        .into_bytes()
}

fn send_params(context_id: Option<&str>) -> Value {
    let mut message =
        json!({"messageId": "m-in", "role": "ROLE_USER", "parts": [{"text": "hello"}]});
    if let Some(id) = context_id {
        message["contextId"] = json!(id);
    }
    json!({"message": message})
}

const BEARER: &str = "Bearer gtw_test-token";

/// Drive a JSON-RPC request the way the ingress does: authenticate from the
/// header FIRST (before any body is read), then hand the verified credential
/// id to the handler. A test that called the handler directly would not
/// exercise the order the real path depends on.
async fn rpc_call(
    fixture: &Fixture,
    authorization: Option<&str>,
    req: &A2aRequest<'_>,
    runner: &dyn TurnRunner,
) -> HttpResponse {
    let ctx = fixture.ctx();
    match crate::interop::a2a::rpc::authenticate(&ctx, authorization) {
        Ok(credential_id) => handle_jsonrpc(&ctx, req, credential_id, runner).await,
        Err(response) => *response,
    }
}

/// The same for the HTTP+JSON binding.
async fn rest_call(
    fixture: &Fixture,
    authorization: Option<&str>,
    req: &A2aRequest<'_>,
    runner: &dyn TurnRunner,
) -> HttpResponse {
    let ctx = fixture.ctx();
    match crate::interop::a2a::rpc::authenticate(&ctx, authorization) {
        Ok(credential_id) => handle_rest_send(&ctx, req, credential_id, runner).await,
        Err(response) => *response,
    }
}

#[tokio::test]
async fn send_message_runs_one_namespaced_turn_and_returns_a_message() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![Activity::custom(
        "response",
        json!({"reply": "hi there"}),
    )]);
    let body = rpc("SendMessage", send_params(Some("ctx-9")));
    let response = rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = body_json(response).await;
    let message = &value["result"]["message"];
    assert_eq!(message["role"], "ROLE_AGENT");
    assert_eq!(message["contextId"], "ctx-9");
    assert_eq!(message["parts"], json!([{"text": "hi there"}]));
    assert!(message.get("metadata").is_none());
    assert_eq!(value["id"], 1);

    let calls = runner.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "a2a:c1:ctx-9");
    assert_eq!(calls[0].1, "a2a:c1");
    assert_eq!(calls[0].2, json!({"text": "hello"}));
}

#[tokio::test]
async fn a_missing_context_id_is_minted_and_returned() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![Activity::text("ok")]);
    let body = rpc("SendMessage", send_params(None));
    let value = body_json(rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await).await;
    let context = value["result"]["message"]["contextId"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert_eq!(context.len(), 26, "a ULID");
    assert_eq!(runner.calls()[0].0, format!("a2a:c1:{context}"));
}

#[tokio::test]
async fn a_parked_turn_with_a_card_sets_awaiting_input() {
    let fixture = Fixture::new(config());
    let card = json!({"type": "AdaptiveCard", "fallbackText": "Fill it in"});
    let runner = FakeRunner::replying(vec![Activity::custom(
        "response",
        json!({"status": "pending", "response": {"renderedCard": card.clone()}}),
    )]);
    let body = rpc("SendMessage", send_params(Some("c")));
    let value = body_json(rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await).await;
    let message = &value["result"]["message"];
    assert_eq!(message["metadata"], json!({"awaitingInput": true}));
    assert_eq!(
        message["parts"],
        json!([
            {"data": card, "mediaType": ADAPTIVE_CARD_MEDIA_TYPE},
            {"text": "Fill it in"}
        ])
    );
}

#[tokio::test]
async fn no_or_wrong_bearer_is_401_and_runs_nothing() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![]);
    let body = rpc("SendMessage", send_params(None));
    for auth in [None, Some("Bearer gtw_wrong")] {
        let response = rpc_call(&fixture, auth, &request(&body), &runner).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
    }
    assert!(runner.calls().is_empty());
}

#[tokio::test]
async fn task_rpcs_answer_statelessly() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![]);
    let cases = [
        ("GetTask", json!({"id": "t"}), Some(-32001)),
        ("CancelTask", json!({"id": "t"}), Some(-32001)),
        ("SendStreamingMessage", send_params(None), Some(-32004)),
        ("SubscribeToTask", json!({"id": "t"}), Some(-32004)),
        ("CreateTaskPushNotificationConfig", json!({}), Some(-32003)),
        ("ListTaskPushNotificationConfigs", json!({}), Some(-32003)),
        ("GetExtendedAgentCard", json!({}), Some(-32007)),
        ("message/send", json!({}), Some(-32601)),
        ("ListTasks", json!({}), None),
    ];
    for (method, params, code) in cases {
        let body = rpc(method, params);
        let value =
            body_json(rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await).await;
        match code {
            Some(code) => assert_eq!(value["error"]["code"], code, "{method}"),
            None => assert_eq!(
                value["result"],
                json!({"tasks": [], "nextPageToken": "", "pageSize": 0, "totalSize": 0})
            ),
        }
    }
    assert!(runner.calls().is_empty());
}

#[tokio::test]
async fn malformed_requests_get_json_rpc_errors() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![]);
    let cases: [(&[u8], i64); 3] = [
        (b"{not json", -32700),
        (
            br#"{"jsonrpc":"1.0","id":1,"method":"SendMessage"}"#,
            -32600,
        ),
        (
            br#"[{"jsonrpc":"2.0","id":1,"method":"SendMessage"}]"#,
            -32600,
        ),
    ];
    for (body, code) in cases {
        let value =
            body_json(rpc_call(&fixture, Some(BEARER), &request(body), &runner).await).await;
        assert_eq!(value["error"]["code"], code);
        assert_eq!(value["id"], Value::Null);
    }
    let bad_params = rpc("SendMessage", json!({"message": {"parts": "x"}}));
    let value =
        body_json(rpc_call(&fixture, Some(BEARER), &request(&bad_params), &runner).await).await;
    assert_eq!(value["error"]["code"], -32602);
    let raw_only = rpc(
        "SendMessage",
        json!({"message": {"messageId": "m", "role": "ROLE_USER", "parts": [{"raw": "aGk="}]}}),
    );
    let value =
        body_json(rpc_call(&fixture, Some(BEARER), &request(&raw_only), &runner).await).await;
    assert_eq!(value["error"]["code"], -32005);
}

#[tokio::test]
async fn version_is_negotiated_on_major_minor() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![Activity::text("ok")]);
    let body = rpc("SendMessage", send_params(Some("c")));
    for (header_value, query, ok) in [
        (Some("1.0"), None, true),
        (Some("1.0.3"), None, true),
        (None, Some("A2A-Version=1.0"), true),
        (None, None, true),
        (Some("0.3"), None, false),
        (None, Some("x=1&A2A-Version=2.0"), false),
    ] {
        let mut req = request(&body);
        req.version_header = header_value;
        req.query = query;
        let value = body_json(rpc_call(&fixture, Some(BEARER), &req, &runner).await).await;
        if ok {
            assert!(
                value.get("result").is_some(),
                "{header_value:?} {query:?}: {value}"
            );
        } else {
            assert_eq!(value["error"]["code"], -32009, "{header_value:?} {query:?}");
        }
    }
}

#[tokio::test]
async fn the_rate_limit_refuses_with_retry_after() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![Activity::text("ok")]);
    let body = rpc("SendMessage", send_params(Some("c")));
    let mut last = StatusCode::OK;
    for _ in 0..61 {
        let response = rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await;
        last = response.status();
        if last == StatusCode::TOO_MANY_REQUESTS {
            assert!(response.headers().contains_key(header::RETRY_AFTER));
            break;
        }
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(runner.calls().len(), 60, "burst 120 at cost 2");
}

#[tokio::test]
async fn the_concurrent_turn_cap_refuses_when_full() {
    let mut fixture = Fixture::new(config());
    fixture.turns = TurnGate::new(1);
    let _held = fixture.turns.try_acquire(fixture.deployment_id);
    let runner = FakeRunner::replying(vec![Activity::text("ok")]);
    let body = rpc("SendMessage", send_params(Some("c")));
    let response = rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(runner.calls().is_empty());
}

#[tokio::test]
async fn rest_send_uses_the_same_turn() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![Activity::text("rest reply")]);
    let body = send_params(Some("r")).to_string().into_bytes();
    let response = rest_call(&fixture, Some(BEARER), &request(&body), &runner).await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = body_json(response).await;
    assert_eq!(value["message"]["parts"], json!([{"text": "rest reply"}]));
    assert_eq!(runner.calls()[0].0, "a2a:c1:r");

    let bad = rest_call(&fixture, Some(BEARER), &request(b"{}"), &runner).await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    let unauth = rest_call(&fixture, None, &request(&body), &runner).await;
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Metering (worker-interop contract §8)
// ---------------------------------------------------------------------------

/// One `dw.agent` reply activity, exactly the shape greentic-runner-host
/// builds: `{"reply","trail","terminated_by","usage"}`.
fn dw_agent_reply(text: &str) -> Activity {
    Activity::custom(
        "response",
        json!({
            "reply": text,
            "trail": [],
            "terminated_by": "final",
            "usage": {"tokens_in": 310, "tokens_out": 88, "iterations": 2},
        }),
    )
}

/// The whole feature, end to end on the A2A binding: a stub admin receives
/// the usage POST **while the caller still gets its answer**. Both halves are
/// asserted in one test on purpose — a metering emit that cost the turn its
/// reply would pass a queue-only assertion.
#[tokio::test]
async fn a_send_message_records_usage_while_the_caller_still_gets_its_reply() {
    let stub = StubAdmin::accepting().await;
    let mut config = config();
    config.metering = Some(stub.metering());
    let fixture = Fixture::with_live_meter(config);
    let runner = FakeRunner::replying(vec![dw_agent_reply("the answer")]);
    let body = rpc(methods::SEND_MESSAGE, send_params(Some("ctx-metered")));

    let response = rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await;
    assert_eq!(response.status(), StatusCode::OK);
    let answered = body_json(response).await;
    assert_eq!(
        answered["result"]["message"]["parts"][0]["text"], "the answer",
        "the caller must still be answered: {answered}"
    );

    assert_eq!(
        stub.wait_for(1).await,
        1,
        "no usage event reached the admin"
    );
    let event = stub.last_body();
    assert_eq!(event["surface"], "a2a");
    assert_eq!(event["tokens_in"], 310);
    assert_eq!(event["tokens_out"], 88);
    assert_eq!(event["iterations"], 2);
    assert_eq!(event["tenant_slug"], "acme");
    assert_eq!(event["credential_id"], "c1");
    assert_eq!(event["bundle_id"], "support-bot");
    assert_eq!(event["deployment_id"], fixture.deployment_id.to_string());
    assert!(event["duration_ms"].is_u64(), "{event}");
    // The caller's message and the worker's reply must not be in it.
    let wire = event.to_string();
    assert!(!wire.contains("hello"), "{wire}");
    assert!(!wire.contains("the answer"), "{wire}");
}

/// Absent config, absent feature: the deployment every unit is on today.
#[tokio::test]
async fn a_unit_with_no_metering_block_emits_nothing() {
    let fixture = Fixture::new(config());
    assert!(
        fixture.ctx().metering.is_none(),
        "an unstaged unit must build no metering"
    );
    let runner = FakeRunner::replying(vec![dw_agent_reply("the answer")]);
    let body = rpc(methods::SEND_MESSAGE, send_params(None));
    let response = rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(fixture.meter.drain().is_empty());
}

/// A turn is what produces an event. A request refused BEFORE one ran —
/// here, a bad bearer and an unparseable `params` — spent nothing, so it
/// records nothing.
#[tokio::test]
async fn a_request_refused_before_the_turn_records_nothing() {
    let mut config = config();
    config.metering = Some(unreachable_metering());
    let fixture = Fixture::new(config);
    let runner = FakeRunner::replying(vec![dw_agent_reply("unreachable")]);

    let body = rpc(methods::SEND_MESSAGE, send_params(None));
    let refused = rpc_call(&fixture, Some("Bearer gtw_wrong"), &request(&body), &runner).await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);

    let bad_params = rpc(methods::SEND_MESSAGE, json!({"message": {"parts": []}}));
    let _ = rpc_call(&fixture, Some(BEARER), &request(&bad_params), &runner).await;

    let listed = rpc(methods::LIST_TASKS, json!({}));
    let _ = rpc_call(&fixture, Some(BEARER), &request(&listed), &runner).await;

    assert!(
        fixture.meter.drain().is_empty(),
        "nothing ran, so nothing may be recorded"
    );
    assert!(runner.calls().is_empty());
}

/// A turn that produced no measurable usage still produces an event: "a turn
/// ran and cost nothing measurable" and "no turn ran" are different facts.
#[tokio::test]
async fn a_turn_with_no_usage_records_zeros_rather_than_nothing() {
    let mut config = config();
    config.metering = Some(unreachable_metering());
    let fixture = Fixture::new(config);
    let runner = FakeRunner::replying(vec![Activity::text("a card-only flow answered")]);
    let body = rpc(methods::SEND_MESSAGE, send_params(None));
    let _ = rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await;

    let queued = fixture.meter.drain();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].event.tokens_in, 0);
    assert_eq!(queued[0].event.tokens_out, 0);
    assert_eq!(queued[0].event.iterations, 0);
}

/// A turn that FAILED still ran, and may well have spent before it failed.
#[tokio::test]
async fn a_failed_turn_is_still_recorded() {
    let mut config = config();
    config.metering = Some(unreachable_metering());
    let fixture = Fixture::new(config);
    let runner = FailingRunner;
    let body = rpc(methods::SEND_MESSAGE, send_params(None));
    let response = rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await;
    let answered = body_json(response).await;
    assert_eq!(answered["error"]["code"], codes::INTERNAL_ERROR);
    assert_eq!(fixture.meter.drain().len(), 1);
}

/// A turn is metered on both bindings, not only the JSON-RPC one.
#[tokio::test]
async fn the_rest_binding_records_the_same_event() {
    let mut config = config();
    config.metering = Some(unreachable_metering());
    let fixture = Fixture::new(config);
    let runner = FakeRunner::replying(vec![dw_agent_reply("the answer")]);
    let body = send_params(None).to_string().into_bytes();
    let ctx = fixture.ctx();
    let response = handle_rest_send(&ctx, &request(&body), "c1", &runner).await;
    assert_eq!(response.status(), StatusCode::OK);
    let queued = fixture.meter.drain();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].event.surface, "a2a");
    assert_eq!(queued[0].event.tokens_in, 310);
}

struct FailingRunner;

#[async_trait]
impl TurnRunner for FailingRunner {
    async fn run(
        &self,
        _session_hint: &str,
        _user: &str,
        _payload: &Value,
    ) -> Result<Vec<Activity>, TurnFailure> {
        Err(TurnFailure)
    }
}

/// **The property this whole feature turns on, over the production chain.**
///
/// A real turn answers with every reply shape this runtime projects — plain
/// text, a `dw.agent` reply, a nested card, a parked card, a categorized flow
/// error — each carrying distinctive content. The event that reaches the
/// queue is then serialized and must contain NONE of it.
///
/// Asserted over the RECORDED event rather than over a hand-built one, so a
/// field added anywhere between the reply activities and the queue fails
/// here. The type-level half — that the event's key set is a closed list —
/// is `metering::event::event_tests::the_event_carries_only_identifiers_and_counters`.
#[tokio::test]
async fn no_turn_content_reaches_the_recorded_event() {
    const CONTENT: &[&str] = &[
        "my credit card is 4111111111111111",
        "the answer is 42 and here is why",
        "Pick a department",
        "Nested detail",
        "Fill the form",
        "API key is invalid",
    ];
    let mut config = config();
    // `credential_id` populated too, so the key-set assertion below sees the
    // event at its WIDEST: a field that is skipped when absent cannot be
    // caught by a fixture that leaves it absent.
    config.metering = Some(unreachable_metering());
    let fixture = Fixture::new(config);
    let runner = FakeRunner::replying(vec![
        // The `dw.agent` reply is FIRST on purpose: anything that lifts a
        // "preview" off a turn reads the first reply, so putting a
        // content-bearing one there is what catches it.
        Activity::custom(
            "response",
            json!({"reply": CONTENT[1], "trail": [], "terminated_by": "final",
                   "usage": {"tokens_in": 9, "tokens_out": 3, "iterations": 1}}),
        ),
        Activity::text(CONTENT[1]),
        Activity::custom(
            "response",
            json!({"outputs": {"result": {"renderedCard": {
                "type": "AdaptiveCard", "version": "1.6",
                "body": [{"type": "TextBlock", "text": CONTENT[2]},
                         {"type": "Container",
                          "items": [{"type": "TextBlock", "text": CONTENT[3]}]}]
            }}}}),
        ),
        Activity::custom(
            "response",
            json!({"status": "pending", "response": {"renderedCard":
                {"type": "AdaptiveCard", "fallbackText": CONTENT[4]}}}),
        ),
        Activity::custom(
            "response",
            json!({"metadata": {"error_kind": "component", "error_message": CONTENT[5]}}),
        ),
    ]);

    let mut message =
        json!({"messageId": "m-in", "role": "ROLE_USER", "parts": [{"text": CONTENT[0]}]});
    message["contextId"] = json!("ctx-with-content");
    let body = rpc(methods::SEND_MESSAGE, json!({"message": message}));
    let response = rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await;
    assert_eq!(response.status(), StatusCode::OK);

    let queued = fixture.meter.drain();
    assert_eq!(
        queued.len(),
        1,
        "the turn ran, so exactly one event is owed"
    );
    let wire = serde_json::to_string(&queued[0].event).expect("serialise");
    for content in CONTENT {
        assert!(
            !wire.contains(content),
            "turn content `{content}` reached the usage event: {wire}"
        );
    }
    // The caller-chosen conversation id is content too: it is a string the
    // caller writes, and it must not be recorded either.
    assert!(!wire.contains("ctx-with-content"), "{wire}");
    // The counters DID travel — a test that passed because nothing was read
    // would prove nothing.
    assert!(wire.contains("\"tokens_in\":9"), "{wire}");
    // And the recorded event carries nothing BEYOND the closed list. A
    // substring check alone cannot see a new field whose value happens not to
    // match this fixture's strings; the key set can.
    let recorded: Value = serde_json::from_str(&wire).expect("an object");
    let mut keys: Vec<&str> = recorded
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "agent_id",
            "bundle_id",
            "credential_id",
            "deployment_id",
            "duration_ms",
            "event_id",
            "iterations",
            "occurred_at",
            "surface",
            "tenant_slug",
            "tokens_in",
            "tokens_out",
        ],
        "a field was added to the recorded usage event: {wire}"
    );
}
