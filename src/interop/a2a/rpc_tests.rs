//! Binding-level tests with a fake turn runner: no listener, no pack.

use std::sync::Mutex;

use http_body_util::BodyExt;
use serde_json::json;
use sha2::{Digest, Sha256};

use greentic_deploy_spec::ids::DeploymentId;

use super::*;
use crate::interop::a2a::{A2aContext, A2aRequest, ADAPTIVE_CARD_MEDIA_TYPE};
use crate::interop::config::{Credential, InteropConfig};
use crate::interop::input_request::INPUT_REQUEST_MEDIA_TYPE;
use crate::interop::limits::{RateLimiter, TurnGate};
use crate::interop::metering::event::Surface;
use crate::interop::metering::testkit::{StubAdmin, unreachable_metering};
use crate::interop::metering::{Meter, TurnMetering};
use crate::interop::telemetry::{FieldValue, RequestTrace};

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

/// A trace for one request, attributed the way the ingress attributes one.
fn trace() -> RequestTrace {
    RequestTrace::new(
        Surface::A2a,
        greentic_telemetry::TelemetryCtx::new("default").with_bundle_id("support-bot"),
    )
}

struct Fixture {
    config: InteropConfig,
    limiter: RateLimiter,
    turns: TurnGate,
    deployment_id: DeploymentId,
    /// One fixture serves ONE request when a test asserts on the trace:
    /// `RequestTrace` accumulates a request's facts and an outcome is
    /// first-wins, so a second request through the same fixture would read
    /// the first one's outcome.
    trace: RequestTrace,
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
            trace: trace(),
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
            trace: &self.trace,
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

// ---------------------------------------------------------------------------
// Asking the caller for more input (worker-interop contract §9)
// ---------------------------------------------------------------------------

/// The card a real parked turn renders: a required choice, an optional
/// bounded number, a toggle, and a submit button whose `data.action` is what
/// the flow routes on.
fn parked_card() -> Value {
    json!({
        "type": "AdaptiveCard", "version": "1.6",
        "fallbackText": "Which plan should I set up?",
        "body": [
            {"type": "Input.ChoiceSet", "id": "plan", "label": "Plan",
             "isRequired": true, "isMultiSelect": false,
             "choices": [{"title": "Basic", "value": "basic"},
                         {"title": "Pro", "value": "pro"}]},
            {"type": "Input.Number", "id": "seats", "label": "Seats",
             "min": 1, "max": 100},
            {"type": "Input.Toggle", "id": "trial", "title": "Start a trial"}
        ],
        "actions": [{"type": "Action.Submit", "title": "Confirm",
                     "data": {"action": "confirm"}}]
    })
}

fn parked_turn(card: Value) -> FakeRunner {
    FakeRunner::replying(vec![Activity::custom(
        "response",
        json!({"status": "pending", "response": {"renderedCard": card}}),
    )])
}

/// A `SendMessage` whose `configuration.acceptedOutputModes` names `mode`.
fn send_params_accepting(context_id: &str, mode: &str) -> Value {
    let mut params = send_params(Some(context_id));
    params["configuration"] = json!({"acceptedOutputModes": ["text/plain", mode]});
    params
}

/// **D8 and D11.** A parked turn answers with a `Task` in `input-required`,
/// whose status message carries the question as prose AND as a structured
/// input request derived from the card's own inputs.
#[tokio::test]
async fn a_parked_turn_answers_input_required_with_the_fields_it_wants() {
    let fixture = Fixture::new(config());
    let runner = parked_turn(parked_card());
    let body = rpc("SendMessage", send_params(Some("ctx-parked")));
    let value = body_json(rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await).await;

    assert!(
        value["result"].get("message").is_none(),
        "a parked turn is not a completed message: {value}"
    );
    let task = &value["result"]["task"];
    assert_eq!(task["status"]["state"], "TASK_STATE_INPUT_REQUIRED");
    // D9: the conversation names the one thing that can be resumed.
    assert_eq!(task["id"], "ctx-parked");
    assert_eq!(task["contextId"], "ctx-parked");
    assert!(task["status"]["timestamp"].is_string(), "{task}");

    let parts = &task["status"]["message"]["parts"];
    assert_eq!(
        parts[0],
        json!({"text": "Which plan should I set up?"}),
        "the question in prose comes first: {parts}"
    );
    assert_eq!(
        parts[1],
        json!({
            "data": {
                "prompt": "Which plan should I set up?",
                "fields": [
                    {"id": "plan", "label": "Plan", "type": "choice", "required": true,
                     "multiSelect": false,
                     "choices": [{"value": "basic", "label": "Basic"},
                                 {"value": "pro", "label": "Pro"}]},
                    {"id": "seats", "label": "Seats", "type": "number",
                     "required": false, "min": 1, "max": 100},
                    {"id": "trial", "label": "Start a trial", "type": "boolean",
                     "required": false}
                ],
                "actions": [{"id": "confirm", "label": "Confirm"}]
            },
            "mediaType": INPUT_REQUEST_MEDIA_TYPE
        })
    );
    assert_eq!(
        parts.as_array().map(Vec::len),
        Some(2),
        "and no card: {parts}"
    );
}

/// A parked card carrying no input element still parks, and still says so —
/// `fields: []` is an answer, not a missing one.
#[tokio::test]
async fn a_parked_card_with_no_inputs_still_asks_for_an_answer() {
    let fixture = Fixture::new(config());
    let card = json!({"type": "AdaptiveCard", "fallbackText": "Press continue",
                      "body": [{"type": "TextBlock", "text": "Press continue"}]});
    let runner = parked_turn(card);
    let body = rpc("SendMessage", send_params(Some("c")));
    let value = body_json(rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await).await;
    let task = &value["result"]["task"];
    assert_eq!(task["status"]["state"], "TASK_STATE_INPUT_REQUIRED");
    assert_eq!(
        task["status"]["message"]["parts"][1]["data"],
        json!({"prompt": "Press continue", "fields": [], "actions": []})
    );
}

/// **D8, the other half.** A turn that finished still answers with a
/// `Message`, and — with no opt-in — with no card part at all.
#[tokio::test]
async fn a_completed_turn_answers_a_message_with_no_card_part() {
    let fixture = Fixture::new(config());
    let card = json!({"type": "AdaptiveCard", "fallbackText": "Your receipt"});
    let runner = FakeRunner::replying(vec![Activity::custom(
        "response",
        json!({"outputs": {"result": {"renderedCard": card}}}),
    )]);
    let body = rpc("SendMessage", send_params(Some("c")));
    let value = body_json(rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await).await;
    assert!(value["result"].get("task").is_none(), "{value}");
    let message = &value["result"]["message"];
    assert_eq!(message["parts"], json!([{"text": "Your receipt"}]));
    assert!(message.get("metadata").is_none());
    assert!(message.get("taskId").is_none());
}

/// **D10.** The card rides only for a caller that declared it accepts one,
/// under either spelling of the media type. Its fallback text travels either
/// way, so nobody loses the question.
#[tokio::test]
async fn the_card_arrives_only_for_a_caller_that_opted_in() {
    let fixture = Fixture::new(config());
    let card = parked_card();
    for (params, wants_card) in [
        (send_params(Some("c")), false),
        (send_params_accepting("c", "application/json"), false),
        (send_params_accepting("c", ADAPTIVE_CARD_MEDIA_TYPE), true),
        (
            send_params_accepting("c", "application/vnd.microsoft.card.adaptive"),
            true,
        ),
    ] {
        let runner = parked_turn(card.clone());
        let body = rpc("SendMessage", params.clone());
        let value =
            body_json(rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await).await;
        let parts = value["result"]["task"]["status"]["message"]["parts"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let card_parts: Vec<&Value> = parts
            .iter()
            .filter(|part| part["mediaType"] == ADAPTIVE_CARD_MEDIA_TYPE)
            .collect();
        assert_eq!(
            card_parts.len(),
            usize::from(wants_card),
            "{params}: {parts:?}"
        );
        if wants_card {
            assert_eq!(card_parts[0]["data"], card, "{params}");
        }
        assert!(
            parts
                .iter()
                .any(|part| part["text"] == "Which plan should I set up?"),
            "the question in prose is not optional: {params}"
        );
        assert!(
            parts
                .iter()
                .any(|part| part["mediaType"] == INPUT_REQUEST_MEDIA_TYPE),
            "nor is the structured one: {params}"
        );
    }
}

/// A flow that FAILED is not a flow that is asking a question. It ends the
/// turn, so it answers with a `Message` — never `input-required`, which
/// would tell a calling agent to keep trying to answer a dead flow.
#[tokio::test]
async fn a_flow_error_is_not_a_question() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![Activity::custom(
        "response",
        json!({"metadata": {"error_kind": "component", "error_message": "API key is invalid"}}),
    )]);
    let body = rpc("SendMessage", send_params(Some("c")));
    let value = body_json(rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await).await;
    assert!(value["result"].get("task").is_none(), "{value}");
    let message = &value["result"]["message"];
    assert!(message.get("metadata").is_none());
    let parts = message["parts"].as_array().cloned().unwrap_or_default();
    assert!(
        !parts
            .iter()
            .any(|part| part["mediaType"] == INPUT_REQUEST_MEDIA_TYPE),
        "a failure must not read as an input request: {parts:?}"
    );
    assert!(
        parts[0]["text"].as_str().is_some_and(|t| !t.is_empty()),
        "the categorized error still reaches the caller: {parts:?}"
    );
}

/// **The round trip.** The caller answers the input request with a `data`
/// part naming the field ids, and the turn that reaches the runner is the
/// SUBMIT shape on the same conversation.
///
/// `{"metadata": {…}}` is not taken on trust from the contract: it is what
/// `revision_serve::normalize_worker_payload` builds for a card submit on
/// `/workers/invoke`, and greentic-runner-host's `submitted_fields` reads a
/// resumed node's answers back out of `entry.input.metadata.*` (its own
/// `submitted_fields_reads_metadata_on_the_wrapped_path` pins that side).
/// `action` is deliberately among them: that key is the route discriminator
/// the card button carries, which is why an input request's action id is
/// taken from the button's own submit data.
#[tokio::test]
async fn the_answer_to_an_input_request_resumes_the_same_conversation() {
    let fixture = Fixture::new(config());
    let asking = parked_turn(parked_card());
    let first = rpc("SendMessage", send_params(Some("ctx-round-trip")));
    let value = body_json(rpc_call(&fixture, Some(BEARER), &request(&first), &asking).await).await;
    let requested = &value["result"]["task"]["status"]["message"]["parts"][1]["data"];
    let field_ids: Vec<&str> = requested["fields"]
        .as_array()
        .map(|fields| {
            fields
                .iter()
                .filter_map(|field| field["id"].as_str())
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(field_ids, vec!["plan", "seats", "trial"]);
    let action_id = requested["actions"][0]["id"].as_str().unwrap_or_default();

    // Answer it: one `data` part, keyed by the ids just received.
    let answer = json!({"plan": "pro", "seats": 3, "trial": true, "action": action_id});
    let resuming = FakeRunner::replying(vec![Activity::text("Pro it is.")]);
    let second = rpc(
        "SendMessage",
        json!({"message": {"messageId": "m-answer", "role": "ROLE_USER",
                           "contextId": "ctx-round-trip",
                           "parts": [{"data": answer.clone(),
                                      "mediaType": INPUT_REQUEST_MEDIA_TYPE}]}}),
    );
    let value =
        body_json(rpc_call(&fixture, Some(BEARER), &request(&second), &resuming).await).await;
    assert_eq!(
        value["result"]["message"]["parts"],
        json!([{"text": "Pro it is."}]),
        "the resumed turn completed: {value}"
    );

    let calls = resuming.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].0, "a2a:c1:ctx-round-trip",
        "the answer resumes the conversation the task named"
    );
    assert_eq!(
        calls[0].2,
        json!({"metadata": answer}),
        "the submit shape a resumed card node reads its answers from"
    );
}

/// **A sentence must not cost the caller its answer, on this surface either.**
/// A text part beat a data part outright until 2026-09-24, so a caller that
/// filled in the input request AND said something about it had its fields
/// discarded with nothing reported anywhere — the same silent drop the MCP
/// `answer` argument exists to remove (contract §9.4). The commonest sender of
/// both is a model politely writing a line beside the form it just filled in.
#[tokio::test]
async fn a_text_part_beside_a_data_part_submits_both() {
    let fixture = Fixture::new(config());
    let answer = json!({"plan": "pro", "seats": 3, "action": "confirm"});
    let resuming = FakeRunner::replying(vec![Activity::text("Pro it is.")]);
    let body = rpc(
        "SendMessage",
        json!({"message": {"messageId": "m-both", "role": "ROLE_USER",
                           "contextId": "ctx-both",
                           "parts": [{"text": "sure, here you go"},
                                     {"data": answer.clone(),
                                      "mediaType": INPUT_REQUEST_MEDIA_TYPE}]}}),
    );
    let value = body_json(rpc_call(&fixture, Some(BEARER), &request(&body), &resuming).await).await;
    assert_eq!(
        value["result"]["message"]["parts"],
        json!([{"text": "Pro it is."}]),
        "the resumed turn completed: {value}"
    );

    let calls = resuming.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "a2a:c1:ctx-both");
    assert_eq!(
        calls[0].2,
        json!({"text": "sure, here you go", "metadata": answer}),
        "both parts reach the turn: the fields under `metadata`, the sentence beside them"
    );
}

/// Everything that is NOT the both-parts case keeps the payload it produced
/// before the rule changed. A non-object data part in particular is still
/// only a fallback for a message carrying no text at all — it is not an
/// answer, so it must not start riding alongside one.
#[tokio::test]
async fn every_other_part_combination_keeps_its_payload() {
    let fixture = Fixture::new(config());
    let cases = [
        (
            json!([{"text": "one"}, {"text": "two"}]),
            json!({"text": "one\ntwo"}),
        ),
        (
            json!([{"data": {"action": "confirm"}}]),
            json!({"metadata": {"action": "confirm"}}),
        ),
        (
            json!([{"data": "not an object"}]),
            json!({"text": "\"not an object\""}),
        ),
        (
            json!([{"text": "hello"}, {"data": "not an object"}]),
            json!({"text": "hello"}),
        ),
        (
            json!([{"text": "hello"}, {"data": {}}]),
            json!({"text": "hello"}),
        ),
    ];
    for (parts, expected) in cases {
        let runner = FakeRunner::replying(vec![Activity::text("ok")]);
        let body = rpc(
            "SendMessage",
            json!({"message": {"messageId": "m-shape", "role": "ROLE_USER",
                               "contextId": "ctx-shape", "parts": parts}}),
        );
        let _ = rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await;
        let calls = runner.calls();
        assert_eq!(calls.len(), 1, "{parts}");
        assert_eq!(calls[0].2, expected, "{parts}");
    }
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

/// Both bindings, not only the JSON-RPC one: the HTTP+JSON `SendMessage`
/// answers a parked turn with the same `Task`.
#[tokio::test]
async fn rest_send_answers_a_parked_turn_with_a_task() {
    let fixture = Fixture::new(config());
    let runner = parked_turn(parked_card());
    let body = send_params(Some("rest-parked")).to_string().into_bytes();
    let response = rest_call(&fixture, Some(BEARER), &request(&body), &runner).await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = body_json(response).await;
    assert!(value.get("message").is_none(), "{value}");
    assert_eq!(value["task"]["id"], "rest-parked");
    assert_eq!(
        value["task"]["status"]["state"],
        "TASK_STATE_INPUT_REQUIRED"
    );
    assert_eq!(
        value["task"]["status"]["message"]["parts"][1]["mediaType"],
        INPUT_REQUEST_MEDIA_TYPE
    );
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

// ---------------------------------------------------------------------------
// Artifacts (A2A design §7: `artifact/result` -> structured Flow/Worker output)
// ---------------------------------------------------------------------------

/// A component output a flow produced. The shared reply shaper stringifies
/// this into a text part, which is the prose an agent caller used to have to
/// parse.
fn structured_reply() -> Activity {
    Activity::custom(
        "response",
        json!({"result": {"structured_content": {"order_id": "A-1", "total": 42}}}),
    )
}

async fn send_structured(fixture: &Fixture, runner: &dyn TurnRunner) -> Value {
    let body = rpc("SendMessage", send_params(Some("ctx-art")));
    let response = rpc_call(fixture, Some(BEARER), &request(&body), runner).await;
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await
}

/// The gap this closes: the object the flow produced now travels as an
/// artifact a caller can read, instead of only as the JSON string the shaper
/// made of it.
#[tokio::test]
async fn a_turn_with_a_structured_output_answers_with_a_completed_task_carrying_it() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![structured_reply()]);
    let value = send_structured(&fixture, &runner).await;
    let task = &value["result"]["task"];
    assert!(!task.is_null(), "expected a task: {value}");
    assert_eq!(task["status"]["state"], "TASK_STATE_COMPLETED");
    assert_eq!(task["id"], "ctx-art");
    assert_eq!(task["contextId"], "ctx-art");
    let artifacts = task["artifacts"].as_array().expect("artifacts");
    let structured: Vec<&Value> = artifacts
        .iter()
        .flat_map(|artifact| artifact["parts"].as_array().into_iter().flatten())
        .filter(|part| part.get("data").is_some())
        .collect();
    assert_eq!(structured.len(), 1, "{artifacts:?}");
    assert_eq!(
        structured[0]["data"],
        json!({"order_id": "A-1", "total": 42})
    );
    assert_eq!(structured[0]["mediaType"], "application/json");
    // Every artifact is identified, or a caller cannot refer to one.
    for artifact in artifacts {
        assert!(
            artifact["artifactId"]
                .as_str()
                .is_some_and(|id| !id.is_empty()),
            "{artifact}"
        );
    }
}

/// The ratchet the doc on `artifacts_for` names: `greentic-aw-runtime`'s
/// `a2a_source::task_reply` reads a COMPLETED task's answer out of the
/// artifacts' text parts and ignores `status.message`, reporting a completed
/// task with no text artifact to the model as a failure. A completed task
/// whose prose lived only in `status.message` would turn every successful
/// structured turn into a reported failure on our own caller, silently.
#[tokio::test]
async fn a_completed_task_always_carries_the_turns_prose_as_an_artifact() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![
        Activity::custom("response", json!({"reply": "your order is ready"})),
        structured_reply(),
    ]);
    let value = send_structured(&fixture, &runner).await;
    let task = &value["result"]["task"];
    assert_eq!(task["status"]["state"], "TASK_STATE_COMPLETED");
    let artifact_text: Vec<String> = task["artifacts"]
        .as_array()
        .expect("artifacts")
        .iter()
        .flat_map(|artifact| artifact["parts"].as_array().into_iter().flatten())
        .filter_map(|part| part["text"].as_str().map(str::to_string))
        .collect();
    assert!(
        artifact_text
            .iter()
            .any(|text| text == "your order is ready"),
        "the turn's own words are not readable from the artifacts: {artifact_text:?}"
    );
    // And the prose still rides `status.message`, so nothing a client reads
    // today has moved.
    assert_eq!(
        task["status"]["message"]["parts"][0]["text"],
        "your order is ready"
    );
}

/// A prose-only turn is unchanged: a `Message`, no artifacts, no task.
#[tokio::test]
async fn a_prose_only_turn_answers_with_a_message_and_no_artifact() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![Activity::custom(
        "response",
        json!({"reply": "hi there"}),
    )]);
    let body = rpc("SendMessage", send_params(Some("ctx-plain")));
    let response = rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await;
    let value = body_json(response).await;
    assert!(
        value["result"]["task"].is_null(),
        "a turn with nothing structured must not become a task: {value}"
    );
    let message = &value["result"]["message"];
    assert_eq!(message["parts"], json!([{"text": "hi there"}]));
    assert!(
        message["taskId"].is_null(),
        "no task was created: {message}"
    );
}

/// Contract D10 holds through the new path: the card is not an artifact, not
/// even for a caller that asked for one and so does receive it on the
/// message.
#[tokio::test]
async fn no_artifact_carries_an_adaptive_card() {
    let card = json!({"type": "AdaptiveCard", "version": "1.6",
        "body": [{"type": "TextBlock", "text": "Your receipt"}]});
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![
        Activity::custom(
            "response",
            json!({"outputs": {"result": {"renderedCard": card.clone()}}}),
        ),
        structured_reply(),
    ]);
    let mut params = send_params(Some("ctx-card"));
    params["configuration"] = json!({"acceptedOutputModes": [ADAPTIVE_CARD_MEDIA_TYPE]});
    let body = rpc("SendMessage", params);
    let response = rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await;
    let value = body_json(response).await;
    let task = &value["result"]["task"];
    // The opted-in caller still gets the card, on the message.
    let message_media: Vec<&str> = task["status"]["message"]["parts"]
        .as_array()
        .expect("parts")
        .iter()
        .filter_map(|part| part["mediaType"].as_str())
        .collect();
    assert!(
        message_media.contains(&ADAPTIVE_CARD_MEDIA_TYPE),
        "{message_media:?}"
    );
    // And no artifact carries one, by media type or by content.
    let artifacts = serde_json::to_string(&task["artifacts"]).expect("serialize");
    assert!(!artifacts.contains(ADAPTIVE_CARD_MEDIA_TYPE), "{artifacts}");
    assert!(!artifacts.contains("AdaptiveCard"), "{artifacts}");
}

/// A `structured_content` that is really card transport is not a structured
/// output, so such a turn gains no artifact and stays a `Message`.
#[tokio::test]
async fn a_card_carried_under_the_structured_key_produces_no_task() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![Activity::custom(
        "response",
        json!({"result": {"structured_content": {
            "renderedCard": {"type": "AdaptiveCard", "fallbackText": "Your receipt"}
        }}}),
    )]);
    let body = rpc("SendMessage", send_params(Some("ctx-cardonly")));
    let response = rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await;
    let value = body_json(response).await;
    assert!(value["result"]["task"].is_null(), "{value}");
}

/// D8 is untouched: a parked turn is still a `Task` in input-required whose
/// message carries the question and the private `awaitingInput` flag, and a
/// structured output riding along does not make it look completed.
#[tokio::test]
async fn a_parked_turn_with_a_structured_output_is_still_input_required() {
    let card = json!({"type": "AdaptiveCard", "fallbackText": "Which plan?"});
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![
        structured_reply(),
        Activity::custom(
            "response",
            json!({"status": "pending", "response": {"renderedCard": card}}),
        ),
    ]);
    let body = rpc("SendMessage", send_params(Some("ctx-park")));
    let response = rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await;
    let value = body_json(response).await;
    let task = &value["result"]["task"];
    assert_eq!(task["status"]["state"], "TASK_STATE_INPUT_REQUIRED");
    assert_eq!(task["status"]["message"]["metadata"]["awaitingInput"], true);
    assert_eq!(task["artifacts"].as_array().map(Vec::len), Some(1));
    // The question is not restated as an output of a task that has produced
    // no answer yet: the only artifact is the structured value.
    let parts = task["artifacts"][0]["parts"].as_array().expect("parts");
    assert_eq!(parts.len(), 1);
    assert!(parts[0].get("data").is_some(), "{parts:?}");
}

/// A completed task's message must NOT carry the parked-turn flag, or a
/// client that still reads it would treat an answer as a question.
#[tokio::test]
async fn a_completed_task_never_claims_to_be_awaiting_input() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![structured_reply()]);
    let value = send_structured(&fixture, &runner).await;
    let message = &value["result"]["task"]["status"]["message"];
    assert!(message["metadata"].is_null(), "{message}");
    assert_eq!(message["taskId"], "ctx-art");
}

/// A turn that ended at a failure answers exactly as it did before: the
/// categorized error as a `Message`, and no artifact claiming a result.
///
/// The payload nests the structured value under `outputs` on purpose. The
/// shared shaper reads only a TOP-LEVEL `result.structured_content`, and it
/// reads it in the text fallback chain AHEAD of the flow-error branch \u2014 so a
/// top-level one wins and the turn is not classified as a failure at all.
/// (That precedence is the shaper's and predates this work; it is what a
/// webchat user sees too.) Nesting it keeps the shaper on the flow-error
/// branch while this module still finds the value, which is the only shape
/// that can exercise the suppression.
#[tokio::test]
async fn a_failed_flow_produces_no_artifact_and_stays_a_message() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![Activity::custom(
        "response",
        json!({
            "metadata": {"error_kind": "component", "error_message": "API key is invalid"},
            "outputs": {"result": {"structured_content": {"partial": true}}}
        }),
    )]);
    let body = rpc("SendMessage", send_params(Some("ctx-fail")));
    let response = rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await;
    let value = body_json(response).await;
    assert!(value["result"]["task"].is_null(), "{value}");
    let text = value["result"]["message"]["parts"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(!text.is_empty(), "{value}");
    assert!(
        !text.contains("partial"),
        "a failed turn must not present its partial value as an answer: {text}"
    );
}

/// The REST binding answers with the same shape; it serializes the same
/// `SendMessageResponse`.
#[tokio::test]
async fn the_rest_binding_answers_a_structured_turn_with_the_same_task() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![structured_reply()]);
    let body = serde_json::to_vec(&send_params(Some("ctx-rest"))).expect("body");
    let response = rest_call(&fixture, Some(BEARER), &request(&body), &runner).await;
    assert_eq!(response.status(), StatusCode::OK);
    let value = body_json(response).await;
    assert_eq!(value["task"]["status"]["state"], "TASK_STATE_COMPLETED");
    assert!(
        !value["task"]["artifacts"]
            .as_array()
            .expect("artifacts")
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// Per-request telemetry (A2A design PR-15)
// ---------------------------------------------------------------------------

/// The fields the request's span will carry, as text, for assertions.
fn traced(fixture: &Fixture) -> Vec<(&'static str, String)> {
    fixture
        .trace
        .fields()
        .into_iter()
        .map(|(key, value)| {
            let text = match value {
                FieldValue::Text(text) => text,
                FieldValue::Count(count) => count.to_string(),
            };
            (key, text)
        })
        .collect()
}

fn traced_value(fixture: &Fixture, key: &str) -> Option<String> {
    traced(fixture)
        .into_iter()
        .find(|(name, _)| *name == key)
        .map(|(_, value)| value)
}

/// Every refusal has to be tellable from every other one, or the only thing
/// telemetry proves is that working requests work.
#[tokio::test]
async fn a_bad_bearer_is_traced_as_unauthenticated() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![]);
    let body = rpc("SendMessage", send_params(None));
    let response = rpc_call(&fixture, Some("Bearer wrong"), &request(&body), &runner).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        traced_value(&fixture, "interop.outcome").as_deref(),
        Some("unauthenticated")
    );
    // Nothing ran, so nothing claims a turn duration, and no credential was
    // verified to name.
    assert!(traced_value(&fixture, "interop.turn_duration_ms").is_none());
    assert!(traced_value(&fixture, "interop.credential_id").is_none());
}

#[tokio::test]
async fn a_rate_limited_request_is_traced_as_rate_limited() {
    let fixture = Fixture::new(config());
    // Spend this credential's whole burst directly, so the one request this
    // fixture's trace describes is the refused one.
    while fixture
        .limiter
        .check("c1", crate::interop::limits::TURN_COST)
        .is_ok()
    {}
    let runner = FakeRunner::replying(vec![Activity::text("hi")]);
    let body = rpc("SendMessage", send_params(None));
    let response = rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        traced_value(&fixture, "interop.outcome").as_deref(),
        Some("rate_limited")
    );
    assert!(
        runner.calls().is_empty(),
        "a refused request must run no turn"
    );
}

#[tokio::test]
async fn a_version_this_server_does_not_speak_is_traced_as_such() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![]);
    let body = rpc("SendMessage", send_params(None));
    let req = A2aRequest {
        version_header: Some("2.0"),
        query: None,
        if_none_match: None,
        body: &body,
    };
    let _ = rpc_call(&fixture, Some(BEARER), &req, &runner).await;
    assert_eq!(
        traced_value(&fixture, "interop.outcome").as_deref(),
        Some("version_unsupported")
    );
    assert_eq!(
        traced_value(&fixture, "interop.rpc_error_code").as_deref(),
        Some("-32009")
    );
}

#[tokio::test]
async fn a_turn_that_could_not_run_is_traced_apart_from_one_that_ran_and_failed() {
    let fixture = Fixture::new(config());
    let body = rpc("SendMessage", send_params(None));
    let response = rpc_call(&fixture, Some(BEARER), &request(&body), &FailingRunner).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        traced_value(&fixture, "interop.outcome").as_deref(),
        Some("turn_failed")
    );
    assert_eq!(
        traced_value(&fixture, "interop.rpc_error_code").as_deref(),
        Some("-32603")
    );

    // A flow that RAN and ended at a failure is a different fact.
    let ran = Fixture::new(config());
    let runner = FakeRunner::replying(vec![Activity::custom(
        "response",
        json!({"metadata": {"error_kind": "component", "error_message": "API key is invalid"}}),
    )]);
    let _ = rpc_call(&ran, Some(BEARER), &request(&body), &runner).await;
    assert_eq!(
        traced_value(&ran, "interop.outcome").as_deref(),
        Some("flow_failed")
    );
}

#[tokio::test]
async fn an_unknown_method_is_traced_by_its_code_and_never_by_its_name() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![]);
    let body = rpc("DropTables--<script>", json!({}));
    let _ = rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await;
    assert_eq!(
        traced_value(&fixture, "interop.outcome").as_deref(),
        Some("rejected")
    );
    assert_eq!(
        traced_value(&fixture, "interop.rpc_error_code").as_deref(),
        Some("-32601")
    );
    assert!(
        traced_value(&fixture, "interop.method").is_none(),
        "a method this server does not serve must not become a field"
    );
}

/// A successful turn names its outcome, the task state it answered with, the
/// credential that called it and how long the turn took.
#[tokio::test]
async fn a_completed_structured_turn_is_traced_with_its_task_state_and_artifacts() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![structured_reply()]);
    let _ = send_structured(&fixture, &runner).await;
    assert_eq!(
        traced_value(&fixture, "interop.outcome").as_deref(),
        Some("completed")
    );
    assert_eq!(
        traced_value(&fixture, "interop.task_state").as_deref(),
        Some("TASK_STATE_COMPLETED")
    );
    assert_eq!(
        traced_value(&fixture, "interop.artifacts").as_deref(),
        Some("2")
    );
    assert_eq!(
        traced_value(&fixture, "interop.method").as_deref(),
        Some("SendMessage")
    );
    assert_eq!(
        traced_value(&fixture, "interop.credential_id").as_deref(),
        Some("c1")
    );
    assert!(traced_value(&fixture, "interop.turn_duration_ms").is_some());
    assert_eq!(
        traced_value(&fixture, "gt.tenant").as_deref(),
        Some("default")
    );
}

/// A turn that answers with a `Message` names no task state, because no task
/// was created — absent is the fact, not an empty string.
#[tokio::test]
async fn a_message_answer_names_no_task_state() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![Activity::text("hi")]);
    let body = rpc("SendMessage", send_params(None));
    let _ = rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await;
    assert_eq!(
        traced_value(&fixture, "interop.outcome").as_deref(),
        Some("completed")
    );
    assert!(traced_value(&fixture, "interop.task_state").is_none());
}

/// The one rule the whole module rests on: no caller-supplied string reaches
/// a field. Asserted on the fields that ARE emitted, with every
/// caller-controlled input made distinctive — the bearer, the message text,
/// a card-submit answer, the conversation id and the method — and with the
/// worker's own reply content made distinctive too.
#[tokio::test]
async fn no_caller_supplied_string_or_turn_content_reaches_a_field() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![
        Activity::custom("response", json!({"reply": "REPLY-CONTENT-9"})),
        Activity::custom(
            "response",
            json!({"result": {"structured_content": {"secret_field": "STRUCTURED-CONTENT-9"}}}),
        ),
    ]);
    let params = json!({"message": {
        "messageId": "MESSAGE-ID-9",
        "contextId": "CONTEXT-ID-9",
        "role": "ROLE_USER",
        "parts": [
            {"text": "INBOUND-TEXT-9"},
            {"data": {"answer_field": "ANSWER-CONTENT-9"}}
        ]
    }});
    let body = rpc("SendMessage", params);
    let response = rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await;
    assert_eq!(response.status(), StatusCode::OK);
    // The turn really ran and really answered, or this would prove nothing.
    let value = body_json(response).await;
    assert_eq!(
        value["result"]["task"]["status"]["state"],
        "TASK_STATE_COMPLETED"
    );

    let fields = traced(&fixture);
    let wire = fields
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(" ");
    for secret in [
        // The bearer, in both the header spelling and the bare token.
        BEARER,
        "gtw_test-token",
        // Caller-supplied strings.
        "MESSAGE-ID-9",
        "CONTEXT-ID-9",
        "INBOUND-TEXT-9",
        "ANSWER-CONTENT-9",
        // The worker's own words and the tenant's own data.
        "REPLY-CONTENT-9",
        "STRUCTURED-CONTENT-9",
        "secret_field",
    ] {
        assert!(
            !wire.contains(secret),
            "`{secret}` reached a span field: {wire}"
        );
    }
    // And no field BEYOND the closed list, so a field added anywhere between
    // the request and the span is caught even when its value happens not to
    // match a fixture string. `interop.route` and `interop.http_status` are
    // absent because this test drives the HANDLER, as the whole file does;
    // the ingress records those two and neither is caller text.
    let mut keys: Vec<&str> = fields.iter().map(|(key, _)| *key).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "gt.bundle_id",
            "gt.tenant",
            "interop.artifacts",
            "interop.credential_id",
            "interop.duration_ms",
            "interop.method",
            "interop.outcome",
            "interop.surface",
            "interop.task_state",
            "interop.turn_duration_ms",
        ],
        "a field was added to the request span: {wire}"
    );
}
