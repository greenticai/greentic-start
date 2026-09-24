//! The `ask` tool's own metering (worker-interop contract §8) and what it
//! says about a parked turn (§9).
//!
//! The A2A binding's tests cover the shared event shape end to end against a
//! stub admin; what is specific here is WHO an MCP caller is. The same tool
//! serves a staged bearer and an OAuth token, and only the first names a
//! credential the designer issued.

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::{AskArgs, McpContext, WorkerMcpServer};
use crate::interop::a2a::rpc::{TurnFailure, TurnRunner};
use crate::interop::config::InteropConfig;
use crate::interop::limits::{DEFAULT_MAX_CONCURRENT_TURNS, RateLimiter, TurnGate};
use crate::interop::metering::testkit::{StubAdmin, unreachable_metering};
use crate::interop::metering::{Meter, TurnMetering};
use greentic_deploy_spec::ids::DeploymentId;
use greentic_runner_host::Activity;
use rmcp::handler::server::wrapper::Parameters;

/// Records every turn and answers with a fixed reply list.
struct FakeRunner {
    replies: Vec<Activity>,
    calls: Mutex<Vec<(String, String, Value)>>,
}

impl FakeRunner {
    fn replying(replies: Vec<Activity>) -> Arc<Self> {
        Arc::new(Self {
            replies,
            calls: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<(String, String, Value)> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

#[async_trait::async_trait]
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

fn dw_agent_reply(text: &str) -> Activity {
    Activity::custom(
        "response",
        json!({
            "reply": text,
            "trail": [],
            "terminated_by": "final",
            "usage": {"tokens_in": 64, "tokens_out": 16, "iterations": 1},
        }),
    )
}

fn config_with(metering: crate::interop::metering::MeteringConfig) -> InteropConfig {
    InteropConfig {
        mcp: true,
        tenant_slug: Some("acme".into()),
        metering: Some(metering),
        ..InteropConfig::default()
    }
}

/// The tenant every staged fixture records against — the one the metering
/// config carries, which is what reaches the wire.
const TENANT: &str = crate::interop::metering::testkit::TEST_TENANT;

fn server(
    meter: &Arc<Meter>,
    config: &InteropConfig,
    caller_key: &str,
    credential_id: Option<&str>,
) -> WorkerMcpServer {
    server_running(
        FakeRunner::replying(vec![dw_agent_reply("the answer")]),
        meter,
        config,
        caller_key,
        credential_id,
    )
}

fn server_running(
    runner: Arc<FakeRunner>,
    meter: &Arc<Meter>,
    config: &InteropConfig,
    caller_key: &str,
    credential_id: Option<&str>,
) -> WorkerMcpServer {
    let deployment_id = DeploymentId::new();
    WorkerMcpServer::new(Arc::new(McpContext {
        runner,
        turns: Arc::new(TurnGate::new(DEFAULT_MAX_CONCURRENT_TURNS)),
        limiter: Arc::new(RateLimiter::default()),
        prepaid: 0.0,
        deployment_id,
        tenant: "default".into(),
        bundle_id: "support-bot".into(),
        caller_key: caller_key.into(),
        credential_id: credential_id.map(str::to_string),
        metering: TurnMetering::for_unit(meter, config, deployment_id, "support-bot"),
        agent_name: "Support Bot".into(),
    }))
}

async fn ask(server: &WorkerMcpServer, message: &str) -> rmcp::model::CallToolResult {
    server
        .ask(Parameters(AskArgs {
            message: Some(message.into()),
            conversation_id: None,
            answer: None,
        }))
        .await
        .expect("the tool answers")
}

/// The whole feature on the MCP binding: the stub admin receives the usage
/// POST **while the caller still gets its answer**.
#[tokio::test]
async fn an_ask_records_usage_while_the_caller_still_gets_its_reply() {
    let stub = StubAdmin::accepting().await;
    let meter = Arc::new(Meter::default());
    let config = config_with(stub.metering());
    let result = ask(
        &server(&meter, &config, "c_01J", Some("c_01J")),
        "how long do refunds take?",
    )
    .await;
    assert_ne!(result.is_error, Some(true), "the turn succeeded");

    assert_eq!(
        stub.wait_for(1).await,
        1,
        "no usage event reached the admin"
    );
    let event = stub.last_body();
    assert_eq!(event["surface"], "mcp");
    assert_eq!(event["tokens_in"], 64);
    assert_eq!(event["credential_id"], "c_01J");
    assert_eq!(event["tenant_slug"], TENANT);
    let wire = event.to_string();
    assert!(!wire.contains("refunds"), "{wire}");
    assert!(!wire.contains("the answer"), "{wire}");
}

/// An OAuth caller's `sub` is minted by the authorization server and is not a
/// credential the designer staged, so the event names none — which is exactly
/// why the admin made the field optional.
#[tokio::test]
async fn an_oauth_caller_names_no_credential() {
    let meter = Arc::new(Meter::inspectable());
    let config = config_with(unreachable_metering());
    let _ = ask(&server(&meter, &config, "u-oauth-sub", None), "hello").await;
    let queued = meter.drain();
    assert_eq!(queued.len(), 1);
    assert!(queued[0].event.credential_id.is_none());
    assert_eq!(queued[0].event.surface, "mcp");
}

#[tokio::test]
async fn a_unit_with_no_metering_block_emits_nothing() {
    let meter = Arc::new(Meter::inspectable());
    let config = InteropConfig {
        mcp: true,
        ..InteropConfig::default()
    };
    let _ = ask(&server(&meter, &config, "c_01J", Some("c_01J")), "hello").await;
    assert!(meter.drain().is_empty());
}

/// An `ask` refused before the turn ran spent nothing.
#[tokio::test]
async fn an_empty_message_is_refused_and_records_nothing() {
    let meter = Arc::new(Meter::inspectable());
    let config = config_with(unreachable_metering());
    let refused = server(&meter, &config, "c_01J", Some("c_01J"))
        .ask(Parameters(AskArgs {
            message: Some("   ".into()),
            conversation_id: None,
            answer: None,
        }))
        .await;
    assert!(refused.is_err());
    assert!(meter.drain().is_empty());
}

// ---------------------------------------------------------------------------
// Asking the caller for more input (worker-interop contract §9)
// ---------------------------------------------------------------------------

/// An `InteropConfig` with no metering, for the §9 tests — what a parked
/// turn REPORTS is independent of whether the unit records usage.
fn plain_config() -> InteropConfig {
    InteropConfig {
        mcp: true,
        ..InteropConfig::default()
    }
}

fn parked(card: Value) -> Arc<FakeRunner> {
    FakeRunner::replying(vec![Activity::custom(
        "response",
        json!({"status": "pending", "response": {"renderedCard": card}}),
    )])
}

/// **D10 and D11 on MCP.** An MCP caller has no `acceptedOutputModes`, so it
/// can never opt in to an Adaptive Card and never receives one. What it gets
/// instead is the question it can actually answer: the structured input
/// request, plus an explicit awaiting-input flag.
#[tokio::test]
async fn a_parked_turn_returns_the_input_request_and_no_card() {
    let meter = Arc::new(Meter::inspectable());
    let config = plain_config();
    let card = json!({
        "type": "AdaptiveCard", "fallbackText": "Which plan should I set up?",
        "body": [
            {"type": "Input.ChoiceSet", "id": "plan", "label": "Plan",
             "isRequired": true,
             "choices": [{"title": "Pro", "value": "pro"}]},
            {"type": "Input.Number", "id": "seats", "label": "Seats", "min": 1, "max": 100}
        ],
        "actions": [{"type": "Action.Submit", "title": "Confirm",
                     "data": {"action": "confirm"}}]
    });
    let result = ask(
        &server_running(
            parked(card.clone()),
            &meter,
            &config,
            "c_01J",
            Some("c_01J"),
        ),
        "set me up",
    )
    .await;

    let structured = result.structured_content.clone().unwrap_or(Value::Null);
    assert_eq!(structured["awaiting_input"], json!(true));
    assert_eq!(
        structured["input_request"],
        json!({
            "prompt": "Which plan should I set up?",
            "fields": [
                {"id": "plan", "label": "Plan", "type": "choice", "required": true,
                 "multiSelect": false, "choices": [{"value": "pro", "label": "Pro"}]},
                {"id": "seats", "label": "Seats", "type": "number", "required": false,
                 "min": 1, "max": 100}
            ],
            "actions": [{"id": "confirm", "label": "Confirm"}]
        })
    );
    assert!(
        structured.get("cards").is_none(),
        "the card is gone from this surface: {structured}"
    );
    let wire = structured.to_string();
    assert!(
        !wire.contains("AdaptiveCard") && !wire.contains("Input.ChoiceSet"),
        "no part of the card may travel: {wire}"
    );
    // The prose question still reaches a client that reads only text.
    let text = serde_json::to_value(&result.content)
        .map(|content| content.to_string())
        .unwrap_or_default();
    assert!(text.contains("Which plan should I set up?"), "{text}");
}

/// `awaiting_input` is present on every outcome, true or false: a flag that
/// exists only when set cannot be told apart from a server that omits it.
#[tokio::test]
async fn a_completed_turn_says_it_is_not_waiting_and_carries_no_input_request() {
    let meter = Arc::new(Meter::inspectable());
    let config = plain_config();
    let card = json!({"type": "AdaptiveCard", "fallbackText": "Your receipt"});
    let runner = FakeRunner::replying(vec![Activity::custom(
        "response",
        json!({"outputs": {"result": {"renderedCard": card}}}),
    )]);
    let result = ask(
        &server_running(runner, &meter, &config, "c_01J", Some("c_01J")),
        "receipt please",
    )
    .await;
    let structured = result.structured_content.clone().unwrap_or(Value::Null);
    assert_eq!(structured["awaiting_input"], json!(false));
    assert!(structured.get("input_request").is_none(), "{structured}");
    assert!(structured.get("cards").is_none(), "{structured}");
    assert!(structured["conversation_id"].is_string(), "{structured}");
}

/// A flow that FAILED is an error, not a question: `isError` stays the
/// signal, and nothing invites the caller to answer a dead flow.
#[tokio::test]
async fn a_flow_error_is_an_error_and_not_a_question() {
    let meter = Arc::new(Meter::inspectable());
    let config = plain_config();
    let runner = FakeRunner::replying(vec![Activity::custom(
        "response",
        json!({"metadata": {"error_kind": "component", "error_message": "API key is invalid"}}),
    )]);
    let result = ask(
        &server_running(runner, &meter, &config, "c_01J", Some("c_01J")),
        "do the thing",
    )
    .await;
    assert_eq!(result.is_error, Some(true));
    let structured = result.structured_content.clone().unwrap_or(Value::Null);
    assert_eq!(structured["awaiting_input"], json!(false));
    assert!(structured.get("input_request").is_none(), "{structured}");
}

// ---------------------------------------------------------------------------
// Answering one (worker-interop contract D12 / §9.4)
// ---------------------------------------------------------------------------

/// The card the §9.4 tests park on: two named inputs and one submit button.
fn plan_card() -> Value {
    json!({
        "type": "AdaptiveCard", "fallbackText": "Which plan should I set up?",
        "body": [
            {"type": "Input.ChoiceSet", "id": "plan", "label": "Plan",
             "isRequired": true,
             "choices": [{"title": "Pro", "value": "pro"}]},
            {"type": "Input.Number", "id": "seats", "label": "Seats", "min": 1, "max": 100}
        ],
        "actions": [{"type": "Action.Submit", "title": "Confirm",
                     "data": {"action": "confirm"}}]
    })
}

/// Park a turn, then hand back what it asked for: the conversation id and the
/// ids of the fields and the submit action.
async fn park_and_read_request(
    meter: &Arc<Meter>,
    config: &InteropConfig,
) -> (String, Vec<String>, String) {
    let asking = server_running(parked(plan_card()), meter, config, "c_01J", Some("c_01J"));
    let structured = ask(&asking, "set me up")
        .await
        .structured_content
        .clone()
        .unwrap_or(Value::Null);
    assert_eq!(structured["awaiting_input"], json!(true), "{structured}");
    let conversation = structured["conversation_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let request = &structured["input_request"];
    let fields = request["fields"]
        .as_array()
        .map(|fields| {
            fields
                .iter()
                .filter_map(|field| field["id"].as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let action = request["actions"][0]["id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    (conversation, fields, action)
}

/// Call `ask` with an explicit argument set, returning the tool's own result.
async fn ask_with(
    server: &WorkerMcpServer,
    message: Option<&str>,
    conversation_id: Option<&str>,
    answer: Option<&Value>,
) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
    server
        .ask(Parameters(AskArgs {
            message: message.map(str::to_string),
            conversation_id: conversation_id.map(str::to_string),
            answer: answer.and_then(|answer| answer.as_object().cloned()),
        }))
        .await
}

/// **The round trip on MCP.** The field ids the worker named in
/// `input_request` come back under `answer`, and the turn that reaches the
/// runner is the submit shape, on the SAME conversation.
///
/// `{"metadata": …}` is asserted as a literal rather than through the builder
/// so this test and the agent-to-agent one
/// (`a2a::rpc_tests::the_answer_to_an_input_request_resumes_the_same_conversation`)
/// pin the same bytes independently: the point of D12 is that the two
/// surfaces submit identically, which a shared helper compared with itself
/// could not show.
#[tokio::test]
async fn an_answer_alone_submits_the_fields_on_the_same_conversation() {
    let meter = Arc::new(Meter::inspectable());
    let config = plain_config();
    let (conversation, fields, action) = park_and_read_request(&meter, &config).await;
    assert_eq!(fields, vec!["plan".to_string(), "seats".to_string()]);

    let resuming = FakeRunner::replying(vec![Activity::text("Pro it is.")]);
    let server = server_running(
        Arc::clone(&resuming),
        &meter,
        &config,
        "c_01J",
        Some("c_01J"),
    );
    let answer = json!({"plan": "pro", "seats": 3, "action": action});
    let result = ask_with(&server, None, Some(&conversation), Some(&answer))
        .await
        .expect("the tool answers");
    assert_ne!(result.is_error, Some(true), "the resumed turn completed");

    let calls = resuming.calls();
    assert_eq!(calls.len(), 1, "the answer ran exactly one turn");
    assert_eq!(
        calls[0].0,
        format!("mcp:c_01J:{conversation}"),
        "the answer resumes the conversation the input request named"
    );
    assert_eq!(
        calls[0].2,
        json!({"metadata": answer}),
        "the submit shape a resumed card node reads its answers from"
    );
}

/// `answer` and `message` are not alternatives: both travel, the answer under
/// `metadata` and the sentence as the turn's text.
#[tokio::test]
async fn an_answer_and_a_message_both_reach_the_turn() {
    let meter = Arc::new(Meter::inspectable());
    let config = plain_config();
    let runner = FakeRunner::replying(vec![Activity::text("done")]);
    let server = server_running(Arc::clone(&runner), &meter, &config, "c_01J", Some("c_01J"));
    let answer = json!({"plan": "pro", "action": "confirm"});
    let _ = ask_with(
        &server,
        Some("  and please bill it annually  "),
        Some("conv-both"),
        Some(&answer),
    )
    .await
    .expect("the tool answers");

    let calls = runner.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].2,
        json!({"text": "and please bill it annually", "metadata": answer}),
        "the sentence must not cost the caller its answer"
    );
}

/// A field id the parked card never declared is PASSED THROUGH, not refused.
/// This server does not hold that card, and a wrong id already fails the way
/// a wrong id fails from webchat — the flow does not route. Refusing here
/// would be a second, weaker copy of the runner's own check and would turn
/// valid submits into tool errors.
#[tokio::test]
async fn an_unknown_field_id_is_passed_through_not_refused() {
    let meter = Arc::new(Meter::inspectable());
    let config = plain_config();
    let runner = FakeRunner::replying(vec![Activity::text("ok")]);
    let server = server_running(Arc::clone(&runner), &meter, &config, "c_01J", Some("c_01J"));
    let answer = json!({"plan": "pro", "no_such_field": "whatever"});
    let result = ask_with(&server, None, Some("conv-unknown"), Some(&answer))
        .await
        .expect("the tool answers");
    assert_ne!(result.is_error, Some(true), "an unknown id is not an error");

    let calls = runner.calls();
    assert_eq!(calls.len(), 1, "the turn still ran");
    assert_eq!(calls[0].2, json!({"metadata": answer}));
}

/// An answer is arbitrary JSON, because a card input can be. Nested objects
/// and arrays reach the runner intact rather than being flattened or
/// stringified on the way.
#[tokio::test]
async fn a_nested_or_array_answer_value_survives() {
    let meter = Arc::new(Meter::inspectable());
    let config = plain_config();
    let runner = FakeRunner::replying(vec![Activity::text("ok")]);
    let server = server_running(Arc::clone(&runner), &meter, &config, "c_01J", Some("c_01J"));
    let answer = json!({
        "seats": [1, 2, 3],
        "contact": {"emails": ["a@example.com", "b@example.com"], "tier": {"level": 2}},
        "trial": true,
        "note": null,
    });
    let _ = ask_with(&server, None, Some("conv-nested"), Some(&answer))
        .await
        .expect("the tool answers");

    let calls = runner.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].2, json!({"metadata": answer}));
    assert_eq!(
        calls[0].2["metadata"]["contact"]["tier"]["level"],
        json!(2),
        "a nested value is not flattened"
    );
}

/// Neither field present is the same refusal as before, and an EMPTY `answer`
/// object submits nothing, so it counts as absent rather than as a submit of
/// zero fields. Both are refused before the turn gate, so nothing runs and
/// nothing is metered.
#[tokio::test]
async fn neither_a_message_nor_an_answer_is_still_refused() {
    let meter = Arc::new(Meter::inspectable());
    let config = config_with(unreachable_metering());
    let runner = FakeRunner::replying(vec![Activity::text("unreachable")]);
    let server = server_running(Arc::clone(&runner), &meter, &config, "c_01J", Some("c_01J"));

    let empty = json!({});
    for (message, answer) in [
        (None, None),
        (Some("   "), None),
        (None, Some(&empty)),
        (Some("  "), Some(&empty)),
    ] {
        let refused = ask_with(&server, message, None, answer).await;
        assert!(refused.is_err(), "{message:?} / {answer:?} must be refused");
    }
    assert!(runner.calls().is_empty(), "a refused call runs nothing");
    assert!(meter.drain().is_empty(), "a refused call records nothing");
}

/// The tool's own schema and description are the ONLY instruction an MCP
/// client ever reads, so they are what makes D12 usable: `answer` has to be
/// advertised, optional, and explained — including the rule that it never
/// carries a credential.
#[test]
fn the_tool_schema_advertises_an_optional_answer_object() {
    let tools = WorkerMcpServer::tool_router_ask().list_all();
    let tool = tools
        .iter()
        .find(|tool| tool.name == "ask")
        .expect("the ask tool");
    let schema = Value::Object(tool.input_schema.as_ref().clone());
    let answer = &schema["properties"]["answer"];
    assert!(!answer.is_null(), "`answer` is not advertised: {schema}");
    let rendered = answer.to_string();
    assert!(
        rendered.contains("object"),
        "`answer` must advertise an object: {rendered}"
    );
    let required: Vec<String> = schema["required"]
        .as_array()
        .map(|names| {
            names
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !required.iter().any(|name| name == "answer"),
        "`answer` is optional: {required:?}"
    );
    assert!(
        !required.iter().any(|name| name == "message"),
        "an answer alone is a valid submit, so `message` is optional too: {required:?}"
    );

    let description = tool.description.clone().unwrap_or_default().to_string();
    assert!(
        description.contains("input_request") && description.contains("answer"),
        "the description must tell a model when to fill `answer`: {description}"
    );
    assert!(
        description.contains("credential"),
        "the description must say an answer never carries a credential: {description}"
    );
}

/// `/mcp` is the one POST on this ingress that `rmcp` reads the body of
/// itself, so it is the one that does not go through
/// `revision_serve::read_body_limited`. `rmcp`'s own default is 4 MiB —
/// four times what every sibling surface accepts — and `ask` now takes an
/// arbitrary JSON object, so the two have to be the same number.
#[test]
fn the_mcp_transport_accepts_no_larger_a_body_than_the_rest_of_the_ingress() {
    assert_eq!(
        super::mcp_config().max_request_body_bytes,
        crate::revision_serve::MAX_BODY_BYTES,
        "the MCP body cap must be the ingress body cap"
    );
}
