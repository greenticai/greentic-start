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
}

impl Fixture {
    fn new(config: InteropConfig) -> Self {
        Self {
            config,
            limiter: RateLimiter::default(),
            turns: TurnGate::new(4),
            deployment_id: DeploymentId::new(),
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
