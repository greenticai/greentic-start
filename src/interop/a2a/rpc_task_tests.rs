//! `GetTask` / `CancelTask` against the tasks `SendMessage` recorded.

use super::*;

const OTHER_TOKEN: &str = "gtw_other-token";
const OTHER_BEARER: &str = "Bearer gtw_other-token";

fn two_credentials() -> InteropConfig {
    let mut config = config();
    config.credentials.push(Credential {
        id: "c2".into(),
        sha256: Sha256::digest(OTHER_TOKEN.as_bytes()).into(),
        expires_at_ms: None,
    });
    config
}

async fn call(fixture: &Fixture, bearer: &str, method: &str, params: Value) -> Value {
    let runner = FakeRunner::replying(vec![]);
    let body = rpc(method, params);
    body_json(rpc_call(fixture, Some(bearer), &request(&body), &runner).await).await
}

#[tokio::test]
async fn get_task_answers_the_parked_task_send_message_returned() {
    let fixture = Fixture::new(config());
    let runner = parked_turn(parked_card());
    let body = rpc("SendMessage", send_params(Some("ctx-parked")));
    let sent = body_json(rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await).await;
    let sent_task = sent["result"]["task"].clone();
    assert_eq!(sent_task["status"]["state"], "TASK_STATE_INPUT_REQUIRED");

    let got = call(&fixture, BEARER, "GetTask", json!({"id": "ctx-parked"})).await;
    // `GetTask` answers the bare `Task`, the one `SendMessage` wrapped.
    assert_eq!(got["result"], sent_task, "{got}");
    assert_eq!(runner.calls().len(), 1, "a poll runs no turn");
}

#[tokio::test]
async fn get_task_answers_a_completed_task_with_its_artifacts() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![structured_reply()]);
    let sent = send_structured(&fixture, &runner).await;
    let got = call(&fixture, BEARER, "GetTask", json!({"id": "ctx-art"})).await;
    assert_eq!(got["result"]["status"]["state"], "TASK_STATE_COMPLETED");
    assert_eq!(got["result"], sent["result"]["task"]);
    assert!(
        !got["result"]["artifacts"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
}

#[tokio::test]
async fn a_message_answer_creates_no_task() {
    let fixture = Fixture::new(config());
    let runner = FakeRunner::replying(vec![Activity::text("hi")]);
    let body = rpc("SendMessage", send_params(Some("ctx-msg")));
    let sent = body_json(rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await).await;
    assert!(sent["result"]["message"].is_object(), "{sent}");
    let got = call(&fixture, BEARER, "GetTask", json!({"id": "ctx-msg"})).await;
    assert_eq!(got["error"]["code"], -32001, "{got}");
}

#[tokio::test]
async fn another_credential_cannot_read_or_probe_the_task() {
    let fixture = Fixture::new(two_credentials());
    let runner = parked_turn(parked_card());
    let body = rpc("SendMessage", send_params(Some("ctx-mine")));
    let _ = rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await;

    // Even naming the owner's tenant in the request changes nothing.
    let got = call(
        &fixture,
        OTHER_BEARER,
        "GetTask",
        json!({"id": "ctx-mine", "tenant": "default"}),
    )
    .await;
    assert_eq!(got["error"]["code"], -32001, "{got}");
    assert!(got.get("result").is_none());
    let cancel = call(
        &fixture,
        OTHER_BEARER,
        "CancelTask",
        json!({"id": "ctx-mine"}),
    )
    .await;
    assert_eq!(cancel["error"]["code"], -32001, "not -32002: {cancel}");

    let owner = call(&fixture, BEARER, "GetTask", json!({"id": "ctx-mine"})).await;
    assert_eq!(owner["result"]["id"], "ctx-mine");
}

#[tokio::test]
async fn a_later_turn_in_the_conversation_replaces_the_snapshot() {
    let fixture = Fixture::new(config());
    let body = rpc("SendMessage", send_params(Some("ctx-flow")));
    let asking = parked_turn(parked_card());
    let _ = rpc_call(&fixture, Some(BEARER), &request(&body), &asking).await;
    let done = FakeRunner::replying(vec![structured_reply()]);
    let _ = rpc_call(&fixture, Some(BEARER), &request(&body), &done).await;
    let got = call(&fixture, BEARER, "GetTask", json!({"id": "ctx-flow"})).await;
    assert_eq!(got["result"]["status"]["state"], "TASK_STATE_COMPLETED");
}

#[tokio::test]
async fn cancel_task_on_an_owned_task_is_not_cancelable() {
    let fixture = Fixture::new(config());
    let runner = parked_turn(parked_card());
    let body = rpc("SendMessage", send_params(Some("ctx-c")));
    let _ = rpc_call(&fixture, Some(BEARER), &request(&body), &runner).await;
    let cancel = call(&fixture, BEARER, "CancelTask", json!({"id": "ctx-c"})).await;
    assert_eq!(cancel["error"]["code"], -32002, "{cancel}");
    // Still there afterwards: nothing was canceled.
    let got = call(&fixture, BEARER, "GetTask", json!({"id": "ctx-c"})).await;
    assert_eq!(
        got["result"]["status"]["state"],
        "TASK_STATE_INPUT_REQUIRED"
    );
}

#[tokio::test]
async fn get_task_with_malformed_params_is_invalid_params() {
    let fixture = Fixture::new(config());
    let got = call(&fixture, BEARER, "GetTask", json!({"nope": 1})).await;
    assert_eq!(got["error"]["code"], -32602, "{got}");
}
