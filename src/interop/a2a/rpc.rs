//! The two request bindings: JSON-RPC 2.0 on `/a2a`, and the HTTP+JSON
//! `SendMessage` on `/a2a/message:send`. Both run ONE turn synchronously.
//!
//! A turn that COMPLETED answers with a `Message` (contract D4: no task
//! store). A turn that PARKED answers with a `Task` in `input-required`
//! (contract D8): a `Message` carries no state, so the one fact that matters
//! to a program — *I am waiting for you* — had nowhere protocol-native to
//! live. `Task.id` is the conversation's `contextId` (D9), which is the one
//! thing that can be resumed and needs no store to mint.
//!
//! `GetTask` still answers `-32001` for every id, this one included: see
//! [`handle_jsonrpc`]'s `GET_TASK` arm.

use async_trait::async_trait;
use hyper::{StatusCode, header};
use serde_json::{Value, json};

use greentic_runner_host::Activity;

use super::super::input_request::INPUT_REQUEST_MEDIA_TYPE;
use super::super::limits::{CHEAP_COST, TURN_COST};
use super::super::metering::event::{Surface, usage_from_replies};
use super::super::reply::{ProjectedReply, ReplyItem, project_replies};
use super::types::{
    CancelTaskRequest, GetTaskRequest, JsonRpcError, JsonRpcId, JsonRpcRequest, JsonRpcResponse,
    ListTasksRequest, ListTasksResponse, Message, Part, ProtocolVersion, Role, SendMessageRequest,
    SendMessageResponse, Task, TaskState, TaskStatus, codes, methods,
};
use super::{
    A2aContext, A2aRequest, ADAPTIVE_CARD_MEDIA_TYPE, HttpResponse, json as json_response, plain,
};

/// Longest `contextId` accepted; it becomes part of a session key.
const MAX_CONTEXT_ID_LEN: usize = 256;

/// Why a turn could not run. The detail is logged by the host; the caller
/// sees a generic internal error.
#[derive(Debug)]
pub(crate) struct TurnFailure;

/// What the handlers need from the host to run one turn.
#[async_trait]
pub(crate) trait TurnRunner: Send + Sync {
    /// Run `payload` as one turn in conversation `session_hint`.
    async fn run(
        &self,
        session_hint: &str,
        user: &str,
        payload: &Value,
    ) -> Result<Vec<Activity>, TurnFailure>;
}

/// Bearer check. `Ok(credential id)` or a ready `401`.
///
/// Called by the ingress BEFORE the request body is read, so an
/// unauthenticated peer cannot make this process read a megabyte per request.
/// It needs only the `Authorization` header, so nothing forces the body to be
/// available first — the handlers below take the verified id as a parameter
/// rather than re-deriving it.
///
/// The error is boxed because a `hyper::Response` is ~144 bytes — the same
/// reason `revision_serve::resolve_endpoint_admission` boxes its own.
pub(crate) fn authenticate<'c>(
    ctx: &'c A2aContext<'_>,
    authorization: Option<&str>,
) -> Result<&'c str, Box<HttpResponse>> {
    crate::ingress_auth::verify_bearer(ctx.config, authorization, ctx.now_ms).map_err(|_| {
        let mut response = plain(StatusCode::UNAUTHORIZED, "a valid bearer token is required");
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Bearer realm=\"a2a\""),
        );
        Box::new(response)
    })
}

fn rate_limited(retry_after_secs: u64) -> HttpResponse {
    let mut response = plain(
        StatusCode::TOO_MANY_REQUESTS,
        "too many requests for this credential; wait and retry",
    );
    if let Ok(value) = header::HeaderValue::from_str(&retry_after_secs.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// The requested protocol version: the `A2A-Version` header, else the
/// `A2A-Version` query parameter. `Ok(())` when absent (see below) or
/// Major.Minor-compatible; `Err(requested)` otherwise.
///
/// Absent is ACCEPTED as 1.0. The spec reads an absent version as `0.3`,
/// which this server does not speak; refusing every header-less caller would
/// break plain `curl` and clients that predate the header, for no safety gain.
fn check_version(req: &A2aRequest<'_>) -> Result<(), String> {
    let requested = req.version_header.map(str::to_string).or_else(|| {
        req.query.and_then(|q| {
            q.split('&').find_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                key.eq_ignore_ascii_case("A2A-Version")
                    .then(|| urlencoding::decode(value).map(|v| v.into_owned()).ok())
                    .flatten()
            })
        })
    });
    let Some(requested) = requested else {
        return Ok(());
    };
    match ProtocolVersion::parse(&requested) {
        Some(version) if version == ProtocolVersion::SUPPORTED => Ok(()),
        _ => Err(requested),
    }
}

/// A `SendMessage` refusal before or after the turn, independent of binding.
enum SendError {
    InvalidParams(String),
    ContentTypeNotSupported,
    Busy,
    Internal,
}

/// Run one `SendMessage`, independent of the binding.
async fn send_message(
    ctx: &A2aContext<'_>,
    credential_id: &str,
    request: SendMessageRequest,
    runner: &dyn TurnRunner,
) -> Result<SendMessageResponse, SendError> {
    let wants_card = accepts_adaptive_card(&request);
    let payload = message_payload(&request.message)?;
    let context_id = match request.message.context_id.as_deref() {
        Some(id) => valid_context_id(id)
            .ok_or_else(|| SendError::InvalidParams("invalid contextId".into()))?
            .to_string(),
        None => ulid::Ulid::new().to_string(),
    };
    let session_hint = crate::interop::session_hint("a2a", credential_id, &context_id);
    let user = format!("a2a:{credential_id}");
    let _permit = ctx
        .turns
        .try_acquire(ctx.deployment_id)
        .ok_or(SendError::Busy)?;
    // One event per turn that RAN, recorded whether or not the turn
    // succeeded: a turn that failed after calling the model still spent, and
    // the honest reading of one that failed before is zeros. Everything
    // refused ABOVE this line — a bad bearer, the limiter, invalid params, a
    // full turn gate — ran nothing and records nothing.
    let started = std::time::Instant::now();
    let outcome = runner.run(&session_hint, &user, &payload).await;
    let elapsed = started.elapsed();
    if let Some(metering) = ctx.metering.as_ref() {
        let usage = outcome
            .as_ref()
            .map(|replies| usage_from_replies(replies))
            .unwrap_or_default();
        metering.record(Surface::A2a, Some(credential_id), usage, elapsed);
    }
    let replies = outcome.map_err(|_| SendError::Internal)?;
    let projected = project_replies(&replies, "a2a", ctx.tenant, ctx.bundle_id, &session_hint);
    let awaiting = projected.awaiting_input;
    let mut parts = reply_parts(&projected, wants_card);
    if awaiting {
        // The structured question, beside the prose one the card's fallback
        // text already put in `parts` (contract §9.2).
        parts.push(Part::data(
            projected.input_request(),
            INPUT_REQUEST_MEDIA_TYPE,
        ));
    }
    if parts.is_empty() {
        parts.push(Part::text(""));
    }
    let message = Message {
        message_id: ulid::Ulid::new().to_string(),
        context_id: Some(context_id.clone()),
        // A parked turn's message belongs to the task below; a completed
        // turn's belongs to no task, because none was created.
        task_id: awaiting.then(|| context_id.clone()),
        role: Role::Agent,
        parts,
        // `status.state` is what a third-party client reads (D8). This flag
        // is kept for the Greentic clients that shipped before it and is
        // deliberately not the signal any new reader should use.
        metadata: awaiting.then(|| json!({"awaitingInput": true})),
        extensions: Vec::new(),
        reference_task_ids: Vec::new(),
    };
    if !awaiting {
        return Ok(SendMessageResponse::Message(message));
    }
    Ok(SendMessageResponse::Task(Task {
        // D9: one conversation parks at most one turn, so the conversation
        // names the one thing that can be resumed — and needs no store.
        id: context_id.clone(),
        context_id,
        status: TaskStatus {
            state: TaskState::InputRequired,
            message: Some(message),
            // The same RFC 3339 spelling the usage events use, so one
            // process does not emit two.
            timestamp: Some(crate::interop::metering::event::now_rfc3339()),
        },
        artifacts: Vec::new(),
        history: Vec::new(),
        metadata: None,
    }))
}

/// The turn's own replies as message parts.
///
/// The Adaptive Card rides only when the caller asked for one
/// ([`accepts_adaptive_card`], contract D10). Its plain-text fallback is
/// pushed either way, so a caller that did not ask still reads the question.
fn reply_parts(projected: &ProjectedReply, wants_card: bool) -> Vec<Part> {
    let mut parts = Vec::new();
    for item in &projected.items {
        match item {
            ReplyItem::Text(text) => parts.push(Part::text(text.clone())),
            ReplyItem::Card { card, fallback } => {
                if wants_card {
                    parts.push(Part::data(card.clone(), ADAPTIVE_CARD_MEDIA_TYPE));
                }
                parts.push(Part::text(fallback.clone()));
            }
        }
    }
    parts
}

/// Whether this caller declared it can render an Adaptive Card (D10).
///
/// Both spellings are honoured: the media type this server stamps on the
/// part (`…adaptive+json`) and the bare `…adaptive` the contract names. A
/// caller that opts in with either means the same thing, and refusing one of
/// them would fail by silently withholding the card.
fn accepts_adaptive_card(request: &SendMessageRequest) -> bool {
    let Some(configuration) = request.configuration.as_ref() else {
        return false;
    };
    configuration.accepted_output_modes.iter().any(|mode| {
        let mode = mode.trim();
        mode.eq_ignore_ascii_case(ADAPTIVE_CARD_MEDIA_TYPE)
            || mode.eq_ignore_ascii_case(BARE_ADAPTIVE_CARD_MEDIA_TYPE)
    })
}

/// [`ADAPTIVE_CARD_MEDIA_TYPE`] without the `+json` structured suffix — how
/// the contract and most clients spell it.
const BARE_ADAPTIVE_CARD_MEDIA_TYPE: &str = "application/vnd.microsoft.card.adaptive";

/// The flow payload for an inbound message: its text parts joined, its first
/// object `data` part lifted under `metadata` (an Adaptive Card submit, the
/// way `/workers/invoke` lifts one), or BOTH, else a refusal.
///
/// A text part used to beat a data part outright, and this function returned
/// on the first text it found. That discarded the answer of any caller that
/// filled in an input request AND said something about it — which is the
/// commonest thing a model does — with nothing reported at any layer, the
/// exact silent drop the MCP `answer` argument exists to remove (contract
/// §9.4). Both now travel, through the same builder the MCP surface uses.
///
/// Every other combination keeps the payload it produced before: text alone
/// is `{"text": …}`, an object data part alone is `{"metadata": …}`, a
/// NON-object data part is still only a fallback for a message with no text
/// at all, and no usable part is still a refusal.
fn message_payload(message: &Message) -> Result<Value, SendError> {
    if message.parts.is_empty() {
        return Err(SendError::InvalidParams("message has no parts".into()));
    }
    let texts: Vec<&str> = message
        .parts
        .iter()
        .filter_map(|p| p.text.as_deref())
        .collect();
    let text = (!texts.is_empty()).then(|| texts.join("\n"));
    let data = message.parts.iter().find_map(|p| p.data.as_ref());
    // Only an object is an ANSWER: it is field id → value, the shape a card
    // submit travels in.
    let answer = data.and_then(|data| match data {
        Value::Object(map) if !map.is_empty() => Some(map),
        _ => None,
    });
    match (answer, text) {
        // The same builder the MCP `answer` argument goes through, so the two
        // surfaces cannot submit differently shaped answers.
        (Some(answer), text) => Ok(crate::interop::input_request::answer_payload(
            answer,
            text.as_deref(),
        )),
        (None, Some(text)) => Ok(json!({"text": text})),
        // No text and nothing that reads as an answer: a non-object data part
        // is all that is left to say.
        (None, None) => match data {
            Some(other) => Ok(json!({"text": other.to_string()})),
            None => Err(SendError::ContentTypeNotSupported),
        },
    }
}

fn valid_context_id(id: &str) -> Option<&str> {
    (!id.is_empty() && id.len() <= MAX_CONTEXT_ID_LEN && !id.chars().any(char::is_control))
        .then_some(id)
}

/// `POST /a2a`.
pub(crate) async fn handle_jsonrpc(
    ctx: &A2aContext<'_>,
    req: &A2aRequest<'_>,
    credential_id: &str,
    runner: &dyn TurnRunner,
) -> HttpResponse {
    let value: Value = match serde_json::from_slice(req.body) {
        Ok(value) => value,
        Err(_) => {
            return rpc_error(JsonRpcId::Null, codes::PARSE_ERROR, "parse error", None);
        }
    };
    let request: JsonRpcRequest = match serde_json::from_value::<JsonRpcRequest>(value) {
        Ok(request) if request.jsonrpc == "2.0" => request,
        _ => {
            return rpc_error(
                JsonRpcId::Null,
                codes::INVALID_REQUEST,
                "invalid JSON-RPC 2.0 request",
                None,
            );
        }
    };
    let id = request.id.clone().unwrap_or(JsonRpcId::Null);
    let cost = if request.method == methods::SEND_MESSAGE {
        TURN_COST
    } else {
        CHEAP_COST
    };
    if let Err(retry_after) = ctx.limiter.check(credential_id, cost) {
        return rate_limited(retry_after);
    }
    if let Err(requested) = check_version(req) {
        return rpc_error(
            id,
            codes::VERSION_NOT_SUPPORTED,
            "protocol version not supported",
            Some(
                json!({"requested": requested, "supported": [ProtocolVersion::SUPPORTED.to_string()]}),
            ),
        );
    }
    let params = request.params.unwrap_or(Value::Null);
    match request.method.as_str() {
        methods::SEND_MESSAGE => {
            let parsed: SendMessageRequest = match serde_json::from_value(params) {
                Ok(parsed) => parsed,
                Err(err) => {
                    return rpc_error(
                        id,
                        codes::INVALID_PARAMS,
                        &format!("invalid params: {err}"),
                        None,
                    );
                }
            };
            match send_message(ctx, credential_id, parsed, runner).await {
                Ok(answer) => match serde_json::to_value(answer) {
                    Ok(result) => rpc_ok(id, result),
                    Err(_) => rpc_error(id, codes::INTERNAL_ERROR, "internal error", None),
                },
                Err(SendError::InvalidParams(message)) => {
                    rpc_error(id, codes::INVALID_PARAMS, &message, None)
                }
                Err(SendError::ContentTypeNotSupported) => rpc_error(
                    id,
                    codes::CONTENT_TYPE_NOT_SUPPORTED,
                    "only text and data parts are supported",
                    None,
                ),
                Err(SendError::Busy) => rate_limited(1),
                Err(SendError::Internal) => {
                    rpc_error(id, codes::INTERNAL_ERROR, "the turn failed", None)
                }
            }
        }
        // `-32001` for EVERY id, including one this server minted for a
        // parked turn (D9). Contract §9.3 asks for such an id to resolve by
        // reading the session the turn parked on; that is not reachable from
        // here, and faking it would be worse than refusing:
        //
        // - the only seam to the runtime is `TurnRunner::run`, which runs a
        //   turn — the one thing a poll must not do;
        // - a wait is found by `find_wait_by_scope(ctx, user, scope)` in
        //   greentic-runner-host, where `user` is a digest of
        //   `<hint>::pack=<pack id>` and `scope` is the `ReplyScope` the
        //   PARKING envelope carried. Neither the pack id nor that scope is
        //   known here: the pack comes from dispatching the revision (which
        //   also commits a session pin — a write on a read), and the scope is
        //   built inside the host from the activity it never returns;
        // - `revision_boot` gives each revision its OWN session store, so the
        //   answer also depends on picking the same revision;
        // - and every one of those four derivations fails SILENTLY to "no
        //   wait found", which is this same `-32001`. A poll that answers
        //   "gone" for a conversation that is in fact parked is worse than
        //   one that never claimed to be able to answer.
        //
        // Closing it needs a lookup seam on the runtime side, not a second
        // derivation of the key on this one.
        //
        // The params are still parsed, so a malformed request is told so
        // rather than being reported as a missing task.
        methods::GET_TASK => match serde_json::from_value::<GetTaskRequest>(params) {
            Ok(_) => rpc_error(id, codes::TASK_NOT_FOUND, "task not found", None),
            Err(err) => rpc_error(
                id,
                codes::INVALID_PARAMS,
                &format!("invalid params: {err}"),
                None,
            ),
        },
        methods::CANCEL_TASK => match serde_json::from_value::<CancelTaskRequest>(params) {
            Ok(_) => rpc_error(id, codes::TASK_NOT_FOUND, "task not found", None),
            Err(err) => rpc_error(
                id,
                codes::INVALID_PARAMS,
                &format!("invalid params: {err}"),
                None,
            ),
        },
        methods::LIST_TASKS => {
            // Every field is optional, so an omitted `params` is a valid
            // request for the first page.
            let params = if params.is_null() { json!({}) } else { params };
            match serde_json::from_value::<ListTasksRequest>(params) {
                Ok(_) => match serde_json::to_value(ListTasksResponse::default()) {
                    Ok(result) => rpc_ok(id, result),
                    Err(_) => rpc_error(id, codes::INTERNAL_ERROR, "internal error", None),
                },
                Err(err) => rpc_error(
                    id,
                    codes::INVALID_PARAMS,
                    &format!("invalid params: {err}"),
                    None,
                ),
            }
        }
        methods::SEND_STREAMING_MESSAGE | methods::SUBSCRIBE_TO_TASK => rpc_error(
            id,
            codes::UNSUPPORTED_OPERATION,
            "streaming is not supported",
            None,
        ),
        methods::CREATE_PUSH_CONFIG
        | methods::GET_PUSH_CONFIG
        | methods::LIST_PUSH_CONFIGS
        | methods::DELETE_PUSH_CONFIG => rpc_error(
            id,
            codes::PUSH_NOTIFICATION_NOT_SUPPORTED,
            "push notifications are not supported",
            None,
        ),
        methods::GET_EXTENDED_AGENT_CARD => rpc_error(
            id,
            codes::EXTENDED_AGENT_CARD_NOT_CONFIGURED,
            "no extended agent card is configured",
            None,
        ),
        _ => rpc_error(id, codes::METHOD_NOT_FOUND, "method not found", None),
    }
}

fn rpc_ok(id: JsonRpcId, result: Value) -> HttpResponse {
    rpc_body(&JsonRpcResponse::ok(id, result))
}

fn rpc_error(id: JsonRpcId, code: i64, message: &str, data: Option<Value>) -> HttpResponse {
    rpc_body(&JsonRpcResponse::err(
        id,
        JsonRpcError {
            code,
            message: message.to_string(),
            data,
        },
    ))
}

/// JSON-RPC answers are HTTP 200 whatever the outcome.
fn rpc_body(response: &JsonRpcResponse) -> HttpResponse {
    match serde_json::to_vec(response) {
        Ok(body) => json_response(StatusCode::OK, body),
        Err(_) => plain(StatusCode::INTERNAL_SERVER_ERROR, "serialization failed"),
    }
}

/// `POST /a2a/message:send`. Errors use the AIP-193 shape
/// `{"error":{"code","status","message"}}` with a matching HTTP status.
pub(crate) async fn handle_rest_send(
    ctx: &A2aContext<'_>,
    req: &A2aRequest<'_>,
    credential_id: &str,
    runner: &dyn TurnRunner,
) -> HttpResponse {
    if let Err(retry_after) = ctx.limiter.check(credential_id, TURN_COST) {
        return rate_limited(retry_after);
    }
    if check_version(req).is_err() {
        return rest_error(
            StatusCode::BAD_REQUEST,
            "FAILED_PRECONDITION",
            "protocol version not supported",
        );
    }
    let parsed: SendMessageRequest = match serde_json::from_slice(req.body) {
        Ok(parsed) => parsed,
        Err(err) => {
            return rest_error(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                &format!("invalid SendMessageRequest: {err}"),
            );
        }
    };
    match send_message(ctx, credential_id, parsed, runner).await {
        Ok(answer) => match serde_json::to_vec(&answer) {
            Ok(body) => json_response(StatusCode::OK, body),
            Err(_) => rest_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "internal error",
            ),
        },
        Err(SendError::InvalidParams(message)) => {
            rest_error(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT", &message)
        }
        Err(SendError::ContentTypeNotSupported) => rest_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "INVALID_ARGUMENT",
            "only text and data parts are supported",
        ),
        Err(SendError::Busy) => rate_limited(1),
        Err(SendError::Internal) => rest_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            "the turn failed",
        ),
    }
}

fn rest_error(status: StatusCode, code_name: &str, message: &str) -> HttpResponse {
    let body = json!({"error": {"code": status.as_u16(), "status": code_name, "message": message}});
    json_response(status, body.to_string().into_bytes())
}

#[cfg(test)]
#[path = "rpc_tests.rs"]
mod rpc_tests;
