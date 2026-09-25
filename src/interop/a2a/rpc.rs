//! The two request bindings: JSON-RPC 2.0 on `/a2a`, and the HTTP+JSON
//! `SendMessage` on `/a2a/message:send`. Both run ONE turn synchronously.
//!
//! A turn that PARKED answers with a `Task` in `input-required` (contract
//! D8): a `Message` carries no state, so the one fact that matters to a
//! program — *I am waiting for you* — had nowhere protocol-native to live.
//! `Task.id` is the conversation's `contextId` (D9), which is the one thing
//! that can be resumed and needs no store to mint.
//!
//! A turn that COMPLETED answers with a `Message`, **unless it produced a
//! structured output**, in which case it answers with a `Task` in
//! `TASK_STATE_COMPLETED` whose `artifacts` carry it — see
//! [`send_message`] for why that does not weaken D8, and
//! [`artifacts_for`] for why the prose rides an artifact too.
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
use super::super::telemetry::Outcome;
use super::types::{
    Artifact, CancelTaskRequest, GetTaskRequest, JsonRpcError, JsonRpcId, JsonRpcRequest,
    JsonRpcResponse, ListTasksRequest, ListTasksResponse, Message, Part, ProtocolVersion, Role,
    SendMessageRequest, SendMessageResponse, Task, TaskState, TaskStatus, codes, methods,
};
use super::{
    A2aContext, A2aRequest, ADAPTIVE_CARD_MEDIA_TYPE, HttpResponse, STRUCTURED_OUTPUT_MEDIA_TYPE,
    json as json_response, plain,
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
///
/// Both arms are traced here rather than at the call site: the verified
/// credential ID is what contract §6 means by auditing caller identity, and
/// recording it where it is produced is what stops a new binding forgetting
/// to. The TOKEN is never recorded anywhere — see
/// [`super::super::telemetry`].
pub(crate) fn authenticate<'c>(
    ctx: &'c A2aContext<'_>,
    authorization: Option<&str>,
) -> Result<&'c str, Box<HttpResponse>> {
    let verified = crate::ingress_auth::verify_bearer(ctx.config, authorization, ctx.now_ms)
        .map_err(|_| {
            ctx.trace.outcome(Outcome::Unauthenticated);
            let mut response = plain(StatusCode::UNAUTHORIZED, "a valid bearer token is required");
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                header::HeaderValue::from_static("Bearer realm=\"a2a\""),
            );
            Box::new(response)
        })?;
    ctx.trace.credential(verified);
    Ok(verified)
}

fn rate_limited(ctx: &A2aContext<'_>, outcome: Outcome, retry_after_secs: u64) -> HttpResponse {
    ctx.trace.outcome(outcome);
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
///
/// # Which wire shape a completed turn takes, and why D8 still holds
///
/// Contract D8 says a parked turn answers with a `Task` and a completed one
/// with a `Message`. A2A hangs `artifacts` off a `Task` and nowhere else, so
/// a completed turn that produced a structured output
/// ([`crate::interop::structured_output`]) has to become a `Task` too — in
/// `TASK_STATE_COMPLETED` — or the output has nowhere protocol-native to go
/// and a caller is back to parsing prose. A completed turn with NO structured
/// output is unchanged: still a `Message`.
///
/// That does not weaken what D8 buys a client, because D8's rule is about the
/// SIGNAL, not the container: *`status.state` is the only thing a third-party
/// client acts on*, and a `Message` means there is no state to read because
/// no task was created. Under this change every case still answers that
/// question correctly — parked is `TASK_STATE_INPUT_REQUIRED`, completed is
/// `TASK_STATE_COMPLETED` or a stateless `Message`. `SendMessageResponse` is
/// a proto `oneof`, so a conformant client already has to handle both arms of
/// every response; nothing in A2A licenses reading "I got a `Task`" as "it
/// must be input-required", and a client that did would have been wrong about
/// this server the day it started answering `TASK_STATE_COMPLETED` for any
/// other reason.
///
/// Measured, not assumed, on the client we own: `greentic-aw-runtime`'s
/// `a2a_source::task_reply` branches on `TaskState::progress()` and treats
/// `Completed` as `Done` — and reads a `Done` task's answer out of its
/// ARTIFACTS, ignoring `status.message` entirely. See [`artifacts_for`].
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
    let _permit = ctx.turns.try_acquire(ctx.deployment_id).ok_or_else(|| {
        ctx.trace.outcome(Outcome::Busy);
        SendError::Busy
    })?;
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
    // Traced beside the meter, and separately: the meter records only a turn
    // that RAN, while the span records every request. `interop.duration_ms`
    // is the whole request, so the gap between the two is what the surface
    // itself cost.
    ctx.trace.turn_duration(elapsed);
    let replies = outcome.map_err(|_| {
        ctx.trace.outcome(Outcome::TurnFailed);
        SendError::Internal
    })?;
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
    // A turn that ended at a FAILURE produces no artifact, whatever it left
    // behind on the way: a partial value from a flow that then failed is not
    // a result, and the A2A state for such a turn would be
    // `TASK_STATE_FAILED` — a wire-shape change on the error path that no
    // caller has asked for. Such a turn answers exactly as it does today,
    // with the categorized error as a `Message`.
    let artifacts = if projected.flow_error {
        Vec::new()
    } else {
        artifacts_for(&projected, &parts, !awaiting)
    };
    // A task is created when the turn parked (D8) OR when it has artifacts to
    // hang off one.
    let as_task = awaiting || !artifacts.is_empty();
    let message = Message {
        message_id: ulid::Ulid::new().to_string(),
        context_id: Some(context_id.clone()),
        // The message belongs to the task below when there is one, and to no
        // task otherwise, because none was created.
        task_id: as_task.then(|| context_id.clone()),
        role: Role::Agent,
        parts,
        // `status.state` is what a third-party client reads (D8). This flag
        // is kept for the Greentic clients that shipped before it and is
        // deliberately not the signal any new reader should use. It stays
        // bound to PARKING, never to "this is a task": a completed task must
        // not look like a question.
        metadata: awaiting.then(|| json!({"awaitingInput": true})),
        extensions: Vec::new(),
        reference_task_ids: Vec::new(),
    };
    ctx.trace.artifacts(artifacts.len() as u64);
    if !as_task {
        ctx.trace.outcome(if projected.flow_error {
            Outcome::FlowFailed
        } else {
            Outcome::Completed
        });
        return Ok(SendMessageResponse::Message(message));
    }
    let state = if awaiting {
        TaskState::InputRequired
    } else {
        TaskState::Completed
    };
    ctx.trace.outcome(if awaiting {
        Outcome::InputRequired
    } else {
        Outcome::Completed
    });
    ctx.trace.task_state(state.wire_name());
    Ok(SendMessageResponse::Task(Task {
        // D9: one conversation parks at most one turn, so the conversation
        // names the one thing that can be resumed — and needs no store. A
        // completed task is keyed the same way for the same reason: the
        // stateless MVP (D4) has nothing else to mint an id from, and
        // `GetTask` refuses every id including this one either way.
        id: context_id.clone(),
        context_id,
        status: TaskStatus {
            state,
            message: Some(message),
            // The same RFC 3339 spelling the usage events use, so one
            // process does not emit two.
            timestamp: Some(crate::interop::metering::event::now_rfc3339()),
        },
        artifacts,
        history: Vec::new(),
        metadata: None,
    }))
}

/// The artifacts one turn's answer carries.
///
/// Empty when the turn produced no structured output, which is what keeps a
/// prose-only turn answering with a `Message` exactly as before.
///
/// When it did produce one, the list is:
///
/// 1. **the turn's own prose**, as the `text` parts of `message_parts`
///    verbatim — only on a COMPLETED turn, and
/// 2. **one artifact per structured output**, each a single `data` part of
///    [`STRUCTURED_OUTPUT_MEDIA_TYPE`], named after the producing node when
///    the runtime named one.
///
/// Entry 1 is skipped on a parked turn because there the prose is the
/// QUESTION, which every client reads from `status.message` — repeating it as
/// an output of a task that has produced no answer yet would say the opposite
/// of what the state says.
///
/// Entry 1 is not decoration and not a re-shaping: it is the turn's words
/// byte-for-byte, and without it a completed task has no readable answer at
/// all on the client Greentic itself ships. `greentic-aw-runtime`'s
/// `a2a_source::task_reply` builds a `Done` task's reply from
/// `task.artifacts[].parts[].text` ONLY — `status.message` is read into a
/// local that the `Done` branch never uses — and reports a completed task
/// with no text part among its artifacts to the model as a FAILURE
/// (`"completed a task with no text artifact"`). So a completed `Task` whose
/// prose lived only in `status.message` would turn every successful
/// structured turn into a reported failure on our own caller, silently.
/// `rpc_tests::a_completed_task_always_carries_the_turns_prose_as_an_artifact`
/// is the ratchet.
///
/// Only `text` parts are copied, never the message's `data` parts. That is
/// what keeps contract D10 true here: an Adaptive Card rides `status.message`
/// only, and only for a caller that declared it accepts one, so no artifact
/// can carry one into a caller that did not ask.
///
/// # What our own client does with the rest
///
/// The paragraph above describes `task_reply` as reading text parts ONLY, and
/// that stopped being the whole story in greentic-runner#802: it now appends
/// each `application/json` `data` part as compact JSON after the prose, so the
/// object a flow produced reaches the calling model instead of being dropped.
/// Three consequences for anything changed here:
///
/// - the prose artifact is still REQUIRED, for the reason above — a task with
///   neither prose nor a structured part is still reported as a failure;
/// - the media type is matched EXACTLY on that side, so stamping a structured
///   part with a vendor `+json` type would silently stop it reaching a caller;
/// - the client's pin on this shape is `a_structured_answer_reaches_the_model_beside_the_prose`,
///   in `greentic-aw-runtime`'s `a2a_source::tests::dispatch`, which
///   hand-writes the wire JSON this function emits. It is in another
///   repository and cannot fail this build, which is why the assertions HERE
///   are made on the serialized value (`mediaType`, `artifactId`) rather than
///   on the structs.
fn artifacts_for(
    projected: &ProjectedReply,
    message_parts: &[Part],
    completed: bool,
) -> Vec<Artifact> {
    if projected.structured.is_empty() {
        return Vec::new();
    }
    let prose: Vec<Part> = if completed {
        message_parts
            .iter()
            .filter(|part| part.text.is_some())
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    let mut artifacts = Vec::with_capacity(projected.structured.len() + 1);
    if !prose.is_empty() {
        artifacts.push(Artifact {
            artifact_id: ulid::Ulid::new().to_string(),
            name: Some(REPLY_ARTIFACT_NAME.to_string()),
            parts: prose,
        });
    }
    for output in &projected.structured {
        artifacts.push(Artifact {
            artifact_id: ulid::Ulid::new().to_string(),
            // The node the runtime named, or nothing. An invented label
            // would be a name a caller can correlate with nothing.
            name: output.node_id.clone(),
            parts: vec![Part::data(
                output.value.clone(),
                STRUCTURED_OUTPUT_MEDIA_TYPE,
            )],
        });
    }
    artifacts
}

/// The name of the artifact carrying the turn's prose.
pub(crate) const REPLY_ARTIFACT_NAME: &str = "reply";

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
            return rpc_error(
                ctx,
                JsonRpcId::Null,
                codes::PARSE_ERROR,
                "parse error",
                None,
            );
        }
    };
    let request: JsonRpcRequest = match serde_json::from_value::<JsonRpcRequest>(value) {
        Ok(request) if request.jsonrpc == "2.0" => request,
        _ => {
            return rpc_error(
                ctx,
                JsonRpcId::Null,
                codes::INVALID_REQUEST,
                "invalid JSON-RPC 2.0 request",
                None,
            );
        }
    };
    let id = request.id.clone().unwrap_or(JsonRpcId::Null);
    // The caller's method name is NOT recorded; the matching one from
    // `methods` is. An unrecognised method traces as `-32601` with no
    // `interop.method` at all, which is the difference between a bounded
    // token and an unbounded caller-supplied string in a trace backend.
    if let Some(known) = methods::known(&request.method) {
        ctx.trace.method(known);
    }
    let cost = if request.method == methods::SEND_MESSAGE {
        TURN_COST
    } else {
        CHEAP_COST
    };
    if let Err(retry_after) = ctx.limiter.check(credential_id, cost) {
        return rate_limited(ctx, Outcome::RateLimited, retry_after);
    }
    if let Err(requested) = check_version(req) {
        ctx.trace.outcome(Outcome::VersionUnsupported);
        return rpc_error(
            ctx,
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
                        ctx,
                        id,
                        codes::INVALID_PARAMS,
                        &format!("invalid params: {err}"),
                        None,
                    );
                }
            };
            match send_message(ctx, credential_id, parsed, runner).await {
                Ok(answer) => match serde_json::to_value(answer) {
                    Ok(result) => rpc_ok(ctx, id, result),
                    Err(_) => rpc_error(ctx, id, codes::INTERNAL_ERROR, "internal error", None),
                },
                Err(SendError::InvalidParams(message)) => {
                    rpc_error(ctx, id, codes::INVALID_PARAMS, &message, None)
                }
                Err(SendError::ContentTypeNotSupported) => rpc_error(
                    ctx,
                    id,
                    codes::CONTENT_TYPE_NOT_SUPPORTED,
                    "only text and data parts are supported",
                    None,
                ),
                Err(SendError::Busy) => rate_limited(ctx, Outcome::Busy, 1),
                Err(SendError::Internal) => {
                    rpc_error(ctx, id, codes::INTERNAL_ERROR, "the turn failed", None)
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
            Ok(_) => rpc_error(ctx, id, codes::TASK_NOT_FOUND, "task not found", None),
            Err(err) => rpc_error(
                ctx,
                id,
                codes::INVALID_PARAMS,
                &format!("invalid params: {err}"),
                None,
            ),
        },
        methods::CANCEL_TASK => match serde_json::from_value::<CancelTaskRequest>(params) {
            Ok(_) => rpc_error(ctx, id, codes::TASK_NOT_FOUND, "task not found", None),
            Err(err) => rpc_error(
                ctx,
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
                    Ok(result) => rpc_ok(ctx, id, result),
                    Err(_) => rpc_error(ctx, id, codes::INTERNAL_ERROR, "internal error", None),
                },
                Err(err) => rpc_error(
                    ctx,
                    id,
                    codes::INVALID_PARAMS,
                    &format!("invalid params: {err}"),
                    None,
                ),
            }
        }
        methods::SEND_STREAMING_MESSAGE | methods::SUBSCRIBE_TO_TASK => rpc_error(
            ctx,
            id,
            codes::UNSUPPORTED_OPERATION,
            "streaming is not supported",
            None,
        ),
        methods::CREATE_PUSH_CONFIG
        | methods::GET_PUSH_CONFIG
        | methods::LIST_PUSH_CONFIGS
        | methods::DELETE_PUSH_CONFIG => rpc_error(
            ctx,
            id,
            codes::PUSH_NOTIFICATION_NOT_SUPPORTED,
            "push notifications are not supported",
            None,
        ),
        methods::GET_EXTENDED_AGENT_CARD => rpc_error(
            ctx,
            id,
            codes::EXTENDED_AGENT_CARD_NOT_CONFIGURED,
            "no extended agent card is configured",
            None,
        ),
        _ => rpc_error(ctx, id, codes::METHOD_NOT_FOUND, "method not found", None),
    }
}

fn rpc_ok(ctx: &A2aContext<'_>, id: JsonRpcId, result: Value) -> HttpResponse {
    ctx.trace.outcome(Outcome::Served);
    rpc_body(&JsonRpcResponse::ok(id, result))
}

fn rpc_error(
    ctx: &A2aContext<'_>,
    id: JsonRpcId,
    code: i64,
    message: &str,
    data: Option<Value>,
) -> HttpResponse {
    ctx.trace.rpc_error(code);
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
    // This binding serves exactly one RPC, so it names it up front rather
    // than reading one off the request.
    ctx.trace.method(methods::SEND_MESSAGE);
    if let Err(retry_after) = ctx.limiter.check(credential_id, TURN_COST) {
        return rate_limited(ctx, Outcome::RateLimited, retry_after);
    }
    if check_version(req).is_err() {
        ctx.trace.outcome(Outcome::VersionUnsupported);
        return rest_error(
            ctx,
            StatusCode::BAD_REQUEST,
            "FAILED_PRECONDITION",
            "protocol version not supported",
        );
    }
    let parsed: SendMessageRequest = match serde_json::from_slice(req.body) {
        Ok(parsed) => parsed,
        Err(err) => {
            return rest_error(
                ctx,
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
                ctx,
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "internal error",
            ),
        },
        Err(SendError::InvalidParams(message)) => {
            rest_error(ctx, StatusCode::BAD_REQUEST, "INVALID_ARGUMENT", &message)
        }
        Err(SendError::ContentTypeNotSupported) => rest_error(
            ctx,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "INVALID_ARGUMENT",
            "only text and data parts are supported",
        ),
        Err(SendError::Busy) => rate_limited(ctx, Outcome::Busy, 1),
        Err(SendError::Internal) => rest_error(
            ctx,
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            "the turn failed",
        ),
    }
}

fn rest_error(
    ctx: &A2aContext<'_>,
    status: StatusCode,
    code_name: &str,
    message: &str,
) -> HttpResponse {
    ctx.trace.outcome(Outcome::Rejected);
    let body = json!({"error": {"code": status.as_u16(), "status": code_name, "message": message}});
    json_response(status, body.to_string().into_bytes())
}

#[cfg(test)]
#[path = "rpc_tests.rs"]
mod rpc_tests;
