//! The two OpenAI-compatible endpoints, over the same turn runner, credential
//! gate, limiter, turn cap and usage meter as `/a2a` and `/mcp`.
//!
//! Order matters and mirrors the other surfaces: authenticate BEFORE the body
//! is read (so an unauthenticated peer cannot make this process buffer a
//! megabyte), charge the limiter, parse, take a turn permit, run.

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Response, StatusCode};
use serde_json::json;

use super::request::{self, Refusal};
use super::response::{self, MeasuredUsage};
use super::{OpenaiRoute, model_id};
use crate::interop::a2a::rpc::TurnRunner;
use crate::interop::auth::Auth;
use crate::interop::caller::Caller;
use crate::interop::config::InteropConfig;
use crate::interop::limits::{Charge, RateLimiter, TurnGate};
use crate::interop::metering::TurnMetering;
use crate::interop::metering::event::{Surface, usage_from_replies};
use crate::interop::reply::{ReplyItem, project_replies};
use crate::interop::telemetry::{Outcome, RequestTrace};
use greentic_deploy_spec::ids::DeploymentId;

/// Everything one request needs from its unit and the host.
pub(crate) struct OpenaiContext<'a> {
    pub config: &'a InteropConfig,
    pub tenant: &'a str,
    pub bundle_id: &'a str,
    pub deployment_id: DeploymentId,
    pub limiter: &'a RateLimiter,
    pub turns: &'a TurnGate,
    pub now_ms: u64,
    pub metering: Option<TurnMetering>,
    pub trace: &'a RequestTrace,
}

/// The facts of the request read before its body.
pub(crate) struct OpenaiHeaders<'a> {
    pub authorization: Option<&'a str>,
    pub authorization_unreadable: bool,
    /// `X-Greentic-Conversation-Id`.
    pub conversation: Option<&'a str>,
}

/// The unit's OAuth audience for this surface, when it staged one.
fn resource(config: &InteropConfig) -> Option<&str> {
    config.openai_resource.as_deref()
}

/// Authenticate. A refusal is a ready response.
///
/// There is no anonymous caller: the surface is private-only, and a public
/// unit never reaches here (it does not serve these paths at all).
pub(crate) async fn authenticate(
    ctx: &OpenaiContext<'_>,
    headers: &OpenaiHeaders<'_>,
) -> Result<Caller, Box<Response<Full<Bytes>>>> {
    let auth = crate::interop::auth::authenticate(
        ctx.config,
        resource(ctx.config),
        headers.authorization,
        headers.authorization_unreadable,
        ctx.now_ms,
        None,
    )
    .await;
    match auth {
        Auth::Allowed(caller) if !caller.is_anonymous() => {
            if let Some(id) = caller.credential_id() {
                ctx.trace.credential(id);
            }
            Ok(caller)
        }
        // An anonymous caller cannot happen on a private unit; refuse rather
        // than serve one if it somehow does.
        Auth::Allowed(_) | Auth::Unauthorized => {
            ctx.trace.outcome(Outcome::Unauthenticated);
            Err(Box::new(response::unauthorized()))
        }
        Auth::IssuerUnavailable => {
            ctx.trace.outcome(Outcome::Rejected);
            Err(Box::new(response::error(
                StatusCode::SERVICE_UNAVAILABLE,
                "issuer_unavailable",
                "The authorization server could not be reached to verify this token.",
                None,
            )))
        }
    }
}

/// Serve an authenticated request.
pub(crate) async fn handle(
    ctx: &OpenaiContext<'_>,
    route: OpenaiRoute,
    caller: &Caller,
    headers: &OpenaiHeaders<'_>,
    body: &[u8],
    runner: &dyn TurnRunner,
) -> Response<Full<Bytes>> {
    let charge = match route {
        OpenaiRoute::Models => Charge::CHEAP,
        OpenaiRoute::ChatCompletions => Charge::TURN,
    };
    if let Err(retry_after) = ctx.limiter.admit(
        caller,
        &ctx.config.access,
        &ctx.deployment_id.to_string(),
        charge,
        ctx.now_ms,
    ) {
        ctx.trace.outcome(Outcome::RateLimited);
        return response::rate_limited(
            retry_after,
            "rate_limit_exceeded",
            "Too many requests from this credential. Wait and retry.",
        );
    }
    let model = model_id(ctx.config, ctx.bundle_id);
    let created = ctx.now_ms / 1000;
    match route {
        OpenaiRoute::Models => {
            ctx.trace.outcome(Outcome::Served);
            response::models(&model, created)
        }
        OpenaiRoute::ChatCompletions => {
            chat(ctx, caller, headers, body, runner, &model, created).await
        }
    }
}

async fn chat(
    ctx: &OpenaiContext<'_>,
    caller: &Caller,
    headers: &OpenaiHeaders<'_>,
    body: &[u8],
    runner: &dyn TurnRunner,
    model: &str,
    created: u64,
) -> Response<Full<Bytes>> {
    let turn = match request::parse(body, model, headers.conversation) {
        Ok(turn) => turn,
        Err(refusal) => {
            ctx.trace.outcome(Outcome::Rejected);
            return refuse(refusal);
        }
    };
    let conversation_id = turn
        .conversation_id
        .clone()
        .unwrap_or_else(|| ulid::Ulid::new().to_string());
    let namespace = caller.session_key(&conversation_id);
    let session_hint = crate::interop::session_hint("openai", &namespace, &conversation_id);
    let user = format!("openai:{namespace}");

    // The cap is per deployment and nothing queues: the caller holds its
    // connection open for the whole turn.
    let Some(_permit) = ctx.turns.try_acquire_for(ctx.deployment_id, caller) else {
        ctx.trace.outcome(Outcome::Busy);
        return response::rate_limited(
            1,
            "worker_busy",
            "This worker is running as many turns as it can at once. Retry shortly.",
        );
    };

    let payload = json!({ "text": turn.text });
    // One event per turn that RAN; everything refused above ran nothing.
    let started = std::time::Instant::now();
    let outcome = runner.run(&session_hint, &user, &payload, None).await;
    let elapsed = started.elapsed();
    let usage = outcome
        .as_ref()
        .map(|replies| usage_from_replies(replies))
        .unwrap_or_default();
    if let Some(metering) = ctx.metering.as_ref() {
        metering.record_for(Surface::Openai, caller, usage, elapsed);
    }
    ctx.trace.turn_duration(elapsed);
    let Ok(replies) = outcome else {
        ctx.trace.outcome(Outcome::TurnFailed);
        return failed(&conversation_id);
    };

    let projected = project_replies(&replies, "openai", ctx.tenant, ctx.bundle_id, &session_hint);
    if projected.flow_error {
        // The flow ended at a failure and its text is a categorized error, not
        // an answer: it must not read as the worker's reply.
        ctx.trace.outcome(Outcome::FlowFailed);
        return failed(&conversation_id);
    }
    let content = projected
        .items
        .iter()
        .map(|item| match item {
            ReplyItem::Text(text) => text.as_str(),
            // Only the card's plain-text fallback: this surface has no way to
            // carry a card.
            ReplyItem::Card { fallback, .. } => fallback.as_str(),
        })
        .collect::<Vec<_>>()
        .join("\n\n");
    ctx.trace.outcome(if projected.awaiting_input {
        Outcome::InputRequired
    } else {
        Outcome::Completed
    });
    // Reported only when the runtime measured something: a zero reading is
    // indistinguishable from "nothing was measured", and this surface never
    // estimates.
    let measured = (usage.tokens_in > 0 || usage.tokens_out > 0).then_some(MeasuredUsage {
        prompt_tokens: usage.tokens_in,
        completion_tokens: usage.tokens_out,
    });
    response::completion(
        model,
        created,
        &conversation_id,
        &content,
        measured,
        projected.awaiting_input,
    )
}

fn failed(conversation_id: &str) -> Response<Full<Bytes>> {
    let mut response = response::error(
        StatusCode::BAD_GATEWAY,
        "worker_turn_failed",
        "The worker could not answer this turn.",
        None,
    );
    response::with_conversation(&mut response, conversation_id);
    response
}

fn refuse(refusal: Refusal) -> Response<Full<Bytes>> {
    match refusal {
        Refusal::Malformed(message) => response::error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!("Invalid request: {message}."),
            None,
        ),
        Refusal::UnknownModel => response::error(
            StatusCode::NOT_FOUND,
            "model_not_found",
            "This endpoint serves one model. List it with GET /v1/models.",
            Some("model"),
        ),
        Refusal::Tools => response::error(
            StatusCode::BAD_REQUEST,
            "worker_tools_unsupported",
            "This worker runs its own tools. Remove `tools` from the request.",
            Some("tools"),
        ),
        Refusal::Streaming => response::error(
            StatusCode::BAD_REQUEST,
            "streaming_unsupported",
            "This worker answers in one piece. Send the request with `stream` false or omitted.",
            Some("stream"),
        ),
        Refusal::ConversationId => response::error(
            StatusCode::BAD_REQUEST,
            "invalid_conversation_id",
            "The conversation id is too long or contains control characters.",
            None,
        ),
        Refusal::NoUserMessage => response::error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The last message must be a non-empty message from the user.",
            Some("messages"),
        ),
        Refusal::UnsupportedContent => response::error(
            StatusCode::BAD_REQUEST,
            "unsupported_content",
            "Only text content is supported.",
            Some("messages"),
        ),
    }
}
