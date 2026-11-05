//! A deployed worker as an OpenAI-compatible chat endpoint (worker-interop
//! contract, OpenAI-compatible surface; designer spec
//! `2026-10-31-openai-compatible-worker-endpoint-and-observability-export`).
//!
//! | path | method | auth |
//! |---|---|---|
//! | `/v1/models` | GET | the A2A bearer, or an OAuth JWT for the `openai` resource |
//! | `/v1/chat/completions` | POST | same |
//!
//! Reserved only when the unit's staged config sets `openai: true` AND the unit
//! is private; otherwise the paths fall through to normal routing exactly as
//! before. **The surface is private-only by decision**: a public unit would let
//! anonymous callers spend the owner's LLM budget through a surface that
//! invites scripts, so a public unit never serves it.
//!
//! It is `/a2a` with a different body and nothing more: the same credential
//! gate ([`crate::interop::auth`]), the same per-credential bucket and
//! per-deployment turn cap, the same turn runner and the same usage meter.
//!
//! What it deliberately does NOT do:
//!
//! - **`model` never picks anything.** `GET /v1/models` lists exactly one
//!   entry, `worker:<agent id>`; any other `model` is `404 model_not_found`.
//! - **No `tools`.** The worker's own tools run inside the worker. A non-empty
//!   `tools` array is `400 worker_tools_unsupported`, because ignoring it
//!   would leave the caller's agent loop waiting for a `tool_calls` finish
//!   reason that never comes.
//! - **No streaming.** `stream: true` is `400 streaming_unsupported`. The
//!   runtime hands the host whole replies, not token deltas, and buffering a
//!   finished reply into one chunk labelled streaming would be a lie.
//! - **The caller's `system` message is not the worker's system prompt.** It is
//!   framed as context, like every earlier message of a request that names no
//!   conversation.
//! - **`usage` only when measured.** Never estimated.

pub(crate) mod handler;
pub(crate) mod request;
pub(crate) mod response;

#[cfg(test)]
mod tests;

/// `GET /v1/models`.
pub(crate) const MODELS_PATH: &str = "/v1/models";
/// `POST /v1/chat/completions`.
pub(crate) const CHAT_PATH: &str = "/v1/chat/completions";

/// The header that names the conversation to continue, and that every answer
/// carries back.
pub(crate) const CONVERSATION_HEADER: &str = "x-greentic-conversation-id";

/// Which OpenAI-compatible path a request names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenaiRoute {
    Models,
    ChatCompletions,
}

impl OpenaiRoute {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            OpenaiRoute::Models => "openai_models",
            OpenaiRoute::ChatCompletions => "openai_chat_completions",
        }
    }
}

/// Classify a request path. Exact matches only.
///
/// **The argument is the path BELOW the unit's mount**, as for
/// [`crate::interop::mcp::route_for`]: the env-canvas Cloud Run lane mounts
/// each unit at `/<slug>`, so the raw path would match a unit at `/` alone.
pub(crate) fn route_for(path: &str) -> Option<OpenaiRoute> {
    match path {
        MODELS_PATH => Some(OpenaiRoute::Models),
        CHAT_PATH => Some(OpenaiRoute::ChatCompletions),
        _ => None,
    }
}

/// Neither path is CORS-enabled: a browser page has no business driving an
/// authenticated turn runner, and the only credential accepted is a bearer
/// header, so the preflight for `Authorization` must never succeed. A browser
/// caller goes through the operator's own backend.
pub(crate) fn is_cors_excluded(path: &str) -> bool {
    route_for(path).is_some()
}

/// The one model id this worker answers to.
pub(crate) fn model_id(config: &super::config::InteropConfig, bundle_id: &str) -> String {
    let id = config
        .agent
        .id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .unwrap_or(bundle_id);
    format!("worker:{id}")
}
