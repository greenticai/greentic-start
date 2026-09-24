//! A deployed worker as an A2A v1.0 agent (worker-interop contract §3,
//! Feature A of the research spec).
//!
//! Three paths, reserved only when the unit's staged config sets `a2a: true`
//! (otherwise [`route_for`] matches but the caller falls through to normal
//! routing):
//!
//! | path | method | auth |
//! |---|---|---|
//! | `/.well-known/agent-card.json` | GET | none |
//! | `/a2a` | POST, JSON-RPC 2.0 | bearer |
//! | `/a2a/message:send` | POST, HTTP+JSON binding | bearer |
//!
//! Stateless MVP (D4): `SendMessage` runs ONE turn synchronously. A turn that
//! COMPLETED answers with a `Message`; a turn that PARKED answers with a
//! `Task` in `input-required` whose id is the conversation's `contextId`
//! (D8/D9), carrying the question as prose and as a structured input request
//! ([`crate::interop::input_request`]). There is still no task store, so
//! `GetTask`/`CancelTask` answer `TaskNotFoundError` for every id — including
//! one this server minted; [`rpc::handle_jsonrpc`]'s `GetTask` arm records
//! what would have to exist first. `ListTasks` answers an empty page.
//!
//! The conversation is `a2a:<credential id>:<contextId>`: namespaced by the
//! caller's credential so two callers cannot resume each other's parked flow,
//! whatever `contextId` they send.

pub(crate) mod card;
pub(crate) mod rpc;
pub(crate) mod types;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Response, StatusCode, header};

use greentic_deploy_spec::ids::DeploymentId;

use super::config::InteropConfig;
use super::limits::{RateLimiter, TurnGate};
use types::ProtocolVersion;

/// `GET` path of the public agent card.
pub(crate) const AGENT_CARD_PATH: &str = "/.well-known/agent-card.json";
/// JSON-RPC endpoint.
pub(crate) const JSONRPC_PATH: &str = "/a2a";
/// HTTP+JSON `SendMessage`.
pub(crate) const REST_SEND_PATH: &str = "/a2a/message:send";

/// Media type of an Adaptive Card `data` part.
pub(crate) const ADAPTIVE_CARD_MEDIA_TYPE: &str = "application/vnd.microsoft.card.adaptive+json";

/// The request header carrying the caller's protocol version. Its
/// query-parameter alternative (`?A2A-Version=`) is read by the handlers.
pub(crate) const VERSION_HEADER: &str = "a2a-version";

/// `Cache-Control` on the card (A2A §8.6: SHOULD carry max-age and an ETag).
const CARD_CACHE_CONTROL: &str = "public, max-age=300";

/// Which interop surface a path names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum A2aRoute {
    Card,
    JsonRpc,
    RestSend,
}

/// Classify a request path. Exact matches only.
///
/// **The argument is the path BELOW the unit's mount**, not the raw request
/// path — see
/// [`RouteMount::remainder`](crate::deployment_routes::RouteMount::remainder).
/// Every one of these paths is reserved relative to the unit, because the
/// env-canvas Cloud Run lane mounts each unit at `/<slug>`
/// (`BundleRouting::PerUnit`). Matching the raw path instead reserved them for
/// a unit at `/` alone — the one mount that lane never emits — and the whole
/// surface answered `404` or `405` in production.
pub(crate) fn route_for(path: &str) -> Option<A2aRoute> {
    match path {
        AGENT_CARD_PATH => Some(A2aRoute::Card),
        JSONRPC_PATH => Some(A2aRoute::JsonRpc),
        REST_SEND_PATH => Some(A2aRoute::RestSend),
        _ => None,
    }
}

/// `/a2a` and everything under it is never CORS-enabled: a browser page has no
/// business driving an authenticated turn runner. The card stays CORS-open.
pub(crate) fn is_cors_excluded(path: &str) -> bool {
    path == JSONRPC_PATH || path.starts_with("/a2a/")
}

/// Everything the A2A handlers know about the unit being served.
pub(crate) struct A2aContext<'a> {
    pub config: &'a InteropConfig,
    /// The public base URL (no trailing slash), when known.
    pub base_url: Option<&'a str>,
    pub tenant: &'a str,
    pub bundle_id: &'a str,
    pub deployment_id: DeploymentId,
    pub limiter: &'a RateLimiter,
    pub turns: &'a TurnGate,
    /// The wall clock the credential expiry is judged against, threaded in so
    /// a test can drive it.
    pub now_ms: u64,
    /// Where to record what this unit's turns spend. `None` is the whole off
    /// switch: a unit that stages no `metering` block has nothing to call.
    pub metering: Option<super::metering::TurnMetering>,
}

/// The request facts the handlers read, gathered before the body is consumed.
///
/// Deliberately carries NO credential: the ingress authenticates from the
/// `Authorization` header before it reads a body, and hands the handlers the
/// verified credential id. A request type that carried the header would
/// invite a handler to re-derive it, and the whole point is that the check
/// has already happened.
pub(crate) struct A2aRequest<'a> {
    pub version_header: Option<&'a str>,
    pub query: Option<&'a str>,
    pub if_none_match: Option<&'a str>,
    pub body: &'a [u8],
}

pub(crate) type HttpResponse = Response<Full<Bytes>>;

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

pub(crate) fn json(status: StatusCode, body: Vec<u8>) -> HttpResponse {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header("A2A-Version", ProtocolVersion::SUPPORTED.to_string())
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

pub(crate) fn plain(status: StatusCode, message: &str) -> HttpResponse {
    let mut response = Response::new(Full::new(Bytes::from(message.to_string())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod mod_tests;
