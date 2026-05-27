//! Slim HTTP serving loop for the no-bundle, runtime-config-activated revision
//! path (the B3 → execution-bridge step).
//!
//! When `greentic start` runs without `--bundle`/`--config`, the runtime-config
//! activation ([`crate::revision_boot`]) loads every pinned revision into an
//! embedded [`RunnerHost`] and produces a [`RevisionIngressRouting`] bundle. The
//! legacy [`crate::http_ingress`] server cannot serve that: it is hard-wired to a
//! single `DemoRunnerHost` rooted at a bundle directory, neither of which exists
//! here. This module is the dedicated, minimal serving surface for the new path.
//!
//! Per request it: resolves the bound deployment + tenant from `(host, path)`,
//! asks the dispatcher to pick a revision (honouring stickiness cookies), maps
//! the request body to a canonical [`Activity`], runs it against that revision's
//! runtime via [`RunnerHost::handle_activity_for_revision`], and serializes the
//! reply activities back as a JSON array.
//!
//! This is the **generic-JSON vertical slice**: the body is treated as a generic
//! JSON activity (a `text` field becomes a messaging activity, anything else a
//! custom `http.request` activity routed to the pack's entry flow). Provider
//! webhook parsing (Slack/Telegram signature-verified `ingest_http`), WebChat /
//! DirectLine, WebSocket upgrades, and static-asset serving under revisions are
//! deliberately out of scope and stay on the legacy ingress for now.
//!
//! Because provider parsing is deferred, the slice is **fail-closed** rather than
//! a catch-all: a request whose `(path, method)` matches the selected revision's
//! declared provider route is refused (`501`) instead of being run generically —
//! that would skip the provider's signature/token verification. Only `POST`
//! requests to non-provider paths run the entry flow; everything else is `404`
//! (no deployment bound) / `405` (wrong method) / `501` (provider path). Caller-
//! asserted identity (`x-greentic-user`/`-session`, body `user`/`session`) is
//! honoured only from loopback peers, so a remote caller cannot impersonate a
//! user/session or pin a chosen revision (see `caller_identity`).

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1::Builder as Http1Builder;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, header};
use hyper_util::rt::tokio::TokioIo;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;

use greentic_runner_host::{Activity, RunnerHost};

use crate::deployment_routes::RevisionIngressRouting;
use crate::http_routes::{HttpRouteTable, RevisionScope};
use crate::operator_log;
use crate::revision_dispatcher::{DispatchRequest, SetCookieDirective, cookie_name};

/// Largest request body the revision ingress accepts, in bytes. Even on the
/// loopback / local posture a cap is required so one oversized POST cannot
/// exhaust memory before the JSON parse rejects it.
const MAX_BODY_BYTES: usize = 1 << 20; // 1 MiB

/// Inputs for [`RevisionServer::start`]: where to listen plus the activated host
/// and routing the server serves over.
pub(crate) struct RevisionServeConfig {
    pub bind_addr: SocketAddr,
    pub env_id: String,
    pub host: Arc<RunnerHost>,
    pub routing: RevisionIngressRouting,
}

/// Per-connection shared state. Cheap to clone (everything behind an `Arc`).
struct ServeState {
    env_id: String,
    host: Arc<RunnerHost>,
    routing: RevisionIngressRouting,
}

/// A running revision ingress server on its own thread + Tokio runtime, mirroring
/// the legacy ingress's lifecycle so `run_start` can `stop()` it on shutdown.
pub(crate) struct RevisionServer {
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<Result<()>>>,
    actual_port: u16,
}

impl RevisionServer {
    /// Bind, spawn the serving thread, and return once the listener is up (or the
    /// bind failed). The requested port is bumped to the next free one if taken,
    /// matching the legacy ingress.
    pub(crate) fn start(config: RevisionServeConfig) -> Result<Self> {
        let requested_port = config.bind_addr.port();
        let listen_ip = config.bind_addr.ip();
        let actual_port =
            crate::port_utils::find_available_port(&listen_ip.to_string(), requested_port, 10)
                .context("failed to find available port for revision ingress")?;
        if actual_port != requested_port {
            operator_log::warn(
                module_path!(),
                format!(
                    "requested port {requested_port} is in use; using port {actual_port} instead"
                ),
            );
        }
        let addr = SocketAddr::new(listen_ip, actual_port);

        let state = Arc::new(ServeState {
            env_id: config.env_id,
            host: config.host,
            routing: config.routing,
        });

        let (tx, rx) = oneshot::channel();
        let (startup_tx, startup_rx) = mpsc::channel();
        let handle = thread::Builder::new()
            .name("revision-ingress".to_string())
            .spawn(move || -> Result<()> {
                let runtime =
                    match Runtime::new().context("failed to create revision ingress runtime") {
                        Ok(runtime) => runtime,
                        Err(err) => {
                            let _ = startup_tx.send(Err(anyhow::anyhow!("{err:#}")));
                            return Err(err);
                        }
                    };
                runtime.block_on(async move {
                    let listener = match TcpListener::bind(addr)
                        .await
                        .context("failed to bind revision ingress listener")
                    {
                        Ok(listener) => listener,
                        Err(err) => {
                            let _ = startup_tx.send(Err(anyhow::anyhow!("{err:#}")));
                            return Err(err);
                        }
                    };
                    let _ = startup_tx.send(Ok(()));
                    operator_log::info(
                        module_path!(),
                        format!("revision ingress listening on http://{addr}"),
                    );
                    let mut shutdown = rx;
                    loop {
                        tokio::select! {
                            _ = &mut shutdown => break,
                            accept = listener.accept() => match accept {
                                Ok((stream, peer)) => {
                                    let connection_state = state.clone();
                                    // Caller-asserted identity (see `serve`) is only
                                    // honoured from loopback peers; capture it here.
                                    let peer_is_loopback = peer.ip().is_loopback();
                                    tokio::spawn(async move {
                                        let service = service_fn(move |req| {
                                            handle_connection(
                                                req,
                                                connection_state.clone(),
                                                peer_is_loopback,
                                            )
                                        });
                                        let io = TokioIo::new(stream);
                                        if let Err(err) =
                                            Http1Builder::new().serve_connection(io, service).await
                                        {
                                            operator_log::error(
                                                module_path!(),
                                                format!("revision ingress connection error: {err}"),
                                            );
                                        }
                                    });
                                }
                                Err(err) => operator_log::error(
                                    module_path!(),
                                    format!("revision ingress accept error: {err}"),
                                ),
                            },
                        }
                    }
                    Ok(())
                })
            })?;
        startup_rx
            .recv()
            .context("failed to receive revision ingress startup result")??;

        Ok(Self {
            shutdown: Some(tx),
            handle: Some(handle),
            actual_port,
        })
    }

    /// The port the server actually bound (may differ from the request if it was
    /// taken).
    pub(crate) fn actual_port(&self) -> u16 {
        self.actual_port
    }

    /// Signal shutdown and join the serving thread.
    pub(crate) fn stop(mut self) -> Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            handle
                .join()
                .map_err(|err| anyhow::anyhow!("revision ingress server panicked: {err:?}"))??;
        }
        Ok(())
    }
}

/// `service_fn` adapter: collapse the `Ok`/`Err` response halves into the single
/// infallible response hyper wants.
async fn handle_connection(
    req: Request<Incoming>,
    state: Arc<ServeState>,
    peer_is_loopback: bool,
) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(match serve(req, state, peer_is_loopback).await {
        Ok(response) => response,
        Err(response) => response,
    })
}

/// Resolve → dispatch → execute for a single request. `Err` carries a ready HTTP
/// error response; it is never a fall-through to any other handler.
async fn serve(
    req: Request<Incoming>,
    state: Arc<ServeState>,
    peer_is_loopback: bool,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    if path == "/healthz" || path == "/health" {
        return Ok(text_response(StatusCode::OK, "ok"));
    }

    let host_header = header_str(req.headers(), header::HOST.as_str());
    let cookie_header = header_str(req.headers(), header::COOKIE.as_str());
    let user_header = header_str(req.headers(), "x-greentic-user");
    let session_header = header_str(req.headers(), "x-greentic-session");

    // Resolve the bound deployment + tenant before touching the body, so an
    // unroutable request is rejected cheaply.
    let (deployment_id, tenant) = state
        .routing
        .deployment_routes
        .resolve(host_header.as_deref(), &path)
        .map(|(deployment_id, tenant)| (deployment_id, tenant.to_string()))
        .ok_or_else(|| {
            error_response(
                StatusCode::NOT_FOUND,
                "no deployment is bound to this host and path",
            )
        })?;

    let body_bytes = read_body_limited(req).await.map_err(|_| {
        error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body exceeds the size limit",
        )
    })?;
    let payload: Value = if body_bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body_bytes)
            .map_err(|_| error_response(StatusCode::BAD_REQUEST, "request body must be JSON"))?
    };

    // Caller-asserted identity is only honoured from loopback peers (see
    // `caller_identity`). The session hint both pins the revision (stickiness)
    // and keys the flow session, so it feeds the dispatcher and the activity.
    let (user, session_hint) =
        caller_identity(peer_is_loopback, user_header, session_header, &payload);
    let cookie_value = cookie_header
        .as_deref()
        .and_then(|jar| read_cookie(jar, &cookie_name(deployment_id)));

    let dispatch_req = DispatchRequest {
        env_id: &state.env_id,
        tenant: &tenant,
        deployment_id,
        session_hint: session_hint.as_deref(),
        // Public client traffic is never trusted: the header-pinned revision
        // override is a debug-only affordance.
        trusted: false,
        header_revision: None,
        cookie: cookie_value.as_deref(),
    };
    // `ThreadRng` is `!Send` and the dispatcher is async, so it cannot survive
    // the `.await` in the spawned connection task. Seed a `Send` `SmallRng`.
    let mut rng: rand::rngs::SmallRng = rand::make_rng();
    let outcome = state
        .routing
        .dispatcher
        .dispatch(&dispatch_req, &mut rng)
        .await
        .map_err(|err| {
            operator_log::warn(
                module_path!(),
                format!("revision dispatch for deployment {deployment_id} failed: {err:#}"),
            );
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "revision dispatch failed",
            )
        })?;

    // Gate before executing: refuse provider webhook paths (deferred) and
    // non-POST generic requests, rather than running the entry flow for them.
    let scope = RevisionScope {
        deployment_id,
        bundle_id: outcome.bundle_id.clone(),
        revision_id: outcome.revision_id,
    };
    match admit_request(&state.routing.http_routes, &scope, &path, &method) {
        Admission::ProviderRoute => {
            return Err(error_response(
                StatusCode::NOT_IMPLEMENTED,
                "this path is a provider ingress route; revision-aware provider serving is not \
                 yet implemented (use the legacy --bundle ingress)",
            ));
        }
        Admission::MethodNotAllowed => {
            return Err(error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "only POST is supported for the generic revision ingress",
            ));
        }
        Admission::Serve => {}
    }

    let activity = build_activity(&payload, &tenant, user.as_deref(), session_hint.as_deref());

    let replies = state
        .host
        .handle_activity_for_revision(
            &tenant,
            deployment_id,
            outcome.bundle_id.clone(),
            outcome.revision_id,
            activity,
        )
        .await
        .map_err(|err| {
            operator_log::error(
                module_path!(),
                format!(
                    "revision execution failed for deployment {deployment_id} revision {}: {err:#}",
                    outcome.revision_id
                ),
            );
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "flow execution failed")
        })?;

    let body = serde_json::to_vec(&replies)
        .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let mut response = json_response(StatusCode::OK, body);
    if let Some(directive) = outcome.set_cookie {
        apply_set_cookie(&mut response, &directive);
    }
    Ok(response)
}

/// Map a generic JSON request body to a canonical [`Activity`]. A `text` field
/// becomes a messaging activity; anything else is wrapped as a custom
/// `http.request` activity. With no `flow_id` set, the runtime routes it to the
/// pack's entry flow.
fn build_activity(
    payload: &Value,
    tenant: &str,
    user: Option<&str>,
    session: Option<&str>,
) -> Activity {
    let mut activity = match payload.get("text").and_then(Value::as_str) {
        Some(text) => Activity::text(text),
        None => Activity::custom("http.request", payload.clone()),
    };
    activity = activity.with_tenant(tenant);
    if let Some(user) = user {
        activity = activity.from_user(user);
    }
    if let Some(session) = session {
        activity = activity.with_session(session);
    }
    activity
}

/// Resolve the caller-asserted `(user, session)` identity, honouring it **only
/// from loopback peers**. Header (`x-greentic-user`/`x-greentic-session`) wins
/// over the body `user`/`session` field.
///
/// The legacy webchat/DirectLine ingress likewise derives identity from the
/// unauthenticated client request, so on loopback this matches the existing
/// posture. But this path has no authentication, so a non-loopback caller must
/// not be able to assert another user's identity — which would let it resume
/// that user's waiting flow or key its session — nor poison revision stickiness
/// via a chosen session hint. Remote callers therefore run anonymously with no
/// session hint (the HMAC-signed stickiness cookie, which they cannot forge,
/// still works). A verified provider/DirectLine token is the Phase-D upgrade.
fn caller_identity(
    peer_is_loopback: bool,
    user_header: Option<String>,
    session_header: Option<String>,
    payload: &Value,
) -> (Option<String>, Option<String>) {
    if !peer_is_loopback {
        return (None, None);
    }
    let user = user_header.or_else(|| str_field(payload, "user"));
    let session = session_header.or_else(|| str_field(payload, "session"));
    (user, session)
}

/// Pre-execution admission decision for a dispatched revision request.
#[derive(Debug, PartialEq, Eq)]
enum Admission {
    /// Run the generic entry-flow activity.
    Serve,
    /// The path matches a declared provider ingress route for this revision —
    /// deferred (serving it generically would skip provider signature/token
    /// verification), so it is refused.
    ProviderRoute,
    /// A non-POST request to a generic (non-provider) path.
    MethodNotAllowed,
}

/// Decide whether a dispatched request may run the generic entry flow. Provider
/// routes win first (they are refused regardless of method); otherwise only POST
/// is admitted — a browser `GET /favicon.ico` under a broad `/` binding must not
/// execute the flow.
fn admit_request(
    routes: &HttpRouteTable,
    scope: &RevisionScope,
    path: &str,
    method: &hyper::Method,
) -> Admission {
    if routes
        .match_request_for_revision(path, method.as_str(), scope)
        .is_some()
    {
        return Admission::ProviderRoute;
    }
    if method != hyper::Method::POST {
        return Admission::MethodNotAllowed;
    }
    Admission::Serve
}

/// Read the request body with a hard size cap. `Err(())` means the limit was
/// exceeded (or the body stream errored); the caller maps it to `413`.
async fn read_body_limited(req: Request<Incoming>) -> Result<Bytes, ()> {
    Limited::new(req.into_body(), MAX_BODY_BYTES)
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .map_err(|_| ())
}

/// Fetch a single header value as an owned `String`, if present and valid UTF-8.
fn header_str(headers: &header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
}

/// Read a top-level string field from a JSON object body.
fn str_field(payload: &Value, key: &str) -> Option<String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(|value| value.to_string())
}

/// Look up a cookie value by name across a `Cookie` header value (RFC 6265
/// permits several `name=value` pairs separated by `; `).
fn read_cookie(jar: &str, name: &str) -> Option<String> {
    jar.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key.trim() == name).then(|| value.trim().to_string())
    })
}

/// Attach the revision stickiness `Set-Cookie`. Cookie attributes (`Path`,
/// `Secure`, `HttpOnly`, `SameSite`) are an ingress concern, stamped here rather
/// than by the dispatcher.
fn apply_set_cookie(response: &mut Response<Full<Bytes>>, directive: &SetCookieDirective) {
    let header_value = format!(
        "{}={}; Path=/; Max-Age={}; Secure; HttpOnly; SameSite=Lax",
        directive.name,
        directive.value,
        directive.max_age.as_secs()
    );
    match header::HeaderValue::from_str(&header_value) {
        Ok(value) => {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
        // The value is base64 (URL_SAFE_NO_PAD) so this should never fire; log
        // rather than silently drop the stickiness cookie.
        Err(err) => operator_log::warn(
            module_path!(),
            format!(
                "failed to encode revision Set-Cookie `{}`: {err}",
                directive.name
            ),
        ),
    }
}

fn json_response(status: StatusCode, body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .expect("static response builder inputs are valid")
}

fn text_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("static response builder inputs are valid")
}

fn error_response(status: StatusCode, message: impl AsRef<str>) -> Response<Full<Bytes>> {
    text_response(status, message.as_ref())
}

/// Default bind address for the revision ingress: `127.0.0.1:8080`, with
/// `GREENTIC_GATEWAY_LISTEN_ADDR` (IP) and `PORT` overrides matching the rest of
/// the gateway configuration.
pub(crate) fn default_bind_addr() -> SocketAddr {
    let ip = std::env::var("GREENTIC_GATEWAY_LISTEN_ADDR")
        .ok()
        .and_then(|raw| raw.trim().parse::<IpAddr>().ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let port = std::env::var("PORT")
        .ok()
        .and_then(|raw| raw.trim().parse::<u16>().ok())
        .unwrap_or(8080);
    SocketAddr::new(ip, port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_runner_host::engine::runtime::{FlowResumeStore, IngressEnvelope};
    use greentic_runner_host::runner::engine::{ExecutionState, FlowSnapshot, FlowWait};
    use greentic_runner_host::storage::new_session_store;
    use greentic_types::ReplyScope;
    use serde_json::json;

    #[test]
    fn build_activity_text_field_becomes_messaging_activity() {
        let payload = json!({ "text": "hello there" });
        let activity = build_activity(&payload, "acme", Some("u1"), Some("s1"));
        assert_eq!(activity.tenant(), Some("acme"));
        assert_eq!(activity.user(), Some("u1"));
        assert_eq!(activity.session_id(), Some("s1"));
        assert_eq!(activity.flow_type(), Some("messaging"));
        assert_eq!(
            activity.payload().get("text").and_then(Value::as_str),
            Some("hello there")
        );
    }

    #[test]
    fn build_activity_without_text_wraps_generic_payload() {
        let payload = json!({ "kind": "ping", "n": 7 });
        let activity = build_activity(&payload, "acme", None, None);
        assert_eq!(activity.tenant(), Some("acme"));
        assert_eq!(activity.user(), None);
        assert_eq!(activity.session_id(), None);
        // The whole body is preserved for the entry flow to interpret.
        assert_eq!(activity.payload(), &payload);
    }

    #[test]
    fn build_activity_empty_body_is_a_null_custom_activity() {
        let activity = build_activity(&Value::Null, "acme", None, None);
        assert_eq!(activity.tenant(), Some("acme"));
        assert_eq!(activity.payload(), &Value::Null);
    }

    #[test]
    fn read_cookie_picks_the_named_pair() {
        let jar = "foo=1; _gt_rev_abc=xyz ; bar=2";
        assert_eq!(read_cookie(jar, "_gt_rev_abc"), Some("xyz".to_string()));
        assert_eq!(read_cookie(jar, "missing"), None);
    }

    #[test]
    fn caller_identity_is_honoured_only_from_loopback() {
        let payload = json!({ "user": "body-user", "session": "body-session" });

        // Loopback: header wins over body, body fills the rest.
        let (user, session) = caller_identity(true, Some("hdr-user".into()), None, &payload);
        assert_eq!(user.as_deref(), Some("hdr-user"));
        assert_eq!(session.as_deref(), Some("body-session"));

        // Non-loopback: client-asserted identity is dropped entirely so a remote
        // caller cannot impersonate a user/session or pin a chosen revision.
        let (user, session) = caller_identity(
            false,
            Some("hdr-user".into()),
            Some("hdr-session".into()),
            &payload,
        );
        assert_eq!(user, None);
        assert_eq!(session, None);
    }

    fn provider_route_table(scope: &RevisionScope) -> HttpRouteTable {
        use crate::domains::Domain;
        HttpRouteTable::from_descriptors(vec![crate::http_routes::descriptor_for_test(
            "/slack/events",
            &["POST"],
            Domain::Messaging,
            Some(scope.clone()),
        )])
    }

    fn test_scope() -> RevisionScope {
        RevisionScope {
            deployment_id: greentic_deploy_spec::DeploymentId::new(),
            bundle_id: greentic_deploy_spec::BundleId::new("fast2flow"),
            revision_id: greentic_deploy_spec::RevisionId::new(),
        }
    }

    #[test]
    fn admit_refuses_declared_provider_route() {
        let scope = test_scope();
        let routes = provider_route_table(&scope);
        // A POST to the declared provider webhook path is refused (deferred),
        // never run as a generic activity that would skip signature verification.
        assert_eq!(
            admit_request(&routes, &scope, "/slack/events", &hyper::Method::POST),
            Admission::ProviderRoute
        );
    }

    #[test]
    fn admit_rejects_non_post_on_generic_path() {
        let scope = test_scope();
        let routes = provider_route_table(&scope);
        // A browser GET that doesn't hit a provider route must not run the flow.
        assert_eq!(
            admit_request(&routes, &scope, "/favicon.ico", &hyper::Method::GET),
            Admission::MethodNotAllowed
        );
    }

    #[test]
    fn admit_serves_generic_post() {
        let scope = test_scope();
        let routes = provider_route_table(&scope);
        assert_eq!(
            admit_request(&routes, &scope, "/api/chat", &hyper::Method::POST),
            Admission::Serve
        );
    }

    #[test]
    fn admit_does_not_match_provider_route_of_a_different_revision() {
        let scope = test_scope();
        let routes = provider_route_table(&scope);
        // Same path, but a different revision's scope: not this revision's
        // provider route, so a POST falls through to generic serving.
        let other = test_scope();
        assert_eq!(
            admit_request(&routes, &other, "/slack/events", &hyper::Method::POST),
            Admission::Serve
        );
    }

    fn envelope_for(user: &str, conversation: &str) -> IngressEnvelope {
        IngressEnvelope {
            tenant: "acme".into(),
            env: Some("local".into()),
            pack_id: Some("pack.demo".into()),
            flow_id: "flow.main".into(),
            flow_type: Some("messaging".into()),
            action: Some("messaging".into()),
            session_hint: Some(format!("acme:provider:{conversation}:{user}")),
            provider: Some("provider".into()),
            channel: Some(conversation.into()),
            conversation: Some(conversation.into()),
            user: Some(user.into()),
            activity_id: Some(format!("activity-{conversation}")),
            timestamp: None,
            payload: json!({ "text": "hi" }),
            metadata: None,
            reply_scope: Some(ReplyScope {
                conversation: conversation.into(),
                thread: None,
                reply_to: None,
                correlation: None,
            }),
        }
        .canonicalize()
    }

    fn wait_for(next_node: &str) -> FlowWait {
        let state: ExecutionState = serde_json::from_value(json!({
            "input": { "text": "hi" },
            "nodes": {},
            "egress": []
        }))
        .expect("state");
        FlowWait {
            reason: Some("await-user".into()),
            snapshot: FlowSnapshot {
                pack_id: "pack.demo".into(),
                flow_id: "flow.main".into(),
                next_flow: None,
                next_node: next_node.into(),
                state,
            },
        }
    }

    /// The core of the cross-revision contamination fix: two revisions of one
    /// pack, serving the SAME tenant/user/conversation, must not see each other's
    /// suspended `wait` snapshots. `revision_boot` now gives each revision its
    /// own session store; here we model that — two `FlowResumeStore`s over
    /// separate session backends — and prove a snapshot saved by revision A is
    /// invisible to revision B for the identical resume envelope.
    #[test]
    fn isolated_revision_stores_do_not_cross_resume() {
        let store_a = FlowResumeStore::new(new_session_store());
        let store_b = FlowResumeStore::new(new_session_store());

        // Identical resume key (same tenant/user/conversation) across revisions.
        let envelope = envelope_for("user-1", "conv-1");

        store_a
            .save(&envelope, &wait_for("node-a"))
            .expect("save A");

        // Revision B, with its own store, sees nothing for the same envelope.
        assert!(
            store_b.fetch(&envelope).expect("fetch B").is_none(),
            "revision B must not observe revision A's suspended snapshot"
        );
        // Revision A still resumes its own snapshot at the right node.
        let resumed = store_a
            .fetch(&envelope)
            .expect("fetch A")
            .expect("A snapshot present");
        assert_eq!(resumed.next_node, "node-a");

        store_a.clear(&envelope).expect("clear A");
    }

    /// Negative control: a SHARED session store (the pre-fix behavior) DOES leak
    /// across revisions for the same envelope — revision B resumes revision A's
    /// snapshot against a potentially different flow graph. This is exactly the
    /// contamination `revision_boot`'s per-revision stores prevent.
    #[test]
    fn shared_revision_store_leaks_across_revisions() {
        let shared = new_session_store();
        let store_a = FlowResumeStore::new(Arc::clone(&shared));
        let store_b = FlowResumeStore::new(shared);

        let envelope = envelope_for("user-1", "conv-1");
        store_a
            .save(&envelope, &wait_for("node-a"))
            .expect("save A");

        let leaked = store_b
            .fetch(&envelope)
            .expect("fetch B")
            .expect("shared store leaks the snapshot to revision B");
        assert_eq!(
            leaked.next_node, "node-a",
            "shared store hands revision A's snapshot to revision B (the bug)"
        );

        store_a.clear(&envelope).expect("clear");
    }
}
