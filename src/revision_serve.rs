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

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use greentic_deploy_spec::ids::{BundleId, DeploymentId, RevisionId};
use greentic_types::ChannelMessageEnvelope;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1::Builder as Http1Builder;
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response, StatusCode, header};
use hyper_util::rt::tokio::TokioIo;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::runtime::{Handle, Runtime};
use tokio::sync::oneshot;

use greentic_runner_host::{Activity, RunnerHost, WelcomeFlowHint};

use greentic_deploy_spec::{DEFAULT_LISTEN_ADDR, EnvironmentHostConfig};

use crate::deployment_routes::RevisionIngressRouting;
use crate::endpoint_resolver;
use crate::http_routes::{HttpRouteTable, RevisionScope};
use crate::identify_payload;
use crate::ingress_dispatch::parse_dispatch_result;
use crate::ingress_types::IngressHttpResponse;
use crate::messaging_dto::HttpInV1;
use crate::operator_log;
use crate::revision_dispatcher::{
    DispatchRequest, RevisionDispatcher, RevisionKey, SetCookieDirective, cookie_name,
};
use crate::revision_drain::{
    DrainRequest, NoopRevisionTeardown, RevisionDrainCoordinator, RevisionLivenessProbe,
    RevisionTeardown,
};

/// Largest request body the revision ingress accepts, in bytes. Even on the
/// loopback / local posture a cap is required so one oversized POST cannot
/// exhaust memory before the JSON parse rejects it.
const MAX_BODY_BYTES: usize = 1 << 20; // 1 MiB

/// Activated host + routing as a single coherent unit. Requests bind to one
/// `Arc<Activation>` at the top of [`serve`] and use the same `host` and
/// `routing` for the rest of their lifetime — so a [`RevisionServer::reload`]
/// that swaps the slot mid-request cannot tear (dispatch via the new
/// dispatcher, execute against the old host, or vice versa).
pub(crate) struct Activation {
    pub host: Arc<RunnerHost>,
    pub routing: Arc<RevisionIngressRouting>,
}

/// Inputs for [`RevisionServer::start`]: where to listen plus the initial
/// activation the server serves over. Reload swaps in a new [`Activation`] via
/// [`RevisionServer::reload`].
pub(crate) struct RevisionServeConfig {
    pub bind_addr: SocketAddr,
    pub activation: Arc<Activation>,
}

/// Per-connection shared state. Holds the live activation behind an
/// [`ArcSwap`] so the producer (file-watcher / HTTP signal) can hot-attach new
/// revisions without restarting the listener. Each request reads `slot` once
/// at the top of [`serve`] and threads that snapshot through dispatch +
/// execute. The env id is read from `activation.routing.dispatcher.env_id()`
/// — not stored twice.
struct ServeState {
    slot: ArcSwap<Activation>,
    /// Address the listener bound to (after the `find_available_port` bump).
    /// Reported by `/status` so operators see the actual interface + port
    /// rather than what the user requested.
    bound_addr: SocketAddr,
}

impl ServeState {
    /// Snapshot the live activation. Holding the returned `Arc` keeps the
    /// activation alive across `.await` points, even if a concurrent reload
    /// swaps the slot — the reload's drain window still ensures the old
    /// activation outlives every in-flight request that pinned it.
    fn current(&self) -> Arc<Activation> {
        self.slot.load_full()
    }
}

/// [`RevisionKey`]s present in `prev` but absent from `next`. Used by
/// [`RevisionServer::reload`] to identify revisions the operator just removed
/// so the drain coordinator can fire one drain per removed revision against
/// the OLD activation.
fn removed_revisions(prev: &RevisionDispatcher, next: &RevisionDispatcher) -> Vec<RevisionKey> {
    prev.revision_keys()
        .into_iter()
        .filter(|(deployment_id, _bundle_id, revision_id)| {
            !next.contains_revision(*deployment_id, *revision_id)
        })
        .collect()
}

/// Liveness probe handed to each drain coordinator so it can suppress a
/// stale `RevisionEvicted` event when the revision it's draining is rolled
/// back / re-added into a newer activation before the drain window elapses.
///
/// Checks the server's live activation slot, not the OLD activation being
/// drained: if the revision reappears in whatever the server is currently
/// serving (a strictly newer activation than `draining_dispatcher`), the
/// eviction is stale and must not be reported.
struct SlotLivenessProbe {
    state: Arc<ServeState>,
    /// The dispatcher this coordinator is draining. Identity guard: if the
    /// live slot still points at it, the revision is NOT live "elsewhere" —
    /// it's the same routing table, so the eviction event should fire
    /// (matches a direct drain of the live dispatcher).
    draining_dispatcher: Arc<RevisionDispatcher>,
}

impl RevisionLivenessProbe for SlotLivenessProbe {
    fn is_live_elsewhere(&self, deployment_id: DeploymentId, revision_id: RevisionId) -> bool {
        let live = self.state.current();
        // Same dispatcher instance ⇒ we're draining the live routing table,
        // so the revision isn't live in a NEWER activation. Every reload
        // swaps in a freshly-built dispatcher `Arc`, so pointer identity is
        // a sound discriminator.
        if Arc::ptr_eq(&live.routing.dispatcher, &self.draining_dispatcher) {
            return false;
        }
        live.routing
            .dispatcher
            .contains_revision(deployment_id, revision_id)
    }
}

/// Spawn one [`RevisionDrainCoordinator::run`] task per removed revision
/// against `prev`'s dispatcher. Each task owns its own `Arc` to the OLD
/// activation so the dispatcher and route table outlive the overlap-window
/// drop spawned by [`RevisionServer::reload`]. WS close and teardown are
/// both no-ops in N2.3 — see [`crate::revision_drain`] module docs for the
/// Phase D follow-up.
///
/// Each task carries a [`SlotLivenessProbe`] over `state` so a revision
/// rolled back into a newer activation within the drain window does not
/// produce a stale `RevisionEvicted` event.
fn spawn_revision_drains(
    runtime_handle: &Handle,
    state: Arc<ServeState>,
    prev: Arc<Activation>,
    removed: Vec<RevisionKey>,
    drain_window: Duration,
) {
    let drain_seconds: u32 = drain_window.as_secs().try_into().unwrap_or(u32::MAX);
    let teardown: Arc<dyn RevisionTeardown> = Arc::new(NoopRevisionTeardown);
    for (deployment_id, bundle_id, revision_id) in removed {
        let Some(tenant) = prev
            .routing
            .deployment_routes
            .tenant_for(deployment_id)
            .map(str::to_string)
        else {
            // The route table is built from the SAME runtime-config the
            // dispatcher snapshotted, so a revision known to the dispatcher
            // but missing from the route table is a structural inconsistency.
            // Surface it loudly and skip — emitting telemetry on a tenantless
            // drain would corrupt downstream rollouts of multi-tenant metrics.
            operator_log::warn(
                module_path!(),
                format!(
                    "skipping drain for revision {revision_id} of deployment \
                     {deployment_id}: no tenant binding found in OLD activation \
                     route table (deployment likely removed before reload diff)"
                ),
            );
            continue;
        };
        let dispatcher = Arc::clone(&prev.routing.dispatcher);
        let teardown = Arc::clone(&teardown);
        let liveness: Arc<dyn RevisionLivenessProbe> = Arc::new(SlotLivenessProbe {
            state: Arc::clone(&state),
            draining_dispatcher: Arc::clone(&dispatcher),
        });
        runtime_handle.spawn(async move {
            let coord = RevisionDrainCoordinator::with_noop_ws(dispatcher, teardown)
                .with_liveness_probe(liveness);
            let req = DrainRequest {
                tenant: tenant.as_str(),
                deployment_id,
                bundle_id,
                revision_id,
                drain_seconds,
            };
            if let Err(err) = coord.run(req).await {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "drain coordinator for revision {revision_id} of \
                         deployment {deployment_id} returned an error: {err}"
                    ),
                );
            }
        });
    }
}

/// What [`RevisionServer::reload`] returns so the producer can log / emit
/// telemetry describing the transition without re-reading the dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReloadReport {
    pub prev_deployments: usize,
    pub prev_revisions: usize,
    pub new_deployments: usize,
    pub new_revisions: usize,
}

/// A running revision ingress server on its own thread + Tokio runtime, mirroring
/// the legacy ingress's lifecycle so `run_start` can `stop()` it on shutdown.
pub(crate) struct RevisionServer {
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<Result<()>>>,
    actual_port: u16,
    /// Shared state holding the [`ArcSwap`] activation slot. Kept here so
    /// [`reload`](Self::reload) can swap a new [`Activation`] in and
    /// [`counts`](Self::counts) can read the live snapshot.
    state: Arc<ServeState>,
    /// Handle to the listener thread's Tokio runtime. [`reload`](Self::reload)
    /// schedules the overlap-window drop of the previous activation on it so
    /// any async resources held by the old [`RunnerHost`] tear down on the
    /// same runtime that built them.
    runtime_handle: Handle,
    /// Serializes [`reload`](Self::reload) calls. Without it the
    /// `load_full(prev) → bump_generations → swap(new)` sequence is not
    /// atomic across concurrent producers: two reloads can both observe
    /// the same prev, both bump generations from it, then both swap — the
    /// second reload's generation bump is lost relative to the first's
    /// published activation, so cookies minted in the brief window the
    /// first reload was live still verify against the second's dispatcher.
    ///
    /// N2.2's file-watcher is a single producer today, but an admin HTTP
    /// reload signal (or any future second producer) would violate that
    /// invariant; guarding the swap primitive here means the type system
    /// cannot be tricked.
    reload_lock: std::sync::Mutex<()>,
    /// Per-deployment-id generation high-watermark, surviving across
    /// activations including ones that drop a deployment entirely.
    ///
    /// Without this map, a bump driven only by the previous dispatcher
    /// would miss deployments that disappeared from runtime-config: a
    /// remove → re-add sequence within cookie/pin TTL would mint a fresh
    /// dispatcher at the same generation the original served at, and
    /// cookies signed before the removal would still verify after the
    /// re-add. The watermark tombstones removed deployments so a re-added
    /// one always bumps past its prior generation.
    ///
    /// Updated by [`reload`](Self::reload) by absorbing both the previous
    /// and new activations on every swap. Initialized from the initial
    /// activation at [`start`](Self::start) so cookie invalidation works
    /// even on the very first reload after boot.
    generation_watermark: std::sync::Mutex<HashMap<DeploymentId, u64>>,
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
            slot: ArcSwap::new(config.activation),
            bound_addr: addr,
        });
        // Cloned into the listener thread; the original lives on as the
        // [`RevisionServer::state`] handle so [`reload`] / [`counts`] read the
        // same slot the running listener reads.
        let listener_state = Arc::clone(&state);

        let (tx, rx) = oneshot::channel();
        // The startup channel ships the Tokio runtime handle alongside the
        // bind result so [`reload`] can schedule the overlap-window drop of
        // the previous activation on the listener thread's runtime — the same
        // runtime any held async resources were built on.
        let (startup_tx, startup_rx) = mpsc::channel::<Result<Handle>>();
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
                let runtime_handle = runtime.handle().clone();
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
                    let _ = startup_tx.send(Ok(runtime_handle));
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
                                    let connection_state = listener_state.clone();
                                    // Caller-asserted identity (see `serve`) is only
                                    // honoured from loopback peers; capture it here.
                                    // `to_canonical` so an IPv4-mapped IPv6 peer
                                    // (`::ffff:127.0.0.1`, seen under an IPv6 bind)
                                    // still reads as loopback.
                                    let peer_is_loopback = peer.ip().to_canonical().is_loopback();
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
        let runtime_handle = startup_rx
            .recv()
            .context("failed to receive revision ingress startup result")??;

        // Seed the watermark from the initial activation so the very first
        // reload bumps generations off it — otherwise cookies signed against
        // the cold-start activation could survive a remove → re-add that
        // happens before any other reload has populated the watermark.
        let mut initial_watermark: HashMap<DeploymentId, u64> = HashMap::new();
        state
            .slot
            .load()
            .routing
            .dispatcher
            .absorb_into_watermark(&mut initial_watermark);

        Ok(Self {
            shutdown: Some(tx),
            handle: Some(handle),
            actual_port,
            state,
            runtime_handle,
            reload_lock: std::sync::Mutex::new(()),
            generation_watermark: std::sync::Mutex::new(initial_watermark),
        })
    }

    /// The port the server actually bound (may differ from the request if it was
    /// taken).
    pub(crate) fn actual_port(&self) -> u16 {
        self.actual_port
    }

    /// `(deployment_count, revision_count)` from a single snapshot of the
    /// live activation's dispatcher — the same source `/status` reads. Used
    /// by the startup banner and post-reload logging so banner and `/status`
    /// cannot disagree.
    pub(crate) fn counts(&self) -> (usize, usize) {
        self.state.slot.load().routing.dispatcher.counts()
    }

    /// Swap the live activation. Atomically replaces the slot so the next
    /// request reaches the new host + routing; every request that already
    /// snapshotted the previous activation (via [`ServeState::current`] at
    /// the top of [`serve`]) keeps running against it for the rest of its
    /// lifetime.
    ///
    /// The previous activation is held alive for `drain_window` on the
    /// listener thread's runtime so async resources owned by the old
    /// [`RunnerHost`] (timer-handle aborts, Redis connection manager drops,
    /// telemetry exporters) tear down on the same runtime that built them,
    /// not on a bare OS thread. After the window, the Arc is dropped — if no
    /// in-flight request still pins it, the host and its [`TenantRuntime`]s
    /// drop on the spot; otherwise the drop is deferred until the last
    /// request completes.
    ///
    /// This is the swap primitive the N2.2 file-watcher + reload signal
    /// producer calls. A `drain_window` of zero drops the previous
    /// activation immediately (only safe in tests, where the producer
    /// controls request scheduling).
    ///
    /// Per-deployment dispatcher generations are bumped against a
    /// server-level high-watermark BEFORE the swap (see
    /// [`crate::revision_dispatcher::RevisionDispatcher::bump_generations_from_watermark`]
    /// and [`Self::generation_watermark`]) so any stickiness cookie or
    /// session pin minted against an earlier activation is invalidated and
    /// the next request re-picks under the new traffic split. The
    /// watermark tracks every deployment id this server has ever seen,
    /// including ones that have been removed and re-added — so a
    /// remove → re-add rollback within cookie/pin TTL doesn't leak
    /// stickiness from before the removal.
    ///
    /// Holds the [`reload_lock`](Self::reload_lock) for the whole sequence
    /// so concurrent producers (file-watcher + admin signal) cannot race
    /// the `load_full(prev) → bump_generations → swap(new)` steps and
    /// lose a generation bump.
    pub(crate) fn reload(&self, new: Activation, drain_window: Duration) -> ReloadReport {
        // Serialize concurrent reloads so the load_full + bump_generations
        // + swap sequence is atomic relative to other producers. See the
        // field doc on `reload_lock`.
        let _reload_guard = self.reload_lock.lock().expect("reload lock poisoned");
        let new_arc = Arc::new(new);
        // Snapshot the previous activation BEFORE publishing the new one so
        // the dispatcher generation bump runs against a stable reference.
        // `swap` would also return the prev pointer atomically with the
        // store, but doing the bump first means we publish a dispatcher
        // whose generations are already correct for the very first
        // dispatch under the new activation.
        let prev = self.state.slot.load_full();
        // `SlotLivenessProbe` (the drain path's stale-eviction guard) relies
        // on every reload publishing a freshly-built dispatcher `Arc`, so it
        // can use `Arc::ptr_eq` to tell the OLD dispatcher apart from the
        // live one. Assert that invariant here: if a future optimization ever
        // reuses a dispatcher `Arc` across reloads, this fails loudly in tests
        // rather than silently breaking eviction telemetry.
        debug_assert!(
            !Arc::ptr_eq(&prev.routing.dispatcher, &new_arc.routing.dispatcher),
            "reload must build a fresh dispatcher Arc (SlotLivenessProbe ptr_eq guard depends on it)"
        );
        // Update the generation watermark and bump the new dispatcher off
        // it. Absorbing prev → bump new → absorb new keeps the watermark
        // strictly monotonic across every deployment id we've ever served
        // (including ids that have been removed), so a re-introduced id
        // always lands at a generation strictly greater than any cookie/pin
        // could still be holding.
        {
            let mut watermark = self
                .generation_watermark
                .lock()
                .expect("generation watermark lock poisoned");
            prev.routing
                .dispatcher
                .absorb_into_watermark(&mut watermark);
            new_arc
                .routing
                .dispatcher
                .bump_generations_from_watermark(&watermark);
            new_arc
                .routing
                .dispatcher
                .absorb_into_watermark(&mut watermark);
        }
        // Diff OLD vs NEW revision sets BEFORE the swap, so the drain
        // coordinator (below) runs against a stable snapshot of "what was
        // serving until now" — independent of the publish ordering.
        let removed = removed_revisions(&prev.routing.dispatcher, &new_arc.routing.dispatcher);
        let (new_deployments, new_revisions) = new_arc.routing.dispatcher.counts();
        let prev = self.state.slot.swap(new_arc);
        let (prev_deployments, prev_revisions) = prev.routing.dispatcher.counts();
        // Fire one drain coordinator per removed revision against the OLD
        // activation. The coordinator marks the revision draining on OLD's
        // dispatcher (cookie/pin holders re-dispatch immediately), waits
        // `drain_window`, then evicts it from OLD's routing table — emitting
        // `RolloutEvent::RevisionDraining` + `RevisionEvicted` along the way.
        // The teardown is a no-op: the OLD activation drops wholesale at the
        // bottom of this fn after `drain_window`, taking the `RunnerHost`'s
        // `ActivePacks` with it. A real `ActivePacks::remove_revision` adapter
        // is the Phase D follow-up (see `revision_drain` module docs).
        if !removed.is_empty() && !drain_window.is_zero() {
            spawn_revision_drains(
                &self.runtime_handle,
                Arc::clone(&self.state),
                Arc::clone(&prev),
                removed,
                drain_window,
            );
        }
        if drain_window.is_zero() {
            drop(prev);
        } else {
            self.runtime_handle.spawn(async move {
                tokio::time::sleep(drain_window).await;
                drop(prev);
            });
        }
        ReloadReport {
            prev_deployments,
            prev_revisions,
            new_deployments,
            new_revisions,
        }
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

    if let Some(response) = try_probe_response(&path, &state) {
        return Ok(response);
    }

    // Worker-invoke gateway contract: a HostWorker gateway (e.g. greentic-gui's
    // `HttpWorkerBackend`) POSTs a `HostWorkerRequest` here and expects a
    // `HostWorkerResponse`. Handled before deployment-route resolution because a
    // broad `/`-prefix route binding would otherwise match `/workers/invoke` and
    // run it as a generic entry-flow activity.
    if path == "/workers/invoke" {
        if method != hyper::Method::POST {
            return Err(error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "worker invoke requires POST",
            ));
        }
        return handle_worker_invoke(req, Arc::clone(&state), peer_is_loopback).await;
    }

    // Snapshot the activation ONCE per request so dispatch and execute see a
    // coherent (host, routing) pair. A concurrent [`RevisionServer::reload`]
    // swap is observed by the *next* request; this one keeps running against
    // the activation it pinned here.
    let activation = state.current();

    let host_header = header_str(req.headers(), header::HOST.as_str());
    let cookie_header = header_str(req.headers(), header::COOKIE.as_str());
    let user_header = header_str(req.headers(), "x-greentic-user");
    let session_header = header_str(req.headers(), "x-greentic-session");
    let endpoint_header = header_str(req.headers(), "x-greentic-messaging-endpoint-id");
    // M1 IID.4d wrapper: collect routing-relevant request headers BEFORE
    // `read_body_limited` consumes `req`. The resolver uses these to give
    // header-discriminated providers (Telegram via secret-token) the same
    // identify-instance call shape that body-discriminated providers use.
    let identify_headers = identify_payload::collect_identify_headers(req.headers());
    // Phase D.3: collect every request header + the raw query string here
    // too, BEFORE the body read consumes `req`. The `ProviderRoute` arm
    // forwards them verbatim to the provider component (via `HttpInV1`) so
    // that signature-verifying providers (Slack, GitHub, etc.) see the
    // exact request the upstream sent.
    let request_headers = collect_forwarded_request_headers(req.headers());
    let query_string = req.uri().query().map(str::to_string);

    // Resolve the bound deployment + tenant before touching the body, so an
    // unroutable request is rejected cheaply.
    let (deployment_id, tenant) = activation
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
    // The messaging endpoint id (M1.4) partitions sessions/telemetry per
    // provider instance — header-only, never from the body.
    //
    // `header_endpoint_id` is the eid the caller pinned via header (loopback
    // only). The eid that flows into the activity is decided AFTER dispatch,
    // by the M1 IID.4 resolver: header wins when present, otherwise the
    // resolver asks each enabled provider component to identify itself from
    // the payload. See [`endpoint_resolver::resolve`].
    let (user, session_hint, header_endpoint_id) = caller_identity(
        peer_is_loopback,
        user_header,
        session_header,
        endpoint_header,
        &payload,
    );

    // M1.4c-ii admit gate, step 1: if the caller asserts a messaging endpoint,
    // it MUST be one this env declared. Resolved here (before dispatch) so an
    // unknown asserted endpoint refuses cheaply; the actual bundle-membership
    // check is step 2, after dispatch picks a revision. Resolver-derived eids
    // (no header asserted) re-resolve admission post-dispatch — see below.
    let header_admission = resolve_endpoint_admission(
        header_endpoint_id.as_deref(),
        activation.routing.endpoint_admit.as_ref(),
    )
    .map_err(|boxed| *boxed)?;

    let cookie_value = cookie_header
        .as_deref()
        .and_then(|jar| read_cookie(jar, &cookie_name(deployment_id)));

    let dispatch_req = DispatchRequest {
        env_id: activation.routing.dispatcher.env_id(),
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
    let outcome = activation
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

    // Bind the dispatched revision tuple once. Both the resolver (below)
    // and `admit_request` (further down) consume it; sharing one binding
    // makes the "every downstream step operates on the same revision"
    // invariant visible at the call site.
    let scope = RevisionScope {
        deployment_id,
        bundle_id: outcome.bundle_id.clone(),
        revision_id: outcome.revision_id,
    };

    // M1 IID.4 resolver: dispatch has picked a revision; ask each enabled
    // provider component (one probe per declared `provider_type`) to
    // identify this payload, and fold the per-type results against the
    // env's `(provider_type, provider_id) → endpoint_id` table.
    //
    // Placement: AFTER dispatch (the host method is revision-scoped — it
    // loads the picked revision's pack runtime to find the component
    // bindings), BEFORE the post-dispatch admit step (so a resolver Hit
    // re-resolves admission against the chosen eid).
    //
    // Trust boundary: `peer_is_loopback` gates the resolver the same way
    // `caller_identity` gates the header path. Without this gate, a remote
    // caller posting a forged webhook payload with a discriminator the
    // provider component identifies (e.g. a Teams serviceUrl for bot X)
    // would derive an endpoint and cross-contaminate sessions/welcome-flows.
    // The resolver short-circuits to `PublicSkipped` for non-loopback peers.
    // M1 IID.4d wrapper: pass `{headers, body}` instead of raw body bytes so
    // providers whose discriminator lives in HTTP headers (Telegram) can
    // identify the instance the same way body-based providers do (Teams,
    // Slack, etc.). Build LAZILY — the resolver short-circuits without
    // touching the payload on public traffic, header-pinned eids, and
    // no-endpoint envs, so most requests skip the body clone + re-serialize.
    let resolution = endpoint_resolver::resolve(
        &activation.host,
        &tenant,
        &scope,
        activation.routing.endpoint_admit.as_ref(),
        header_endpoint_id.as_deref(),
        peer_is_loopback,
        || identify_payload::build_identify_payload(&identify_headers, &payload),
    )
    .await
    .map_err(|err| {
        operator_log::warn(
            module_path!(),
            format!(
                "messaging-endpoint resolver failed for deployment {deployment_id} \
                 revision {}: {err:#}",
                outcome.revision_id
            ),
        );
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "messaging-endpoint resolution failed",
        )
    })?;

    // `gt.endpoint_resolution` telemetry — emitted as a structured event
    // with snake_case field names (tracing's macro grammar can't take
    // dotted field names directly). Operators converting these to
    // `gt.*` attribute form do it at the subscriber layer (the
    // `tracing-opentelemetry` bridge namespaces by event target). The
    // downstream flow span carries `gt.messaging_endpoint_id` via the
    // activity (M1.4 runner-host); this pair lets operators see "did the
    // eid come from a trusted header, the resolver, or fall through".
    tracing::info!(
        target: "greentic_start::endpoint_resolver",
        endpoint_resolution = resolution.origin(),
        messaging_endpoint_id = resolution.endpoint_id().unwrap_or(""),
        "messaging-endpoint resolution outcome",
    );

    // Ambiguous is the only resolver outcome that refuses the request
    // outright: env declares ≥2 endpoints of a `provider_type` and the
    // component returned NoMatch (or multiple distinct hits) — silently
    // routing to "the" endpoint would mis-attribute traffic.
    if matches!(resolution, endpoint_resolver::ResolverOutcome::Ambiguous) {
        return Err(error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "messaging endpoint resolution is ambiguous; assert the endpoint via \
             x-greentic-messaging-endpoint-id",
        ));
    }

    let endpoint_id: Option<String> = resolution.endpoint_id().map(str::to_string);

    // M1.4c-ii admit gate, step 2: now that dispatch + resolver have
    // converged on an eid (header- or resolver-derived) and a revision, the
    // resolved bundle MUST be in that endpoint's `linked_bundles` ACL.
    // `header_admission` covers the header-asserted path; resolver hits
    // re-resolve here against the freshly-resolved eid. Skipped when
    // neither path yielded an eid (legacy single-instance back-compat).
    let admission = match endpoint_id.as_deref() {
        Some(eid) if header_endpoint_id.is_none() => {
            resolve_endpoint_admission(Some(eid), activation.routing.endpoint_admit.as_ref())
                .map_err(|boxed| *boxed)?
        }
        _ => header_admission,
    };
    check_bundle_admission(&admission, outcome.bundle_id.as_str()).map_err(|boxed| *boxed)?;

    // Gate before executing: invoke the provider webhook directly (Phase D.3)
    // for declared provider routes, and refuse non-POST generic requests.
    match admit_request(&activation.routing.http_routes, &scope, &path, &method) {
        Admission::ProviderRoute => {
            return dispatch_provider_route(
                Arc::clone(&activation),
                &tenant,
                deployment_id,
                outcome.bundle_id.clone(),
                outcome.revision_id,
                &scope,
                &path,
                method.as_str(),
                query_string.as_deref(),
                &request_headers,
                &body_bytes,
            )
            .await;
        }
        Admission::MethodNotAllowed => {
            return Err(error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "only POST is supported for the generic revision ingress",
            ));
        }
        Admission::Serve => {}
    }

    // M1.5 welcome-flow override (attach side). The runner-host gates the
    // override on a durable first-contact marker (greentic-runner#382), so
    // attaching the hint on every turn is safe: post-completion / no-wait /
    // TTL-expiry turns no longer re-fire. The hint is also bundle-scoped
    // because dispatch may have picked a different bundle than the welcome
    // ref points at (endpoints can `linked_bundles` more than one bundle);
    // running B's flow on A's revision would either misroute or 500.
    let welcome_hint = resolve_welcome_flow_hint(
        endpoint_id.as_deref(),
        &outcome.bundle_id,
        &activation.routing.endpoint_admit,
    );

    let activity = build_activity(
        &payload,
        &tenant,
        user.as_deref(),
        session_hint.as_deref(),
        endpoint_id.as_deref(),
        welcome_hint,
    );

    let replies = activation
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

/// `POST /workers/invoke` payload, mirroring
/// `greentic_interfaces_host::worker::HostWorkerRequest` (the envelope a
/// HostWorker gateway such as greentic-gui's `HttpWorkerBackend` posts). Defined
/// locally so the runtime need not depend on the interfaces-host crate just to
/// (de)serialize a JSON contract; the field names and [`greentic_types::TenantCtx`]
/// are shared, so the wire form matches. Unknown fields (e.g. `timestamp_utc`,
/// `version`) are ignored.
#[derive(serde::Deserialize)]
struct WorkerInvokeRequest {
    #[serde(default)]
    version: String,
    tenant: greentic_types::TenantCtx,
    #[serde(default)]
    worker_id: String,
    #[serde(default)]
    payload: Value,
    #[serde(default)]
    correlation_id: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    thread_id: Option<String>,
}

/// One reply message, mirroring `HostWorkerMessage`.
#[derive(serde::Serialize)]
struct WorkerInvokeMessage {
    kind: String,
    payload: Value,
}

/// `POST /workers/invoke` response, mirroring `HostWorkerResponse` so the
/// gateway's `resp.json::<HostWorkerResponse>()` round-trips.
#[derive(serde::Serialize)]
struct WorkerInvokeResponse {
    version: String,
    tenant: greentic_types::TenantCtx,
    worker_id: String,
    timestamp_utc: String,
    messages: Vec<WorkerInvokeMessage>,
    correlation_id: Option<String>,
    session_id: Option<String>,
    thread_id: Option<String>,
}

/// Handle `POST /workers/invoke`: resolve the deployment for the asserted tenant,
/// dispatch a revision, run the payload as an [`Activity`], and return the reply
/// activities mapped into a `HostWorkerResponse`-shaped body.
///
/// Loopback-only: the contract trusts the caller-asserted tenant/user/session,
/// so it accepts only co-located gateways (e.g. greentic-gui on the same host).
/// A remote, authenticated gateway is the Phase-D upgrade — mirrors the
/// loopback identity posture of the generic ingress (`caller_identity`).
async fn handle_worker_invoke(
    req: Request<Incoming>,
    state: Arc<ServeState>,
    peer_is_loopback: bool,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    if !peer_is_loopback {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "worker invoke is restricted to loopback callers",
        ));
    }

    let activation = state.current();

    let body_bytes = read_body_limited(req).await.map_err(|_| {
        error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body exceeds the size limit",
        )
    })?;
    let worker_req: WorkerInvokeRequest = serde_json::from_slice(&body_bytes).map_err(|err| {
        error_response(
            StatusCode::BAD_REQUEST,
            format!("invalid HostWorkerRequest body: {err}"),
        )
    })?;

    // Resolve the deployment by the asserted tenant (lone-deployment fallback for
    // the common local case), then execute under the deployment's OWN tenant.
    let (deployment_id, tenant) = activation
        .routing
        .deployment_routes
        .resolve_worker(worker_req.tenant.tenant_id.as_str())
        .map(|(id, tenant)| (id, tenant.to_string()))
        .ok_or_else(|| {
            error_response(
                StatusCode::NOT_FOUND,
                "no active deployment resolves for the requested tenant",
            )
        })?;

    let session_hint = worker_req.session_id.clone();
    let dispatch_req = DispatchRequest {
        env_id: activation.routing.dispatcher.env_id(),
        tenant: &tenant,
        deployment_id,
        session_hint: session_hint.as_deref(),
        trusted: false,
        header_revision: None,
        cookie: None,
    };
    let mut rng: rand::rngs::SmallRng = rand::make_rng();
    let outcome = activation
        .routing
        .dispatcher
        .dispatch(&dispatch_req, &mut rng)
        .await
        .map_err(|err| {
            operator_log::warn(
                module_path!(),
                format!("worker-invoke dispatch for deployment {deployment_id} failed: {err:#}"),
            );
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "revision dispatch failed",
            )
        })?;

    let user = worker_req
        .tenant
        .user_id
        .as_ref()
        .map(|u| u.as_str().to_string());
    let flow_payload = normalize_worker_payload(&worker_req.payload);
    let activity = build_activity(
        &flow_payload,
        &tenant,
        user.as_deref(),
        session_hint.as_deref(),
        None,
        None,
    );

    let replies = activation
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
                    "worker-invoke execution failed for deployment {deployment_id} revision {}: {err:#}",
                    outcome.revision_id
                ),
            );
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "flow execution failed")
        })?;

    let messages = replies.iter().map(activity_to_worker_message).collect();
    let response = WorkerInvokeResponse {
        version: if worker_req.version.is_empty() {
            "1.0.0".to_string()
        } else {
            worker_req.version
        },
        tenant: worker_req.tenant,
        worker_id: worker_req.worker_id,
        timestamp_utc: chrono::Utc::now().to_rfc3339(),
        messages,
        correlation_id: worker_req.correlation_id,
        session_id: worker_req.session_id,
        thread_id: worker_req.thread_id,
    };
    let body = serde_json::to_vec(&response)
        .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(json_response(StatusCode::OK, body))
}

/// Map a runner reply [`Activity`] into a worker message. A rendered Adaptive
/// Card becomes an `adaptive-card` message carrying the card JSON; a reply with
/// a `text` field becomes a `text` message; anything else passes the activity
/// payload through under a generic `activity` kind.
///
/// A node that pauses for user input (`session.wait`, e.g. a card menu whose
/// buttons drive conditional routing) returns its rendered output wrapped in a
/// `{"status":"pending","response":{...}}` envelope. The card the user must see
/// lives in `response`, so unwrap a pending envelope first — otherwise the
/// menu (and every intermediate waiting card) would surface as an opaque
/// `activity` and never render.
fn activity_to_worker_message(activity: &Activity) -> WorkerInvokeMessage {
    let raw = activity.payload();
    let payload = match raw.get("status").and_then(Value::as_str) {
        Some("pending") => raw.get("response").unwrap_or(raw),
        _ => raw,
    };
    if let Some(card) = payload.get("renderedCard") {
        WorkerInvokeMessage {
            kind: "adaptive-card".to_string(),
            payload: card.clone(),
        }
    } else if payload.get("text").is_some() {
        WorkerInvokeMessage {
            kind: "text".to_string(),
            payload: payload.clone(),
        }
    } else {
        WorkerInvokeMessage {
            kind: "activity".to_string(),
            payload: payload.clone(),
        }
    }
}

/// Shape a worker-invoke payload for the flow engine's routing context.
///
/// The engine synthesises the `response.*` object that conditional routes test
/// (e.g. `response.action == "about_card"`) from the activity's
/// `entry.metadata.*`. A typed chat message arrives as `{"text": "..."}` and
/// already drives `response.text`, so it passes through untouched. An Adaptive
/// Card `Action.Submit` instead posts its `data` verbatim (e.g.
/// `{"action": "about_card"}`) with no `text` — lift such a payload under
/// `metadata` so a card button navigates the flow, mirroring how the legacy
/// messaging adapters surface submit data. Non-object, empty, or `text`
/// payloads are returned unchanged.
fn normalize_worker_payload(payload: &Value) -> Value {
    match payload {
        Value::Object(map) if !map.is_empty() && !map.get("text").is_some_and(Value::is_string) => {
            serde_json::json!({ "metadata": payload.clone() })
        }
        _ => payload.clone(),
    }
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
    endpoint: Option<&str>,
    welcome_hint: Option<WelcomeFlowHint>,
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
    if let Some(endpoint) = endpoint {
        activity = activity.with_messaging_endpoint(endpoint);
    }
    if let Some(hint) = welcome_hint {
        activity = activity.with_welcome_flow_hint(hint);
    }
    activity
}

/// Resolve the M1.5 welcome-flow hint for a request, projecting the
/// admit-table's bundle-scoped lookup into the runner-host `WelcomeFlowHint`
/// shape. Runner-host gates the override on a first-contact marker, so
/// attaching on every matching turn is safe (greentic-runner#382).
///
/// See [`EndpointAdmit::welcome_flow_for_bundle`] for the invariant the
/// bundle-scoped lookup enforces.
///
/// [`EndpointAdmit::welcome_flow_for_bundle`]: crate::endpoint_admit::EndpointAdmit::welcome_flow_for_bundle
fn resolve_welcome_flow_hint(
    endpoint_id: Option<&str>,
    dispatched_bundle: &BundleId,
    admit: &crate::endpoint_admit::EndpointAdmit,
) -> Option<WelcomeFlowHint> {
    endpoint_id
        .and_then(|eid| admit.welcome_flow_for_bundle(eid, dispatched_bundle))
        .map(|ref_| WelcomeFlowHint {
            pack_id: ref_.pack_id.as_str().to_string(),
            flow_id: ref_.flow_id.clone(),
        })
}

/// Resolve the caller-asserted identity tuple, honouring it **only from
/// loopback peers**. Header wins over body for `(user, session)`.
///
/// The legacy webchat/DirectLine ingress likewise derives identity from the
/// unauthenticated client request, so on loopback this matches the existing
/// posture. But this path has no authentication, so a non-loopback caller must
/// not be able to assert another user's identity — which would let it resume
/// that user's waiting flow or key its session — nor poison revision stickiness
/// via a chosen session hint. Remote callers therefore run anonymously with no
/// session hint (the HMAC-signed stickiness cookie, which they cannot forge,
/// still works). A verified provider/DirectLine token is the Phase-D upgrade.
///
/// The messaging endpoint id (M1.4) is **header-only**, never read from the
/// body even on loopback. It is an operational routing decision (which provider
/// instance owns this request) that partitions sessions/telemetry per endpoint;
/// reading it from the attacker-controlled payload would let a body-supplied
/// endpoint id route a request to the wrong endpoint and pin the wrong session.
fn caller_identity(
    peer_is_loopback: bool,
    user_header: Option<String>,
    session_header: Option<String>,
    endpoint_header: Option<String>,
    payload: &Value,
) -> (Option<String>, Option<String>, Option<String>) {
    if !peer_is_loopback {
        return (None, None, None);
    }
    let user = user_header.or_else(|| str_field(payload, "user"));
    let session = session_header.or_else(|| str_field(payload, "session"));
    let endpoint = endpoint_header.and_then(validate_endpoint_id);
    (user, session, endpoint)
}

/// Validate a producer-asserted messaging endpoint id. Returns `Some(id)`
/// only for ASCII identifiers matching `[A-Za-z0-9_.-]{1,128}` — the
/// grammar that covers both the M1.2 ULID form and a hand-typeable slug
/// (`teams-legal`). Anything else collapses to `None` so the runner runs
/// unscoped rather than partitioning into a corrupt bucket. No
/// whitespace-trimming — a producer that sends incidental whitespace has
/// a bug we shouldn't mask; reject and let them fix it.
///
/// This defends the canonicalize-layer `ep=<eid>::<base>` session prefix:
/// * an empty value (e.g. `X-Greentic-Messaging-Endpoint-Id:` with no
///   body) would collapse all malformed-header traffic into one
///   `ep=::<base>` namespace, losing endpoint isolation;
/// * a value containing `:` (the prefix delimiter) would collide with
///   other endpoint/base pairs — `eid="a"+base="b::c"` and
///   `eid="a::b"+base="c"` both produce `ep=a::b::c`;
/// * control characters / unbounded length would corrupt downstream
///   session-store keys and telemetry attribute values.
fn validate_endpoint_id(raw: String) -> Option<String> {
    if raw.is_empty() || raw.len() > 128 {
        return None;
    }
    if !raw
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return None;
    }
    Some(raw)
}

/// Outcome of the M1.4c-ii pre-dispatch endpoint admit lookup.
///
/// `NotAsserted` is "no header on this request, gate is dormant"; `Resolved`
/// carries the asserted endpoint's `linked_bundles` ACL so the post-dispatch
/// step ([`check_bundle_admission`]) can deny when the dispatched bundle is
/// outside it. Built by [`resolve_endpoint_admission`].
#[derive(Debug)]
enum EndpointAdmission<'a> {
    NotAsserted,
    Resolved(&'a std::collections::HashSet<String>),
}

/// M1.4c-ii admit gate, step 1: resolve the caller-asserted endpoint id
/// against the env's declared endpoints. Pure, called from [`serve`] before
/// dispatch so an unknown endpoint refuses cheaply (`UNAUTHORIZED`) rather
/// than burning a dispatch + load on a request that will fail step 2 anyway.
///
/// The Err variant is boxed because `hyper::Response<Full<Bytes>>` is ~144
/// bytes — matching [`dispatch_bound_deployment`] in `http_ingress` and the
/// Phase-B "Box large HTTP Response in Result Err" precedent.
fn resolve_endpoint_admission<'a>(
    endpoint_id: Option<&str>,
    admit: &'a crate::endpoint_admit::EndpointAdmit,
) -> Result<EndpointAdmission<'a>, Box<Response<Full<Bytes>>>> {
    let Some(eid) = endpoint_id else {
        return Ok(EndpointAdmission::NotAsserted);
    };
    match admit.linked_bundles(eid) {
        Some(acl) => Ok(EndpointAdmission::Resolved(acl)),
        None => Err(Box::new(error_response(
            StatusCode::UNAUTHORIZED,
            "messaging endpoint not recognized in this environment",
        ))),
    }
}

/// M1.4c-ii admit gate, step 2: once dispatch picked a revision, refuse when
/// the resolved bundle is not in the endpoint's `linked_bundles` ACL. Pure,
/// called from [`serve`]. `NotAsserted` short-circuits to `Ok` (no header was
/// asserted, no ACL applies).
fn check_bundle_admission(
    admission: &EndpointAdmission<'_>,
    bundle_id: &str,
) -> Result<(), Box<Response<Full<Bytes>>>> {
    let EndpointAdmission::Resolved(acl) = admission else {
        return Ok(());
    };
    if acl.contains(bundle_id) {
        Ok(())
    } else {
        Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "this messaging endpoint is not authorized to route to the resolved bundle",
        )))
    }
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
    let header_value = directive.to_header_value();
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

/// `/livez`, `/readyz`, `/healthz`, `/health` return `200 ok`; `/status`
/// returns the diagnostics JSON. Returns `None` for non-probe paths so the
/// caller falls through to routing.
fn try_probe_response(path: &str, state: &ServeState) -> Option<Response<Full<Bytes>>> {
    if matches!(path, "/livez" | "/readyz" | "/healthz" | "/health") {
        return Some(text_response(StatusCode::OK, "ok"));
    }
    if path == "/status" {
        let activation = state.current();
        let (deployments_routed, revisions_active) = activation.routing.dispatcher.counts();
        let body = serde_json::json!({
            "schema": "greentic.status.v1",
            "env_id": activation.routing.dispatcher.env_id(),
            "listen_addr": state.bound_addr.to_string(),
            "bundles_active": activation.routing.deployment_routes.len(),
            "deployments_routed": deployments_routed,
            "revisions_active": revisions_active,
        });
        return Some(json_response(StatusCode::OK, body.to_string().into_bytes()));
    }
    None
}

/// Resolve the bind address for the revision ingress.
///
/// Precedence (lowest to highest, each layer wins over the previous):
/// 1. The spec default ([`DEFAULT_LISTEN_ADDR`], `127.0.0.1:8080`).
/// 2. The persisted `host_config.listen_addr` (set by `op env init` /
///    `op config set listen_addr`).
/// 3. `GREENTIC_GATEWAY_LISTEN_ADDR` — accepts a full `SocketAddr`
///    (`0.0.0.0:9090`) or a bare `IpAddr` (`0.0.0.0`); for the bare-IP form
///    the port is taken from layer (1) or (2).
/// 4. `PORT` — port-only override matching the convention used by Heroku /
///    Cloud Run / Fly and the rest of the gateway configuration.
///
/// Operators set `host_config.listen_addr` once at env init; the env-vars
/// stay available for ad-hoc overrides (CI ports, local debugging) without
/// rewriting the env file.
pub(crate) fn resolve_bind_addr(host_config: Option<&EnvironmentHostConfig>) -> SocketAddr {
    let mut addr = host_config
        .map(EnvironmentHostConfig::resolved_listen_addr)
        .unwrap_or(DEFAULT_LISTEN_ADDR);

    if let Ok(raw) = std::env::var("GREENTIC_GATEWAY_LISTEN_ADDR") {
        let trimmed = raw.trim();
        // Empty / whitespace-only is treated as unset — many deployment
        // systems expose env-vars as empty strings to mean "use default";
        // a warning here would be noise.
        if !trimmed.is_empty() {
            if let Ok(sa) = trimmed.parse::<SocketAddr>() {
                addr = sa;
            } else if let Ok(ip) = trimmed.parse::<IpAddr>() {
                addr = SocketAddr::new(ip, addr.port());
            } else {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "GREENTIC_GATEWAY_LISTEN_ADDR={trimmed:?} is not a valid SocketAddr or IP; \
                         falling back to {addr}"
                    ),
                );
            }
        }
    }

    if let Ok(raw) = std::env::var("PORT") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            if let Ok(port) = trimmed.parse::<u16>() {
                addr.set_port(port);
            } else {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "PORT={trimmed:?} is not a valid u16; keeping port {}",
                        addr.port()
                    ),
                );
            }
        }
    }

    addr
}

/// Phase D.3 provider-route handler. Invokes the per-revision provider
/// component selected by the synthesized webhook route, parses its HTTP/event
/// envelope, forwards each emitted messaging envelope through the flow
/// runtime, and returns the provider's HTTP response verbatim to the upstream
/// caller (so signature-verifying providers see the round-trip they expect).
///
/// Legacy `greentic.http-routes.v1` routes (no synthesized `provider_type`)
/// are kept on the 501 path: D.3 only wires routes that came from
/// `greentic.provider-extension.v1` synthesis. A future revision can extend
/// to legacy routes once their dispatch contract is settled.
///
/// On provider-invocation error the request returns `502` so the upstream
/// retries; on parse/decode error we return `502` rather than `500` because
/// the failure originated in the downstream component's reply.
#[allow(clippy::too_many_arguments)]
async fn dispatch_provider_route(
    activation: Arc<Activation>,
    tenant: &str,
    deployment_id: DeploymentId,
    bundle_id: BundleId,
    revision_id: RevisionId,
    scope: &RevisionScope,
    path: &str,
    method: &str,
    query: Option<&str>,
    request_headers: &[(String, String)],
    body: &[u8],
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    let Some(route_match) = activation
        .routing
        .http_routes
        .match_request_for_revision(path, method, scope)
    else {
        // `admit_request` just confirmed a match, so this only fires if the
        // table swapped under us between admit and dispatch (or a test
        // misuses this helper). Return 500 so the upstream surfaces the
        // anomaly instead of silently re-running as a generic activity.
        return Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "provider route disappeared between admit and dispatch",
        ));
    };

    let Some(provider_type) = route_match.descriptor.provider_type.clone() else {
        return Err(error_response(
            StatusCode::NOT_IMPLEMENTED,
            "this path is a legacy http-routes.v1 route; Phase D.3 only \
             handles greentic.provider-extension.v1 synthesized routes",
        ));
    };
    let provider_op = route_match.descriptor.provider_op.clone();

    let http_in = build_provider_http_in(
        &provider_type,
        tenant,
        method,
        path,
        query,
        request_headers,
        body,
    );
    let input_json = serde_json::to_vec(&http_in).map_err(|err| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("encode HttpInV1 for provider {provider_type}: {err}"),
        )
    })?;

    let output = activation
        .host
        .invoke_provider_for_revision(
            tenant,
            deployment_id,
            bundle_id.clone(),
            revision_id,
            &provider_type,
            &provider_op,
            input_json,
            None,
            None,
        )
        .await
        .map_err(|err| {
            operator_log::error(
                module_path!(),
                format!(
                    "provider {provider_type} op {provider_op} failed for \
                     deployment {deployment_id} revision {revision_id}: {err:#}"
                ),
            );
            error_response(StatusCode::BAD_GATEWAY, "provider invocation failed")
        })?;

    let result = parse_dispatch_result(&output).map_err(|err| {
        operator_log::warn(
            module_path!(),
            format!(
                "provider {provider_type} op {provider_op} returned an undecodable \
                 envelope (deployment {deployment_id} revision {revision_id}): {err:#}"
            ),
        );
        error_response(
            StatusCode::BAD_GATEWAY,
            "could not decode provider response envelope",
        )
    })?;

    // Forward each emitted messaging envelope through the per-revision flow
    // runtime. Errors are logged but do NOT fail the HTTP response —
    // returning non-2xx would make the upstream (Telegram, Slack, …) retry
    // the webhook, which would then double-process. Mirroring the
    // legacy ingress posture in `dispatch_http_ingress`.
    for envelope in &result.messaging_envelopes {
        let activity = envelope_to_activity(envelope, tenant);
        if let Err(err) = activation
            .host
            .handle_activity_for_revision(
                tenant,
                deployment_id,
                bundle_id.clone(),
                revision_id,
                activity,
            )
            .await
        {
            operator_log::error(
                module_path!(),
                format!(
                    "forwarding provider event to flow runtime failed for \
                     deployment {deployment_id} revision {revision_id}: {err:#}"
                ),
            );
        }
    }

    Ok(synthesize_provider_response(&result.response))
}

/// Collect every request header into a `(name_lowercase, value_utf8)` list
/// suitable for embedding into [`HttpInV1::headers`]. Multi-value headers
/// produce one entry per occurrence. Headers whose value is not valid UTF-8
/// are dropped (the wire shape is JSON; surfacing a hard 500 here would let
/// a single malformed header take down an otherwise-valid webhook).
fn collect_forwarded_request_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            Some((
                name.as_str().to_ascii_lowercase(),
                value.to_str().ok()?.to_string(),
            ))
        })
        .collect()
}

/// Build the [`HttpInV1`] wire envelope a `greentic.provider-extension.v1`
/// component expects on `ingest_http`. Mirrors the shape the legacy ingress
/// builds in [`crate::ingress_dispatch::build_ingress_request`], minus the
/// pack-level config injection (Phase D revision-aware config injection is
/// follow-up work — components that need secrets read them from the host
/// directly today).
fn build_provider_http_in(
    provider: &str,
    tenant: &str,
    method: &str,
    path: &str,
    query: Option<&str>,
    headers: &[(String, String)],
    body: &[u8],
) -> HttpInV1 {
    HttpInV1 {
        v: 1,
        provider: provider.to_string(),
        route: None,
        binding_id: None,
        tenant_hint: Some(tenant.to_string()),
        team_hint: None,
        method: method.to_string(),
        path: path.to_string(),
        query: parse_query_pairs(query),
        headers: headers.to_vec(),
        body_b64: BASE64.encode(body),
        config: None,
    }
}

/// Split a raw query string (sans leading `?`) into `(key, value)` pairs.
/// Empty values are preserved as `""`; entries with no `=` keep an empty
/// value. No percent-decoding here — the provider components decode their
/// own keys (matching the legacy ingress contract).
fn parse_query_pairs(query: Option<&str>) -> Vec<(String, String)> {
    let Some(query) = query else {
        return Vec::new();
    };
    if query.is_empty() {
        return Vec::new();
    }
    query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (pair.to_string(), String::new()),
        })
        .collect()
}

/// Project a [`ChannelMessageEnvelope`] emitted by a provider component into
/// the runtime's [`Activity`] shape. Mirrors [`build_activity`]: a non-empty
/// `text` becomes a messaging activity, otherwise the whole envelope rides
/// as a `provider.event` custom activity so the flow can still inspect it.
fn envelope_to_activity(envelope: &ChannelMessageEnvelope, fallback_tenant: &str) -> Activity {
    let mut activity = match envelope.text.as_deref() {
        Some(text) if !text.is_empty() => Activity::text(text),
        _ => {
            let payload = serde_json::to_value(envelope).unwrap_or(Value::Null);
            Activity::custom("provider.event", payload)
        }
    };
    let envelope_tenant = envelope.tenant.tenant_id.as_str();
    let tenant = if envelope_tenant.is_empty() {
        fallback_tenant
    } else {
        envelope_tenant
    };
    activity = activity.with_tenant(tenant);
    if !envelope.session_id.is_empty() {
        activity = activity.with_session(&envelope.session_id);
    }
    if let Some(from) = envelope.from.as_ref()
        && !from.id.is_empty()
    {
        activity = activity.from_user(&from.id);
    }
    activity
}

/// Turn the provider's [`IngressHttpResponse`] back into a hyper response.
/// Status defaults to `200` when the provider omits it (a common convention
/// for "ack" webhooks). Headers that fail to parse as ASCII are dropped
/// rather than failing the whole response.
fn synthesize_provider_response(response: &IngressHttpResponse) -> Response<Full<Bytes>> {
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::OK);
    let body = response.body.clone().map(Bytes::from).unwrap_or_default();
    let mut builder = Response::builder().status(status);
    for (name, value) in &response.headers {
        // Skip headers that don't parse — surfacing them as a 500 would let
        // a single malformed reply header void an otherwise-correct webhook.
        if let Ok(header_name) = hyper::header::HeaderName::try_from(name.as_str())
            && let Ok(header_value) = hyper::header::HeaderValue::try_from(value.as_str())
        {
            builder = builder.header(header_name, header_value);
        }
    }
    builder
        .body(Full::new(body))
        .unwrap_or_else(|_| error_response(StatusCode::BAD_GATEWAY, "invalid provider response"))
}

#[cfg(test)]
mod tests {
    use super::*;
    // `BundleId` is used only in tests (prod refers to it via the `RevisionKey`
    // alias), so it lives here rather than in the library import set.
    use greentic_deploy_spec::WelcomeFlowRef;
    use greentic_deploy_spec::ids::BundleId;
    use greentic_runner_host::engine::runtime::{FlowResumeStore, IngressEnvelope};
    use greentic_runner_host::runner::engine::{ExecutionState, FlowSnapshot, FlowWait};
    use greentic_runner_host::storage::new_session_store;
    use greentic_types::ReplyScope;
    use serde_json::json;

    #[test]
    fn build_activity_text_field_becomes_messaging_activity() {
        let payload = json!({ "text": "hello there" });
        let activity = build_activity(&payload, "acme", Some("u1"), Some("s1"), None, None);
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
        let activity = build_activity(&payload, "acme", None, None, None, None);
        assert_eq!(activity.tenant(), Some("acme"));
        assert_eq!(activity.user(), None);
        assert_eq!(activity.session_id(), None);
        // The whole body is preserved for the entry flow to interpret.
        assert_eq!(activity.payload(), &payload);
    }

    #[test]
    fn build_activity_empty_body_is_a_null_custom_activity() {
        let activity = build_activity(&Value::Null, "acme", None, None, None, None);
        assert_eq!(activity.tenant(), Some("acme"));
        assert_eq!(activity.payload(), &Value::Null);
    }

    #[test]
    fn normalize_worker_payload_lifts_card_submit_into_metadata() {
        // An Adaptive Card Action.Submit posts its data verbatim with no `text`.
        let submit = json!({ "action": "about_card" });
        let shaped = normalize_worker_payload(&submit);
        assert_eq!(shaped, json!({ "metadata": { "action": "about_card" } }));

        // Through build_activity the action lands where the engine's routing
        // context reads it (`response.action` <- entry.metadata.action).
        let activity = build_activity(&shaped, "acme", None, Some("s1"), None, None);
        assert_eq!(
            activity
                .payload()
                .pointer("/metadata/action")
                .and_then(Value::as_str),
            Some("about_card")
        );
    }

    #[test]
    fn normalize_worker_payload_passes_text_through() {
        let typed = json!({ "text": "capabilities" });
        assert_eq!(normalize_worker_payload(&typed), typed);
    }

    #[test]
    fn normalize_worker_payload_passes_empty_and_non_object_through() {
        assert_eq!(normalize_worker_payload(&json!({})), json!({}));
        assert_eq!(normalize_worker_payload(&Value::Null), Value::Null);
        assert_eq!(normalize_worker_payload(&json!("hi")), json!("hi"));
    }

    #[test]
    fn activity_to_worker_message_maps_card_text_and_generic() {
        // A rendered Adaptive Card becomes an `adaptive-card` message carrying
        // the card JSON (not the wrapping payload).
        let card = json!({ "type": "AdaptiveCard", "version": "1.6" });
        let card_activity = Activity::custom("response", json!({ "renderedCard": card.clone() }));
        let msg = activity_to_worker_message(&card_activity);
        assert_eq!(msg.kind, "adaptive-card");
        assert_eq!(msg.payload, card);

        // A text reply becomes a `text` message preserving the `{text: …}` body.
        let text_activity = Activity::text("hello there");
        let msg = activity_to_worker_message(&text_activity);
        assert_eq!(msg.kind, "text");
        assert_eq!(
            msg.payload.get("text").and_then(Value::as_str),
            Some("hello there")
        );

        // Anything else passes the payload through under the generic kind.
        let other = Activity::custom("response", json!({ "n": 7 }));
        let msg = activity_to_worker_message(&other);
        assert_eq!(msg.kind, "activity");
        assert_eq!(msg.payload, json!({ "n": 7 }));
    }

    #[test]
    fn activity_to_worker_message_unwraps_pending_card() {
        // A paused (session.wait) menu node wraps its rendered card in a
        // pending envelope; the card must still surface as `adaptive-card`.
        let card = json!({ "type": "AdaptiveCard", "version": "1.6" });
        let pending = Activity::custom(
            "response",
            json!({
                "status": "pending",
                "reason": "awaiting user submit",
                "response": { "renderedCard": card.clone() }
            }),
        );
        let msg = activity_to_worker_message(&pending);
        assert_eq!(msg.kind, "adaptive-card");
        assert_eq!(msg.payload, card);
    }

    #[test]
    fn build_activity_plumbs_messaging_endpoint_id() {
        let payload = json!({ "text": "hello" });
        let activity = build_activity(
            &payload,
            "acme",
            Some("u1"),
            Some("s1"),
            Some("teams-legal"),
            None,
        );
        // Serialize to wire form to prove the field rides on the Activity —
        // there's no public accessor returning Option<&str> for the endpoint,
        // and the runner reads it through the same serde shape.
        let wire = serde_json::to_value(&activity).expect("serialize");
        assert_eq!(
            wire.get("messaging_endpoint_id").and_then(Value::as_str),
            Some("teams-legal")
        );
    }

    #[test]
    fn build_activity_plumbs_welcome_flow_hint() {
        let payload = json!({ "text": "hello" });
        let activity = build_activity(
            &payload,
            "acme",
            Some("u1"),
            Some("s1"),
            Some("teams-legal"),
            Some(WelcomeFlowHint {
                pack_id: "legal-pack".to_string(),
                flow_id: "welcome".to_string(),
            }),
        );
        assert_eq!(
            activity.welcome_flow_hint(),
            Some(&WelcomeFlowHint {
                pack_id: "legal-pack".to_string(),
                flow_id: "welcome".to_string(),
            })
        );
    }

    /// Build an `EndpointAdmit` populated with one endpoint and return both
    /// the on-wire endpoint id (the same string `serve` would resolve from
    /// the header) and the admit table.
    fn admit_with_endpoint(
        linked_bundles: Vec<BundleId>,
        welcome_flow: Option<WelcomeFlowRef>,
    ) -> (String, crate::endpoint_admit::EndpointAdmit) {
        use greentic_deploy_spec::{
            Environment, EnvironmentHostConfig, MessagingEndpoint, MessagingEndpointId,
            SchemaVersion,
        };
        use greentic_types::EnvId;
        let env_id = EnvId::try_from("local").unwrap();
        let endpoint_id = MessagingEndpointId::new();
        let wire_id = endpoint_id.to_string();
        let now = chrono::Utc::now();
        let endpoint = MessagingEndpoint {
            schema: SchemaVersion::new(SchemaVersion::MESSAGING_ENDPOINT_V1),
            env_id: env_id.clone(),
            endpoint_id,
            provider_id: "teams-legal".to_string(),
            provider_type: "teams".to_string(),
            display_name: "Legal".to_string(),
            secret_refs: Vec::new(),
            linked_bundles,
            welcome_flow,
            generation: 1,
            created_at: now,
            updated_at: now,
            updated_by: "test".to_string(),
        };
        let env = Environment {
            schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
            environment_id: env_id.clone(),
            name: "local".to_string(),
            host_config: EnvironmentHostConfig {
                env_id,
                region: None,
                tenant_org_id: None,
                listen_addr: None,
            },
            packs: Vec::new(),
            messaging_endpoints: vec![endpoint],
            credentials_ref: None,
            bundles: Vec::new(),
            revisions: Vec::new(),
            traffic_splits: Vec::new(),
            revocation: Default::default(),
            retention: Default::default(),
            health: Default::default(),
        };
        (
            wire_id,
            crate::endpoint_admit::EndpointAdmit::from_environment(&env),
        )
    }

    #[test]
    fn resolve_welcome_flow_hint_returns_hint_when_endpoint_declares_it() {
        use greentic_deploy_spec::{PackId, WelcomeFlowRef};
        let (wire_id, admit) = admit_with_endpoint(
            vec![BundleId::new("legal-bundle")],
            Some(WelcomeFlowRef {
                bundle_id: BundleId::new("legal-bundle"),
                pack_id: PackId::new("legal-pack"),
                flow_id: "welcome".to_string(),
            }),
        );

        assert_eq!(
            resolve_welcome_flow_hint(Some(&wire_id), &BundleId::new("legal-bundle"), &admit),
            Some(WelcomeFlowHint {
                pack_id: "legal-pack".to_string(),
                flow_id: "welcome".to_string(),
            })
        );
    }

    #[test]
    fn resolve_welcome_flow_hint_returns_none_without_endpoint() {
        // No endpoint asserted ⇒ no hint, even if some other endpoint in the
        // admit table has a welcome_flow declared.
        let admit = crate::endpoint_admit::EndpointAdmit::default();
        assert_eq!(
            resolve_welcome_flow_hint(None, &BundleId::new("any-bundle"), &admit),
            None
        );
    }

    #[test]
    fn resolve_welcome_flow_hint_returns_none_when_endpoint_has_no_welcome() {
        // Endpoint declared but `welcome_flow` unset ⇒ no hint. Same shape as
        // an unknown endpoint (the unknown-vs-unset split belongs at the admit
        // gate, not here).
        let admit = crate::endpoint_admit::EndpointAdmit::default();
        assert_eq!(
            resolve_welcome_flow_hint(Some("teams-legal"), &BundleId::new("any-bundle"), &admit),
            None
        );
    }

    #[test]
    fn resolve_welcome_flow_hint_returns_none_when_dispatched_bundle_differs() {
        // Multi-bundle endpoint: endpoint links bundles A and B, welcome ref
        // points at B. A request that dispatches to A MUST drop the hint —
        // running B's pack/flow on A's revision would either misroute or 500.
        // The deploy-spec only invariant is `welcome_flow.bundle_id ∈
        // linked_bundles`, NOT that dispatch lands on the welcome bundle.
        use greentic_deploy_spec::{PackId, WelcomeFlowRef};
        let (wire_id, admit) = admit_with_endpoint(
            vec![BundleId::new("bundle-a"), BundleId::new("bundle-b")],
            Some(WelcomeFlowRef {
                bundle_id: BundleId::new("bundle-b"),
                pack_id: PackId::new("legal-pack"),
                flow_id: "welcome".to_string(),
            }),
        );

        // Dispatch chose bundle A — welcome ref targets B ⇒ drop the hint.
        assert_eq!(
            resolve_welcome_flow_hint(Some(&wire_id), &BundleId::new("bundle-a"), &admit),
            None
        );
        // Dispatch chose bundle B — matches welcome ref ⇒ attach the hint.
        assert_eq!(
            resolve_welcome_flow_hint(Some(&wire_id), &BundleId::new("bundle-b"), &admit),
            Some(WelcomeFlowHint {
                pack_id: "legal-pack".to_string(),
                flow_id: "welcome".to_string(),
            })
        );
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
        let (user, session, endpoint) =
            caller_identity(true, Some("hdr-user".into()), None, None, &payload);
        assert_eq!(user.as_deref(), Some("hdr-user"));
        assert_eq!(session.as_deref(), Some("body-session"));
        assert!(endpoint.is_none());

        // Non-loopback: client-asserted identity is dropped entirely so a remote
        // caller cannot impersonate a user/session or pin a chosen revision.
        let (user, session, endpoint) = caller_identity(
            false,
            Some("hdr-user".into()),
            Some("hdr-session".into()),
            Some("teams-legal".into()),
            &payload,
        );
        assert_eq!(user, None);
        assert_eq!(session, None);
        assert!(endpoint.is_none());
    }

    #[test]
    fn caller_identity_returns_messaging_endpoint_from_loopback_header() {
        let payload = json!({});
        let (_, _, endpoint) =
            caller_identity(true, None, None, Some("teams-legal".into()), &payload);
        assert_eq!(endpoint.as_deref(), Some("teams-legal"));
    }

    #[test]
    fn caller_identity_never_reads_messaging_endpoint_from_body() {
        // Even on loopback, a body-supplied endpoint id must NOT be honoured.
        // Endpoint id is an operational routing decision, not user-asserted
        // identity; reading it from the payload would let an attacker pin a
        // chosen endpoint and partition into the wrong session bucket.
        let payload = json!({ "messaging_endpoint_id": "teams-attacker" });
        let (_, _, endpoint) = caller_identity(true, None, None, None, &payload);
        assert!(endpoint.is_none());
    }

    #[test]
    fn caller_identity_drops_messaging_endpoint_on_non_loopback() {
        // A remote caller cannot pin an endpoint id even via the header. The
        // verified-token Phase-D upgrade is the only way for remote ingress to
        // assert endpoint membership.
        let payload = json!({});
        let (_, _, endpoint) =
            caller_identity(false, None, None, Some("teams-legal".into()), &payload);
        assert!(endpoint.is_none());
    }

    #[test]
    fn caller_identity_silently_drops_malformed_endpoint_header() {
        // A loopback caller asserting a malformed endpoint id (empty, contains
        // the `:` prefix delimiter, control chars, over-length, etc.) gets the
        // unscoped path — never the `ep=::<base>` collapse or a colliding
        // `ep=a::b::c` bucket the runner cannot disambiguate.
        let payload = json!({});
        for raw in ["", "   ", "legal::accounting", "teams legal", "teams\n"] {
            let (_, _, endpoint) = caller_identity(true, None, None, Some(raw.into()), &payload);
            assert!(
                endpoint.is_none(),
                "header value {raw:?} should be rejected"
            );
        }
    }

    #[test]
    fn validate_endpoint_id_accepts_slug_and_ulid_forms() {
        assert_eq!(
            validate_endpoint_id("teams-legal".into()),
            Some("teams-legal".into())
        );
        assert_eq!(
            validate_endpoint_id("teams_legal.v2".into()),
            Some("teams_legal.v2".into())
        );
        // ULID (Crockford base32, 26 chars) — the M1.2 on-disk form.
        let ulid = "01HV3ZQXW8K0YBN8FXZ7P4M2R5";
        assert_eq!(validate_endpoint_id(ulid.into()), Some(ulid.into()));
    }

    #[test]
    fn validate_endpoint_id_rejects_empty_and_surrounding_whitespace() {
        // Empty header value fails the explicit empty check; surrounding
        // whitespace fails the grammar check (no trim, see fn docs).
        for raw in ["", "   ", "\t\n", "  teams-legal  "] {
            assert!(
                validate_endpoint_id(raw.into()).is_none(),
                "{raw:?} should reject"
            );
        }
    }

    #[test]
    fn validate_endpoint_id_rejects_prefix_delimiter() {
        // `:` is the `ep=<eid>::<base>` delimiter; any colon in eid would
        // make `ep=a::b::c` ambiguous (eid="a"+base="b::c" vs eid="a::b"+base="c").
        for raw in ["legal::accounting", "foo:bar"] {
            assert!(
                validate_endpoint_id(raw.into()).is_none(),
                "{raw:?} should reject"
            );
        }
    }

    #[test]
    fn validate_endpoint_id_rejects_control_chars_and_non_ascii() {
        for raw in [
            "teams\nlegal",
            "teams\0legal",
            "teams legal", // space
            "teams/legal",
            "команда", // non-ASCII
        ] {
            assert!(
                validate_endpoint_id(raw.into()).is_none(),
                "{raw:?} should reject"
            );
        }
    }

    #[test]
    fn validate_endpoint_id_rejects_over_length() {
        let too_long = "a".repeat(129);
        assert!(validate_endpoint_id(too_long).is_none());
        let max_ok = "a".repeat(128);
        assert_eq!(validate_endpoint_id(max_ok.clone()), Some(max_ok));
    }

    // --- M1.4c-ii endpoint admit gate ---------------------------------------

    #[test]
    fn resolve_admission_returns_not_asserted_when_no_endpoint_header() {
        let admit = crate::endpoint_admit::EndpointAdmit::default();
        let outcome =
            resolve_endpoint_admission(None, &admit).expect("no header is a clean pass-through");
        assert!(matches!(outcome, EndpointAdmission::NotAsserted));
    }

    #[test]
    fn resolve_admission_resolves_known_endpoint_to_its_acl() {
        // Round-trip through `from_environment` so the keying matches prod.
        use greentic_deploy_spec::{
            BundleId, Environment, EnvironmentHostConfig, MessagingEndpoint, MessagingEndpointId,
            SchemaVersion,
        };
        use greentic_types::EnvId;
        let env_id = EnvId::try_from("local").unwrap();
        let endpoint_id = MessagingEndpointId::new();
        let wire_id = endpoint_id.to_string();
        let now = chrono::Utc::now();
        let endpoint = MessagingEndpoint {
            schema: SchemaVersion::new(SchemaVersion::MESSAGING_ENDPOINT_V1),
            env_id: env_id.clone(),
            endpoint_id,
            provider_id: "teams-legal".to_string(),
            provider_type: "teams".to_string(),
            display_name: "Legal".to_string(),
            secret_refs: Vec::new(),
            linked_bundles: vec![BundleId::new("legal-bundle")],
            welcome_flow: None,
            generation: 1,
            created_at: now,
            updated_at: now,
            updated_by: "test".to_string(),
        };
        let env = Environment {
            schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
            environment_id: env_id.clone(),
            name: "local".to_string(),
            host_config: EnvironmentHostConfig {
                env_id,
                region: None,
                tenant_org_id: None,
                listen_addr: None,
            },
            packs: Vec::new(),
            messaging_endpoints: vec![endpoint],
            credentials_ref: None,
            bundles: Vec::new(),
            revisions: Vec::new(),
            traffic_splits: Vec::new(),
            revocation: Default::default(),
            retention: Default::default(),
            health: Default::default(),
        };
        let admit = crate::endpoint_admit::EndpointAdmit::from_environment(&env);
        let outcome = resolve_endpoint_admission(Some(&wire_id), &admit).expect("known endpoint");
        match outcome {
            EndpointAdmission::Resolved(acl) => assert!(acl.contains("legal-bundle")),
            EndpointAdmission::NotAsserted => panic!("known endpoint must resolve to ACL"),
        }
    }

    #[test]
    fn resolve_admission_refuses_unknown_endpoint_with_401() {
        let admit = crate::endpoint_admit::EndpointAdmit::default();
        let err = resolve_endpoint_admission(Some("bogus"), &admit)
            .expect_err("unknown endpoint must refuse");
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn check_bundle_admission_skips_when_endpoint_not_asserted() {
        // The pre-dispatch step returned `NotAsserted` (no header) — the
        // post-dispatch check must be a no-op so legacy single-instance
        // traffic isn't accidentally gated.
        check_bundle_admission(&EndpointAdmission::NotAsserted, "any-bundle")
            .expect("no-header path must pass");
    }

    #[test]
    fn check_bundle_admission_allows_bundle_in_acl() {
        let mut acl = std::collections::HashSet::new();
        acl.insert("legal-bundle".to_string());
        acl.insert("shared-utils".to_string());
        check_bundle_admission(&EndpointAdmission::Resolved(&acl), "legal-bundle")
            .expect("bundle in ACL is admitted");
    }

    #[test]
    fn check_bundle_admission_rejects_bundle_outside_acl_with_403() {
        // This is the M1-the-accountant-cannot-reach-legal invariant: even
        // if routing resolves a bundle, the endpoint's ACL trumps it.
        let mut acl = std::collections::HashSet::new();
        acl.insert("finance-bundle".to_string());
        let err = check_bundle_admission(&EndpointAdmission::Resolved(&acl), "legal-bundle")
            .expect_err("out-of-ACL bundle must refuse");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn check_bundle_admission_empty_acl_rejects_every_bundle() {
        // A declared-but-unwired endpoint (empty `linked_bundles`) is
        // semantically "this endpoint can route to nothing yet" — every
        // bundle MUST fail closed, not pass through.
        let acl = std::collections::HashSet::new();
        let err = check_bundle_admission(&EndpointAdmission::Resolved(&acl), "any-bundle")
            .expect_err("empty ACL must refuse every bundle");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
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

    #[test]
    fn parse_query_pairs_splits_amp_separated_pairs() {
        let pairs = parse_query_pairs(Some("a=1&b=&c"));
        assert_eq!(
            pairs,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), String::new()),
                ("c".to_string(), String::new()),
            ]
        );
    }

    #[test]
    fn parse_query_pairs_handles_none_and_empty() {
        assert!(parse_query_pairs(None).is_empty());
        assert!(parse_query_pairs(Some("")).is_empty());
        // A leading separator is harmless — the empty segment is skipped.
        assert_eq!(
            parse_query_pairs(Some("&a=1")),
            vec![("a".to_string(), "1".to_string())]
        );
    }

    #[test]
    fn collect_forwarded_request_headers_lowercases_keys_and_keeps_multi_value() {
        use hyper::http::header::{HeaderName, HeaderValue};
        let mut map = HeaderMap::new();
        map.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );
        map.append(
            HeaderName::from_static("x-trace"),
            HeaderValue::from_static("a"),
        );
        map.append(
            HeaderName::from_static("x-trace"),
            HeaderValue::from_static("b"),
        );
        // Non-UTF8 values are silently dropped — see helper doc.
        map.insert(
            HeaderName::from_static("x-bad"),
            HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
        );
        let mut headers = collect_forwarded_request_headers(&map);
        headers.sort();
        assert_eq!(
            headers,
            vec![
                ("content-type".to_string(), "application/json".to_string()),
                ("x-trace".to_string(), "a".to_string()),
                ("x-trace".to_string(), "b".to_string()),
            ]
        );
    }

    #[test]
    fn build_provider_http_in_wires_fields_and_b64_body() {
        let headers = vec![("content-type".to_string(), "application/json".to_string())];
        let http_in = build_provider_http_in(
            "messaging.telegram.bot",
            "acme",
            "POST",
            "/webhook/telegram",
            Some("token=abc&n=1"),
            &headers,
            br#"{"update_id":42}"#,
        );
        assert_eq!(http_in.provider, "messaging.telegram.bot");
        assert_eq!(http_in.tenant_hint.as_deref(), Some("acme"));
        assert_eq!(http_in.method, "POST");
        assert_eq!(http_in.path, "/webhook/telegram");
        assert_eq!(http_in.headers, headers);
        assert_eq!(http_in.query.len(), 2);
        assert_eq!(http_in.body_b64, BASE64.encode(br#"{"update_id":42}"#));
    }

    #[test]
    fn envelope_to_activity_maps_text_and_identity() {
        let envelope: ChannelMessageEnvelope = serde_json::from_value(json!({
            "id": "msg-1",
            "tenant": {
                "env": "dev",
                "tenant": "acme",
                "tenant_id": "acme",
                "attempt": 0,
            },
            "channel": "telegram",
            "session_id": "sess-1",
            "from": { "id": "u1", "kind": "user" },
            "text": "hello",
            "metadata": {},
        }))
        .expect("envelope");
        let activity = envelope_to_activity(&envelope, "fallback");
        assert_eq!(activity.tenant(), Some("acme"));
        assert_eq!(activity.session_id(), Some("sess-1"));
        assert_eq!(activity.user(), Some("u1"));
        assert_eq!(activity.flow_type(), Some("messaging"));
        assert_eq!(
            activity.payload().get("text").and_then(Value::as_str),
            Some("hello"),
        );
    }

    #[test]
    fn envelope_to_activity_skips_empty_session_pin() {
        // Empty `session_id` keeps the activity unpinned — otherwise the
        // runtime buckets parallel callers under a single empty session key.
        let envelope: ChannelMessageEnvelope = serde_json::from_value(json!({
            "id": "msg-1",
            "tenant": {
                "env": "dev",
                "tenant": "acme",
                "tenant_id": "acme",
                "attempt": 0,
            },
            "channel": "telegram",
            "session_id": "",
            "metadata": {},
        }))
        .expect("envelope");
        let activity = envelope_to_activity(&envelope, "fallback");
        assert_eq!(activity.tenant(), Some("acme"));
        assert_eq!(activity.session_id(), None);
    }

    #[test]
    fn synthesize_provider_response_defaults_to_200_and_preserves_body() {
        let response = IngressHttpResponse {
            status: 0, // Not a real HTTP status — synth must fall back to 200.
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: Some(b"ok".to_vec()),
        };
        let out = synthesize_provider_response(&response);
        assert_eq!(out.status(), StatusCode::OK);
        assert_eq!(
            out.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("text/plain"),
        );
    }

    #[test]
    fn synthesize_provider_response_drops_malformed_headers() {
        let response = IngressHttpResponse {
            status: 202,
            // `"\n bad"` is not a valid header name — must be dropped, not 500.
            headers: vec![
                ("\n bad".to_string(), "x".to_string()),
                ("x-good".to_string(), "ok".to_string()),
            ],
            body: None,
        };
        let out = synthesize_provider_response(&response);
        assert_eq!(out.status(), StatusCode::ACCEPTED);
        assert!(out.headers().get("\n bad").is_none());
        assert_eq!(
            out.headers().get("x-good").and_then(|v| v.to_str().ok()),
            Some("ok"),
        );
    }

    #[test]
    fn admit_classifies_synthesized_webhook_for_root_bound_deployment() {
        // Regression guard: a root-bound deployment (empty `path_prefixes`)
        // owning an `ingest_http` provider must still classify
        // `POST /webhook/<provider>` as `ProviderRoute`. An earlier draft of
        // synthesis short-circuited on empty prefixes, which silently dropped
        // the gate and let public webhook POSTs fall through to generic flow
        // serving.
        let scope = test_scope();
        let dir = tempfile::tempdir().expect("tempdir");
        let pack_path = dir.path().join("telegram.gtpack");
        crate::http_routes::tests::write_provider_pack(
            &pack_path,
            "telegram-pack",
            "messaging.telegram.bot",
            &["ingest_http"],
        );

        let descriptors = crate::http_routes::synthesize_provider_ingest_routes(
            &[pack_path],
            &scope,
            &[], // root-bound deployment
        );
        assert_eq!(descriptors.len(), 1, "root-bound synthesis emits one route");
        let table = HttpRouteTable::from_descriptors(descriptors);

        assert_eq!(
            admit_request(&table, &scope, "/webhook/telegram", &hyper::Method::POST),
            Admission::ProviderRoute,
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
            messaging_endpoint_id: None,
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

    // --- N1.2: listen-address resolution ----------------------------------
    //
    // These tests mutate process env-vars; serialize via `test_env_lock` so
    // they don't race the other listen-addr/env tests in the crate.

    fn host_cfg_with(addr: Option<SocketAddr>) -> EnvironmentHostConfig {
        EnvironmentHostConfig {
            env_id: greentic_types::EnvId::new("local").unwrap(),
            region: None,
            tenant_org_id: None,
            listen_addr: addr,
        }
    }

    struct EnvVarGuard {
        gateway_prev: Option<std::ffi::OsString>,
        port_prev: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn clean() -> Self {
            let gateway_prev = std::env::var_os("GREENTIC_GATEWAY_LISTEN_ADDR");
            let port_prev = std::env::var_os("PORT");
            // SAFETY: callers hold `test_env_lock` so env mutation is serialized.
            unsafe {
                std::env::remove_var("GREENTIC_GATEWAY_LISTEN_ADDR");
                std::env::remove_var("PORT");
            }
            Self {
                gateway_prev,
                port_prev,
            }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            // SAFETY: callers hold `test_env_lock` so env mutation is serialized.
            unsafe {
                match &self.gateway_prev {
                    Some(v) => std::env::set_var("GREENTIC_GATEWAY_LISTEN_ADDR", v),
                    None => std::env::remove_var("GREENTIC_GATEWAY_LISTEN_ADDR"),
                }
                match &self.port_prev {
                    Some(v) => std::env::set_var("PORT", v),
                    None => std::env::remove_var("PORT"),
                }
            }
        }
    }

    // --- N1.2: probe surface ---------------------------------------------

    /// Build an [`Activation`] from a host + dispatcher, threading the
    /// other ingress-routing fields with their test-default empty values.
    /// Single source of the assembly so test fixtures (`empty_activation`,
    /// `populated_activation`, `activation_with_ids`) don't redeclare it.
    fn activation_for_test(
        host: std::sync::Arc<greentic_runner_host::RunnerHost>,
        dispatcher: crate::revision_dispatcher::RevisionDispatcher,
    ) -> Activation {
        Activation {
            host,
            routing: std::sync::Arc::new(RevisionIngressRouting {
                dispatcher: std::sync::Arc::new(dispatcher),
                http_routes: HttpRouteTable::from_descriptors(Vec::new()),
                deployment_routes: crate::deployment_routes::DeploymentRouteTable::default(),
                endpoint_admit: std::sync::Arc::new(crate::endpoint_admit::EndpointAdmit::default()),
            }),
        }
    }

    fn empty_activation(env_id: &str) -> Activation {
        use crate::revision_dispatcher::{RevisionDispatcher, RevisionDispatcherConfig};
        let host = std::sync::Arc::new(
            greentic_runner_host::HostBuilder::new()
                .with_config(greentic_runner_host::HostConfig::from_gtbind(
                    greentic_runner_host::TenantBindings {
                        tenant: env_id.to_string(),
                        packs: Vec::new(),
                        env_passthrough: Vec::new(),
                    },
                ))
                .build()
                .expect("build placeholder host"),
        );
        let dispatcher = RevisionDispatcher::new(RevisionDispatcherConfig::new(env_id, [0u8; 32]));
        activation_for_test(host, dispatcher)
    }

    fn empty_state(env_id: &str, bound: SocketAddr) -> ServeState {
        ServeState {
            slot: ArcSwap::new(std::sync::Arc::new(empty_activation(env_id))),
            bound_addr: bound,
        }
    }

    fn body_string(resp: Response<Full<Bytes>>) -> String {
        // `Full<Bytes>` carries its single chunk; `BodyExt::collect` is async,
        // so a current-thread runtime drives the (immediate) future.
        let body = resp.into_body();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime for test body collection");
        let collected = runtime.block_on(body.collect()).expect("collect Full body");
        let bytes = collected.to_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[test]
    fn try_probe_response_returns_ok_for_each_probe_alias() {
        let bound: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let state = empty_state("local", bound);
        for path in ["/livez", "/readyz", "/healthz", "/health"] {
            let resp = try_probe_response(path, &state)
                .unwrap_or_else(|| panic!("expected probe response for {path}"));
            assert_eq!(resp.status(), StatusCode::OK, "{path} status");
            assert_eq!(body_string(resp), "ok", "{path} body");
        }
    }

    #[test]
    fn try_probe_response_status_reports_empty_runtime_diagnostics() {
        // N1.2: with no bundles attached, `/status` returns the same JSON
        // shape, with `bundles_active`/`deployments_routed`/`revisions_active`
        // all zero. Operators read this to confirm the listener is up but no
        // traffic is being served.
        let bound: SocketAddr = "0.0.0.0:9090".parse().unwrap();
        let state = empty_state("prod-eu", bound);
        let resp = try_probe_response("/status", &state).expect("status response");
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_str(&body_string(resp)).unwrap();
        assert_eq!(body["schema"], "greentic.status.v1");
        assert_eq!(body["env_id"], "prod-eu");
        assert_eq!(body["listen_addr"], "0.0.0.0:9090");
        assert_eq!(body["bundles_active"], 0);
        assert_eq!(body["deployments_routed"], 0);
        assert_eq!(body["revisions_active"], 0);
    }

    #[test]
    fn try_probe_response_returns_none_for_non_probe_paths() {
        let bound: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let state = empty_state("local", bound);
        // Real traffic paths must fall through to the routing pipeline.
        assert!(try_probe_response("/api/chat", &state).is_none());
        assert!(try_probe_response("/livez/sub", &state).is_none());
        assert!(try_probe_response("/", &state).is_none());
    }

    // --- N1.2: listen-address resolution ----------------------------------

    #[test]
    fn resolve_bind_addr_falls_back_to_spec_default_when_nothing_is_set() {
        let _lock = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _vars = EnvVarGuard::clean();
        assert_eq!(resolve_bind_addr(None), DEFAULT_LISTEN_ADDR);
    }

    #[test]
    fn resolve_bind_addr_uses_host_config_when_set() {
        let _lock = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _vars = EnvVarGuard::clean();
        let configured: SocketAddr = "192.168.1.10:9000".parse().unwrap();
        let host = host_cfg_with(Some(configured));
        assert_eq!(resolve_bind_addr(Some(&host)), configured);
    }

    #[test]
    fn resolve_bind_addr_gateway_env_full_socketaddr_overrides_host_config() {
        let _lock = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _vars = EnvVarGuard::clean();
        let host = host_cfg_with(Some("192.168.1.10:9000".parse().unwrap()));
        // SAFETY: tests holding `test_env_lock` serialize env mutations.
        unsafe { std::env::set_var("GREENTIC_GATEWAY_LISTEN_ADDR", "0.0.0.0:7000") };
        assert_eq!(
            resolve_bind_addr(Some(&host)),
            "0.0.0.0:7000".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn resolve_bind_addr_gateway_env_bare_ip_keeps_port_from_host_config() {
        let _lock = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _vars = EnvVarGuard::clean();
        let host = host_cfg_with(Some("127.0.0.1:9090".parse().unwrap()));
        // SAFETY: tests holding `test_env_lock` serialize env mutations.
        unsafe { std::env::set_var("GREENTIC_GATEWAY_LISTEN_ADDR", "0.0.0.0") };
        // Port carried over from host_config (9090), IP from env-var.
        assert_eq!(
            resolve_bind_addr(Some(&host)),
            "0.0.0.0:9090".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn resolve_bind_addr_port_env_overrides_only_the_port() {
        let _lock = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _vars = EnvVarGuard::clean();
        let host = host_cfg_with(Some("192.168.1.10:9000".parse().unwrap()));
        // SAFETY: tests holding `test_env_lock` serialize env mutations.
        unsafe { std::env::set_var("PORT", "5555") };
        assert_eq!(
            resolve_bind_addr(Some(&host)),
            "192.168.1.10:5555".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn resolve_bind_addr_port_env_layers_on_top_of_gateway_env() {
        let _lock = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _vars = EnvVarGuard::clean();
        // SAFETY: tests holding `test_env_lock` serialize env mutations.
        unsafe {
            std::env::set_var("GREENTIC_GATEWAY_LISTEN_ADDR", "10.0.0.5:8000");
            std::env::set_var("PORT", "9999");
        }
        // PORT layers AFTER the GATEWAY env-var: same IP, PORT's port wins.
        assert_eq!(
            resolve_bind_addr(None),
            "10.0.0.5:9999".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn resolve_bind_addr_invalid_gateway_env_falls_through() {
        let _lock = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _vars = EnvVarGuard::clean();
        let host = host_cfg_with(Some("127.0.0.1:9090".parse().unwrap()));
        // SAFETY: tests holding `test_env_lock` serialize env mutations.
        unsafe { std::env::set_var("GREENTIC_GATEWAY_LISTEN_ADDR", "not-an-address") };
        // Invalid env-var is ignored; persisted host_config wins.
        assert_eq!(
            resolve_bind_addr(Some(&host)),
            "127.0.0.1:9090".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn resolve_bind_addr_invalid_port_env_falls_through() {
        let _lock = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _vars = EnvVarGuard::clean();
        let host = host_cfg_with(Some("127.0.0.1:9090".parse().unwrap()));
        // SAFETY: tests holding `test_env_lock` serialize env mutations.
        unsafe { std::env::set_var("PORT", "not-a-number") };
        assert_eq!(
            resolve_bind_addr(Some(&host)),
            "127.0.0.1:9090".parse::<SocketAddr>().unwrap()
        );
    }

    // --- N2.1: reload + overlap-window drop --------------------------------

    /// Build an [`Activation`] with `revision_count` revisions under a single
    /// deployment, suitable for asserting reload counts change after swap.
    fn populated_activation(env_id: &str, revision_count: u32) -> Activation {
        use crate::revision_dispatcher::{
            RevisionDispatcher, RevisionDispatcherConfig, RevisionEntry,
        };
        use greentic_deploy_spec::ids::{BundleId, DeploymentId, RevisionId};

        let base = empty_activation(env_id);
        let dispatcher = RevisionDispatcher::new(RevisionDispatcherConfig::new(env_id, [0u8; 32]));
        let deployment_id = DeploymentId::new();
        let bundle_id = BundleId::new("customer.support");
        let total: u32 = 10_000;
        let per_revision = total / revision_count;
        let mut remainder = total - per_revision * revision_count;
        let revisions: Vec<RevisionEntry> = (0..revision_count)
            .map(|_| {
                let weight_bps = per_revision + if remainder > 0 { 1 } else { 0 };
                remainder = remainder.saturating_sub(1);
                RevisionEntry {
                    revision_id: RevisionId::new(),
                    bundle_id: bundle_id.clone(),
                    weight_bps,
                }
            })
            .collect();
        dispatcher
            .apply_traffic_split(deployment_id, revisions, bundle_id, 0)
            .expect("apply_traffic_split for test activation");
        activation_for_test(base.host, dispatcher)
    }

    /// Construct a [`RevisionServer`] with no listener thread, just the state
    /// slot + the current Tokio runtime handle. Lets reload tests run under
    /// `#[tokio::test]` without binding a real port.
    fn server_for_test(state: std::sync::Arc<ServeState>) -> RevisionServer {
        // Mirror `start()`: seed the watermark from the initial activation
        // so reload() tests behave the same way the production cold-start
        // path does.
        let mut watermark: HashMap<DeploymentId, u64> = HashMap::new();
        state
            .slot
            .load()
            .routing
            .dispatcher
            .absorb_into_watermark(&mut watermark);
        RevisionServer {
            shutdown: None,
            handle: None,
            actual_port: 0,
            state,
            runtime_handle: Handle::current(),
            reload_lock: std::sync::Mutex::new(()),
            generation_watermark: std::sync::Mutex::new(watermark),
        }
    }

    #[tokio::test]
    async fn reload_swaps_activation_visible_to_next_counts() {
        let bound: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let state = std::sync::Arc::new(empty_state("env-1", bound));
        let server = server_for_test(state);
        assert_eq!(server.counts(), (0, 0));

        let report = server.reload(populated_activation("env-1", 2), Duration::ZERO);
        assert_eq!(report.prev_deployments, 0);
        assert_eq!(report.prev_revisions, 0);
        assert_eq!(report.new_deployments, 1);
        assert_eq!(report.new_revisions, 2);

        // The next reader sees the new activation; counts come from the same
        // dispatcher `/status` reads.
        assert_eq!(server.counts(), (1, 2));
    }

    #[tokio::test]
    async fn reload_inflight_arc_outlives_swap() {
        let bound: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let state = std::sync::Arc::new(empty_state("env-1", bound));
        let server = server_for_test(std::sync::Arc::clone(&state));

        // Snapshot the activation the way a request handler does at the top
        // of `serve`. After the swap this Arc must still be live: a request
        // mid-flight cannot tear (dispatch on new, execute on old).
        let inflight = state.current();
        let inflight_ptr = std::sync::Arc::as_ptr(&inflight) as usize;

        server.reload(populated_activation("env-1", 1), Duration::from_secs(60));

        // The swap is visible to the next reader, but the previously
        // snapshotted Arc still points at the old activation.
        let post_swap = state.current();
        assert_ne!(
            std::sync::Arc::as_ptr(&post_swap) as usize,
            inflight_ptr,
            "post-swap snapshot must point at the new activation"
        );
        // Old activation still serves zero revisions; new serves one.
        let (old_deps, old_revs) = inflight.routing.dispatcher.counts();
        assert_eq!((old_deps, old_revs), (0, 0));
        let (new_deps, new_revs) = post_swap.routing.dispatcher.counts();
        assert_eq!((new_deps, new_revs), (1, 1));
    }

    #[tokio::test]
    async fn reload_drops_old_activation_after_drain_window() {
        let bound: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let state = std::sync::Arc::new(empty_state("env-1", bound));
        let server = server_for_test(std::sync::Arc::clone(&state));

        // Track the pre-swap activation via a `Weak`. After the drain window
        // elapses, every strong ref the spawned drop task held should be gone
        // — `upgrade()` returns `None`.
        let weak_old = std::sync::Arc::downgrade(&state.current());

        let drain_window = Duration::from_millis(50);
        server.reload(populated_activation("env-1", 1), drain_window);

        // Inside the drain window: the spawned drop task is still sleeping,
        // so the old activation is still alive.
        assert!(
            weak_old.upgrade().is_some(),
            "old activation must outlive the drain window"
        );

        // Wait past the window. The drop task wakes, drops its Arc, and the
        // last strong ref is gone.
        tokio::time::sleep(drain_window + Duration::from_millis(200)).await;
        assert!(
            weak_old.upgrade().is_none(),
            "old activation must be freed once the drain window elapses"
        );
    }

    /// Build an [`Activation`] with a single deployment + revision, both
    /// taken as parameters so two activations can share IDs across a reload.
    /// The dispatcher carries the deployment at generation 1 (whatever
    /// `apply_traffic_split(.., expected_generation=0)` yields).
    fn activation_with_ids(
        env_id: &str,
        deployment_id: greentic_deploy_spec::ids::DeploymentId,
        revision_id: greentic_deploy_spec::ids::RevisionId,
        bundle_id: greentic_deploy_spec::ids::BundleId,
    ) -> Activation {
        use crate::revision_dispatcher::{
            RevisionDispatcher, RevisionDispatcherConfig, RevisionEntry,
        };
        let base = empty_activation(env_id);
        let dispatcher = RevisionDispatcher::new(RevisionDispatcherConfig::new(env_id, [0u8; 32]));
        let revisions = vec![RevisionEntry {
            revision_id,
            bundle_id: bundle_id.clone(),
            weight_bps: 10_000,
        }];
        dispatcher
            .apply_traffic_split(deployment_id, revisions, bundle_id, 0)
            .expect("apply_traffic_split for shared-deployment activation");
        activation_for_test(base.host, dispatcher)
    }

    #[tokio::test]
    async fn reload_invalidates_pre_reload_cookie_for_persisted_deployment() {
        // Regression test for the Codex finding on PR-N2.1: without the
        // generation bump in reload(), a fresh dispatcher built from the
        // same runtime-config would carry the same `apply_traffic_split`-
        // from-zero default generation (1), and a cookie minted pre-reload
        // would still verify post-reload — defeating canary weight cuts
        // and partial rollbacks for already-cookie'd clients.
        let env_id = "env-1";
        let tenant = "tenant-a";
        let dep_id = greentic_deploy_spec::ids::DeploymentId::new();
        let rev_id = greentic_deploy_spec::ids::RevisionId::new();
        let bundle_id = greentic_deploy_spec::ids::BundleId::new("customer.support");

        let act1 = activation_with_ids(env_id, dep_id, rev_id, bundle_id.clone());
        let bound: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let state = std::sync::Arc::new(ServeState {
            slot: ArcSwap::new(std::sync::Arc::new(act1)),
            bound_addr: bound,
        });
        let server = server_for_test(std::sync::Arc::clone(&state));

        // Mint a cookie against the live (pre-reload) dispatcher. The test
        // helper seals it under generation 1 — the value `apply_traffic_split`
        // writes for a from-zero call.
        let act1_snap = state.current();
        assert_eq!(
            act1_snap.routing.dispatcher.counts(),
            (1, 1),
            "pre-reload activation must hold the test deployment + revision"
        );
        let cookie = act1_snap.routing.dispatcher.seal_cookie(
            env_id,
            tenant,
            dep_id,
            rev_id,
            /* generation */ 1,
            /* expires_at */ 9_999_999_999,
        );
        // Sanity: the cookie verifies against the pre-reload dispatcher at
        // generation 1, the value `apply_traffic_split(.., 0)` produces.
        assert_eq!(
            act1_snap
                .routing
                .dispatcher
                .verify_cookie(&cookie, env_id, tenant, dep_id, 1, 0),
            Some(rev_id),
            "pre-reload dispatcher must verify its own cookie"
        );

        // Reload to a new activation that re-uses the SAME deployment + bundle
        // + revision (only the dispatcher object is fresh). Carry-forward must
        // bump the new dispatcher's generation so the cookie sealed under
        // generation 1 no longer verifies.
        let act2 = activation_with_ids(env_id, dep_id, rev_id, bundle_id);
        server.reload(act2, Duration::ZERO);

        let act2_snap = state.current();
        // The cookie's `g` is still 1, but the live dispatcher's expected
        // generation is now 2 (1 + 1 from the watermark bump) → mismatch → None.
        assert_eq!(
            act2_snap
                .routing
                .dispatcher
                .verify_cookie(&cookie, env_id, tenant, dep_id, 2, 0),
            None,
            "post-reload dispatcher must reject the pre-reload cookie"
        );
        // And the post-reload cookie minted against `act2`'s actual generation
        // (2) does verify, proving the carry-forward landed at 2 specifically.
        let post_cookie = act2_snap.routing.dispatcher.seal_cookie(
            env_id,
            tenant,
            dep_id,
            rev_id,
            2,
            9_999_999_999,
        );
        assert_eq!(
            act2_snap
                .routing
                .dispatcher
                .verify_cookie(&post_cookie, env_id, tenant, dep_id, 2, 0),
            Some(rev_id),
            "post-reload dispatcher must verify a cookie minted at the new generation"
        );
    }

    #[tokio::test]
    async fn reload_invalidates_cookie_after_remove_and_readd_within_ttl() {
        // Codex regression: without the server-level generation watermark,
        // a bump driven only by the previous dispatcher would miss
        // deployments that had been removed from runtime-config. A
        // deployment removed and later re-added before cookie/pin TTL
        // elapsed got a fresh dispatcher at the same
        // `from_runtime_config`-default generation, and the dispatcher
        // would happily verify a cookie signed against the original
        // activation. This test asserts the watermark tombstones removed
        // deployments so the re-added one is strictly newer than anything
        // a client could be holding.
        let env_id = "env-1";
        let tenant = "tenant-a";
        let dep_id = greentic_deploy_spec::ids::DeploymentId::new();
        let rev_id = greentic_deploy_spec::ids::RevisionId::new();
        let bundle_id = greentic_deploy_spec::ids::BundleId::new("customer.support");

        let act1 = activation_with_ids(env_id, dep_id, rev_id, bundle_id.clone());
        let bound: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let state = std::sync::Arc::new(ServeState {
            slot: ArcSwap::new(std::sync::Arc::new(act1)),
            bound_addr: bound,
        });
        let server = server_for_test(std::sync::Arc::clone(&state));

        // Sign a cookie against act1's generation (1, from
        // `apply_traffic_split(.., 0)`).
        let act1_snap = state.current();
        let cookie = act1_snap.routing.dispatcher.seal_cookie(
            env_id,
            tenant,
            dep_id,
            rev_id,
            /* generation */ 1,
            /* expires_at */ 9_999_999_999,
        );

        // Reload to an activation that drops the deployment entirely
        // (simulates the operator running `gtc op bundles remove` or
        // setting traffic to 0 across all revisions). The watermark must
        // record dep_id at generation 1 even though the live dispatcher
        // no longer carries it.
        let empty = empty_activation(env_id);
        server.reload(empty, Duration::ZERO);

        // Reload AGAIN to re-add the same deployment + revision (rollback
        // / re-stage). The fresh dispatcher would otherwise pin dep_id at
        // generation 1 again — the watermark must force it to 2.
        let act3 = activation_with_ids(env_id, dep_id, rev_id, bundle_id);
        server.reload(act3, Duration::ZERO);

        let act3_snap = state.current();
        assert_eq!(
            act3_snap.routing.dispatcher.counts(),
            (1, 1),
            "re-added deployment must be present in the post-reload dispatcher"
        );

        // `dispatch()` passes the live dispatcher's current generation as
        // `expected_generation` — the watermark must have bumped that past
        // the cookie's signed generation. Mirror that here: a cookie
        // signed at generation 1 must NOT verify under the live dispatcher's
        // post-reload generation (which the watermark forced to 2).
        assert_eq!(
            act3_snap
                .routing
                .dispatcher
                .verify_cookie(&cookie, env_id, tenant, dep_id, 2, 0),
            None,
            "cookie sealed before remove must NOT verify under the bumped generation"
        );
        // Specifically: the new generation is exactly 2 — one bump for
        // the absorb(act1) that landed in the watermark before the empty
        // reload, applied when act3's freshly-built generation 1 was
        // bumped on top of it. A cookie sealed AT 2 verifies; sanity-check
        // the watermark didn't over-bump.
        let post_cookie = act3_snap.routing.dispatcher.seal_cookie(
            env_id,
            tenant,
            dep_id,
            rev_id,
            2,
            9_999_999_999,
        );
        assert_eq!(
            act3_snap
                .routing
                .dispatcher
                .verify_cookie(&post_cookie, env_id, tenant, dep_id, 2, 0),
            Some(rev_id),
            "cookie minted at the bumped generation (2) must verify"
        );
    }

    // --- N2.3: revision drain on removal -----------------------------------

    /// Activation with one deployment + two revisions, route table seeded
    /// with `(deployment_id → tenant)` so `spawn_revision_drains` finds the
    /// tenant binding. Returns `(activation, dispatcher_arc)` so callers can
    /// keep a handle to OLD's dispatcher across the reload and observe drain
    /// transitions on it after the producer task fires.
    fn activation_with_two_revisions(
        env_id: &str,
        tenant: &str,
        deployment_id: DeploymentId,
        rev_a: RevisionId,
        rev_b: RevisionId,
        bundle_id: BundleId,
    ) -> (Activation, std::sync::Arc<RevisionDispatcher>) {
        use crate::revision_dispatcher::{RevisionDispatcherConfig, RevisionEntry};
        let base = empty_activation(env_id);
        let dispatcher = RevisionDispatcher::new(RevisionDispatcherConfig::new(env_id, [0u8; 32]));
        let revisions = vec![
            RevisionEntry {
                revision_id: rev_a,
                bundle_id: bundle_id.clone(),
                weight_bps: 5_000,
            },
            RevisionEntry {
                revision_id: rev_b,
                bundle_id: bundle_id.clone(),
                weight_bps: 5_000,
            },
        ];
        dispatcher
            .apply_traffic_split(deployment_id, revisions, bundle_id, 0)
            .expect("apply_traffic_split");
        let dispatcher = std::sync::Arc::new(dispatcher);
        let routing = std::sync::Arc::new(RevisionIngressRouting {
            dispatcher: std::sync::Arc::clone(&dispatcher),
            http_routes: HttpRouteTable::from_descriptors(Vec::new()),
            deployment_routes: crate::deployment_routes::DeploymentRouteTable::from_parts(vec![(
                deployment_id,
                tenant.to_string(),
                Vec::new(),
                Vec::new(),
            )]),
            endpoint_admit: std::sync::Arc::new(crate::endpoint_admit::EndpointAdmit::default()),
        });
        let activation = Activation {
            host: base.host,
            routing,
        };
        (activation, dispatcher)
    }

    #[tokio::test]
    async fn reload_drain_marks_then_evicts_removed_revision() {
        // Reload removes one of two revisions under the same deployment.
        // The drain coordinator should mark the removed revision draining
        // on the OLD dispatcher immediately, and evict it after the drain
        // window. The kept revision must NOT be marked draining.
        let env_id = "env-1";
        let tenant = "tenant-a";
        let dep_id = DeploymentId::new();
        let rev_kept = RevisionId::new();
        let rev_removed = RevisionId::new();
        let bundle_id = BundleId::new("customer.support");

        let (act_old, old_dispatcher) = activation_with_two_revisions(
            env_id,
            tenant,
            dep_id,
            rev_kept,
            rev_removed,
            bundle_id.clone(),
        );
        let state = serve_state_with(act_old);
        let server = server_for_test(std::sync::Arc::clone(&state));

        // NEW activation keeps `rev_kept` only (single-revision, full weight).
        let act_new = activation_with_ids(env_id, dep_id, rev_kept, bundle_id);

        // Use a short drain window so the test finishes quickly. drain_seconds
        // is derived from drain_window.as_secs(); 1s gives the coordinator
        // enough room to mark, sleep, and evict before we assert.
        server.reload(act_new, Duration::from_secs(1));

        // After the swap returns, the drain task has been spawned but may
        // not have run mark_draining yet. Yield to give it a chance.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            old_dispatcher.is_draining(dep_id, rev_removed),
            "removed revision must be marked draining on OLD dispatcher"
        );
        assert!(
            !old_dispatcher.is_draining(dep_id, rev_kept),
            "kept revision must NOT be marked draining"
        );

        // Wait past the drain window. Coordinator evicts the removed
        // revision from the OLD dispatcher.
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        let revision_ids: std::collections::HashSet<_> = old_dispatcher
            .revision_keys()
            .into_iter()
            .filter(|(d, _, _)| *d == dep_id)
            .map(|(_, _, r)| r)
            .collect();
        assert!(
            !revision_ids.contains(&rev_removed),
            "removed revision must be evicted from OLD dispatcher after drain"
        );
        assert!(
            revision_ids.contains(&rev_kept),
            "kept revision must remain on OLD dispatcher"
        );
    }

    #[tokio::test]
    async fn reload_does_not_drain_when_no_revisions_removed() {
        // Reload that keeps the same revision set must not mark anything
        // draining on the OLD dispatcher — adding a brand new deployment or
        // reweighting the same revisions doesn't constitute a removal.
        let env_id = "env-1";
        let tenant = "tenant-a";
        let dep_id = DeploymentId::new();
        let rev_a = RevisionId::new();
        let rev_b = RevisionId::new();
        let bundle_id = BundleId::new("customer.support");

        let (act_old, old_dispatcher) =
            activation_with_two_revisions(env_id, tenant, dep_id, rev_a, rev_b, bundle_id.clone());
        let state = serve_state_with(act_old);
        let server = server_for_test(std::sync::Arc::clone(&state));

        // NEW activation: same deployment, same two revisions (identical set).
        let (act_new, _) =
            activation_with_two_revisions(env_id, tenant, dep_id, rev_a, rev_b, bundle_id);
        server.reload(act_new, Duration::from_millis(100));

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            old_dispatcher.draining_revisions(dep_id).is_empty(),
            "no revisions removed → nothing marked draining (got {:?})",
            old_dispatcher.draining_revisions(dep_id)
        );
    }

    #[tokio::test]
    async fn reload_zero_drain_window_skips_drain_spawn() {
        // `drain_window == 0` is a test-only mode that drops the OLD
        // activation synchronously. The drain coordinator path MUST be
        // bypassed too — otherwise drain tasks would race the synchronous
        // drop against a dispatcher whose `Arc<RevisionDispatcher>` could
        // have been the last strong handle outside the coordinator.
        let env_id = "env-1";
        let tenant = "tenant-a";
        let dep_id = DeploymentId::new();
        let rev_a = RevisionId::new();
        let rev_b = RevisionId::new();
        let bundle_id = BundleId::new("customer.support");

        let (act_old, old_dispatcher) =
            activation_with_two_revisions(env_id, tenant, dep_id, rev_a, rev_b, bundle_id.clone());
        let state = serve_state_with(act_old);
        let server = server_for_test(std::sync::Arc::clone(&state));

        let act_new = activation_with_ids(env_id, dep_id, rev_a, bundle_id);
        server.reload(act_new, Duration::ZERO);

        // Give any erroneously-spawned drain task a chance to run.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            old_dispatcher.draining_revisions(dep_id).is_empty(),
            "drain_window == 0 must bypass drain spawn (got {:?})",
            old_dispatcher.draining_revisions(dep_id)
        );
    }

    // --- N2.3 Codex fix: stale-eviction suppression probe ------------------

    /// Build a `ServeState` whose live slot holds `activation`. Helper for
    /// the [`SlotLivenessProbe`] tests.
    fn serve_state_with(activation: Activation) -> std::sync::Arc<ServeState> {
        let bound: SocketAddr = "127.0.0.1:0".parse().unwrap();
        std::sync::Arc::new(ServeState {
            slot: ArcSwap::new(std::sync::Arc::new(activation)),
            bound_addr: bound,
        })
    }

    #[test]
    fn liveness_probe_reports_live_when_revision_present_in_newer_activation() {
        // The live slot holds a NEWER activation (different dispatcher Arc)
        // that serves the revision → the OLD activation's drain must treat
        // the revision as live elsewhere and suppress its eviction event.
        let env_id = "env-1";
        let dep_id = DeploymentId::new();
        let rev_id = RevisionId::new();
        let bundle_id = BundleId::new("customer.support");

        let draining = activation_with_ids(env_id, dep_id, rev_id, bundle_id.clone());
        let draining_dispatcher = std::sync::Arc::clone(&draining.routing.dispatcher);
        // A distinct, newer activation that also serves the revision.
        let live = activation_with_ids(env_id, dep_id, rev_id, bundle_id);
        let state = serve_state_with(live);

        let probe = SlotLivenessProbe {
            state,
            draining_dispatcher,
        };
        assert!(
            probe.is_live_elsewhere(dep_id, rev_id),
            "revision present in a newer activation must read as live elsewhere"
        );
    }

    #[test]
    fn liveness_probe_reports_not_live_when_live_slot_is_the_draining_dispatcher() {
        // Identity guard: if the live slot still points at the very
        // dispatcher being drained, the revision is NOT live in a newer
        // activation — the eviction event should fire (direct-drain
        // semantics). Models the future `gtc op revisions drain` path.
        let env_id = "env-1";
        let dep_id = DeploymentId::new();
        let rev_id = RevisionId::new();
        let bundle_id = BundleId::new("customer.support");

        let live = activation_with_ids(env_id, dep_id, rev_id, bundle_id);
        let draining_dispatcher = std::sync::Arc::clone(&live.routing.dispatcher);
        let state = serve_state_with(live);

        let probe = SlotLivenessProbe {
            state,
            draining_dispatcher,
        };
        assert!(
            !probe.is_live_elsewhere(dep_id, rev_id),
            "draining the live dispatcher itself must NOT read as live elsewhere"
        );
    }

    #[test]
    fn liveness_probe_reports_not_live_when_revision_absent_from_live_slot() {
        // Live slot is a newer activation that does NOT serve the revision
        // (genuine removal, no rollback) → not live elsewhere → eviction
        // event fires normally.
        let env_id = "env-1";
        let dep_id = DeploymentId::new();
        let rev_removed = RevisionId::new();
        let rev_other = RevisionId::new();
        let bundle_id = BundleId::new("customer.support");

        let draining = activation_with_ids(env_id, dep_id, rev_removed, bundle_id.clone());
        let draining_dispatcher = std::sync::Arc::clone(&draining.routing.dispatcher);
        // Newer activation serves a DIFFERENT revision under the same deployment.
        let live = activation_with_ids(env_id, dep_id, rev_other, bundle_id);
        let state = serve_state_with(live);

        let probe = SlotLivenessProbe {
            state,
            draining_dispatcher,
        };
        assert!(
            !probe.is_live_elsewhere(dep_id, rev_removed),
            "a genuinely removed revision must NOT read as live elsewhere"
        );
    }
}
