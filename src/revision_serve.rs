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
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use greentic_deploy_spec::ids::{BundleId, DeploymentId, RevisionId};
use greentic_types::ChannelMessageEnvelope;
use greentic_types::messaging::extensions::ext_keys;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1::Builder as Http1Builder;
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response, StatusCode, header};
use hyper_util::rt::tokio::TokioIo;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::runtime::{Handle, Runtime};
use tokio::sync::{Notify, oneshot};

use greentic_runner_host::{Activity, RunnerHost, WelcomeFlowHint};

use greentic_deploy_spec::{
    DEFAULT_LISTEN_ADDR, EnvironmentHostConfig, UpdateAction, UpdateChannelConfig,
};
use greentic_deployer::cli::updates::{self, ApplyUpdatesPayload, UpdatesGetPayload};
use greentic_deployer::cli::{OpError, OpFlags, OpOutcome};
use greentic_deployer::environment::{LocalFsStore, load_trust_root};
use greentic_types::EnvId;
use greentic_update::binswap;
use greentic_update::plan::{select_binary, verify_update_plan};
use greentic_update::staging::UpdatesRoot;
use greentic_update::stream::{StreamError, build_stream_client, run_stream};

use crate::deployment_routes::RevisionIngressRouting;
use crate::endpoint_resolver;
use crate::http_helpers::{cors_preflight_response, with_cors};
use crate::http_routes::{HttpRouteTable, RevisionScope};
use crate::identify_payload;
use crate::ingress_dispatch::parse_dispatch_result;
use crate::ingress_types::IngressHttpResponse;
use crate::messaging_dto::HttpInV1;
use crate::operator_log;
use crate::provider_auth;
use crate::revision_dispatcher::{
    DispatchRequest, RevisionDispatcher, RevisionKey, SetCookieDirective, cookie_name,
};
use crate::revision_drain::{
    DrainRequest, NoopRevisionTeardown, RevisionDrainCoordinator, RevisionLivenessProbe,
    RevisionTeardown,
};

/// Set-once latch for deferred public-URL capture on Cloud Run.
///
/// On Cloud Run, the runtime's own public URL is not known at boot time (no
/// tunnel, no manifest `public_base_url`). The first inbound request through
/// the Google Front End carries the real `Host` header, and this struct lets the
/// request-path writer communicate the derived URL to the boot-side waiter
/// (the deferred webhook-registration task).
///
/// - [`offer`](Self::offer): called from the hot request path; first writer
///   wins (idempotent via `OnceLock`), then wakes the boot waiter.
/// - [`captured`](Self::captured): awaited by the boot task; registers
///   `notified()` before re-checking `get()` to avoid a missed notify.
/// - [`get`](Self::get): non-async read for the reload path.
#[derive(Debug, Default)]
pub(crate) struct PublicUrlCapture {
    url: std::sync::OnceLock<String>,
    notify: tokio::sync::Notify,
    /// K_SERVICE at boot. The derived `Host` must be this service's own
    /// `<expected_service>-*.run.app` URL (see
    /// [`crate::startup_contract::derive_public_base_url`]) — the anti-hijack
    /// pin. Empty in the `Default` case (used only by tests that never
    /// exercise derivation).
    expected_service: String,
}

impl PublicUrlCapture {
    /// Create an armed capture pinned to `expected_service` (the Cloud Run
    /// `K_SERVICE`). Only a `Host` of the form `<expected_service>-*.run.app`
    /// will be captured.
    pub(crate) fn new(expected_service: String) -> Self {
        Self {
            url: std::sync::OnceLock::new(),
            notify: tokio::sync::Notify::default(),
            expected_service,
        }
    }

    /// Offer a derived URL. Only the first call wins; subsequent calls are
    /// no-ops (the `OnceLock` rejects them). After a successful set, wakes
    /// the single boot waiter via `notify_one`.
    pub(crate) fn offer(&self, url: String) {
        if self.url.set(url).is_ok() {
            self.notify.notify_one();
        }
    }

    /// Non-async read of the captured URL. Used by the reload path to check
    /// whether a URL was captured without awaiting.
    pub(crate) fn get(&self) -> Option<&String> {
        self.url.get()
    }

    /// Wait until a URL has been captured. The boot-side deferred registration
    /// task calls this. Race-free for a single waiter: `notified()` is
    /// registered BEFORE re-checking `get()`, so a concurrent `offer` between
    /// the check and the await is not missed.
    pub(crate) async fn captured(&self) -> String {
        loop {
            let waiting = self.notify.notified();
            if let Some(u) = self.url.get() {
                return u.clone();
            }
            waiting.await;
        }
    }
}

/// Largest request body the revision ingress accepts, in bytes. Even on the
/// loopback / local posture a cap is required so one oversized POST cannot
/// exhaust memory before the JSON parse rejects it.
const MAX_BODY_BYTES: usize = 1 << 20; // 1 MiB

/// Activated host + routing as a single coherent unit. Requests bind to one
/// `Arc<Activation>` at the top of [`serve`] and use the same `host` and
/// `routing` for the rest of their lifetime — so a [`RevisionServer::reload`]
/// that swaps the slot mid-request cannot tear (dispatch via the new
/// dispatcher, execute against the old host, or vice versa).
///
/// `Clone` is two `Arc` bumps — the reload worker clones the activation it
/// swaps in so the post-reload hook observes the same (host, routing) pair
/// the server now serves.
#[derive(Clone)]
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
    /// Serve the built-in webchat console (`GET /chat` + `/adaptivecards.min.js`)
    /// over this listener. Resolved from `host_config.resolved_gui_enabled()` at
    /// boot (on by default for the `local` env, off elsewhere unless the operator
    /// opts in). When false the chat paths fall through to deployment routing.
    pub gui_enabled: bool,
    /// Whether a loopback TCP peer may be granted the trust the loopback gate
    /// confers (`/chat`, `/workers/invoke`, caller-asserted identity) on the
    /// main listener. Set `false` when a public tunnel (cloudflared/ngrok)
    /// fronts it: the tunnel forwards external traffic to `127.0.0.1:<port>`,
    /// so a tunneled request's peer reads as loopback and would otherwise
    /// inherit that trust. See [`peer_is_loopback_trusted`].
    pub trust_loopback_peers: bool,
    /// Optional second, loopback-scoped admin/console listener that runs
    /// alongside the main one and *always* trusts loopback peers. Set when a
    /// tunnel fronts the main listener (`trust_loopback_peers = false`): the
    /// tunnel targets the main port only, so this listener — reachable solely
    /// via a local port-forward / in-pod loopback — keeps serving `/chat` +
    /// `/workers/invoke` to a genuine local caller while the public face
    /// refuses them. `None` = single listener (the non-tunnel default).
    pub admin_bind_addr: Option<SocketAddr>,
    /// Whether this process participates in the update channel at all: run the
    /// poll loop and reserve `/v1/updates/notify`. `false` is the `--no-updates`
    /// kill switch — a host-local override, not a policy change. Policy (whether
    /// the channel is enabled, and what a notification does) still lives in the
    /// env's `update-channel.json`; with `true` the poll loop reads it every
    /// cycle and no-ops while it is absent or disabled.
    pub updates_enabled: bool,
    /// Whether auto-restart after a binary self-update is enabled.
    pub auto_restart_enabled: bool,
    /// Executable path captured at boot, before any swap.
    pub exe_path: Option<std::path::PathBuf>,
    /// Armed on Cloud Run when no boot-time `public_base_url` is available:
    /// the first inbound request that passes the GFE trust gate sets the URL
    /// via [`PublicUrlCapture::offer`], waking the deferred registration task.
    /// `None` = not on Cloud Run, or a URL was already known at boot.
    pub public_url_capture: Option<Arc<PublicUrlCapture>>,
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
    /// Whether the built-in webchat console is served on this listener. Read on
    /// every request (a cheap `Copy` bool) to gate the chat-asset short-circuit.
    gui_enabled: bool,
    /// Set to `true` after a binary self-update swap succeeds. The new binary is
    /// on disk but the running process is still the old one — a restart is
    /// required to activate it. Surfaced in `/status` and `/healthz` so
    /// operators and orchestrators can observe when a restart is pending. Reset
    /// implicitly on process restart (the new process starts with `false`).
    restart_required: AtomicBool,
    /// `--no-updates` inverted: when `false`, `/v1/updates/notify` is never
    /// reserved (the path falls through to deployment routing) and no poll loop
    /// runs. See [`RevisionServeConfig::updates_enabled`].
    updates_enabled: bool,
    /// Set to `true` when a binary swap succeeded AND auto-restart is enabled
    /// AND we are on unix. The main thread's shutdown loop returns
    /// `BinaryUpdateRestart` when this is set.
    auto_restart_pending: AtomicBool,
    /// Whether auto-restart after a binary self-update is enabled for this
    /// process. Derived from `--no-auto-restart` / `GREENTIC_NO_AUTO_RESTART`.
    auto_restart_enabled: bool,
    /// Executable path captured once at boot (before any swap can invalidate
    /// `/proc/self/exe`). Used by `try_apply_binary_update` as a fallback
    /// and by the exec-into-self logic after shutdown.
    exe_path: Option<std::path::PathBuf>,
    /// Sliding-window registry of active DirectLine conversations, used to
    /// re-mint session tokens on activity so long-running chats don't 401 once
    /// the original session JWT lapses. See [`crate::directline_session`].
    directline_sessions: Arc<crate::directline_session::DirectLineSessions>,
    /// Short-window idempotency cache for `POST /v3/directline/conversations`.
    /// Prevents racy double-calls from clients from minting two independent
    /// conversations for the same browser session.
    conversation_dedup: Arc<crate::conv_dedup::ConversationDedupCache>,
    /// WebSocket session concurrency limits + per-tenant/conversation gauges.
    /// Shared with the WS upgrade handler so every revision listener shares one
    /// session accounting pool.
    session_manager: Arc<crate::websocket::SessionManager>,
    /// Activity push notifier — informs WS sessions when a conversation has
    /// new activities. Shared across all revisions so a REST POST that writes
    /// an activity on one revision wakes the WS pump watching that conversation.
    notifier: Arc<dyn crate::notifier::ActivityNotifier>,
    /// Deferred public-URL capture for Cloud Run. When armed, the first
    /// inbound request that passes the GFE trust gate writes the URL here
    /// via [`PublicUrlCapture::offer`], waking the deferred registration
    /// task in `lib.rs`. `None` = not armed.
    public_url_capture: Option<Arc<PublicUrlCapture>>,
    /// Test-only: override the activity source used by the WS pump. When
    /// `Some`, `handle_websocket_upgrade` substitutes this source instead of
    /// constructing a `RevisionActivitySource` that calls
    /// `invoke_provider_for_revision`. This lets integration tests exercise the
    /// full WS upgrade + pump pipeline without loading a real WASM pack.
    #[cfg(test)]
    activity_source_override: Option<Arc<dyn crate::websocket::pump::ActivitySource>>,
}

impl ServeState {
    /// Snapshot the live activation. Holding the returned `Arc` keeps the
    /// activation alive across `.await` points, even if a concurrent reload
    /// swaps the slot — the reload's drain window still ensures the old
    /// activation outlives every in-flight request that pinned it.
    fn current(&self) -> Arc<Activation> {
        self.slot.load_full()
    }

    /// Record that a restart is required (binary swap succeeded) and, when
    /// auto-restart is enabled on this platform, arm the auto-restart flag
    /// so the shutdown loop returns `BinaryUpdateRestart`.
    fn mark_restart_required(&self) {
        self.restart_required.store(true, Ordering::Relaxed);
        #[cfg(unix)]
        if self.auto_restart_enabled {
            self.auto_restart_pending.store(true, Ordering::Relaxed);
        }
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

/// Deployments whose session stickiness must survive the reload — every
/// revision that was taking traffic in `prev` is still taking traffic in
/// `next`. B1: a pure traffic reweight or a canary *addition* (the old
/// revision stays routable, a new one joins) keeps existing sessions pinned;
/// [`RevisionServer::reload`] hands this set to
/// [`RevisionDispatcher::reanchor_generations`] so those deployments carry
/// their generation forward instead of bumping.
///
/// A deployment is preserved only if it was present in `prev` AND
/// `routable(prev) ⊆ routable(next)`. This excludes, by construction:
/// a revision removed or ramped to weight 0 (its pins would flap → must bump),
/// and a deployment re-added after removal (absent from `prev`, so its pre-
/// removal cookies/pins must be tombstoned by a bump, not honored).
fn deployments_preserving_stickiness(
    prev: &RevisionDispatcher,
    next: &RevisionDispatcher,
) -> std::collections::HashSet<DeploymentId> {
    let next_routable = next.routable_revisions();
    prev.routable_revisions()
        .into_iter()
        .filter_map(|(deployment_id, prev_set)| {
            let next_set = next_routable.get(&deployment_id)?;
            prev_set.is_subset(next_set).then_some(deployment_id)
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
    /// Port the loopback-only admin/console listener bound, when one was
    /// requested (a tunnel fronts the main listener). `None` = single
    /// listener. Surfaced so the boot banner can point operators at the
    /// console port to port-forward.
    admin_port: Option<u16>,
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
    /// `load_full(prev) → reanchor_generations → swap(new)` sequence is not
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

        // Optional loopback-only admin/console listener. Its port is resolved
        // here (same synchronous probe as the main port) so the bound port is
        // known before the serving thread starts and can be surfaced to the
        // boot banner. The search starts at `actual_port + 1` when the
        // originally requested admin port would collide with the resolved
        // main port (e.g. the main port was bumped into the admin range).
        let admin_addr = match config.admin_bind_addr {
            Some(requested) => {
                let admin_start = if requested.port() <= actual_port {
                    actual_port.saturating_add(1)
                } else {
                    requested.port()
                };
                let admin_port = crate::port_utils::find_available_port(
                    &requested.ip().to_string(),
                    admin_start,
                    10,
                )
                .context("failed to find available port for admin/console listener")?;
                Some(SocketAddr::new(requested.ip(), admin_port))
            }
            None => None,
        };
        let admin_port = admin_addr.map(|a| a.port());

        let session_manager = Arc::new(crate::websocket::SessionManager::new(
            crate::websocket::WsLimits::default(),
        ));
        // In-memory notifier is sufficient for single-process revision hosts.
        // A Redis-backed notifier (for horizontally scaled deployments) plugs
        // in via the same `build_notifier` machinery as the legacy path.
        let notifier: Arc<dyn crate::notifier::ActivityNotifier> =
            Arc::new(crate::notifier::InMemoryNotifier::new(64));
        let state = Arc::new(ServeState {
            slot: ArcSwap::new(config.activation),
            bound_addr: addr,
            gui_enabled: config.gui_enabled,
            restart_required: AtomicBool::new(false),
            updates_enabled: config.updates_enabled,
            auto_restart_pending: AtomicBool::new(false),
            auto_restart_enabled: config.auto_restart_enabled,
            exe_path: config.exe_path,
            directline_sessions: Arc::new(crate::directline_session::DirectLineSessions::from_env()),
            conversation_dedup: Arc::new(crate::conv_dedup::ConversationDedupCache::new()),
            session_manager,
            notifier,
            public_url_capture: config.public_url_capture,
            #[cfg(test)]
            activity_source_override: None,
        });
        // Cloned into the listener thread; the original lives on as the
        // [`RevisionServer::state`] handle so [`reload`] / [`counts`] read the
        // same slot the running listener reads.
        let listener_state = Arc::clone(&state);
        // Captured into the accept loop: a listener-thread concern (not
        // per-request state), so it lives as a thread-local rather than on
        // `ServeState`. AND-ed into the per-connection loopback decision below.
        let trust_loopback_peers = config.trust_loopback_peers;

        // Updater: the ingress runtime runs two cooperating tasks against the
        // env's configured update channel. `run_update_stream_loop` holds an SSE
        // connection and is the *primary* discovery path; `run_update_poll_loop`
        // does the actual verified fetch and is the fallback that also runs on a
        // timer. Both re-read `update-channel.json` and no-op while the channel is
        // absent, disabled, or endpoint-less, so deny-by-default lives in them —
        // not in a boot-time sidecar probe, which would strand an env that
        // subscribes *after* boot until the next restart. `--no-updates` (and a
        // missing store root) is the only thing that keeps them from spawning.
        let update_poll_root = config
            .updates_enabled
            .then(LocalFsStore::default_root)
            .flatten();
        let poll_state = Arc::clone(&state);
        let stream_state = Arc::clone(&state);
        // Wakes the poll loop out of its interval wait when a plan is published.
        let update_wake = Arc::new(Notify::new());
        let poll_wake = Arc::clone(&update_wake);

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
                let serve_result = runtime.block_on(async move {
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
                    let admin_listener = match admin_addr {
                        Some(a) => match TcpListener::bind(a)
                            .await
                            .context("failed to bind admin/console listener")
                        {
                            Ok(l) => Some(l),
                            Err(err) => {
                                let _ = startup_tx.send(Err(anyhow::anyhow!("{err:#}")));
                                return Err(err);
                            }
                        },
                        None => None,
                    };
                    let _ = startup_tx.send(Ok(runtime_handle));
                    operator_log::info(
                        module_path!(),
                        format!("revision ingress listening on http://{addr}"),
                    );
                    if let Some(a) = admin_addr {
                        operator_log::info(
                            module_path!(),
                            format!("revision ingress admin/console listening on http://{a}"),
                        );
                    }
                    // Spawn the updater tasks on this runtime when the env opted in
                    // (sidecar present). Both re-read config as they go, so a
                    // disabled or endpoint-less channel simply no-ops. Aborted on
                    // shutdown below.
                    let update_poll_task = update_poll_root.as_ref().map(|root| {
                        tokio::spawn(run_update_poll_loop(poll_state, root.clone(), poll_wake))
                    });
                    let update_stream_task = update_poll_root.map(|root| {
                        tokio::spawn(run_update_stream_loop(stream_state, root, update_wake))
                    });
                    let mut shutdown = rx;
                    loop {
                        tokio::select! {
                            _ = &mut shutdown => {
                                // Stop the updater tasks. The abort is prompt when the
                                // poll task is waiting between cycles (the common case).
                                // A cycle already inside its `spawn_blocking`
                                // (mid fetch/stage) runs to completion before the
                                // runtime tears down — the same property the push
                                // receiver's `spawn_blocking(run_update_notify)` has;
                                // `updates::get`'s staging FSM is resumable, so no
                                // half-staged state results, only a bounded delay.
                                // The stream task's `spawn_blocking` is parked on a
                                // socket read, so it unblocks when the connection is
                                // dropped or recycled; it holds no staging state.
                                if let Some(task) = &update_poll_task {
                                    task.abort();
                                }
                                if let Some(task) = &update_stream_task {
                                    task.abort();
                                }
                                break;
                            }
                            // Main listener: the loopback gate + caller-asserted
                            // identity (see `serve`) honour `trust_loopback_peers`,
                            // which is false when a tunnel fronts this port.
                            accept = listener.accept() => {
                                spawn_revision_connection(
                                    accept,
                                    &listener_state,
                                    trust_loopback_peers,
                                );
                            }
                            // Admin/console listener (when bound): loopback-scoped
                            // and unreachable from the tunnel, so it always trusts
                            // loopback peers. `pending()` disables this arm when no
                            // admin listener exists.
                            accept = async {
                                match admin_listener.as_ref() {
                                    Some(l) => l.accept().await,
                                    None => std::future::pending::<
                                        std::io::Result<(tokio::net::TcpStream, SocketAddr)>,
                                    >()
                                    .await,
                                }
                            } => {
                                spawn_revision_connection(accept, &listener_state, true);
                            }
                        }
                    }
                    Ok(())
                });
                // The updater's SSE stream loop runs on a `spawn_blocking` thread
                // parked in a synchronous socket read that, by design, has no read
                // timeout: reqwest's blocking client exposes none, so the stream
                // bounds a silently-wedged read with a 900s connection recycle
                // instead (see greentic-update `stream.rs`). Letting this `Runtime`
                // drop would join the blocking pool and block shutdown until that
                // read returns — up to the full recycle interval — which an operator
                // experiences as "Ctrl+C does nothing." This is the terminal shutdown
                // path (`RevisionServer::stop`), so detach the blocking pool rather
                // than wait for it: the parked read's socket and thread are reclaimed
                // by the OS as the process exits.
                runtime.shutdown_background();
                serve_result
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
            admin_port,
            state,
            runtime_handle,
            reload_lock: std::sync::Mutex::new(()),
            generation_watermark: std::sync::Mutex::new(initial_watermark),
        })
    }

    /// The port the server actually bound (may differ from the request if it was
    /// taken). This is the port a tunnel targets.
    pub(crate) fn actual_port(&self) -> u16 {
        self.actual_port
    }

    /// The loopback admin/console listener's port, when one was bound (a tunnel
    /// fronts the main listener). `None` = single listener.
    pub(crate) fn admin_port(&self) -> Option<u16> {
        self.admin_port
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
    /// Per-deployment dispatcher generations are re-anchored against a
    /// server-level high-watermark BEFORE the swap (see
    /// [`crate::revision_dispatcher::RevisionDispatcher::reanchor_generations`]
    /// and [`Self::generation_watermark`]). A deployment whose routable
    /// revision set was fully retained — a pure reweight or a canary addition,
    /// per [`deployments_preserving_stickiness`] — carries its generation
    /// FORWARD so existing cookies/pins stay valid and sessions stay sticky
    /// (B1). Every other deployment bumps, invalidating its stickiness so the
    /// next request re-picks: a removed or ramped-to-zero revision (whose pins
    /// would otherwise flap) and a re-added deployment alike. The watermark
    /// tracks every deployment id this server has ever seen, including ones
    /// removed and re-added — so a remove → re-add rollback within cookie/pin
    /// TTL doesn't leak stickiness from before the removal.
    ///
    /// Holds the [`reload_lock`](Self::reload_lock) for the whole sequence
    /// so concurrent producers (file-watcher + admin signal) cannot race
    /// the `load_full(prev) → reanchor_generations → swap(new)` steps and
    /// lose a generation bump.
    pub(crate) fn reload(&self, new: Activation, drain_window: Duration) -> ReloadReport {
        // Serialize concurrent reloads so the load_full + reanchor_generations
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
        // Deployments whose routable revision set was fully retained from prev
        // to new — these carry their generation forward (sticky sessions
        // survive a reweight / canary addition); everything else bumps. Must
        // run against `prev` while it is still the snapshot served until now.
        let preserve = deployments_preserving_stickiness(
            &prev.routing.dispatcher,
            &new_arc.routing.dispatcher,
        );
        // Update the generation watermark and re-anchor the new dispatcher off
        // it. Absorbing prev → reanchor new → absorb new keeps the watermark
        // strictly monotonic across every deployment id we've ever served
        // (including ids that have been removed), so a re-introduced id always
        // lands at a generation strictly greater than any cookie/pin could
        // still be holding. Preserved deployments carry forward to (not past)
        // the watermark, leaving their existing cookies/pins valid.
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
                .reanchor_generations(&watermark, &preserve);
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

    /// Whether a binary swap succeeded and auto-restart was requested. Polled
    /// by the main thread's shutdown loop to return `BinaryUpdateRestart`.
    pub(crate) fn auto_restart_pending(&self) -> bool {
        self.state.auto_restart_pending.load(Ordering::Relaxed)
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

/// Decide whether a connection's peer should be granted loopback trust.
///
/// Trust is the AND of two facts: the TCP peer is a loopback address, AND this
/// listener is not fronted by a public tunnel. A cloudflared/ngrok quick tunnel
/// forwards external traffic to `127.0.0.1:<port>`, so every tunneled request
/// would otherwise read as a loopback peer and inherit the trust the loopback
/// gate confers on `/chat`, `/workers/invoke`, and caller-asserted identity.
/// When a tunnel fronts the listener we refuse loopback trust outright
/// (`trust_loopback_peers = false`): those endpoints become unavailable for the
/// tunnel's lifetime rather than publicly reachable. `to_canonical` keeps an
/// IPv4-mapped IPv6 loopback (`::ffff:127.0.0.1`, seen under an IPv6 bind)
/// reading as loopback.
fn peer_is_loopback_trusted(trust_loopback_peers: bool, peer: std::net::IpAddr) -> bool {
    trust_loopback_peers && peer.to_canonical().is_loopback()
}

/// Accept-loop helper: spawn a task to serve one accepted connection, deciding
/// loopback trust from this listener's `trust_loopback_peers` and the peer IP.
/// Shared by the main listener and the optional loopback admin listener so each
/// applies its own trust to the same [`ServeState`]/app.
fn spawn_revision_connection(
    accept: std::io::Result<(tokio::net::TcpStream, SocketAddr)>,
    state: &Arc<ServeState>,
    trust_loopback_peers: bool,
) {
    match accept {
        Ok((stream, peer)) => {
            let connection_state = Arc::clone(state);
            let peer_is_loopback = peer_is_loopback_trusted(trust_loopback_peers, peer.ip());
            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    handle_connection(req, connection_state.clone(), peer_is_loopback)
                });
                let io = TokioIo::new(stream);
                // `with_upgrades` is required so the WebSocket handshake
                // completes — without it hyper closes the TCP connection right
                // after the 101 response and hyper-tungstenite's
                // `websocket.await` errors out with "Handshake not finished".
                if let Err(err) = Http1Builder::new()
                    .serve_connection(io, service)
                    .with_upgrades()
                    .await
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
    }
}

/// `service_fn` adapter: collapse the `Ok`/`Err` response halves into the single
/// Cloud Run deferred public-URL capture, extracted from [`handle_connection`]
/// so the decision is unit-testable without constructing a hyper
/// `Request<Incoming>`. On the first inbound request whose headers pass the GFE
/// trust gate AND match this service's own `<service>-*.run.app` URL, records
/// the derived base URL and wakes the deferred webhook-registration task. A
/// no-op once captured, and whenever the headers fail the gate.
///
/// NOTE: Cloud Run Host-forwarding is observed GFE behaviour, not a documented
/// contract. See plan section 7 for the live acceptance test.
fn try_capture_public_url(cap: &PublicUrlCapture, headers: &hyper::HeaderMap) {
    if cap.get().is_none()
        && let Some(url) =
            crate::startup_contract::derive_public_base_url(headers, &cap.expected_service)
    {
        cap.offer(url);
    }
}

/// infallible response hyper wants.
async fn handle_connection(
    mut req: Request<Incoming>,
    state: Arc<ServeState>,
    peer_is_loopback: bool,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // Cloud Run deferred public-URL capture: on the first inbound request
    // through the GFE, derive the public base URL from the Host header and
    // wake the deferred webhook-registration task. Placed BEFORE the WS
    // intercept so even WebSocket-first traffic triggers capture.
    if let Some(cap) = state.public_url_capture.as_ref() {
        try_capture_public_url(cap, req.headers());
    }

    // A5: intercept WebSocket stream paths BEFORE `serve` so the upgrade
    // handshake can borrow the request mutably. The stream path is the WS
    // endpoint browsers open after creating a conversation over REST.
    let path = req.uri().path().to_string();
    if is_directline_stream_path(&path) {
        let (Ok(response) | Err(response)) =
            handle_websocket_upgrade(&mut req, &path, Arc::clone(&state)).await;
        return Ok(response);
    }

    let cors = path_allows_cors(&path);
    let (Ok(response) | Err(response)) = serve(req, state, peer_is_loopback).await;
    Ok(if cors { with_cors(response) } else { response })
}

/// Paths that are never legitimately called cross-origin, and so must not
/// receive `Access-Control-Allow-Origin`.
///
/// `/workers/invoke` executes a flow under the deployment's own tenant and
/// returns its output. It is gated on `peer_is_loopback` — but that gate checks
/// the *TCP peer*, and a page served from any origin, running in a browser on
/// this machine, connects from `127.0.0.1` and passes it. The endpoint does not
/// check `Content-Type` (it just parses the body as JSON), so a blind
/// cross-origin POST is already possible; granting a wildcard
/// `Access-Control-Allow-Origin` would additionally let that page *read the
/// response*, turning a blind write into a full read/write channel. The
/// `X-Frame-Options` header on `/chat` exists to stop exactly this
/// (a cross-site page auto-driving the worker endpoint) — blanket CORS would
/// reopen it by another door.
///
/// Nothing legitimate needs CORS here: the built-in `/chat` console fetches it
/// **same-origin** (a relative `fetch('/workers/invoke')`, see `assets/chat.html`)
/// and `greentic-gui` reaches it **server-side** via `HttpWorkerBackend`, where
/// CORS does not apply.
fn path_allows_cors(path: &str) -> bool {
    path != "/workers/invoke"
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

    // CORS preflight: browsers send OPTIONS with no auth and no body before
    // any cross-origin POST. Short-circuited here — before probes, chat
    // assets, worker-invoke, and admission gates — because every one of
    // those either ignores non-GET/POST or hard-rejects the method,
    // turning the preflight into a 405 the browser treats as an opaque
    // CORS failure. Mirrors the legacy `http_ingress` short-circuit.
    if method == hyper::Method::OPTIONS {
        if !path_allows_cors(&path) {
            return Ok(error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "cross-origin requests are not permitted on this path",
            ));
        }
        return Ok(cors_preflight_response());
    }

    if let Some(response) = try_probe_response(&path, &state) {
        return Ok(response);
    }

    // Built-in webchat console: serve the static `/chat` page and its renderer
    // when the env has the GUI enabled. Short-circuited here — after probes,
    // before deployment-route resolution — so a broad `/`-prefix route binding
    // can't shadow it (same reason `/workers/invoke` short-circuits below). The
    // page POSTs to that same loopback `/workers/invoke` endpoint.
    //
    // Loopback-gated, matching the loopback-only `/workers/invoke` it drives: on
    // a public bind (a non-local env that opted the GUI in) the console is only
    // served to co-located callers, so a remote client never receives the page
    // (it falls through to deployment routing → 404). The page also carries
    // anti-framing headers (see `asset_response`) so a cross-site iframe can't
    // load it and auto-drive the worker endpoint.
    if state.gui_enabled
        && peer_is_loopback
        && let Some(response) = try_chat_asset_response(&path, &method)
    {
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

    // Phase-4 signed update-plan receiver: a plan server POSTs a DSSE-signed
    // update plan here and the receiver verifies + (optionally) stages it via the
    // deployer `updates::get` library call. Short-circuited before deployment-route
    // resolution for the same reason as `/workers/invoke` — a broad `/`-prefix
    // route binding would otherwise run it as a generic entry-flow activity.
    //
    // NOT loopback-gated (unlike `/chat` and `/workers/invoke`): the notification
    // originates off-host from the plan server. The auth boundary is the DSSE
    // signature verification against the env trust root (inside `updates::get`)
    // plus the per-env update-channel `enabled` gate (deny-by-default) — the same
    // posture as signature-verified provider webhooks, not caller-asserted trust.
    // Only reserve this path on envs that actually have an update channel
    // configured (an `update-channel.json` sidecar). On every other env the
    // request falls through to normal deployment routing, so adding this platform
    // path never shadows an existing app route (e.g. a broad `/`-prefix binding)
    // on an env that never opted into the updater.
    // `--no-updates` also closes this door: the kill switch is "not on this box",
    // so neither the pull nor the push half of the updater may run.
    if path == "/v1/updates/notify" {
        let intercept = state.updates_enabled
            && LocalFsStore::default_root().is_some_and(|root| {
                update_channel_present(&root, state.current().routing.dispatcher.env_id())
            });
        if intercept {
            if method != hyper::Method::POST {
                return Err(error_response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "update notify requires POST",
                ));
            }
            return handle_update_notify(req, Arc::clone(&state)).await;
        }
    }

    // Snapshot the activation ONCE per request so dispatch and execute see a
    // coherent (host, routing) pair. A concurrent [`RevisionServer::reload`]
    // swap is observed by the *next* request; this one keeps running against
    // the activation it pinned here.
    let activation = state.current();

    let host_header = header_str(req.headers(), header::HOST.as_str());
    let cookie_header = header_str(req.headers(), header::COOKIE.as_str());
    let content_type_header = header_str(req.headers(), header::CONTENT_TYPE.as_str());
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

    // Phase D.3: the body is read as raw bytes; the strict JSON parse is
    // deferred until we know this is the generic-JSON branch (provider
    // webhooks send form-urlencoded / signature payloads that the provider
    // component decodes itself). `caller_identity` only consumes a JSON
    // body on loopback peers — non-loopback callers go straight to
    // `(None, None, None)` regardless of body content — so we skip the
    // tolerant parse entirely off-loopback to save the cost on every
    // public provider webhook.
    let identity_payload: Value = if peer_is_loopback && !body_bytes.is_empty() {
        serde_json::from_slice(&body_bytes).unwrap_or(Value::Null)
    } else {
        Value::Null
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
        &identity_payload,
    );

    // M1.4c-ii admit gate, step 1: if the caller asserts a messaging endpoint,
    // it MUST be one this env declared. Checked here (before dispatch) so an
    // unknown asserted endpoint refuses cheaply; the bundle-membership check
    // is step 2, inside [`resolve_endpoint_for_scope`] after dispatch picks a
    // revision.
    resolve_endpoint_admission(
        header_endpoint_id.as_deref(),
        activation.routing.endpoint_admit.as_ref(),
    )
    .map_err(|boxed| *boxed)?;

    // A1: external provider webhooks carry no caller-asserted session header and
    // no stickiness cookie, so caller_identity yields None and every message would
    // re-pick a revision at random, flapping a single chat between bundles. Derive
    // a stable chat/channel-level hint from the webhook body so the pin store keeps
    // the conversation on one revision. provider_type is revision-independent so it
    // resolves before dispatch. Loopback callers already supply their own hint.
    //
    // A4: webchat/DirectLine carries the conversation_id in the URL path, not
    // the body. Try path-based extraction first (cheap, no parse) then fall
    // back to body-based for other providers.
    let session_hint = session_hint.or_else(|| {
        if peer_is_loopback {
            return None;
        }
        // A4: DirectLine conversation stickiness — the conversation_id is in
        // the URL path, not the webhook body.
        if let Some(hint) = crate::session_hint_extractor::extract_webchat_session_hint(&path) {
            return Some(hint);
        }
        let provider_type = activation.routing.http_routes.provider_type_for(
            &path,
            method.as_str(),
            deployment_id,
        )?;
        let provider = crate::http_routes::derive_provider_name(provider_type)?;
        crate::session_hint_extractor::extract_session_hint(
            &provider,
            content_type_header.as_deref(),
            &body_bytes,
        )
    });

    let cookie_value = cookie_header
        .as_deref()
        .and_then(|jar| read_cookie(jar, &cookie_name(deployment_id)));

    let dispatch_req = DispatchRequest {
        env_id: activation.routing.dispatcher.env_id(),
        tenant: &tenant,
        deployment_id,
        session_hint: session_hint.as_deref(),
        // A1 derives this hint from the raw (not-yet-authenticated) provider
        // body for non-loopback webhooks, so defer the pin write until the
        // auth gate in `dispatch_provider_route` admits the request. Loopback /
        // caller-asserted hints are trusted and pin inline. The pin LOOKUP is
        // unaffected — a returning chat stays sticky either way.
        defer_pin: !peer_is_loopback,
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

    // A3: revision-scoped static routes. Checked AFTER reserved operator
    // paths (probes, /chat, /workers/invoke, /v1/updates/notify) which all
    // short-circuited above, and AFTER deployment-route resolution, but
    // BEFORE the provider-route admission gate and generic-flow branch.
    // Only GET — a POST to a path that happens to overlap a static route's
    // public_path prefix must fall through to the provider/generic flow so
    // webhooks keep working.
    if method == hyper::Method::GET
        && let Some(route_match) = activation
            .routing
            .static_routes
            .match_request_for_revision(&path, &scope)
    {
        let response = crate::static_handler::serve_static_route_from_pack(&route_match, &path);
        return Ok(with_cors(response));
    }

    // Phase D.3: branch out to the provider-route handler BEFORE the
    // generic-JSON path runs the endpoint resolver / strict JSON parse /
    // entry-flow build_activity. Provider webhooks send raw bodies
    // (form-urlencoded, signature blobs, custom encodings) that the
    // provider component decodes itself; forcing JSON parse here would
    // turn every non-JSON webhook into a 400 even though the provider
    // would have handled it correctly.
    match admit_request(&activation.routing.http_routes, &scope, &path, &method) {
        Admission::ProviderRoute => {
            return dispatch_provider_route(
                Arc::clone(&activation),
                Arc::clone(&state),
                &tenant,
                &scope,
                &path,
                method.as_str(),
                query_string.as_deref(),
                &request_headers,
                &body_bytes,
                peer_is_loopback,
                &identify_headers,
                header_endpoint_id.as_deref(),
                session_hint.as_deref(),
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

    // Generic-JSON branch: NOW require the body to be valid JSON. Provider
    // routes already short-circuited above with the raw bytes.
    let payload: Value = if body_bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body_bytes)
            .map_err(|_| error_response(StatusCode::BAD_REQUEST, "request body must be JSON"))?
    };

    // M1 IID.4 resolver + M1.4c-ii admit + M1.5 welcome hint — shared with the
    // provider-route arm; see [`resolve_endpoint_for_scope`]. The structured
    // `(headers, body)` pair is built lazily from the already-parsed JSON body
    // and the allowlisted header list; the runner builds the per-provider
    // wrapper from each component's describe-identify-instance hint.
    let (endpoint_id, welcome_hint) = resolve_endpoint_for_scope(
        &activation,
        &tenant,
        &scope,
        header_endpoint_id.as_deref(),
        peer_is_loopback,
        || (identify_headers.clone(), payload.clone()),
    )
    .await?;

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
        // Worker-invoke is loopback-gated (trusted caller), so the supplied
        // session id pins inline like other caller-asserted hints.
        defer_pin: false,
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

/// Wire contract `greentic.update-notify.v1`: a signed update plan pushed to a
/// running environment by a plan server. `plan_b64` / `sig_b64` carry the EXACT
/// plan document and DSSE-envelope bytes, base64-encoded. They are base64 (not a
/// nested JSON plan) on purpose: DSSE verification pins `sha256(plan_bytes)` as
/// the subject digest, so the bytes must survive transport unaltered — nesting
/// the plan as JSON would re-serialize it and break the digest.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateNotifyV1 {
    schema: String,
    plan_b64: String,
    sig_b64: String,
}

/// The wire `schema` discriminator the receiver accepts.
const UPDATE_NOTIFY_SCHEMA_V1: &str = "greentic.update-notify.v1";

/// What the receiver does with a transport-accepted notification, resolved from
/// the env's update-channel policy. Deny-by-default: an absent or disabled
/// channel is [`NotifyAction::Ignore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotifyAction {
    Ignore,
    Record,
    Stage,
    /// Stage, then converge this environment onto the plan's target manifest.
    Apply,
}

/// A staging failure. `Op` is a deployer [`OpError`] from `updates::get` (mapped
/// to an HTTP status by [`map_op_error`], with a category-only body so trust /
/// path details never leak to the caller). `Internal` is a server-side failure
/// (store, tempfile, env-id) reported as an opaque 500.
#[derive(Debug)]
enum NotifyError {
    Op(OpError),
    Internal(String),
}

/// Parse + validate a `greentic.update-notify.v1` body into the raw plan and
/// signature bytes. `Err((status, message))` is a ready 4xx (all client faults:
/// malformed JSON, unknown schema, non-base64 payloads).
fn decode_update_notify(body: &[u8]) -> Result<(Vec<u8>, Vec<u8>), (StatusCode, String)> {
    let notify: UpdateNotifyV1 = serde_json::from_slice(body).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid update-notify body: {err}"),
        )
    })?;
    if notify.schema != UPDATE_NOTIFY_SCHEMA_V1 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("unsupported update-notify schema `{}`", notify.schema),
        ));
    }
    let plan = BASE64.decode(notify.plan_b64.as_bytes()).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("plan_b64 is not valid base64: {err}"),
        )
    })?;
    let sig = BASE64.decode(notify.sig_b64.as_bytes()).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("sig_b64 is not valid base64: {err}"),
        )
    })?;
    Ok((plan, sig))
}

/// Resolve the update-channel policy into the action to take. Deny-by-default:
/// `resolved_enabled()` is `false` for an absent (`None`) or `enabled: None/false`
/// channel, so an operator must explicitly opt the environment in.
///
/// Reads `resolved_action()`, which prefers the `on_update` field and falls back
/// to the legacy `on_notify` when it is absent — a channel written by an older
/// deployer keeps its meaning. `UpdateAction` is `#[non_exhaustive]`; an action
/// this binary does not know is treated as `Stage`, the conservative floor:
/// content lands on disk, traffic does not move.
fn notify_action(cfg: &UpdateChannelConfig) -> NotifyAction {
    if !cfg.resolved_enabled() {
        return NotifyAction::Ignore;
    }
    match cfg.resolved_action() {
        UpdateAction::RecordOnly => NotifyAction::Record,
        UpdateAction::Stage => NotifyAction::Stage,
        UpdateAction::Apply => NotifyAction::Apply,
        _ => NotifyAction::Stage,
    }
}

/// Whether `env_id` has an update channel configured — i.e. an
/// `update-channel.json` sidecar exists under its env dir. Only such envs
/// reserve `/v1/updates/notify`; every other env lets the path fall through to
/// normal deployment routing (see the route gate in [`serve`]).
fn update_channel_present(store_root: &std::path::Path, env_id: &str) -> bool {
    match crate::runtime_config::env_dir_in(store_root, env_id) {
        Ok(env_dir) => env_dir.join("update-channel.json").exists(),
        Err(_) => false,
    }
}

/// Verify a posted plan the way the stage path does — trusted-key DSSE signature
/// plus target-env match — but WITHOUT staging it. Used by the record-only path
/// so an enabled record-only channel records a *verified* notification. Reuses
/// the shared [`verify_update_plan`] primitive (verification is not forked); a
/// missing/empty trust root fails closed. Failures surface as the same
/// [`OpError`] categories `map_op_error` maps for the stage path — verification
/// or trust-root problems → 409, target-env mismatch → 400.
fn verify_signed_plan(
    store: &LocalFsStore,
    env_id: &EnvId,
    plan: &[u8],
    sig: &[u8],
) -> Result<(), NotifyError> {
    let env_dir = crate::runtime_config::env_dir_in(store.root(), env_id.as_str())
        .map_err(|err| NotifyError::Internal(format!("resolve env dir: {err}")))?;
    let trust = load_trust_root(&env_dir).map_err(|err| {
        NotifyError::Op(OpError::Conflict(format!(
            "record-only verify: trust root unavailable: {err}"
        )))
    })?;
    let verified = verify_update_plan(plan, sig, &trust).map_err(|err| {
        NotifyError::Op(OpError::Conflict(format!(
            "record-only verify: plan verification failed: {err}"
        )))
    })?;
    if verified.plan.env_id.as_str() != env_id.as_str() {
        return Err(NotifyError::Op(OpError::InvalidArgument(format!(
            "record-only verify: plan targets env `{}`, not this environment",
            verified.plan.env_id
        ))));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Binary self-update (P7d: stage-only apply, no restart)
// ---------------------------------------------------------------------------

/// Size cap for a binary release archive fetch (256 MiB). Binary archives are
/// larger than a plan doc but still bounded — a compromised or misbehaving
/// source cannot exhaust memory.
const MAX_BINARY_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;

/// Timeout for the binary archive download.
const BINARY_FETCH_TIMEOUT: Duration = Duration::from_secs(300);

/// Marker file name persisted under the env dir when a binary swap succeeds.
/// Its presence signals "a newer binary is on disk but the running process has
/// not restarted yet." Idempotent: re-applying the same version does not
/// re-write it.
const BINARY_UPDATE_PENDING_FILE: &str = "binary-update-pending.json";

/// Typed marker written to [`BINARY_UPDATE_PENDING_FILE`] after a binary swap.
/// Old markers (pre-P7e) that lack `phase` deserialize as [`MarkerPhase::Pending`]
/// via the serde default.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct BinaryUpdateMarker {
    name: String,
    pub(crate) from_version: String,
    pub(crate) to_version: String,
    staged_at: String,
    #[serde(default = "default_marker_phase")]
    pub(crate) phase: MarkerPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rolled_back_at: Option<String>,
    /// SHA-256 digest of the binary artifact at swap time. Allows the
    /// tombstone guard to distinguish a same-version re-release (different
    /// build artifact) from the exact binary that already failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) digest: Option<String>,
    /// Number of times this pending marker has been booted. Incremented and
    /// persisted (fsync) before boot proceeds; when it exceeds
    /// [`MAX_BOOT_ATTEMPTS`] the boot-time logic rolls back immediately
    /// instead of arming the RAII guard, breaking hard-kill crash loops.
    #[serde(default)]
    pub(crate) boot_attempts: u32,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MarkerPhase {
    Pending,
    RolledBack,
}

fn default_marker_phase() -> MarkerPhase {
    MarkerPhase::Pending
}

/// Read and parse the binary-update marker for the given env dir.
/// Returns `None` if the file is absent or unparseable.
pub(crate) fn read_binary_update_marker(env_dir: &std::path::Path) -> Option<BinaryUpdateMarker> {
    let path = env_dir.join(BINARY_UPDATE_PENDING_FILE);
    let bytes = std::fs::read(&path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Delete the binary-update marker.
pub(crate) fn clear_binary_update_marker(env_dir: &std::path::Path) {
    let path = env_dir.join(BINARY_UPDATE_PENDING_FILE);
    let _ = std::fs::remove_file(&path);
}

/// Maximum number of boot attempts before the boot-time logic rolls back
/// immediately instead of arming the RAII guard. A hard-killed process
/// (OOM-kill, SIGKILL, SIGSEGV) runs no destructors, so the guard never
/// fires; the counter breaks the infinite crash-loop.
pub(crate) const MAX_BOOT_ATTEMPTS: u32 = 3;

/// Decision the boot-time marker processing should execute. Extracted as a
/// pure function so the logic is unit-testable without standing up the full
/// `run_start` environment.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BootAction {
    /// No marker on disk — proceed with a normal boot.
    Proceed,
    /// Pending marker, `to_version == own`: arm the rollback guard with the
    /// (already-incremented) marker.
    ArmGuard(BinaryUpdateMarker),
    /// Pending marker, `to_version == own`, but `boot_attempts >= MAX`:
    /// roll back immediately (tombstone + restore_prev + exec).
    RollbackNow(BinaryUpdateMarker),
    /// Marker is stale or matches a different version lineage — delete it.
    ClearMarker,
    /// Rolled-back tombstone where `to_version == own` (restore_prev failed,
    /// supervisor restarted the broken binary): keep the tombstone so the
    /// anti-retry guard still blocks re-swap.
    PreserveTombstone,
}

/// Decide what the boot should do given an optional on-disk marker and the
/// version of the running binary.
pub(crate) fn decide_boot_action(
    marker: Option<BinaryUpdateMarker>,
    own_version: &str,
) -> BootAction {
    let marker = match marker {
        Some(m) => m,
        None => return BootAction::Proceed,
    };
    match marker.phase {
        MarkerPhase::Pending if marker.to_version == own_version => {
            if marker.boot_attempts >= MAX_BOOT_ATTEMPTS {
                BootAction::RollbackNow(marker)
            } else {
                BootAction::ArmGuard(marker)
            }
        }
        MarkerPhase::Pending if marker.from_version == own_version => BootAction::Proceed,
        MarkerPhase::RolledBack if marker.from_version == own_version => BootAction::Proceed,
        MarkerPhase::RolledBack if marker.to_version == own_version => {
            BootAction::PreserveTombstone
        }
        _ => BootAction::ClearMarker,
    }
}

/// Durably write the marker to disk: create, write_all, fsync. Returns an
/// error if any step fails — the caller must treat a failure as "rollback
/// state not persisted."
/// Persist the rollback marker, undoing the binary swap if it cannot be written.
///
/// The marker is the rollback state: without it on disk the boot-fail guard
/// cannot arm, so a new binary that fails to boot would never be rolled back.
/// Rather than exec into a binary with no rollback coverage, restore the
/// previous one and fail the binary step (content staging is unaffected).
fn persist_marker_or_undo_swap(
    env_dir: &std::path::Path,
    marker: &BinaryUpdateMarker,
    exe_path: &std::path::Path,
) -> Result<(), NotifyError> {
    let Err(err) = write_marker_durable(env_dir, marker) else {
        return Ok(());
    };
    operator_log::error(
        module_path!(),
        format!("binary-update: failed to persist rollback marker: {err}; undoing swap"),
    );
    if let Err(restore_err) = binswap::restore_prev(exe_path) {
        operator_log::error(
            module_path!(),
            format!(
                "binary-update: restore_prev ALSO failed after marker write failure: \
                 {restore_err}; manual recovery required"
            ),
        );
    }
    Err(NotifyError::Internal(format!(
        "binary update aborted: rollback marker not persisted: {err}"
    )))
}

pub(crate) fn write_marker_durable(
    env_dir: &std::path::Path,
    marker: &BinaryUpdateMarker,
) -> std::io::Result<()> {
    use std::io::Write;
    let path = env_dir.join(BINARY_UPDATE_PENDING_FILE);
    let bytes = serde_json::to_vec_pretty(marker).map_err(std::io::Error::other)?;
    let file = std::fs::File::create(&path)?;
    let mut writer = std::io::BufWriter::new(file);
    writer.write_all(&bytes)?;
    let file = writer.into_inner()?;
    file.sync_all()?;
    Ok(())
}

/// Write a rolled-back tombstone marker.
pub(crate) fn write_rollback_tombstone(env_dir: &std::path::Path, marker: &BinaryUpdateMarker) {
    let tombstone = BinaryUpdateMarker {
        phase: MarkerPhase::RolledBack,
        rolled_back_at: Some(chrono::Utc::now().to_rfc3339()),
        ..marker.clone()
    };
    let path = env_dir.join(BINARY_UPDATE_PENDING_FILE);
    if let Ok(bytes) = serde_json::to_vec_pretty(&tombstone) {
        let _ = std::fs::write(&path, bytes);
    }
}

/// Concurrent update notifies must not both pass the marker inspection before
/// either writes. Coarse hold is fine: swaps are rare and the function is sync
/// on blocking threads.
/// The process resolves a single env at startup, so a process-wide lock equals
/// a per-env lock today; a per-env lock would be needed if multi-env-per-process
/// ever lands.
static BINARY_UPDATE_SWAP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Post-acquisition shared path: swap a verified binary into `current_exe`,
/// build and persist the rollback marker, and return the staged-JSON fragment.
/// Called by both the URL-fetch path and the in-band staging path so the
/// swap + marker logic is not duplicated.
fn apply_binary_from_path(
    own_name: &str,
    binary: &greentic_update::plan::BinaryArtifact,
    inner_binary: &std::path::Path,
    current_exe: &std::path::Path,
    env_dir: &std::path::Path,
    current_version: &str,
) -> Result<Option<Value>, NotifyError> {
    let swap_opts = binswap::SwapOptions {
        expected_digest: Some(binary.digest.clone()),
    };
    binswap::swap_binary(inner_binary, current_exe, &swap_opts).map_err(|err| {
        // Fail-closed: the binary is NOT applied, content staging stays
        // intact. Log the category, never leak the path.
        operator_log::error(module_path!(), format!("binary-update: swap failed: {err}"));
        NotifyError::Internal("binary update swap failed".to_string())
    })?;

    // Durably persist the rollback marker BEFORE reporting success. The
    // marker is the rollback state — without it the boot-fail guard cannot
    // arm, and a crash-looping new binary is never rolled back. If the
    // write fails, undo the swap so we never exec into a binary that has
    // no rollback coverage.
    let marker = BinaryUpdateMarker {
        name: own_name.to_string(),
        from_version: current_version.to_string(),
        to_version: binary.version.clone(),
        staged_at: chrono::Utc::now().to_rfc3339(),
        phase: MarkerPhase::Pending,
        rolled_back_at: None,
        digest: Some(binary.digest.clone()),
        boot_attempts: 0,
    };
    persist_marker_or_undo_swap(env_dir, &marker, current_exe)?;

    operator_log::warn(
        module_path!(),
        format!(
            "binary-update: {own_name} {} installed; restart required to activate",
            binary.version,
        ),
    );

    Ok(Some(serde_json::json!({
        "staged": true,
        "restart_required": true,
        "version": binary.version,
    })))
}

/// Read `env_id`'s update channel off disk and return `blob_base_url` when set.
/// An absent or unreadable channel, or an unset field, yields `None`.
///
/// No `resolved_enabled()` gate: reaching `try_apply_binary_update` already
/// implies the channel was enabled (`notify_action` gated it upstream), so
/// re-gating here would duplicate the check with no added safety.
fn load_blob_base_url(store: &LocalFsStore, env_id: &str) -> Option<String> {
    let env_typed = EnvId::new(env_id).ok()?;
    let cfg = store.load_update_channel(&env_typed).ok()??;
    cfg.resolved_blob_base_url().map(|s| s.to_owned())
}

/// Validate a `sha256:<hex>` digest string and return the bare hex if valid.
/// Returns `Err` with a human-readable message if the digest is malformed
/// (missing prefix, wrong length, non-hex chars). This is an URL-injection
/// defense: we build a fetch URL from the hex so it must be tightly validated
/// before any network call.
fn validate_digest_hex(digest: &str) -> Result<&str, String> {
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("binary-update: digest missing `sha256:` prefix: {digest}"))?;
    if hex.len() != 64 {
        return Err(format!(
            "binary-update: digest hex must be 64 chars, got {}: {digest}",
            hex.len(),
        ));
    }
    if !hex
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(format!(
            "binary-update: digest contains non-lowercase-hex chars: {digest}",
        ));
    }
    Ok(hex)
}

/// Fetch a binary blob from a blob-mirror HTTP endpoint.
///
/// The deployer's `import --push-to` (C3) writes blobs as `blobs/sha256-<hex>`,
/// so the mirror URL is `{base_url}/sha256-{hex}` where the hex is extracted
/// from the `sha256:<hex>` digest string (colon → hyphen in the URL).
///
/// The transport's scheme is NOT validated here: the blob is digest-verified
/// against the DSSE-verified plan, so the mirror is a cache and never an
/// authority — plaintext transport can cause a denial but never a compromise.
/// The deployer's `config-set` (C2) is the single validation altitude for host
/// policy, and `greentic-start` likewise does not validate `plan_endpoint`'s
/// scheme today (see `resolve_poll_cycle`). Adding a second altitude here would
/// drift from C2.
fn fetch_blob_from_mirror(base_url: &str, digest: &str) -> Result<Vec<u8>, String> {
    fetch_blob_from_mirror_capped(base_url, digest, MAX_BINARY_ARCHIVE_BYTES)
}

/// Inner implementation with an explicit byte cap, so tests can exercise the
/// cap-check branch without allocating 256 MiB.
fn fetch_blob_from_mirror_capped(
    base_url: &str,
    digest: &str,
    cap: u64,
) -> Result<Vec<u8>, String> {
    let hex = validate_digest_hex(digest)?;

    let url = format!("{}/sha256-{hex}", base_url.trim_end_matches('/'));

    let client = reqwest::blocking::Client::builder()
        .timeout(BINARY_FETCH_TIMEOUT)
        .build()
        .map_err(|err| format!("binary-update: mirror: failed to build HTTP client: {err}"))?;

    use std::io::Read as _;
    let resp = client
        .get(&url)
        .send()
        .map_err(|err| format!("binary-update: mirror fetch failed for {url}: {err}"))?
        .error_for_status()
        .map_err(|err| format!("binary-update: mirror fetch status error for {url}: {err}"))?;

    let mut buf = Vec::new();
    resp.take(cap + 1)
        .read_to_end(&mut buf)
        .map_err(|err| format!("binary-update: mirror read error: {err}"))?;
    if buf.len() as u64 > cap {
        return Err(format!("binary-update: mirror blob exceeds {cap} byte cap",));
    }

    // Digest verification: the plan is DSSE-verified, so the expected digest is
    // authoritative. A mismatch means the mirror served wrong bytes.
    let actual = sha256_hex(&buf);
    if actual != hex {
        return Err(format!(
            "binary-update: mirror blob digest mismatch: expected sha256:{hex}, got sha256:{actual}",
        ));
    }

    Ok(buf)
}

/// Shared tail for both in-band and mirror blob acquisition: write the raw
/// binary bytes to a temp file, set executable permissions on Unix, then apply
/// via `apply_binary_from_path`. The byte buffer is consumed (moved in) so it
/// is dropped after the temp-file write and before the swap, avoiding doubled
/// peak memory — the same property the original in-band path preserved.
fn write_blob_and_apply(
    blob_bytes: Vec<u8>,
    own_name: &str,
    binary: &greentic_update::plan::BinaryArtifact,
    current_exe: &std::path::Path,
    env_dir: &std::path::Path,
    current_version: &str,
) -> Result<Option<Value>, NotifyError> {
    let tmp_dir = tempfile::TempDir::new().map_err(|err| {
        NotifyError::Internal(format!(
            "binary-update: failed to create temp dir for binary: {err}"
        ))
    })?;
    let tmp_binary = tmp_dir.path().join(own_name);
    std::fs::write(&tmp_binary, &blob_bytes).map_err(|err| {
        NotifyError::Internal(format!(
            "binary-update: failed to write binary to temp: {err}"
        ))
    })?;
    // Release the buffer before the swap so peak memory holds one copy, not two.
    // The caller moved it in, so this `drop` is what makes that guaranteed —
    // the original in-band path got the same effect from a narrower scope.
    drop(blob_bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_binary, std::fs::Permissions::from_mode(0o755)).map_err(
            |err| {
                NotifyError::Internal(format!(
                    "binary-update: failed to set executable permissions: {err}"
                ))
            },
        )?;
    }

    apply_binary_from_path(
        own_name,
        binary,
        &tmp_binary,
        current_exe,
        env_dir,
        current_version,
    )
}

/// Attempt to apply a binary self-update for THIS process after content staging
/// has succeeded. Returns a JSON fragment to merge into the notify response, or
/// `None` when no binary update applies to this host (the normal case for plans
/// that carry only content updates).
///
/// Fail-closed on every guard: a failure here does NOT regress the content
/// staging that already completed — the content apply stands, only the binary
/// step is skipped/errored.
fn try_apply_binary_update(
    plan_bytes: &[u8],
    sig_bytes: &[u8],
    store: &LocalFsStore,
    env_id: &str,
    exe_path: Option<&std::path::Path>,
    updates_root_override: Option<&std::path::Path>,
) -> Result<Option<Value>, NotifyError> {
    // 1. Verify the plan to get the VerifiedUpdatePlan (which has `binaries`).
    //    Content staging already verified via `updates::get`, but we need our own
    //    VerifiedUpdatePlan handle. Re-verification is cheap (no I/O beyond the
    //    trust-root read) and avoids coupling to the deployer's internal verified
    //    plan representation.
    let env_dir = crate::runtime_config::env_dir_in(store.root(), env_id)
        .map_err(|err| NotifyError::Internal(format!("resolve env dir: {err}")))?;
    let trust = load_trust_root(&env_dir).map_err(|err| {
        NotifyError::Internal(format!("binary-update: trust root unavailable: {err}"))
    })?;
    let verified = verify_update_plan(plan_bytes, sig_bytes, &trust).map_err(|err| {
        // Content staging already succeeded against the same trust root, so a
        // verification failure here is a logic error, not a user fault.
        NotifyError::Internal(format!("binary-update: plan re-verification failed: {err}"))
    })?;

    // 2. Select THIS binary for THIS host.
    let own_name = env!("CARGO_PKG_NAME");
    let own_target = binswap::current_target();
    let binary = match select_binary(&verified.plan.binaries, own_name, own_target) {
        Ok(Some(b)) => b,
        Ok(None) => return Ok(None), // No binary update for this host — content-only.
        Err(err) => {
            // Ambiguous: fail-closed, do not guess.
            operator_log::error(
                module_path!(),
                format!(
                    "binary-update: ambiguous binary selection for \
                     `{own_name}` / `{own_target}`: {err}"
                ),
            );
            return Err(NotifyError::Internal(
                "binary update refused: ambiguous binary in plan".to_string(),
            ));
        }
    };

    // 3. Guards (fail-safe / fail-closed), BEFORE any download or staging read.

    // 3a. Container refuse: distroless/immutable images cannot (and should not)
    //     swap binaries on disk — update via image tag instead.
    if binswap::is_container_environment() {
        operator_log::warn(
            module_path!(),
            "binary-update: skipped — containerized deployment; update via image tag",
        );
        return Ok(None);
    }

    // 3b. Version guard: refuse downgrades and no-op on equal version.
    let current_version = env!("CARGO_PKG_VERSION");
    match (
        semver::Version::parse(&binary.version),
        semver::Version::parse(current_version),
    ) {
        (Ok(plan_ver), Ok(running_ver)) => {
            if plan_ver < running_ver {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "binary-update: skipped — plan version {} is older than \
                         running version {current_version} (anti-rollback)",
                        binary.version,
                    ),
                );
                return Ok(None);
            }
            if plan_ver == running_ver {
                operator_log::info(
                    module_path!(),
                    format!("binary-update: skipped — already running version {current_version}",),
                );
                return Ok(None);
            }
        }
        (Err(err), _) => {
            operator_log::warn(
                module_path!(),
                format!(
                    "binary-update: skipped — plan binary version `{}` is not valid semver: {err}",
                    binary.version,
                ),
            );
            return Ok(None);
        }
        (_, Err(err)) => {
            operator_log::warn(
                module_path!(),
                format!(
                    "binary-update: skipped — running version `{current_version}` \
                     is not valid semver: {err}",
                ),
            );
            return Ok(None);
        }
    }

    // Serialize the marker-read → swap → marker-write critical section so
    // concurrent notify requests cannot both pass the marker inspection
    // before either writes. Held for the rest of the function.
    let _swap_guard = BINARY_UPDATE_SWAP_LOCK
        .lock()
        .expect("binary update swap lock poisoned");

    // 3d. Lineage protection: the `.prev` backup and pending marker form
    //     the rollback lineage. A second different-version swap before
    //     reboot would overwrite the only known-good backup with a
    //     never-booted binary, destroying the ability to roll back. When a
    //     Pending marker exists for the SAME version+digest, short-circuit
    //     idempotently; for ANY other Pending marker, refuse fail-closed.
    let marker_path = env_dir.join(BINARY_UPDATE_PENDING_FILE);
    if let Some(existing_marker) = read_binary_update_marker(&env_dir) {
        if existing_marker.phase == MarkerPhase::Pending
            && existing_marker.to_version == binary.version
            && existing_marker
                .digest
                .as_ref()
                .is_none_or(|d| d == &binary.digest)
        {
            operator_log::info(
                module_path!(),
                format!(
                    "binary-update: version {} already staged; restart required to activate",
                    binary.version,
                ),
            );
            return Ok(Some(serde_json::json!({
                "staged": true,
                "restart_required": true,
                "version": binary.version,
            })));
        }

        if existing_marker.phase == MarkerPhase::Pending {
            // A different version (or same version, different digest) is
            // already staged. Refuse the swap to protect the rollback
            // lineage — the caller must restart first.
            operator_log::warn(
                module_path!(),
                format!(
                    "binary-update: version {} blocked — version {} already staged \
                     and awaiting restart; a second swap would destroy the rollback \
                     backup. Restart first, then retry.",
                    binary.version, existing_marker.to_version,
                ),
            );
            return Ok(Some(serde_json::json!({
                "staged": false,
                "blocked_on_pending": existing_marker.to_version,
                "restart_required": true,
            })));
        }

        // 3e. Anti-rollback tombstone: a previous attempt to run this version
        //     failed to boot and was rolled back. Do not retry the SAME build
        //     artifact. If the digest differs (a same-version re-release with
        //     a fixed binary), allow the swap. Hoisted above the source
        //     dispatch so a crash-looped in-band binary is not auto-retried.
        if existing_marker.phase == MarkerPhase::RolledBack
            && existing_marker.to_version == binary.version
            && existing_marker
                .digest
                .as_ref()
                .is_none_or(|d| d == &binary.digest)
        {
            operator_log::warn(
                module_path!(),
                format!(
                    "binary-update: version {} previously rolled back after boot failure \
                     at {}; refusing auto-retry. Clear `{}` to override.",
                    binary.version,
                    existing_marker
                        .rolled_back_at
                        .as_deref()
                        .unwrap_or("unknown"),
                    marker_path.display(),
                ),
            );
            return Ok(None);
        }
    }

    // Resolve the current exe once — shared by both acquisition paths.
    let current_exe = match exe_path {
        Some(p) => p.to_path_buf(),
        None => std::env::current_exe().map_err(|err| {
            NotifyError::Internal(format!("binary-update: cannot resolve current exe: {err}"))
        })?,
    };

    // 4. Acquire the binary — URL-fetch or in-band staging read.
    match &binary.source {
        Some(source_url) => {
            // URL path: fetch the archive, unpack, then apply.
            let archive_dir = tempfile::TempDir::new().map_err(|err| {
                NotifyError::Internal(format!("binary-update: failed to create temp dir: {err}"))
            })?;
            let archive_ext = if source_url.ends_with(".zip") {
                "archive.zip"
            } else {
                "archive.tgz"
            };
            let archive_path = archive_dir.path().join(archive_ext);

            {
                let client = reqwest::blocking::Client::builder()
                    .timeout(BINARY_FETCH_TIMEOUT)
                    .build()
                    .map_err(|err| {
                        NotifyError::Internal(format!(
                            "binary-update: failed to build HTTP client: {err}"
                        ))
                    })?;

                use std::io::Read as _;
                let resp = client
                    .get(source_url)
                    .send()
                    .map_err(|err| {
                        NotifyError::Internal(format!("binary-update: archive fetch failed: {err}"))
                    })?
                    .error_for_status()
                    .map_err(|err| {
                        NotifyError::Internal(format!(
                            "binary-update: archive fetch status error: {err}"
                        ))
                    })?;

                let mut buf = Vec::new();
                resp.take(MAX_BINARY_ARCHIVE_BYTES + 1)
                    .read_to_end(&mut buf)
                    .map_err(|err| {
                        NotifyError::Internal(format!("binary-update: archive read error: {err}"))
                    })?;
                if buf.len() as u64 > MAX_BINARY_ARCHIVE_BYTES {
                    return Err(NotifyError::Internal(format!(
                        "binary-update: archive exceeds {} byte cap",
                        MAX_BINARY_ARCHIVE_BYTES,
                    )));
                }
                std::fs::write(&archive_path, &buf).map_err(|err| {
                    NotifyError::Internal(format!("binary-update: failed to write archive: {err}"))
                })?;
            }

            let unpack_dir = tempfile::TempDir::new().map_err(|err| {
                NotifyError::Internal(format!(
                    "binary-update: failed to create unpack temp dir: {err}"
                ))
            })?;
            let inner_binary =
                binswap::unpack_release_binary(&archive_path, own_name, unpack_dir.path())
                    .map_err(|err| {
                        NotifyError::Internal(format!(
                            "binary-update: archive unpack failed: {err}"
                        ))
                    })?;

            apply_binary_from_path(
                own_name,
                binary,
                &inner_binary,
                &current_exe,
                &env_dir,
                current_version,
            )
        }
        None => {
            // In-band path: the binary blob was staged alongside the plan by
            // `updates::get`. Open the same staging root, load the plan, verify
            // the blob's digest on disk, then copy it to a temp file and apply.
            //
            // C4 extension: when the staged blob is MISSING (NotFound from
            // `fs::metadata`) and a `blob_base_url` is configured on the env's
            // update channel, fall back to fetching the blob from the mirror.
            // This is the Tier 2 airgap path where the plan was served over
            // plain HTTP from a static directory written by `op updates import
            // --push-to`, which does not embed binary blobs in-band.
            let root = match updates_root_override {
                Some(r) => UpdatesRoot::open_in(r, env_id),
                None => UpdatesRoot::open(env_id),
            }
            .map_err(|err| {
                NotifyError::Internal(format!(
                    "binary-update: open staging root for env `{env_id}`: {err}"
                ))
            })?;

            let staged = root
                .load(&verified.plan.plan_id)
                .map_err(|err| {
                    NotifyError::Internal(format!(
                        "binary-update: load staged plan `{}`: {err}",
                        verified.plan.plan_id,
                    ))
                })?
                .ok_or_else(|| {
                    NotifyError::Internal(format!(
                        "binary-update: staged plan `{}` not found — \
                         in-band binary requires a staged plan",
                        verified.plan.plan_id,
                    ))
                })?;

            // Pre-read size guard: reject oversized blobs via stat before
            // allocating the full read, catching sparse/inflated files cheaply.
            // When the blob file is absent (NotFound), try the mirror fallback
            // instead of hard-erroring. Any OTHER metadata error (permission
            // denied, etc.) keeps today's hard error — it signals a broken
            // local install, not an absent blob.
            let blob_path = staged.binary_blob_path(binary).map_err(|err| {
                NotifyError::Internal(format!(
                    "binary-update: in-band binary blob path for `{}`: {err}",
                    binary.name,
                ))
            })?;
            match std::fs::metadata(&blob_path) {
                Ok(meta) => {
                    // Staged blob exists — the original in-band path.
                    let blob_len = meta.len();
                    if blob_len > MAX_BINARY_ARCHIVE_BYTES {
                        return Err(NotifyError::Internal(format!(
                            "binary-update: in-band binary exceeds {} byte cap",
                            MAX_BINARY_ARCHIVE_BYTES,
                        )));
                    }

                    // Scope blob_bytes so it is dropped after the temp-file
                    // write and before the swap, avoiding doubled peak memory.
                    let blob_bytes = staged.verify_binary_on_disk(binary).map_err(|err| {
                        NotifyError::Internal(format!(
                            "binary-update: in-band binary verification failed for `{}`: {err}",
                            binary.name,
                        ))
                    })?;

                    // Defense-in-depth: post-read cap (the stat check above
                    // catches most cases; this covers TOCTOU or non-regular
                    // files).
                    if blob_bytes.len() as u64 > MAX_BINARY_ARCHIVE_BYTES {
                        return Err(NotifyError::Internal(format!(
                            "binary-update: in-band binary exceeds {} byte cap",
                            MAX_BINARY_ARCHIVE_BYTES,
                        )));
                    }

                    write_blob_and_apply(
                        blob_bytes,
                        own_name,
                        binary,
                        &current_exe,
                        &env_dir,
                        current_version,
                    )
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    // Blob not on disk — try the blob-mirror fallback.
                    let Some(base_url) = load_blob_base_url(store, env_id) else {
                        // No mirror configured: reproduce the pre-C4 hard error
                        // unchanged.
                        return Err(NotifyError::Internal(format!(
                            "binary-update: in-band binary stat for `{}`: {err}",
                            binary.name,
                        )));
                    };

                    operator_log::info(
                        module_path!(),
                        format!(
                            "binary-update: env `{env_id}` blob not staged; \
                             fetching {} from mirror",
                            binary.digest,
                        ),
                    );

                    let blob_bytes = fetch_blob_from_mirror(&base_url, &binary.digest)
                        .map_err(NotifyError::Internal)?;

                    write_blob_and_apply(
                        blob_bytes,
                        own_name,
                        binary,
                        &current_exe,
                        &env_dir,
                        current_version,
                    )
                }
                Err(err) => {
                    // Non-NotFound error: broken local install, hard error.
                    Err(NotifyError::Internal(format!(
                        "binary-update: in-band binary stat for `{}`: {err}",
                        binary.name,
                    )))
                }
            }
        }
    }
}

/// Core of the receiver: load the env's update-channel policy and act on a
/// notification — ignore (disabled), record (log only), or stage
/// (download + DSSE-verify + stage the plan via the deployer `updates::get`).
///
/// Sync and internally blocking: `updates::get` downloads + verifies artifacts on
/// a blocking runtime. The async handler runs this on a blocking thread so the
/// request worker is never parked. Returns the HTTP status + JSON body on a
/// resolved outcome, or a [`NotifyError`] the handler maps to a status.
fn run_update_notify(
    store: &LocalFsStore,
    env_id: &str,
    plan: &[u8],
    sig: &[u8],
    exe_path: Option<&std::path::Path>,
) -> Result<(StatusCode, Value), NotifyError> {
    let env_typed = EnvId::new(env_id).map_err(|err| {
        NotifyError::Internal(format!("invalid environment id `{env_id}`: {err}"))
    })?;
    let cfg = store
        .load_update_channel(&env_typed)
        .map_err(|err| NotifyError::Internal(format!("failed to read update channel: {err}")))?
        .unwrap_or_else(|| UpdateChannelConfig::disabled(env_typed.clone()));

    match notify_action(&cfg) {
        NotifyAction::Ignore => {
            operator_log::info(
                module_path!(),
                format!("update-notify: channel disabled for env `{env_id}`, ignoring"),
            );
            Ok((
                StatusCode::FORBIDDEN,
                serde_json::json!({ "status": "disabled" }),
            ))
        }
        NotifyAction::Record => {
            // Record-only still VERIFIES the plan (trusted-key DSSE signature +
            // target env) before recording: `on_notify` is the action on a
            // *verified* notification, and the endpoint is not loopback-gated, so
            // recording an unverified plan would let any caller forge the signal.
            // Verify without staging — the Stage arm below verifies via
            // `updates::get`.
            verify_signed_plan(store, &env_typed, plan, sig)?;
            operator_log::info(
                module_path!(),
                format!("update-notify: verified plan available for env `{env_id}` (record-only)"),
            );
            Ok((
                StatusCode::ACCEPTED,
                serde_json::json!({ "status": "recorded" }),
            ))
        }
        action @ (NotifyAction::Stage | NotifyAction::Apply) => {
            // Stage the posted bytes into a TempDir so the deployer's file-import
            // path can read them. `dir` stays in scope until after `get()` returns
            // (it reads the files synchronously) and is removed on drop.
            let dir = tempfile::TempDir::new().map_err(|err| {
                NotifyError::Internal(format!("failed to create temp dir: {err}"))
            })?;
            let plan_path = dir.path().join("plan.json");
            let sig_path = dir.path().join("plan.json.sig");
            std::fs::write(&plan_path, plan).map_err(|err| {
                NotifyError::Internal(format!("failed to stage plan bytes: {err}"))
            })?;
            std::fs::write(&sig_path, sig).map_err(|err| {
                NotifyError::Internal(format!("failed to stage signature bytes: {err}"))
            })?;

            let payload = UpdatesGetPayload {
                environment_id: env_id.to_string(),
                plan_url: None,
                plan_file: Some(plan_path),
                plan_sig_file: Some(sig_path),
            };
            let flags = OpFlags {
                schema_only: false,
                answers: None,
            };
            // The deployer's `OpOutcome.result` carries the staging directory path
            // and the trust-root key IDs that verified the plan, which must not
            // leak to the off-host caller — the response below is a category
            // signal only, matching the `disabled` / `recorded` arms above. The
            // `plan_id` is read back out here for the apply arm, which needs to
            // name the plan `get` just staged and verified; re-deriving it from
            // the posted bytes would trust unverified input.
            let staged = updates::get(store, &flags, Some(payload)).map_err(NotifyError::Op)?;
            operator_log::info(
                module_path!(),
                format!("update-notify: staged update plan for env `{env_id}`"),
            );

            // Binary self-update (P7d): after content staging succeeds, check
            // whether the plan carries a binary for THIS process on THIS host
            // and, if so, download + verify + swap it. The content path is
            // never regressed — a binary-step failure is logged and the
            // content-staged result still returns.
            let binary_result = match try_apply_binary_update(
                plan, sig, store, env_id, exe_path, None,
            ) {
                Ok(info) => info,
                Err(err) => {
                    // Log the error but do NOT fail the content staging.
                    operator_log::error(
                        module_path!(),
                        format!(
                            "update-notify: binary self-update failed for env `{env_id}`: {err:?}"
                        ),
                    );
                    None
                }
            };

            // `Apply` converges on top of the staged content: snapshot → apply →
            // verify → rollback on failure, all inside the deployer's
            // single-flight `begin_apply_checked`. The apply rewrites
            // `runtime-config.json`, which this process's own `revision_reload`
            // watcher picks up and hot-swaps — no explicit reload, no restart.
            // Unlike the binary step, a failure here is NOT swallowed: the
            // operator asked for convergence, and reporting "staged" after a
            // failed rollback would hide it.
            let status = if action == NotifyAction::Apply {
                apply_staged_plan(store, env_id, plan_id_of(&staged)?)?;
                "applied"
            } else {
                "staged"
            };

            let mut body = serde_json::json!({ "status": status });
            if let Some(binary_info) = binary_result {
                body["binary"] = binary_info;
            }
            Ok((StatusCode::OK, body))
        }
    }
}

/// The `plan_id` of the plan `updates::get` just staged and verified. Read back
/// off the deployer's outcome rather than re-parsed from the posted bytes: those
/// are attacker-supplied until `get` has checked the DSSE signature and the
/// target env, and the id names *what was staged*.
fn plan_id_of(staged: &OpOutcome) -> Result<&str, NotifyError> {
    staged
        .result
        .get("plan_id")
        .and_then(Value::as_str)
        .ok_or_else(|| NotifyError::Internal("staged update plan carries no plan id".to_string()))
}

/// Converge the environment onto a staged plan's signed target manifest.
/// Delegates to the deployer's `updates::apply` — the same code path
/// `op updates apply` runs — so snapshot / verify / rollback and the applied-set
/// bookkeeping are not forked here. The outcome is discarded for the same reason
/// the stage path discards it: it names host paths the off-host caller must not
/// see.
fn apply_staged_plan(store: &LocalFsStore, env_id: &str, plan_id: &str) -> Result<(), NotifyError> {
    let flags = OpFlags {
        schema_only: false,
        answers: None,
    };
    let payload = ApplyUpdatesPayload {
        environment_id: env_id.to_string(),
        plan_id: plan_id.to_string(),
    };
    updates::apply_updates(store, &flags, Some(payload)).map_err(NotifyError::Op)?;
    operator_log::info(
        module_path!(),
        format!("update-notify: applied update plan `{plan_id}` to env `{env_id}`"),
    );
    Ok(())
}

/// Map a deployer [`OpError`] from `updates::get` to an HTTP status with a
/// category-only body. The full error is logged; the response body is a fixed
/// per-status string so untrusted-signer, path, or trust-root details are never
/// echoed back to the (unauthenticated) caller.
fn map_op_error(err: &OpError) -> Response<Full<Bytes>> {
    let status = match err {
        // Untrusted signer, downgrade, or target-env mismatch, and trust-root
        // failures are all "the plan is not acceptable here" → 409.
        OpError::TrustRoot(_) | OpError::Conflict(_) => StatusCode::CONFLICT,
        OpError::Unauthorized { .. } => StatusCode::FORBIDDEN,
        OpError::NotFound(_) => StatusCode::NOT_FOUND,
        OpError::InvalidArgument(_) => StatusCode::BAD_REQUEST,
        // Artifact download failed against the plan/distributor endpoint.
        OpError::Fetch(_) => StatusCode::BAD_GATEWAY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    operator_log::warn(
        module_path!(),
        format!("update-notify: rejected ({status}): {err}"),
    );
    let message = match status {
        StatusCode::CONFLICT => {
            "update plan rejected (untrusted signer, downgrade, or env mismatch)"
        }
        StatusCode::FORBIDDEN => "update plan rejected by policy",
        StatusCode::NOT_FOUND => "update plan or a referenced artifact was not found",
        StatusCode::BAD_REQUEST => "update plan is malformed",
        StatusCode::BAD_GATEWAY => "failed to fetch update artifacts",
        _ => "internal error staging update plan",
    };
    text_response(status, message)
}

/// Handle `POST /v1/updates/notify`: read the posted signed plan, resolve the
/// env's update-channel policy, and ignore / record / stage it. The heavy path
/// (`updates::get` — download + DSSE-verify + stage) is sync and internally
/// blocking, so it runs on a blocking thread and the request worker is never
/// parked. NOT loopback-gated — see the route comment in [`serve`].
async fn handle_update_notify(
    req: Request<Incoming>,
    state: Arc<ServeState>,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    let body = read_body_limited(req).await.map_err(|_| {
        error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body exceeds the size limit",
        )
    })?;
    let (plan, sig) =
        decode_update_notify(&body).map_err(|(status, message)| error_response(status, message))?;

    let env_id = state.current().routing.dispatcher.env_id().to_string();

    let store_root = LocalFsStore::default_root().ok_or_else(|| {
        operator_log::error(
            module_path!(),
            "update-notify: no environment store root (HOME unset)",
        );
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "environment store unavailable",
        )
    })?;
    let store = LocalFsStore::new(store_root);
    let captured_exe = state.exe_path.clone();

    let result = tokio::task::spawn_blocking(move || {
        run_update_notify(&store, &env_id, &plan, &sig, captured_exe.as_deref())
    })
    .await
    .map_err(|err| {
        operator_log::error(
            module_path!(),
            format!("update-notify: worker task failed: {err}"),
        );
        error_response(StatusCode::INTERNAL_SERVER_ERROR, "update notify failed")
    })?;

    match result {
        Ok((status, body)) => {
            // P7d: if the response indicates a binary swap happened, set the
            // in-memory restart-required flag so health probes surface it.
            if body
                .get("binary")
                .and_then(|b| b.get("restart_required"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                state.mark_restart_required();
            }
            let bytes = serde_json::to_vec(&body).map_err(|err| {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            })?;
            Ok(json_response(status, bytes))
        }
        Err(NotifyError::Op(err)) => Err(map_op_error(&err)),
        Err(NotifyError::Internal(message)) => {
            operator_log::error(
                module_path!(),
                format!("update-notify: internal failure: {message}"),
            );
            Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error staging update plan",
            ))
        }
    }
}

/// Server plan-metadata (`GET {plan_endpoint}/meta`) — only the fields the poll
/// loop needs; any others the server adds are ignored. Mirrors the plan server's
/// `PlanMetaResponse` without depending on the (private, Docker-only) server
/// crate.
#[derive(serde::Deserialize)]
struct PlanMeta {
    sequence: u64,
    plan_sha256: String,
}

/// Interval used when a cycle can't resolve one from config (invalid env id,
/// unreadable channel, or a worker-task failure). Matches deploy-spec's default
/// so behavior is the same whether the interval comes from config or here.
const POLL_FALLBACK_INTERVAL_SECS: u64 = 3600;

/// Size caps for the poll fetch, so a compromised or misbehaving plan server
/// can't exhaust memory (`updates::get`'s own artifact download is separately
/// bounded). A plan doc + DSSE envelope are small; these are generous ceilings.
const MAX_PLAN_META_BYTES: u64 = 64 * 1024;
const MAX_PLAN_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PLAN_SIG_BYTES: u64 = 64 * 1024;

/// Updater pull path: fetch the latest signed plan from the env's configured
/// `plan_endpoint` and hand it to the same receiver core the push path uses
/// ([`run_update_notify`]) — so `on_update: apply` converges on the pull path
/// too. Spawned by [`RevisionServer::start`] unless `--no-updates`; the
/// per-cycle config read enforces deny-by-default (an absent, disabled, or
/// endpoint-less channel no-ops) and lets a channel written *after* boot — by
/// `op env apply` or `op updates config-set` — take effect without a restart.
///
/// The wait between cycles is **interruptible**: [`run_update_stream_loop`]
/// notifies `wake` the moment the server publishes a plan, so `interval` is the
/// fallback ceiling for discovery latency, not its typical value. With the
/// stream connected, a publish is picked up in roughly the time one poll cycle
/// takes; with it unavailable, this loop degrades to exactly the polling
/// behavior it had before.
///
/// Cancelled (via the returned task's `abort`) when the ingress shuts down; it
/// is otherwise waiting between cycles, so cancellation is prompt.
async fn run_update_poll_loop(
    state: Arc<ServeState>,
    store_root: std::path::PathBuf,
    wake: Arc<Notify>,
) {
    // Build the blocking HTTP client off the runtime (the blocking client must
    // not be constructed or used on an async runtime thread).
    let client = match tokio::task::spawn_blocking(|| {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
    })
    .await
    {
        Ok(Ok(client)) => client,
        Ok(Err(err)) => {
            operator_log::error(
                module_path!(),
                format!("update-poll: failed to build HTTP client, poll loop disabled: {err}"),
            );
            return;
        }
        Err(err) => {
            operator_log::error(
                module_path!(),
                format!("update-poll: client-build task failed, poll loop disabled: {err}"),
            );
            return;
        }
    };

    // Last plan sequence acted on, so an unchanged `/meta` short-circuits the
    // plan + signature GETs. Advisory: the authoritative anti-rollback is the
    // signed manifest version checked inside `updates::get`.
    let mut last_sequence: Option<u64> = None;
    loop {
        // Read the served env id fresh each cycle (a cheap ArcSwap load) so a
        // reload that changes it is picked up.
        let env_id = state.current().routing.dispatcher.env_id().to_string();
        let root = store_root.clone();
        let client_for_cycle = client.clone();
        let seq_in = last_sequence;
        let captured_exe = state.exe_path.clone();
        // The cycle downloads + DSSE-verifies + records/stages synchronously
        // (`updates::get` is internally blocking), so it runs off the runtime.
        let interval = match tokio::task::spawn_blocking(move || {
            poll_update_cycle(
                &env_id,
                &root,
                &client_for_cycle,
                seq_in,
                captured_exe.as_deref(),
            )
        })
        .await
        {
            Ok((new_sequence, interval_secs, restart)) => {
                last_sequence = new_sequence;
                if restart {
                    state.mark_restart_required();
                }
                interval_secs
            }
            Err(err) => {
                operator_log::error(
                    module_path!(),
                    format!("update-poll: worker task failed: {err}"),
                );
                POLL_FALLBACK_INTERVAL_SECS
            }
        };
        wait_for_next_cycle(&wake, interval).await;
    }
}

/// Wait until the next poll cycle is due, or until a pushed plan event cuts the
/// wait short. Returns `true` when a push woke us, `false` on interval expiry.
///
/// [`Notify::notify_one`] stores a permit when no waiter is registered, so an
/// event that lands *while a cycle is still running* is not lost — the next call
/// here returns immediately. Permits do not accumulate, so a burst of events
/// coalesces into a single extra cycle rather than a thundering herd of them.
/// Both properties are what make the stream a safe accelerator for the poll
/// loop rather than a second, racing control path.
async fn wait_for_next_cycle(wake: &Notify, interval: u64) -> bool {
    tokio::time::timeout(Duration::from_secs(interval), wake.notified())
        .await
        .is_ok()
}

/// Signal the poll loop that the server published a plan.
///
/// `notify_one`, deliberately — NOT `notify_waiters`. `notify_one` stores a
/// permit when no waiter is registered, so an event arriving while a poll cycle
/// is still running survives to the next wait. `notify_waiters` wakes only
/// currently-registered waiters and drops the signal otherwise, which would lose
/// exactly the events that matter most: the ones a publish triggers while we are
/// mid-fetch. The permit does not accumulate, so a burst still costs one cycle.
fn signal_plan_published(wake: &Notify) {
    wake.notify_one();
}

/// How often the stream task re-reads `update-channel.json` while push is not in
/// play (channel absent, disabled, or `push_enabled: false`). This is a local
/// file read, not a network call — it exists so that *enabling* push takes
/// effect without a restart, the same promise the poll loop's per-cycle config
/// read already makes.
const STREAM_CONFIG_RECHECK_SECS: u64 = 60;

/// The SSE endpoint this channel says to hold open, or `None` when push is not
/// in play.
///
/// Deny-by-default, the same shape as [`notify_action`]: `enabled` is the gate
/// and `push_enabled` is the policy, so a disabled channel never streams no
/// matter what `push_enabled` says. A channel with no endpoint to derive a
/// stream URL from also yields `None`.
fn stream_endpoint_for(cfg: &UpdateChannelConfig) -> Option<String> {
    if !cfg.resolved_enabled() || !cfg.resolved_push_enabled() {
        return None;
    }
    cfg.resolved_stream_endpoint()
}

/// Read `env_id`'s update channel off disk and resolve it through
/// [`stream_endpoint_for`]. An absent or unreadable channel yields `None`, which
/// is the same deny-by-default answer as a disabled one.
fn resolve_stream_endpoint(store_root: &std::path::Path, env_id: &str) -> Option<String> {
    let store = LocalFsStore::new(store_root);
    let env_typed = EnvId::new(env_id).ok()?;
    let cfg = store.load_update_channel(&env_typed).ok()??;
    stream_endpoint_for(&cfg)
}

/// Updater push path: hold an SSE connection to the env's `stream_endpoint` and
/// wake [`run_update_poll_loop`] the moment the server publishes a plan.
///
/// The event is a **hint whose contents are never read**. Waking simply runs the
/// ordinary poll cycle, which re-fetches `/meta`, the plan, and its signature
/// and DSSE-verifies them exactly as it always has. So the worst a spoofed,
/// replayed, or stale event can do is cost one wasted `/meta` GET — adding this
/// transport does not widen the trust model, which is precisely why the event
/// carries no plan bytes.
///
/// [`run_stream`] owns reconnection, the resume cursor, and backoff internally,
/// so it returns only when `should_stop` fires (the config changed underneath
/// us) or when the server does not implement the endpoint at all
/// ([`StreamError::Unsupported`]). The latter is the old-server case: fall back
/// to polling and re-check on a long interval, so upgrading the server heals it
/// without a restart.
///
/// Cancelled (via the returned task's `abort`) when the ingress shuts down.
async fn run_update_stream_loop(
    state: Arc<ServeState>,
    store_root: std::path::PathBuf,
    wake: Arc<Notify>,
) {
    // The blocking client must not be constructed on a runtime thread.
    let client = match tokio::task::spawn_blocking(build_stream_client).await {
        Ok(Ok(client)) => client,
        Ok(Err(err)) => {
            operator_log::error(
                module_path!(),
                format!("update-stream: failed to build HTTP client, push disabled: {err}"),
            );
            return;
        }
        Err(err) => {
            operator_log::error(
                module_path!(),
                format!("update-stream: client-build task failed, push disabled: {err}"),
            );
            return;
        }
    };

    loop {
        // Read the served env id fresh each attempt (a cheap ArcSwap load), like
        // the poll loop, so a reload that changes it is picked up.
        let env_id = state.current().routing.dispatcher.env_id().to_string();
        let root = store_root.clone();

        let resolve_root = root.clone();
        let resolve_env = env_id.clone();
        let endpoint = tokio::task::spawn_blocking(move || {
            resolve_stream_endpoint(&resolve_root, &resolve_env)
        })
        .await
        .unwrap_or(None);
        let Some(endpoint) = endpoint else {
            tokio::time::sleep(Duration::from_secs(STREAM_CONFIG_RECHECK_SECS)).await;
            continue;
        };

        operator_log::info(
            module_path!(),
            format!("update-stream: env `{env_id}` subscribing to {endpoint}"),
        );

        let client_for_task = client.clone();
        let wake_for_task = Arc::clone(&wake);
        let stop_state = Arc::clone(&state);
        let stop_root = root;
        let held_endpoint = endpoint.clone();

        let outcome = tokio::task::spawn_blocking(move || {
            run_stream(
                &client_for_task,
                &held_endpoint,
                None,
                // Checked before each (re)connect. Resolves against the *current*
                // env rather than the one we started with, so a reload that swaps
                // the served env drops this stream instead of leaving it wedged on
                // the previous env's endpoint (the env id is part of the URL, so a
                // swap always changes it). Retargeting or disabling push via
                // `op env apply` lands the same way — no restart needed.
                || {
                    let env = stop_state.current().routing.dispatcher.env_id().to_string();
                    resolve_stream_endpoint(&stop_root, &env).as_deref()
                        != Some(held_endpoint.as_str())
                },
                |_event| {
                    signal_plan_published(&wake_for_task);
                    ControlFlow::Continue(())
                },
            )
        })
        .await;

        match outcome {
            // `should_stop` fired: the config no longer names this endpoint. Loop
            // straight around to re-resolve — it cannot spin, because reaching
            // here means the config changed since we resolved it moments ago, and
            // the next iteration either connects to the new endpoint or (push now
            // off) falls into the idle sleep above.
            Ok(Ok(())) => continue,
            Ok(Err(StreamError::Unsupported { status })) => {
                operator_log::info(
                    module_path!(),
                    format!(
                        "update-stream: server does not implement the stream endpoint \
                         (HTTP {status}) for env `{env_id}`; using the poll fallback"
                    ),
                );
                tokio::time::sleep(Duration::from_secs(POLL_FALLBACK_INTERVAL_SECS)).await;
            }
            // `run_stream` retries every other transport error internally, so it
            // does not surface them; treat an unexpected one as a bad moment.
            Ok(Err(err)) => {
                operator_log::warn(
                    module_path!(),
                    format!("update-stream: stream ended for env `{env_id}`: {err}"),
                );
                tokio::time::sleep(Duration::from_secs(STREAM_CONFIG_RECHECK_SECS)).await;
            }
            Err(err) => {
                operator_log::error(
                    module_path!(),
                    format!("update-stream: worker task failed: {err}"),
                );
                tokio::time::sleep(Duration::from_secs(STREAM_CONFIG_RECHECK_SECS)).await;
            }
        }
    }
}

/// One poll cycle, run on a blocking thread. Re-reads the env's update-channel
/// policy (deny-by-default), and when enabled with a plan endpoint: GETs
/// `/meta`, short-circuits if the sequence is unchanged, else GETs the plan and
/// its `.sig`, checks the plan digest against `/meta` to drop torn reads (a
/// concurrent upload split across the two GETs), and hands the bytes to
/// [`run_update_notify`] — which DSSE-verifies and records or stages per
/// `on_notify`. Returns `(sequence, interval, restart_required)`: the sequence
/// to remember (advanced only on a clean record/stage), the interval to wait
/// before the next cycle, and whether a binary swap set the restart flag.
fn poll_update_cycle(
    env_id: &str,
    store_root: &std::path::Path,
    client: &reqwest::blocking::Client,
    last_sequence: Option<u64>,
    exe_path: Option<&std::path::Path>,
) -> (Option<u64>, u64, bool) {
    let store = LocalFsStore::new(store_root);

    let env_typed = match EnvId::new(env_id) {
        Ok(env) => env,
        Err(err) => {
            operator_log::error(
                module_path!(),
                format!("update-poll: invalid environment id `{env_id}`: {err}"),
            );
            return (last_sequence, POLL_FALLBACK_INTERVAL_SECS, false);
        }
    };

    let cfg = match store.load_update_channel(&env_typed) {
        Ok(Some(cfg)) => cfg,
        Ok(None) => return (last_sequence, POLL_FALLBACK_INTERVAL_SECS, false),
        Err(err) => {
            operator_log::warn(
                module_path!(),
                format!("update-poll: failed to read update channel for env `{env_id}`: {err}"),
            );
            return (last_sequence, POLL_FALLBACK_INTERVAL_SECS, false);
        }
    };

    let interval = cfg.resolved_poll_interval_secs();

    // Deny-by-default: only an enabled channel with a plan endpoint polls.
    if !cfg.resolved_enabled() {
        return (last_sequence, interval, false);
    }
    let Some(plan_endpoint) = cfg.resolved_plan_endpoint() else {
        return (last_sequence, interval, false);
    };
    let plan_endpoint = plan_endpoint.trim_end_matches('/');

    // 1. `/meta` — advisory sequence gate.
    let meta = match fetch_plan_meta(client, plan_endpoint) {
        Ok(meta) => meta,
        Err(err) => {
            operator_log::warn(
                module_path!(),
                format!(
                    "update-poll: `{plan_endpoint}/meta` fetch failed for env `{env_id}`: {err}"
                ),
            );
            return (last_sequence, interval, false);
        }
    };
    if last_sequence == Some(meta.sequence) {
        // Nothing new since the last acted-on plan.
        return (last_sequence, interval, false);
    }

    // 2. plan + signature.
    let (plan, sig) = match fetch_plan_and_sig(client, plan_endpoint) {
        Ok(pair) => pair,
        Err(err) => {
            operator_log::warn(
                module_path!(),
                format!("update-poll: plan/sig fetch failed for env `{env_id}`: {err}"),
            );
            return (last_sequence, interval, false);
        }
    };

    // 3. Torn-read guard: the server resolves `/meta`, `/plan`, `/plan.sig`
    //    independently, so a concurrent upload between the GETs can split the
    //    plan and signature across sequences. `/meta` carries the authoritative
    //    digest for its sequence; a mismatch means the plan we fetched is not the
    //    one `/meta` described — skip and retry next cycle rather than fail DSSE
    //    verification noisily.
    if sha256_hex(&plan) != meta.plan_sha256 {
        operator_log::info(
            module_path!(),
            format!(
                "update-poll: plan digest does not match `/meta` for env `{env_id}` \
                 (torn read across a concurrent upload); retrying next cycle"
            ),
        );
        return (last_sequence, interval, false);
    }

    // 4. Verify + record/stage via the shared receiver core.
    match run_update_notify(&store, env_id, &plan, &sig, exe_path) {
        Ok((status, body)) => {
            let restart = body
                .get("binary")
                .and_then(|b| b.get("restart_required"))
                .and_then(Value::as_bool)
                == Some(true);
            operator_log::info(
                module_path!(),
                format!(
                    "update-poll: env `{env_id}` plan sequence {} -> {} ({})",
                    meta.sequence,
                    status.as_u16(),
                    body.get("status").and_then(|s| s.as_str()).unwrap_or("ok"),
                ),
            );
            // Advance the remembered sequence ONLY when the plan was actually
            // acted on (2xx = staged or recorded). A non-2xx `Ok` means the
            // channel was disabled between this cycle's config read and the
            // receiver's own re-read (a TOCTOU that yields 403 `disabled`);
            // leaving the sequence unadvanced lets a re-enabled channel pick the
            // plan up next cycle instead of skipping it until the server
            // publishes a newer one.
            if status.is_success() {
                (Some(meta.sequence), interval, restart)
            } else {
                (last_sequence, interval, false)
            }
        }
        Err(NotifyError::Op(err)) => {
            operator_log::warn(
                module_path!(),
                format!("update-poll: plan rejected for env `{env_id}`: {err}"),
            );
            (last_sequence, interval, false)
        }
        Err(NotifyError::Internal(message)) => {
            operator_log::error(
                module_path!(),
                format!("update-poll: internal failure staging plan for env `{env_id}`: {message}"),
            );
            (last_sequence, interval, false)
        }
    }
}

/// GET `{plan_endpoint}/meta` and parse the plan metadata (size-capped).
fn fetch_plan_meta(
    client: &reqwest::blocking::Client,
    plan_endpoint: &str,
) -> Result<PlanMeta, String> {
    let bytes = fetch_bytes(
        client,
        &format!("{plan_endpoint}/meta"),
        MAX_PLAN_META_BYTES,
    )?;
    serde_json::from_slice(&bytes).map_err(|err| format!("decode error: {err}"))
}

/// GET the plan (`{plan_endpoint}`) and its DSSE envelope (`{plan_endpoint}.sig`),
/// each size-capped.
fn fetch_plan_and_sig(
    client: &reqwest::blocking::Client,
    plan_endpoint: &str,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let plan = fetch_bytes(client, plan_endpoint, MAX_PLAN_BYTES)?;
    let sig = fetch_bytes(client, &format!("{plan_endpoint}.sig"), MAX_PLAN_SIG_BYTES)?;
    Ok((plan, sig))
}

/// GET `url` into memory, reading at most `max_bytes` so a lying/oversized
/// response can't exhaust memory (the body is streamed through a bounded reader
/// rather than trusting `Content-Length`).
fn fetch_bytes(
    client: &reqwest::blocking::Client,
    url: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let resp = client
        .get(url)
        .send()
        .map_err(|err| format!("request error: {err}"))?
        .error_for_status()
        .map_err(|err| format!("status error: {err}"))?;
    let mut buf = Vec::new();
    // Read one byte past the cap so an over-limit body is detected, not silently
    // truncated (a truncated plan would just fail verification anyway, but an
    // explicit error is clearer).
    resp.take(max_bytes + 1)
        .read_to_end(&mut buf)
        .map_err(|err| format!("read error: {err}"))?;
    if buf.len() as u64 > max_bytes {
        return Err(format!("response exceeds {max_bytes} bytes"));
    }
    Ok(buf)
}

/// Lowercase hex of the SHA-256 of `bytes` — matches the server's `plan_sha256`
/// (`hex::encode(Sha256::digest(...))`).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
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
/// Unwrap a `session.wait` "pending" reply: a paused flow returns
/// `{ "status": "pending", "response": <activity> }`, and the activity to
/// actually forward is the inner `response`. Anything else is returned as-is.
/// Shared so the content lift and the DirectLine passthrough copy operate on
/// the same JSON.
fn unwrap_pending_response(raw: &Value) -> &Value {
    match raw.get("status").and_then(Value::as_str) {
        Some("pending") => raw.get("response").unwrap_or(raw),
        _ => raw,
    }
}

fn activity_to_worker_message(activity: &Activity) -> WorkerInvokeMessage {
    let payload = unwrap_pending_response(activity.payload());
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

pub(crate) fn error_response(
    status: StatusCode,
    message: impl AsRef<str>,
) -> Response<Full<Bytes>> {
    text_response(status, message.as_ref())
}

/// The built-in webchat console page, embedded so the binary serves it with no
/// working directory or network access. It POSTs to the loopback
/// `/workers/invoke` endpoint on the same origin.
const CHAT_HTML: &str = include_str!("../assets/chat.html");
/// Vendored Adaptive Cards renderer the chat page loads from `/adaptivecards.min.js`.
const ADAPTIVE_CARDS_JS: &str = include_str!("../assets/adaptivecards.min.js");

/// Serve the built-in webchat console: `GET /chat` returns the HTML page and
/// `GET /adaptivecards.min.js` returns the vendored renderer. A non-GET method
/// on either path is a `405`. Returns `None` for any other path so the caller
/// falls through to deployment routing. Reached only when the env has the GUI
/// enabled ([`ServeState::gui_enabled`]).
fn try_chat_asset_response(path: &str, method: &hyper::Method) -> Option<Response<Full<Bytes>>> {
    let (content_type, body) = match path {
        "/chat" => ("text/html; charset=utf-8", CHAT_HTML),
        "/adaptivecards.min.js" => ("application/javascript; charset=utf-8", ADAPTIVE_CARDS_JS),
        _ => return None,
    };
    if *method != hyper::Method::GET {
        return Some(error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "the webchat console is served over GET",
        ));
    }
    Some(asset_response(content_type, body))
}

/// Build a `200 OK` response for an embedded `'static` asset. The body is a
/// zero-copy [`Bytes::from_static`] view, so serving the ~440 KB renderer adds
/// no per-request allocation.
///
/// Sends anti-framing headers (`X-Frame-Options: DENY` +
/// `Content-Security-Policy: frame-ancestors 'none'`) so the console page can't
/// be embedded in a cross-site iframe — which would otherwise load it as
/// `127.0.0.1` and let the page's on-open `send({})` drive the loopback
/// `/workers/invoke` endpoint from a malicious origin.
fn asset_response(content_type: &'static str, body: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::X_FRAME_OPTIONS, "DENY")
        .header(header::CONTENT_SECURITY_POLICY, "frame-ancestors 'none'")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .expect("static response builder inputs are valid")
}

/// `/livez`, `/readyz`, `/healthz`, `/health` return `200 ok`; `/status`
/// returns the diagnostics JSON. Returns `None` for non-probe paths so the
/// caller falls through to routing.
///
/// When a binary self-update is staged but not yet activated (the process must
/// be restarted), the health probes still return `200` (the running process is
/// healthy) but include a `X-Greentic-Restart-Required: true` header so
/// orchestrators can observe the pending restart. `/status` includes a
/// `restart_required` field in the JSON body.
fn try_probe_response(path: &str, state: &ServeState) -> Option<Response<Full<Bytes>>> {
    let restart = state.restart_required.load(Ordering::Relaxed);
    if matches!(path, "/livez" | "/readyz" | "/healthz" | "/health") {
        let mut resp = text_response(StatusCode::OK, "ok");
        if restart {
            resp.headers_mut().insert(
                "x-greentic-restart-required",
                hyper::header::HeaderValue::from_static("true"),
            );
        }
        return Some(resp);
    }
    if path == "/status" {
        let activation = state.current();
        let (deployments_routed, revisions_active) = activation.routing.dispatcher.counts();
        let body = serde_json::json!({
            "schema": "greentic.status.v1",
            "env_id": activation.routing.dispatcher.env_id(),
            "listen_addr": state.bound_addr.to_string(),
            "version": env!("CARGO_PKG_VERSION"),
            "bundles_active": activation.routing.deployment_routes.len(),
            "deployments_routed": deployments_routed,
            "revisions_active": revisions_active,
            "restart_required": restart,
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
/// 4. `GREENTIC_GATEWAY_PORT` — port-only override. The legacy `http_ingress`
///    boot honoured this (via `bundle_config`) and the revision path did not,
///    so callers that set it — the greentic-e2e Playwright fixture and
///    greentic-designer's local-deploy — silently landed on the default port.
/// 5. `PORT` — port-only override matching the convention used by Heroku /
///    Cloud Run / Fly and the rest of the gateway configuration. Kept as the
///    outermost layer so existing deployments that set it are unaffected.
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

    if let Ok(raw) = std::env::var("GREENTIC_GATEWAY_PORT") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            if let Ok(port) = trimmed.parse::<u16>() {
                addr.set_port(port);
            } else {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "GREENTIC_GATEWAY_PORT={trimmed:?} is not a valid u16; keeping port {}",
                        addr.port()
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
/// Post-dispatch messaging-endpoint pipeline, shared by the generic-JSON and
/// provider-route arms of [`serve`]: resolve the endpoint (M1 IID.4), emit the
/// resolution telemetry, fail closed on ambiguity, enforce the linked-bundle
/// ACL (M1.4c-ii step 2), and look up the bundle-scoped welcome hint (M1.5).
/// One implementation so the two arms cannot drift on admission semantics.
///
/// Trust boundary: `peer_is_loopback` gates the resolver the same way
/// `caller_identity` gates the header path — a remote caller posting a forged
/// payload with a discriminator a component identifies (e.g. a Teams
/// serviceUrl) must not derive an endpoint; the resolver short-circuits to
/// `PublicSkipped` off-loopback. `build_headers_body` produces the structured
/// `(headers, body)` pair LAZILY — public traffic, header-pinned eids, and
/// no-endpoint envs never pay for it. The runner builds the per-provider
/// wrapper from each component's `describe-identify-instance` hint, so each
/// probed `provider_type` only sees the headers its hint declares.
///
/// The `gt.endpoint_resolution` telemetry is a structured event (tracing's
/// macro grammar can't take dotted field names); the downstream flow span
/// carries `gt.messaging_endpoint_id` via the activity, so operators can see
/// "did the eid come from a trusted header, the resolver, or fall through".
///
/// `Ambiguous` (≥2 endpoints of a probed type and no decisive match) is the
/// only resolver outcome refused outright — silently routing to "the"
/// endpoint would mis-attribute traffic. A `None` eid passes (legacy
/// single-instance back-compat). The welcome hint is bundle-scoped because
/// dispatch may have picked a different bundle than the welcome ref points
/// at; attaching it per-turn is safe — runner-host gates the override on a
/// durable first-contact marker (greentic-runner#382).
async fn resolve_endpoint_for_scope<F>(
    activation: &Activation,
    tenant: &str,
    scope: &RevisionScope,
    header_endpoint_id: Option<&str>,
    peer_is_loopback: bool,
    build_headers_body: F,
) -> Result<(Option<String>, Option<WelcomeFlowHint>), Response<Full<Bytes>>>
where
    F: FnOnce() -> (Vec<(String, String)>, Value),
{
    let resolution = endpoint_resolver::resolve(
        &activation.host,
        tenant,
        scope,
        activation.routing.endpoint_admit.as_ref(),
        header_endpoint_id,
        peer_is_loopback,
        build_headers_body,
    )
    .await
    .map_err(|err| {
        operator_log::warn(
            module_path!(),
            format!(
                "messaging-endpoint resolver failed for deployment {} revision {}: {err:#}",
                scope.deployment_id, scope.revision_id,
            ),
        );
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "messaging-endpoint resolution failed",
        )
    })?;

    tracing::info!(
        target: "greentic_start::endpoint_resolver",
        endpoint_resolution = resolution.origin(),
        messaging_endpoint_id = resolution.endpoint_id().unwrap_or(""),
        "messaging-endpoint resolution outcome",
    );

    if matches!(resolution, endpoint_resolver::ResolverOutcome::Ambiguous) {
        return Err(error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "messaging endpoint resolution is ambiguous; assert the endpoint via \
             x-greentic-messaging-endpoint-id",
        ));
    }
    let endpoint_id: Option<String> = resolution.endpoint_id().map(str::to_string);

    let admission = resolve_endpoint_admission(
        endpoint_id.as_deref(),
        activation.routing.endpoint_admit.as_ref(),
    )
    .map_err(|boxed| *boxed)?;
    check_bundle_admission(&admission, scope.bundle_id.as_str()).map_err(|boxed| *boxed)?;

    let welcome_hint = resolve_welcome_flow_hint(
        endpoint_id.as_deref(),
        &scope.bundle_id,
        &activation.routing.endpoint_admit,
    );

    Ok((endpoint_id, welcome_hint))
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_provider_route(
    activation: Arc<Activation>,
    state: Arc<ServeState>,
    tenant: &str,
    scope: &RevisionScope,
    path: &str,
    method: &str,
    query: Option<&str>,
    request_headers: &[(String, String)],
    body: &[u8],
    peer_is_loopback: bool,
    identify_headers: &[(String, String)],
    header_endpoint_id: Option<&str>,
    session_hint: Option<&str>,
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
    let descriptor_pack_id = route_match.descriptor.pack_id.clone();
    let provider_op = route_match.descriptor.provider_op.clone();
    let route_tenant = route_match.tenant.clone();
    let route_team = route_match.team.clone();
    let deployment_id = scope.deployment_id;
    let bundle_id = scope.bundle_id.clone();
    let revision_id = scope.revision_id;

    // A4: detect DirectLine routes by provider_type. When the request is
    // DirectLine, apply the same pre/post processing the legacy path does:
    // path normalization, query augmentation, session-token preflight,
    // conversation dedup, streamUrl rewrite, POST /token validation.
    let is_directline = provider_type.starts_with("messaging.webchat");
    let (dl_method, dl_path, dl_query_pairs, mut dl_headers, dl_forward_plan, dl_dedup_key);
    if is_directline {
        // Extract the provider-relative path from the full request path.
        // The http-routes.v1 routes carry the full URL pattern
        // (e.g. /v1/messaging/webchat/{tenant}/v3/directline/{path*}), so
        // the provider path is everything from /v3/directline onward. Fall
        // back to the legacy parse for /token, /auth/config, etc.
        let provider_path = extract_directline_provider_path(path);
        let (norm_method, norm_path) = normalize_directline_dispatch(method, &provider_path);
        let parsed_query = parse_query_pairs(query);
        let augmented = augment_directline_queries(&parsed_query, &route_tenant, Some(&route_team));
        dl_headers = request_headers.to_vec();

        // Session-token renewal preflight: loads the provider's
        // jwt_signing_key, applies any Authorization rewrite, and may
        // short-circuit (auth failure, /tokens/refresh served locally).
        let signing_key =
            read_provider_signing_key(&activation, tenant, Some(&route_team), &provider_type).await;
        let preflight_outcome = crate::directline_session::preflight(
            &hyper::Method::from_bytes(norm_method.as_bytes()).unwrap_or(hyper::Method::POST),
            &norm_path,
            &dl_headers,
            signing_key.as_deref(),
            &state.directline_sessions,
        );
        let forward_plan = match preflight_outcome {
            crate::directline_session::Preflight::Respond(response) => {
                return Err(response);
            }
            crate::directline_session::Preflight::Forward(plan) => plan,
        };
        if let Some(authorization) = forward_plan.rewrite_authorization.as_deref() {
            crate::directline_session::apply_authorization_rewrite(&mut dl_headers, authorization);
        }

        // Conversation dedup: for POST /conversations, check if we already
        // have a cached response for this user.
        let dedup_key = if norm_method == "POST"
            && (norm_path == "/v3/directline/conversations"
                || norm_path.ends_with("/conversations"))
        {
            crate::conv_dedup::extract_user_id(body).map(|user_id| crate::conv_dedup::DedupKey {
                tenant: route_tenant.clone(),
                team: route_team.clone(),
                user_id,
            })
        } else {
            None
        };
        if let Some(ref key) = dedup_key
            && let Some(mut cached) = state.conversation_dedup.get(key)
        {
            apply_directline_forward_plan_to_response(&state, &forward_plan, &mut cached);
            return Ok(synthesize_provider_response(&cached));
        }

        dl_method = norm_method;
        dl_path = norm_path;
        dl_query_pairs = augmented;
        dl_forward_plan = Some(forward_plan);
        dl_dedup_key = dedup_key;
    } else {
        dl_method = method.to_string();
        dl_path = path.to_string();
        dl_query_pairs = parse_query_pairs(query);
        dl_headers = request_headers.to_vec();
        dl_forward_plan = None;
        dl_dedup_key = None;
    }

    // Phase D.3 / M1 IID auth gate: for provider classes whose endpoint
    // declares `webhook_secret_ref`, constant-time compare the inbound
    // discriminator header (Telegram: `x-telegram-bot-api-secret-token`)
    // against the resolved per-endpoint secret. Runs BEFORE the IID resolver
    // because a matched secret is BOTH an authenticator AND the routing
    // discriminator — no need to invoke `identify-instance` after.
    //
    // [`provider_auth::AuthOutcome::Skipped`] is the back-compat path:
    // endpoints provisioned before PR #246 have no `webhook_secret_ref` and
    // continue to identify-route by `provider_id`.
    let secrets = activation.host.secrets_manager();
    let header_endpoint_id_authenticated = match provider_auth::authenticate_provider_webhook(
        activation.routing.endpoint_admit.as_ref(),
        &secrets,
        scope,
        &provider_type,
        request_headers,
    )
    .await
    {
        Ok(provider_auth::AuthOutcome::Authenticated(eid)) => Some(eid),
        Ok(provider_auth::AuthOutcome::Skipped) => None,
        Err(response) => return Err(response),
    };

    // Second half of the `defer_pin` two-phase write (A1 follow-up): commit the
    // body-derived chat-stickiness pin now that the host gate above has admitted
    // the request (a rejected request returns `Err` above and never pins).
    //
    // Trust boundary: the gate only *verifies* the body for providers with a
    // host-side authenticator — today Telegram endpoints carrying a
    // `webhook_secret_ref`, i.e. the `Authenticated` outcome. A `Skipped`
    // outcome means the host had nothing to check the body against: either the
    // provider verifies inside its own component (e.g. Slack signature), which
    // runs *after* this point, or the endpoint is a legacy no-secret one. Those
    // still pin here — unchanged from A1, which pinned them inline during
    // dispatch — so the pin can precede (delegated) or lack (legacy)
    // verification. Impact stays low: same-bundle version routing only,
    // `try_pin` cannot overwrite an existing pin, and the store caps + TTL bound
    // cardinality. Fully gating the delegated case would need the component to
    // report its verification result back to the host (tracked separately).
    //
    // No-op when there is no hint (endpoint with no extractable chat id).
    if let Some(hint) = session_hint {
        activation
            .routing
            .dispatcher
            .commit_pin(tenant, deployment_id, hint, revision_id)
            .await;
    }

    // M1 IID.4 resolver + admit + welcome hint — shared with the generic-JSON
    // branch; see [`resolve_endpoint_for_scope`]. This is what makes the
    // auto-registered IID `secret_token` (see `revision_webhook_register`)
    // actually identify the endpoint on provider webhooks. Provider bodies are
    // not necessarily JSON (form-urlencoded, signature blobs) — identify is
    // best-effort on the body; the header set (e.g. Telegram's secret-token)
    // is always carried.
    //
    // When the auth gate authenticated above, that endpoint id wins — passed
    // as the resolver's header override so the IID probe is skipped (the
    // resolver still validates ACL membership of the dispatched bundle).
    let header_endpoint_id_for_resolver = header_endpoint_id_authenticated
        .as_deref()
        .or(header_endpoint_id);
    let (endpoint_id, welcome_hint) = resolve_endpoint_for_scope(
        &activation,
        tenant,
        scope,
        header_endpoint_id_for_resolver,
        peer_is_loopback,
        || {
            let body_value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
            (identify_headers.to_vec(), body_value)
        },
    )
    .await?;

    let http_in = build_provider_http_in(
        &provider_type,
        tenant,
        &dl_method,
        &dl_path,
        &dl_query_pairs,
        &dl_headers,
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

    // A5: notify the WS pump when the provider op itself writes an activity
    // (e.g. `directline_http` bumps the watermark on POST /activities). The
    // legacy path solves this via `register_webchat_post_op_notifier`; the
    // revision path has no callback mechanism on `invoke_provider_for_revision`,
    // so we extract the `_greentic` metadata inline.
    try_notify_webchat_activity(state.notifier.as_ref(), &output).await;

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

    // `result.events` are EventEnvelopeV1 (event-fabric) emissions. The
    // legacy `dispatch_http_ingress` routes these only for `Domain::Events`
    // through `event_router::route_events_to_default_flow`; the revision-
    // aware event path is Phase D.4 work. Log non-empty counts so operators
    // see the gap until the routing seam lands.
    if !result.events.is_empty() {
        operator_log::warn(
            module_path!(),
            format!(
                "provider {provider_type} emitted {} event(s) on op {provider_op} \
                 (deployment {deployment_id} revision {revision_id}); revision-aware \
                 event routing is Phase D.4 work — events dropped for now",
                result.events.len()
            ),
        );
    }

    // Detach the per-ingress pipeline so the HTTP response isn't blocked
    // by the 3-call egress chain (`render_plan` → `encode` → `send_payload`).
    // Slack enforces a 3-second webhook timeout; with N replies per ingress
    // and M envelopes per webhook the inline cost = `M * N * 3 * WASM_invoke`
    // would routinely blow past it. Matches the legacy posture in
    // `dispatch_http_ingress`, which `std::thread::spawn`s
    // `route_messaging_envelopes`. Errors are logged inside the spawned
    // task — the upstream already received its 2xx ack by the time the
    // egress runs.
    if !result.messaging_envelopes.is_empty() {
        let ingress_envelopes = result.messaging_envelopes.clone();
        let pipeline_activation = Arc::clone(&activation);
        let pipeline_tenant = tenant.to_string();
        let pipeline_provider = provider_type.clone();
        let pipeline_bundle = bundle_id.clone();
        let pipeline_notifier = Arc::clone(&state.notifier);
        tokio::spawn(async move {
            run_provider_inbound_pipeline(
                pipeline_activation,
                pipeline_tenant,
                deployment_id,
                pipeline_bundle,
                revision_id,
                descriptor_pack_id,
                pipeline_provider,
                ingress_envelopes,
                endpoint_id,
                welcome_hint,
                pipeline_notifier,
            )
            .await;
        });
    }

    // A4: DirectLine post-processing — apply the forward plan (seed sliding
    // window, inject renewed token), rewrite streamUrl to absolute, validate
    // POST /token response, cache for conversation dedup.
    let mut response = result.response;
    if is_directline {
        if let Some(ref plan) = dl_forward_plan {
            apply_directline_forward_plan_to_response(&state, plan, &mut response);
        }

        // streamUrl rewrite: the provider returns a relative path, but
        // DirectLineJS requires an absolute ws:// URL.
        if dl_method == "POST"
            && (dl_path == "/v3/directline/conversations" || dl_path.ends_with("/conversations"))
            && (200..300).contains(&response.status)
        {
            // Pin the newly created conversation to the revision that
            // created it. POST /conversations has no conversation_id in
            // the URL yet, so the pre-dispatch session_hint was None
            // and no pin was written. Extract the id from the response
            // and commit the pin now so subsequent activities on this
            // conversation stick to the same revision.
            if let Some(conv) = crate::directline_session::conversation_id_from_response(&response)
            {
                let hint = format!("webchat:{conv}");
                activation
                    .routing
                    .dispatcher
                    .commit_pin(tenant, deployment_id, &hint, revision_id)
                    .await;
            }

            rewrite_stream_url(&dl_headers, &mut response);

            // Cache the post-rewrite response for conversation dedup.
            if let Some(key) = dl_dedup_key {
                state.conversation_dedup.insert(key, response.clone());
            }
        }

        // POST /token response validation (same as legacy path).
        if dl_path == "/v3/directline/tokens/generate" {
            validate_token_response(&response)?;
        }
    }

    Ok(synthesize_provider_response(&response))
}

/// Per-ingress pipeline: for each inbound envelope, drive the flow runtime
/// and ship each reply Activity back out through the provider's egress
/// chain. Runs in a detached `tokio::spawn` so the HTTP ack is sent before
/// the egress completes (the webhook upstream doesn't need to wait for our
/// bot reply to be delivered).
///
/// Errors are logged but never bubble out — the upstream already saw its
/// 2xx, so returning a non-2xx now is impossible, and propagating an Err
/// would just hang in the abandoned task.
#[allow(clippy::too_many_arguments)]
async fn run_provider_inbound_pipeline(
    activation: Arc<Activation>,
    tenant: String,
    deployment_id: DeploymentId,
    bundle_id: BundleId,
    revision_id: RevisionId,
    pack_id: String,
    provider_type: String,
    envelopes: Vec<ChannelMessageEnvelope>,
    endpoint_id: Option<String>,
    welcome_hint: Option<WelcomeFlowHint>,
    notifier: Arc<dyn crate::notifier::ActivityNotifier>,
) {
    for ingress in &envelopes {
        let activity = envelope_to_activity(
            ingress,
            &tenant,
            endpoint_id.as_deref(),
            welcome_hint.clone(),
        );
        let replies = match activation
            .host
            .handle_activity_for_revision(
                &tenant,
                deployment_id,
                bundle_id.clone(),
                revision_id,
                activity,
            )
            .await
        {
            Ok(replies) => replies,
            Err(err) => {
                operator_log::error(
                    module_path!(),
                    format!(
                        "forwarding provider event to flow runtime failed for \
                         deployment {deployment_id} revision {revision_id}: {err:#}"
                    ),
                );
                continue;
            }
        };

        for reply in replies {
            let reply_envelope = build_reply_envelope(ingress, &reply);
            match run_reply_egress(
                &activation,
                &tenant,
                deployment_id,
                bundle_id.clone(),
                revision_id,
                &pack_id,
                &provider_type,
                &reply_envelope,
            )
            .await
            {
                Ok(send_outcome) => {
                    try_notify_webchat_activity(notifier.as_ref(), &send_outcome).await;
                }
                Err(err) => {
                    operator_log::error(
                        module_path!(),
                        format!(
                            "provider {provider_type} egress failed for deployment \
                             {deployment_id} revision {revision_id} (reply id={}): {err:#}",
                            reply_envelope.id
                        ),
                    );
                }
            }
        }
    }
}

/// Run the provider's egress chain for a single reply envelope: invoke
/// `render_plan`, feed the plan into `encode`, then ship the encoded
/// payload via `send_payload`. Each step calls
/// [`RunnerHost::invoke_provider_for_revision`] so the same revision that
/// handled the inbound webhook also produces the outbound reply.
///
/// Provider components declare `render_plan`/`encode`/`send_payload` in
/// their `greentic.provider-extension.v1` ops allowlist; if a provider
/// omits one, the helper fails closed with the host's allowlist error.
/// That mirrors the legacy `messaging_egress` pipeline (`render_plan` →
/// `encode_payload` → `send_payload`).
#[allow(clippy::too_many_arguments)]
async fn run_reply_egress(
    activation: &Activation,
    tenant: &str,
    deployment_id: DeploymentId,
    bundle_id: BundleId,
    revision_id: RevisionId,
    pack_id: &str,
    provider_type: &str,
    envelope: &ChannelMessageEnvelope,
) -> Result<Value> {
    use crate::messaging_dto::{EncodeInV1, ProviderPayloadV1, RenderPlanInV1};

    let message_value = serde_json::to_value(envelope).context("serialize reply envelope")?;

    // Shared closure: each step calls `invoke_provider_for_revision` with
    // the same 7 routing args, varying only by op + serialized input.
    let invoke = async |op: &'static str, input: Value| -> Result<Value> {
        let input_bytes =
            serde_json::to_vec(&input).with_context(|| format!("encode {op} input"))?;
        activation
            .host
            .invoke_provider_for_revision(
                tenant,
                deployment_id,
                bundle_id.clone(),
                revision_id,
                provider_type,
                op,
                input_bytes,
                None,
                None,
            )
            .await
            .with_context(|| format!("{op} invocation"))
    };

    // render_plan(message) → plan
    let render_input = serde_json::to_value(RenderPlanInV1 {
        v: 1,
        message: message_value.clone(),
    })
    .context("encode RenderPlanInV1")?;
    let plan_value = invoke("render_plan", render_input).await?;
    // Providers may return the plan as a typed `RenderPlanOutV1` (`plan_json`)
    // string, a `{ "plan": ... }` wrapper, or the plan object directly.
    let plan = plan_value
        .get("plan_json")
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .or_else(|| plan_value.get("plan").cloned())
        .unwrap_or(plan_value);

    // encode(message, plan) → ProviderPayloadV1
    let encode_input = serde_json::to_value(EncodeInV1 {
        v: 1,
        message: message_value,
        plan,
    })
    .context("encode EncodeInV1")?;
    let encode_value = invoke("encode", encode_input).await?;
    let payload_value = encode_value.get("payload").cloned().unwrap_or(encode_value);
    let payload: ProviderPayloadV1 =
        serde_json::from_value(payload_value).context("decode ProviderPayloadV1")?;

    // send_payload(provider_type, payload, tenant, config) → outcome.
    // Per-pack overrides — projected from this Active deployment's
    // `BundleDeployment.config_overrides` (D.4) — flow through
    // `messaging_egress::build_send_payload`, which injects them into
    // the Greentic envelope body so the provider's `load_config` sees
    // the same shape the legacy path produces.
    let pack_overrides = crate::messaging_egress::pack_config_overrides_as_json(
        &activation.routing.deployment_config_overrides,
        deployment_id,
        pack_id,
    );
    let send = crate::messaging_egress::build_send_payload(
        payload,
        provider_type.to_string(),
        tenant.to_string(),
        None,
        pack_overrides,
    );
    let send_input = serde_json::to_value(&send).context("encode SendPayloadInV1")?;
    let send_outcome = invoke("send_payload", send_input).await?;

    if send_outcome
        .get("ok")
        .and_then(|v| v.as_bool())
        .is_some_and(|ok| !ok)
    {
        let error_msg = send_outcome
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("send_payload reported ok=false");
        anyhow::bail!("{error_msg}");
    }
    Ok(send_outcome)
}

/// Extract `_greentic` metadata from a provider-op output and publish a
/// [`NotifyEvent`] so the WS pump wakes up. Mirrors the legacy
/// `register_webchat_post_op_notifier` callback in [`crate::http_ingress`]
/// which fires on `directline_http` and `send_payload` outputs.
///
/// The metadata may appear at the top level (`send_payload`) or inside a
/// base64-encoded `body_b64` field (`directline_http`). When absent the call
/// is a no-op — non-webchat providers simply don't carry `_greentic`.
async fn try_notify_webchat_activity(
    notifier: &dyn crate::notifier::ActivityNotifier,
    output: &Value,
) {
    let metadata = if let Some(body_b64) = output.get("body_b64").and_then(|v| v.as_str()) {
        let Ok(decoded) = BASE64.decode(body_b64.as_bytes()) else {
            return;
        };
        let Ok(body) = serde_json::from_slice::<Value>(&decoded) else {
            return;
        };
        match body.get("_greentic").cloned() {
            Some(m) => m,
            None => return,
        }
    } else {
        match output.get("_greentic").cloned() {
            Some(m) => m,
            None => return,
        }
    };
    let Some(tenant_id) = metadata.get("tenant").and_then(|v| v.as_str()) else {
        return;
    };
    let Some(conversation_id) = metadata.get("conversation_id").and_then(|v| v.as_str()) else {
        return;
    };
    let Some(new_watermark) = metadata.get("watermark_bumped").and_then(|v| v.as_u64()) else {
        return;
    };
    operator_log::debug(
        module_path!(),
        format!(
            "[revision ws notifier] publishing event tenant={tenant_id} \
             conv={conversation_id} watermark={new_watermark}",
        ),
    );
    notifier
        .publish(crate::notifier::NotifyEvent {
            tenant_id: tenant_id.to_string(),
            conversation_id: conversation_id.to_string(),
            new_watermark,
        })
        .await;
}

/// Build a reply [`ChannelMessageEnvelope`] from an inbound `ingress`
/// envelope (used as the routing base — channel, session_id, recipients,
/// tenant) and a reply [`Activity`] produced by the flow runtime. Mirrors
/// `messaging_app::base_reply_envelope` and layers the activity's payload
/// on top.
///
/// If the activity's payload itself deserializes as a full envelope (some
/// flows emit one directly), use that and only repair the route fields
/// (channel/session/to) from the ingress. Otherwise treat the payload as
/// the reply text or wholesale `metadata` carrier and start from a
/// clone of the ingress envelope.
fn build_reply_envelope(
    ingress: &ChannelMessageEnvelope,
    reply: &Activity,
) -> ChannelMessageEnvelope {
    // Keys carried forward from the ingress envelope's metadata when the
    // reply doesn't supply its own. Kept in sync with the legacy
    // `messaging_app::base_reply_envelope` reset list.
    const REPLY_METADATA_KEYS: &[&str] = &[
        "env",
        "tenant",
        "team",
        "route",
        "locale",
        "universal",
        "autoStart",
    ];

    if let Ok(mut envelope) =
        serde_json::from_value::<ChannelMessageEnvelope>(reply.payload().clone())
    {
        if envelope.session_id.trim().is_empty() {
            envelope.session_id = ingress.session_id.clone();
        }
        if envelope.channel.is_empty() {
            envelope.channel = ingress.channel.clone();
        }
        if envelope.to.is_empty() {
            envelope.to = ingress.to.clone();
        }
        if envelope.id.is_empty() {
            envelope.id = uuid::Uuid::new_v4().to_string();
        }
        return envelope;
    }

    let mut envelope = ingress.clone();
    envelope.id = uuid::Uuid::new_v4().to_string();
    envelope.from = None;
    envelope.correlation_id = None;
    envelope.reply_scope = None;
    envelope.text = None;
    envelope.attachments.clear();

    let mut clean = std::collections::BTreeMap::new();
    for key in REPLY_METADATA_KEYS {
        if let Some(value) = envelope.metadata.remove(*key) {
            clean.insert((*key).to_string(), value);
        }
    }
    envelope.metadata = clean;

    // Lift the flow reply's content via the same extractor the worker/chat
    // path uses (`activity_to_worker_message`), so it handles the `session.wait`
    // "pending" wrapper and `renderedCard` shape uniformly. An adaptive card
    // goes into `metadata["adaptive_card"]` — where every provider's
    // `resolve_adaptive_card` reads it — plus `extensions[ADAPTIVE_CARD]` for
    // the typed pipeline; otherwise carry the reply text. Without the card lift,
    // TierD providers (Telegram/Slack/WhatsApp/...) fall back to their
    // "universal <provider> payload" placeholder instead of the card.
    let message = activity_to_worker_message(reply);
    match message.kind.as_str() {
        "adaptive-card" => {
            if let Ok(ac_json) = serde_json::to_string(&message.payload) {
                envelope
                    .metadata
                    .insert("adaptive_card".to_string(), ac_json);
            }
            envelope
                .extensions
                .insert(ext_keys::ADAPTIVE_CARD.to_string(), message.payload);
        }
        "text" => {
            if let Some(text) = message
                .payload
                .get("text")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                envelope.text = Some(text.to_string());
            }
        }
        _ => {}
    }

    // Forward the reply's DirectLine passthrough fields (attachments /
    // channelData / entities / suggestedActions / speak / inputHint / rag) into
    // the outbound envelope's extensions, using the exact same mapping the
    // legacy `messaging_app` path applies. The egress chain
    // (`render_plan` → `encode` → `send_payload`) reads these from
    // `extensions`; without this copy a rich reply reaches the provider as
    // text only and attachments/channelData/entities are dropped. Operates on
    // the pending-unwrapped payload so it matches the content lift above.
    crate::messaging_app::copy_directline_passthrough(
        unwrap_pending_response(reply.payload()),
        &mut envelope,
    );

    envelope
}

/// Collect every request header into `(name_lowercase, value_utf8)` pairs
/// for [`HttpInV1::headers`]. Non-UTF-8 values are silently dropped — the
/// wire is JSON, so a single malformed header would otherwise 500 the
/// whole webhook.
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
    query: &[(String, String)],
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
        query: query.to_vec(),
        headers: headers.to_vec(),
        body_b64: BASE64.encode(body),
        config: None,
    }
}

/// Split a raw query string (sans leading `?`) into `(key, value)` pairs.
/// Entries with no `=` keep an empty value. No percent-decoding — the
/// provider component decodes its own keys (legacy ingress contract).
fn parse_query_pairs(query: Option<&str>) -> Vec<(String, String)> {
    query
        .unwrap_or_default()
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
fn envelope_to_activity(
    envelope: &ChannelMessageEnvelope,
    fallback_tenant: &str,
    endpoint_id: Option<&str>,
    welcome_hint: Option<WelcomeFlowHint>,
) -> Activity {
    // Serialize the whole envelope as the activity payload so the flow engine
    // sees BOTH `entry.text` and `entry.metadata.*`. `build_routing_context`
    // synthesises the `response.*` object that conditional routes test (e.g.
    // `response.action == "about_card"`) from `entry.metadata.*` plus
    // `entry.text`. A card button's submit data is flattened into the provider
    // envelope's metadata by the provider ingest (slack/teams/webex/telegram),
    // so it must reach the flow — otherwise every button press loses its action
    // and the entry (welcome) card re-renders. Mirrors the legacy
    // `messaging_app::run_app_flow`, which passes the full envelope as
    // `entry.input`; `messaging` flow type matches the prior `Activity::text`
    // resolution for typed messages.
    let payload = serde_json::to_value(envelope).unwrap_or(Value::Null);
    let mut activity = Activity::custom("provider.event", payload).with_flow_type("messaging");
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
    // M1.4 endpoint attribution + M1.5 welcome hint, resolved once per request
    // in `dispatch_provider_route` and attached to every envelope's activity —
    // the same pair `build_activity` threads on the generic-JSON branch.
    if let Some(eid) = endpoint_id {
        activity = activity.with_messaging_endpoint(eid);
    }
    if let Some(hint) = welcome_hint {
        activity = activity.with_welcome_flow_hint(hint);
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

// ---------------------------------------------------------------------------
// A4: DirectLine helpers (revision-path equivalents of the legacy
// `http_ingress` helpers). These are pure functions — no state, no I/O —
// except `read_provider_signing_key` which reads the secrets manager.
// ---------------------------------------------------------------------------

/// Read the `jwt_signing_key` for a provider from the secrets manager.
/// Returns `None` when the key is absent or the read fails (best-effort —
/// a missing key just means no token renewal, not a hard failure).
async fn read_provider_signing_key(
    activation: &Activation,
    tenant: &str,
    team: Option<&str>,
    provider_type: &str,
) -> Option<Vec<u8>> {
    let secrets = activation.host.secrets_manager();
    let env = crate::resolve_env(None);
    let team_segment = crate::secrets_manager::canonical_team(team);
    // The provider type uses dots (`messaging.webchat.gui`) while secrets
    // are stored under the hyphenated form (`messaging-webchat-gui`).
    // Build both raw-hyphenated and canonical-underscored URIs, matching
    // the resolution order in `DemoRunnerHost::get_secret`.
    let provider_hyphen = provider_type.replace('.', "-");
    let raw_uri =
        format!("secrets://{env}/{tenant}/{team_segment}/{provider_hyphen}/jwt_signing_key");
    let canonical_uri = crate::secrets_gate::canonical_secret_uri(
        &env,
        tenant,
        team,
        &provider_hyphen,
        "jwt_signing_key",
    );
    for uri in [&raw_uri, &canonical_uri] {
        match secrets.read(uri).await {
            Ok(bytes) => return Some(bytes),
            Err(_) => continue,
        }
    }
    None
}

/// Extract the DirectLine-relative path from a full request path.
///
/// Revision-path routes carry the full URL pattern
/// (e.g. `/v1/messaging/webchat/{tenant}/v3/directline/conversations/{id}/activities`).
/// The provider path is everything from `/v3/directline` onward. Falls back
/// to `/token` when the path ends with `/token` (the legacy shorthand).
fn extract_directline_provider_path(path: &str) -> String {
    // Fast path: find `/v3/directline` anywhere in the path.
    if let Some(idx) = path.find("/v3/directline") {
        return path[idx..].to_string();
    }
    // Legacy shorthand paths: the last segment(s) map to a known
    // provider-relative path.
    let segments: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    if segments.last() == Some(&"token") {
        return "/token".to_string();
    }
    // /auth/config — OAuth configuration endpoint used by webchat-gui.
    if segments.len() >= 2
        && segments[segments.len() - 2] == "auth"
        && segments[segments.len() - 1] == "config"
    {
        return "/auth/config".to_string();
    }
    // Fallback: return the path as-is (should not happen for well-formed
    // webchat routes, but avoids a panic).
    path.to_string()
}

/// Map shorthand DirectLine paths to canonical API paths.
/// `/token` → `POST /v3/directline/tokens/generate`
/// `/directline/...` → `/v3/directline/...`
fn normalize_directline_dispatch(method: &str, path: &str) -> (String, String) {
    if path == "/token" {
        return (
            "POST".to_string(),
            "/v3/directline/tokens/generate".to_string(),
        );
    }
    if path == "/directline" {
        return (method.to_string(), "/v3/directline".to_string());
    }
    if let Some(rest) = path.strip_prefix("/directline/") {
        return (method.to_string(), format!("/v3/directline/{rest}"));
    }
    (method.to_string(), path.to_string())
}

/// Inject `tenant` and `team` query parameters when not already present.
fn augment_directline_queries(
    queries: &[(String, String)],
    tenant: &str,
    team: Option<&str>,
) -> Vec<(String, String)> {
    let mut augmented = queries.to_vec();
    if !augmented.iter().any(|(name, _)| name == "tenant") {
        augmented.push(("tenant".to_string(), tenant.to_string()));
    }
    if let Some(team) = team.filter(|value| !value.is_empty())
        && !augmented.iter().any(|(name, _)| name == "team")
    {
        augmented.push(("team".to_string(), team.to_string()));
    }
    augmented
}

/// Percent-encode a query-string key or value per RFC 3986 unreserved set.
#[cfg(test)]
fn percent_encode_query_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            b' ' => encoded.push_str("%20"),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

/// Serialize query pairs into a percent-encoded query string.
/// Returns `None` for an empty list (no `?` suffix needed).
#[cfg(test)]
fn encode_directline_query_string(queries: &[(String, String)]) -> Option<String> {
    if queries.is_empty() {
        return None;
    }
    Some(
        queries
            .iter()
            .map(|(name, value)| {
                format!(
                    "{}={}",
                    percent_encode_query_component(name),
                    percent_encode_query_component(value)
                )
            })
            .collect::<Vec<_>>()
            .join("&"),
    )
}

/// Apply the post-response side of a [`crate::directline_session::ForwardPlan`]:
/// seed the sliding window from a `POST /conversations` response and/or inject
/// `_directline.renewed_token` into the body.
fn apply_directline_forward_plan_to_response(
    state: &ServeState,
    plan: &crate::directline_session::ForwardPlan,
    response: &mut IngressHttpResponse,
) {
    if plan.seed_from_response
        && let Some(conv) = crate::directline_session::conversation_id_from_response(response)
    {
        state.directline_sessions.touch(&conv);
    }
    if let Some(renewed) = plan.inject_renewed_token.as_deref() {
        crate::directline_session::inject_renewed_token(
            response,
            renewed,
            state.directline_sessions.ttl_secs(),
        );
    }
}

/// Rewrite a relative `streamUrl` in a `POST /conversations` response body
/// to an absolute `ws://` URL using the request's `Host` header. DirectLineJS
/// requires an absolute URL on the WebSocket constructor; a relative path
/// makes the SDK fall back to HTTP polling.
fn rewrite_stream_url(headers: &[(String, String)], response: &mut IngressHttpResponse) {
    let Some(body_bytes) = response.body.as_ref() else {
        return;
    };
    let Ok(mut body_json) = serde_json::from_slice::<serde_json::Value>(body_bytes) else {
        return;
    };
    let needs_rewrite = body_json
        .get("streamUrl")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| s.starts_with('/'));
    if !needs_rewrite {
        return;
    }
    let Some(host) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone())
    else {
        return;
    };
    let relative = body_json["streamUrl"].as_str().unwrap_or("").to_string();
    // Behind a TLS-terminating proxy (Cloud Run, K8s ingress) the page is
    // HTTPS, so the socket must be wss:// — a ws:// URL throws SecurityError in
    // the browser. Derive the scheme from X-Forwarded-Proto rather than the
    // container's own (always-plain-HTTP) listener.
    let scheme = crate::startup_contract::forwarded_ws_scheme(headers);
    let absolute = format!("{scheme}://{host}{relative}");
    body_json["streamUrl"] = serde_json::Value::String(absolute);
    if let Ok(rewritten) = serde_json::to_vec(&body_json) {
        response.body = Some(rewritten);
    }
}

/// Validate a `POST /tokens/generate` response: the body must be JSON with a
/// non-empty `token` field. Returns an error response on failure so the
/// upstream gets a clear `502` instead of a malformed token.
#[allow(clippy::result_large_err)]
fn validate_token_response(response: &IngressHttpResponse) -> Result<(), Response<Full<Bytes>>> {
    let body = response.body.as_deref().unwrap_or_default();
    if !(200..300).contains(&response.status) {
        operator_log::error(
            module_path!(),
            format!(
                "[webchat directline] token request failed status={} body={}",
                response.status,
                String::from_utf8_lossy(body)
                    .chars()
                    .take(500)
                    .collect::<String>()
            ),
        );
        return Err(error_response(
            StatusCode::BAD_GATEWAY,
            "invalid directline token response: expected JSON body with non-empty token",
        ));
    }
    let has_token = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("token")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .is_some_and(|token| !token.trim().is_empty());
    if !has_token {
        return Err(error_response(
            StatusCode::BAD_GATEWAY,
            "invalid directline token response: expected JSON body with non-empty token",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// A5: WebSocket upgrade on the revision path
// ---------------------------------------------------------------------------

/// True when the full request path is a DirectLine stream endpoint:
/// `.../v3/directline/conversations/{id}/stream`.
fn is_directline_stream_path(path: &str) -> bool {
    let dl = extract_directline_provider_path(path);
    let segments: Vec<&str> = dl.trim_start_matches('/').split('/').collect();
    matches!(
        segments.as_slice(),
        ["v3", "directline", "conversations", _, "stream"]
    )
}

/// Extract the conversation id from a DirectLine stream path.
fn extract_stream_conversation_id(path: &str) -> Option<String> {
    let dl = extract_directline_provider_path(path);
    let segments: Vec<&str> = dl.trim_start_matches('/').split('/').collect();
    match segments.as_slice() {
        ["v3", "directline", "conversations", conv_id, "stream"] => Some((*conv_id).to_string()),
        _ => None,
    }
}

/// `ActivitySource` that calls `RunnerHost::invoke_provider_for_revision`
/// to read activities from the conversation state. Unlike the legacy
/// `RunnerHostActivitySource` (which wraps a sync `RunnerHostHandle` in
/// `spawn_blocking`), this source calls the async revision-path API
/// directly — no sync/async bridge required.
struct RevisionActivitySource {
    host: Arc<RunnerHost>,
    deployment_id: DeploymentId,
    bundle_id: BundleId,
    revision_id: RevisionId,
    provider_type: String,
    team: String,
    /// Bearer token captured at WS upgrade time.
    auth_token: Option<String>,
}

#[async_trait::async_trait]
impl crate::websocket::pump::ActivitySource for RevisionActivitySource {
    async fn fetch_since(
        &self,
        tenant_id: &str,
        conversation_id: &str,
        since_watermark: u64,
    ) -> Result<(Vec<Value>, u64), String> {
        let headers: Vec<Value> = match &self.auth_token {
            Some(token) if !token.is_empty() => {
                vec![serde_json::json!([
                    "Authorization",
                    format!("Bearer {token}")
                ])]
            }
            _ => Vec::new(),
        };
        let payload = serde_json::json!({
            "v": 1,
            "provider": self.provider_type,
            "route": Value::Null,
            "binding_id": Value::Null,
            "tenant_hint": tenant_id,
            "team_hint": self.team,
            "method": "GET",
            "path": format!("/v3/directline/conversations/{conversation_id}/activities"),
            "query": format!("watermark={since_watermark}&tenant={tenant_id}&team={}", self.team),
            "headers": headers,
            "body_b64": "",
            "config": Value::Null,
        });
        let input_json = serde_json::to_vec(&payload).map_err(|err| err.to_string())?;

        // Try canonical `ingest-http` op, then fall back to the underscore
        // alias used by older pack builds — same pattern as the legacy
        // `DemoRunnerHost` impl.
        let output = match self
            .host
            .invoke_provider_for_revision(
                tenant_id,
                self.deployment_id,
                self.bundle_id.clone(),
                self.revision_id,
                &self.provider_type,
                "ingest-http",
                input_json.clone(),
                None,
                None,
            )
            .await
        {
            Ok(v) => v,
            Err(_) => self
                .host
                .invoke_provider_for_revision(
                    tenant_id,
                    self.deployment_id,
                    self.bundle_id.clone(),
                    self.revision_id,
                    &self.provider_type,
                    "ingest_http",
                    input_json,
                    None,
                    None,
                )
                .await
                .map_err(|err| err.to_string())?,
        };

        // Decode the provider response envelope.
        let body_b64 = output
            .get("body_b64")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing body_b64 in provider response".to_string())?;
        let body_bytes = BASE64
            .decode(body_b64.as_bytes())
            .map_err(|err| format!("invalid base64 body_b64: {err}"))?;
        if body_bytes.is_empty() {
            return Ok((Vec::new(), since_watermark));
        }
        let value: Value = serde_json::from_slice(&body_bytes)
            .map_err(|err| format!("invalid body json: {err}"))?;
        let activities = value
            .get("activities")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let next_watermark = value
            .get("watermark")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(since_watermark);
        Ok((activities, next_watermark))
    }
}

/// Handle a WebSocket upgrade on the revision path.
///
/// The conversation must already exist (created via REST `POST /conversations`)
/// and be pinned to a revision. The WS pump reads activities from the SAME
/// revision the REST conversation was pinned to — never re-dispatching — so
/// the socket and the REST endpoint always see the same conversation state.
async fn handle_websocket_upgrade(
    req: &mut Request<Incoming>,
    path: &str,
    state: Arc<ServeState>,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    let conv_id = match extract_stream_conversation_id(path) {
        Some(c) => c,
        None => return Err(error_response(StatusCode::NOT_FOUND, "invalid stream path")),
    };

    let activation = state.current();
    let host_header = header_str(req.headers(), header::HOST.as_str());

    // Resolve deployment + tenant from the path so we know which env's
    // secrets to read the signing key from.
    let (deployment_id, tenant) = activation
        .routing
        .deployment_routes
        .resolve(host_header.as_deref(), path)
        .map(|(deployment_id, tenant)| (deployment_id, tenant.to_string()))
        .ok_or_else(|| {
            error_response(
                StatusCode::NOT_FOUND,
                "no deployment is bound to this host and path",
            )
        })?;

    // Resolve the provider_type for this path so we can read its signing key.
    let provider_type = activation
        .routing
        .http_routes
        .provider_type_for(path, "GET", deployment_id)
        .ok_or_else(|| {
            error_response(
                StatusCode::NOT_FOUND,
                "no provider route matches this stream path",
            )
        })?
        .to_string();

    // Look up the revision pin for this conversation. A5 critical invariant:
    // the WS pump MUST read from the same revision the REST POST pinned to.
    // The session hint format is `webchat:{conversation_id}`.
    let session_hint = format!("webchat:{conv_id}");
    let pinned = activation
        .routing
        .dispatcher
        .lookup_pin(&tenant, deployment_id, &session_hint)
        .await;

    let (bundle_id, revision_id) = match pinned {
        Some((bid, rid)) => (bid, rid),
        None => {
            // No pin means the conversation was never created via REST, or the
            // pin expired. Either way, we cannot safely pick a revision.
            return Err(error_response(
                StatusCode::NOT_FOUND,
                "no revision pin for this conversation; create it via REST first",
            ));
        }
    };

    // Read the JWT signing key from the pinned revision's secrets.
    let team = "default";
    let signing_key =
        read_provider_signing_key(&activation, &tenant, Some(team), &provider_type).await;
    let signing_key = match signing_key {
        Some(key) => key,
        None => {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "missing jwt_signing_key for the webchat provider",
            ));
        }
    };

    // Validate the ?t= token.
    let ctx = match crate::websocket::validate_request_parts(
        req.uri(),
        req.headers(),
        &conv_id,
        &tenant,
        &signing_key,
    ) {
        Ok(c) => c,
        Err(err) => return Ok(crate::websocket::refusal_response(&err)),
    };

    // Acquire a session slot.
    let guard = match state.session_manager.acquire(&tenant, &conv_id) {
        Ok(g) => g,
        Err(err) => {
            return Ok(crate::websocket::refusal_response(
                &crate::websocket::UpgradeError::LimitExceeded(err.to_string()),
            ));
        }
    };

    // Extract the bearer token from ?t= BEFORE the upgrade call consumes
    // the request reference. The token authenticates the pump's internal
    // GET /activities calls against the WASM provider's JWT guard.
    let auth_token = req.uri().query().and_then(|q| {
        q.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            if k == "t" { Some(v.to_string()) } else { None }
        })
    });

    // Perform the HTTP -> WS upgrade.
    let (response, websocket) = match hyper_tungstenite::upgrade(req, None) {
        Ok(pair) => pair,
        Err(err) => {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                format!("websocket upgrade failed: {err}"),
            ));
        }
    };

    // Build the revision-specific activity source. This calls
    // `invoke_provider_for_revision` directly (async) — no sync/async bridge
    // needed because the pump runs entirely in an async context.
    #[cfg(test)]
    let source: Arc<dyn crate::websocket::pump::ActivitySource> =
        if let Some(ref override_source) = state.activity_source_override {
            Arc::clone(override_source)
        } else {
            Arc::new(RevisionActivitySource {
                host: Arc::clone(&activation.host),
                deployment_id,
                bundle_id,
                revision_id,
                provider_type,
                team: team.to_string(),
                auth_token,
            })
        };
    #[cfg(not(test))]
    let source: Arc<dyn crate::websocket::pump::ActivitySource> =
        Arc::new(RevisionActivitySource {
            host: Arc::clone(&activation.host),
            deployment_id,
            bundle_id,
            revision_id,
            provider_type,
            team: team.to_string(),
            auth_token,
        });

    let notifier = state.notifier.clone();
    let limits = state.session_manager.limits().clone();

    tokio::spawn(crate::websocket::serve_session(
        websocket,
        notifier,
        source,
        tenant,
        conv_id,
        ctx.initial_watermark,
        limits,
        guard,
    ));

    // Repackage the upgrade response into `Full<Bytes>` (the 101 body is
    // empty; only the status + headers matter for the handshake).
    let (parts, _body) = response.into_parts();
    Ok(Response::from_parts(parts, Full::new(Bytes::new())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notifier::ActivityNotifier;
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
            webhook_secret_ref: None,
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
                public_base_url: None,
                gui_enabled: None,
            },
            packs: Vec::new(),
            messaging_endpoints: vec![endpoint],
            extensions: Vec::new(),
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
    fn loopback_trust_requires_both_a_loopback_peer_and_no_tunnel() {
        use std::net::{IpAddr, Ipv4Addr};
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mapped_loopback = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
        let public = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

        // No tunnel: only genuine loopback peers are trusted (an IPv4-mapped
        // IPv6 loopback still counts; a public peer never does).
        assert!(peer_is_loopback_trusted(true, loopback));
        assert!(peer_is_loopback_trusted(true, mapped_loopback));
        assert!(!peer_is_loopback_trusted(true, public));

        // Tunnel fronting the listener: every peer is untrusted, including a
        // loopback one — the tunnel forwards public traffic over loopback, so
        // the peer address can no longer prove the caller is local.
        assert!(!peer_is_loopback_trusted(false, loopback));
        assert!(!peer_is_loopback_trusted(false, mapped_loopback));
        assert!(!peer_is_loopback_trusted(false, public));
    }

    #[test]
    fn tunneled_split_serves_console_on_admin_listener_only() {
        use std::io::{Read, Write};
        use std::net::SocketAddr;

        // Status code of `GET <path>` over a fresh loopback connection.
        fn get_status(port: u16, path: &str) -> u16 {
            let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
            s.write_all(
                format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .expect("write request");
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).expect("read response");
            let head = String::from_utf8_lossy(&buf);
            head.lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|c| c.parse().ok())
                .unwrap_or_else(|| panic!("no status line in response: {head:?}"))
        }

        // A tunnel fronts the main listener (trust_loopback_peers = false), with
        // a loopback-only admin listener alongside it. Far-apart base ports so
        // the two `find_available_port` ranges can't overlap.
        let server = RevisionServer::start(RevisionServeConfig {
            bind_addr: "127.0.0.1:17780".parse::<SocketAddr>().unwrap(),
            activation: std::sync::Arc::new(empty_activation("split-test")),
            gui_enabled: true,
            trust_loopback_peers: false,
            admin_bind_addr: Some("127.0.0.1:17900".parse::<SocketAddr>().unwrap()),
            updates_enabled: false,
            auto_restart_enabled: false,
            exe_path: None,
            public_url_capture: None,
        })
        .expect("start split server");

        let main = server.actual_port();
        let admin = server.admin_port().expect("admin listener bound");
        assert_ne!(main, admin, "admin listener must be a distinct port");

        // Both listeners are live: the ungated probe answers on each.
        assert_eq!(get_status(main, "/healthz"), 200, "main /healthz");
        assert_eq!(get_status(admin, "/healthz"), 200, "admin /healthz");

        // The whole point of the split: the console is refused on the public
        // (tunneled, untrusted) listener but served on the loopback admin
        // listener — webchat and a tunnelled provider face at the same time.
        assert_ne!(
            get_status(main, "/chat"),
            200,
            "public listener must NOT serve the console"
        );
        assert_eq!(
            get_status(admin, "/chat"),
            200,
            "loopback admin listener must serve the console"
        );

        server.stop().expect("stop server");
    }

    #[test]
    fn admin_port_skips_bumped_main_port() {
        // Regression: when the requested main port is busy,
        // `find_available_port` bumps it (e.g. N → N+1). The admin listener
        // defaults to N+1, so a naïve probe would also pick N+1 — then the
        // serving thread binds both to the same port and the second bind
        // fails. The fix starts the admin search from `actual_port + 1`.
        let base: u16 = 17810;
        // Hold the base port so the main listener bumps to base+1.
        let _hold = std::net::TcpListener::bind(format!("127.0.0.1:{base}")).expect("hold base");
        let server = RevisionServer::start(RevisionServeConfig {
            bind_addr: format!("127.0.0.1:{base}").parse().unwrap(),
            activation: std::sync::Arc::new(empty_activation("port-bump")),
            gui_enabled: true,
            trust_loopback_peers: false,
            // Admin requested at base+1 — exactly where the main listener
            // will land after bumping past the held base port.
            admin_bind_addr: Some(format!("127.0.0.1:{}", base + 1).parse().unwrap()),
            updates_enabled: false,
            auto_restart_enabled: false,
            exe_path: None,
            public_url_capture: None,
        })
        .expect("start must succeed even when main bumps into admin range");

        let main = server.actual_port();
        let admin = server.admin_port().expect("admin bound");
        assert_eq!(main, base + 1, "main should have bumped to base+1");
        assert!(
            admin > main,
            "admin ({admin}) must be above the bumped main ({main})"
        );

        server.stop().expect("stop server");
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
            webhook_secret_ref: None,
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
                public_base_url: None,
                gui_enabled: None,
            },
            packs: Vec::new(),
            messaging_endpoints: vec![endpoint],
            extensions: Vec::new(),
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
        let query = parse_query_pairs(Some("token=abc&n=1"));
        let http_in = build_provider_http_in(
            "messaging.telegram.bot",
            "acme",
            "POST",
            "/webhook/telegram",
            &query,
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
    fn build_provider_http_in_preserves_percent_encoded_query() {
        // Regression: the old path encoded pairs into a query string then
        // re-parsed them, double-encoding any `%` already in the raw
        // query (e.g. `%20` became `%2520`). The fix passes pairs
        // directly so percent-encoded characters survive unchanged.
        let pairs = parse_query_pairs(Some("user=John%20Doe&tag=%E2%9C%93"));
        let http_in = build_provider_http_in(
            "messaging.webchat.standard",
            "acme",
            "POST",
            "/v3/directline/conversations",
            &pairs,
            &[],
            b"{}",
        );
        assert_eq!(
            http_in.query,
            vec![
                ("user".to_string(), "John%20Doe".to_string()),
                ("tag".to_string(), "%E2%9C%93".to_string()),
            ],
            "percent-encoded characters must survive without double-encoding"
        );
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
        let activity = envelope_to_activity(&envelope, "fallback", None, None);
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
        let activity = envelope_to_activity(&envelope, "fallback", None, None);
        assert_eq!(activity.tenant(), Some("acme"));
        assert_eq!(activity.session_id(), None);
    }

    #[test]
    fn envelope_to_activity_carries_metadata_for_button_routing() {
        // A card-button press arrives as an ingress envelope whose submit data
        // is flattened into `metadata` (e.g. `action`). The flow engine builds
        // `response.action` from `entry.metadata.action`, so the activity
        // payload must expose the envelope metadata — otherwise the button
        // press loses its action and the entry (welcome) card re-renders.
        let envelope: ChannelMessageEnvelope = serde_json::from_value(json!({
            "id": "cb-1",
            "tenant": {
                "env": "dev",
                "tenant": "acme",
                "tenant_id": "acme",
                "attempt": 0,
            },
            "channel": "telegram",
            "session_id": "sess-1",
            "from": { "id": "u1", "kind": "user" },
            "text": "[callback:{\"action\":\"about_card\"}]",
            "metadata": {
                "action": "about_card",
                "callback_data": "{\"action\":\"about_card\"}",
            },
        }))
        .expect("envelope");
        let activity = envelope_to_activity(&envelope, "fallback", None, None);
        let entry = activity.payload();
        // `response.action` resolves from `entry.metadata.action`.
        assert_eq!(
            entry.pointer("/metadata/action").and_then(Value::as_str),
            Some("about_card"),
        );
        // `response.text` still resolves from `entry.text`.
        assert_eq!(
            entry.pointer("/text").and_then(Value::as_str),
            Some("[callback:{\"action\":\"about_card\"}]"),
        );
        assert_eq!(activity.flow_type(), Some("messaging"));
    }

    #[test]
    fn envelope_to_activity_attaches_endpoint_and_welcome_hint() {
        // M1.4/M1.5 on the provider-route path: the eid + welcome hint
        // resolved in `dispatch_provider_route` must reach the activity so
        // per-endpoint session isolation and welcome-flow selection apply to
        // provider webhooks the same way the generic-JSON branch's
        // `build_activity` applies them.
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
        let hint = WelcomeFlowHint {
            pack_id: "welcome-pack".to_string(),
            flow_id: "welcome-flow".to_string(),
        };
        let activity =
            envelope_to_activity(&envelope, "fallback", Some("ep-legal"), Some(hint.clone()));
        assert_eq!(activity.messaging_endpoint_id(), Some("ep-legal"));
        assert_eq!(activity.welcome_flow_hint(), Some(&hint));
    }

    #[test]
    fn build_reply_envelope_text_activity_clones_ingress_route() {
        // A simple "text" reply Activity carries its text in `payload.text`;
        // route fields (channel, session, to) must come from the ingress
        // envelope so the provider knows where to deliver the bot reply.
        let ingress: ChannelMessageEnvelope = serde_json::from_value(json!({
            "id": "msg-in-1",
            "tenant": {
                "env": "dev",
                "tenant": "acme",
                "tenant_id": "acme",
                "attempt": 0,
            },
            "channel": "telegram",
            "session_id": "chat-42",
            "to": [{ "id": "room-1", "kind": "room" }],
            "from": { "id": "user-1", "kind": "user" },
            "text": "hi",
            "metadata": { "route": "/webhook/telegram", "leftover": "stripped" },
        }))
        .expect("ingress envelope");

        let reply = Activity::text("hello back");
        let envelope = build_reply_envelope(&ingress, &reply);

        // Route fields preserved.
        assert_eq!(envelope.session_id, "chat-42");
        assert_eq!(envelope.channel, "telegram");
        assert_eq!(envelope.to.len(), 1);
        // Reply text picked up from activity payload.
        assert_eq!(envelope.text.as_deref(), Some("hello back"));
        // From / correlation reset on a reply (the bot does NOT impersonate
        // the inbound user).
        assert!(envelope.from.is_none());
        assert!(envelope.correlation_id.is_none());
        // New `id` — not the inbound `id` (deduper would otherwise drop the
        // reply as a duplicate of the inbound).
        assert_ne!(envelope.id, "msg-in-1");
        // Ingress metadata pruned to the routing-relevant subset.
        assert!(envelope.metadata.contains_key("route"));
        assert!(!envelope.metadata.contains_key("leftover"));
    }

    #[test]
    fn build_reply_envelope_lifts_rendered_card_into_metadata() {
        // A flow that renders an Adaptive Card (e.g. welcome_card) returns it as
        // a custom `response` Activity carrying `renderedCard`. The provider
        // egress reads the card from `metadata["adaptive_card"]`; if it isn't
        // lifted, TierD providers (Telegram/Slack/...) send their
        // "universal <provider> payload" placeholder instead of the card.
        let ingress: ChannelMessageEnvelope = serde_json::from_value(json!({
            "id": "msg-in-card",
            "tenant": { "env": "dev", "tenant": "acme", "tenant_id": "acme", "attempt": 0 },
            "channel": "telegram",
            "session_id": "chat-7",
            "to": [{ "id": "room-1", "kind": "room" }],
            "text": "hi",
        }))
        .expect("ingress envelope");

        let card = json!({ "type": "AdaptiveCard", "version": "1.6" });

        // Direct `renderedCard` shape.
        let reply = Activity::custom("response", json!({ "renderedCard": card.clone() }));
        let envelope = build_reply_envelope(&ingress, &reply);
        let stored: Value = serde_json::from_str(
            envelope
                .metadata
                .get("adaptive_card")
                .expect("adaptive_card in metadata"),
        )
        .expect("card json");
        assert_eq!(stored, card);
        assert_eq!(
            envelope.extensions.get(ext_keys::ADAPTIVE_CARD),
            Some(&card)
        );
        // Card present → no redundant text bubble, route cloned from ingress.
        assert!(envelope.text.is_none());
        assert_eq!(envelope.channel, "telegram");
        assert_eq!(envelope.session_id, "chat-7");

        // `session.wait` "pending" wrapper: the welcome_card node pauses, so the
        // card arrives wrapped — the same extractor must still find it.
        let pending = Activity::custom(
            "response",
            json!({ "status": "pending", "response": { "renderedCard": card.clone() } }),
        );
        let envelope = build_reply_envelope(&ingress, &pending);
        let stored: Value = serde_json::from_str(
            envelope
                .metadata
                .get("adaptive_card")
                .expect("adaptive_card from pending wrapper"),
        )
        .expect("card json");
        assert_eq!(stored, card);
    }

    #[test]
    fn build_reply_envelope_full_payload_envelope_uses_it_verbatim() {
        // An Activity whose payload IS a ChannelMessageEnvelope (e.g. an
        // emit_message node serializing one) should be used verbatim —
        // only route holes (empty session/channel/to/id) get backfilled
        // from the ingress so the egress can deliver it.
        let ingress: ChannelMessageEnvelope = serde_json::from_value(json!({
            "id": "msg-in-2",
            "tenant": {
                "env": "dev",
                "tenant": "acme",
                "tenant_id": "acme",
                "attempt": 0,
            },
            "channel": "telegram",
            "session_id": "chat-7",
            "to": [{ "id": "room-7", "kind": "room" }],
            "metadata": {},
        }))
        .expect("ingress envelope");

        // Reply envelope only carries text + (empty) session_id; the
        // builder must fall back to the ingress session/channel/to so the
        // provider knows where to deliver.
        let reply_payload = json!({
            "id": "",
            "tenant": {
                "env": "dev",
                "tenant": "acme",
                "tenant_id": "acme",
                "attempt": 0,
            },
            "channel": "",
            "session_id": "",
            "text": "scripted-reply",
            "metadata": {},
        });
        let reply = Activity::custom("messaging", reply_payload);

        let envelope = build_reply_envelope(&ingress, &reply);
        assert_eq!(envelope.session_id, "chat-7");
        assert_eq!(envelope.channel, "telegram");
        assert_eq!(envelope.to.len(), 1);
        assert_eq!(envelope.text.as_deref(), Some("scripted-reply"));
        assert!(!envelope.id.is_empty(), "id backfilled from uuid");
    }

    #[test]
    fn build_reply_envelope_forwards_directline_passthrough_fields() {
        // Regression for the env-path attachment-strip (greentic-e2e webchat
        // passthrough): a flow reply carrying attachments + channelData +
        // entities alongside text must forward those into `extensions` so the
        // provider's egress chain renders them. Before the fix the env path
        // kept only the text and dropped the rest — the legacy `--bundle` boot
        // preserved them, so the nightly (on the legacy boot) never caught it.
        let ingress: ChannelMessageEnvelope = serde_json::from_value(json!({
            "id": "msg-in-dl",
            "tenant": { "env": "dev", "tenant": "acme", "tenant_id": "acme", "attempt": 0 },
            "channel": "webchat-gui",
            "session_id": "conv-1",
            "to": [{ "id": "room-1", "kind": "room" }],
            "text": "hi",
        }))
        .expect("ingress envelope");

        let card = json!({
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.5",
        });
        let reply = Activity::custom(
            "message",
            json!({
                "ok": true,
                "text": "Bug 3 probe — reply carries a rich envelope",
                "attachments": [
                    { "contentType": "application/vnd.microsoft.card.adaptive", "content": card }
                ],
                "channelData": { "bug3_probe": true },
                "entities": [{ "type": "bug3-probe", "id": "attachment-passthrough-check" }],
            }),
        );

        let envelope = build_reply_envelope(&ingress, &reply);

        // Text still lifted.
        assert_eq!(
            envelope.text.as_deref(),
            Some("Bug 3 probe — reply carries a rich envelope")
        );
        // The three DirectLine fields the probe checks reach `extensions`.
        assert!(
            envelope.extensions.contains_key(ext_keys::ATTACHMENTS),
            "attachments must be forwarded, not dropped"
        );
        assert_eq!(
            envelope.extensions.get(ext_keys::CHANNEL_DATA),
            Some(&json!({ "bug3_probe": true }))
        );
        assert_eq!(
            envelope.extensions.get(ext_keys::ENTITIES),
            Some(&json!([{ "type": "bug3-probe", "id": "attachment-passthrough-check" }]))
        );
        // Attachments carry the card, so it is NOT also lifted into
        // ADAPTIVE_CARD (that would duplicate it on the outbound activity) —
        // matches the legacy `copy_directline_passthrough` contract.
        assert!(
            !envelope.extensions.contains_key(ext_keys::ADAPTIVE_CARD),
            "card rides inside forwarded attachments; no separate lift"
        );
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
            public_base_url: None,
            gui_enabled: None,
        }
    }

    struct EnvVarGuard {
        gateway_prev: Option<std::ffi::OsString>,
        gateway_port_prev: Option<std::ffi::OsString>,
        port_prev: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn clean() -> Self {
            let gateway_prev = std::env::var_os("GREENTIC_GATEWAY_LISTEN_ADDR");
            let gateway_port_prev = std::env::var_os("GREENTIC_GATEWAY_PORT");
            let port_prev = std::env::var_os("PORT");
            // SAFETY: callers hold `test_env_lock` so env mutation is serialized.
            unsafe {
                std::env::remove_var("GREENTIC_GATEWAY_LISTEN_ADDR");
                std::env::remove_var("GREENTIC_GATEWAY_PORT");
                std::env::remove_var("PORT");
            }
            Self {
                gateway_prev,
                gateway_port_prev,
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
                match &self.gateway_port_prev {
                    Some(v) => std::env::set_var("GREENTIC_GATEWAY_PORT", v),
                    None => std::env::remove_var("GREENTIC_GATEWAY_PORT"),
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
                deployment_config_overrides: std::sync::Arc::default(),
                static_routes: crate::static_routes::ActiveRouteTable::default(),
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
            gui_enabled: false,
            restart_required: AtomicBool::new(false),
            updates_enabled: false,
            auto_restart_pending: AtomicBool::new(false),
            auto_restart_enabled: false,
            exe_path: None,
            directline_sessions: Arc::new(
                crate::directline_session::DirectLineSessions::with_ttl_secs(1800),
            ),
            conversation_dedup: Arc::new(crate::conv_dedup::ConversationDedupCache::new()),
            session_manager: Arc::new(crate::websocket::SessionManager::new(
                crate::websocket::WsLimits::default(),
            )),
            notifier: Arc::new(crate::notifier::InMemoryNotifier::new(64)),
            public_url_capture: None,
            activity_source_override: None,
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

    #[test]
    fn try_chat_asset_serves_console_page_and_renderer_on_get() {
        let page = try_chat_asset_response("/chat", &hyper::Method::GET).expect("chat page");
        assert_eq!(page.status(), StatusCode::OK);
        assert_eq!(
            page.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8"),
        );
        // Anti-framing headers must be present so a cross-site iframe can't load
        // the console and auto-drive the loopback worker endpoint.
        assert_eq!(
            page.headers()
                .get(header::X_FRAME_OPTIONS)
                .and_then(|v| v.to_str().ok()),
            Some("DENY"),
        );
        assert_eq!(
            page.headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .and_then(|v| v.to_str().ok()),
            Some("frame-ancestors 'none'"),
        );
        // The page must POST to the loopback worker endpoint, not a gui gateway.
        assert!(body_string(page).contains("/workers/invoke"));

        let js = try_chat_asset_response("/adaptivecards.min.js", &hyper::Method::GET)
            .expect("renderer");
        assert_eq!(js.status(), StatusCode::OK);
        assert_eq!(
            js.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/javascript; charset=utf-8"),
        );
        assert!(!body_string(js).is_empty());
    }

    #[test]
    fn try_chat_asset_rejects_non_get_and_ignores_other_paths() {
        let not_allowed =
            try_chat_asset_response("/chat", &hyper::Method::POST).expect("405 for non-GET");
        assert_eq!(not_allowed.status(), StatusCode::METHOD_NOT_ALLOWED);
        // Non-asset paths fall through so deployment routing still handles them.
        assert!(try_chat_asset_response("/", &hyper::Method::GET).is_none());
        assert!(try_chat_asset_response("/workers/invoke", &hyper::Method::POST).is_none());
    }

    // --- A.2: CORS + OPTIONS preflight on the revision path ----------------

    fn cors_roundtrip(port: u16, gui_enabled: bool, raw_request: &str) -> String {
        use std::io::{Read, Write};
        use std::net::SocketAddr;

        let server = RevisionServer::start(RevisionServeConfig {
            bind_addr: format!("127.0.0.1:{port}").parse::<SocketAddr>().unwrap(),
            activation: std::sync::Arc::new(empty_activation("cors")),
            gui_enabled,
            trust_loopback_peers: true,
            admin_bind_addr: None,
            updates_enabled: false,
            auto_restart_enabled: false,
            exe_path: None,
            public_url_capture: None,
        })
        .expect("start server");
        let port = server.actual_port();

        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.write_all(raw_request.as_bytes()).expect("write");
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).expect("read");
        server.stop().expect("stop");
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[test]
    fn cors_preflight_returns_204_for_realistic_browser_preflight() {
        let resp = cors_roundtrip(
            17950,
            true,
            concat!(
                "OPTIONS /any/path HTTP/1.1\r\n",
                "Host: localhost\r\n",
                "Origin: https://example.com\r\n",
                "Access-Control-Request-Method: POST\r\n",
                "Connection: close\r\n",
                "\r\n",
            ),
        );

        assert!(
            resp.starts_with("HTTP/1.1 204"),
            "preflight must return 204, got: {}",
            resp.lines().next().unwrap_or("")
        );

        let methods_header = resp
            .lines()
            .find(|l| {
                l.to_ascii_lowercase()
                    .starts_with("access-control-allow-methods:")
            })
            .expect("Access-Control-Allow-Methods header missing");
        assert!(
            methods_header.contains("POST"),
            "Allow-Methods must include POST: {methods_header}"
        );
    }

    #[test]
    fn cors_allow_headers_covers_webchat_gui_custom_headers() {
        let preflight = cors_preflight_response();
        let allow = preflight.headers()["access-control-allow-headers"]
            .to_str()
            .expect("valid UTF-8");
        let allowed: Vec<&str> = allow.split(',').map(str::trim).collect();

        for required in ["Content-Type", "X-Greentic-Locale"] {
            assert!(
                allowed.iter().any(|h| h.eq_ignore_ascii_case(required)),
                "Allow-Headers must include {required} (sent by the webchat GUI), got: {allow}"
            );
        }
    }

    #[test]
    fn cors_options_to_chat_path_returns_204_not_405() {
        let resp = cors_roundtrip(
            17960,
            true,
            concat!(
                "OPTIONS /chat HTTP/1.1\r\n",
                "Host: localhost\r\n",
                "Origin: https://example.com\r\n",
                "Access-Control-Request-Method: GET\r\n",
                "Connection: close\r\n",
                "\r\n",
            ),
        );

        assert!(
            resp.starts_with("HTTP/1.1 204"),
            "OPTIONS /chat must return 204 (not 405), got: {}",
            resp.lines().next().unwrap_or("")
        );
    }

    #[test]
    fn post_response_carries_cors_origin_header() {
        let body = r#"{"text":"hello"}"#;
        let resp = cors_roundtrip(
            17970,
            false,
            &format!(
                "POST /some/path HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {}",
                body.len(),
                body
            ),
        );

        assert!(
            resp.lines().any(|l| l
                .to_ascii_lowercase()
                .starts_with("access-control-allow-origin:")),
            "POST response must carry Access-Control-Allow-Origin header, got:\n{resp}"
        );
    }

    /// `/workers/invoke` executes a flow and returns its output. It is gated on
    /// the TCP peer being loopback — which a page from *any* origin, running in
    /// a browser on this machine, satisfies. It also ignores `Content-Type`, so
    /// a blind cross-origin POST already reaches it. Granting a wildcard
    /// `Access-Control-Allow-Origin` would additionally let that page read the
    /// response. Nothing legitimate needs it: `/chat` calls it same-origin and
    /// `greentic-gui` calls it server-side.
    #[test]
    fn worker_invoke_is_not_exposed_cross_origin() {
        let preflight = cors_roundtrip(
            17980,
            false,
            "OPTIONS /workers/invoke HTTP/1.1\r\n\
             Host: localhost\r\n\
             Origin: https://evil.example\r\n\
             Access-Control-Request-Method: POST\r\n\
             Access-Control-Request-Headers: content-type\r\n\
             Connection: close\r\n\
             \r\n",
        );
        assert!(
            !preflight.to_ascii_lowercase().contains("204"),
            "a cross-origin preflight for /workers/invoke must NOT be granted, got:\n{preflight}"
        );
        assert!(
            !preflight
                .to_ascii_lowercase()
                .contains("access-control-allow-origin"),
            "/workers/invoke preflight must not carry Access-Control-Allow-Origin, got:\n{preflight}"
        );

        let body = r#"{"text":"hello"}"#;
        let posted = cors_roundtrip(
            17981,
            false,
            &format!(
                "POST /workers/invoke HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Origin: https://evil.example\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {}",
                body.len(),
                body
            ),
        );
        assert!(
            !posted
                .to_ascii_lowercase()
                .contains("access-control-allow-origin"),
            "/workers/invoke response must not be readable cross-origin, got:\n{posted}"
        );
    }

    // --- A4: DirectLine dispatch helpers unit tests -------------------------

    // Category 1: extract_directline_provider_path

    #[test]
    fn extract_directline_provider_path_finds_v3_directline() {
        assert_eq!(
            extract_directline_provider_path(
                "/v1/messaging/webchat/demo/v3/directline/conversations"
            ),
            "/v3/directline/conversations"
        );
    }

    #[test]
    fn extract_directline_provider_path_with_subpath() {
        assert_eq!(
            extract_directline_provider_path(
                "/v1/messaging/webchat/demo/v3/directline/conversations/abc123/activities"
            ),
            "/v3/directline/conversations/abc123/activities"
        );
    }

    #[test]
    fn extract_directline_provider_path_legacy_token_shorthand() {
        assert_eq!(
            extract_directline_provider_path("/v1/messaging/webchat/demo/token"),
            "/token"
        );
    }

    #[test]
    fn extract_directline_provider_path_passthrough_on_unknown() {
        assert_eq!(
            extract_directline_provider_path("/v1/messaging/webchat/demo/unknown"),
            "/v1/messaging/webchat/demo/unknown"
        );
    }

    #[test]
    fn extract_directline_provider_path_auth_config() {
        assert_eq!(
            extract_directline_provider_path("/v1/messaging/webchat/demo/auth/config"),
            "/auth/config"
        );
    }

    // Category 2: normalize_directline_dispatch

    #[test]
    fn normalize_directline_dispatch_maps_token_to_canonical() {
        let (method, path) = normalize_directline_dispatch("GET", "/token");
        assert_eq!(method, "POST");
        assert_eq!(path, "/v3/directline/tokens/generate");
    }

    #[test]
    fn normalize_directline_dispatch_expands_directline_prefix() {
        let (method, path) = normalize_directline_dispatch("GET", "/directline/conversations");
        assert_eq!(method, "GET");
        assert_eq!(path, "/v3/directline/conversations");
    }

    #[test]
    fn normalize_directline_dispatch_bare_directline() {
        let (method, path) = normalize_directline_dispatch("GET", "/directline");
        assert_eq!(method, "GET");
        assert_eq!(path, "/v3/directline");
    }

    #[test]
    fn normalize_directline_dispatch_already_canonical() {
        let (method, path) = normalize_directline_dispatch("POST", "/v3/directline/conversations");
        assert_eq!(method, "POST");
        assert_eq!(path, "/v3/directline/conversations");
    }

    // Category 3: augment_directline_queries

    #[test]
    fn augment_directline_queries_injects_tenant_and_team() {
        let queries = vec![];
        let result = augment_directline_queries(&queries, "acme", Some("support"));
        assert!(
            result.iter().any(|(k, v)| k == "tenant" && v == "acme"),
            "must inject tenant"
        );
        assert!(
            result.iter().any(|(k, v)| k == "team" && v == "support"),
            "must inject team"
        );
    }

    #[test]
    fn augment_directline_queries_preserves_existing_tenant() {
        let queries = vec![("tenant".to_string(), "existing".to_string())];
        let result = augment_directline_queries(&queries, "acme", Some("support"));
        assert_eq!(
            result.iter().filter(|(k, _)| k == "tenant").count(),
            1,
            "must not duplicate tenant"
        );
        assert_eq!(result[0].1, "existing", "existing tenant must be preserved");
    }

    #[test]
    fn augment_directline_queries_skips_empty_team() {
        let queries = vec![];
        let result = augment_directline_queries(&queries, "acme", Some(""));
        assert!(
            !result.iter().any(|(k, _)| k == "team"),
            "empty team must not be injected"
        );
    }

    // Category 4: encode_directline_query_string

    #[test]
    fn encode_directline_query_string_serializes_pairs() {
        let pairs = vec![
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "two three".to_string()),
        ];
        let result = encode_directline_query_string(&pairs);
        assert_eq!(result, Some("a=1&b=two%20three".to_string()));
    }

    #[test]
    fn encode_directline_query_string_empty_returns_none() {
        assert_eq!(encode_directline_query_string(&[]), None);
    }

    // Category 5: rewrite_stream_url

    #[test]
    fn rewrite_stream_url_makes_relative_absolute() {
        let headers = vec![("Host".to_string(), "example.com:8080".to_string())];
        let mut response = IngressHttpResponse {
            status: 200,
            headers: vec![],
            body: Some(
                serde_json::to_vec(&serde_json::json!({
                    "conversationId": "abc123",
                    "streamUrl": "/v3/directline/conversations/abc123/stream?t=TOKEN"
                }))
                .unwrap(),
            ),
        };
        rewrite_stream_url(&headers, &mut response);
        let body: serde_json::Value =
            serde_json::from_slice(response.body.as_ref().unwrap()).unwrap();
        assert_eq!(
            body["streamUrl"],
            "ws://example.com:8080/v3/directline/conversations/abc123/stream?t=TOKEN",
            "relative streamUrl must become an absolute ws:// URL using the Host header"
        );
    }

    #[test]
    fn rewrite_stream_url_uses_wss_when_forwarded_https() {
        // Behind a TLS-terminating proxy (Cloud Run) the page is HTTPS, so the
        // rewritten streamUrl must be wss:// or the browser refuses the socket.
        let headers = vec![
            ("host".to_string(), "svc.run.app".to_string()),
            ("x-forwarded-proto".to_string(), "https".to_string()),
        ];
        let mut response = IngressHttpResponse {
            status: 200,
            headers: vec![],
            body: Some(
                serde_json::to_vec(&serde_json::json!({
                    "conversationId": "abc123",
                    "streamUrl": "/v3/directline/conversations/abc123/stream?t=TOKEN"
                }))
                .unwrap(),
            ),
        };
        rewrite_stream_url(&headers, &mut response);
        let body: serde_json::Value =
            serde_json::from_slice(response.body.as_ref().unwrap()).unwrap();
        assert_eq!(
            body["streamUrl"],
            "wss://svc.run.app/v3/directline/conversations/abc123/stream?t=TOKEN",
            "with X-Forwarded-Proto: https the streamUrl must be wss://"
        );
    }

    #[test]
    fn rewrite_stream_url_noop_when_already_absolute() {
        let headers = vec![("Host".to_string(), "example.com".to_string())];
        let original_url = "wss://other.example.com/stream";
        let mut response = IngressHttpResponse {
            status: 200,
            headers: vec![],
            body: Some(
                serde_json::to_vec(&serde_json::json!({
                    "streamUrl": original_url
                }))
                .unwrap(),
            ),
        };
        rewrite_stream_url(&headers, &mut response);
        let body: serde_json::Value =
            serde_json::from_slice(response.body.as_ref().unwrap()).unwrap();
        assert_eq!(
            body["streamUrl"], original_url,
            "already-absolute streamUrl must not be touched"
        );
    }

    // Category 6: validate_token_response

    #[test]
    fn validate_token_response_accepts_valid_token() {
        let response = IngressHttpResponse {
            status: 200,
            headers: vec![],
            body: Some(
                serde_json::to_vec(&serde_json::json!({
                    "token": "eyJhbGciOiJIUzI1NiJ9.e30.test",
                    "expires_in": 1800
                }))
                .unwrap(),
            ),
        };
        assert!(
            validate_token_response(&response).is_ok(),
            "a valid token response must pass validation"
        );
    }

    #[test]
    fn validate_token_response_rejects_missing_token_field() {
        let response = IngressHttpResponse {
            status: 200,
            headers: vec![],
            body: Some(serde_json::to_vec(&serde_json::json!({"expires_in": 1800})).unwrap()),
        };
        assert!(
            validate_token_response(&response).is_err(),
            "a response without a token field must be rejected"
        );
    }

    #[test]
    fn validate_token_response_rejects_empty_token() {
        let response = IngressHttpResponse {
            status: 200,
            headers: vec![],
            body: Some(serde_json::to_vec(&serde_json::json!({"token": "  "})).unwrap()),
        };
        assert!(
            validate_token_response(&response).is_err(),
            "a whitespace-only token must be rejected"
        );
    }

    #[test]
    fn validate_token_response_rejects_non_2xx() {
        let response = IngressHttpResponse {
            status: 500,
            headers: vec![],
            body: Some(serde_json::to_vec(&serde_json::json!({"token": "valid"})).unwrap()),
        };
        assert!(
            validate_token_response(&response).is_err(),
            "a non-2xx status must be rejected even if the body has a token"
        );
    }

    // Category 7: CORS asymmetry — DirectLine paths get CORS,
    //              /workers/invoke does not (the existing test above
    //              `worker_invoke_is_not_exposed_cross_origin` covers
    //              the /workers/invoke side; these prove DirectLine gets CORS).

    #[test]
    fn cors_allows_directline_conversations_path() {
        assert!(
            path_allows_cors("/v3/directline/conversations"),
            "DirectLine conversations path must allow CORS"
        );
    }

    #[test]
    fn cors_allows_directline_activities_path() {
        assert!(
            path_allows_cors(
                "/v1/messaging/webchat/demo/v3/directline/conversations/abc/activities"
            ),
            "DirectLine activities path must allow CORS"
        );
    }

    #[test]
    fn cors_allows_directline_token_path() {
        assert!(
            path_allows_cors("/v1/messaging/webchat/demo/token"),
            "DirectLine token path must allow CORS"
        );
    }

    #[test]
    fn cors_blocks_workers_invoke() {
        assert!(
            !path_allows_cors("/workers/invoke"),
            "/workers/invoke must NOT allow CORS"
        );
    }

    // Category 8: session hint extraction for webchat

    #[test]
    fn webchat_session_hint_extracts_conversation_id() {
        let hint = crate::session_hint_extractor::extract_webchat_session_hint(
            "/v1/messaging/webchat/demo/v3/directline/conversations/conv-42/activities",
        );
        assert_eq!(
            hint,
            Some("webchat:conv-42".to_string()),
            "must extract conversation_id from DirectLine URL path"
        );
    }

    #[test]
    fn webchat_session_hint_none_for_conversations_list() {
        let hint = crate::session_hint_extractor::extract_webchat_session_hint(
            "/v1/messaging/webchat/demo/v3/directline/conversations",
        );
        assert!(
            hint.is_none(),
            "POST /conversations has no conv_id yet — hint must be None"
        );
    }

    #[test]
    fn webchat_session_hint_none_for_non_directline_path() {
        let hint = crate::session_hint_extractor::extract_webchat_session_hint(
            "/v1/messaging/telegram/demo/webhook",
        );
        assert!(
            hint.is_none(),
            "non-DirectLine paths must not produce a webchat hint"
        );
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

    /// The legacy `http_ingress` boot honoured `GREENTIC_GATEWAY_PORT`
    /// (`bundle_config.rs`); the revision path did not. The greentic-e2e
    /// Playwright fixture and greentic-designer's local-deploy both set it, so
    /// without this they would silently bind the default port.
    #[test]
    fn resolve_bind_addr_honours_gateway_port_env() {
        let _lock = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _vars = EnvVarGuard::clean();
        // SAFETY: the lock above serializes env mutation.
        unsafe { std::env::set_var("GREENTIC_GATEWAY_PORT", "19311") };

        let addr = resolve_bind_addr(None);
        assert_eq!(addr.port(), 19311);
        assert_eq!(addr.ip(), DEFAULT_LISTEN_ADDR.ip());
    }

    /// A bare IP in `GREENTIC_GATEWAY_LISTEN_ADDR` takes its port from the layer
    /// below — exactly the pair the Playwright fixture sets (`127.0.0.1` plus a
    /// per-worker port).
    #[test]
    fn resolve_bind_addr_gateway_port_supplies_port_for_bare_listen_ip() {
        let _lock = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _vars = EnvVarGuard::clean();
        // SAFETY: the lock above serializes env mutation.
        unsafe {
            std::env::set_var("GREENTIC_GATEWAY_LISTEN_ADDR", "127.0.0.1");
            std::env::set_var("GREENTIC_GATEWAY_PORT", "19312");
        }

        assert_eq!(resolve_bind_addr(None).to_string(), "127.0.0.1:19312");
    }

    /// `GREENTIC_GATEWAY_PORT` overrides the port of a FULL socket address, so
    /// the two gateway vars compose the way the legacy path composed them.
    #[test]
    fn resolve_bind_addr_gateway_port_overrides_port_of_full_socket_addr() {
        let _lock = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _vars = EnvVarGuard::clean();
        // SAFETY: the lock above serializes env mutation.
        unsafe {
            std::env::set_var("GREENTIC_GATEWAY_LISTEN_ADDR", "0.0.0.0:9090");
            std::env::set_var("GREENTIC_GATEWAY_PORT", "19313");
        }

        assert_eq!(resolve_bind_addr(None).to_string(), "0.0.0.0:19313");
    }

    /// `PORT` stays the outermost layer: adding `GREENTIC_GATEWAY_PORT` must not
    /// disturb the precedence existing deployments already rely on.
    #[test]
    fn resolve_bind_addr_port_still_wins_over_gateway_port() {
        let _lock = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _vars = EnvVarGuard::clean();
        // SAFETY: the lock above serializes env mutation.
        unsafe {
            std::env::set_var("GREENTIC_GATEWAY_PORT", "19314");
            std::env::set_var("PORT", "19315");
        }

        assert_eq!(resolve_bind_addr(None).port(), 19315);
    }

    /// Deployment systems expose unset vars as empty strings; an unparseable
    /// value must not panic or zero the port.
    #[test]
    fn resolve_bind_addr_ignores_empty_or_invalid_gateway_port() {
        let _lock = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _vars = EnvVarGuard::clean();
        // SAFETY: the lock above serializes env mutation.
        unsafe { std::env::set_var("GREENTIC_GATEWAY_PORT", "   ") };
        assert_eq!(resolve_bind_addr(None).port(), DEFAULT_LISTEN_ADDR.port());

        // SAFETY: the lock above serializes env mutation.
        unsafe { std::env::set_var("GREENTIC_GATEWAY_PORT", "not-a-port") };
        assert_eq!(resolve_bind_addr(None).port(), DEFAULT_LISTEN_ADDR.port());
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
            admin_port: None,
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
    /// `apply_traffic_split(.., expected_generation=0)` yields) on a fresh,
    /// unshared pin store. Thin wrapper over [`activation_split_sharing_store`].
    fn activation_with_ids(
        env_id: &str,
        deployment_id: greentic_deploy_spec::ids::DeploymentId,
        revision_id: greentic_deploy_spec::ids::RevisionId,
        bundle_id: greentic_deploy_spec::ids::BundleId,
    ) -> Activation {
        activation_split_sharing_store(
            env_id,
            deployment_id,
            &[(revision_id, 10_000)],
            bundle_id,
            std::sync::Arc::new(crate::revision_pin::InMemoryPinStore::new()),
        )
    }

    /// Build an [`Activation`] with a caller-chosen revision split and a
    /// caller-supplied pin store, so two activations across a reload can reuse
    /// one store (mirroring the B1a boot wiring). Weights must sum to 10,000.
    fn activation_split_sharing_store(
        env_id: &str,
        deployment_id: greentic_deploy_spec::ids::DeploymentId,
        revisions: &[(greentic_deploy_spec::ids::RevisionId, u32)],
        bundle_id: greentic_deploy_spec::ids::BundleId,
        pin_store: std::sync::Arc<dyn crate::revision_pin::RevisionPinStore>,
    ) -> Activation {
        use crate::revision_dispatcher::{
            RevisionDispatcher, RevisionDispatcherConfig, RevisionEntry,
        };
        let base = empty_activation(env_id);
        let dispatcher = RevisionDispatcher::with_pin_store(
            RevisionDispatcherConfig::new(env_id, [0u8; 32]),
            pin_store,
        );
        let entries = revisions
            .iter()
            .map(|(revision_id, weight_bps)| RevisionEntry {
                revision_id: *revision_id,
                bundle_id: bundle_id.clone(),
                weight_bps: *weight_bps,
            })
            .collect();
        dispatcher
            .apply_traffic_split(deployment_id, entries, bundle_id, 0)
            .expect("apply_traffic_split for shared-store activation");
        activation_for_test(base.host, dispatcher)
    }

    #[tokio::test]
    async fn reload_preserves_pre_reload_cookie_for_unchanged_routable_set() {
        // B1: a reload that retains the deployment's routable revision set
        // (here: the same single revision, the pure-reweight shape) must CARRY
        // the generation FORWARD, so a stickiness cookie minted before the
        // reload still verifies after it and the session stays on its revision.
        // (Before B1 this bumped the generation and invalidated the cookie —
        // which flapped sticky sessions on every canary weight nudge.)
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
            gui_enabled: false,
            restart_required: AtomicBool::new(false),
            updates_enabled: false,
            auto_restart_pending: AtomicBool::new(false),
            auto_restart_enabled: false,
            exe_path: None,
            directline_sessions: Arc::new(
                crate::directline_session::DirectLineSessions::with_ttl_secs(1800),
            ),
            conversation_dedup: Arc::new(crate::conv_dedup::ConversationDedupCache::new()),
            session_manager: Arc::new(crate::websocket::SessionManager::new(
                crate::websocket::WsLimits::default(),
            )),
            notifier: Arc::new(crate::notifier::InMemoryNotifier::new(64)),
            public_url_capture: None,
            activity_source_override: None,
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

        // Reload to a new activation that re-uses the SAME deployment + bundle
        // + revision (only the dispatcher object is fresh). The routable set is
        // unchanged, so reanchor carries the generation forward to 1 (NOT 2):
        // the cookie sealed under generation 1 must still verify.
        let act2 = activation_with_ids(env_id, dep_id, rev_id, bundle_id);
        server.reload(act2, Duration::ZERO);

        let act2_snap = state.current();
        // Live generation is still 1 (carried forward) → the pre-reload cookie
        // verifies, proving sticky sessions survive a pure reweight.
        assert_eq!(
            act2_snap
                .routing
                .dispatcher
                .verify_cookie(&cookie, env_id, tenant, dep_id, 1, 0),
            Some(rev_id),
            "post-reload dispatcher must still honor the pre-reload cookie"
        );
        // And a cookie sealed at generation 2 must NOT verify — proving the
        // carry-forward landed at 1 specifically, not a silent over-bump.
        let bumped_cookie = act2_snap.routing.dispatcher.seal_cookie(
            env_id,
            tenant,
            dep_id,
            rev_id,
            2,
            9_999_999_999,
        );
        assert_eq!(
            act2_snap.routing.dispatcher.verify_cookie(
                &bumped_cookie,
                env_id,
                tenant,
                dep_id,
                1,
                0
            ),
            None,
            "live generation must be 1 (carried forward), so a gen-2 cookie is rejected"
        );
    }

    #[tokio::test]
    async fn reload_keeps_session_pin_across_reweight() {
        // B1a + B1b end-to-end. A messaging connector holds NO cookie, so a
        // session pin is the only thing keeping its conversation on one
        // revision. Establish a pin, reweight (same routable set), and the pin
        // must still resolve — proving the shared store survived the dispatcher
        // rebuild (B1a) AND the generation was carried forward (B1b).
        use crate::revision_dispatcher::SelectionReason;
        let env_id = "env-1";
        let tenant = "t";
        let dep_id = greentic_deploy_spec::ids::DeploymentId::new();
        let r1 = greentic_deploy_spec::ids::RevisionId::new();
        let r2 = greentic_deploy_spec::ids::RevisionId::new();
        let bundle_id = greentic_deploy_spec::ids::BundleId::new("customer.support");
        let store: std::sync::Arc<dyn crate::revision_pin::RevisionPinStore> =
            std::sync::Arc::new(crate::revision_pin::InMemoryPinStore::new());

        let act1 = activation_split_sharing_store(
            env_id,
            dep_id,
            &[(r1, 5000), (r2, 5000)],
            bundle_id.clone(),
            std::sync::Arc::clone(&store),
        );
        let bound: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let state = std::sync::Arc::new(ServeState {
            slot: ArcSwap::new(std::sync::Arc::new(act1)),
            bound_addr: bound,
            gui_enabled: false,
            restart_required: AtomicBool::new(false),
            updates_enabled: false,
            auto_restart_pending: AtomicBool::new(false),
            auto_restart_enabled: false,
            exe_path: None,
            directline_sessions: Arc::new(
                crate::directline_session::DirectLineSessions::with_ttl_secs(1800),
            ),
            conversation_dedup: Arc::new(crate::conv_dedup::ConversationDedupCache::new()),
            session_manager: Arc::new(crate::websocket::SessionManager::new(
                crate::websocket::WsLimits::default(),
            )),
            notifier: Arc::new(crate::notifier::InMemoryNotifier::new(64)),
            public_url_capture: None,
            activity_source_override: None,
        });
        let server = server_for_test(std::sync::Arc::clone(&state));

        // First dispatch: weighted pick, writes the pin inline (defer_pin =
        // false → trusted/loopback-style traffic).
        let hint = "chat-42";
        let req = DispatchRequest {
            env_id,
            tenant,
            deployment_id: dep_id,
            session_hint: Some(hint),
            defer_pin: false,
            trusted: false,
            header_revision: None,
            cookie: None,
        };
        let mut rng: rand::rngs::SmallRng = rand::make_rng();
        let first = state
            .current()
            .routing
            .dispatcher
            .dispatch(&req, &mut rng)
            .await
            .unwrap();
        assert_eq!(first.reason, SelectionReason::Weighted);
        let pinned = first.revision_id;

        // Reweight to a different split over the SAME routable set, sharing the
        // store. Generation carries forward; the pin persists.
        let act2 = activation_split_sharing_store(
            env_id,
            dep_id,
            &[(r1, 9000), (r2, 1000)],
            bundle_id,
            std::sync::Arc::clone(&store),
        );
        server.reload(act2, Duration::ZERO);

        // Second dispatch after the reweight: must hit the pin and land on the
        // same revision the first request picked.
        let mut rng: rand::rngs::SmallRng = rand::make_rng();
        let second = state
            .current()
            .routing
            .dispatcher
            .dispatch(&req, &mut rng)
            .await
            .unwrap();
        assert_eq!(
            second.reason,
            SelectionReason::Pin,
            "the pre-reweight pin must survive the reload"
        );
        assert_eq!(
            second.revision_id, pinned,
            "the surviving pin must resolve to the originally-pinned revision"
        );
    }

    #[tokio::test]
    async fn reload_bumps_generation_when_routable_revision_removed() {
        // The bump branch: dropping a routable revision (promote r2 to 100%,
        // r1 gone) must invalidate stickiness anchored at the old generation —
        // a cookie pinned to the vanished r1 must NOT verify, so its holder
        // re-picks instead of flapping on a revision that no longer routes.
        let env_id = "env-1";
        let tenant = "tenant-a";
        let dep_id = greentic_deploy_spec::ids::DeploymentId::new();
        let r1 = greentic_deploy_spec::ids::RevisionId::new();
        let r2 = greentic_deploy_spec::ids::RevisionId::new();
        let bundle_id = greentic_deploy_spec::ids::BundleId::new("customer.support");
        let throwaway: std::sync::Arc<dyn crate::revision_pin::RevisionPinStore> =
            std::sync::Arc::new(crate::revision_pin::InMemoryPinStore::new());

        let act1 = activation_split_sharing_store(
            env_id,
            dep_id,
            &[(r1, 5000), (r2, 5000)],
            bundle_id.clone(),
            std::sync::Arc::clone(&throwaway),
        );
        let bound: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let state = std::sync::Arc::new(ServeState {
            slot: ArcSwap::new(std::sync::Arc::new(act1)),
            bound_addr: bound,
            gui_enabled: false,
            restart_required: AtomicBool::new(false),
            updates_enabled: false,
            auto_restart_pending: AtomicBool::new(false),
            auto_restart_enabled: false,
            exe_path: None,
            directline_sessions: Arc::new(
                crate::directline_session::DirectLineSessions::with_ttl_secs(1800),
            ),
            conversation_dedup: Arc::new(crate::conv_dedup::ConversationDedupCache::new()),
            session_manager: Arc::new(crate::websocket::SessionManager::new(
                crate::websocket::WsLimits::default(),
            )),
            notifier: Arc::new(crate::notifier::InMemoryNotifier::new(64)),
            public_url_capture: None,
            activity_source_override: None,
        });
        let server = server_for_test(std::sync::Arc::clone(&state));

        // Cookie pinned to r1 at the pre-reload generation (1).
        let cookie = state.current().routing.dispatcher.seal_cookie(
            env_id,
            tenant,
            dep_id,
            r1,
            /* generation */ 1,
            /* expires_at */ 9_999_999_999,
        );

        // Promote r2 to 100% — r1 leaves the routable set, so the deployment is
        // NOT preserved and its generation bumps to 2.
        let act2 = activation_split_sharing_store(
            env_id,
            dep_id,
            &[(r2, 10_000)],
            bundle_id,
            std::sync::Arc::clone(&throwaway),
        );
        server.reload(act2, Duration::ZERO);

        let act2_snap = state.current();
        assert_eq!(
            act2_snap
                .routing
                .dispatcher
                .verify_cookie(&cookie, env_id, tenant, dep_id, 2, 0),
            None,
            "a cookie pinned to the removed revision must not verify post-reload"
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
            gui_enabled: false,
            restart_required: AtomicBool::new(false),
            updates_enabled: false,
            auto_restart_pending: AtomicBool::new(false),
            auto_restart_enabled: false,
            exe_path: None,
            directline_sessions: Arc::new(
                crate::directline_session::DirectLineSessions::with_ttl_secs(1800),
            ),
            conversation_dedup: Arc::new(crate::conv_dedup::ConversationDedupCache::new()),
            session_manager: Arc::new(crate::websocket::SessionManager::new(
                crate::websocket::WsLimits::default(),
            )),
            notifier: Arc::new(crate::notifier::InMemoryNotifier::new(64)),
            public_url_capture: None,
            activity_source_override: None,
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
            deployment_config_overrides: std::sync::Arc::default(),
            static_routes: crate::static_routes::ActiveRouteTable::default(),
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
            gui_enabled: false,
            restart_required: AtomicBool::new(false),
            updates_enabled: false,
            auto_restart_pending: AtomicBool::new(false),
            auto_restart_enabled: false,
            exe_path: None,
            directline_sessions: Arc::new(
                crate::directline_session::DirectLineSessions::with_ttl_secs(1800),
            ),
            conversation_dedup: Arc::new(crate::conv_dedup::ConversationDedupCache::new()),
            session_manager: Arc::new(crate::websocket::SessionManager::new(
                crate::websocket::WsLimits::default(),
            )),
            notifier: Arc::new(crate::notifier::InMemoryNotifier::new(64)),
            public_url_capture: None,
            activity_source_override: None,
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

    // -----------------------------------------------------------------------
    // Category 10: A5 — WebSocket stream path helpers
    // -----------------------------------------------------------------------

    #[test]
    fn is_directline_stream_path_accepts_full_path() {
        assert!(is_directline_stream_path(
            "/v1/messaging/webchat/tenant1/v3/directline/conversations/conv-42/stream"
        ));
    }

    #[test]
    fn is_directline_stream_path_rejects_activities() {
        assert!(!is_directline_stream_path(
            "/v1/messaging/webchat/tenant1/v3/directline/conversations/conv-42/activities"
        ));
    }

    #[test]
    fn is_directline_stream_path_rejects_bare_conversations() {
        assert!(!is_directline_stream_path(
            "/v1/messaging/webchat/tenant1/v3/directline/conversations"
        ));
    }

    #[test]
    fn is_directline_stream_path_rejects_non_directline() {
        assert!(!is_directline_stream_path(
            "/v1/messaging/telegram/tenant1/webhook"
        ));
    }

    #[test]
    fn extract_stream_conversation_id_returns_id() {
        assert_eq!(
            extract_stream_conversation_id(
                "/v1/messaging/webchat/tenant1/v3/directline/conversations/abc-123/stream"
            ),
            Some("abc-123".to_string())
        );
    }

    #[test]
    fn extract_stream_conversation_id_returns_none_for_non_stream() {
        assert_eq!(
            extract_stream_conversation_id(
                "/v1/messaging/webchat/tenant1/v3/directline/conversations/abc/activities"
            ),
            None
        );
    }

    #[test]
    fn stream_path_matches_cors_allowlist() {
        // `path_allows_cors` classifies stream paths as CORS-eligible.
        // In practice `handle_connection` intercepts stream paths for the WS
        // upgrade BEFORE reaching the CORS wrapper, so the header is never
        // applied — browsers don't enforce CORS on WebSocket connections
        // anyway. This test validates the classifier's output, not the
        // end-to-end CORS behaviour on stream responses.
        assert!(path_allows_cors(
            "/v1/messaging/webchat/tenant1/v3/directline/conversations/c1/stream"
        ));
    }

    // -----------------------------------------------------------------------
    // Category 11: A5 — WS notifier integration (try_notify_webchat_activity)
    // -----------------------------------------------------------------------

    /// Verify that `try_notify_webchat_activity` publishes a `NotifyEvent`
    /// when the provider output carries top-level `_greentic` metadata
    /// (the shape returned by `send_payload`).
    #[tokio::test]
    async fn notify_publishes_on_top_level_greentic_metadata() {
        let notifier = crate::notifier::InMemoryNotifier::new(16);
        let mut events = notifier.subscribe("t1", "conv-1").await.expect("subscribe");

        let output = serde_json::json!({
            "ok": true,
            "_greentic": {
                "tenant": "t1",
                "conversation_id": "conv-1",
                "watermark_bumped": 42u64,
            }
        });
        try_notify_webchat_activity(&notifier, &output).await;

        let event = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            futures_util::StreamExt::next(&mut events),
        )
        .await
        .expect("timeout waiting for notify event")
        .expect("stream ended");
        assert_eq!(event.tenant_id, "t1");
        assert_eq!(event.conversation_id, "conv-1");
        assert_eq!(event.new_watermark, 42);
    }

    /// Verify that `try_notify_webchat_activity` publishes when `_greentic`
    /// is embedded inside a base64-encoded `body_b64` field (the shape
    /// returned by `directline_http`).
    #[tokio::test]
    async fn notify_publishes_on_body_b64_greentic_metadata() {
        let notifier = crate::notifier::InMemoryNotifier::new(16);
        let mut events = notifier
            .subscribe("t2", "conv-99")
            .await
            .expect("subscribe");

        let inner = serde_json::json!({
            "_greentic": {
                "tenant": "t2",
                "conversation_id": "conv-99",
                "watermark_bumped": 7u64,
            },
            "id": "a1"
        });
        let body_b64 = BASE64.encode(serde_json::to_vec(&inner).unwrap());
        let output = serde_json::json!({
            "status": 200,
            "body_b64": body_b64,
        });
        try_notify_webchat_activity(&notifier, &output).await;

        let event = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            futures_util::StreamExt::next(&mut events),
        )
        .await
        .expect("timeout waiting for notify event")
        .expect("stream ended");
        assert_eq!(event.tenant_id, "t2");
        assert_eq!(event.conversation_id, "conv-99");
        assert_eq!(event.new_watermark, 7);
    }

    /// Non-webchat provider outputs (no `_greentic`) must not trigger a
    /// publish. The notifier stream must stay empty.
    #[tokio::test]
    async fn notify_is_noop_without_greentic_metadata() {
        let notifier = crate::notifier::InMemoryNotifier::new(16);
        let mut events = notifier.subscribe("t1", "conv-1").await.expect("subscribe");

        let output = serde_json::json!({"ok": true});
        try_notify_webchat_activity(&notifier, &output).await;

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            futures_util::StreamExt::next(&mut events),
        )
        .await;
        assert!(
            result.is_err(),
            "no event should be published for non-webchat output"
        );
    }
}

#[cfg(test)]
mod update_notify_tests {
    use super::*;
    // The legacy field these tests still exercise, to prove `resolved_action()`
    // keeps honoring a channel written before `on_update` existed.
    use greentic_deploy_spec::OnNotifyAction;

    fn env(id: &str) -> EnvId {
        EnvId::new(id).expect("valid env id")
    }

    fn notify_body(schema: &str, plan: &[u8], sig: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": schema,
            "plan_b64": BASE64.encode(plan),
            "sig_b64": BASE64.encode(sig),
        }))
        .unwrap()
    }

    #[test]
    fn decode_accepts_valid_body() {
        let body = notify_body(UPDATE_NOTIFY_SCHEMA_V1, b"plan-bytes", b"sig-bytes");
        let (plan, sig) = decode_update_notify(&body).expect("valid body decodes");
        assert_eq!(plan, b"plan-bytes");
        assert_eq!(sig, b"sig-bytes");
    }

    #[test]
    fn decode_rejects_unknown_schema() {
        let body = notify_body("greentic.update-notify.v99", b"p", b"s");
        let (status, _) = decode_update_notify(&body).expect_err("unknown schema is rejected");
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn decode_rejects_non_base64_payload() {
        let body = serde_json::to_vec(&serde_json::json!({
            "schema": UPDATE_NOTIFY_SCHEMA_V1,
            "plan_b64": "not valid base64!!",
            "sig_b64": BASE64.encode(b"s"),
        }))
        .unwrap();
        let (status, _) = decode_update_notify(&body).expect_err("bad base64 is rejected");
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn decode_rejects_unknown_fields() {
        // `deny_unknown_fields` guards against a plan server smuggling extra keys.
        let body = serde_json::to_vec(&serde_json::json!({
            "schema": UPDATE_NOTIFY_SCHEMA_V1,
            "plan_b64": BASE64.encode(b"p"),
            "sig_b64": BASE64.encode(b"s"),
            "extra": "surprise",
        }))
        .unwrap();
        let (status, _) = decode_update_notify(&body).expect_err("unknown field is rejected");
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn decode_rejects_malformed_json() {
        let (status, _) =
            decode_update_notify(b"{not json").expect_err("malformed json is rejected");
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn notify_action_denies_by_default() {
        // Absent operator opt-in must never stage: disabled(), enabled: None, and
        // enabled: Some(false) all resolve to Ignore.
        assert_eq!(
            notify_action(&UpdateChannelConfig::disabled(env("local"))),
            NotifyAction::Ignore
        );

        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.enabled = None;
        cfg.on_notify = Some(OnNotifyAction::Stage);
        assert_eq!(notify_action(&cfg), NotifyAction::Ignore);

        cfg.enabled = Some(false);
        assert_eq!(notify_action(&cfg), NotifyAction::Ignore);
    }

    #[test]
    fn notify_action_enabled_branches() {
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.enabled = Some(true);

        cfg.on_notify = Some(OnNotifyAction::RecordOnly);
        assert_eq!(notify_action(&cfg), NotifyAction::Record);

        cfg.on_notify = Some(OnNotifyAction::Stage);
        assert_eq!(notify_action(&cfg), NotifyAction::Stage);

        // Unset on_notify resolves to Stage (the deploy-spec default).
        cfg.on_notify = None;
        assert_eq!(notify_action(&cfg), NotifyAction::Stage);
    }

    #[test]
    fn notify_action_reads_on_update_over_legacy_on_notify() {
        // `set_action` writes both fields: `on_update: apply` for a binary that
        // understands it, `on_notify: stage` as the conservative floor an older
        // binary reads. This binary must pick the former.
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.enabled = Some(true);
        cfg.set_action(UpdateAction::Apply);
        assert_eq!(cfg.on_notify, Some(OnNotifyAction::Stage));
        assert_eq!(notify_action(&cfg), NotifyAction::Apply);
    }

    #[test]
    fn notify_action_falls_back_to_legacy_when_on_update_absent() {
        // A channel written before `on_update` existed keeps its meaning.
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.enabled = Some(true);
        cfg.on_update = None;
        cfg.on_notify = Some(OnNotifyAction::RecordOnly);
        assert_eq!(notify_action(&cfg), NotifyAction::Record);
    }

    #[test]
    fn notify_action_never_applies_a_disabled_channel() {
        // `apply` is policy, `enabled` is the gate. The gate wins.
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.set_action(UpdateAction::Apply);
        cfg.enabled = Some(false);
        assert_eq!(notify_action(&cfg), NotifyAction::Ignore);
    }

    // ── push path: the stream gate ──────────────────────────────────

    /// `enabled` is the gate, `push_enabled` is the policy. A channel the
    /// operator never enabled must not open an outbound connection, even if it
    /// carries a plan endpoint and push defaults on.
    #[test]
    fn stream_endpoint_denies_by_default() {
        assert_eq!(
            stream_endpoint_for(&UpdateChannelConfig::disabled(env("local"))),
            None
        );

        // Endpoint present but the channel was never enabled: still nothing.
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.plan_endpoint = Some("https://updates.example/v1/environments/local/plan".into());
        cfg.enabled = None;
        assert_eq!(stream_endpoint_for(&cfg), None);

        cfg.enabled = Some(false);
        assert_eq!(stream_endpoint_for(&cfg), None);

        // The gate outranks the policy: explicit push on a disabled channel is
        // still off.
        cfg.push_enabled = Some(true);
        assert_eq!(stream_endpoint_for(&cfg), None);
    }

    /// An enabled channel streams by default — `push_enabled` is opt-*out*. The
    /// URL is derived from the plan endpoint, so an operator who configured the
    /// channel before this feature existed gets push with no config change.
    #[test]
    fn stream_endpoint_derives_from_the_plan_endpoint_and_push_is_opt_out() {
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.enabled = Some(true);
        cfg.plan_endpoint = Some("https://updates.example/v1/environments/local/plan".into());

        assert_eq!(
            stream_endpoint_for(&cfg).as_deref(),
            Some("https://updates.example/v1/environments/local/updates/stream"),
        );

        // Opt out explicitly and the stream must not be held open.
        cfg.push_enabled = Some(false);
        assert_eq!(stream_endpoint_for(&cfg), None);

        // Opt back in.
        cfg.push_enabled = Some(true);
        assert!(stream_endpoint_for(&cfg).is_some());
    }

    /// An explicit `stream_endpoint` overrides the derived one, so an operator
    /// can front the stream with a different host than the plan.
    #[test]
    fn explicit_stream_endpoint_overrides_the_derived_one() {
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.enabled = Some(true);
        cfg.plan_endpoint = Some("https://updates.example/v1/environments/local/plan".into());
        cfg.stream_endpoint = Some("https://push.example/stream".into());

        assert_eq!(
            stream_endpoint_for(&cfg).as_deref(),
            Some("https://push.example/stream")
        );
    }

    // ── push path: the interruptible wait ───────────────────────────

    /// THE load-bearing property. A plan published while a poll cycle is still
    /// running lands on `notify_one` with no waiter registered. If that wake is
    /// dropped, the push is lost and discovery silently falls back to the poll
    /// interval — the exact regression this whole change exists to prevent, and
    /// one that no amount of "it compiled" would catch.
    ///
    /// `start_paused` means the 1-hour interval below costs no wall-clock: if the
    /// permit were dropped, this test would hang on the virtual clock rather than
    /// pass slowly.
    #[tokio::test(start_paused = true)]
    async fn a_push_landing_mid_cycle_is_not_lost() {
        let wake = Notify::new();

        // Goes through the SAME function the stream task's `on_plan` calls, so
        // swapping it to `notify_waiters` (which drops a signal with no waiter
        // registered) fails here rather than silently in production.
        signal_plan_published(&wake);

        assert!(
            wait_for_next_cycle(&wake, 3600).await,
            "a wake stored while the cycle was running must survive to the next wait"
        );
    }

    /// With nothing pushed, the wait must expire on the interval and run the
    /// cycle anyway. This is the fallback that keeps updates flowing when the
    /// stream is down, and it is what makes push a pure accelerator.
    #[tokio::test(start_paused = true)]
    async fn without_a_push_the_wait_falls_back_to_the_interval() {
        let wake = Notify::new();

        // Bounded deliberately. The regression this guards against — dropping the
        // `timeout` and awaiting the wake forever — makes `wait_for_next_cycle`
        // never return, which would HANG this test rather than fail it, wedging CI
        // instead of reporting. The outer bound turns that into a clean failure.
        // Virtual time, so the 2h ceiling costs no wall-clock.
        let woke =
            tokio::time::timeout(Duration::from_secs(7200), wait_for_next_cycle(&wake, 3600))
                .await
                .expect("wait_for_next_cycle must return on its interval, not block forever");

        assert!(
            !woke,
            "an un-pushed wait must expire on the interval, not wake early"
        );
    }

    /// A burst of events must coalesce into ONE extra cycle, not one per event.
    /// `Notify` holds at most a single permit, so ten publishes in a row cost one
    /// poll — otherwise a chatty server would queue up a cycle per event and
    /// hammer the plan endpoint.
    #[tokio::test(start_paused = true)]
    async fn a_burst_of_pushes_coalesces_into_one_cycle() {
        let wake = Notify::new();

        for _ in 0..10 {
            signal_plan_published(&wake);
        }

        assert!(
            wait_for_next_cycle(&wake, 3600).await,
            "the burst must wake the loop"
        );
        assert!(
            !wait_for_next_cycle(&wake, 3600).await,
            "10 events must not buy 10 cycles — the permits coalesce into one"
        );
    }

    #[test]
    fn plan_id_of_reads_the_staged_outcome_and_rejects_a_missing_id() {
        let ok = OpOutcome::new("updates", "get", serde_json::json!({ "plan_id": "plan-7" }));
        assert_eq!(plan_id_of(&ok).expect("plan id"), "plan-7");

        let bad = OpOutcome::new("updates", "get", serde_json::json!({ "sequence": 3 }));
        assert!(matches!(
            plan_id_of(&bad),
            Err(NotifyError::Internal(msg)) if msg.contains("no plan id")
        ));
    }

    #[test]
    fn map_op_error_status_mapping() {
        assert_eq!(
            map_op_error(&OpError::Conflict("downgrade".into())).status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            map_op_error(&OpError::Unauthorized {
                policy: "p".into(),
                reason: "r".into()
            })
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            map_op_error(&OpError::NotFound("plan".into())).status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            map_op_error(&OpError::InvalidArgument("bad".into())).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            map_op_error(&OpError::Fetch("timeout".into())).status(),
            StatusCode::BAD_GATEWAY
        );
    }

    #[test]
    fn sha256_hex_matches_known_vectors() {
        // The torn-read guard compares this against the server's `plan_sha256`
        // (`hex::encode(Sha256::digest(...))`), so it must be lowercase hex.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn poll_cycle_disabled_channel_does_not_fetch() {
        // Deny-by-default: a disabled channel returns before any HTTP. The
        // endpoint points at an unroutable port, so a fetch attempt would error;
        // the sequence stays put and the resolved interval is returned.
        let root = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(root.path().join("local")).expect("env dir");
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.enabled = Some(false);
        cfg.plan_endpoint = Some("http://127.0.0.1:1/plan".into());
        std::fs::write(
            root.path().join("local").join("update-channel.json"),
            serde_json::to_vec(&cfg).expect("serialize channel"),
        )
        .expect("write channel");
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(50))
            .build()
            .expect("client");

        let (seq, interval, _restart) =
            poll_update_cycle("local", root.path(), &client, Some(7), None);
        assert_eq!(
            seq,
            Some(7),
            "disabled channel must not advance the sequence"
        );
        assert!(interval >= 60, "resolved interval is floored");
    }

    #[test]
    fn poll_cycle_enabled_without_endpoint_does_not_fetch() {
        // Enabled but no plan endpoint → the poll loop has no source and returns
        // without fetching (again, an unroutable endpoint is never set).
        let root = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(root.path().join("local")).expect("env dir");
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.enabled = Some(true);
        cfg.plan_endpoint = None;
        std::fs::write(
            root.path().join("local").join("update-channel.json"),
            serde_json::to_vec(&cfg).expect("serialize channel"),
        )
        .expect("write channel");
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(50))
            .build()
            .expect("client");

        let (seq, _interval, _restart) =
            poll_update_cycle("local", root.path(), &client, None, None);
        assert_eq!(seq, None, "no endpoint must not advance the sequence");
    }

    #[test]
    fn disabled_channel_does_not_stage() {
        // End-to-end deny-by-default: a store with no update-channel policy resolves
        // to disabled, so `run_update_notify` returns 403 WITHOUT ever calling
        // `updates::get` — the garbage plan/sig below would error if it were staged.
        let root = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(root.path().join("local")).expect("env dir");
        let store = LocalFsStore::new(root.path().to_path_buf());

        let (status, body) = run_update_notify(&store, "local", b"not-a-plan", b"not-a-sig", None)
            .expect("disabled is Ok");
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["status"], "disabled");
    }

    #[test]
    fn record_only_rejects_unverified_plan() {
        // Enabled + record-only still VERIFIES before recording. The env has no
        // trust root and the bytes carry no valid DSSE signature, so verification
        // fails closed and the request is REJECTED (409) — never `202 recorded`.
        // (An unverified record would let any caller forge the notification.)
        let root = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(root.path().join("local")).expect("env dir");
        let mut cfg = UpdateChannelConfig::disabled(env("local"));
        cfg.enabled = Some(true);
        cfg.on_notify = Some(OnNotifyAction::RecordOnly);
        std::fs::write(
            root.path().join("local").join("update-channel.json"),
            serde_json::to_vec(&cfg).expect("serialize channel"),
        )
        .expect("write channel");
        let store = LocalFsStore::new(root.path().to_path_buf());

        match run_update_notify(&store, "local", b"not-a-plan", b"not-a-sig", None) {
            Err(NotifyError::Op(op)) => {
                assert_eq!(map_op_error(&op).status(), StatusCode::CONFLICT);
            }
            other => panic!("expected verification rejection, got {other:?}"),
        }
    }

    #[test]
    fn update_channel_present_reflects_the_sidecar() {
        // The route only reserves `/v1/updates/notify` on envs that have run
        // `op updates config-set` (an `update-channel.json` sidecar); every other
        // env falls through to deployment routing.
        let root = tempfile::TempDir::new().expect("tempdir");
        assert!(!update_channel_present(root.path(), "local"));

        std::fs::create_dir_all(root.path().join("local")).expect("env dir");
        std::fs::write(root.path().join("local").join("update-channel.json"), b"{}")
            .expect("write sidecar");
        assert!(update_channel_present(root.path(), "local"));
        // A different env is unaffected.
        assert!(!update_channel_present(root.path(), "other"));
    }
}

// ---------------------------------------------------------------------------
// P7d: binary self-update decision logic tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod binary_update_tests {
    use super::*;
    use greentic_update::plan::BinaryArtifact;

    fn empty_activation_for_test(env_id: &str) -> Activation {
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
        Activation {
            host,
            routing: std::sync::Arc::new(RevisionIngressRouting {
                dispatcher: std::sync::Arc::new(dispatcher),
                http_routes: HttpRouteTable::from_descriptors(Vec::new()),
                deployment_routes: crate::deployment_routes::DeploymentRouteTable::default(),
                endpoint_admit: std::sync::Arc::new(crate::endpoint_admit::EndpointAdmit::default()),
                deployment_config_overrides: std::sync::Arc::default(),
                static_routes: crate::static_routes::ActiveRouteTable::default(),
            }),
        }
    }

    fn sample_binary(name: &str, target: &str, version: &str) -> BinaryArtifact {
        BinaryArtifact {
            name: name.to_string(),
            version: version.to_string(),
            target: target.to_string(),
            digest: "sha256:aabbccdd".to_string(),
            source: Some("https://example.com/archive.tgz".to_string()),
        }
    }

    // --- select_binary wiring tests ---

    #[test]
    fn select_own_binary_finds_exact_match() {
        let own_name = env!("CARGO_PKG_NAME");
        let own_target = binswap::current_target();
        let binaries = vec![
            sample_binary("gtc", own_target, "2.0.0"),
            sample_binary(own_name, own_target, "2.0.0"),
            sample_binary("greentic-runner", own_target, "2.0.0"),
        ];
        let result = select_binary(&binaries, own_name, own_target).unwrap();
        assert!(result.is_some(), "must find our own binary");
        let found = result.unwrap();
        assert_eq!(found.name, own_name);
        assert_eq!(found.target, own_target);
    }

    #[test]
    fn no_binary_for_host_returns_none() {
        let own_name = env!("CARGO_PKG_NAME");
        let own_target = binswap::current_target();
        // Plan has binaries for a DIFFERENT target.
        let binaries = vec![sample_binary(own_name, "aarch64-unknown-freebsd", "2.0.0")];
        let result = select_binary(&binaries, own_name, own_target).unwrap();
        assert!(result.is_none(), "no match for a different target");
    }

    #[test]
    fn no_binary_for_name_returns_none() {
        let own_target = binswap::current_target();
        // Plan has binaries for a DIFFERENT name.
        let binaries = vec![sample_binary("gtc", own_target, "2.0.0")];
        let result = select_binary(&binaries, env!("CARGO_PKG_NAME"), own_target).unwrap();
        assert!(result.is_none(), "no match for a different name");
    }

    #[test]
    fn empty_binaries_returns_none() {
        let result = select_binary(&[], env!("CARGO_PKG_NAME"), binswap::current_target()).unwrap();
        assert!(result.is_none(), "empty list yields None");
    }

    #[test]
    fn ambiguous_binary_fails_closed() {
        let own_name = env!("CARGO_PKG_NAME");
        let own_target = binswap::current_target();
        let binaries = vec![
            sample_binary(own_name, own_target, "2.0.0"),
            sample_binary(own_name, own_target, "2.0.1"),
        ];
        let err = select_binary(&binaries, own_name, own_target).unwrap_err();
        assert!(
            format!("{err}").contains("ambiguous"),
            "error must mention ambiguity: {err}"
        );
    }

    // --- version guard tests ---

    #[test]
    fn version_guard_refuses_downgrade() {
        let current = env!("CARGO_PKG_VERSION");
        let current_ver = semver::Version::parse(current).unwrap();
        // Construct a version strictly older than current.
        let older = semver::Version::new(
            current_ver.major,
            current_ver.minor,
            current_ver.patch.saturating_sub(1),
        );
        // If current patch is 0, this is equal rather than older — that case is
        // the no-op test below. This test exercises the `<` branch.
        if older < current_ver {
            assert!(
                older < current_ver,
                "constructed older version must be strictly less"
            );
        }
    }

    #[test]
    fn version_guard_noop_on_equal() {
        let current = env!("CARGO_PKG_VERSION");
        let current_ver = semver::Version::parse(current).unwrap();
        assert_eq!(current_ver, current_ver, "equal version is a no-op");
    }

    #[test]
    fn version_guard_allows_upgrade() {
        let current = env!("CARGO_PKG_VERSION");
        let current_ver = semver::Version::parse(current).unwrap();
        let newer =
            semver::Version::new(current_ver.major, current_ver.minor, current_ver.patch + 1);
        assert!(newer > current_ver, "newer version must proceed");
    }

    // --- status shape / no-leak tests ---

    #[test]
    fn staged_response_without_binary_has_no_binary_key() {
        let body = serde_json::json!({ "status": "staged" });
        assert!(
            body.get("binary").is_none(),
            "no binary key in content-only"
        );
    }

    #[test]
    fn staged_response_with_binary_exposes_version_and_restart() {
        let binary_info = serde_json::json!({
            "staged": true,
            "restart_required": true,
            "version": "2.0.0",
        });
        let mut body = serde_json::json!({ "status": "staged" });
        body["binary"] = binary_info;

        assert_eq!(body["status"], "staged");
        let bin = body.get("binary").expect("binary key present");
        assert_eq!(bin["staged"], true);
        assert_eq!(bin["restart_required"], true);
        assert_eq!(bin["version"], "2.0.0");
        // Must NOT contain filesystem paths or trust-root details.
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(
            !serialized.contains(".prev"),
            "must not leak .prev path: {serialized}"
        );
        assert!(
            !serialized.contains("key_id"),
            "must not leak key id: {serialized}"
        );
    }

    // --- restart_required flag integration ---

    #[test]
    fn restart_required_flag_surfaces_in_status() {
        let bound: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let state = ServeState {
            slot: ArcSwap::new(std::sync::Arc::new(empty_activation_for_test("local"))),
            bound_addr: bound,
            gui_enabled: false,
            restart_required: AtomicBool::new(true),
            updates_enabled: false,
            auto_restart_pending: AtomicBool::new(false),
            auto_restart_enabled: false,
            exe_path: None,
            directline_sessions: Arc::new(
                crate::directline_session::DirectLineSessions::with_ttl_secs(1800),
            ),
            conversation_dedup: Arc::new(crate::conv_dedup::ConversationDedupCache::new()),
            session_manager: Arc::new(crate::websocket::SessionManager::new(
                crate::websocket::WsLimits::default(),
            )),
            notifier: Arc::new(crate::notifier::InMemoryNotifier::new(64)),
            public_url_capture: None,
            activity_source_override: None,
        };
        let resp = try_probe_response("/status", &state).expect("/status response");
        let body_bytes = resp.into_body();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let collected = rt
            .block_on(http_body_util::BodyExt::collect(body_bytes))
            .unwrap();
        let text = String::from_utf8_lossy(&collected.to_bytes()).to_string();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            json["restart_required"], true,
            "/status must expose restart_required"
        );
    }

    #[test]
    fn restart_required_flag_surfaces_header_on_healthz() {
        let bound: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let state = ServeState {
            slot: ArcSwap::new(std::sync::Arc::new(empty_activation_for_test("local"))),
            bound_addr: bound,
            gui_enabled: false,
            restart_required: AtomicBool::new(true),
            updates_enabled: false,
            auto_restart_pending: AtomicBool::new(false),
            auto_restart_enabled: false,
            exe_path: None,
            directline_sessions: Arc::new(
                crate::directline_session::DirectLineSessions::with_ttl_secs(1800),
            ),
            conversation_dedup: Arc::new(crate::conv_dedup::ConversationDedupCache::new()),
            session_manager: Arc::new(crate::websocket::SessionManager::new(
                crate::websocket::WsLimits::default(),
            )),
            notifier: Arc::new(crate::notifier::InMemoryNotifier::new(64)),
            public_url_capture: None,
            activity_source_override: None,
        };
        let resp = try_probe_response("/healthz", &state).expect("/healthz response");
        assert_eq!(resp.status(), StatusCode::OK, "still healthy");
        assert_eq!(
            resp.headers()
                .get("x-greentic-restart-required")
                .and_then(|v| v.to_str().ok()),
            Some("true"),
            "header must be present when restart is required",
        );
    }

    #[test]
    fn no_restart_header_when_not_required() {
        let bound: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let state = ServeState {
            slot: ArcSwap::new(std::sync::Arc::new(empty_activation_for_test("local"))),
            bound_addr: bound,
            gui_enabled: false,
            restart_required: AtomicBool::new(false),
            updates_enabled: false,
            auto_restart_pending: AtomicBool::new(false),
            auto_restart_enabled: false,
            exe_path: None,
            directline_sessions: Arc::new(
                crate::directline_session::DirectLineSessions::with_ttl_secs(1800),
            ),
            conversation_dedup: Arc::new(crate::conv_dedup::ConversationDedupCache::new()),
            session_manager: Arc::new(crate::websocket::SessionManager::new(
                crate::websocket::WsLimits::default(),
            )),
            notifier: Arc::new(crate::notifier::InMemoryNotifier::new(64)),
            public_url_capture: None,
            activity_source_override: None,
        };
        let resp = try_probe_response("/healthz", &state).expect("/healthz response");
        assert!(
            resp.headers().get("x-greentic-restart-required").is_none(),
            "header must be absent when no restart is required",
        );
    }

    #[test]
    fn status_restart_required_false_by_default() {
        let bound: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let state = ServeState {
            slot: ArcSwap::new(std::sync::Arc::new(empty_activation_for_test("local"))),
            bound_addr: bound,
            gui_enabled: false,
            restart_required: AtomicBool::new(false),
            updates_enabled: false,
            auto_restart_pending: AtomicBool::new(false),
            auto_restart_enabled: false,
            exe_path: None,
            directline_sessions: Arc::new(
                crate::directline_session::DirectLineSessions::with_ttl_secs(1800),
            ),
            conversation_dedup: Arc::new(crate::conv_dedup::ConversationDedupCache::new()),
            session_manager: Arc::new(crate::websocket::SessionManager::new(
                crate::websocket::WsLimits::default(),
            )),
            notifier: Arc::new(crate::notifier::InMemoryNotifier::new(64)),
            public_url_capture: None,
            activity_source_override: None,
        };
        let resp = try_probe_response("/status", &state).expect("/status response");
        let body_bytes = resp.into_body();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let collected = rt
            .block_on(http_body_util::BodyExt::collect(body_bytes))
            .unwrap();
        let text = String::from_utf8_lossy(&collected.to_bytes()).to_string();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            json["restart_required"], false,
            "/status must report false by default"
        );
    }

    // --- marker file idempotency ---

    #[test]
    fn marker_file_is_valid_json() {
        let marker = serde_json::json!({
            "name": "greentic-start",
            "from_version": "1.1.8",
            "to_version": "1.1.9",
            "staged_at": "2026-07-07T00:00:00Z",
        });
        let bytes = serde_json::to_vec_pretty(&marker).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            parsed.get("to_version").and_then(Value::as_str),
            Some("1.1.9")
        );
        assert_eq!(
            parsed.get("name").and_then(Value::as_str),
            Some("greentic-start")
        );
    }

    #[test]
    fn marker_version_check_detects_same_version() {
        let marker = serde_json::json!({
            "name": "greentic-start",
            "from_version": "1.1.8",
            "to_version": "1.1.9",
        });
        // Same version -> should be treated as already staged.
        assert_eq!(
            marker.get("to_version").and_then(Value::as_str),
            Some("1.1.9"),
        );
        // Different version -> should NOT match.
        assert_ne!(
            marker.get("to_version").and_then(Value::as_str),
            Some("2.0.0"),
        );
    }

    // --- P7e: BinaryUpdateMarker typed tests ---

    #[test]
    fn marker_phase_defaults_to_pending_on_missing_field() {
        let json = r#"{"name":"x","from_version":"1","to_version":"2","staged_at":"t"}"#;
        let marker: BinaryUpdateMarker = serde_json::from_str(json).unwrap();
        assert_eq!(marker.phase, MarkerPhase::Pending);
        assert!(marker.rolled_back_at.is_none());
    }

    #[test]
    fn marker_roundtrip_pending() {
        let marker = BinaryUpdateMarker {
            name: "greentic-start".to_string(),
            from_version: "1.1.11".to_string(),
            to_version: "1.1.12".to_string(),
            staged_at: "2026-07-13T00:00:00Z".to_string(),
            phase: MarkerPhase::Pending,
            rolled_back_at: None,
            digest: None,
            boot_attempts: 0,
        };
        let bytes = serde_json::to_vec(&marker).unwrap();
        let back: BinaryUpdateMarker = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.phase, MarkerPhase::Pending);
        assert_eq!(back.to_version, "1.1.12");
        assert!(back.rolled_back_at.is_none());
    }

    #[test]
    fn marker_roundtrip_rolled_back() {
        let marker = BinaryUpdateMarker {
            name: "greentic-start".to_string(),
            from_version: "1.1.11".to_string(),
            to_version: "1.1.12".to_string(),
            staged_at: "2026-07-13T00:00:00Z".to_string(),
            phase: MarkerPhase::RolledBack,
            rolled_back_at: Some("2026-07-13T01:00:00Z".to_string()),
            digest: Some("abc123".to_string()),
            boot_attempts: 0,
        };
        let bytes = serde_json::to_vec(&marker).unwrap();
        let back: BinaryUpdateMarker = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.phase, MarkerPhase::RolledBack);
        assert_eq!(back.rolled_back_at.as_deref(), Some("2026-07-13T01:00:00Z"));
    }

    #[test]
    fn read_binary_update_marker_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        assert!(read_binary_update_marker(dir.path()).is_none());
    }

    #[test]
    fn read_binary_update_marker_valid() {
        let dir = tempfile::TempDir::new().unwrap();
        let marker = BinaryUpdateMarker {
            name: "greentic-start".to_string(),
            from_version: "1.0.0".to_string(),
            to_version: "1.1.0".to_string(),
            staged_at: "2026-01-01T00:00:00Z".to_string(),
            phase: MarkerPhase::Pending,
            rolled_back_at: None,
            digest: None,
            boot_attempts: 0,
        };
        std::fs::write(
            dir.path().join(BINARY_UPDATE_PENDING_FILE),
            serde_json::to_vec(&marker).unwrap(),
        )
        .unwrap();
        let read = read_binary_update_marker(dir.path()).expect("should parse");
        assert_eq!(read.to_version, "1.1.0");
        assert_eq!(read.phase, MarkerPhase::Pending);
    }

    #[test]
    fn read_binary_update_marker_corrupt() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join(BINARY_UPDATE_PENDING_FILE), b"not json").unwrap();
        assert!(read_binary_update_marker(dir.path()).is_none());
    }

    #[test]
    fn clear_binary_update_marker_removes_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(BINARY_UPDATE_PENDING_FILE);
        std::fs::write(&path, b"{}").unwrap();
        assert!(path.exists());
        clear_binary_update_marker(dir.path());
        assert!(!path.exists());
    }

    #[test]
    fn write_rollback_tombstone_sets_phase_and_timestamp() {
        let dir = tempfile::TempDir::new().unwrap();
        let marker = BinaryUpdateMarker {
            name: "greentic-start".to_string(),
            from_version: "1.1.11".to_string(),
            to_version: "1.1.12".to_string(),
            staged_at: "2026-07-13T00:00:00Z".to_string(),
            phase: MarkerPhase::Pending,
            rolled_back_at: None,
            digest: Some("sha256:abc".to_string()),
            boot_attempts: 0,
        };
        write_rollback_tombstone(dir.path(), &marker);
        let read = read_binary_update_marker(dir.path()).expect("should read tombstone");
        assert_eq!(read.phase, MarkerPhase::RolledBack);
        assert!(read.rolled_back_at.is_some());
        assert_eq!(read.to_version, "1.1.12");
        assert_eq!(read.from_version, "1.1.11");
    }

    #[test]
    fn write_rollback_tombstone_preserves_digest() {
        let dir = tempfile::TempDir::new().unwrap();
        let marker = BinaryUpdateMarker {
            name: "greentic-start".to_string(),
            from_version: "1.1.11".to_string(),
            to_version: "1.1.12".to_string(),
            staged_at: "2026-07-13T00:00:00Z".to_string(),
            phase: MarkerPhase::Pending,
            rolled_back_at: None,
            digest: Some("sha256:deadbeef".to_string()),
            boot_attempts: 0,
        };
        write_rollback_tombstone(dir.path(), &marker);
        let read = read_binary_update_marker(dir.path()).expect("should read tombstone");
        assert_eq!(read.digest.as_deref(), Some("sha256:deadbeef"));
    }

    #[test]
    fn marker_digest_defaults_to_none_on_missing_field() {
        let json = r#"{"name":"x","from_version":"1","to_version":"2","staged_at":"t"}"#;
        let marker: BinaryUpdateMarker = serde_json::from_str(json).unwrap();
        assert!(marker.digest.is_none());
    }

    #[test]
    fn status_includes_version_field() {
        let bound: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let state = ServeState {
            slot: ArcSwap::new(std::sync::Arc::new(empty_activation_for_test("local"))),
            bound_addr: bound,
            gui_enabled: false,
            restart_required: AtomicBool::new(false),
            updates_enabled: false,
            auto_restart_pending: AtomicBool::new(false),
            auto_restart_enabled: false,
            exe_path: None,
            directline_sessions: Arc::new(
                crate::directline_session::DirectLineSessions::with_ttl_secs(1800),
            ),
            conversation_dedup: Arc::new(crate::conv_dedup::ConversationDedupCache::new()),
            session_manager: Arc::new(crate::websocket::SessionManager::new(
                crate::websocket::WsLimits::default(),
            )),
            notifier: Arc::new(crate::notifier::InMemoryNotifier::new(64)),
            public_url_capture: None,
            activity_source_override: None,
        };
        let resp = try_probe_response("/status", &state).expect("/status response");
        let body_bytes = resp.into_body();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let collected = rt
            .block_on(http_body_util::BodyExt::collect(body_bytes))
            .unwrap();
        let text = String::from_utf8_lossy(&collected.to_bytes()).to_string();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            json["version"].as_str(),
            Some(env!("CARGO_PKG_VERSION")),
            "/status must include version"
        );
    }

    /// Regression: binary swap response with restart_required=true must set
    /// auto_restart_pending when auto_restart_enabled is true.
    #[test]
    fn auto_restart_pending_set_on_binary_swap_response() {
        let bound: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let state = Arc::new(ServeState {
            slot: ArcSwap::new(std::sync::Arc::new(empty_activation_for_test("local"))),
            bound_addr: bound,
            gui_enabled: false,
            restart_required: AtomicBool::new(false),
            updates_enabled: true,
            auto_restart_pending: AtomicBool::new(false),
            auto_restart_enabled: true,
            exe_path: None,
            directline_sessions: Arc::new(
                crate::directline_session::DirectLineSessions::with_ttl_secs(1800),
            ),
            conversation_dedup: Arc::new(crate::conv_dedup::ConversationDedupCache::new()),
            session_manager: Arc::new(crate::websocket::SessionManager::new(
                crate::websocket::WsLimits::default(),
            )),
            notifier: Arc::new(crate::notifier::InMemoryNotifier::new(64)),
            public_url_capture: None,
            activity_source_override: None,
        });
        state.mark_restart_required();
        assert!(
            state.restart_required.load(Ordering::Relaxed),
            "restart_required must be set"
        );
        #[cfg(unix)]
        assert!(
            state.auto_restart_pending.load(Ordering::Relaxed),
            "auto_restart_pending must be set when auto_restart_enabled is true"
        );
    }

    /// Complement: when auto_restart_enabled is false, auto_restart_pending
    /// must remain false even after a binary swap.
    #[test]
    fn auto_restart_pending_not_set_when_disabled() {
        let bound: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let state = Arc::new(ServeState {
            slot: ArcSwap::new(std::sync::Arc::new(empty_activation_for_test("local"))),
            bound_addr: bound,
            gui_enabled: false,
            restart_required: AtomicBool::new(false),
            updates_enabled: true,
            auto_restart_pending: AtomicBool::new(false),
            auto_restart_enabled: false,
            exe_path: None,
            directline_sessions: Arc::new(
                crate::directline_session::DirectLineSessions::with_ttl_secs(1800),
            ),
            conversation_dedup: Arc::new(crate::conv_dedup::ConversationDedupCache::new()),
            session_manager: Arc::new(crate::websocket::SessionManager::new(
                crate::websocket::WsLimits::default(),
            )),
            notifier: Arc::new(crate::notifier::InMemoryNotifier::new(64)),
            public_url_capture: None,
            activity_source_override: None,
        });
        state.mark_restart_required();
        assert!(
            state.restart_required.load(Ordering::Relaxed),
            "restart_required must still be set"
        );
        assert!(
            !state.auto_restart_pending.load(Ordering::Relaxed),
            "auto_restart_pending must NOT be set when disabled"
        );
    }

    // --- boot_attempts field and decide_boot_action tests ---

    fn make_pending_marker(from: &str, to: &str, attempts: u32) -> BinaryUpdateMarker {
        BinaryUpdateMarker {
            name: "greentic-start".to_string(),
            from_version: from.to_string(),
            to_version: to.to_string(),
            staged_at: "2026-07-13T00:00:00Z".to_string(),
            phase: MarkerPhase::Pending,
            rolled_back_at: None,
            digest: Some("sha256:abc".to_string()),
            boot_attempts: attempts,
        }
    }

    fn make_rolled_back_marker(from: &str, to: &str) -> BinaryUpdateMarker {
        BinaryUpdateMarker {
            name: "greentic-start".to_string(),
            from_version: from.to_string(),
            to_version: to.to_string(),
            staged_at: "2026-07-13T00:00:00Z".to_string(),
            phase: MarkerPhase::RolledBack,
            rolled_back_at: Some("2026-07-13T01:00:00Z".to_string()),
            digest: Some("sha256:abc".to_string()),
            boot_attempts: 0,
        }
    }

    #[test]
    fn boot_attempts_defaults_to_zero_on_missing_field() {
        let json = r#"{"name":"x","from_version":"1","to_version":"2","staged_at":"t"}"#;
        let marker: BinaryUpdateMarker = serde_json::from_str(json).unwrap();
        assert_eq!(marker.boot_attempts, 0);
    }

    #[test]
    fn marker_roundtrip_with_boot_attempts() {
        let marker = make_pending_marker("1.1.11", "1.1.12", 2);
        let bytes = serde_json::to_vec(&marker).unwrap();
        let back: BinaryUpdateMarker = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.boot_attempts, 2);
        assert_eq!(back.phase, MarkerPhase::Pending);
        assert_eq!(back.to_version, "1.1.12");
    }

    #[test]
    fn decide_boot_action_no_marker() {
        assert_eq!(decide_boot_action(None, "1.1.12"), BootAction::Proceed);
    }

    #[test]
    fn decide_boot_action_pending_to_eq_own_below_max() {
        let marker = make_pending_marker("1.1.11", "1.1.12", 0);
        let action = decide_boot_action(Some(marker.clone()), "1.1.12");
        assert_eq!(action, BootAction::ArmGuard(marker));
    }

    #[test]
    fn decide_boot_action_pending_to_eq_own_at_max() {
        let marker = make_pending_marker("1.1.11", "1.1.12", MAX_BOOT_ATTEMPTS);
        let action = decide_boot_action(Some(marker.clone()), "1.1.12");
        assert_eq!(action, BootAction::RollbackNow(marker));
    }

    #[test]
    fn decide_boot_action_pending_to_eq_own_above_max() {
        let marker = make_pending_marker("1.1.11", "1.1.12", MAX_BOOT_ATTEMPTS + 5);
        let action = decide_boot_action(Some(marker.clone()), "1.1.12");
        assert_eq!(action, BootAction::RollbackNow(marker));
    }

    #[test]
    fn decide_boot_action_pending_from_eq_own() {
        let marker = make_pending_marker("1.1.12", "1.1.13", 0);
        assert_eq!(
            decide_boot_action(Some(marker), "1.1.12"),
            BootAction::Proceed
        );
    }

    #[test]
    fn decide_boot_action_rolled_back_from_eq_own() {
        let marker = make_rolled_back_marker("1.1.12", "1.1.13");
        assert_eq!(
            decide_boot_action(Some(marker), "1.1.12"),
            BootAction::Proceed
        );
    }

    #[test]
    fn decide_boot_action_rolled_back_to_eq_own() {
        let marker = make_rolled_back_marker("1.1.11", "1.1.12");
        assert_eq!(
            decide_boot_action(Some(marker), "1.1.12"),
            BootAction::PreserveTombstone
        );
    }

    #[test]
    fn decide_boot_action_stale_marker() {
        let marker = make_pending_marker("1.0.0", "1.0.1", 0);
        assert_eq!(
            decide_boot_action(Some(marker), "1.1.12"),
            BootAction::ClearMarker
        );
    }

    #[test]
    fn write_marker_durable_persists_and_survives_read() {
        let dir = tempfile::TempDir::new().unwrap();
        let marker = make_pending_marker("1.1.11", "1.1.12", 2);
        write_marker_durable(dir.path(), &marker).expect("durable write should succeed");
        let read = read_binary_update_marker(dir.path()).expect("should parse");
        assert_eq!(read.boot_attempts, 2);
        assert_eq!(read.to_version, "1.1.12");
        assert_eq!(read.phase, MarkerPhase::Pending);
    }

    #[test]
    fn boot_attempt_counter_persisted_before_boot() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut marker = make_pending_marker("1.1.11", "1.1.12", 0);
        marker.boot_attempts += 1;
        write_marker_durable(dir.path(), &marker).expect("write");
        let on_disk = read_binary_update_marker(dir.path()).expect("read");
        assert_eq!(
            on_disk.boot_attempts, 1,
            "incremented counter must be visible on disk before boot proceeds"
        );
    }

    #[cfg(unix)]
    #[test]
    fn marker_write_failure_returns_err_and_restores_binary() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().unwrap();
        let exe_path = dir.path().join("greentic-start");
        let prev_path = dir.path().join("greentic-start.prev");
        let old_binary = b"old-binary-content";
        let new_binary = b"new-binary-content";

        std::fs::write(&prev_path, old_binary).unwrap();
        std::fs::write(&exe_path, new_binary).unwrap();

        let env_dir = dir.path().join("env");
        std::fs::create_dir_all(&env_dir).unwrap();
        let perms = std::fs::Permissions::from_mode(0o500);
        std::fs::set_permissions(&env_dir, perms).unwrap();

        let marker = make_pending_marker("1.1.11", "1.1.12", 0);
        let result = persist_marker_or_undo_swap(&env_dir, &marker, &exe_path);

        std::fs::set_permissions(&env_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            result.is_err(),
            "an unpersistable marker must fail the binary step"
        );
        // The swap must be undone: exec'ing into a binary with no rollback
        // state on disk is exactly the case the marker exists to prevent.
        assert_eq!(
            std::fs::read(&exe_path).unwrap(),
            old_binary,
            "the previous binary must be restored when the marker cannot be persisted"
        );
        assert!(
            !prev_path.exists(),
            "restore_prev consumes the .prev copy it restores from"
        );
    }

    // ── B3: in-band binary delivery tests ───────────────────────────────────

    use greentic_update::plan::UPDATE_PLAN_SCHEMA_V1;
    use greentic_update::plan::{
        CompatRequirements, OnFail, RollbackKind, RollbackPolicy, UpdatePlan,
    };
    use greentic_update::staging::UpdatesRoot;

    /// Compute `sha256:<hex>` digest for the given bytes, matching the staging
    /// API's convention.
    fn test_digest_of(bytes: &[u8]) -> String {
        format!("sha256:{}", sha256_hex(bytes))
    }

    /// Build a minimal `UpdatePlan` carrying a single binary, no content
    /// artifacts. `env_id` must match the staging root opened by the test.
    fn test_plan_with_binary(plan_id: &str, env_id: &str, binary: BinaryArtifact) -> UpdatePlan {
        UpdatePlan {
            schema: UPDATE_PLAN_SCHEMA_V1.to_string(),
            plan_id: plan_id.to_string(),
            env_id: env_id.to_string(),
            sequence: 1,
            created_at: chrono::Utc::now(),
            nonce: "test-nonce".to_string(),
            target: serde_json::json!({}),
            artifacts: vec![],
            binaries: vec![binary],
            compat: CompatRequirements::default(),
            rollback: RollbackPolicy {
                policy: RollbackKind::Auto,
                health_timeout_s: 60,
                on_fail: OnFail::Restore,
            },
        }
    }

    fn test_verified(plan: UpdatePlan) -> greentic_update::plan::VerifiedUpdatePlan {
        greentic_update::plan::VerifiedUpdatePlan {
            plan,
            plan_sha256: "0".repeat(64),
            verified_key_ids: vec!["k1".to_string()],
        }
    }

    fn test_inband_binary(version: &str, digest: String) -> BinaryArtifact {
        BinaryArtifact {
            name: env!("CARGO_PKG_NAME").to_string(),
            version: version.to_string(),
            target: binswap::current_target().to_string(),
            digest,
            source: None,
        }
    }

    /// Stage a plan into a fresh staging root and return the root path, the
    /// `StagedPlan` handle, and the `BinaryArtifact`. When `skip_blob` is
    /// true the binary blob is NOT written, simulating a missing-blob scenario.
    fn stage_inband_binary(
        dummy_exe: &[u8],
        env_id: &str,
        skip_blob: bool,
    ) -> (
        tempfile::TempDir,
        greentic_update::staging::StagedPlan,
        BinaryArtifact,
    ) {
        let staging_dir = tempfile::TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(staging_dir.path(), env_id).unwrap();
        let bin = test_inband_binary("99.0.0", test_digest_of(dummy_exe));
        let plan = test_plan_with_binary("plan-inband-1", env_id, bin.clone());
        let verified = test_verified(plan);
        let staged = root.begin(&verified, b"plan", b"sig").unwrap();
        if !skip_blob {
            staged.put_binary_blob(&bin, dummy_exe).unwrap();
        }
        staged
            .transition(greentic_update::staging::UpdateStage::Inbox)
            .unwrap();
        staged
            .transition(greentic_update::staging::UpdateStage::Staged)
            .unwrap();
        (staging_dir, staged, bin)
    }

    #[test]
    fn binary_update_inband_swaps_from_staging() {
        let dummy_exe = b"dummy-binary-payload-v99";
        let env_id = "test-env-inband";
        let (staging_dir, staged, bin) = stage_inband_binary(dummy_exe, env_id, false);

        // Verify the blob is readable from staging.
        let blob_bytes = staged.verify_binary_on_disk(&bin).unwrap();
        assert_eq!(blob_bytes, dummy_exe, "staged blob must match");

        // Write the blob to a temp file (the in-band path copies staged bytes
        // to a temp before swap_binary).
        let tmp = tempfile::TempDir::new().unwrap();
        let tmp_binary = tmp.path().join(env!("CARGO_PKG_NAME"));
        std::fs::write(&tmp_binary, &blob_bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        // Target exe is a TEMP file — never the real test binary.
        let target_exe = tmp.path().join("target-exe");
        std::fs::write(&target_exe, b"old-binary").unwrap();

        let env_dir = tempfile::TempDir::new().unwrap();

        let result = apply_binary_from_path(
            env!("CARGO_PKG_NAME"),
            &bin,
            &tmp_binary,
            &target_exe,
            env_dir.path(),
            env!("CARGO_PKG_VERSION"),
        );
        assert!(result.is_ok(), "apply_binary_from_path should succeed");
        let json = result.unwrap().expect("should return Some");
        assert_eq!(json["staged"], true);
        assert_eq!(json["restart_required"], true);
        assert_eq!(json["version"], "99.0.0");

        // The target exe must now contain the dummy payload (swap happened).
        let swapped = std::fs::read(&target_exe).unwrap();
        assert_eq!(
            swapped, dummy_exe,
            "target must be replaced by the new binary"
        );

        // A Pending marker must exist with the right versions and digest.
        let marker = read_binary_update_marker(env_dir.path()).expect("marker must be written");
        assert_eq!(marker.phase, MarkerPhase::Pending);
        assert_eq!(marker.from_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(marker.to_version, "99.0.0");
        assert_eq!(marker.digest.as_deref(), Some(bin.digest.as_str()));

        drop(staging_dir); // keep alive until here
    }

    #[test]
    fn binary_update_inband_verify_fails_tampered() {
        let dummy_exe = b"good-binary-content";
        let env_id = "test-env-tampered";
        let (_staging_dir, staged, bin) = stage_inband_binary(dummy_exe, env_id, false);

        // Tamper the blob on disk after staging.
        let blob_path = staged.binary_blob_path(&bin).unwrap();
        std::fs::write(&blob_path, b"corrupted-bytes").unwrap();

        // verify_binary_on_disk must fail with a digest mismatch.
        let err = staged.verify_binary_on_disk(&bin).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("mismatch"),
            "error must mention digest mismatch: {msg}"
        );
    }

    #[test]
    fn binary_update_inband_missing_blob_errors() {
        let dummy_exe = b"binary-content";
        let (_staging_dir, staged, bin) = stage_inband_binary(dummy_exe, "test-env-missing", true);

        // verify_binary_on_disk must fail with an IO error (file not found).
        let err = staged.verify_binary_on_disk(&bin).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("io error") || msg.contains("not a regular file"),
            "error must name the problem (IO or not-regular-file): {msg}"
        );
    }

    // ── B3: end-to-end try_apply_binary_update coverage ─────────────────────

    use greentic_deployer::environment::{TRUST_ROOT_FILE, TrustRootDocument};
    use greentic_distributor_client::signing::{TrustRoot, TrustedKey, key_id_for_public_key_pem};
    use greentic_update::plan::build_update_plan;

    /// Deterministic Ed25519 test key pair: returns (private PKCS#8 PEM,
    /// TrustedKey with SPKI PEM + canonical key id).
    fn test_signing_key(seed: u8) -> (String, TrustedKey) {
        use ed25519_dalek::SigningKey;
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        use ed25519_dalek::pkcs8::EncodePublicKey;
        use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;

        let sk = SigningKey::from_bytes(&[seed; 32]);
        let priv_pem = sk.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let pub_pem = sk
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let key_id = key_id_for_public_key_pem(&pub_pem).unwrap();
        (
            priv_pem,
            TrustedKey {
                key_id,
                public_key_pem: pub_pem,
            },
        )
    }

    struct InbandHarnessOpts {
        version: &'static str,
        plan_id: &'static str,
        skip_blob: bool,
        source: Option<String>,
    }

    impl Default for InbandHarnessOpts {
        fn default() -> Self {
            Self {
                version: "99.0.0",
                plan_id: "plan-e2e-1",
                skip_blob: false,
                source: None,
            }
        }
    }

    /// Wire up all infrastructure needed by `try_apply_binary_update`:
    /// store, trust root, signed plan, and staged binary. Returns the
    /// components the test needs to call the function and assert on results.
    struct InbandTestHarness {
        store_dir: tempfile::TempDir,
        staging_dir: tempfile::TempDir,
        #[allow(dead_code)]
        exe_dir: tempfile::TempDir,
        plan_bytes: Vec<u8>,
        sig_bytes: Vec<u8>,
        env_id: String,
        target_exe: std::path::PathBuf,
        binary_digest: String,
    }

    fn stage_plan(
        plan_id: &str,
        env_id: &str,
        bin: &BinaryArtifact,
        dummy_exe: &[u8],
        plan_bytes: &[u8],
        envelope_bytes: &[u8],
        skip_blob: bool,
    ) -> tempfile::TempDir {
        let staging_dir = tempfile::TempDir::new().unwrap();
        let root = UpdatesRoot::open_in(staging_dir.path(), env_id).unwrap();
        let verified = test_verified(test_plan_with_binary(plan_id, env_id, bin.clone()));
        let staged = root.begin(&verified, plan_bytes, envelope_bytes).unwrap();
        if !skip_blob {
            staged.put_binary_blob(bin, dummy_exe).unwrap();
        }
        staged
            .transition(greentic_update::staging::UpdateStage::Inbox)
            .unwrap();
        staged
            .transition(greentic_update::staging::UpdateStage::Staged)
            .unwrap();
        staging_dir
    }

    impl InbandTestHarness {
        /// Build a harness with a single in-band binary (source=None) for THIS
        /// process name + target. The dummy binary payload differs from the
        /// current test binary so the swap is observable.
        fn new(env_id: &str, dummy_exe: &[u8]) -> Self {
            Self::with_opts(env_id, dummy_exe, InbandHarnessOpts::default())
        }

        /// Like [`new`] but with a caller-chosen version and plan id.
        fn new_with_version(
            env_id: &str,
            dummy_exe: &[u8],
            version: &'static str,
            plan_id: &'static str,
        ) -> Self {
            Self::with_opts(
                env_id,
                dummy_exe,
                InbandHarnessOpts {
                    version,
                    plan_id,
                    ..Default::default()
                },
            )
        }

        fn with_opts(env_id: &str, dummy_exe: &[u8], opts: InbandHarnessOpts) -> Self {
            let (priv_pem, tk) = test_signing_key(42);
            let trust = TrustRoot::new(vec![tk.clone()]);

            let digest = test_digest_of(dummy_exe);
            let mut bin = test_inband_binary(opts.version, digest.clone());
            bin.source = opts.source;

            let plan = test_plan_with_binary(opts.plan_id, env_id, bin.clone());
            let built = build_update_plan(&plan, &priv_pem, &tk.key_id, &trust)
                .expect("test plan must build");

            // Set up the store directory with the env's trust-root.
            let store_dir = tempfile::TempDir::new().unwrap();
            let env_dir = store_dir.path().join(env_id);
            std::fs::create_dir_all(&env_dir).unwrap();
            let trust_doc = TrustRootDocument::v1(vec![tk]);
            std::fs::write(
                env_dir.join(TRUST_ROOT_FILE),
                serde_json::to_vec_pretty(&trust_doc).unwrap(),
            )
            .unwrap();

            let staging_dir = stage_plan(
                opts.plan_id,
                env_id,
                &bin,
                dummy_exe,
                &built.plan_bytes,
                &built.envelope_bytes,
                opts.skip_blob,
            );

            // Create a temp target exe (NEVER the real test binary).
            let exe_dir = tempfile::TempDir::new().unwrap();
            let target_exe = exe_dir.path().join("target-exe");
            std::fs::write(&target_exe, b"old-binary").unwrap();

            Self {
                store_dir,
                staging_dir,
                exe_dir,
                plan_bytes: built.plan_bytes,
                sig_bytes: built.envelope_bytes,
                env_id: env_id.to_string(),
                target_exe,
                binary_digest: digest,
            }
        }

        fn store(&self) -> LocalFsStore {
            LocalFsStore::new(self.store_dir.path())
        }

        fn env_dir(&self) -> std::path::PathBuf {
            self.store_dir.path().join(&self.env_id)
        }

        fn call(&self) -> Result<Option<Value>, NotifyError> {
            try_apply_binary_update(
                &self.plan_bytes,
                &self.sig_bytes,
                &self.store(),
                &self.env_id,
                Some(&self.target_exe),
                Some(self.staging_dir.path()),
            )
        }
    }

    #[test]
    fn e2e_inband_happy_path_swaps_and_writes_marker() {
        let h = InbandTestHarness::new("e2e-happy", b"dummy-v99-binary");
        let result = h.call();
        let json = result.expect("must succeed").expect("must return Some");
        assert_eq!(json["staged"], true);
        assert_eq!(json["restart_required"], true);
        assert_eq!(json["version"], "99.0.0");

        // The target exe must contain the dummy payload.
        let swapped = std::fs::read(&h.target_exe).unwrap();
        assert_eq!(swapped, b"dummy-v99-binary", "binary must be swapped");

        // A Pending marker must exist with the correct digest.
        let marker = read_binary_update_marker(&h.env_dir()).expect("marker must be written");
        assert_eq!(marker.phase, MarkerPhase::Pending);
        assert_eq!(marker.to_version, "99.0.0");
        assert_eq!(
            marker.digest.as_deref(),
            Some(h.binary_digest.as_str()),
            "marker must record the digest"
        );
    }

    #[test]
    fn e2e_inband_verify_rejects_tampered_blob() {
        let dummy = b"good-binary-for-tamper-test";
        let h = InbandTestHarness::new("e2e-tamper", dummy);

        // Tamper the staged blob AFTER staging.
        let root = UpdatesRoot::open_in(h.staging_dir.path(), &h.env_id).unwrap();
        let staged = root.load("plan-e2e-1").unwrap().unwrap();
        let bin = test_inband_binary("99.0.0", h.binary_digest.clone());
        let blob_path = staged.binary_blob_path(&bin).unwrap();
        std::fs::write(&blob_path, b"tampered-content").unwrap();

        let result = h.call();
        assert!(
            result.is_err(),
            "tampered blob must be rejected: {result:?}"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("verification failed") || err_msg.contains("mismatch"),
            "error must name verification failure: {err_msg}"
        );
    }

    #[test]
    fn e2e_inband_missing_blob_is_an_error() {
        let h = InbandTestHarness::with_opts(
            "e2e-missing-blob",
            b"never-staged",
            InbandHarnessOpts {
                skip_blob: true,
                ..Default::default()
            },
        );
        let result = h.call();
        assert!(
            result.is_err(),
            "missing blob must be an error, not a silent skip: {result:?}"
        );
    }

    #[test]
    fn e2e_inband_tombstone_blocks_same_digest() {
        let dummy = b"tombstone-test-binary";
        let h = InbandTestHarness::new("e2e-tombstone", dummy);

        // Write a RolledBack tombstone for the SAME version + digest.
        let tombstone = BinaryUpdateMarker {
            name: env!("CARGO_PKG_NAME").to_string(),
            from_version: env!("CARGO_PKG_VERSION").to_string(),
            to_version: "99.0.0".to_string(),
            staged_at: "2026-07-28T00:00:00Z".to_string(),
            phase: MarkerPhase::RolledBack,
            rolled_back_at: Some("2026-07-28T01:00:00Z".to_string()),
            digest: Some(h.binary_digest.clone()),
            boot_attempts: 0,
        };
        std::fs::write(
            h.env_dir().join(BINARY_UPDATE_PENDING_FILE),
            serde_json::to_vec(&tombstone).unwrap(),
        )
        .unwrap();

        let result = h.call();
        let json = result.expect("tombstone guard returns Ok");
        assert!(
            json.is_none(),
            "tombstone must block retry of the same digest: {json:?}"
        );
        // The target exe must NOT have been swapped.
        let on_disk = std::fs::read(&h.target_exe).unwrap();
        assert_eq!(
            on_disk, b"old-binary",
            "binary must not be swapped when tombstone blocks"
        );
    }

    #[test]
    fn e2e_apply_binary_rejects_digest_mismatch_at_swap() {
        // Verifies that apply_binary_from_path passes expected_digest to
        // SwapOptions so swap_binary re-verifies the bytes. Construct a
        // BinaryArtifact whose digest does NOT match the file on disk:
        // with expected_digest=Some the swap must fail; dropping it to None
        // (the mutation) would let this pass.
        let real_content = b"real-binary-content";
        let wrong_digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let bin = test_inband_binary("99.0.0", wrong_digest.to_string());

        let tmp = tempfile::TempDir::new().unwrap();
        let inner_binary = tmp.path().join("binary");
        std::fs::write(&inner_binary, real_content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&inner_binary, std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }

        let target_exe = tmp.path().join("target-exe");
        std::fs::write(&target_exe, b"old-binary").unwrap();

        let env_dir = tempfile::TempDir::new().unwrap();

        let result = apply_binary_from_path(
            env!("CARGO_PKG_NAME"),
            &bin,
            &inner_binary,
            &target_exe,
            env_dir.path(),
            env!("CARGO_PKG_VERSION"),
        );
        assert!(
            result.is_err(),
            "digest mismatch at swap must fail: {result:?}"
        );
        // The target exe must NOT have been swapped.
        let on_disk = std::fs::read(&target_exe).unwrap();
        assert_eq!(
            on_disk, b"old-binary",
            "binary must not be swapped when digest mismatches"
        );
    }

    #[test]
    fn e2e_source_some_does_not_use_staging_path() {
        // A plan with source=Some(url) must NOT go through the staging path.
        // We set up staging that WOULD succeed if used, but the source=Some
        // path must be taken instead — and since the URL is fake, it must fail
        // with a fetch error, proving the URL path was taken.
        let h = InbandTestHarness::with_opts(
            "e2e-source-some",
            b"should-not-be-used",
            InbandHarnessOpts {
                plan_id: "plan-e2e-source",
                source: Some("https://localhost:1/nonexistent-archive.tgz".to_string()),
                ..Default::default()
            },
        );
        let result = h.call();
        assert!(
            result.is_err(),
            "source=Some must take URL path, not staging: {result:?}"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("fetch") || err_msg.contains("connect") || err_msg.contains("error"),
            "error must be a fetch failure, not a staging error: {err_msg}"
        );
        // The binary must NOT have been swapped.
        let on_disk = std::fs::read(&h.target_exe).unwrap();
        assert_eq!(on_disk, b"old-binary", "binary must not be swapped");
    }

    #[test]
    fn e2e_pending_different_version_blocks_swap() {
        // First swap: stage v99 successfully.
        let h = InbandTestHarness::new("e2e-lineage-block", b"dummy-v99");
        let r1 = h.call().expect("first swap must succeed").unwrap();
        assert_eq!(r1["staged"], true);
        let swapped_v99 = std::fs::read(&h.target_exe).unwrap();
        assert_eq!(
            swapped_v99, b"dummy-v99",
            "binary must be v99 after first swap"
        );

        let marker_after_v99 =
            read_binary_update_marker(&h.env_dir()).expect("marker must exist after first swap");
        assert_eq!(marker_after_v99.to_version, "99.0.0");

        // Second swap: try to stage v100 (different, higher version).
        // Must be blocked by the lineage guard.
        let h2 = InbandTestHarness::new_with_version(
            "e2e-lineage-block",
            b"dummy-v100",
            "100.0.0",
            "plan-e2e-lineage-v100",
        );
        // Reuse h's store/env_dir (which has the pending marker) but h2's
        // staging has the v100 blob. Call through h2's staging + h's store.
        let result = try_apply_binary_update(
            &h2.plan_bytes,
            &h2.sig_bytes,
            &h.store(),
            &h.env_id,
            Some(&h.target_exe),
            Some(h2.staging_dir.path()),
        );
        let json = result.expect("lineage guard returns Ok").unwrap();
        assert_eq!(json["staged"], false, "second swap must be blocked");
        assert_eq!(json["blocked_on_pending"], "99.0.0");
        assert_eq!(json["restart_required"], true);

        // The binary on disk must still be v99 (no second swap).
        let still_v99 = std::fs::read(&h.target_exe).unwrap();
        assert_eq!(still_v99, b"dummy-v99", "binary must not be overwritten");

        // The marker must still name v99.
        let marker_still =
            read_binary_update_marker(&h.env_dir()).expect("marker must still exist");
        assert_eq!(marker_still.to_version, "99.0.0");
    }

    #[test]
    fn e2e_oversized_blob_rejected_before_read() {
        let dummy = b"small-exe";
        let h = InbandTestHarness::new("e2e-oversize", dummy);

        // Inflate the staged blob to exceed MAX_BINARY_ARCHIVE_BYTES via
        // set_len (sparse — cheap, no actual disk I/O).
        let bin = test_inband_binary("99.0.0", h.binary_digest.clone());
        let root = UpdatesRoot::open_in(h.staging_dir.path(), &h.env_id).unwrap();
        let staged = root.load("plan-e2e-1").unwrap().unwrap();
        let blob_path = staged.binary_blob_path(&bin).unwrap();
        {
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(&blob_path)
                .unwrap();
            f.set_len(MAX_BINARY_ARCHIVE_BYTES + 1).unwrap();
        }

        let result = h.call();
        assert!(
            result.is_err(),
            "oversized blob must be rejected: {result:?}"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("byte cap"),
            "error must mention byte cap: {err_msg}"
        );

        // The target exe must NOT have been swapped.
        let on_disk = std::fs::read(&h.target_exe).unwrap();
        assert_eq!(
            on_disk, b"old-binary",
            "binary must not be swapped when blob is oversized"
        );
    }

    // ── C4: blob-mirror fallback tests ───────────────────────────────────────

    /// Write `update-channel.json` into the harness's store so
    /// `load_blob_base_url` returns the given base URL.
    fn write_blob_base_url(harness: &InbandTestHarness, base_url: &str) {
        let mut cfg = UpdateChannelConfig::disabled(EnvId::new(&harness.env_id).unwrap());
        cfg.enabled = Some(true);
        cfg.on_update = Some(UpdateAction::Stage);
        cfg.blob_base_url = Some(base_url.to_string());
        let env_dir = harness.env_dir();
        std::fs::create_dir_all(&env_dir).unwrap();
        std::fs::write(
            env_dir.join("update-channel.json"),
            serde_json::to_vec_pretty(&cfg).unwrap(),
        )
        .unwrap();
    }

    /// Spawn a minimal HTTP/1.1 server on a random port that serves exactly one
    /// blob at `/sha256-<hex>`. Returns `(base_url, join_handle)`. The server
    /// accepts one connection, serves the response, then shuts down.
    fn spawn_blob_mirror(
        blob_hex: &str,
        body: &[u8],
        status: u16,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{port}");
        let expected_path = format!("/sha256-{blob_hex}");
        let body = body.to_vec();
        let handle = std::thread::spawn(move || {
            use std::io::{BufRead, Write};
            // Bounded accept. A plain blocking `accept()` deadlocks the caller's
            // `join()` whenever the client never connects — which is exactly what
            // a "the mirror must not be contacted" regression looks like. That
            // turns a clean assertion failure into a CI job timeout carrying no
            // diagnostic, so give up after a deadline and let the test's own
            // assertions report the real problem.
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break Some(stream),
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() >= deadline {
                            break None;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break None,
                }
            };
            let Some(stream) = stream else {
                return;
            };
            // The accepted socket can inherit the listener's non-blocking flag;
            // the request/response exchange below wants blocking semantics.
            stream.set_nonblocking(false).unwrap();
            let mut reader = std::io::BufReader::new(&stream);
            // Read the request line and headers (up to blank line).
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            // Drain remaining headers.
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line == "\n" || line.is_empty() {
                    break;
                }
            }
            // Verify the request path.
            let path = request_line.split_whitespace().nth(1).unwrap_or("");
            let mut writer = reader.into_inner();
            if path != expected_path {
                let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string();
                let _ = writer.write_all(resp.as_bytes());
                return;
            }
            let resp = format!(
                "HTTP/1.1 {status} {}\r\nContent-Length: {}\r\n\r\n",
                if status == 200 { "OK" } else { "Error" },
                body.len(),
            );
            let _ = writer.write_all(resp.as_bytes());
            let _ = writer.write_all(&body);
        });
        (base_url, handle)
    }

    #[test]
    fn c4_mirror_fallback_swaps_from_mirror() {
        let dummy_exe = b"mirror-binary-v99";
        let h = InbandTestHarness::with_opts(
            "c4-mirror-happy",
            dummy_exe,
            InbandHarnessOpts {
                skip_blob: true,
                ..Default::default()
            },
        );

        // Extract the bare hex from the digest.
        let hex = h.binary_digest.strip_prefix("sha256:").unwrap();
        let (base_url, server) = spawn_blob_mirror(hex, dummy_exe, 200);
        write_blob_base_url(&h, &base_url);

        let result = h.call();
        server.join().unwrap();

        let json = result.expect("must succeed").expect("must return Some");
        assert_eq!(json["staged"], true);
        assert_eq!(json["restart_required"], true);
        assert_eq!(json["version"], "99.0.0");

        // The target exe must contain the mirror payload.
        let swapped = std::fs::read(&h.target_exe).unwrap();
        assert_eq!(swapped, dummy_exe, "binary must be swapped from mirror");

        // A Pending marker must exist.
        let marker = read_binary_update_marker(&h.env_dir()).expect("marker must be written");
        assert_eq!(marker.phase, MarkerPhase::Pending);
        assert_eq!(marker.to_version, "99.0.0");
        assert_eq!(marker.digest.as_deref(), Some(h.binary_digest.as_str()),);
    }

    #[test]
    fn c4_mirror_tampered_bytes_hard_error() {
        let dummy_exe = b"good-mirror-binary";
        let h = InbandTestHarness::with_opts(
            "c4-mirror-tamper",
            dummy_exe,
            InbandHarnessOpts {
                skip_blob: true,
                ..Default::default()
            },
        );

        let hex = h.binary_digest.strip_prefix("sha256:").unwrap();
        // Serve WRONG bytes — the digest will not match.
        let (base_url, server) = spawn_blob_mirror(hex, b"tampered-payload", 200);
        write_blob_base_url(&h, &base_url);

        let result = h.call();
        server.join().unwrap();

        assert!(
            result.is_err(),
            "tampered mirror blob must be rejected: {result:?}"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("digest mismatch"),
            "error must mention digest mismatch: {err_msg}"
        );

        // Binary must NOT have been swapped.
        let on_disk = std::fs::read(&h.target_exe).unwrap();
        assert_eq!(
            on_disk, b"old-binary",
            "binary must not be swapped on tamper"
        );

        // No pending marker.
        assert!(
            read_binary_update_marker(&h.env_dir()).is_none(),
            "no marker must be written on mirror digest mismatch"
        );
    }

    #[test]
    fn c4_no_mirror_configured_reproduces_pre_c4_error() {
        // Staged blob is missing AND no mirror configured → the pre-C4 hard
        // error, byte-for-byte (regression pin).
        let h = InbandTestHarness::with_opts(
            "c4-no-mirror",
            b"never-staged",
            InbandHarnessOpts {
                skip_blob: true,
                ..Default::default()
            },
        );
        // Do NOT write_blob_base_url → load_blob_base_url returns None.

        let result = h.call();
        assert!(
            result.is_err(),
            "missing blob + no mirror must error: {result:?}"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("in-band binary stat"),
            "error must be the pre-C4 stat error, not a new message: {err_msg}"
        );

        // Binary must NOT have been swapped.
        let on_disk = std::fs::read(&h.target_exe).unwrap();
        assert_eq!(on_disk, b"old-binary", "binary must not be swapped");
    }

    #[test]
    fn c4_blob_present_ignores_mirror() {
        // Staged blob IS present, mirror is configured at an unroutable address.
        // Must succeed from the staged blob, proving the mirror was never contacted.
        let dummy_exe = b"local-blob-binary";
        let h = InbandTestHarness::new("c4-blob-present", dummy_exe);

        // Point the mirror at an unroutable address — if contacted, it would fail.
        write_blob_base_url(&h, "http://127.0.0.1:1");

        let result = h.call();
        let json = result.expect("must succeed").expect("must return Some");
        assert_eq!(json["staged"], true);
        assert_eq!(json["version"], "99.0.0");

        // The target exe must contain the STAGED payload, not anything from a mirror.
        let swapped = std::fs::read(&h.target_exe).unwrap();
        assert_eq!(
            swapped, dummy_exe,
            "binary must come from staging, not mirror"
        );
    }

    #[test]
    fn c4_mirror_fetch_failure_is_hard_error() {
        // Mirror configured at an unroutable address, blob missing → hard error
        // from the fetch failure, not a silent skip.
        let h = InbandTestHarness::with_opts(
            "c4-fetch-fail",
            b"unreachable-binary",
            InbandHarnessOpts {
                skip_blob: true,
                ..Default::default()
            },
        );
        write_blob_base_url(&h, "http://127.0.0.1:1");

        let result = h.call();
        assert!(
            result.is_err(),
            "mirror fetch failure must be a hard error: {result:?}"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("mirror fetch failed"),
            "error must name the mirror fetch failure: {err_msg}"
        );

        // Binary must NOT have been swapped.
        let on_disk = std::fs::read(&h.target_exe).unwrap();
        assert_eq!(
            on_disk, b"old-binary",
            "binary must not be swapped on fetch failure"
        );

        // No pending marker.
        assert!(
            read_binary_update_marker(&h.env_dir()).is_none(),
            "no marker on mirror fetch failure"
        );
    }

    #[test]
    fn c4_mirror_500_is_hard_error() {
        // Mirror serves a 500 Internal Server Error → hard error.
        let dummy_exe = b"server-error-binary";
        let h = InbandTestHarness::with_opts(
            "c4-mirror-500",
            dummy_exe,
            InbandHarnessOpts {
                skip_blob: true,
                ..Default::default()
            },
        );
        let hex = h.binary_digest.strip_prefix("sha256:").unwrap();
        let (base_url, server) = spawn_blob_mirror(hex, b"", 500);
        write_blob_base_url(&h, &base_url);

        let result = h.call();
        server.join().unwrap();

        assert!(
            result.is_err(),
            "mirror 500 must be a hard error: {result:?}"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("mirror fetch status error"),
            "error must name the status error: {err_msg}"
        );

        let on_disk = std::fs::read(&h.target_exe).unwrap();
        assert_eq!(on_disk, b"old-binary", "binary must not be swapped on 500");
    }

    #[test]
    fn c4_malformed_digest_rejected_upstream_of_the_mirror() {
        // A binary whose digest is NOT `sha256:<64 hex>` must fail BEFORE any
        // network call. The gate that actually fires is UPSTREAM of C4:
        // `staged.binary_blob_path()` validates the digest inside
        // greentic-update (`staging.rs`: "malformed artifact digest") before the
        // metadata match that dispatches to the mirror, so a bad digest can
        // never reach URL construction. Assert that specific error rather than
        // accepting `validate_digest_hex`'s message too — an `||` over both
        // would hide which gate fired, and would keep passing if the ordering
        // regressed so that the mirror ran first. `validate_digest_hex` is the
        // second, defense-in-depth gate and is pinned directly by
        // `c4_validate_digest_hex_rejects_bad_inputs`.
        let dummy_exe = b"malformed-digest-binary";
        let digest = "md5:abc123".to_string();

        let (priv_pem, tk) = test_signing_key(42);
        let trust = TrustRoot::new(vec![tk.clone()]);

        let bin = BinaryArtifact {
            name: env!("CARGO_PKG_NAME").to_string(),
            version: "99.0.0".to_string(),
            target: binswap::current_target().to_string(),
            digest,
            source: None,
        };

        let plan = test_plan_with_binary("plan-c4-malformed", "c4-malformed", bin.clone());
        let built = build_update_plan(&plan, &priv_pem, &tk.key_id, &trust).unwrap();

        let store_dir = tempfile::TempDir::new().unwrap();
        let env_dir = store_dir.path().join("c4-malformed");
        std::fs::create_dir_all(&env_dir).unwrap();
        let trust_doc = TrustRootDocument::v1(vec![tk]);
        std::fs::write(
            env_dir.join(TRUST_ROOT_FILE),
            serde_json::to_vec_pretty(&trust_doc).unwrap(),
        )
        .unwrap();

        let staging_dir = stage_plan(
            "plan-c4-malformed",
            "c4-malformed",
            &bin,
            dummy_exe,
            &built.plan_bytes,
            &built.envelope_bytes,
            true, // skip_blob
        );

        // Configure mirror at an unroutable address.
        let mut cfg = UpdateChannelConfig::disabled(EnvId::new("c4-malformed").unwrap());
        cfg.enabled = Some(true);
        cfg.on_update = Some(UpdateAction::Stage);
        cfg.blob_base_url = Some("http://127.0.0.1:1/blobs".to_string());
        std::fs::write(
            env_dir.join("update-channel.json"),
            serde_json::to_vec_pretty(&cfg).unwrap(),
        )
        .unwrap();

        let exe_dir = tempfile::TempDir::new().unwrap();
        let target_exe = exe_dir.path().join("target-exe");
        std::fs::write(&target_exe, b"old-binary").unwrap();

        let store = LocalFsStore::new(store_dir.path());
        let result = try_apply_binary_update(
            &built.plan_bytes,
            &built.envelope_bytes,
            &store,
            "c4-malformed",
            Some(&target_exe),
            Some(staging_dir.path()),
        );

        assert!(
            result.is_err(),
            "malformed digest must be a hard error: {result:?}"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("malformed artifact digest"),
            "the upstream blob-path gate must reject the digest before the \
             mirror dispatch is reached: {err_msg}"
        );

        let on_disk = std::fs::read(&target_exe).unwrap();
        assert_eq!(
            on_disk, b"old-binary",
            "binary must not be swapped on malformed digest"
        );
    }

    #[test]
    fn c4_mirror_oversized_response_rejected() {
        // Exercise the cap-check branch in fetch_blob_from_mirror_capped.
        // Allocating 256 MiB (the production cap) is impractical in a unit
        // test, so we call the _capped variant with a small cap and spawn a
        // server that sends more bytes than that cap.
        const TEST_CAP: u64 = 128; // tiny cap for the test

        // Build a payload that exceeds TEST_CAP. Content doesn't matter for
        // the cap check — it fires before digest verification.
        let oversized_body = vec![0u8; (TEST_CAP + 1) as usize];

        // We still need a valid digest string to pass validate_digest_hex.
        let dummy_exe = b"oversized-cap-test";
        let digest = test_digest_of(dummy_exe);
        let hex = digest.strip_prefix("sha256:").unwrap();

        let (base_url, server) = spawn_blob_mirror(hex, &oversized_body, 200);
        let result = fetch_blob_from_mirror_capped(&base_url, &digest, TEST_CAP);
        server.join().unwrap();

        assert!(
            result.is_err(),
            "oversized mirror response must be rejected: {result:?}"
        );
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("byte cap"),
            "error must mention byte cap, not digest mismatch: {err_msg}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn c4_non_notfound_metadata_error_is_hard_error() {
        // When fs::metadata on the blob path fails with something OTHER than
        // NotFound (e.g. PermissionDenied), the error must be a hard error
        // that does NOT attempt a mirror fallback. This pins the
        // ErrorKind::NotFound guard so it cannot be silently widened to a
        // catch-all.
        let dummy_exe = b"perm-denied-binary";
        let h = InbandTestHarness::new("c4-perm-denied", dummy_exe);

        // The blob IS staged (skip_blob defaults to false). Now remove
        // permissions on the blob's parent directory so that fs::metadata
        // returns PermissionDenied instead of NotFound.
        let bin = test_inband_binary("99.0.0", h.binary_digest.clone());
        let root = UpdatesRoot::open_in(h.staging_dir.path(), &h.env_id).unwrap();
        let staged = root.load("plan-e2e-1").unwrap().unwrap();
        let blob_path = staged.binary_blob_path(&bin).unwrap();
        let blob_parent = blob_path.parent().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(blob_parent, std::fs::Permissions::from_mode(0o000)).unwrap();

        // Configure a mirror at an unroutable address — if the code
        // incorrectly falls through to the mirror, it would produce a
        // different error ("mirror fetch failed") instead of the expected
        // "in-band binary stat" error.
        write_blob_base_url(&h, "http://127.0.0.1:1");

        let result = h.call();

        // Restore permissions so the TempDir cleanup succeeds.
        std::fs::set_permissions(blob_parent, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            result.is_err(),
            "permission-denied on blob must be a hard error: {result:?}"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("in-band binary stat"),
            "error must be the non-NotFound stat error, not a mirror fallback: {err_msg}"
        );

        // Binary must NOT have been swapped.
        let on_disk = std::fs::read(&h.target_exe).unwrap();
        assert_eq!(
            on_disk, b"old-binary",
            "binary must not be swapped on permission denied"
        );
    }

    #[test]
    fn c4_validate_digest_hex_rejects_bad_inputs() {
        // Comprehensive unit tests for validate_digest_hex.
        assert!(validate_digest_hex(&format!("sha256:{}", "a".repeat(64))).is_ok());
        assert!(validate_digest_hex(&format!("sha256:{}", "0123456789abcdef".repeat(4))).is_ok());

        // Missing prefix.
        let err = validate_digest_hex("abcd").unwrap_err();
        assert!(err.contains("missing `sha256:` prefix"), "{err}");

        // Wrong prefix.
        let err = validate_digest_hex(&format!("sha512:{}", "a".repeat(64))).unwrap_err();
        assert!(err.contains("missing `sha256:` prefix"), "{err}");

        // Too short.
        let err = validate_digest_hex("sha256:abcd").unwrap_err();
        assert!(err.contains("64 chars"), "{err}");

        // Too long.
        let err = validate_digest_hex(&format!("sha256:{}", "a".repeat(65))).unwrap_err();
        assert!(err.contains("64 chars"), "{err}");

        // Uppercase hex.
        let err = validate_digest_hex(&format!("sha256:{}", "A".repeat(64))).unwrap_err();
        assert!(err.contains("non-lowercase-hex"), "{err}");

        // Non-hex chars.
        let err = validate_digest_hex(&format!("sha256:{}z", "a".repeat(63))).unwrap_err();
        assert!(err.contains("non-lowercase-hex"), "{err}");
    }

    // ── Category 12: A5 — end-to-end WS upgrade through revision-serve ─────

    /// In-memory `SecretsManager` for tests: returns a pre-loaded signing key
    /// and rejects everything else.
    struct TestSecretsManager {
        entries: std::sync::Mutex<HashMap<String, Vec<u8>>>,
    }

    impl TestSecretsManager {
        fn with_entry(key: &str, value: Vec<u8>) -> Self {
            let mut map = HashMap::new();
            map.insert(key.to_string(), value);
            Self {
                entries: std::sync::Mutex::new(map),
            }
        }
    }

    #[async_trait::async_trait]
    impl greentic_secrets_lib::SecretsManager for TestSecretsManager {
        async fn read(&self, path: &str) -> greentic_secrets_lib::Result<Vec<u8>> {
            self.entries
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| greentic_secrets_lib::SecretError::NotFound(path.to_string()))
        }

        async fn write(&self, _path: &str, _bytes: &[u8]) -> greentic_secrets_lib::Result<()> {
            Ok(())
        }

        async fn delete(&self, _path: &str) -> greentic_secrets_lib::Result<()> {
            Ok(())
        }
    }

    /// In-memory activity source for the WS pump that bypasses the WASM
    /// provider. Shared between the test driver and the pump via `Arc`.
    struct TestActivitySource {
        entries: std::sync::Mutex<Vec<serde_json::Value>>,
        next_watermark: std::sync::Mutex<u64>,
    }

    impl TestActivitySource {
        fn new() -> Self {
            Self {
                entries: std::sync::Mutex::new(Vec::new()),
                next_watermark: std::sync::Mutex::new(0),
            }
        }

        fn append(&self, text: &str) -> u64 {
            let mut wm = self.next_watermark.lock().unwrap();
            let watermark = *wm;
            *wm += 1;
            self.entries.lock().unwrap().push(serde_json::json!({
                "type": "message",
                "text": text,
                "channelData": {"watermark": watermark},
            }));
            watermark
        }
    }

    #[async_trait::async_trait]
    impl crate::websocket::pump::ActivitySource for TestActivitySource {
        async fn fetch_since(
            &self,
            _tenant_id: &str,
            _conversation_id: &str,
            since_watermark: u64,
        ) -> Result<(Vec<serde_json::Value>, u64), String> {
            let entries = self.entries.lock().unwrap();
            let next = *self.next_watermark.lock().unwrap();
            let filtered: Vec<serde_json::Value> = entries
                .iter()
                .filter(|a| {
                    a.get("channelData")
                        .and_then(|cd| cd.get("watermark"))
                        .and_then(|w| w.as_u64())
                        .map(|w| w >= since_watermark)
                        .unwrap_or(false)
                })
                .cloned()
                .collect();
            Ok((filtered, next))
        }
    }

    /// Issue a HS256 JWT for the test WebSocket handshake.
    fn issue_test_token(conversation_id: &str, tenant: &str, signing_key: &[u8]) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;

        let exp = chrono::Utc::now().timestamp() + 60;
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let claims = format!(
            r#"{{"sub":"test-user","exp":{exp},"ctx":{{"env":"test","tenant":"{tenant}"}},"conv":"{conversation_id}"}}"#
        );
        let payload = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let signing_input = format!("{header}.{payload}");
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(signing_key).expect("hmac key");
        mac.update(signing_input.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{signing_input}.{sig}")
    }

    /// Build an [`Activation`] wired for the A5 end-to-end WS test: routes
    /// resolve, the dispatcher holds one revision, and the secrets manager
    /// returns the signing key.
    fn ws_test_activation(
        env_id: &str,
        tenant: &str,
        deployment_id: greentic_deploy_spec::ids::DeploymentId,
        revision_id: greentic_deploy_spec::ids::RevisionId,
        bundle_id: greentic_deploy_spec::ids::BundleId,
        signing_key: &[u8],
        pin_store: std::sync::Arc<dyn crate::revision_pin::RevisionPinStore>,
    ) -> Activation {
        use crate::deployment_routes::DeploymentRouteTable;
        use crate::http_routes::{HttpRouteTable, provider_descriptor_for_test};
        use crate::revision_dispatcher::{
            RevisionDispatcher, RevisionDispatcherConfig, RevisionEntry,
        };

        let scope = crate::http_routes::RevisionScope {
            deployment_id,
            bundle_id: bundle_id.clone(),
            revision_id,
        };

        let mut provider_route = provider_descriptor_for_test(
            "/v1/messaging/webchat/{tenant}/{path*}",
            "messaging.webchat.gui",
            scope,
        );
        provider_route.methods = Vec::new();
        let http_routes = HttpRouteTable::from_descriptors(vec![provider_route]);

        let deployment_routes = DeploymentRouteTable::from_parts(vec![(
            deployment_id,
            tenant.to_string(),
            Vec::new(),
            Vec::new(),
        )]);

        let dispatcher = RevisionDispatcher::with_pin_store(
            RevisionDispatcherConfig::new(env_id, [0u8; 32]),
            pin_store,
        );
        dispatcher
            .apply_traffic_split(
                deployment_id,
                vec![RevisionEntry {
                    revision_id,
                    bundle_id: bundle_id.clone(),
                    weight_bps: 10_000,
                }],
                bundle_id,
                0,
            )
            .expect("apply_traffic_split");

        let provider_hyphen = "messaging-webchat-gui";
        let env = crate::resolve_env(None);
        let team_segment = crate::secrets_manager::canonical_team(Some("default"));
        let raw_uri =
            format!("secrets://{env}/{tenant}/{team_segment}/{provider_hyphen}/jwt_signing_key");
        let secrets: greentic_runner_host::secrets::DynSecretsManager = std::sync::Arc::new(
            TestSecretsManager::with_entry(&raw_uri, signing_key.to_vec()),
        );

        let host = std::sync::Arc::new(
            greentic_runner_host::HostBuilder::new()
                .with_config(greentic_runner_host::HostConfig::from_gtbind(
                    greentic_runner_host::TenantBindings {
                        tenant: tenant.to_string(),
                        packs: Vec::new(),
                        env_passthrough: Vec::new(),
                    },
                ))
                .with_secrets_manager(secrets)
                .build()
                .expect("build test host"),
        );

        Activation {
            host,
            routing: std::sync::Arc::new(RevisionIngressRouting {
                dispatcher: std::sync::Arc::new(dispatcher),
                http_routes,
                deployment_routes,
                endpoint_admit: std::sync::Arc::new(crate::endpoint_admit::EndpointAdmit::default()),
                deployment_config_overrides: std::sync::Arc::default(),
                static_routes: crate::static_routes::ActiveRouteTable::default(),
            }),
        }
    }

    /// A5 end-to-end: a WebSocket client connects through the REAL
    /// `spawn_revision_connection` → `handle_connection` →
    /// `handle_websocket_upgrade` pipeline, completes the handshake,
    /// receives a pre-populated replay activity, then receives a
    /// live-pushed activity via the notifier.
    ///
    /// Mutation proof:
    /// (a) Removing `.with_upgrades()` from `spawn_revision_connection`
    ///     makes the handshake fail ("Handshake not finished").
    /// (b) Removing `try_notify_webchat_activity` removes the only
    ///     `notifier.publish` on the revision path; the pump never
    ///     wakes for live activities and the second frame never arrives.
    #[tokio::test(flavor = "multi_thread")]
    async fn revision_ws_upgrade_end_to_end() {
        let env_id = "local";
        let tenant = "test-tenant";
        let signing_key = b"revision-ws-test-key";
        let dep_id = greentic_deploy_spec::ids::DeploymentId::new();
        let rev_id = greentic_deploy_spec::ids::RevisionId::new();
        let bundle_id = greentic_deploy_spec::ids::BundleId::new("test.webchat");
        let conv_id = "conv-ws-e2e";
        let pin_store: std::sync::Arc<dyn crate::revision_pin::RevisionPinStore> =
            std::sync::Arc::new(crate::revision_pin::InMemoryPinStore::new());

        let activation = ws_test_activation(
            env_id,
            tenant,
            dep_id,
            rev_id,
            bundle_id.clone(),
            signing_key,
            std::sync::Arc::clone(&pin_store),
        );

        let test_source = std::sync::Arc::new(TestActivitySource::new());
        test_source.append("hello from replay");

        let notifier: Arc<dyn crate::notifier::ActivityNotifier> =
            Arc::new(crate::notifier::InMemoryNotifier::new(64));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");

        let state = Arc::new(ServeState {
            slot: ArcSwap::new(std::sync::Arc::new(activation)),
            bound_addr: addr,
            gui_enabled: false,
            restart_required: AtomicBool::new(false),
            updates_enabled: false,
            auto_restart_pending: AtomicBool::new(false),
            auto_restart_enabled: false,
            exe_path: None,
            directline_sessions: Arc::new(
                crate::directline_session::DirectLineSessions::with_ttl_secs(1800),
            ),
            conversation_dedup: Arc::new(crate::conv_dedup::ConversationDedupCache::new()),
            session_manager: Arc::new(crate::websocket::SessionManager::new(
                crate::websocket::WsLimits::default(),
            )),
            notifier: Arc::clone(&notifier),
            public_url_capture: None,
            activity_source_override: Some(
                test_source.clone() as Arc<dyn crate::websocket::pump::ActivitySource>
            ),
        });

        // Pre-seed a revision pin for this conversation so the WS upgrade
        // finds it (A5: the WS endpoint requires a prior REST POST
        // /conversations that pins the session).
        let session_hint = format!("webchat:{conv_id}");
        state
            .current()
            .routing
            .dispatcher
            .commit_pin(tenant, dep_id, &session_hint, rev_id)
            .await;

        // Spawn the accept loop.
        let accept_state = Arc::clone(&state);
        let accept_handle = tokio::spawn(async move {
            while let Ok(accept) = listener.accept().await {
                spawn_revision_connection(Ok(accept), &accept_state, true);
            }
        });

        // Build the WS URL with a valid token.
        let token = issue_test_token(conv_id, tenant, signing_key);
        let url = format!(
            "ws://{addr}/v1/messaging/webchat/{tenant}/v3/directline/conversations/{conv_id}/stream?t={token}&watermark=0"
        );

        // Connect and complete the WebSocket handshake.
        let (mut ws, response) = tokio_tungstenite::connect_async(&url)
            .await
            .expect("ws connect must succeed (handshake)");
        assert_eq!(
            response.status(),
            tokio_tungstenite::tungstenite::http::StatusCode::SWITCHING_PROTOCOLS,
            "handshake must complete with 101"
        );

        // First frame: the replay activity pre-populated in the source.
        use futures_util::StreamExt;
        let replay = tokio::time::timeout(std::time::Duration::from_millis(3000), ws.next())
            .await
            .expect("replay timeout")
            .expect("ws closed before replay")
            .expect("ws error");
        let replay_text = match replay {
            tokio_tungstenite::tungstenite::Message::Text(t) => t.to_string(),
            other => panic!("expected text frame, got {other:?}"),
        };
        let payload: serde_json::Value = serde_json::from_str(&replay_text).expect("replay json");
        let activities = payload["activities"].as_array().expect("activities array");
        assert_eq!(activities.len(), 1, "replay should contain one activity");
        assert_eq!(
            activities[0]["text"], "hello from replay",
            "replay activity text"
        );

        // Simulate a provider-op writing a new activity: append to source,
        // then publish a notify event (the production code path calls
        // `try_notify_webchat_activity` after `invoke_provider_for_revision`).
        let new_wm = test_source.append("live bot reply");
        notifier
            .publish(crate::notifier::NotifyEvent {
                tenant_id: tenant.to_string(),
                conversation_id: conv_id.to_string(),
                new_watermark: new_wm + 1,
            })
            .await;

        // Second frame: the live-pushed activity.
        let live = tokio::time::timeout(std::time::Duration::from_millis(3000), ws.next())
            .await
            .expect("live timeout — pump never woke (notifier publish missing?)")
            .expect("ws closed before live frame")
            .expect("ws error");
        let live_text = match live {
            tokio_tungstenite::tungstenite::Message::Text(t) => t.to_string(),
            other => panic!("expected text frame for live push, got {other:?}"),
        };
        let live_payload: serde_json::Value = serde_json::from_str(&live_text).expect("live json");
        let live_activities = live_payload["activities"]
            .as_array()
            .expect("live activities array");
        assert!(
            live_activities
                .iter()
                .any(|a| a["text"] == "live bot reply"),
            "expected live bot reply in {live_activities:?}",
        );

        let _ = ws.close(None).await;
        accept_handle.abort();
    }

    /// Combined regression for the webchat token 502: the store is keyed the
    /// way greentic-setup/`SecretsSetup` persist (canonical underscore
    /// provider segment, tenant-level `_` team), the serve-path manager built
    /// by `resolve_serve_secrets_manager` is installed via
    /// `HostBuilder::with_secrets_manager` exactly like `revision_boot`, and
    /// the read uses the raw hyphenated pack-stem URI the runner-host's
    /// provider self-read emits. Before the fallback wrapper this read was
    /// NotFound → webchat-gui returned 500 secret_error → `/token` 502'd.
    #[tokio::test]
    async fn serve_secrets_stack_resolves_component_self_read_uri() {
        use greentic_secrets_lib::{
            SecretFormat, SeedDoc, SeedEntry, SeedValue,
            core::seed::{ApplyOptions, DevStore, apply_seed},
        };

        let env_dir = tempfile::tempdir().expect("tempdir");
        let store_path = env_dir.path().join(".greentic/dev/.dev.secrets.env");
        std::fs::create_dir_all(store_path.parent().unwrap()).expect("store dir");
        let store = DevStore::with_path(store_path).expect("dev store");
        let seed = SeedDoc {
            entries: vec![SeedEntry {
                uri: "secrets://local/demo/_/messaging_webchat_gui/jwt_signing_key".to_string(),
                format: SecretFormat::Text,
                value: SeedValue::Text {
                    text: "signing-key".to_string(),
                },
                description: None,
            }],
        };
        let report = apply_seed(&store, &seed, ApplyOptions::default()).await;
        assert_eq!(report.ok, 1);

        let (secrets, _scope) = {
            let guard = crate::test_env_lock().lock().unwrap();
            unsafe {
                std::env::remove_var(crate::secrets_gate::ENV_SERVE_SECRETS_BACKEND);
                std::env::remove_var("GREENTIC_DEV_SECRETS_PATH");
            }
            let resolved =
                crate::secrets_gate::resolve_serve_secrets_manager(env_dir.path(), "demo");
            drop(guard);
            resolved.expect("serve secrets manager")
        };

        let host = greentic_runner_host::HostBuilder::new()
            .with_config(greentic_runner_host::HostConfig::from_gtbind(
                greentic_runner_host::TenantBindings {
                    tenant: "demo".to_string(),
                    packs: Vec::new(),
                    env_passthrough: Vec::new(),
                },
            ))
            .with_secrets_manager(secrets)
            .build()
            .expect("build host");

        let value = host
            .secrets_manager()
            .read("secrets://local/demo/_/messaging-webchat-gui/jwt_signing_key")
            .await
            .expect("hyphenated self-read URI must resolve the underscore-keyed store");
        assert_eq!(value, b"signing-key");
    }
}

#[cfg(test)]
mod public_url_capture_tests {
    use super::{PublicUrlCapture, try_capture_public_url};

    /// Build a Cloud-Run-shaped request header map.
    fn cr_headers(host: &str, trace: bool) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        h.insert(hyper::header::HOST, host.parse().unwrap());
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        if trace {
            h.insert("x-cloud-trace-context", "abc/1;o=1".parse().unwrap());
        }
        h
    }

    #[test]
    fn try_capture_fires_for_own_service_host() {
        // Exercises the actual handle_connection hook logic: a GFE-fronted
        // request to this service's own run.app URL captures the base URL.
        let cap = PublicUrlCapture::new("gtc-svc-abc".to_string());
        try_capture_public_url(&cap, &cr_headers("gtc-svc-abc-uc.a.run.app", true));
        assert_eq!(
            cap.get().map(String::as_str),
            Some("https://gtc-svc-abc-uc.a.run.app"),
        );
    }

    #[test]
    fn try_capture_ignores_request_without_trace_context() {
        // No X-Cloud-Trace-Context → not a GFE-fronted request → no capture.
        let cap = PublicUrlCapture::new("gtc-svc-abc".to_string());
        try_capture_public_url(&cap, &cr_headers("gtc-svc-abc-uc.a.run.app", false));
        assert_eq!(cap.get(), None);
    }

    #[test]
    fn try_capture_ignores_foreign_host_hijack() {
        // Attacker-supplied Host that is not this service's own URL — the
        // service-name pin must reject it (webhook-hijack defense).
        let cap = PublicUrlCapture::new("gtc-svc-abc".to_string());
        try_capture_public_url(&cap, &cr_headers("evil.attacker.com", true));
        try_capture_public_url(&cap, &cr_headers("othersvc-1.a.run.app", true));
        assert_eq!(cap.get(), None);
    }

    #[test]
    fn try_capture_is_noop_once_captured() {
        // First valid capture wins; a later request cannot overwrite it, even
        // one that would otherwise be valid.
        let cap = PublicUrlCapture::new("gtc-svc-abc".to_string());
        try_capture_public_url(&cap, &cr_headers("gtc-svc-abc-uc.a.run.app", true));
        try_capture_public_url(&cap, &cr_headers("gtc-svc-abc-zz.a.run.app", true));
        assert_eq!(
            cap.get().map(String::as_str),
            Some("https://gtc-svc-abc-uc.a.run.app"),
        );
    }

    #[test]
    fn offer_sets_once_and_second_offer_is_ignored() {
        let cap = PublicUrlCapture::default();
        cap.offer("https://first.run.app".to_string());
        cap.offer("https://second.run.app".to_string());
        assert_eq!(
            cap.get().map(String::as_str),
            Some("https://first.run.app"),
            "only the first offer should win",
        );
    }

    #[tokio::test]
    async fn captured_resolves_after_offer() {
        let cap = std::sync::Arc::new(PublicUrlCapture::default());
        let cap2 = std::sync::Arc::clone(&cap);

        let handle = tokio::spawn(async move { cap2.captured().await });

        // Small yield to let the waiter register before the offer.
        tokio::task::yield_now().await;
        cap.offer("https://test.run.app".to_string());

        let url = handle.await.expect("task should not panic");
        assert_eq!(url, "https://test.run.app");
    }

    #[tokio::test]
    async fn captured_returns_immediately_when_already_set() {
        let cap = PublicUrlCapture::default();
        cap.offer("https://already.run.app".to_string());

        // Should return immediately — no waiting.
        let url = cap.captured().await;
        assert_eq!(url, "https://already.run.app");
    }

    #[tokio::test]
    async fn captured_wakes_waiter_registered_before_offer() {
        // Reproduces the race condition the plan warns about:
        // the waiter registers notified() before re-checking get().
        let cap = std::sync::Arc::new(PublicUrlCapture::default());
        let cap2 = std::sync::Arc::clone(&cap);

        let handle = tokio::spawn(async move { cap2.captured().await });

        // Give the spawned task time to enter the loop and register notified().
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        cap.offer("https://race.run.app".to_string());

        let url = tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("should not time out")
            .expect("task should not panic");
        assert_eq!(url, "https://race.run.app");
    }
}
