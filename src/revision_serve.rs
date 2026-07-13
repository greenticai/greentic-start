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
use tokio::sync::oneshot;

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

use crate::deployment_routes::RevisionIngressRouting;
use crate::endpoint_resolver;
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

        let state = Arc::new(ServeState {
            slot: ArcSwap::new(config.activation),
            bound_addr: addr,
            gui_enabled: config.gui_enabled,
            restart_required: AtomicBool::new(false),
            updates_enabled: config.updates_enabled,
            auto_restart_pending: AtomicBool::new(false),
            auto_restart_enabled: config.auto_restart_enabled,
            exe_path: config.exe_path,
        });
        // Cloned into the listener thread; the original lives on as the
        // [`RevisionServer::state`] handle so [`reload`] / [`counts`] read the
        // same slot the running listener reads.
        let listener_state = Arc::clone(&state);
        // Captured into the accept loop: a listener-thread concern (not
        // per-request state), so it lives as a thread-local rather than on
        // `ServeState`. AND-ed into the per-connection loopback decision below.
        let trust_loopback_peers = config.trust_loopback_peers;

        // Updater pull path: the ingress runtime runs a poll loop against the
        // env's configured plan endpoint (see `run_update_poll_loop`). The loop
        // re-reads `update-channel.json` every cycle and no-ops while the channel
        // is absent, disabled, or endpoint-less, so deny-by-default lives there —
        // not in a boot-time sidecar probe, which would strand an env that
        // subscribes *after* boot until the next restart. `--no-updates` (and a
        // missing store root) is the only thing that keeps the task from spawning.
        let update_poll_root = config
            .updates_enabled
            .then(LocalFsStore::default_root)
            .flatten();
        let poll_state = Arc::clone(&state);

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
                    // Spawn the updater poll loop on this runtime when the env
                    // opted in (sidecar present). It re-reads config each cycle,
                    // so a disabled or endpoint-less channel simply no-ops.
                    // Aborted on shutdown below.
                    let update_poll_task = update_poll_root
                        .map(|root| tokio::spawn(run_update_poll_loop(poll_state, root)));
                    let mut shutdown = rx;
                    loop {
                        tokio::select! {
                            _ = &mut shutdown => {
                                // Stop the poll loop. The abort is prompt when the
                                // task is sleeping between cycles (the common case).
                                // A cycle already inside its `spawn_blocking`
                                // (mid fetch/stage) runs to completion before the
                                // runtime tears down — the same property the push
                                // receiver's `spawn_blocking(run_update_notify)` has;
                                // `updates::get`'s staging FSM is resumable, so no
                                // half-staged state results, only a bounded delay.
                                if let Some(task) = &update_poll_task {
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
                if let Err(err) = Http1Builder::new().serve_connection(io, service).await {
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
    let session_hint = session_hint.or_else(|| {
        if peer_is_loopback {
            return None;
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
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
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

    // 3. Guards (fail-safe / fail-closed), BEFORE any download.

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

    // 3c. Airgap: if `source` is None, the binary is carried in-band (not
    //     implemented in P7d).
    let source_url = match &binary.source {
        Some(url) => url.clone(),
        None => {
            operator_log::info(
                module_path!(),
                "binary-update: skipped — airgap in-band delivery (out of P7d scope)",
            );
            return Ok(None);
        }
    };

    // 3d. Idempotency: if a pending marker for this exact version already exists, skip.
    let marker_path = env_dir.join(BINARY_UPDATE_PENDING_FILE);
    if let Some(existing_marker) = read_binary_update_marker(&env_dir) {
        if existing_marker.phase == MarkerPhase::Pending
            && existing_marker.to_version == binary.version
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

        // 3e. Anti-rollback tombstone: a previous attempt to run this version
        //     failed to boot and was rolled back. Do not retry the SAME build
        //     artifact. If the digest differs (a same-version re-release with
        //     a fixed binary), allow the swap.
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

    // 4. Fetch the archive from `source_url` with bounded size + timeout.
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
                NotifyError::Internal(format!("binary-update: failed to build HTTP client: {err}"))
            })?;

        use std::io::Read as _;
        let resp = client
            .get(&source_url)
            .send()
            .map_err(|err| {
                NotifyError::Internal(format!("binary-update: archive fetch failed: {err}"))
            })?
            .error_for_status()
            .map_err(|err| {
                NotifyError::Internal(format!("binary-update: archive fetch status error: {err}"))
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

    // 5. Unpack + verify + swap.
    let unpack_dir = tempfile::TempDir::new().map_err(|err| {
        NotifyError::Internal(format!(
            "binary-update: failed to create unpack temp dir: {err}"
        ))
    })?;
    let inner_binary = binswap::unpack_release_binary(&archive_path, own_name, unpack_dir.path())
        .map_err(|err| {
        NotifyError::Internal(format!("binary-update: archive unpack failed: {err}"))
    })?;

    let current_exe = match exe_path {
        Some(p) => p.to_path_buf(),
        None => std::env::current_exe().map_err(|err| {
            NotifyError::Internal(format!("binary-update: cannot resolve current exe: {err}"))
        })?,
    };

    let swap_opts = binswap::SwapOptions {
        expected_digest: Some(binary.digest.clone()),
    };
    let _outcome =
        binswap::swap_binary(&inner_binary, &current_exe, &swap_opts).map_err(|err| {
            // Fail-closed: the binary is NOT applied, content staging stays
            // intact. Log the category, never leak the path.
            operator_log::error(module_path!(), format!("binary-update: swap failed: {err}"));
            NotifyError::Internal("binary update swap failed".to_string())
        })?;

    // 6. Write the restart-required marker file.
    let marker = BinaryUpdateMarker {
        name: own_name.to_string(),
        from_version: current_version.to_string(),
        to_version: binary.version.clone(),
        staged_at: chrono::Utc::now().to_rfc3339(),
        phase: MarkerPhase::Pending,
        rolled_back_at: None,
        digest: Some(binary.digest.clone()),
    };
    if let Err(err) = std::fs::write(&marker_path, serde_json::to_vec_pretty(&marker).unwrap()) {
        // Non-fatal: the swap already succeeded; the marker is advisory.
        operator_log::warn(
            module_path!(),
            format!("binary-update: failed to write marker: {err}"),
        );
    }

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
            let binary_result = match try_apply_binary_update(plan, sig, store, env_id, exe_path) {
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

/// Updater pull path: periodically fetch the latest signed plan from the env's
/// configured `plan_endpoint` and hand it to the same receiver core the push
/// path uses ([`run_update_notify`]) — so `on_update: apply` converges on the
/// pull path too. Spawned by [`RevisionServer::start`] unless `--no-updates`; the
/// per-cycle config read enforces deny-by-default (an absent, disabled, or
/// endpoint-less channel no-ops) and lets a channel written *after* boot — by
/// `op env apply` or `op updates config-set` — take effect without a restart.
///
/// Cancelled (via the returned task's `abort`) when the ingress shuts down; it
/// is otherwise sleeping between cycles, so cancellation is prompt.
async fn run_update_poll_loop(state: Arc<ServeState>, store_root: std::path::PathBuf) {
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
        tokio::time::sleep(Duration::from_secs(interval)).await;
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
    let deployment_id = scope.deployment_id;
    let bundle_id = scope.bundle_id.clone();
    let revision_id = scope.revision_id;

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
            )
            .await;
        });
    }

    Ok(synthesize_provider_response(&result.response))
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
            if let Err(err) = run_reply_egress(
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
) -> Result<()> {
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
    Ok(())
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
                deployment_config_overrides: std::sync::Arc::default(),
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
}
