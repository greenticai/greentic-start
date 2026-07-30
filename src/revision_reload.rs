//! Runtime-config watcher — the N2.2 producer for the N2.1 `RevisionServer::reload`
//! primitive.
//!
//! When `gtc start` runs without `--bundle`, [`crate::lib`] spawns this
//! watcher on the env directory. The deployer mutates
//! `<env_dir>/runtime-config.json` via atomic rename (see
//! `greentic-deployer/src/environment/store.rs::save_runtime_config_locked`
//! → `atomic_write_json`) whenever the operator runs `bundles add`,
//! `revisions stage/warm`, or `traffic set`. The watcher observes those
//! file events through `notify-debouncer-full`, coalesces a burst of
//! writes inside a debounce window, and on each coalesced event rebuilds
//! the runtime-config activation (via [`crate::revision_boot::activate_runtime_config`])
//! and hands the new activation to [`crate::revision_serve::RevisionServer::reload`].
//!
//! Some env-side mutations don't touch `runtime-config.json` — notably
//! `op messaging endpoint {add,link-bundle,unlink-bundle,set-welcome-flow,remove}`,
//! which writes `environment.json` plus the `messaging/` projection but
//! leaves `runtime-config.json` alone. The admit table in
//! [`crate::endpoint_admit`] is derived from `Environment.messaging_endpoints`,
//! so the watcher must also fire on `environment.json` writes — otherwise an
//! ACL revocation would not take effect on a running server until the next
//! unrelated runtime-config write or a restart. The rebuild's dedup
//! compares both the loaded `runtime-config` and the loaded `Environment`,
//! so an unrelated `environment.json` rewrite that produces identical content
//! still short-circuits, but a real ACL change always re-activates.
//!
//! The producer is intentionally tolerant: a malformed `runtime-config.json`,
//! a missing `environment.json`, or any other failure inside the rebuild
//! closure is logged and the previous activation keeps serving. The watcher
//! itself only exits when the [`WatcherHandle`] is dropped or the underlying
//! file-system thread shuts down (both happen on `Ctrl+C`).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use notify_debouncer_full::notify::RecursiveMode;
use notify_debouncer_full::{
    DebounceEventResult, Debouncer, RecommendedCache, new_debouncer, notify::RecommendedWatcher,
};

use greentic_deploy_spec::Environment;
use greentic_deployer::environment::{EnvironmentStore, LocalFsStore};
use greentic_runner_host::runtime_refs::RuntimeRefResolver;
use greentic_types::EnvId;

/// Keep in sync with `greentic-deployer/src/environment/store.rs::environment_path`.
const ENVIRONMENT_FILE: &str = "environment.json";

use crate::operator_log;
use crate::revision_boot::{self, RuntimeConfigActivation};
use crate::revision_pin::RevisionPinStore;
use crate::revision_secrets;
use crate::revision_serve::{Activation, RevisionServer};
use crate::runtime_config::{self, LoadedRuntimeConfig};
use crate::secrets_gate::DynSecretsManager;

/// Default debounce window for coalescing the deployer's commonly bundled
/// `bundles add → revisions stage → traffic set` write sequence into a
/// single rebuild. Tuned to be wider than the deployer's per-verb fsync
/// latency on a warm cache (typical 5–30ms) and narrower than the
/// operator's interactive expectation of "the change took effect".
pub(crate) const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(250);

/// Maximum number of re-read attempts when the torn-write guard detects a
/// newly-unbacked Active deployment. Each attempt sleeps `DEFAULT_DEBOUNCE`
/// before re-reading. If all are exhausted and the pair is still torn, the
/// rebuild proceeds with a warning (the state may be legitimate — see comment
/// in `rebuild_once`).
const TORN_WRITE_MAX_RETRIES: u32 = 3;

/// Owned cleanup handle: dropping it shuts the debouncer (which closes the
/// event channel) and joins the worker thread, so callers don't need to
/// remember a separate `stop()` call.
pub(crate) struct WatcherHandle {
    /// Wrapped in `Option` so [`Drop`] can `.take()` it and drop the
    /// debouncer BEFORE joining the worker. Drop order matters: the worker
    /// loops over the channel the debouncer feeds; dropping the worker
    /// first (or leaving the debouncer alive when joining) blocks the
    /// join forever because the channel never closes.
    debouncer: Option<Debouncer<RecommendedWatcher, RecommendedCache>>,
    worker: Option<JoinHandle<()>>,
}

impl Drop for WatcherHandle {
    fn drop(&mut self) {
        // Drop the debouncer FIRST so it signals its internal tick thread
        // to stop. The event channel doesn't close synchronously here —
        // `Debouncer::drop` only sets an atomic stop flag and detaches its
        // tick thread; the channel closes when that thread wakes from its
        // next tick (~timeout/4 = 62.5ms), sees the flag, and drops the
        // `Sender` it owns. The worker join below blocks until that happens,
        // so reversing this order (joining before dropping the debouncer)
        // would deadlock — the channel would never close.
        drop(self.debouncer.take());
        if let Some(h) = self.worker.take() {
            // Worker exits when the event channel disconnects. Join logs a
            // warning if the worker panicked; we don't bubble it because
            // Drop must not panic.
            if let Err(err) = h.join() {
                operator_log::warn(
                    module_path!(),
                    format!("runtime-config watcher worker panicked: {err:?}"),
                );
            }
        }
    }
}

/// Spawn the runtime-config file-watcher.
///
/// One `notify-debouncer-full` instance watches the env directory and
/// dispatches per-batch to TWO independent actions:
///
/// 1. `rebuild` + `server.reload` + `post_reload` — when an event touches
///    `runtime-config.json` or `environment.json` (the activation-bearing
///    files). Identical to the pre-C5 behaviour.
/// 2. `snapshot_reload` — when an event touches `runtime.json` (the C5
///    `EnvironmentRuntime` sidecar). Cheap snapshot swap; no activation
///    rebuild.
///
/// Both can fire from a single debounced batch (the deployer's `apply` writes
/// runtime-config.json AND runtime.json together). Coalescing them onto one
/// debouncer halves the inotify watches + worker threads vs spawning two.
///
/// `rebuild` returns a [`ReloadOutcome`]:
/// - `Full(activation)` to swap a rebuilt activation into `server`,
/// - `RoutingOnly(env)` to swap only the env-derived routing, sharing the live
///   host and dispatcher,
/// - `Unchanged` to skip the swap (e.g. hash-skip on identical content),
/// - `Err(_)` to log + keep the previous activation serving.
///
/// The watcher takes ownership of every closure for the worker's lifetime;
/// they are dropped when the returned [`WatcherHandle`] is dropped.
///
/// `post_reload` runs AFTER `server.reload` swapped the new activation in.
/// Side effects that need the new routes to be live (e.g. provider webhook
/// re-registration, which an external provider may validate or deliver to
/// immediately) belong there, never inside `rebuild` — the server still
/// serves the OLD activation while `rebuild` runs, so a slow side effect
/// inside `rebuild` would also delay the swap itself.
pub(crate) fn spawn_runtime_config_watcher<R, P, S>(
    env_dir: PathBuf,
    debounce: Duration,
    drain_window: Duration,
    server: Arc<RevisionServer>,
    rebuild: R,
    post_reload: P,
    snapshot_reload: S,
) -> Result<WatcherHandle>
where
    R: FnMut() -> Result<ReloadOutcome> + Send + 'static,
    P: FnMut(&Activation) + Send + 'static,
    S: FnMut() + Send + 'static,
{
    let env_dir = env_dir.canonicalize().unwrap_or(env_dir);

    // Activation triggers: paths whose mutations must invalidate the
    // RevisionServer's current activation. `runtime-config.json` is the
    // original trigger; `environment.json` is the M1.4c-ii fix so messaging
    // endpoint mutations (which only touch env.json + the messaging
    // projection) re-activate the admit table.
    let activation_targets = vec![
        env_dir.join(runtime_config::RUNTIME_CONFIG_FILE),
        env_dir.join(ENVIRONMENT_FILE),
    ];
    // Snapshot triggers: paths whose mutations must refresh the C5
    // `EnvironmentRuntime` snapshot used by the `runtime://` resolver.
    let snapshot_targets = vec![env_dir.join(crate::runtime_refs_store::RUNTIME_FILE)];
    let (tx, rx) = mpsc::channel::<DebounceEventResult>();

    // notify watches the env DIR (not the file): the deployer rewrites
    // `runtime-config.json` via atomic rename, which swaps the inode out
    // from under any per-file watch. A non-recursive directory watch sees
    // the rename-into-place as a create/modify event on the basename.
    let mut debouncer = new_debouncer(debounce, None, move |res| {
        // Drop on send failure — the worker has exited and we're shutting
        // down. The OS-level watcher's drop will be observed via the same
        // channel close.
        let _ = tx.send(res);
    })
    .context("creating runtime-config debouncer")?;
    debouncer
        .watch(&env_dir, RecursiveMode::NonRecursive)
        .with_context(|| format!("watching env directory {}", env_dir.display()))?;

    let worker = thread::Builder::new()
        .name("revision-reload".to_string())
        .spawn(move || {
            reload_worker(
                rx,
                activation_targets,
                snapshot_targets,
                drain_window,
                server,
                rebuild,
                post_reload,
                snapshot_reload,
            );
        })
        .context("spawning runtime-config reload worker")?;

    Ok(WatcherHandle {
        debouncer: Some(debouncer),
        worker: Some(worker),
    })
}

/// The worker loop. Reads debounced batches off `rx`, classifies the touched
/// paths against `activation_targets` and `snapshot_targets`, and dispatches:
/// snapshot_reload fires first (cheap, makes new discovered values visible to
/// any in-flight invocation about to run on the swapped activation); rebuild
/// + server.reload + post_reload fire second.
///
/// Extracted from `spawn_runtime_config_watcher` so tests can drive the
/// worker directly without going through `notify`.
#[allow(clippy::too_many_arguments)]
fn reload_worker<R, P, S>(
    rx: mpsc::Receiver<DebounceEventResult>,
    activation_targets: Vec<PathBuf>,
    snapshot_targets: Vec<PathBuf>,
    drain_window: Duration,
    server: Arc<RevisionServer>,
    mut rebuild: R,
    mut post_reload: P,
    mut snapshot_reload: S,
) where
    R: FnMut() -> Result<ReloadOutcome> + Send + 'static,
    P: FnMut(&Activation) + Send + 'static,
    S: FnMut() + Send + 'static,
{
    for result in rx {
        let events = match result {
            Ok(events) => events,
            Err(errs) => {
                for err in errs {
                    operator_log::warn(
                        module_path!(),
                        format!("runtime-config watcher notify error: {err}"),
                    );
                }
                continue;
            }
        };
        // Classify: which target sets did this batch touch? `notify` reports
        // every event under the watched directory; an unrelated
        // `revision-signing.key` write must NOT trigger anything. Backup
        // files (`environment.json.<ts>.bak`) don't match either — path
        // equality, not prefix matching.
        let touches = |targets: &[PathBuf]| {
            events.iter().any(|ev| {
                ev.event
                    .paths
                    .iter()
                    .any(|p| targets.iter().any(|t| p == t))
            })
        };
        let touches_snapshot = touches(&snapshot_targets);
        let touches_activation = touches(&activation_targets);
        if !touches_snapshot && !touches_activation {
            continue;
        }
        // Snapshot first: cheap, makes new discovered values visible before
        // the activation rebuild that might run against them.
        if touches_snapshot {
            snapshot_reload();
        }
        if !touches_activation {
            continue;
        }
        // Re-check after every rebuild. `rebuild()` snapshots the env files at
        // the moment it runs, and a write that lands DURING that rebuild is not
        // guaranteed to arrive as a separate debounced batch — notify can
        // coalesce it into the batch already being drained. When that happens
        // the rebuild publishes an activation derived from the PRE-write files
        // and nothing re-reads them, so the write is silently lost until some
        // unrelated event touches the directory again.
        //
        // Observed 2026-07-25: `op config set --default-bundle legal` landed
        // while a prior rebuild was in flight; the reload that followed still
        // carried `default_bundle=acct`, and the change only took effect 11s
        // later when the next write happened to fire. On a quiet system there
        // is no next write, so the loss is permanent, not merely delayed.
        //
        // The loop is cheap: `rebuild()` dedups on (rc, env) and returns
        // Ok(None) the moment the inputs stop changing, so the steady state
        // costs exactly one extra file read per batch. `MAX_RECHECKS` bounds a
        // pathological writer that mutates the env faster than we can rebuild —
        // we give up the tight loop and let the next batch carry it, rather
        // than spinning here forever.
        const MAX_RECHECKS: usize = 8;
        for attempt in 0..=MAX_RECHECKS {
            let outcome = match rebuild() {
                Ok(outcome) => outcome,
                Err(err) => {
                    operator_log::error(
                        module_path!(),
                        format!("runtime-config reload failed: {err:#}"),
                    );
                    break;
                }
            };
            let (report, live, kind) = match outcome {
                ReloadOutcome::Unchanged => {
                    // Inputs are stable — the activation now reflects the
                    // latest bytes on disk. This is the only exit that
                    // guarantees no write was lost.
                    break;
                }
                ReloadOutcome::RoutingOnly(env) => {
                    // No revision or pack moved, so the host and dispatcher are
                    // carried forward: no WASM re-instantiation, no second host
                    // resident for the drain window, and — because the host
                    // owns every revision's session and state store — no
                    // in-flight conversation loses its history across the swap.
                    let (report, live) = server.reload_routing_only(|current| {
                        revision_boot::reactivate_routing_only(&current.routing, &env)
                    });
                    (report, live, "routing")
                }
                ReloadOutcome::Full(activation) => {
                    // Clone (two Arc bumps) so the post-reload hook observes the
                    // SAME (host, routing) pair the server now serves; the hook
                    // fires only after the swap below.
                    let live = activation.clone();
                    (server.reload(activation, drain_window), live, "full")
                }
            };
            operator_log::info(
                module_path!(),
                format!(
                    "runtime-config reloaded ({kind}): {} → {} deployment(s), {} → {} revision(s)",
                    report.prev_deployments,
                    report.new_deployments,
                    report.prev_revisions,
                    report.new_revisions,
                ),
            );
            post_reload(&live);
            if attempt == MAX_RECHECKS {
                operator_log::warn(
                    module_path!(),
                    "runtime-config still changing after MAX_RECHECKS rebuilds; \
                     deferring to the next watcher batch",
                );
            }
            // Inputs changed, so go round again: another write may have landed
            // while THIS rebuild was running.
        }
    }
}

/// Snapshot of the inputs that produced the current activation, kept by
/// [`default_rebuild`] for content-based dedup. Both `rc` and `env` are
/// tracked because the activation derives state from both — `rc` drives
/// the dispatcher; `env` drives the deployment route table AND the
/// M1.4c-ii endpoint admit table — and either can change without the other
/// (notably, `op messaging endpoint *` mutates env but not rc).
#[derive(Debug, PartialEq, Eq)]
struct LastReloadInputs {
    rc: LoadedRuntimeConfig,
    env: Environment,
}

/// How the watched files changed, and therefore how much of the activation has
/// to be rebuilt. Produced by [`rebuild_once`], consumed by [`reload_worker`].
///
/// The classification exists because [`crate::revision_boot::activate_runtime_config`]
/// is expensive in a way that is invisible at three bundles and painful at
/// twenty: it constructs a fresh `RunnerHost` with every revision's packs
/// re-instantiated (WASM compile), and the superseded host stays resident for
/// the whole drain window. Flipping `host_config.default_bundle` — one string —
/// used to pay all of that.
pub(crate) enum ReloadOutcome {
    /// Inputs are byte-identical to what produced the live activation. Nothing
    /// to publish; skip the swap so cookies and pins aren't churned.
    Unchanged,
    /// Only env-derived routing changed. Carries the freshly loaded
    /// `Environment`; the worker turns it into routing against the live
    /// activation inside
    /// [`RevisionServer::reload_routing_only`](crate::revision_serve::RevisionServer::reload_routing_only),
    /// so the host and dispatcher are shared rather than rebuilt.
    RoutingOnly(Box<Environment>),
    /// Something reached the revisions or the packs. Full swap, with drain.
    Full(Activation),
}

/// Build the production rebuild closure: loads + dedupes + activates.
/// The returned closure carries [`LastReloadInputs`] so identical-content
/// writes (the deployer occasionally rewrites the same content on no-op
/// operations) short-circuit before the expensive `activate_runtime_config`.
///
/// `activation_rt` is the Tokio runtime [`crate::lib::run_start`] already
/// built for cold-start activation; we re-use it so the rebuilt host is
/// constructed on the same runtime that the original was — keeping any
/// async resources affine to one runtime.
///
/// `pin_store` is the SAME `Arc` the cold-start activation was built with, so
/// every rebuilt dispatcher shares one session-pin store across reloads (B1a).
/// A reweight rebuilds the dispatcher but must not drop live pins.
#[allow(clippy::too_many_arguments)]
pub(crate) fn default_rebuild(
    store_root: PathBuf,
    env_id: String,
    secrets: DynSecretsManager,
    secrets_tenant_scope: Option<String>,
    runtime_ref_resolver: Arc<dyn RuntimeRefResolver>,
    pin_store: Arc<dyn RevisionPinStore>,
    activation_rt: tokio::runtime::Handle,
    revision_stores: revision_boot::RevisionStores,
    initial: Option<(LoadedRuntimeConfig, Environment)>,
) -> impl FnMut() -> Result<ReloadOutcome> + Send + 'static {
    // Seed the dedup snapshot with the inputs the COLD-START activation was
    // built from. Without it the first watched-file change after boot has
    // nothing to diff against and is forced down the full path — so the very
    // first `op config set --default-bundle` of a process rebuilt the whole
    // host, which is exactly the reload most likely to land while someone is
    // mid-conversation. Observed in `my_demos/multi-url-webchat-demo` Phase 7:
    // the first flip lost a reply, the second (identical in kind) did not.
    let mut last: Option<LastReloadInputs> = initial.map(|(rc, env)| LastReloadInputs { rc, env });
    move || {
        rebuild_once(
            &store_root,
            &env_id,
            &secrets,
            secrets_tenant_scope.as_deref(),
            &runtime_ref_resolver,
            &pin_store,
            &activation_rt,
            &revision_stores,
            &mut last,
        )
    }
}

/// Load the two files a reload activates from. Split out so the torn-write
/// re-read in [`rebuild_once`] reads them the same way the first pass did.
fn load_reload_inputs(
    store_root: &Path,
    env_id: &str,
) -> Result<(LoadedRuntimeConfig, Environment)> {
    let rc = runtime_config::load_in(store_root, env_id)?.unwrap_or_else(|| LoadedRuntimeConfig {
        env_id: env_id.to_string(),
        revisions: Vec::new(),
    });
    let store = LocalFsStore::new(store_root.to_path_buf());
    let env_typed =
        EnvId::new(env_id).with_context(|| format!("invalid environment id `{env_id}`"))?;
    let environment = EnvironmentStore::load(&store, &env_typed)
        .with_context(|| format!("loading environment `{env_id}` for reload"))?;
    Ok((rc, environment))
}

/// Returns the set of deployment ids that are newly unbacked (Active in the
/// environment with no revision block in the runtime-config) relative to a
/// previously-observed set. An empty return means either no unbacked deployments
/// exist or all of them were already known — i.e. the torn-write window has
/// closed or the state is the legitimate `op bundles add` steady state.
///
/// Factored out as a pure function so the bounded-retry decision logic in
/// `rebuild_once` is independently testable without real files or sleeps.
fn torn_write_newly_unbacked(
    current_unbacked: &std::collections::BTreeSet<String>,
    previously_unbacked: &std::collections::BTreeSet<String>,
) -> Vec<String> {
    current_unbacked
        .iter()
        .filter(|id| !previously_unbacked.contains(id.as_str()))
        .cloned()
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn rebuild_once(
    store_root: &Path,
    env_id: &str,
    secrets: &DynSecretsManager,
    secrets_tenant_scope: Option<&str>,
    runtime_ref_resolver: &Arc<dyn RuntimeRefResolver>,
    pin_store: &Arc<dyn RevisionPinStore>,
    activation_rt: &tokio::runtime::Handle,
    revision_stores: &revision_boot::RevisionStores,
    last: &mut Option<LastReloadInputs>,
) -> Result<ReloadOutcome> {
    let (mut rc, mut environment) = load_reload_inputs(store_root, env_id)?;
    // `environment.json` and `runtime-config.json` are two separate writes: the
    // deployer's `env-deploy` adds the deployment to the environment and the
    // revision block to the runtime-config in sequence, not atomically. A
    // reload that reads between them sees an Active deployment with no revision
    // to serve, and activating that publishes routing for a bundle the
    // dispatcher cannot dispatch to — every request to it fails with
    // `deployment ... not known to dispatcher`. It also burns a full activation
    // (WASM re-instantiation for every revision) on a state that is superseded
    // milliseconds later.
    //
    // This window has always existed; it was invisible only because every
    // reload used to take seconds of WASM work, so the second write reliably
    // landed before the files were read. Making the common reload cheap (D2)
    // made it observable, and `my_demos/multi-url-webchat-demo` Phase 8 caught
    // it: the hot-attached bundle 502'd because its routing went live a full
    // activation ahead of its revision.
    //
    // Bounded retry: if a deployment is newly Active-but-unbacked, wait one
    // debounce window and re-read, up to `TORN_WRITE_MAX_RETRIES` times.
    // `newly` is what keeps this free in the steady state — `op bundles add`
    // legitimately creates a deployment before `revisions stage` supplies its
    // block, and once that state has been observed in `previously_unbacked` it
    // is not a torn write and never waits again.
    //
    // If all retries are exhausted and the pair is still torn, we proceed with
    // a warning rather than returning early. An Active deployment with no
    // revision block IS a legitimate steady state (`op bundles add` before
    // `revisions stage`), and refusing to publish would silently drop a genuine
    // environment change (e.g. a `default_bundle` flip) written in the same
    // batch for as long as that deployment stays unstaged.
    let previously_unbacked = last
        .as_ref()
        .map(|prev| revision_boot::unbacked_active_deployments(&prev.rc, &prev.env))
        .unwrap_or_default();
    let mut newly_unbacked = torn_write_newly_unbacked(
        &revision_boot::unbacked_active_deployments(&rc, &environment),
        &previously_unbacked,
    );
    if !newly_unbacked.is_empty() {
        for _ in 0..TORN_WRITE_MAX_RETRIES {
            std::thread::sleep(DEFAULT_DEBOUNCE);
            (rc, environment) = load_reload_inputs(store_root, env_id)?;
            newly_unbacked = torn_write_newly_unbacked(
                &revision_boot::unbacked_active_deployments(&rc, &environment),
                &previously_unbacked,
            );
            if newly_unbacked.is_empty() {
                break;
            }
        }
        // Non-empty here means every retry saw the same tear, so `newly_unbacked`
        // already describes the final read — no need to recompute it.
        if !newly_unbacked.is_empty() {
            operator_log::warn(
                module_path!(),
                format!(
                    "torn-write guard exhausted {TORN_WRITE_MAX_RETRIES} retries; \
                     deployment(s) {newly_unbacked:?} are Active-but-unbacked — routing \
                     for them will not be dispatchable until their revision block lands",
                ),
            );
        }
    }
    // Dedup AFTER both reads — neither file alone is a sufficient key. An
    // env.json rewrite with no real change short-circuits here even though
    // the watcher fired, so cookies/pins aren't churned by no-op writes.
    if let Some(prev) = last.as_ref()
        && prev.rc == rc
        && prev.env == environment
    {
        return Ok(ReloadOutcome::Unchanged);
    }
    // D2 fast path: the runtime-config is untouched and the environment changed
    // only in ways that cannot reach the host or any pack manifest. Hand the
    // environment back so the worker can rebuild the four env-derived routing
    // tables against the live activation under the reload lock, skipping the
    // WASM work entirely. Requires a previous snapshot to compare against — on
    // the first rebuild after boot there is none, so that one takes the full
    // path.
    if let Some(prev) = last.as_ref()
        && prev.rc == rc
        && revision_boot::env_routing_only_delta(&prev.env, &environment)
    {
        *last = Some(LastReloadInputs {
            rc,
            env: environment.clone(),
        });
        return Ok(ReloadOutcome::RoutingOnly(Box::new(environment)));
    }
    // A reload can attach revisions of packs whose `generated` secrets were
    // never minted (the deployer stages packs, not secrets). Seed before
    // activating, exactly like the cold-start boot; on failure this reload is
    // aborted (logged by the watcher) and the old activation keeps serving.
    let env_dir = runtime_config::env_dir_in(store_root, env_id)?;
    activation_rt.block_on(revision_secrets::ensure_generated_secrets_for_activation(
        &env_dir,
        &rc,
        &environment,
    ))?;
    let RuntimeConfigActivation { host, routing } =
        activation_rt.block_on(revision_boot::activate_runtime_config(
            store_root,
            &rc,
            Arc::clone(secrets),
            secrets_tenant_scope,
            &environment,
            Arc::clone(runtime_ref_resolver),
            Arc::clone(pin_store),
            revision_stores,
        ))?;
    *last = Some(LastReloadInputs {
        rc,
        env: environment,
    });
    Ok(ReloadOutcome::Full(Activation {
        host: Arc::new(host),
        routing: Arc::new(routing),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc as std_mpsc;
    use std::time::Instant;

    /// A counting rebuild closure suitable for unit tests. Returns
    /// `Unchanged` always (no real activation is built) but increments a
    /// counter so the test can assert how many rebuild attempts the
    /// watcher actually fired.
    fn counting_rebuild(
        counter: Arc<AtomicUsize>,
    ) -> impl FnMut() -> Result<ReloadOutcome> + Send + 'static {
        move || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(ReloadOutcome::Unchanged)
        }
    }

    /// Same as `counting_rebuild`, but routes each fired rebuild through a
    /// channel so the test can await the next firing deterministically.
    fn channel_rebuild(
        tx: std_mpsc::Sender<()>,
    ) -> impl FnMut() -> Result<ReloadOutcome> + Send + 'static {
        move || {
            let _ = tx.send(());
            Ok(ReloadOutcome::Unchanged)
        }
    }

    fn fresh_env_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("create temp env dir")
    }

    fn write_runtime_config(env_dir: &Path, body: &str) {
        std::fs::write(env_dir.join(runtime_config::RUNTIME_CONFIG_FILE), body)
            .expect("write runtime-config");
    }

    fn delete_runtime_config(env_dir: &Path) {
        std::fs::remove_file(env_dir.join(runtime_config::RUNTIME_CONFIG_FILE))
            .expect("delete runtime-config");
    }

    fn write_environment_json(env_dir: &Path, body: &str) {
        std::fs::write(env_dir.join(ENVIRONMENT_FILE), body).expect("write environment.json");
    }

    // The reload worker requires a `RevisionServer`. The test-only
    // constructor in `revision_serve::tests` is module-private; we build a
    // production-style one over a free port. Tests that exercise the
    // server side of the reload are kept short to avoid port contention.
    //
    // For watcher-only tests we use an `Arc::new(...)` placeholder and a
    // counting rebuild that returns `Ok(None)` so `server.reload` is
    // never called — the only paths exercised are filter + dedup + error
    // isolation.
    /// A minimal `Activation` for tests that only need the worker to observe
    /// "the rebuild produced something". Shares the same construction path as
    /// `placeholder_server`; neither the host nor the routing is exercised.
    fn placeholder_activation() -> Activation {
        use crate::deployment_routes::{DeploymentRouteTable, RevisionIngressRouting};
        use crate::endpoint_admit::EndpointAdmit;
        use crate::http_routes::HttpRouteTable;
        use crate::revision_dispatcher::{RevisionDispatcher, RevisionDispatcherConfig};
        use greentic_runner_host::{HostBuilder, HostConfig, TenantBindings};

        let host = Arc::new(
            HostBuilder::new()
                .with_config(HostConfig::from_gtbind(TenantBindings {
                    tenant: "watcher-test".to_string(),
                    packs: Vec::new(),
                    env_passthrough: Vec::new(),
                }))
                .build()
                .expect("build placeholder host"),
        );
        let dispatcher = Arc::new(RevisionDispatcher::new(RevisionDispatcherConfig::new(
            "watcher-test",
            [0u8; 32],
        )));
        Activation {
            host,
            routing: Arc::new(RevisionIngressRouting {
                dispatcher,
                http_routes: HttpRouteTable::from_descriptors(Vec::new()),
                deployment_routes: DeploymentRouteTable::default(),
                endpoint_admit: Arc::new(EndpointAdmit::default()),
                deployment_config_overrides: Arc::default(),
                static_routes: crate::static_routes::ActiveRouteTable::default(),
                bundle_index: crate::webchat_routing::BundleIndex::empty(),
                flow_index: crate::webchat_routing::FlowIndex::default(),
            }),
        }
    }

    fn placeholder_server() -> Arc<RevisionServer> {
        // RevisionServer doesn't expose a no-op test ctor publicly. Use
        // RevisionServer::start with the same placeholder activation the
        // rebuild-returning tests publish, so the two cannot drift.
        use crate::revision_serve::{RevisionServeConfig, RevisionServer};
        use std::net::SocketAddr;

        let activation = Arc::new(placeholder_activation());
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        Arc::new(
            RevisionServer::start(RevisionServeConfig {
                bind_addr: bind,
                activation,
                gui_enabled: false,
                trust_loopback_peers: true,
                admin_bind_addr: None,
                updates_enabled: false,
                auto_restart_enabled: false,
                exe_path: None,
                public_url_capture: None,
            })
            .expect("placeholder server"),
        )
    }

    /// D1 regression: a write that lands DURING a rebuild must not be lost.
    ///
    /// `rebuild()` snapshots the env files when it runs. A write arriving while
    /// it is in flight is not guaranteed to come back as a separate debounced
    /// batch — notify can coalesce it into the batch already being drained. The
    /// pre-fix worker called `rebuild()` exactly once per batch, so that write
    /// was silently lost until some unrelated event touched the directory.
    ///
    /// Observed live 2026-07-25: `op config set --default-bundle legal` landed
    /// during a prior rebuild; the reload that followed still carried
    /// `default_bundle=acct`, and the change only took effect 11s later when an
    /// unrelated write fired. On a quiet system there is no next write.
    ///
    /// The closure below models exactly that: the first call reports changed
    /// inputs (Some), the second reports them stable (None). A worker that
    /// re-checks calls it twice; one that trusts a single snapshot calls it once
    /// and publishes the stale activation.
    ///
    /// MUTATION PROOF: replace the `for attempt in 0..=MAX_RECHECKS` loop in
    /// `reload_worker` with a bare `match rebuild()` and this fails with
    /// `rebuild called 1 time(s), want 2`.
    #[test]
    fn write_during_rebuild_is_not_lost() {
        use std::sync::mpsc as std_mpsc;

        let (tx, rx) = std_mpsc::channel::<DebounceEventResult>();
        let env = fresh_env_dir();
        let target = env.path().join(ENVIRONMENT_FILE);
        write_environment_json(env.path(), r#"{"schema":"x"}"#);

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_closure = Arc::clone(&calls);
        let rebuild = move || -> Result<ReloadOutcome> {
            let n = calls_for_closure.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                // Inputs changed -> a real activation is published. The worker
                // must now ask again, because another write may have landed
                // while this rebuild was running.
                Ok(ReloadOutcome::Full(placeholder_activation()))
            } else {
                // Inputs stable -> nothing left to pick up.
                Ok(ReloadOutcome::Unchanged)
            }
        };

        tx.send(Ok(vec![notify_debouncer_full::DebouncedEvent {
            event: notify_debouncer_full::notify::Event::new(
                notify_debouncer_full::notify::EventKind::Modify(
                    notify_debouncer_full::notify::event::ModifyKind::Any,
                ),
            )
            .add_path(target.clone()),
            time: std::time::Instant::now(),
        }]))
        .expect("send batch");
        drop(tx);

        reload_worker(
            rx,
            vec![target],
            Vec::new(),
            Duration::ZERO,
            placeholder_server(),
            rebuild,
            |_: &Activation| {},
            || {},
        );

        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "rebuild called {} time(s), want 2 — the worker must re-check after \
             a rebuild that changed the activation, or a write landing during \
             that rebuild is lost",
            calls.load(Ordering::SeqCst)
        );
    }

    /// C5: runtime.json writes fire `snapshot_reload` and NOT `rebuild`.
    #[test]
    fn watcher_dispatches_runtime_json_to_snapshot_only() {
        let env = fresh_env_dir();
        let rebuild_counter = Arc::new(AtomicUsize::new(0));
        let snapshot_counter = Arc::new(AtomicUsize::new(0));
        let snapshot_counter_for_closure = Arc::clone(&snapshot_counter);
        let _handle = spawn_runtime_config_watcher(
            env.path().to_path_buf(),
            Duration::from_millis(50),
            Duration::ZERO,
            placeholder_server(),
            counting_rebuild(Arc::clone(&rebuild_counter)),
            |_: &Activation| {},
            move || {
                snapshot_counter_for_closure.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("spawn watcher");

        std::fs::write(
            env.path().join(crate::runtime_refs_store::RUNTIME_FILE),
            br#"{"schema":"x"}"#,
        )
        .expect("write runtime.json");
        std::thread::sleep(Duration::from_millis(400));

        assert!(
            snapshot_counter.load(Ordering::SeqCst) >= 1,
            "runtime.json write must invoke snapshot_reload"
        );
        assert_eq!(
            rebuild_counter.load(Ordering::SeqCst),
            0,
            "runtime.json write must NOT invoke rebuild"
        );
    }

    #[test]
    fn watcher_fires_on_runtime_config_create() {
        let env = fresh_env_dir();
        let (tx, rx) = std_mpsc::channel();
        let _handle = spawn_runtime_config_watcher(
            env.path().to_path_buf(),
            Duration::from_millis(50),
            Duration::ZERO,
            placeholder_server(),
            channel_rebuild(tx),
            |_: &Activation| {},
            || {},
        )
        .expect("spawn watcher");

        write_runtime_config(
            env.path(),
            r#"{"schema":"x","env_id":"local","revisions":[]}"#,
        );

        rx.recv_timeout(Duration::from_secs(3))
            .expect("watcher must fire after the runtime-config is created");
    }

    #[test]
    fn watcher_fires_on_runtime_config_delete() {
        let env = fresh_env_dir();
        write_runtime_config(env.path(), r#"{"a":1}"#);

        let (tx, rx) = std_mpsc::channel();
        let _handle = spawn_runtime_config_watcher(
            env.path().to_path_buf(),
            Duration::from_millis(50),
            Duration::ZERO,
            placeholder_server(),
            channel_rebuild(tx),
            |_: &Activation| {},
            || {},
        )
        .expect("spawn watcher");

        // Some notify backends emit an initial event when the watch
        // starts on a populated dir; drain it.
        let _ = rx.recv_timeout(Duration::from_millis(500));

        delete_runtime_config(env.path());
        rx.recv_timeout(Duration::from_secs(3))
            .expect("watcher must fire after the runtime-config is deleted");
    }

    #[test]
    fn watcher_coalesces_burst_writes_into_one_rebuild() {
        // Narrow enough to keep the debouncer's tick fine-grained, wide
        // enough that a loaded runner still lands the whole burst in one
        // window; the burst is timed below so a runner slow enough to break
        // that premise says so instead of failing as "did not coalesce".
        const DEBOUNCE: Duration = Duration::from_millis(200);

        let env = fresh_env_dir();
        let (tx, rx) = std_mpsc::channel();
        let _handle = spawn_runtime_config_watcher(
            env.path().to_path_buf(),
            DEBOUNCE,
            Duration::ZERO,
            placeholder_server(),
            channel_rebuild(tx),
            |_: &Activation| {},
            || {},
        )
        .expect("spawn watcher");

        let burst_started = Instant::now();
        for i in 0..5 {
            write_runtime_config(env.path(), &format!(r#"{{"i":{i}}}"#));
        }
        let burst = burst_started.elapsed();
        assert!(
            burst < DEBOUNCE,
            "burst of 5 writes took {burst:?}, exceeding the {DEBOUNCE:?} debounce — coalescing was never exercised"
        );

        // Await the flush; do NOT sleep a fixed margin past the debounce.
        // `notify-debouncer-full` only emits on a tick boundary (tick =
        // debounce/4 when unset, as noted in `WatcherHandle::drop`), so the
        // flush lands anywhere in `[debounce, debounce + tick]` depending on
        // how the burst aligns with the tick the debouncer thread is already
        // sleeping in. Any fixed margin narrower than one tick reads the
        // count before the rebuild has run.
        rx.recv_timeout(Duration::from_secs(3))
            .expect("burst of 5 writes must produce a rebuild");

        // Coalescing is the actual claim: the other four writes must not each
        // produce a rebuild of their own. Drain a quiet window and allow one
        // straggler batch, nothing more.
        let mut rebuilds = 1;
        while rx.recv_timeout(DEBOUNCE * 4).is_ok() {
            rebuilds += 1;
        }
        assert!(
            rebuilds <= 2,
            "burst of 5 writes must coalesce to ~1 rebuild (saw {rebuilds})"
        );
    }

    #[test]
    fn watcher_fires_on_environment_json_create() {
        // M1.4c-ii: `op messaging endpoint *` mutates `environment.json`
        // (and the messaging projection under `messaging/`), NOT
        // `runtime-config.json`. The watcher must fire on env.json so an
        // ACL revocation re-activates the running server without a
        // restart or an unrelated runtime-config write.
        let env = fresh_env_dir();
        let (tx, rx) = std_mpsc::channel();
        let _handle = spawn_runtime_config_watcher(
            env.path().to_path_buf(),
            Duration::from_millis(50),
            Duration::ZERO,
            placeholder_server(),
            channel_rebuild(tx),
            |_: &Activation| {},
            || {},
        )
        .expect("spawn watcher");

        write_environment_json(env.path(), r#"{"schema":"x"}"#);

        rx.recv_timeout(Duration::from_secs(3))
            .expect("watcher must fire after environment.json is created");
    }

    #[test]
    fn watcher_ignores_environment_json_backup_files() {
        // The deployer writes `environment.json.<ts>.bak` backups in the
        // same directory. Path equality (not prefix matching) keeps those
        // out of the trigger set.
        let env = fresh_env_dir();
        let counter = Arc::new(AtomicUsize::new(0));
        let _handle = spawn_runtime_config_watcher(
            env.path().to_path_buf(),
            Duration::from_millis(50),
            Duration::ZERO,
            placeholder_server(),
            counting_rebuild(Arc::clone(&counter)),
            |_: &Activation| {},
            || {},
        )
        .expect("spawn watcher");

        std::fs::write(
            env.path().join("environment.json.1234567890.bak"),
            b"old-content",
        )
        .expect("write backup decoy");
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "watcher must ignore environment.json.<ts>.bak backups"
        );
    }

    #[test]
    fn watcher_ignores_other_files_in_env_dir() {
        let env = fresh_env_dir();
        let counter = Arc::new(AtomicUsize::new(0));
        let _handle = spawn_runtime_config_watcher(
            env.path().to_path_buf(),
            Duration::from_millis(50),
            Duration::ZERO,
            placeholder_server(),
            counting_rebuild(Arc::clone(&counter)),
            |_: &Activation| {},
            || {},
        )
        .expect("spawn watcher");

        // Write a different file in the watched dir; the watcher must NOT
        // invoke rebuild for it (e.g. the per-env `revision-signing.key`
        // write at cold-start time triggered an event, but only the
        // `runtime-config.json` target should fire reload).
        std::fs::write(env.path().join("revision-signing.key"), b"not-the-target")
            .expect("write decoy");

        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "watcher must ignore writes to files other than runtime-config.json"
        );
    }

    fn empty_loaded_rc() -> LoadedRuntimeConfig {
        LoadedRuntimeConfig {
            env_id: "local".to_string(),
            revisions: Vec::new(),
        }
    }

    fn env_with_endpoints(endpoints: Vec<greentic_deploy_spec::MessagingEndpoint>) -> Environment {
        use greentic_deploy_spec::{EnvironmentHostConfig, SchemaVersion};
        use greentic_types::EnvId;
        let env_id = EnvId::try_from("local").unwrap();
        Environment {
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
            messaging_endpoints: endpoints,
            extensions: Vec::new(),
            credentials_ref: None,
            bundles: Vec::new(),
            revisions: Vec::new(),
            traffic_splits: Vec::new(),
            revocation: Default::default(),
            retention: Default::default(),
            health: Default::default(),
        }
    }

    fn make_endpoint(linked_bundles: &[&str]) -> greentic_deploy_spec::MessagingEndpoint {
        use greentic_deploy_spec::{
            BundleId, MessagingEndpoint, MessagingEndpointId, SchemaVersion,
        };
        use greentic_types::EnvId;
        let now = chrono::Utc::now();
        MessagingEndpoint {
            schema: SchemaVersion::new(SchemaVersion::MESSAGING_ENDPOINT_V1),
            env_id: EnvId::try_from("local").unwrap(),
            endpoint_id: MessagingEndpointId::new(),
            provider_id: "teams-legal".to_string(),
            provider_type: "teams".to_string(),
            display_name: "Legal".to_string(),
            secret_refs: Vec::new(),
            webhook_secret_ref: None,
            linked_bundles: linked_bundles.iter().map(|b| BundleId::new(*b)).collect(),
            welcome_flow: None,
            generation: 1,
            created_at: now,
            updated_at: now,
            updated_by: "test".to_string(),
        }
    }

    #[test]
    fn last_reload_inputs_inequality_on_messaging_endpoint_change() {
        // M1.4c-ii correctness gate: an ACL revocation that updates env.json
        // but leaves runtime-config.json untouched MUST not dedup. The
        // `LastReloadInputs` key combines rc and env, so distinct env states
        // (different `linked_bundles`) produce distinct keys and re-activate.
        let rc = empty_loaded_rc();
        let env_with = env_with_endpoints(vec![make_endpoint(&["legal-bundle"])]);
        let env_without = env_with_endpoints(vec![make_endpoint(&[])]);
        let a = LastReloadInputs {
            rc: rc.clone(),
            env: env_with,
        };
        let b = LastReloadInputs {
            rc,
            env: env_without,
        };
        assert_ne!(
            a, b,
            "messaging endpoint linked_bundles change must defeat dedup"
        );
    }

    #[test]
    fn watcher_keeps_running_when_rebuild_returns_error() {
        let env = fresh_env_dir();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_closure = Arc::clone(&counter);

        let _handle = spawn_runtime_config_watcher(
            env.path().to_path_buf(),
            Duration::from_millis(50),
            Duration::ZERO,
            placeholder_server(),
            move || {
                let n = counter_for_closure.fetch_add(1, Ordering::SeqCst) + 1;
                if n == 1 {
                    Err(anyhow::anyhow!("synthetic rebuild error"))
                } else {
                    Ok(ReloadOutcome::Unchanged)
                }
            },
            |_: &Activation| {},
            || {},
        )
        .expect("spawn watcher");

        // First write → rebuild returns Err. The watcher must NOT exit.
        write_runtime_config(env.path(), r#"{"first":true}"#);
        std::thread::sleep(Duration::from_millis(250));

        // Second write → rebuild returns Ok(None). If the watcher had
        // exited on the first error, this would not fire.
        write_runtime_config(env.path(), r#"{"second":true}"#);
        std::thread::sleep(Duration::from_millis(500));

        let observed = counter.load(Ordering::SeqCst);
        assert!(
            observed >= 2,
            "watcher must keep running after a rebuild error (rebuild fired {observed} times)"
        );
    }

    // ---------------------------------------------------------------
    // Torn-write bounded retry: the `torn_write_newly_unbacked` helper
    // decides whether the torn-write guard should re-read.
    // ---------------------------------------------------------------

    #[test]
    fn torn_write_no_newly_unbacked_returns_empty() {
        use std::collections::BTreeSet;
        // All current unbacked ids were already known — nothing is "new".
        let previously = BTreeSet::from(["dep-a".to_string()]);
        let current = BTreeSet::from(["dep-a".to_string()]);
        assert!(
            torn_write_newly_unbacked(&current, &previously).is_empty(),
            "a deployment already in previously_unbacked is not a torn write"
        );
    }

    #[test]
    fn torn_write_newly_unbacked_surfaces_new_ids() {
        use std::collections::BTreeSet;
        let previously = BTreeSet::from(["dep-a".to_string()]);
        let current = BTreeSet::from(["dep-a".to_string(), "dep-b".to_string()]);
        let newly = torn_write_newly_unbacked(&current, &previously);
        assert_eq!(
            newly,
            vec!["dep-b".to_string()],
            "a deployment not in previously_unbacked IS newly torn"
        );
    }

    #[test]
    fn torn_write_empty_current_returns_empty() {
        use std::collections::BTreeSet;
        let previously = BTreeSet::from(["dep-a".to_string()]);
        let current = BTreeSet::new();
        assert!(
            torn_write_newly_unbacked(&current, &previously).is_empty(),
            "no unbacked deployments means no torn write"
        );
    }

    #[test]
    fn torn_write_resolved_after_reread_returns_empty() {
        use std::collections::BTreeSet;
        // Simulates: initial read showed dep-b as newly unbacked, re-read
        // shows it backed (disappeared from unbacked set) — the guard should
        // stop retrying.
        let previously = BTreeSet::new();
        let after_reread = BTreeSet::new(); // dep-b no longer unbacked
        assert!(
            torn_write_newly_unbacked(&after_reread, &previously).is_empty(),
            "once the unbacked deployment disappears, the guard must stop retrying"
        );
    }
}
