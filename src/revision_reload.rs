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

use greentic_deployer::environment::{EnvironmentStore, LocalFsStore};
use greentic_types::EnvId;

use crate::operator_log;
use crate::revision_boot::{self, RuntimeConfigActivation};
use crate::revision_serve::{Activation, RevisionServer};
use crate::runtime_config::{self, LoadedRuntimeConfig};
use crate::secrets_gate::DynSecretsManager;

/// Default debounce window for coalescing the deployer's commonly bundled
/// `bundles add → revisions stage → traffic set` write sequence into a
/// single rebuild. Tuned to be wider than the deployer's per-verb fsync
/// latency on a warm cache (typical 5–30ms) and narrower than the
/// operator's interactive expectation of "the change took effect".
pub(crate) const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(250);

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
/// `rebuild` is the rebuild closure: invoked once per debounced event for
/// `<env_dir>/runtime-config.json`. It returns:
/// - `Ok(Some(activation))` to swap the new activation into `server`,
/// - `Ok(None)` to skip the swap (e.g. hash-skip on identical content),
/// - `Err(_)` to log + keep the previous activation serving.
///
/// The watcher takes ownership of `rebuild` and `server` for the worker's
/// lifetime; both are dropped when the returned [`WatcherHandle`] is
/// dropped.
pub(crate) fn spawn_runtime_config_watcher<R>(
    env_dir: PathBuf,
    debounce: Duration,
    drain_window: Duration,
    server: Arc<RevisionServer>,
    rebuild: R,
) -> Result<WatcherHandle>
where
    R: FnMut() -> Result<Option<Activation>> + Send + 'static,
{
    let target_file = env_dir.join(runtime_config::RUNTIME_CONFIG_FILE);
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
            reload_worker(rx, target_file, drain_window, server, rebuild);
        })
        .context("spawning runtime-config reload worker")?;

    Ok(WatcherHandle {
        debouncer: Some(debouncer),
        worker: Some(worker),
    })
}

/// The worker loop. Reads debounced batches off `rx`, filters for events
/// touching `target_file`, and on each matching batch calls `rebuild`
/// then `server.reload` with whatever activation the rebuild produced.
///
/// Extracted from `spawn_runtime_config_watcher` so tests can drive the
/// worker directly without going through `notify`.
fn reload_worker<R>(
    rx: mpsc::Receiver<DebounceEventResult>,
    target_file: PathBuf,
    drain_window: Duration,
    server: Arc<RevisionServer>,
    mut rebuild: R,
) where
    R: FnMut() -> Result<Option<Activation>> + Send + 'static,
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
        // Filter: only fire when an event actually touches our target.
        // `notify` reports every event under the watched directory; an
        // unrelated `revision-signing.key` write must NOT trigger reload.
        let relevant = events
            .iter()
            .any(|ev| ev.event.paths.iter().any(|p| p == &target_file));
        if !relevant {
            continue;
        }
        match rebuild() {
            Ok(Some(activation)) => {
                let report = server.reload(activation, drain_window);
                operator_log::info(
                    module_path!(),
                    format!(
                        "runtime-config reloaded: {} → {} deployment(s), {} → {} revision(s)",
                        report.prev_deployments,
                        report.new_deployments,
                        report.prev_revisions,
                        report.new_revisions,
                    ),
                );
            }
            Ok(None) => {
                // Identical-config write or otherwise no-op rebuild;
                // skip the swap so cookies/pins aren't churned.
            }
            Err(err) => {
                operator_log::error(
                    module_path!(),
                    format!("runtime-config reload failed: {err:#}"),
                );
            }
        }
    }
}

/// Build the production rebuild closure: loads + dedupes + activates.
/// The returned closure carries `last_rc` so identical-content writes
/// (the deployer occasionally rewrites the same content on no-op
/// operations) short-circuit before the expensive `activate_runtime_config`.
///
/// `activation_rt` is the Tokio runtime [`crate::lib::run_start`] already
/// built for cold-start activation; we re-use it so the rebuilt host is
/// constructed on the same runtime that the original was — keeping any
/// async resources affine to one runtime.
pub(crate) fn default_rebuild(
    store_root: PathBuf,
    env_id: String,
    secrets: DynSecretsManager,
    activation_rt: tokio::runtime::Handle,
) -> impl FnMut() -> Result<Option<Activation>> + Send + 'static {
    let mut last_rc: Option<LoadedRuntimeConfig> = None;
    move || rebuild_once(&store_root, &env_id, &secrets, &activation_rt, &mut last_rc)
}

fn rebuild_once(
    store_root: &Path,
    env_id: &str,
    secrets: &DynSecretsManager,
    activation_rt: &tokio::runtime::Handle,
    last_rc: &mut Option<LoadedRuntimeConfig>,
) -> Result<Option<Activation>> {
    let rc = runtime_config::load_in(store_root, env_id)?.unwrap_or_else(|| LoadedRuntimeConfig {
        env_id: env_id.to_string(),
        revisions: Vec::new(),
    });
    if last_rc.as_ref() == Some(&rc) {
        return Ok(None);
    }
    let store = LocalFsStore::new(store_root.to_path_buf());
    let env_typed =
        EnvId::new(env_id).with_context(|| format!("invalid environment id `{env_id}`"))?;
    let environment = EnvironmentStore::load(&store, &env_typed)
        .with_context(|| format!("loading environment `{env_id}` for reload"))?;
    let RuntimeConfigActivation { host, routing } = activation_rt.block_on(
        revision_boot::activate_runtime_config(store_root, &rc, Arc::clone(secrets), &environment),
    )?;
    *last_rc = Some(rc);
    Ok(Some(Activation {
        host: Arc::new(host),
        routing: Arc::new(routing),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc as std_mpsc;

    /// A counting rebuild closure suitable for unit tests. Returns
    /// `Ok(None)` always (no real activation is built) but increments a
    /// counter so the test can assert how many rebuild attempts the
    /// watcher actually fired.
    fn counting_rebuild(
        counter: Arc<AtomicUsize>,
    ) -> impl FnMut() -> Result<Option<Activation>> + Send + 'static {
        move || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }
    }

    /// Same as `counting_rebuild`, but routes each fired rebuild through a
    /// channel so the test can await the next firing deterministically.
    fn channel_rebuild(
        tx: std_mpsc::Sender<()>,
    ) -> impl FnMut() -> Result<Option<Activation>> + Send + 'static {
        move || {
            let _ = tx.send(());
            Ok(None)
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

    // The reload worker requires a `RevisionServer`. The test-only
    // constructor in `revision_serve::tests` is module-private; we build a
    // production-style one over a free port. Tests that exercise the
    // server side of the reload are kept short to avoid port contention.
    //
    // For watcher-only tests we use an `Arc::new(...)` placeholder and a
    // counting rebuild that returns `Ok(None)` so `server.reload` is
    // never called — the only paths exercised are filter + dedup + error
    // isolation.
    fn placeholder_server() -> Arc<RevisionServer> {
        // RevisionServer doesn't expose a no-op test ctor publicly. Use
        // RevisionServer::start with a placeholder activation built via
        // the same construction path the cold-start uses.
        use crate::deployment_routes::{DeploymentRouteTable, RevisionIngressRouting};
        use crate::http_routes::HttpRouteTable;
        use crate::revision_dispatcher::{RevisionDispatcher, RevisionDispatcherConfig};
        use crate::revision_serve::{RevisionServeConfig, RevisionServer};
        use greentic_runner_host::{HostBuilder, HostConfig, TenantBindings};
        use std::net::SocketAddr;

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
        let routing = Arc::new(RevisionIngressRouting {
            dispatcher,
            http_routes: HttpRouteTable::from_descriptors(Vec::new()),
            deployment_routes: DeploymentRouteTable::default(),
        });
        let activation = Arc::new(Activation { host, routing });
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        Arc::new(
            RevisionServer::start(RevisionServeConfig {
                bind_addr: bind,
                activation,
            })
            .expect("placeholder server"),
        )
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
        let env = fresh_env_dir();
        let counter = Arc::new(AtomicUsize::new(0));
        let _handle = spawn_runtime_config_watcher(
            env.path().to_path_buf(),
            Duration::from_millis(200),
            Duration::ZERO,
            placeholder_server(),
            counting_rebuild(Arc::clone(&counter)),
        )
        .expect("spawn watcher");

        // Five back-to-back writes well within the 200ms debounce window.
        for i in 0..5 {
            write_runtime_config(env.path(), &format!(r#"{{"i":{i}}}"#));
        }

        // Wait past the debounce window plus a safety margin.
        std::thread::sleep(Duration::from_millis(800));
        let observed = counter.load(Ordering::SeqCst);
        assert!(
            (1..=2).contains(&observed),
            "burst of 5 writes must coalesce to ~1 rebuild (saw {observed})"
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
                    Ok(None)
                }
            },
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
}
