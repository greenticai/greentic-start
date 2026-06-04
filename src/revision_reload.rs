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
use greentic_types::EnvId;

/// Keep in sync with `greentic-deployer/src/environment/store.rs::environment_path`.
const ENVIRONMENT_FILE: &str = "environment.json";

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
///
/// `post_reload` runs AFTER `server.reload` swapped the new activation in.
/// Side effects that need the new routes to be live (e.g. provider webhook
/// re-registration, which an external provider may validate or deliver to
/// immediately) belong there, never inside `rebuild` — the server still
/// serves the OLD activation while `rebuild` runs, so a slow side effect
/// inside `rebuild` would also delay the swap itself.
pub(crate) fn spawn_runtime_config_watcher<R, P>(
    env_dir: PathBuf,
    debounce: Duration,
    drain_window: Duration,
    server: Arc<RevisionServer>,
    rebuild: R,
    post_reload: P,
) -> Result<WatcherHandle>
where
    R: FnMut() -> Result<Option<Activation>> + Send + 'static,
    P: FnMut(&Activation) + Send + 'static,
{
    // Trigger set: paths whose mutations must invalidate the activation.
    // `runtime-config.json` is the original trigger; `environment.json` is
    // the M1.4c-ii fix so messaging endpoint mutations (which only touch
    // env.json + the messaging projection) re-activate the admit table.
    let target_files = vec![
        env_dir.join(runtime_config::RUNTIME_CONFIG_FILE),
        env_dir.join(ENVIRONMENT_FILE),
    ];
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
            reload_worker(rx, target_files, drain_window, server, rebuild, post_reload);
        })
        .context("spawning runtime-config reload worker")?;

    Ok(WatcherHandle {
        debouncer: Some(debouncer),
        worker: Some(worker),
    })
}

/// The worker loop. Reads debounced batches off `rx`, filters for events
/// touching any of `target_files`, and on each matching batch calls `rebuild`
/// then `server.reload` with whatever activation the rebuild produced.
///
/// Extracted from `spawn_runtime_config_watcher` so tests can drive the
/// worker directly without going through `notify`.
fn reload_worker<R, P>(
    rx: mpsc::Receiver<DebounceEventResult>,
    target_files: Vec<PathBuf>,
    drain_window: Duration,
    server: Arc<RevisionServer>,
    mut rebuild: R,
    mut post_reload: P,
) where
    R: FnMut() -> Result<Option<Activation>> + Send + 'static,
    P: FnMut(&Activation) + Send + 'static,
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
        // Filter: only fire when an event actually touches one of our targets.
        // `notify` reports every event under the watched directory; an
        // unrelated `revision-signing.key` write must NOT trigger reload.
        // Backup files (`environment.json.<ts>.bak`) don't match either —
        // path equality, not prefix matching.
        let relevant = events.iter().any(|ev| {
            ev.event
                .paths
                .iter()
                .any(|p| target_files.iter().any(|t| p == t))
        });
        if !relevant {
            continue;
        }
        match rebuild() {
            Ok(Some(activation)) => {
                // Clone (two Arc bumps) so the post-reload hook observes the
                // SAME (host, routing) pair the server now serves; the hook
                // fires only after the swap below.
                let live = activation.clone();
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
                post_reload(&live);
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

/// Build the production rebuild closure: loads + dedupes + activates.
/// The returned closure carries [`LastReloadInputs`] so identical-content
/// writes (the deployer occasionally rewrites the same content on no-op
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
    let mut last: Option<LastReloadInputs> = None;
    move || rebuild_once(&store_root, &env_id, &secrets, &activation_rt, &mut last)
}

fn rebuild_once(
    store_root: &Path,
    env_id: &str,
    secrets: &DynSecretsManager,
    activation_rt: &tokio::runtime::Handle,
    last: &mut Option<LastReloadInputs>,
) -> Result<Option<Activation>> {
    let rc = runtime_config::load_in(store_root, env_id)?.unwrap_or_else(|| LoadedRuntimeConfig {
        env_id: env_id.to_string(),
        revisions: Vec::new(),
    });
    let store = LocalFsStore::new(store_root.to_path_buf());
    let env_typed =
        EnvId::new(env_id).with_context(|| format!("invalid environment id `{env_id}`"))?;
    let environment = EnvironmentStore::load(&store, &env_typed)
        .with_context(|| format!("loading environment `{env_id}` for reload"))?;
    // Dedup AFTER both reads — neither file alone is a sufficient key. An
    // env.json rewrite with no real change short-circuits here even though
    // the watcher fired, so cookies/pins aren't churned by no-op writes.
    if let Some(prev) = last.as_ref()
        && prev.rc == rc
        && prev.env == environment
    {
        return Ok(None);
    }
    let RuntimeConfigActivation { host, routing } = activation_rt.block_on(
        revision_boot::activate_runtime_config(store_root, &rc, Arc::clone(secrets), &environment),
    )?;
    *last = Some(LastReloadInputs {
        rc,
        env: environment,
    });
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
    fn placeholder_server() -> Arc<RevisionServer> {
        // RevisionServer doesn't expose a no-op test ctor publicly. Use
        // RevisionServer::start with a placeholder activation built via
        // the same construction path the cold-start uses.
        use crate::deployment_routes::{DeploymentRouteTable, RevisionIngressRouting};
        use crate::endpoint_admit::EndpointAdmit;
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
            endpoint_admit: Arc::new(EndpointAdmit::default()),
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
            |_: &Activation| {},
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
            |_: &Activation| {},
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
                    Ok(None)
                }
            },
            |_: &Activation| {},
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
