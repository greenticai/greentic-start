//! C5 — `runtime://<env>/discovered/<key>` resolver, backed by the env-scoped
//! [`EnvironmentRuntime`] snapshot the deployer materializes into `runtime.json`.
//!
//! Architecture:
//!
//! - [`EnvironmentRuntimeStore`] owns an `ArcSwap` snapshot of the current
//!   `<env_dir>/runtime.json`. The runtime is loaded once at boot and re-loaded
//!   on every `runtime.json` write by [`spawn_runtime_snapshot_watcher`]. The
//!   snapshot is `Option<EnvironmentRuntime>`: `None` means the file hasn't
//!   been emitted yet (the deployer writes it on the first apply), and the
//!   resolver returns `Ok(None)` for every lookup in that state — the runner
//!   host maps that to `ConfigError::NotFound`, fail-closed.
//!
//! - [`StartRuntimeRefResolver`] implements
//!   [`greentic_runner_host::runtime_refs::RuntimeRefResolver`]: parses
//!   `runtime://<env>/discovered/<key>` URIs against a known env id and looks
//!   up `discovered[key]` in the live snapshot. Cross-env URIs and ill-shaped
//!   URIs return [`RuntimeRefResolverError::Invalid`]; snapshot read errors
//!   return [`RuntimeRefResolverError::Internal`].
//!
//! - The watcher is intentionally separate from the existing runtime-config
//!   watcher ([`crate::revision_reload`]). `runtime-config.json` /
//!   `environment.json` writes rebuild the full revision activation;
//!   `runtime.json` writes only refresh the resolver snapshot. Coupling the
//!   two would force a full revision rebuild every time the deployer
//!   re-emitted discovered values (Phase D ALB DNS refresh, ECS scaling
//!   churn), which is exactly what the resolver-on-snapshot design is meant
//!   to avoid.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use greentic_deploy_spec::EnvironmentRuntime;
use greentic_runner_host::runtime_refs::{RuntimeRefResolver, RuntimeRefResolverError};
use greentic_types::EnvId;
use notify_debouncer_full::notify::RecursiveMode;
use notify_debouncer_full::{
    DebounceEventResult, Debouncer, RecommendedCache, new_debouncer, notify::RecommendedWatcher,
};
use serde_json::Value;

use crate::operator_log;

/// On-disk name of the [`EnvironmentRuntime`] sidecar. Mirrors the path
/// `greentic-deployer/src/environment/store.rs::runtime_path` writes to.
pub(crate) const RUNTIME_FILE: &str = "runtime.json";

/// `runtime://` scheme prefix. The full grammar lives in
/// [`greentic_deploy_spec::RuntimeRef`]; we only need the scheme + the
/// `discovered/` segment marker here.
const RUNTIME_SCHEME: &str = "runtime://";
const DISCOVERED_SEGMENT: &str = "discovered";

/// Env-scoped, hot-reloadable snapshot of the deployer's `runtime.json`.
///
/// One instance per env, shared via `Arc` across:
/// 1. the cold-start activation that builds [`StartRuntimeRefResolver`],
/// 2. each reload-rebuilt activation (re-uses the same in-memory snapshot),
/// 3. the file watcher that calls [`Self::reload`] on every `runtime.json`
///    write.
///
/// Lookups go through the snapshot's `ArcSwap`, so a host-import call from a
/// running pack sees the latest published snapshot without taking any lock.
#[derive(Debug)]
pub(crate) struct EnvironmentRuntimeStore {
    env_id: EnvId,
    runtime_path: PathBuf,
    snapshot: ArcSwap<Option<EnvironmentRuntime>>,
}

impl EnvironmentRuntimeStore {
    /// Open the store for the env rooted at `env_dir`. Reads `runtime.json`
    /// if present; absent file is fine (snapshot stays `None` and lookups
    /// return `Ok(None)` until the deployer emits one).
    pub(crate) fn open(env_dir: &Path, env_id: EnvId) -> Result<Arc<Self>> {
        let runtime_path = env_dir.join(RUNTIME_FILE);
        let initial = load_runtime_if_present(&runtime_path, &env_id)?;
        Ok(Arc::new(Self {
            env_id,
            runtime_path,
            snapshot: ArcSwap::from_pointee(initial),
        }))
    }

    /// Re-read `runtime.json` and atomically swap the snapshot. Tolerant of
    /// transient I/O errors and parse failures: logs and keeps the previous
    /// snapshot so a half-written file (e.g. a non-atomic deployer write)
    /// can't take down the resolver. The deployer's `atomic_write_json`
    /// makes that rare, but a third-party emitter is allowed.
    pub(crate) fn reload(&self) {
        match load_runtime_if_present(&self.runtime_path, &self.env_id) {
            Ok(loaded) => {
                self.snapshot.store(Arc::new(loaded));
            }
            Err(err) => {
                operator_log::warn(
                    module_path!(),
                    format!("runtime.json reload failed (keeping previous snapshot): {err:#}"),
                );
            }
        }
    }

    /// Cheap snapshot accessor — used both by [`StartRuntimeRefResolver`] on
    /// every URI lookup and by tests that want to read the current discovered
    /// map.
    fn current(&self) -> arc_swap::Guard<Arc<Option<EnvironmentRuntime>>> {
        self.snapshot.load()
    }
}

fn load_runtime_if_present(
    path: &Path,
    expected_env: &EnvId,
) -> Result<Option<EnvironmentRuntime>> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(
                anyhow::Error::new(e).context(format!("reading runtime.json `{}`", path.display()))
            );
        }
    };
    let parsed: EnvironmentRuntime = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing runtime.json `{}`", path.display()))?;
    // Fail-closed on a cross-env file: a misplaced runtime.json must not
    // bleed its `discovered` values into the resolver for the env we're
    // serving. Mirrors the same `revision_id` defence-in-depth check on
    // pack-config and pack-list.lock.
    if &parsed.environment_id != expected_env {
        anyhow::bail!(
            "runtime.json `{}` declares env `{}`, expected `{}`",
            path.display(),
            parsed.environment_id,
            expected_env
        );
    }
    Ok(Some(parsed))
}

/// `RuntimeRefResolver` implementation backed by an [`EnvironmentRuntimeStore`].
///
/// Bound to a single env id at construction so the env-segment check on every
/// URI is a cheap string comparison (and a misrouted URI for a different env
/// is unambiguously `Invalid` rather than `NotFound`).
#[derive(Debug)]
pub(crate) struct StartRuntimeRefResolver {
    store: Arc<EnvironmentRuntimeStore>,
}

impl StartRuntimeRefResolver {
    pub(crate) fn new(store: Arc<EnvironmentRuntimeStore>) -> Arc<Self> {
        Arc::new(Self { store })
    }
}

impl RuntimeRefResolver for StartRuntimeRefResolver {
    fn resolve(&self, runtime_ref: &str) -> Result<Option<Value>, RuntimeRefResolverError> {
        let key = parse_discovered_key(runtime_ref, self.store.env_id.as_str())?;
        let snapshot = self.store.current();
        let Some(runtime) = snapshot.as_ref() else {
            return Ok(None);
        };
        Ok(runtime.discovered.get(key).cloned())
    }
}

/// Parse `runtime://<env>/discovered/<key>` and return the `<key>` slice,
/// validating that `<env>` matches `expected_env`.
///
/// The grammar accepted here is intentionally narrower than
/// [`greentic_deploy_spec::RuntimeRef`] permits: we only resolve
/// `discovered/` URIs (the only address space C5 wires up). Any other
/// second-segment value, an env mismatch, or a missing key fails
/// [`RuntimeRefResolverError::Invalid`] so the runner host maps it to
/// `ConfigError::InvalidKey`.
fn parse_discovered_key<'a>(
    raw: &'a str,
    expected_env: &str,
) -> Result<&'a str, RuntimeRefResolverError> {
    let after_scheme = raw.strip_prefix(RUNTIME_SCHEME).ok_or_else(|| {
        RuntimeRefResolverError::Invalid(format!(
            "runtime-ref `{raw}` must start with `{RUNTIME_SCHEME}`"
        ))
    })?;
    let (env_seg, rest) = after_scheme.split_once('/').ok_or_else(|| {
        RuntimeRefResolverError::Invalid(format!(
            "runtime-ref `{raw}` is missing `/discovered/<key>`"
        ))
    })?;
    if env_seg != expected_env {
        return Err(RuntimeRefResolverError::Invalid(format!(
            "runtime-ref `{raw}` env segment `{env_seg}` does not match env `{expected_env}`"
        )));
    }
    let (segment, key) = rest.split_once('/').ok_or_else(|| {
        RuntimeRefResolverError::Invalid(format!(
            "runtime-ref `{raw}` is missing `/<key>` after `discovered`"
        ))
    })?;
    if segment != DISCOVERED_SEGMENT {
        return Err(RuntimeRefResolverError::Invalid(format!(
            "runtime-ref `{raw}` second segment `{segment}` is not `{DISCOVERED_SEGMENT}` \
             (no other address space is supported yet)"
        )));
    }
    if key.is_empty() {
        return Err(RuntimeRefResolverError::Invalid(format!(
            "runtime-ref `{raw}` has an empty key"
        )));
    }
    Ok(key)
}

/// Owned cleanup handle for [`spawn_runtime_snapshot_watcher`]. Dropping it
/// shuts the debouncer and joins the worker thread. Same drop-order
/// discipline as [`crate::revision_reload::WatcherHandle`].
pub(crate) struct RuntimeSnapshotWatcherHandle {
    debouncer: Option<Debouncer<RecommendedWatcher, RecommendedCache>>,
    worker: Option<JoinHandle<()>>,
}

impl Drop for RuntimeSnapshotWatcherHandle {
    fn drop(&mut self) {
        drop(self.debouncer.take());
        if let Some(h) = self.worker.take()
            && let Err(err) = h.join()
        {
            operator_log::warn(
                module_path!(),
                format!("runtime.json watcher worker panicked: {err:?}"),
            );
        }
    }
}

/// Default debounce window for coalescing back-to-back `runtime.json`
/// rewrites (the deployer's env-pack apply may write more than once during
/// a single dry-run / commit / sidecar update sequence).
pub(crate) const DEFAULT_RUNTIME_DEBOUNCE: Duration = Duration::from_millis(250);

/// Spawn a notify-debouncer-backed watcher that calls `store.reload()` on
/// every `runtime.json` write under `env_dir`.
///
/// Watches the env DIR (not the file) so an atomic-rename rewrite still
/// fires — `notify` reports the rename-into-place as a directory event on
/// the basename. The trigger filter is exact path equality so a write to
/// `runtime-config.json` or a backup file does NOT spuriously trigger a
/// snapshot reload.
pub(crate) fn spawn_runtime_snapshot_watcher(
    env_dir: PathBuf,
    debounce: Duration,
    store: Arc<EnvironmentRuntimeStore>,
) -> Result<RuntimeSnapshotWatcherHandle> {
    let target_file = env_dir.join(RUNTIME_FILE);
    let (tx, rx) = mpsc::channel::<DebounceEventResult>();
    let mut debouncer = new_debouncer(debounce, None, move |res| {
        let _ = tx.send(res);
    })
    .context("creating runtime.json debouncer")?;
    debouncer
        .watch(&env_dir, RecursiveMode::NonRecursive)
        .with_context(|| {
            format!(
                "watching env directory {} for runtime.json",
                env_dir.display()
            )
        })?;

    let worker = thread::Builder::new()
        .name("runtime-snapshot-reload".to_string())
        .spawn(move || snapshot_reload_worker(rx, target_file, store))
        .context("spawning runtime.json reload worker")?;

    Ok(RuntimeSnapshotWatcherHandle {
        debouncer: Some(debouncer),
        worker: Some(worker),
    })
}

fn snapshot_reload_worker(
    rx: mpsc::Receiver<DebounceEventResult>,
    target_file: PathBuf,
    store: Arc<EnvironmentRuntimeStore>,
) {
    for result in rx {
        let events = match result {
            Ok(events) => events,
            Err(errs) => {
                for err in errs {
                    operator_log::warn(
                        module_path!(),
                        format!("runtime.json watcher notify error: {err}"),
                    );
                }
                continue;
            }
        };
        let relevant = events
            .iter()
            .any(|ev| ev.event.paths.iter().any(|p| p == &target_file));
        if !relevant {
            continue;
        }
        store.reload();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use greentic_deploy_spec::{PackDescriptor, SchemaVersion};
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::tempdir;

    fn env_id() -> EnvId {
        EnvId::try_from("local").unwrap()
    }

    fn sample_runtime(discovered: BTreeMap<String, Value>) -> EnvironmentRuntime {
        EnvironmentRuntime {
            schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_RUNTIME_V1),
            environment_id: env_id(),
            discovered,
            generated_at: Utc::now(),
            generated_by: PackDescriptor::try_new("greentic.deployer.local@0.1.0").unwrap(),
            generation: 1,
        }
    }

    fn write_runtime(env_dir: &Path, runtime: &EnvironmentRuntime) {
        std::fs::write(
            env_dir.join(RUNTIME_FILE),
            serde_json::to_vec_pretty(runtime).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn open_returns_none_snapshot_when_file_absent() {
        let dir = tempdir().unwrap();
        let store = EnvironmentRuntimeStore::open(dir.path(), env_id()).unwrap();
        assert!(store.current().is_none());
    }

    #[test]
    fn open_loads_existing_runtime_json() {
        let dir = tempdir().unwrap();
        let mut discovered = BTreeMap::new();
        discovered.insert("alb_dns".to_string(), json!("alb.example.com"));
        write_runtime(dir.path(), &sample_runtime(discovered));

        let store = EnvironmentRuntimeStore::open(dir.path(), env_id()).unwrap();
        let snap = store.current();
        let snap = snap.as_ref().as_ref().expect("snapshot loaded");
        assert_eq!(
            snap.discovered.get("alb_dns").and_then(Value::as_str),
            Some("alb.example.com")
        );
    }

    #[test]
    fn open_rejects_cross_env_runtime_json() {
        let dir = tempdir().unwrap();
        let mut foreign = sample_runtime(BTreeMap::new());
        foreign.environment_id = EnvId::try_from("not-local").unwrap();
        write_runtime(dir.path(), &foreign);

        let err = EnvironmentRuntimeStore::open(dir.path(), env_id()).unwrap_err();
        assert!(
            err.to_string().contains("does not exist") || err.to_string().contains("declares env"),
            "expected env-mismatch error, got: {err:#}"
        );
    }

    #[test]
    fn reload_picks_up_written_file() {
        let dir = tempdir().unwrap();
        let store = EnvironmentRuntimeStore::open(dir.path(), env_id()).unwrap();
        assert!(store.current().is_none());

        let mut discovered = BTreeMap::new();
        discovered.insert("alb_dns".to_string(), json!("alb-1.example.com"));
        write_runtime(dir.path(), &sample_runtime(discovered));
        store.reload();
        let snap = store.current();
        let snap = snap
            .as_ref()
            .as_ref()
            .expect("snapshot loaded after reload");
        assert_eq!(
            snap.discovered.get("alb_dns").and_then(Value::as_str),
            Some("alb-1.example.com")
        );

        let mut discovered = BTreeMap::new();
        discovered.insert("alb_dns".to_string(), json!("alb-2.example.com"));
        write_runtime(dir.path(), &sample_runtime(discovered));
        store.reload();
        let snap = store.current();
        let snap = snap.as_ref().as_ref().expect("snapshot reloaded");
        assert_eq!(
            snap.discovered.get("alb_dns").and_then(Value::as_str),
            Some("alb-2.example.com")
        );
    }

    #[test]
    fn reload_keeps_previous_snapshot_on_parse_error() {
        let dir = tempdir().unwrap();
        let mut discovered = BTreeMap::new();
        discovered.insert("alb_dns".to_string(), json!("alb.example.com"));
        write_runtime(dir.path(), &sample_runtime(discovered));
        let store = EnvironmentRuntimeStore::open(dir.path(), env_id()).unwrap();

        std::fs::write(dir.path().join(RUNTIME_FILE), b"{not json").unwrap();
        store.reload();

        // Previous snapshot survived the bad write.
        let snap = store.current();
        let snap = snap.as_ref().as_ref().expect("previous snapshot preserved");
        assert_eq!(
            snap.discovered.get("alb_dns").and_then(Value::as_str),
            Some("alb.example.com")
        );
    }

    fn make_resolver(store: Arc<EnvironmentRuntimeStore>) -> StartRuntimeRefResolver {
        StartRuntimeRefResolver { store }
    }

    #[test]
    fn resolver_returns_value_for_bound_key() {
        let dir = tempdir().unwrap();
        let mut discovered = BTreeMap::new();
        discovered.insert("alb_dns".to_string(), json!("alb.example.com"));
        write_runtime(dir.path(), &sample_runtime(discovered));
        let store = EnvironmentRuntimeStore::open(dir.path(), env_id()).unwrap();
        let resolver = make_resolver(store);

        let value = resolver
            .resolve("runtime://local/discovered/alb_dns")
            .expect("resolver returns Ok");
        assert_eq!(value, Some(json!("alb.example.com")));
    }

    #[test]
    fn resolver_returns_none_for_unbound_key() {
        let dir = tempdir().unwrap();
        write_runtime(dir.path(), &sample_runtime(BTreeMap::new()));
        let store = EnvironmentRuntimeStore::open(dir.path(), env_id()).unwrap();
        let resolver = make_resolver(store);

        let value = resolver
            .resolve("runtime://local/discovered/missing_key")
            .expect("resolver returns Ok(None)");
        assert!(value.is_none());
    }

    #[test]
    fn resolver_returns_none_when_runtime_json_absent() {
        let dir = tempdir().unwrap();
        let store = EnvironmentRuntimeStore::open(dir.path(), env_id()).unwrap();
        let resolver = make_resolver(store);

        let value = resolver
            .resolve("runtime://local/discovered/alb_dns")
            .expect("resolver returns Ok(None) when no snapshot");
        assert!(value.is_none());
    }

    #[test]
    fn resolver_rejects_cross_env_uri() {
        let dir = tempdir().unwrap();
        let store = EnvironmentRuntimeStore::open(dir.path(), env_id()).unwrap();
        let resolver = make_resolver(store);

        let err = resolver
            .resolve("runtime://other/discovered/alb_dns")
            .expect_err("cross-env URI must surface Invalid");
        assert!(matches!(err, RuntimeRefResolverError::Invalid(_)));
    }

    #[test]
    fn resolver_rejects_non_runtime_scheme() {
        let dir = tempdir().unwrap();
        let store = EnvironmentRuntimeStore::open(dir.path(), env_id()).unwrap();
        let resolver = make_resolver(store);

        for raw in [
            "secret://local/foo",
            "https://local/discovered/alb_dns",
            "runtime:/local/discovered/alb_dns",
            "alb_dns",
        ] {
            let err = resolver
                .resolve(raw)
                .expect_err("non-runtime scheme must be Invalid");
            assert!(matches!(err, RuntimeRefResolverError::Invalid(_)), "{raw}");
        }
    }

    #[test]
    fn resolver_rejects_non_discovered_segment() {
        let dir = tempdir().unwrap();
        let store = EnvironmentRuntimeStore::open(dir.path(), env_id()).unwrap();
        let resolver = make_resolver(store);

        let err = resolver
            .resolve("runtime://local/secrets/alb_dns")
            .expect_err("unsupported segment must be Invalid");
        assert!(matches!(err, RuntimeRefResolverError::Invalid(_)));
    }

    #[test]
    fn resolver_rejects_empty_key() {
        let dir = tempdir().unwrap();
        let store = EnvironmentRuntimeStore::open(dir.path(), env_id()).unwrap();
        let resolver = make_resolver(store);

        let err = resolver
            .resolve("runtime://local/discovered/")
            .expect_err("empty key must be Invalid");
        assert!(matches!(err, RuntimeRefResolverError::Invalid(_)));
    }

    /// Concurrency probe: many resolver lookups against an `ArcSwap` snapshot
    /// while another thread reloads. We don't assert ordering — we assert
    /// that every resolved value is one of the two known-good shapes (never
    /// torn / panicking / poisoned).
    #[test]
    fn resolver_lookups_under_concurrent_reload() {
        let dir = tempdir().unwrap();
        let mut discovered_a = BTreeMap::new();
        discovered_a.insert("alb_dns".to_string(), json!("alb.A"));
        write_runtime(dir.path(), &sample_runtime(discovered_a));
        let store = EnvironmentRuntimeStore::open(dir.path(), env_id()).unwrap();
        let resolver = Arc::new(make_resolver(Arc::clone(&store)));

        let reader_hits = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let resolver = Arc::clone(&resolver);
            let counter = Arc::clone(&reader_hits);
            handles.push(std::thread::spawn(move || {
                for _ in 0..1_000 {
                    let value = resolver
                        .resolve("runtime://local/discovered/alb_dns")
                        .expect("resolver Ok");
                    if let Some(Value::String(s)) = value {
                        assert!(s == "alb.A" || s == "alb.B", "torn value: {s}");
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        // Reloader flips between A and B several times.
        for i in 0..50 {
            let mut discovered = BTreeMap::new();
            discovered.insert(
                "alb_dns".to_string(),
                if i % 2 == 0 {
                    json!("alb.A")
                } else {
                    json!("alb.B")
                },
            );
            write_runtime(dir.path(), &sample_runtime(discovered));
            store.reload();
        }
        for h in handles {
            h.join().unwrap();
        }
        assert!(reader_hits.load(Ordering::Relaxed) > 0);
    }
}
