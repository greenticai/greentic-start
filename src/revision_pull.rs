//! M2 worker-boot bundle pull.
//!
//! A bundle-less worker (e.g. a K8s pod running `greentic-start start --env
//! <id>`) boots from a staged env store. In production that store is seeded
//! from a ConfigMap that can only carry `environment.json` — pack binaries and
//! the `runtime-config.json` projection are absent, so without this step the
//! worker activates a zero-revision runtime and serves probes only.
//!
//! When the environment's **routed** revisions were resolved from a bundle
//! source ([`Revision::bundle_source_uri`](greentic_deploy_spec::Revision::bundle_source_uri)),
//! this module fetches each referenced `.gtbundle` and hands the raw archive to
//! the deployer's `materialize_revision_from_bundle`, which stages the packs +
//! `pack-list.lock` under the env directory, integrity-gates the staged digest
//! against the revision's pinned `bundle_digest` (fail-closed), and rewrites
//! `runtime-config.json`. The boot seam then re-loads the now-populated
//! runtime-config and activates real revisions.
//!
//! This runs only on a cold boot with an empty runtime-config: a worker whose
//! packs already sit on a persisted volume short-circuits the pull and serves
//! straight from disk. Hot-reload pull (re-pulling when a running worker's
//! `environment.json` changes in place) is intentionally not handled here — a
//! K8s rolling update replaces pods, so each new revision cold-boots through
//! this same path.

use std::collections::HashSet;
use std::path::Path;

use anyhow::Context;
use greentic_deploy_spec::{BundleId, DeploymentId, Environment, Revision, RevisionId};
use greentic_deployer::cli::bundle_stage::materialize_revision_from_bundle;
use greentic_deployer::environment::{LocalFsStore, StoreError};
use greentic_types::EnvId;

use crate::bundle_ref;
use crate::operator_log;
use crate::runtime_config::RUNTIME_CONFIG_FILE;

/// The revision this process was deployed to serve.
///
/// Set by greentic-deployer on every per-revision workload it renders: the
/// Cloud Run env-pack (`gcp_cloudrun::runtime_boot_env`, one container per
/// unit) and the K8s env-pack's worker Deployment (`render_worker_deployment`,
/// one pod per revision). It is NOT set on the K8s router, on an operator-env
/// child, or on a local `gtc start` — those processes serve the environment as
/// a whole and have no revision of their own.
pub(crate) const OWN_REVISION_ENV: &str = "GREENTIC_REVISION_ID";

/// Reads [`OWN_REVISION_ENV`]; blank counts as unset.
pub(crate) fn own_revision_from_env() -> Option<String> {
    std::env::var(OWN_REVISION_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// A routed revision whose pull failed and that this process skipped because
/// it belongs to ANOTHER unit.
#[derive(Clone, Debug)]
pub(crate) struct SkippedRevision {
    pub(crate) revision_id: RevisionId,
    pub(crate) deployment_id: DeploymentId,
    pub(crate) bundle_id: BundleId,
    pub(crate) bundle_source_uri: String,
    /// The rendered cause chain.
    pub(crate) cause: String,
}

/// What a boot pull did.
#[derive(Debug, Default)]
pub(crate) struct PullOutcome {
    /// Revisions whose packs were materialized.
    pub(crate) materialized: usize,
    /// Foreign revisions that failed and were left out of the runtime-config.
    pub(crate) skipped: Vec<SkippedRevision>,
}

impl PullOutcome {
    /// Whether `runtime-config.json` may have been (re)written, i.e. whether
    /// the caller must re-load it.
    pub(crate) fn wrote_runtime_config(&self) -> bool {
        self.materialized > 0 || !self.skipped.is_empty()
    }
}

/// How a failed pull is treated.
///
/// **Why the unset case stays fail-fast.** Without [`OWN_REVISION_ENV`] the
/// process is one of: the K8s router, an operator-env child, or a local
/// `gtc start`. Each of those serves EVERY routed revision of the environment
/// from one process — there is no "own" unit whose availability a broken
/// sibling could hold hostage, and a revision that did not materialize is a
/// revision this very process was asked to serve. Skipping it there would turn
/// a loud boot failure into a process that answers probes green while part of
/// the environment is silently dark. The per-revision lanes are different: the
/// deployer runs one workload per unit, every one of them boots the WHOLE
/// environment, and without this rule one unit's broken bundle crashes every
/// other unit's container before it binds its port.
#[derive(Clone, Debug, PartialEq, Eq)]
enum FailurePolicy {
    /// Any failure aborts the boot (the pre-existing behaviour).
    FailFast,
    /// A failure of a revision outside this process's own deployment is
    /// logged and skipped; a failure inside it is fatal.
    SkipForeign {
        own_revision: RevisionId,
        own_deployment: DeploymentId,
    },
}

impl FailurePolicy {
    fn resolve(environment: &Environment, routed: &HashSet<RevisionId>, own: Option<&str>) -> Self {
        let Some(own) = own else {
            return Self::FailFast;
        };
        let own_revision = environment.revisions.iter().find(|revision| {
            routed.contains(&revision.revision_id)
                && revision.revision_id.to_string().eq_ignore_ascii_case(own)
        });
        match own_revision {
            Some(revision) => Self::SkipForeign {
                own_revision: revision.revision_id,
                own_deployment: revision.deployment_id,
            },
            None => {
                // We cannot tell which unit we are, so we cannot tell a sibling
                // apart from ourselves. Keep the conservative behaviour.
                operator_log::warn(
                    module_path!(),
                    format!(
                        "{OWN_REVISION_ENV}=`{own}` names no routed revision in environment \
                         `{}`; every revision pull failure will abort the boot",
                        environment.environment_id
                    ),
                );
                Self::FailFast
            }
        }
    }

    /// A revision is foreign when it is neither this process's revision nor a
    /// sibling revision of the same deployment. A same-deployment sibling (a
    /// canary split) is NOT foreign: the runtime-config loader serves a
    /// deployment as a unit (its weights must sum to 10,000 bps), so leaving
    /// one of its revisions out would drop this process's own deployment too.
    fn is_foreign(&self, revision: &Revision) -> bool {
        match self {
            Self::FailFast => false,
            Self::SkipForeign {
                own_revision,
                own_deployment,
            } => revision.revision_id != *own_revision && revision.deployment_id != *own_deployment,
        }
    }
}

/// Pull and materialize every **routed** revision in `environment` that carries
/// a `bundle_source_uri`.
///
/// Only revisions referenced by a traffic split are pulled — that is exactly
/// the set the runtime-config projection serves
/// ([`materialize_runtime_config`](greentic_deploy_spec) joins `traffic_splits`
/// to `revisions`). Retained-but-unrouted revisions in the env's history are
/// skipped, so an old revision with an expired or moved bundle source cannot
/// keep a fresh worker from booting the revision live traffic actually points
/// at.
///
/// **Own vs foreign.** `own_revision` is [`OWN_REVISION_ENV`]. When it names a
/// routed revision, a pull failure of a revision in ANOTHER deployment (another
/// unit) is logged at ERROR and skipped, and boot continues; a failure of this
/// process's own revision, or of a sibling in its own deployment, is fatal.
/// When it is unset, every failure is fatal — see [`FailurePolicy`].
///
/// **Runtime-config consistency.** The deployer's materializer rewrites
/// `runtime-config.json` from the WHOLE environment after each successful
/// revision, so after a skip that file still lists the skipped revision, whose
/// packs never landed. Once the loop finishes, the projection is re-written
/// through the deployer's own writer from the environment with the skipped
/// deployments' traffic splits removed, so nothing downstream (activation, the
/// dispatcher, the cache adoption, the reload watcher) ever sees a block for a
/// revision that is not on disk. The skipped deployment simply does not serve
/// from this process — the same shape the loader's quarantine already produces
/// for a deployment whose packs are missing, minus its misleading message.
///
/// Fail-closed: a fatal error clears `runtime-config.json` (a partial file
/// could reference packs the failed revision never staged, which would
/// hard-fail `load_or_empty_in` on the next boot before this repair path can
/// re-pull), leaving the env re-pullable on the next boot.
///
/// Revisions without a `bundle_source_uri` (locally-staged, not pullable) are
/// skipped.
pub(crate) fn pull_and_materialize_bundle_revisions(
    store: &LocalFsStore,
    env_id: &EnvId,
    env_dir: &Path,
    environment: &Environment,
    own_revision: Option<&str>,
) -> anyhow::Result<PullOutcome> {
    pull_with(
        store,
        env_id,
        env_dir,
        environment,
        own_revision,
        |revision, uri| pull_one(store, env_id, revision, uri),
    )
}

/// [`pull_and_materialize_bundle_revisions`] with the per-revision pull
/// injected, so the own/foreign rule can be tested without a real bundle.
fn pull_with<F>(
    store: &LocalFsStore,
    env_id: &EnvId,
    env_dir: &Path,
    environment: &Environment,
    own_revision: Option<&str>,
    mut pull: F,
) -> anyhow::Result<PullOutcome>
where
    F: FnMut(&Revision, &str) -> anyhow::Result<()>,
{
    let routed = routed_revision_ids(environment);
    let policy = FailurePolicy::resolve(environment, &routed, own_revision);
    let mut outcome = PullOutcome::default();
    for revision in &environment.revisions {
        if !routed.contains(&revision.revision_id) {
            continue;
        }
        let Some(uri) = revision.bundle_source_uri.as_deref() else {
            continue;
        };
        match pull(revision, uri) {
            Ok(()) => outcome.materialized += 1,
            Err(err) if policy.is_foreign(revision) => {
                let skipped = SkippedRevision {
                    revision_id: revision.revision_id,
                    deployment_id: revision.deployment_id,
                    bundle_id: revision.bundle_id.clone(),
                    bundle_source_uri: uri.to_string(),
                    cause: format!("{err:#}"),
                };
                log_skipped(&skipped);
                outcome.skipped.push(skipped);
            }
            Err(err) => {
                clear_runtime_config(env_dir);
                return Err(err);
            }
        }
    }
    if !outcome.skipped.is_empty()
        && let Err(err) = reproject_without(store, env_id, &outcome.skipped)
    {
        clear_runtime_config(env_dir);
        return Err(err);
    }
    Ok(outcome)
}

/// Clear any partial runtime-config so the next boot's `load_or_empty_in` returns
/// empty and re-enters this repair path instead of hard-failing on a dangling
/// pack ref.
fn clear_runtime_config(env_dir: &Path) {
    let _ = std::fs::remove_file(env_dir.join(RUNTIME_CONFIG_FILE));
}

fn log_skipped(skipped: &SkippedRevision) {
    let message = format!(
        "revision `{}` (bundle `{}`, deployment `{}`, source `{}`) FAILED to materialize and is \
         NOT served by this process: {}. It belongs to another unit, so this process keeps \
         booting its own revision; that unit's own workload still fails until its bundle is \
         fixed and redeployed.",
        skipped.revision_id,
        skipped.bundle_id,
        skipped.deployment_id,
        skipped.bundle_source_uri,
        skipped.cause,
    );
    tracing::error!(
        revision_id = %skipped.revision_id,
        bundle_id = %skipped.bundle_id,
        deployment_id = %skipped.deployment_id,
        bundle_source_uri = %skipped.bundle_source_uri,
        "{message}"
    );
    operator_log::error(module_path!(), message);
}

/// Re-write `runtime-config.json` from the stored environment with every
/// skipped deployment's traffic split removed, through the deployer's own
/// projection + writer and under the env lock. `environment.json` itself is
/// NOT modified: the skip is this process's boot decision, not a change to the
/// environment. An empty projection deletes the file, as the deployer does.
fn reproject_without(
    store: &LocalFsStore,
    env_id: &EnvId,
    skipped: &[SkippedRevision],
) -> anyhow::Result<()> {
    let excluded: HashSet<DeploymentId> = skipped
        .iter()
        .map(|revision| revision.deployment_id)
        .collect();
    store
        .transact(env_id, |locked| -> Result<(), StoreError> {
            let mut environment = locked.load()?;
            environment
                .traffic_splits
                .retain(|split| !excluded.contains(&split.deployment_id));
            locked.refresh_runtime_config(&environment)
        })
        .with_context(|| {
            format!(
                "re-projecting runtime-config for env `{env_id}` without {} skipped revision(s)",
                skipped.len()
            )
        })
}

/// The set of revision ids referenced by the environment's traffic splits —
/// i.e. the revisions that can appear in the runtime-config projection.
fn routed_revision_ids(environment: &Environment) -> HashSet<RevisionId> {
    environment
        .traffic_splits
        .iter()
        .flat_map(|split| split.entries.iter().map(|entry| entry.revision_id))
        .collect()
}

/// Fetch `revision`'s bundle to a local archive and materialize its packs +
/// runtime-config. The deployer's materializer integrity-gates the staged
/// digest against `revision.bundle_digest` (fail-closed) and is itself
/// failure-atomic (move-aside + rollback), so a partial pull cannot brick a
/// revision the env still references.
fn pull_one(
    store: &LocalFsStore,
    env_id: &EnvId,
    revision: &Revision,
    uri: &str,
) -> anyhow::Result<()> {
    let bundle_file = bundle_ref::fetch_bundle_to_file(uri).with_context(|| {
        format!(
            "fetching bundle `{uri}` for revision `{}`",
            revision.revision_id
        )
    })?;
    materialize_revision_from_bundle(store, env_id, revision.revision_id, &bundle_file)
        .with_context(|| {
            format!(
                "materializing revision `{}` from bundle `{uri}`",
                revision.revision_id
            )
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use greentic_deploy_spec::{
        BundleId, DeploymentId, EnvironmentHostConfig, RevisionLifecycle, SchemaVersion,
        TrafficSplit, TrafficSplitEntry,
    };
    use std::path::PathBuf;

    fn env_id() -> EnvId {
        EnvId::try_from("local").unwrap()
    }

    fn make_env(revisions: Vec<Revision>) -> Environment {
        Environment {
            schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
            environment_id: env_id(),
            name: "local".to_string(),
            host_config: EnvironmentHostConfig::new(env_id()),
            packs: Vec::new(),
            messaging_endpoints: Vec::new(),
            extensions: Vec::new(),
            credentials_ref: None,
            bundles: Vec::new(),
            revisions,
            traffic_splits: Vec::new(),
            revocation: Default::default(),
            retention: Default::default(),
            health: Default::default(),
        }
    }

    /// Like [`make_env`], but adds a single traffic split routing every given
    /// revision (so they count as routed for the pull).
    fn make_env_routed(revisions: Vec<Revision>) -> Environment {
        let split = route_all(&revisions);
        let mut env = make_env(revisions);
        env.traffic_splits = split;
        env
    }

    fn route_all(revisions: &[Revision]) -> Vec<TrafficSplit> {
        if revisions.is_empty() {
            return Vec::new();
        }
        vec![TrafficSplit {
            schema: SchemaVersion::new(SchemaVersion::TRAFFIC_SPLIT_V1),
            env_id: env_id(),
            deployment_id: revisions[0].deployment_id,
            bundle_id: BundleId::new("fast2flow"),
            generation: 1,
            entries: revisions
                .iter()
                .map(|r| TrafficSplitEntry {
                    revision_id: r.revision_id,
                    weight_bps: 10_000 / revisions.len() as u32,
                })
                .collect(),
            updated_at: Utc.timestamp_opt(0, 0).unwrap(),
            updated_by: "test".to_string(),
            idempotency_key: "k".to_string(),
            authorization_ref: PathBuf::from("auth.json"),
            previous_split_ref: None,
        }]
    }

    fn make_revision(bundle_source_uri: Option<String>) -> Revision {
        Revision {
            schema: SchemaVersion::new(SchemaVersion::REVISION_V1),
            revision_id: RevisionId::new(),
            env_id: env_id(),
            bundle_id: BundleId::new("fast2flow"),
            deployment_id: DeploymentId::new(),
            sequence: 1,
            created_at: Utc.timestamp_opt(0, 0).unwrap(),
            bundle_digest: "sha256:00".to_string(),
            bundle_source_uri,
            pack_list: Vec::new(),
            pack_list_lock_ref: PathBuf::new(),
            pack_config_refs: Vec::new(),
            config_digest: String::new(),
            signature_sidecar_ref: PathBuf::from("rev.sig"),
            lifecycle: RevisionLifecycle::Ready,
            staged_at: None,
            warmed_at: None,
            drain_seconds: 0,
            abort_metrics: Vec::new(),
        }
    }

    fn throwaway_store() -> (tempfile::TempDir, LocalFsStore) {
        let tmp = tempfile::tempdir().unwrap();
        let store = LocalFsStore::new(tmp.path().to_path_buf());
        (tmp, store)
    }

    #[test]
    fn empty_environment_materializes_nothing() {
        let (tmp, store) = throwaway_store();
        let env = make_env(Vec::new());
        let count =
            pull_and_materialize_bundle_revisions(&store, &env_id(), tmp.path(), &env, None)
                .unwrap()
                .materialized;
        assert_eq!(count, 0);
    }

    #[test]
    fn routed_revision_without_a_bundle_source_is_skipped() {
        let (tmp, store) = throwaway_store();
        let env = make_env_routed(vec![make_revision(None)]);
        let count =
            pull_and_materialize_bundle_revisions(&store, &env_id(), tmp.path(), &env, None)
                .unwrap()
                .materialized;
        assert_eq!(count, 0);
    }

    #[test]
    fn non_routed_revision_with_a_bad_ref_does_not_block_boot() {
        // A retained revision with an unreachable bundle source that no
        // traffic split routes must NOT fail the boot — live traffic does not
        // depend on it.
        let (tmp, store) = throwaway_store();
        let env = make_env(vec![make_revision(Some(
            "ftp://nope/demo.gtbundle".to_string(),
        ))]);
        let count =
            pull_and_materialize_bundle_revisions(&store, &env_id(), tmp.path(), &env, None)
                .unwrap()
                .materialized;
        assert_eq!(count, 0);
    }

    #[test]
    fn routed_revision_with_unresolvable_ref_fails_closed() {
        let (tmp, store) = throwaway_store();
        // An unsupported scheme bails synchronously in `map_remote_bundle_ref`
        // — no network — proving the fetch was attempted and the boot aborts
        // rather than serving a revision whose packs never materialized.
        let env = make_env_routed(vec![make_revision(Some(
            "ftp://nope/demo.gtbundle".to_string(),
        ))]);
        let err = pull_and_materialize_bundle_revisions(&store, &env_id(), tmp.path(), &env, None)
            .expect_err("an unresolvable bundle ref must fail the boot");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("fetching bundle") && rendered.contains("ftp://nope"),
            "error should name the failed fetch, got: {rendered}"
        );
    }

    #[test]
    fn failed_pull_clears_partial_runtime_config() {
        let (tmp, store) = throwaway_store();
        let env_dir = tmp.path().join("env");
        std::fs::create_dir_all(&env_dir).unwrap();
        // Stand-in for a runtime-config left behind by an earlier revision that
        // materialized before a later one failed.
        let rc_file = env_dir.join(RUNTIME_CONFIG_FILE);
        std::fs::write(&rc_file, "{}").unwrap();

        let env = make_env_routed(vec![make_revision(Some(
            "ftp://nope/demo.gtbundle".to_string(),
        ))]);
        let _err = pull_and_materialize_bundle_revisions(&store, &env_id(), &env_dir, &env, None)
            .expect_err("bad ref fails the pull");

        assert!(
            !rc_file.exists(),
            "a partial runtime-config must be cleared so the next boot retries"
        );
    }

    // ---- own vs foreign ------------------------------------------------

    /// One revision per deployment, each with its own full-weight split — the
    /// env-canvas Cloud Run shape (one unit = one bundle = one deployment).
    fn make_env_units(revisions: Vec<Revision>) -> Environment {
        let splits = revisions
            .iter()
            .flat_map(|revision| {
                let mut split = route_all(std::slice::from_ref(revision));
                for s in &mut split {
                    s.deployment_id = revision.deployment_id;
                    s.bundle_id = revision.bundle_id.clone();
                }
                split
            })
            .collect();
        let mut env = make_env(revisions);
        env.traffic_splits = splits;
        env
    }

    fn unit(bundle: &str) -> Revision {
        let mut revision = make_revision(Some(format!("oci://registry/{bundle}:tag")));
        revision.bundle_id = BundleId::new(bundle);
        revision.pack_list_lock_ref = PathBuf::from(format!(
            "revisions/{}/bundle/pack-list.lock",
            revision.revision_id
        ));
        revision
    }

    /// A store holding `env` on disk, as a seeded worker's store does.
    ///
    /// Also records a bundle deployment for every deployment the revisions
    /// name, which the store's save-time validation requires.
    fn store_with(env: &mut Environment) -> (tempfile::TempDir, LocalFsStore, std::path::PathBuf) {
        for revision in &env.revisions {
            if env
                .bundles
                .iter()
                .any(|b| b.deployment_id == revision.deployment_id)
            {
                continue;
            }
            let (fixture, _) =
                crate::test_fixtures::env_with_active_bundle("demo", revision.bundle_id.as_str());
            let mut deployment = fixture.bundles[0].clone();
            deployment.deployment_id = revision.deployment_id;
            deployment.env_id = env_id();
            env.bundles.push(deployment);
        }
        let (tmp, store) = throwaway_store();
        store
            .transact(&env_id(), |locked| locked.save(env))
            .expect("saving the environment");
        let env_dir =
            crate::runtime_config::env_dir_in(tmp.path(), env_id().as_str()).expect("env dir");
        (tmp, store, env_dir)
    }

    /// Stand-in for the deployer's materializer: succeeds for every revision
    /// except the one named `broken`, and on success writes the WHOLE-env
    /// projection exactly as `materialize_revision_from_bundle` does.
    fn fake_pull<'a>(
        store: &'a LocalFsStore,
        broken: RevisionId,
    ) -> impl FnMut(&Revision, &str) -> anyhow::Result<()> + 'a {
        move |revision, _uri| {
            if revision.revision_id == broken {
                anyhow::bail!(
                    "invalid argument: pack-config-input `messaging-webchat-gui.json`: EOF while \
                     parsing a value at line 1 column 0"
                );
            }
            store
                .transact(&env_id(), |locked| -> Result<(), StoreError> {
                    let env = locked.load()?;
                    locked.refresh_runtime_config(&env)
                })
                .map_err(anyhow::Error::from)
        }
    }

    fn projected_revisions(env_dir: &Path) -> Vec<RevisionId> {
        let raw = std::fs::read_to_string(env_dir.join(RUNTIME_CONFIG_FILE))
            .expect("runtime-config.json exists");
        let cfg: greentic_deploy_spec::RuntimeConfig =
            serde_json::from_str(&raw).expect("runtime-config parses");
        cfg.revisions
            .iter()
            .map(|block| block.revision_id)
            .collect()
    }

    #[test]
    fn own_revision_failure_is_fatal() {
        let own = unit("outlook-helpdesk-assistant");
        let other = unit("ssc-ict-tra");
        let mut env = make_env_units(vec![other.clone(), own.clone()]);
        let (_tmp, store, env_dir) = store_with(&mut env);
        let own_id = own.revision_id.to_string();

        let err = pull_with(
            &store,
            &env_id(),
            &env_dir,
            &env,
            Some(&own_id),
            fake_pull(&store, own.revision_id),
        )
        .expect_err("this process's own revision failing must abort the boot");
        assert!(format!("{err:#}").contains("EOF while parsing"));
        assert!(
            !env_dir.join(RUNTIME_CONFIG_FILE).exists(),
            "a fatal failure still clears runtime-config so the next boot re-pulls"
        );
    }

    #[test]
    fn foreign_revision_failure_is_skipped_and_own_revision_still_serves() {
        let broken = unit("ssc-ict-tra");
        let own = unit("outlook-helpdesk-assistant");
        let third = unit("third-unit");
        // The broken unit is pulled FIRST, as in the incident.
        let mut env = make_env_units(vec![broken.clone(), own.clone(), third.clone()]);
        let (_tmp, store, env_dir) = store_with(&mut env);
        let own_id = own.revision_id.to_string();

        let outcome = pull_with(
            &store,
            &env_id(),
            &env_dir,
            &env,
            Some(&own_id),
            fake_pull(&store, broken.revision_id),
        )
        .expect("a sibling unit's broken bundle must not abort this boot");

        assert_eq!(outcome.materialized, 2);
        assert_eq!(outcome.skipped.len(), 1);
        let skipped = &outcome.skipped[0];
        assert_eq!(skipped.revision_id, broken.revision_id);
        assert_eq!(skipped.bundle_id.as_str(), "ssc-ict-tra");
        assert!(skipped.bundle_source_uri.contains("ssc-ict-tra"));
        assert!(skipped.cause.contains("EOF while parsing"));

        // The projection must not reference the revision whose packs never
        // landed, or a later step fails on a dangling ref.
        let projected = projected_revisions(&env_dir);
        assert!(projected.contains(&own.revision_id));
        assert!(projected.contains(&third.revision_id));
        assert!(
            !projected.contains(&broken.revision_id),
            "the skipped revision must be removed from runtime-config, got {projected:?}"
        );

        // environment.json is untouched: the skip is a boot decision only.
        let stored = store
            .transact(&env_id(), |locked| locked.load())
            .expect("reload env");
        assert_eq!(stored.traffic_splits.len(), 3);
    }

    #[test]
    fn a_failing_sibling_in_the_own_deployment_is_fatal() {
        // A canary split: two revisions of ONE deployment. The loader serves a
        // deployment as a unit, so skipping the sibling would drop our own
        // deployment too — that must stay fatal.
        let own = unit("outlook-helpdesk-assistant");
        let mut canary = unit("outlook-helpdesk-assistant");
        canary.deployment_id = own.deployment_id;
        let mut env = make_env_routed(vec![own.clone(), canary.clone()]);
        for split in &mut env.traffic_splits {
            split.bundle_id = own.bundle_id.clone();
        }
        let (_tmp, store, env_dir) = store_with(&mut env);
        let own_id = own.revision_id.to_string();

        pull_with(
            &store,
            &env_id(),
            &env_dir,
            &env,
            Some(&own_id),
            fake_pull(&store, canary.revision_id),
        )
        .expect_err("a sibling in this process's own deployment is not foreign");
        assert!(!env_dir.join(RUNTIME_CONFIG_FILE).exists());
    }

    #[test]
    fn without_an_own_revision_every_failure_stays_fatal() {
        // Router / operator-env / local: one process serves every revision, so
        // a revision that did not materialize is one it was asked to serve.
        let broken = unit("ssc-ict-tra");
        let other = unit("outlook-helpdesk-assistant");
        let mut env = make_env_units(vec![other, broken.clone()]);
        let (_tmp, store, env_dir) = store_with(&mut env);

        pull_with(
            &store,
            &env_id(),
            &env_dir,
            &env,
            None,
            fake_pull(&store, broken.revision_id),
        )
        .expect_err("with no own revision the pull keeps failing fast");
        assert!(!env_dir.join(RUNTIME_CONFIG_FILE).exists());
    }

    #[test]
    fn an_own_revision_naming_no_routed_revision_stays_fatal() {
        let broken = unit("ssc-ict-tra");
        let other = unit("outlook-helpdesk-assistant");
        let mut env = make_env_units(vec![other, broken.clone()]);
        let (_tmp, store, env_dir) = store_with(&mut env);
        let stranger = RevisionId::new().to_string();

        pull_with(
            &store,
            &env_id(),
            &env_dir,
            &env,
            Some(&stranger),
            fake_pull(&store, broken.revision_id),
        )
        .expect_err("an unknown own revision cannot tell siblings from itself");
    }

    #[test]
    fn own_revision_matches_case_insensitively() {
        let broken = unit("ssc-ict-tra");
        let own = unit("outlook-helpdesk-assistant");
        let mut env = make_env_units(vec![broken.clone(), own.clone()]);
        let (_tmp, store, env_dir) = store_with(&mut env);
        let own_id = own.revision_id.to_string().to_ascii_lowercase();

        let outcome = pull_with(
            &store,
            &env_id(),
            &env_dir,
            &env,
            Some(&own_id),
            fake_pull(&store, broken.revision_id),
        )
        .expect("lower-cased ULID still names this process's revision");
        assert_eq!(outcome.skipped.len(), 1);
    }
}
