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
use greentic_deploy_spec::{Environment, Revision, RevisionId};
use greentic_deployer::cli::bundle_stage::materialize_revision_from_bundle;
use greentic_deployer::environment::LocalFsStore;
use greentic_types::EnvId;

use crate::bundle_ref;
use crate::runtime_config::RUNTIME_CONFIG_FILE;

/// Pull and materialize every **routed** revision in `environment` that carries
/// a `bundle_source_uri`. Returns the number of revisions materialized.
///
/// Only revisions referenced by a traffic split are pulled — that is exactly
/// the set the runtime-config projection serves
/// ([`materialize_runtime_config`](greentic_deploy_spec) joins `traffic_splits`
/// to `revisions`). Retained-but-unrouted revisions in the env's history are
/// skipped, so an old revision with an expired or moved bundle source cannot
/// keep a fresh worker from booting the revision live traffic actually points
/// at.
///
/// Fail-closed: a fetch or materialization error aborts the boot rather than
/// serving a degraded surface. Because the deployer's materializer rewrites
/// `runtime-config.json` from the whole environment after each successful
/// revision, a failure partway through a multi-revision pull can leave a
/// `runtime-config.json` that references packs the failed revision never
/// staged — which would hard-fail `load_or_empty` on the next boot before this
/// repair path can re-pull. So on any error this clears that partial file,
/// leaving the env re-pullable on the next boot.
///
/// Revisions without a `bundle_source_uri` (locally-staged, not pullable) are
/// skipped.
pub(crate) fn pull_and_materialize_bundle_revisions(
    store: &LocalFsStore,
    env_id: &EnvId,
    env_dir: &Path,
    environment: &Environment,
) -> anyhow::Result<usize> {
    let routed = routed_revision_ids(environment);
    let mut materialized = 0;
    for revision in &environment.revisions {
        if !routed.contains(&revision.revision_id) {
            continue;
        }
        let Some(uri) = revision.bundle_source_uri.as_deref() else {
            continue;
        };
        if let Err(err) = pull_one(store, env_id, revision, uri) {
            // Clear any partial runtime-config so the next boot's
            // `load_or_empty` returns empty and re-enters this repair path
            // instead of hard-failing on a dangling pack ref.
            let _ = std::fs::remove_file(env_dir.join(RUNTIME_CONFIG_FILE));
            return Err(err);
        }
        materialized += 1;
    }
    Ok(materialized)
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
            pull_and_materialize_bundle_revisions(&store, &env_id(), tmp.path(), &env).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn routed_revision_without_a_bundle_source_is_skipped() {
        let (tmp, store) = throwaway_store();
        let env = make_env_routed(vec![make_revision(None)]);
        let count =
            pull_and_materialize_bundle_revisions(&store, &env_id(), tmp.path(), &env).unwrap();
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
            pull_and_materialize_bundle_revisions(&store, &env_id(), tmp.path(), &env).unwrap();
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
        let err = pull_and_materialize_bundle_revisions(&store, &env_id(), tmp.path(), &env)
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
        let _err = pull_and_materialize_bundle_revisions(&store, &env_id(), &env_dir, &env)
            .expect_err("bad ref fails the pull");

        assert!(
            !rc_file.exists(),
            "a partial runtime-config must be cleared so the next boot retries"
        );
    }
}
