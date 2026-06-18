//! M2 worker-boot bundle pull.
//!
//! A bundle-less worker (e.g. a K8s pod running `greentic-start start --env
//! <id>`) boots from a staged env store. In production that store is seeded
//! from a ConfigMap that can only carry `environment.json` — pack binaries and
//! the `runtime-config.json` projection are absent, so without this step the
//! worker activates a zero-revision runtime and serves probes only.
//!
//! When the environment's revisions were resolved from a bundle source
//! ([`Revision::bundle_source_uri`](greentic_deploy_spec::Revision::bundle_source_uri)),
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

use anyhow::Context;
use greentic_deploy_spec::Environment;
use greentic_deployer::environment::LocalFsStore;
use greentic_types::EnvId;

use crate::bundle_ref;

/// Pull and materialize every revision in `environment` that carries a
/// `bundle_source_uri`. Returns the number of revisions materialized.
///
/// Fail-closed: a fetch or materialization error aborts the boot rather than
/// serving a degraded surface. The deployer's materializer is itself
/// failure-atomic (it moves an existing revision dir aside and rolls back on
/// error), so a partial pull cannot brick a revision the env still references.
///
/// Revisions without a `bundle_source_uri` (locally-staged, not pullable) are
/// skipped — they either already have their packs on disk or are served by a
/// non-worker deployment.
pub(crate) fn pull_and_materialize_bundle_revisions(
    store: &LocalFsStore,
    env_id: &EnvId,
    environment: &Environment,
) -> anyhow::Result<usize> {
    let mut materialized = 0usize;
    for revision in &environment.revisions {
        let Some(uri) = revision.bundle_source_uri.as_deref() else {
            continue;
        };
        let bundle_file = bundle_ref::fetch_bundle_to_file(uri).with_context(|| {
            format!(
                "fetching bundle `{uri}` for revision `{}`",
                revision.revision_id
            )
        })?;
        greentic_deployer::cli::bundle_stage::materialize_revision_from_bundle(
            store,
            env_id,
            revision.revision_id,
            &bundle_file,
        )
        .with_context(|| {
            format!(
                "materializing revision `{}` from bundle `{uri}`",
                revision.revision_id
            )
        })?;
        materialized += 1;
    }
    Ok(materialized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use greentic_deploy_spec::{
        BundleId, DeploymentId, EnvironmentHostConfig, Revision, RevisionId, RevisionLifecycle,
        SchemaVersion,
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
            host_config: EnvironmentHostConfig {
                env_id: env_id(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
                gui_enabled: None,
            },
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
    fn revisions_without_a_bundle_source_are_skipped() {
        let (_tmp, store) = throwaway_store();
        let env = make_env(vec![make_revision(None), make_revision(None)]);
        let count = pull_and_materialize_bundle_revisions(&store, &env_id(), &env).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn empty_environment_materializes_nothing() {
        let (_tmp, store) = throwaway_store();
        let env = make_env(Vec::new());
        let count = pull_and_materialize_bundle_revisions(&store, &env_id(), &env).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn unresolvable_bundle_ref_fails_closed() {
        let (_tmp, store) = throwaway_store();
        // An unsupported scheme bails synchronously in `map_remote_bundle_ref`
        // — no network — proving the fetch was attempted and the boot aborts
        // rather than serving a revision whose packs never materialized.
        let env = make_env(vec![make_revision(Some(
            "ftp://nope/demo.gtbundle".to_string(),
        ))]);
        let err = pull_and_materialize_bundle_revisions(&store, &env_id(), &env)
            .expect_err("an unresolvable bundle ref must fail the boot");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("fetching bundle") && rendered.contains("ftp://nope"),
            "error should name the failed fetch, got: {rendered}"
        );
    }
}
