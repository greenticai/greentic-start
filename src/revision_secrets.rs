//! Boot-time seeding of declared `generated` provider secrets for the
//! bundle-less `start --env` serve path.
//!
//! The legacy `--bundle` boot mints declared `generated` secrets (e.g. the
//! webchat-gui `jwt_signing_key`) before serving, via
//! `runtime::ensure_generated_provider_secrets`. The env/revision path never
//! did, so a bundle only ever started through `gtc start` (env deploy) had no
//! signing key in any store and every DirectLine token request failed with
//! `secret_error: not-found`. This module walks the activation's pinned packs
//! and runs the same [`SecretsSetup`] minting logic against the store the
//! serve-path secrets manager reads (the env dir's DevStore, or the
//! `GREENTIC_DEV_SECRETS_PATH` override the launcher exported).

use std::collections::{HashMap, HashSet};
use std::env;
use std::path::{Path, PathBuf};

use anyhow::Context;
use greentic_deploy_spec::{Environment, PackListLock};
use greentic_deployer::path_safety::normalize_under_root;

use crate::operator_log;
use crate::runtime_config::LoadedRuntimeConfig;
use crate::secrets_backend::SecretsBackendKind;
use crate::secrets_gate::ENV_SERVE_SECRETS_BACKEND;
use crate::secrets_setup::SecretsSetup;

/// Mint missing `generated` secrets for every pack pinned by `rc`'s revision
/// blocks, scoped per deployment tenant/team. No-op for runtime-read-only
/// backends (`env`, `vault`) — generated secrets must be pre-provisioned there
/// by the operator. Idempotent: existing entries are preserved unless the pack
/// declares `regenerate_if_present`.
pub(crate) async fn ensure_generated_secrets_for_activation(
    env_dir: &Path,
    rc: &LoadedRuntimeConfig,
    environment: &Environment,
) -> anyhow::Result<()> {
    let raw = env::var(ENV_SERVE_SECRETS_BACKEND).unwrap_or_default();
    let kind = SecretsBackendKind::parse(&raw)
        .with_context(|| format!("invalid {ENV_SERVE_SECRETS_BACKEND}={raw:?}"))?;
    if !matches!(kind, SecretsBackendKind::DevStore) {
        operator_log::info(
            module_path!(),
            format!(
                "skipping generated-secret seeding: {ENV_SERVE_SECRETS_BACKEND}={kind} is \
                 runtime-read-only; provision generated secrets in that backend"
            ),
        );
        return Ok(());
    }

    // deployment_id -> (tenant, team). The runtime-config blocks carry the
    // deployment id; the tenant binding lives on the Environment (same
    // derivation as `revision_boot::deployment_index`, which is private and
    // does not expose the team).
    let scopes: HashMap<String, (String, String)> = environment
        .bundles
        .iter()
        .map(|dep| {
            (
                dep.deployment_id.to_string(),
                (
                    dep.route_binding.tenant_selector.tenant.clone(),
                    dep.route_binding.tenant_selector.team.clone(),
                ),
            )
        })
        .collect();

    let mut seeded: HashSet<(String, String, String)> = HashSet::new();
    for block in &rc.revisions {
        // Unknown deployments are rejected by activation itself; nothing to
        // seed for them here.
        let Some((tenant, team)) = scopes.get(&block.deployment_id) else {
            continue;
        };
        let setup =
            SecretsSetup::new(env_dir, &rc.env_id, tenant, Some(team)).with_context(|| {
                format!(
                    "opening secrets store to seed generated secrets (tenant={tenant} team={team})"
                )
            })?;
        for (pack_id, pack_path) in
            pinned_packs(env_dir, &block.revision_id, &block.pack_list_refs)?
        {
            if !seeded.insert((tenant.clone(), team.clone(), pack_id.clone())) {
                continue;
            }
            setup
                .ensure_pack_generated_secrets(&pack_path, &pack_id)
                .await
                .with_context(|| {
                    format!(
                        "seeding generated secrets for pack `{pack_id}` (tenant={tenant} \
                         team={team})"
                    )
                })?;
        }
    }
    Ok(())
}

/// Parse the revision's `pack-list.lock` file(s) into `(pack_id, abs_path)`
/// pairs. Locks pinning a different revision are skipped (activation reports
/// that misconfiguration with its own error); pack paths are re-contained
/// under `env_dir` like `revision_boot::read_revision_pack_refs`.
fn pinned_packs(
    env_dir: &Path,
    revision_id: &str,
    lock_paths: &[PathBuf],
) -> anyhow::Result<Vec<(String, PathBuf)>> {
    let mut packs = Vec::new();
    for lock_path in lock_paths {
        let bytes = std::fs::read(lock_path)
            .with_context(|| format!("reading pack-list.lock `{}`", lock_path.display()))?;
        let lock: PackListLock = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing pack-list.lock `{}`", lock_path.display()))?;
        if lock.revision_id.to_string() != revision_id {
            continue;
        }
        for pack in lock.packs {
            let abs = normalize_under_root(env_dir, &pack.path).with_context(|| {
                format!(
                    "resolving pinned pack `{}` from `{}`",
                    pack.path.display(),
                    lock_path.display()
                )
            })?;
            if abs.is_file() {
                packs.push((pack.pack_id.to_string(), abs));
            }
        }
    }
    Ok(packs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_config::ResolvedRevisionBlock;
    use greentic_deploy_spec::{
        BundleDeployment, BundleDeploymentStatus, BundleId, CustomerId, DeploymentId,
        EnvironmentHostConfig, LockedPack, PackId, PartyId, RevenueShareEntry, RevisionId,
        RouteBinding, SchemaVersion, TenantSelector,
    };
    use greentic_types::EnvId;
    use std::io::Write as _;
    use tempfile::tempdir;
    use tokio::runtime::Runtime;

    const ENV_ID: &str = "local";
    const STORE_URI: &str = "secrets://local/demo/_/messaging_webchat_gui/jwt_signing_key";

    fn env_id() -> EnvId {
        EnvId::try_from(ENV_ID).unwrap()
    }

    fn make_deployment(deployment_id: DeploymentId, tenant: &str) -> BundleDeployment {
        BundleDeployment {
            schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
            deployment_id,
            env_id: env_id(),
            bundle_id: BundleId::new("hr-onboarding-demo"),
            customer_id: CustomerId::new("acme"),
            status: BundleDeploymentStatus::Active,
            current_revisions: Vec::new(),
            route_binding: RouteBinding {
                hosts: Vec::new(),
                path_prefixes: Vec::new(),
                tenant_selector: TenantSelector {
                    tenant: tenant.to_string(),
                    team: "default".to_string(),
                },
            },
            revenue_share: vec![RevenueShareEntry {
                party_id: PartyId::new("greentic"),
                basis_points: 10_000,
            }],
            revenue_policy_ref: PathBuf::from("revenue.json"),
            usage: None,
            created_at: chrono::Utc::now(),
            authorization_ref: PathBuf::from("auth.json"),
            config_overrides: std::collections::BTreeMap::new(),
        }
    }

    fn make_env(bundles: Vec<BundleDeployment>) -> Environment {
        Environment {
            schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
            environment_id: env_id(),
            name: ENV_ID.to_string(),
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
            bundles,
            revisions: Vec::new(),
            traffic_splits: Vec::new(),
            revocation: Default::default(),
            retention: Default::default(),
            health: Default::default(),
        }
    }

    /// Write a minimal `.gtpack` (zip) declaring one `generated` secret —
    /// mirrors `secrets_setup::tests::write_pack_with_requirements_json`.
    fn write_webchat_pack(path: &Path) {
        let file = std::fs::File::create(path).expect("pack");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file(
            "assets/secret-requirements.json",
            zip::write::FileOptions::<()>::default(),
        )
        .expect("start file");
        let requirements = serde_json::json!([
            {
                "key": "jwt_signing_key",
                "required": true,
                "generated": {
                    "policy": "random",
                    "length": 20,
                    "encoding": "raw_text",
                    "scope": { "level": "tenant", "team": "_" },
                    "regenerate_if_present": false
                }
            }
        ]);
        zip.write_all(&serde_json::to_vec(&requirements).expect("requirements"))
            .expect("write");
        zip.finish().expect("finish");
    }

    /// Lay out an env dir with one revision pinning the fixture pack and
    /// return `(rc, environment)` for it.
    fn fixture(env_dir: &Path) -> (LoadedRuntimeConfig, Environment) {
        let revision_id = RevisionId::new();
        let pack_rel = PathBuf::from("revisions/r1/packs/messaging-webchat-gui.gtpack");
        let pack_abs = env_dir.join(&pack_rel);
        std::fs::create_dir_all(pack_abs.parent().unwrap()).expect("pack dir");
        write_webchat_pack(&pack_abs);

        let lock = PackListLock {
            schema: SchemaVersion::new(SchemaVersion::PACK_LIST_LOCK_V1),
            revision_id,
            packs: vec![LockedPack {
                pack_id: PackId::new("messaging-webchat-gui"),
                path: pack_rel,
                digest: "sha256:0000".to_string(),
            }],
        };
        let lock_path = env_dir.join("revisions/r1/pack-list.lock");
        std::fs::write(&lock_path, serde_json::to_vec(&lock).expect("lock json")).expect("lock");

        let deployment_id = DeploymentId::new();
        let environment = make_env(vec![make_deployment(deployment_id, "demo")]);
        let rc = LoadedRuntimeConfig {
            env_id: ENV_ID.to_string(),
            revisions: vec![ResolvedRevisionBlock {
                deployment_id: deployment_id.to_string(),
                revision_id: revision_id.to_string(),
                bundle_id: "hr-onboarding-demo".to_string(),
                pack_list_refs: vec![lock_path],
                pack_config_refs: Vec::new(),
                weight_bps: 10_000,
            }],
        };
        (rc, environment)
    }

    fn read_seeded_key(env_dir: &Path, runtime: &Runtime) -> anyhow::Result<Vec<u8>> {
        use greentic_secrets_lib::SecretsStore as _;
        let store = greentic_secrets_lib::core::seed::DevStore::with_path(
            env_dir.join(".greentic/dev/.dev.secrets.env"),
        )?;
        runtime
            .block_on(async { store.get(STORE_URI).await })
            .map_err(|err| anyhow::anyhow!("{err}"))
    }

    fn run_seeding(
        env_dir: &Path,
        rc: &LoadedRuntimeConfig,
        environment: &Environment,
        runtime: &Runtime,
    ) -> anyhow::Result<()> {
        let guard = crate::test_env_lock().lock().unwrap();
        unsafe {
            env::remove_var(ENV_SERVE_SECRETS_BACKEND);
            env::remove_var("GREENTIC_DEV_SECRETS_PATH");
        }
        let result = runtime.block_on(ensure_generated_secrets_for_activation(
            env_dir,
            rc,
            environment,
        ));
        drop(guard);
        result
    }

    #[test]
    fn seeds_generated_secret_from_pack_list_lock() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let (rc, environment) = fixture(dir.path());
        let runtime = Runtime::new()?;
        run_seeding(dir.path(), &rc, &environment, &runtime)?;
        let value = read_seeded_key(dir.path(), &runtime)?;
        assert_eq!(value.len(), 20, "generated key has the declared length");
        Ok(())
    }

    #[test]
    fn seeding_is_idempotent() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let (rc, environment) = fixture(dir.path());
        let runtime = Runtime::new()?;
        run_seeding(dir.path(), &rc, &environment, &runtime)?;
        let first = read_seeded_key(dir.path(), &runtime)?;
        run_seeding(dir.path(), &rc, &environment, &runtime)?;
        let second = read_seeded_key(dir.path(), &runtime)?;
        assert_eq!(first, second, "regenerate_if_present:false preserves value");
        Ok(())
    }

    #[test]
    fn skips_non_dev_store_backends() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let (rc, environment) = fixture(dir.path());
        let runtime = Runtime::new()?;
        let guard = crate::test_env_lock().lock().unwrap();
        unsafe {
            env::set_var(ENV_SERVE_SECRETS_BACKEND, "vault");
            env::remove_var("GREENTIC_DEV_SECRETS_PATH");
        }
        let result = runtime.block_on(ensure_generated_secrets_for_activation(
            dir.path(),
            &rc,
            &environment,
        ));
        unsafe {
            env::remove_var(ENV_SERVE_SECRETS_BACKEND);
        }
        drop(guard);
        result?;
        assert!(
            !dir.path().join(".greentic/dev/.dev.secrets.env").exists(),
            "read-only backends must not create a dev store"
        );
        Ok(())
    }
}
