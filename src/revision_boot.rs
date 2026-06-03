//! Phase B / B2 — activate a materialized `runtime-config.v1` into loaded
//! revision runtimes.
//!
//! B0 ([`crate::runtime_config`]) loads + validates the materialized config and
//! resolves every pack-list-lock ref to an existing file under the env dir.
//! This module takes that validated [`LoadedRuntimeConfig`] and:
//!
//! 1. loads the env's [`Environment`] to resolve each revision's `deployment_id`
//!    to the tenant (`route_binding.tenant_selector.tenant`) and `customer_id`
//!    it was deployed under — the runtime-config itself carries no tenant;
//! 2. builds an embedded [`RunnerHost`] with one [`HostConfig`] per distinct
//!    tenant;
//! 3. reads each revision's `pack-list.lock`, turns its pinned packs into
//!    [`RevisionPackRef`]s (env-relative path + `sha256:<hex>` digest), and
//!    loads + digest-verifies them via [`TenantRuntime::load_revision`], keying
//!    each into the host's
//!    [`ActivePacks`](greentic_runner_host::runtime::ActivePacks);
//! 4. builds the [`RevisionDispatcher`] from the same config under a stable
//!    per-env HMAC signing key;
//! 5. discovers each loaded revision's pack-declared HTTP routes and stamps them
//!    with the revision's [`RevisionScope`], and builds the request→deployment
//!    [`DeploymentRouteTable`] from the environment's Active deployments.
//!
//! Steps 4 + 5 produce a [`RevisionIngressRouting`] the ingress consumes to
//! resolve a request to a deployment, pick a revision by traffic split, and find
//! that revision's route. Running the resolved request through the revision's
//! runtime (the execution bridge from HTTP → `RunnerHost::handle_activity`) is
//! the remaining step; until then the caller activates, reports, and drops the
//! host. The activation is a self-contained, testable unit.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, anyhow, bail};
use greentic_deploy_spec::{
    BundleDeploymentStatus, BundleId, DeploymentId, Environment, PackListLock, RevisionId,
};
use greentic_deployer::path_safety::normalize_under_root;
use greentic_runner_host::runtime::{RevisionPackRef, TenantRuntime};
use greentic_runner_host::storage::{
    new_session_store, new_state_store, session_host_from, state_host_from,
};
use greentic_runner_host::{HostBuilder, HostConfig, RunnerHost, TenantBindings};

use crate::deployment_routes::{DeploymentRouteTable, RevisionIngressRouting};
use crate::endpoint_admit::EndpointAdmit;
use crate::http_routes::{
    HttpRouteDescriptor, HttpRouteTable, RevisionScope, discover_revision_routes,
};
use crate::revision_dispatcher::{RevisionDispatcher, RevisionDispatcherConfig, parse_ulid};
use crate::runtime_config::{LoadedRuntimeConfig, env_dir_in};
use crate::secrets_gate::DynSecretsManager;

/// Filename of the per-env revision-dispatcher HMAC signing key, kept under the
/// env directory so cookie/pin stickiness survives restarts. 32 raw bytes,
/// mode `0600`.
const SIGNING_KEY_FILE: &str = "revision-signing.key";

/// The outcome of activating a runtime-config: a host with every active
/// revision loaded into its `ActivePacks`, plus the ingress-routing artifacts
/// (dispatcher + revision-scoped HTTP routes + request→deployment map) that the
/// ingress consumes to serve traffic across them.
pub(crate) struct RuntimeConfigActivation {
    /// Embedded host holding the loaded revision runtimes. The execution bridge
    /// ([`crate::revision_serve`]) runs each request against the resolved
    /// revision's runtime through `RunnerHost::handle_activity_for_revision`.
    pub(crate) host: RunnerHost,
    /// Dispatcher + revision-scoped HTTP routes + request→deployment map, ready
    /// to thread into [`crate::http_ingress`] via `HttpIngressConfig`.
    pub(crate) routing: RevisionIngressRouting,
}

/// What a deployment in the `Environment` says about itself, used both to key
/// revision runtimes under the right tenant and to fail closed on a stale
/// runtime-config that no longer agrees with the environment.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DeploymentMeta {
    tenant: String,
    customer_id: String,
    status: BundleDeploymentStatus,
    /// The bundle the deployment is (immutably) bound to.
    bundle_id: String,
    /// Path prefixes the deployment binds. Used by provider-webhook route
    /// synthesis to mount routes under the deployment's own URL space rather
    /// than at the root.
    path_prefixes: Vec<String>,
}

/// Activate `rc` under `store_root`: load every active revision's packs into a
/// fresh [`RunnerHost`] and build the [`RevisionDispatcher`].
///
/// `store_root` is the environments root (`~/.greentic/environments` in
/// production; a temp dir under test) — the env dir is `<store_root>/<env_id>`.
/// `env` is the pre-loaded [`Environment`] for `rc.env_id`; passing it in (vs
/// re-reading from disk) avoids a duplicate file read AND the TOCTOU window
/// between the caller's bind-address resolution and the activation's
/// deployment/tenant resolution.
pub(crate) async fn activate_runtime_config(
    store_root: &Path,
    rc: &LoadedRuntimeConfig,
    secrets: DynSecretsManager,
    env: &Environment,
) -> anyhow::Result<RuntimeConfigActivation> {
    // `env_dir_in` validates `rc.env_id` as a safe directory segment via
    // `EnvId::new`; no separate `EnvId::new` call is needed.
    let env_dir = env_dir_in(store_root, &rc.env_id)?;

    if env.environment_id.as_str() != rc.env_id {
        bail!(
            "environment `{}` was loaded for activation of runtime-config naming env `{}`",
            env.environment_id,
            rc.env_id
        );
    }
    let deployments = deployment_index(env);

    // Resolve + validate every revision's deployment up front: it fails fast on
    // a stale/inconsistent runtime-config and yields the distinct tenant set the
    // host must be configured for before `build()`.
    //
    // We cross-check against the loaded `Environment` only where it is
    // unambiguous and does not duplicate the operator's materializer: the
    // deployment must exist, be `Active`, and be bound to the bundle the block
    // names. We deliberately do NOT re-derive traffic-split membership/weight or
    // filter by `Revision.lifecycle` — the materializer is authoritative for
    // which revisions serve and intentionally admits draining (non-`Ready`)
    // revisions, and per-pack integrity is enforced by the digest check in
    // `TenantRuntime::load_revision`.
    let mut tenants: HashSet<&str> = HashSet::new();
    for block in &rc.revisions {
        let meta = deployments.get(block.deployment_id.as_str()).ok_or_else(|| {
            anyhow!(
                "runtime-config references deployment `{}` that is not present in environment `{}`",
                block.deployment_id,
                rc.env_id
            )
        })?;
        if meta.status != BundleDeploymentStatus::Active {
            bail!(
                "runtime-config references deployment `{}` whose status is {:?}, not Active — \
                 refusing to activate a stale runtime-config",
                block.deployment_id,
                meta.status
            );
        }
        if meta.bundle_id != block.bundle_id {
            bail!(
                "runtime-config block for deployment `{}` pins bundle `{}`, but that deployment \
                 is bound to bundle `{}`",
                block.deployment_id,
                block.bundle_id,
                meta.bundle_id
            );
        }
        tenants.insert(meta.tenant.as_str());
    }

    // One minimal HostConfig per tenant. Flow-type bindings (routing) are not
    // needed to load + key packs into ActivePacks — they get enriched when the
    // ingress consumer lands (B3). The secrets backend is supplied by the caller
    // (the env's resolved manager) so activation never silently falls back to
    // `HostBuilder`'s default env-var backend (which rejects non-local envs).
    //
    // `HostBuilder::build()` rejects an empty configs map, so the N1.2 bundle-
    // less path (no revisions yet attached) seeds a placeholder tenant keyed by
    // env_id. The dispatcher then has zero deployments, so the placeholder is
    // never resolved at request time — it only exists to satisfy the builder
    // invariant and keep the activation surface uniform across empty and
    // populated runtime-configs.
    let mut builder = HostBuilder::new().with_secrets_manager(secrets);
    let effective_tenants: Vec<String> = if tenants.is_empty() {
        vec![rc.env_id.clone()]
    } else {
        tenants.iter().map(|t| (*t).to_string()).collect()
    };
    for tenant in effective_tenants {
        builder = builder.with_config(HostConfig::from_gtbind(TenantBindings {
            tenant,
            packs: Vec::new(),
            env_passthrough: Vec::new(),
        }));
    }
    let host = builder
        .build()
        .context("building embedded runner host for revision activation")?;

    // Revision-scoped HTTP routes accumulated across every loaded revision; the
    // ingress matches against these via `match_request_for_revision` once the
    // dispatcher picks a revision.
    let mut scoped_routes: Vec<HttpRouteDescriptor> = Vec::new();

    let configs = host.tenant_configs();
    for block in &rc.revisions {
        // Both lookups are infallible: the validation loop above proved every
        // block's deployment is present, and registered a host config for its
        // tenant. `expect` documents that structural invariant.
        let meta = deployments
            .get(block.deployment_id.as_str())
            .expect("deployment validated in the loop above");
        let deployment_id = DeploymentId(parse_ulid(&block.deployment_id, "deployment_id")?);
        let revision_id = RevisionId(parse_ulid(&block.revision_id, "revision_id")?);
        let bundle_id = BundleId::new(&block.bundle_id);
        let config = configs
            .get(&meta.tenant)
            .cloned()
            .expect("host config registered for tenant in the loop above");

        let pack_refs = read_revision_pack_refs(&env_dir, &revision_id, &block.pack_list_refs)
            .with_context(|| {
                format!("reading pinned packs for revision `{}`", block.revision_id)
            })?;

        // Discover this revision's HTTP routes in a single per-pack manifest
        // read: declared (`greentic.http-routes.v1`) AND synthesized provider
        // webhooks (`greentic.provider-extension.v1` with `ingest_http`,
        // mounted under each of the deployment's path prefixes as
        // `<prefix>/webhook/<provider-name>`). Done before `load_revision`
        // consumes `bundle_id`.
        let scope = RevisionScope {
            deployment_id,
            bundle_id: bundle_id.clone(),
            revision_id,
        };
        let pack_paths: Vec<PathBuf> = pack_refs.iter().map(|r| r.path.clone()).collect();
        scoped_routes.extend(discover_revision_routes(
            &pack_paths,
            &scope,
            &meta.path_prefixes,
        ));

        // Session isolation: give each revision its OWN session and state store
        // rather than sharing the host's. The session/resume/state backend keys
        // on `(env, tenant, user)` plus pack/flow, NOT on the revision, so two
        // live revisions of the same pack for one tenant sharing a backend would
        // let a `wait`/resume snapshot created by revision A be fetched — or
        // clobbered — by revision B during a traffic split. A fresh per-revision
        // store namespaces snapshot + resume + working state in one move. This is
        // the caller obligation documented on
        // `RunnerHost::handle_activity_for_revision`.
        let session_store = new_session_store();
        let session_host = session_host_from(Arc::clone(&session_store));
        let state_store = new_state_store();
        let state_host = state_host_from(Arc::clone(&state_store));

        let runtime = TenantRuntime::load_revision(
            &pack_refs,
            config,
            None,
            host.wasi_policy(),
            session_host,
            session_store,
            state_store,
            state_host,
            host.secrets_manager(),
            deployment_id,
            bundle_id.clone(),
            revision_id,
            Some(meta.customer_id.clone()),
        )
        .await
        .with_context(|| format!("loading revision `{}`", block.revision_id))?;

        host.active_packs()
            .insert_revision(&meta.tenant, deployment_id, bundle_id, revision_id, runtime)
            .with_context(|| {
                format!(
                    "inserting revision `{}` into active packs",
                    block.revision_id
                )
            })?;
    }

    let signing_key = load_or_create_signing_key(&env_dir)?;
    let dispatcher = RevisionDispatcher::from_runtime_config(
        RevisionDispatcherConfig::new(&rc.env_id, signing_key),
        rc,
    )
    .context("building revision dispatcher")?;

    let routing = RevisionIngressRouting {
        dispatcher: Arc::new(dispatcher),
        http_routes: HttpRouteTable::from_descriptors(scoped_routes),
        deployment_routes: DeploymentRouteTable::from_environment(env),
        endpoint_admit: Arc::new(EndpointAdmit::from_environment(env)),
    };

    Ok(RuntimeConfigActivation { host, routing })
}

/// Index a deployment's tenant + customer by `deployment_id` string. The
/// runtime-config blocks carry the deployment id; the tenant binding lives on
/// the `Environment`'s `BundleDeployment.route_binding`.
fn deployment_index(env: &Environment) -> HashMap<String, DeploymentMeta> {
    env.bundles
        .iter()
        .map(|dep| {
            (
                dep.deployment_id.to_string(),
                DeploymentMeta {
                    tenant: dep.route_binding.tenant_selector.tenant.clone(),
                    customer_id: dep.customer_id.as_str().to_string(),
                    status: dep.status,
                    bundle_id: dep.bundle_id.as_str().to_string(),
                    path_prefixes: dep.route_binding.path_prefixes.clone(),
                },
            )
        })
        .collect()
}

/// Read a revision's `pack-list.lock` file(s) and turn the pinned packs into
/// [`RevisionPackRef`]s. Each `LockedPack.path` is env-relative; it is
/// re-contained under `env_dir` (defence in depth — the lock is ours but its
/// `path` field is still data) and confirmed to be a regular file.
///
/// `lock_paths` are the already-resolved absolute lock paths from B0. The lock's
/// own `revision_id` must match `expected` so a misplaced or cross-revision lock
/// is rejected rather than silently activated.
fn read_revision_pack_refs(
    env_dir: &Path,
    expected: &RevisionId,
    lock_paths: &[PathBuf],
) -> anyhow::Result<Vec<RevisionPackRef>> {
    let mut refs = Vec::new();
    for lock_path in lock_paths {
        let bytes = std::fs::read(lock_path)
            .with_context(|| format!("reading pack-list.lock `{}`", lock_path.display()))?;
        let lock: PackListLock = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing pack-list.lock `{}`", lock_path.display()))?;
        if &lock.revision_id != expected {
            bail!(
                "pack-list.lock `{}` pins revision `{}` but is referenced by revision `{}`",
                lock_path.display(),
                lock.revision_id,
                expected
            );
        }
        for pack in lock.packs {
            let abs = normalize_under_root(env_dir, &pack.path).with_context(|| {
                format!(
                    "resolving pinned pack `{}` from `{}`",
                    pack.path.display(),
                    lock_path.display()
                )
            })?;
            if !abs.is_file() {
                bail!(
                    "pinned pack `{}` (from `{}`) is not a file",
                    abs.display(),
                    lock_path.display()
                );
            }
            refs.push(RevisionPackRef {
                path: abs,
                digest: pack.digest,
            });
        }
    }
    if refs.is_empty() {
        bail!("revision `{expected}` resolved to no pinned packs");
    }
    Ok(refs)
}

/// Load the per-env revision-dispatcher signing key, creating it on first use.
///
/// The key is a stable 32 random bytes persisted at `<env_dir>/{SIGNING_KEY_FILE}`
/// so cookie + pin stickiness survives a restart. A concurrent first boot is
/// race-safe: the create uses `create_new`, and a lost race re-reads the
/// winner's key.
fn load_or_create_signing_key(env_dir: &Path) -> anyhow::Result<[u8; 32]> {
    let path = env_dir.join(SIGNING_KEY_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => key_from_bytes(&bytes, &path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => create_signing_key(&path),
        Err(e) => Err(anyhow::Error::new(e)
            .context(format!("reading revision signing key `{}`", path.display()))),
    }
}

fn create_signing_key(path: &Path) -> anyhow::Result<[u8; 32]> {
    use rand::Rng;
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(mut file) => {
            use std::io::Write;
            file.write_all(&key)
                .with_context(|| format!("writing revision signing key `{}`", path.display()))?;
            let _ = file.sync_all();
            Ok(key)
        }
        // Another boot created it between our read and create — use its key so
        // both processes sign with the same secret.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("reading revision signing key `{}`", path.display()))?;
            key_from_bytes(&bytes, path)
        }
        Err(e) => Err(anyhow::Error::new(e).context(format!(
            "creating revision signing key `{}`",
            path.display()
        ))),
    }
}

fn key_from_bytes(bytes: &[u8], path: &Path) -> anyhow::Result<[u8; 32]> {
    bytes.try_into().map_err(|_| {
        anyhow!(
            "revision signing key `{}` is {} bytes, expected 32 (corrupt — delete to regenerate)",
            path.display(),
            bytes.len()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_deploy_spec::{
        BundleDeployment, BundleDeploymentStatus, CustomerId, EnvironmentHostConfig, LockedPack,
        PackId, PartyId, RevenueShareEntry, RouteBinding, SchemaVersion, TenantSelector,
    };
    use greentic_types::EnvId;
    use tempfile::tempdir;

    const ENV_ID: &str = "local";

    fn env_id() -> EnvId {
        EnvId::try_from(ENV_ID).unwrap()
    }

    fn make_deployment(
        deployment_id: DeploymentId,
        tenant: &str,
        customer: &str,
        bundle: &str,
        status: BundleDeploymentStatus,
    ) -> BundleDeployment {
        BundleDeployment {
            schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
            deployment_id,
            env_id: env_id(),
            bundle_id: BundleId::new(bundle),
            customer_id: CustomerId::new(customer),
            status,
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
            },
            packs: Vec::new(),
            messaging_endpoints: Vec::new(),
            credentials_ref: None,
            bundles,
            revisions: Vec::new(),
            traffic_splits: Vec::new(),
            revocation: Default::default(),
            retention: Default::default(),
            health: Default::default(),
        }
    }

    fn write_lock(env_dir: &Path, rel: &str, lock: &PackListLock) -> PathBuf {
        let abs = env_dir.join(rel);
        std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
        std::fs::write(&abs, serde_json::to_vec(lock).unwrap()).unwrap();
        abs
    }

    #[test]
    fn deployment_index_maps_id_to_tenant_and_customer() {
        let dep = make_deployment(
            DeploymentId::new(),
            "acme",
            "cust-1",
            "fast2flow",
            BundleDeploymentStatus::Active,
        );
        let key = dep.deployment_id.to_string();
        let env = make_env(vec![dep]);

        let index = deployment_index(&env);
        let meta = index.get(&key).expect("deployment present");
        assert_eq!(meta.tenant, "acme");
        assert_eq!(meta.customer_id, "cust-1");
        assert_eq!(meta.bundle_id, "fast2flow");
        assert_eq!(meta.status, BundleDeploymentStatus::Active);
    }

    #[test]
    fn read_pack_refs_resolves_paths_and_binds_digests() {
        let dir = tempdir().unwrap();
        let env_dir = dir.path();
        let rev = RevisionId::new();

        // A real on-disk "pack" file the lock points at (content unchecked here;
        // digest verification happens in TenantRuntime::load_revision).
        let pack_rel = "revisions/r/bundle/packs/alpha/dist/alpha.gtpack";
        let pack_abs = env_dir.join(pack_rel);
        std::fs::create_dir_all(pack_abs.parent().unwrap()).unwrap();
        std::fs::write(&pack_abs, b"PK\x03\x04").unwrap();

        let lock = PackListLock {
            schema: SchemaVersion::new(SchemaVersion::PACK_LIST_LOCK_V1),
            revision_id: rev,
            packs: vec![LockedPack {
                pack_id: PackId::new("alpha"),
                path: PathBuf::from(pack_rel),
                digest: "sha256:deadbeef".to_string(),
            }],
        };
        let lock_path = write_lock(env_dir, "revisions/r/pack-list.lock", &lock);

        let refs = read_revision_pack_refs(env_dir, &rev, &[lock_path]).unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].path, pack_abs);
        assert_eq!(refs[0].digest, "sha256:deadbeef");
    }

    #[test]
    fn read_pack_refs_rejects_revision_id_mismatch() {
        let dir = tempdir().unwrap();
        let env_dir = dir.path();
        let lock_rev = RevisionId::new();

        // The revision-id guard fires before any pack path is resolved, so the
        // referenced pack file need not exist.
        let lock = PackListLock {
            schema: SchemaVersion::new(SchemaVersion::PACK_LIST_LOCK_V1),
            revision_id: lock_rev,
            packs: vec![LockedPack {
                pack_id: PackId::new("alpha"),
                path: PathBuf::from("packs/alpha.gtpack"),
                digest: "sha256:00".to_string(),
            }],
        };
        let lock_path = write_lock(env_dir, "pack-list.lock", &lock);

        // Reference it under a DIFFERENT revision id.
        let other = RevisionId::new();
        let err = read_revision_pack_refs(env_dir, &other, &[lock_path]).unwrap_err();
        assert!(
            err.to_string().contains("pins revision"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn read_pack_refs_rejects_pack_path_that_is_not_a_regular_file() {
        let dir = tempdir().unwrap();
        let env_dir = dir.path();
        let rev = RevisionId::new();

        // A path that resolves (so it passes containment) but is a directory,
        // not a `.gtpack` file — must be rejected by the is_file guard.
        std::fs::create_dir_all(env_dir.join("packs/ghost.gtpack")).unwrap();

        let lock = PackListLock {
            schema: SchemaVersion::new(SchemaVersion::PACK_LIST_LOCK_V1),
            revision_id: rev,
            packs: vec![LockedPack {
                pack_id: PackId::new("ghost"),
                path: PathBuf::from("packs/ghost.gtpack"),
                digest: "sha256:00".to_string(),
            }],
        };
        let lock_path = write_lock(env_dir, "pack-list.lock", &lock);

        let err = read_revision_pack_refs(env_dir, &rev, &[lock_path]).unwrap_err();
        assert!(err.to_string().contains("is not a file"), "got: {err}");
    }

    #[test]
    fn read_pack_refs_rejects_path_escaping_env_dir() {
        let dir = tempdir().unwrap();
        let env_dir = dir.path().join("env");
        std::fs::create_dir_all(&env_dir).unwrap();
        // A sibling file outside the env dir the lock tries to reach via `..`.
        std::fs::write(dir.path().join("outside.gtpack"), b"PK").unwrap();
        let rev = RevisionId::new();

        let lock = PackListLock {
            schema: SchemaVersion::new(SchemaVersion::PACK_LIST_LOCK_V1),
            revision_id: rev,
            packs: vec![LockedPack {
                pack_id: PackId::new("escape"),
                path: PathBuf::from("../outside.gtpack"),
                digest: "sha256:00".to_string(),
            }],
        };
        let lock_path = write_lock(&env_dir, "pack-list.lock", &lock);

        assert!(read_revision_pack_refs(&env_dir, &rev, &[lock_path]).is_err());
    }

    #[test]
    fn signing_key_is_stable_across_loads() {
        let dir = tempdir().unwrap();
        let first = load_or_create_signing_key(dir.path()).unwrap();
        let second = load_or_create_signing_key(dir.path()).unwrap();
        assert_eq!(first, second, "key must be stable across boots");
        assert!(first.iter().any(|&b| b != 0), "key must not be all zeroes");
    }

    #[test]
    fn signing_key_rejects_wrong_length() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(SIGNING_KEY_FILE), b"too short").unwrap();
        let err = load_or_create_signing_key(dir.path()).unwrap_err();
        assert!(err.to_string().contains("expected 32"), "got: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn signing_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        load_or_create_signing_key(dir.path()).unwrap();
        let mode = std::fs::metadata(dir.path().join(SIGNING_KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// Seed `<store_root>/local/` and return the env dir.
    fn seed_env_dir(store_root: &Path) -> PathBuf {
        let env_dir = store_root.join(ENV_ID);
        std::fs::create_dir_all(&env_dir).unwrap();
        env_dir
    }

    /// A runtime-config with a single revision under `deployment_id`.
    fn single_revision_rc(deployment_id: &DeploymentId) -> LoadedRuntimeConfig {
        LoadedRuntimeConfig {
            env_id: ENV_ID.to_string(),
            revisions: vec![crate::runtime_config::ResolvedRevisionBlock {
                deployment_id: deployment_id.to_string(),
                revision_id: RevisionId::new().to_string(),
                bundle_id: "fast2flow".to_string(),
                pack_list_refs: Vec::new(),
                pack_config_refs: Vec::new(),
                weight_bps: 10_000,
            }],
        }
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Runtime::new().unwrap().block_on(f)
    }

    /// A dummy secrets backend passed directly to activation. Passing it (rather
    /// than letting `HostBuilder` fall back to `default_manager()`) is exactly
    /// what the env path does; `EnvSecretsManager` is convenient here because it
    /// constructs unconditionally — the `default_manager()` env gate is the
    /// fallback we want to prove is never taken.
    fn dummy_secrets() -> DynSecretsManager {
        std::sync::Arc::new(greentic_secrets_lib::env::EnvSecretsManager)
    }

    #[test]
    fn activate_errors_when_env_id_does_not_match_runtime_config() {
        // The caller passes a pre-loaded Environment; activation must reject
        // an env whose `environment_id` does not match the rc's `env_id` so a
        // stale or wrong-env load cannot silently activate.
        let dir = tempdir().unwrap();
        let rc = single_revision_rc(&DeploymentId::new());
        let mut mismatched = make_env(Vec::new());
        mismatched.environment_id = EnvId::try_from("not-local").unwrap();
        mismatched.host_config.env_id = EnvId::try_from("not-local").unwrap();

        let err = match block_on(activate_runtime_config(
            dir.path(),
            &rc,
            dummy_secrets(),
            &mismatched,
        )) {
            Ok(_) => panic!("expected activation to fail"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("was loaded for activation"),
            "got: {err:#}"
        );
    }

    #[test]
    fn activate_errors_when_deployment_not_in_environment() {
        let dir = tempdir().unwrap();
        seed_env_dir(dir.path());
        // Environment has no bundles, so the revision's deployment is unknown.
        let env = make_env(Vec::new());
        let rc = single_revision_rc(&DeploymentId::new());

        let err = match block_on(activate_runtime_config(
            dir.path(),
            &rc,
            dummy_secrets(),
            &env,
        )) {
            Ok(_) => panic!("expected activation to fail"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("not present in environment"),
            "got: {err:#}"
        );
    }

    #[test]
    fn activate_errors_when_deployment_is_not_active() {
        let dir = tempdir().unwrap();
        seed_env_dir(dir.path());
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(
            dep_id,
            "acme",
            "cust",
            "fast2flow",
            BundleDeploymentStatus::Paused,
        )]);
        let rc = single_revision_rc(&dep_id);

        let err = match block_on(activate_runtime_config(
            dir.path(),
            &rc,
            dummy_secrets(),
            &env,
        )) {
            Ok(_) => panic!("expected activation to fail"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("not Active"), "got: {err:#}");
    }

    #[test]
    fn activate_errors_when_block_bundle_mismatches_deployment() {
        let dir = tempdir().unwrap();
        seed_env_dir(dir.path());
        let dep_id = DeploymentId::new();
        // Deployment is bound to a different bundle than the runtime-config block.
        let env = make_env(vec![make_deployment(
            dep_id,
            "acme",
            "cust",
            "other-bundle",
            BundleDeploymentStatus::Active,
        )]);
        let rc = single_revision_rc(&dep_id); // pins bundle "fast2flow"

        let err = match block_on(activate_runtime_config(
            dir.path(),
            &rc,
            dummy_secrets(),
            &env,
        )) {
            Ok(_) => panic!("expected activation to fail"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("bound to bundle"), "got: {err:#}");
    }

    #[test]
    fn activate_builds_host_with_provided_secrets_then_loads_packs() {
        // A consistent deployment (Active + matching bundle) passes validation
        // and the host builds with the provided manager (no default-backend
        // fallback). With no pinned packs, activation then fails at pack
        // reading — proving the build + secrets-wiring step succeeded.
        let dir = tempdir().unwrap();
        seed_env_dir(dir.path());
        let dep_id = DeploymentId::new();
        let env = make_env(vec![make_deployment(
            dep_id,
            "acme",
            "cust",
            "fast2flow",
            BundleDeploymentStatus::Active,
        )]);
        let rc = single_revision_rc(&dep_id); // empty pack_list_refs

        let err = match block_on(activate_runtime_config(
            dir.path(),
            &rc,
            dummy_secrets(),
            &env,
        )) {
            Ok(_) => panic!("expected activation to fail at pack reading"),
            Err(e) => e,
        };
        // The "no pinned packs" cause is wrapped by a per-revision context, so
        // match against the full chain.
        let chain = format!("{err:#}");
        assert!(
            chain.contains("no pinned packs"),
            "expected to reach pack reading (host built with provided secrets), got: {chain}"
        );
    }

    #[test]
    fn activate_empty_runtime_config_yields_zero_routing() {
        // N1.2: an empty runtime-config (no bundles attached yet) activates
        // cleanly. The dispatcher has zero deployments, the route tables are
        // empty, and the placeholder host satisfies `HostBuilder::build()`'s
        // non-empty-configs invariant without being reachable at request time.
        let dir = tempdir().unwrap();
        seed_env_dir(dir.path());
        let env = make_env(Vec::new());
        let rc = LoadedRuntimeConfig {
            env_id: ENV_ID.to_string(),
            revisions: Vec::new(),
        };

        let activation = block_on(activate_runtime_config(
            dir.path(),
            &rc,
            dummy_secrets(),
            &env,
        ))
        .expect("empty rc activates");
        assert_eq!(activation.routing.dispatcher.deployment_count(), 0);
        assert_eq!(activation.routing.dispatcher.revision_count(), 0);
        assert_eq!(activation.routing.deployment_routes.len(), 0);
        // Placeholder tenant config keyed by env_id so `build()` succeeds.
        assert!(activation.host.tenant_configs().contains_key(ENV_ID));
    }
}
