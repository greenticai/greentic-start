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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, anyhow, bail};
use greentic_deploy_spec::{
    BundleDeploymentStatus, BundleId, DeploymentId, Environment, PackConfig, PackListLock,
    RevisionId,
};
use greentic_deployer::path_safety::normalize_under_root;
use greentic_runner_host::runtime::{RevisionPackRef, TenantRuntime};
use greentic_runner_host::runtime_refs::RuntimeRefResolver;
use greentic_runner_host::storage::{
    new_session_store, new_state_store, session_host_from, state_host_from,
};
use greentic_runner_host::{HostBuilder, HostConfig, RunnerHost, TenantBindings};
use serde_json::Value;

use crate::deployment_routes::{
    DeploymentRouteTable, RevisionIngressRouting, deployment_config_overrides_from_environment,
};
use crate::endpoint_admit::EndpointAdmit;
use crate::http_routes::{
    HttpRouteDescriptor, HttpRouteTable, RevisionScope, discover_revision_routes,
};
use crate::revision_dispatcher::{RevisionDispatcher, RevisionDispatcherConfig, parse_ulid};
use crate::revision_pin::RevisionPinStore;
use crate::runtime_config::{LoadedRuntimeConfig, env_dir_in};
use crate::secrets_gate::DynSecretsManager;
use crate::static_routes::{
    ActiveRouteTable, ReservedRouteSet, StaticRoutePlan, discover_revision_static_routes,
};

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
    secrets_tenant_scope: Option<&str>,
    env: &Environment,
    runtime_ref_resolver: Arc<dyn RuntimeRefResolver>,
    pin_store: Arc<dyn RevisionPinStore>,
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

    // When the secrets manager resolves a single tenant org (Vault under pod
    // workload identity scopes its embedded `SecretsCore` to one tenant — a
    // worker pod serves one tenant org), refuse to activate any deployment
    // whose tenant falls outside that scope. The shared manager would
    // otherwise silently fail every `secret://` read for the off-scope tenant
    // at request time; fail closed at activation (cold-start AND hot-attach
    // reload both route through here) instead. The unscoped DevStore/Env
    // backends pass `None` and keep the prior multi-tenant tolerance.
    if let Some(scope) = secrets_tenant_scope {
        let mut outside: Vec<&str> = tenants
            .iter()
            .copied()
            .filter(|tenant| *tenant != scope)
            .collect();
        if !outside.is_empty() {
            outside.sort_unstable();
            bail!(
                "secrets backend is scoped to tenant `{scope}`, but environment `{}` serves \
                 deployment(s) for tenant(s) {:?}; a single worker pod resolves secrets for one \
                 tenant org — split tenants across environments or provision a tenant-wide backend",
                rc.env_id,
                outside
            );
        }
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
    // Revision-scoped static routes, parallel to `scoped_routes`. Accumulated
    // as a `StaticRoutePlan` so validation results (blocking_failures, warnings)
    // propagate to the caller the same way `discover_from_bundle` does on the
    // bundle path.
    let mut static_plan = StaticRoutePlan::default();
    let reserved_routes = ReservedRouteSet::operator_defaults();

    // Webchat flow index: bundle_id -> set of flow ids. Populated from pack
    // manifests in the activation loop, deduped per bundle_id so two revisions
    // of the same bundle do not re-read (they share the same pack set).
    let mut flow_index = crate::webchat_routing::FlowIndex::default();
    let mut flow_indexed_bundles: HashSet<String> = HashSet::new();

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

        // C4.3 + C5: materialize per-pack `pack-config.v1.non_secret` and
        // `pack-config.v1.runtime_refs` for each pack in this revision in a
        // single disk pass. Maps are keyed by `pack_id`;
        // `TenantRuntime::load_revision` routes each pack's entries into the
        // C4.2 `RuntimeConfigHost` seam (`set_runtime_config_non_secret`)
        // and the C5 runtime-refs seam (`set_runtime_refs`).
        let RevisionPackConfigs {
            non_secret_by_pack_id,
            runtime_refs_by_pack_id,
        } = read_revision_pack_configs(&revision_id, &block.pack_config_refs).with_context(
            || format!("reading pack configs for revision `{}`", block.revision_id),
        )?;

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
        static_plan.merge(discover_revision_static_routes(
            &pack_paths,
            &scope,
            &reserved_routes,
        ));

        // Webchat flow index: read each pack's flows and register them under
        // the bundle id. Skipped when the bundle has already been indexed by
        // an earlier revision of the same bundle (several revisions of one
        // bundle share the same pack set and therefore the same flows).
        if flow_indexed_bundles.insert(block.bundle_id.clone()) {
            for pack_path in &pack_paths {
                match crate::messaging_app::load_app_pack_info(pack_path) {
                    Ok(info) => {
                        let flow_ids: Vec<String> =
                            info.flows.iter().map(|f| f.id.clone()).collect();
                        if !flow_ids.is_empty() {
                            flow_index.register_bundle_flows(
                                &block.bundle_id,
                                &info.pack_id,
                                &flow_ids,
                            );
                            // The `/{tenant}/{bundle}` URL form targets the
                            // bundle's default flow. Reuse the pack-level
                            // convention (`default` > `main` > sole messaging
                            // flow) so this URL and the legacy app path agree
                            // on what "default" means. Packs with several
                            // messaging flows and no conventional entry point
                            // simply register none.
                            match crate::messaging_app::select_app_flow(&info) {
                                Ok(default_flow) => flow_index.register_bundle_default_flow(
                                    &block.bundle_id,
                                    &info.pack_id,
                                    &default_flow.id,
                                ),
                                Err(err) => tracing::debug!(
                                    pack = %info.pack_id,
                                    bundle_id = %block.bundle_id,
                                    "no default webchat flow for pack: {err:#}"
                                ),
                            }
                        }
                    }
                    Err(err) => {
                        tracing::debug!(
                            pack = %pack_path.display(),
                            bundle_id = %block.bundle_id,
                            "skipping flow index for pack: {err:#}"
                        );
                    }
                }
            }
        }

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
            &non_secret_by_pack_id,
            &runtime_refs_by_pack_id,
            Some(Arc::clone(&runtime_ref_resolver)),
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
        pin_store,
    )
    .context("building revision dispatcher")?;

    if !static_plan.blocking_failures.is_empty() {
        bail!(
            "static route validation failed: {}",
            static_plan.blocking_failures.join("; ")
        );
    }
    for warning in &static_plan.warnings {
        crate::operator_log::warn(module_path!(), format!("static route warning: {warning}"));
    }

    let deployment_routes = DeploymentRouteTable::from_environment(env);
    let bundle_index =
        crate::webchat_routing::BundleIndex::from_routes_and_env(&deployment_routes, env);

    let routing = RevisionIngressRouting {
        dispatcher: Arc::new(dispatcher),
        http_routes: HttpRouteTable::from_descriptors(scoped_routes),
        deployment_routes,
        endpoint_admit: Arc::new(EndpointAdmit::from_environment(env)),
        deployment_config_overrides: Arc::new(deployment_config_overrides_from_environment(env)),
        static_routes: ActiveRouteTable::from_plan(&static_plan),
        bundle_index,
        flow_index,
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

/// Per-pack maps materialized from one revision's `pack-config.v1` files. Both
/// are keyed by `pack_id`; [`TenantRuntime::load_revision`] routes the matching
/// entry into [`crate::runner_host`]'s seam for each loaded pack.
///
/// Either map may be empty: the runner host short-circuits both lookups when
/// no entry is bound for a pack id.
#[derive(Debug)]
pub(crate) struct RevisionPackConfigs {
    /// `pack_id → Arc<pack-config.v1.non_secret>` for the C4.2
    /// `RuntimeConfigHost` non-secret arm.
    pub(crate) non_secret_by_pack_id: BTreeMap<String, Arc<BTreeMap<String, Value>>>,
    /// `pack_id → Arc<pack-config.v1.runtime_refs>` (key → URI string) for
    /// the C5 `RuntimeRefResolver` arm. The URIs are opaque strings (the
    /// runner host hands them to the env-shared resolver verbatim).
    pub(crate) runtime_refs_by_pack_id: BTreeMap<String, Arc<BTreeMap<String, String>>>,
}

/// Read a revision's `pack-config.v1` files (already resolved + verified to
/// exist by B0) and build the per-pack non-secret + runtime-refs maps that
/// [`TenantRuntime::load_revision`] routes into the C4.2 `RuntimeConfigHost`
/// seam and the C5 `RuntimeRefResolver` seam. Each [`PackConfig`]'s
/// `revision_id` must match `expected` so a misplaced or cross-revision
/// config file is rejected rather than silently activated. Duplicate
/// `pack_id` entries across a revision's config files are likewise rejected:
/// each pack gets at most one config per revision (deploy-spec §5.6), so a
/// duplicate would mean a malformed or tampered materialization. Empty
/// `non_secret` / `runtime_refs` maps are NOT inserted — they would just
/// trigger an empty injection on the runner side that the host also
/// short-circuits on lookup. Single pass over the file list: a file with
/// EITHER channel populated parses once, contributes to whichever sub-map
/// is non-empty, and is dedup-checked once.
fn read_revision_pack_configs(
    expected: &RevisionId,
    config_paths: &[PathBuf],
) -> anyhow::Result<RevisionPackConfigs> {
    let mut non_secret_by_pack_id: BTreeMap<String, Arc<BTreeMap<String, Value>>> = BTreeMap::new();
    let mut runtime_refs_by_pack_id: BTreeMap<String, Arc<BTreeMap<String, String>>> =
        BTreeMap::new();
    // Unified dedup tracker across both output channels: a pack_id that
    // appears in two config files — even if one populated only
    // runtime_refs and the other only non_secret — must still fail closed
    // (deploy-spec §5.6: one config per pack per revision).
    let mut seen_pack_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for config_path in config_paths {
        let bytes = std::fs::read(config_path)
            .with_context(|| format!("reading pack-config `{}`", config_path.display()))?;
        let parsed: PackConfig = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing pack-config `{}`", config_path.display()))?;
        if &parsed.revision_id != expected {
            bail!(
                "pack-config `{}` pins revision `{}` but is referenced by revision `{}`",
                config_path.display(),
                parsed.revision_id,
                expected
            );
        }
        let pack_id = parsed.pack_id.as_str().to_string();
        if !seen_pack_ids.insert(pack_id.clone()) {
            bail!(
                "revision `{}` has duplicate pack-config entries for pack `{}` (second seen in `{}`)",
                expected,
                pack_id,
                config_path.display()
            );
        }
        if !parsed.non_secret.is_empty() {
            non_secret_by_pack_id.insert(pack_id.clone(), Arc::new(parsed.non_secret));
        }
        if !parsed.runtime_refs.is_empty() {
            let refs: BTreeMap<String, String> = parsed
                .runtime_refs
                .into_iter()
                .map(|(k, v)| (k, v.as_str().to_string()))
                .collect();
            runtime_refs_by_pack_id.insert(pack_id, Arc::new(refs));
        }
    }
    Ok(RevisionPackConfigs {
        non_secret_by_pack_id,
        runtime_refs_by_pack_id,
    })
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
                default_bundle: None,
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
        assert_eq!(refs[0].path, pack_abs.canonicalize().unwrap());
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

    fn write_pack_config(env_dir: &Path, rel: &str, cfg: &PackConfig) -> PathBuf {
        let abs = env_dir.join(rel);
        std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
        std::fs::write(&abs, serde_json::to_vec(cfg).unwrap()).unwrap();
        abs
    }

    fn pack_config_with(
        pack_id: &str,
        revision_id: RevisionId,
        non_secret_keys: &[&str],
        runtime_refs: &[(&str, &str)],
    ) -> PackConfig {
        let mut non_secret: BTreeMap<String, Value> = BTreeMap::new();
        for key in non_secret_keys {
            non_secret.insert((*key).to_string(), Value::String(format!("v-{key}")));
        }
        let mut refs: BTreeMap<String, greentic_deploy_spec::RuntimeRef> = BTreeMap::new();
        for (k, uri) in runtime_refs {
            refs.insert(
                (*k).to_string(),
                greentic_deploy_spec::RuntimeRef::try_new(*uri).expect("valid runtime ref"),
            );
        }
        PackConfig {
            schema: SchemaVersion::new(SchemaVersion::PACK_CONFIG_V1),
            pack_id: PackId::new(pack_id),
            revision_id,
            non_secret,
            secret_refs: BTreeMap::new(),
            runtime_refs: refs,
        }
    }

    fn pack_config(pack_id: &str, revision_id: RevisionId, non_secret_keys: &[&str]) -> PackConfig {
        pack_config_with(pack_id, revision_id, non_secret_keys, &[])
    }

    #[test]
    fn read_pack_configs_returns_empty_map_for_no_refs() {
        let cfgs = read_revision_pack_configs(&RevisionId::new(), &[]).unwrap();
        assert!(cfgs.non_secret_by_pack_id.is_empty());
        assert!(cfgs.runtime_refs_by_pack_id.is_empty());
    }

    #[test]
    fn read_pack_configs_builds_map_keyed_by_pack_id() {
        let dir = tempdir().unwrap();
        let env_dir = dir.path();
        let rev = RevisionId::new();

        let cfg_a = pack_config("alpha", rev, &["default_locale"]);
        let cfg_b = pack_config("bravo", rev, &["feature_flag"]);
        let path_a = write_pack_config(env_dir, "revisions/r/alpha/pack-config.json", &cfg_a);
        let path_b = write_pack_config(env_dir, "revisions/r/bravo/pack-config.json", &cfg_b);

        let cfgs = read_revision_pack_configs(&rev, &[path_a, path_b]).unwrap();
        assert_eq!(cfgs.non_secret_by_pack_id.len(), 2);
        let a = cfgs
            .non_secret_by_pack_id
            .get("alpha")
            .expect("alpha present");
        assert_eq!(
            a.get("default_locale").and_then(Value::as_str),
            Some("v-default_locale")
        );
        let b = cfgs
            .non_secret_by_pack_id
            .get("bravo")
            .expect("bravo present");
        assert_eq!(
            b.get("feature_flag").and_then(Value::as_str),
            Some("v-feature_flag")
        );
        assert!(cfgs.runtime_refs_by_pack_id.is_empty());
    }

    #[test]
    fn read_pack_configs_skips_empty_non_secret() {
        let dir = tempdir().unwrap();
        let env_dir = dir.path();
        let rev = RevisionId::new();

        // A pack-config with `non_secret: {}` produces no map entry: the runner
        // host short-circuits empty lookups anyway, so threading an empty Arc
        // through is pure overhead.
        let cfg = pack_config("alpha", rev, &[]);
        let path = write_pack_config(env_dir, "revisions/r/alpha/pack-config.json", &cfg);

        let cfgs = read_revision_pack_configs(&rev, &[path]).unwrap();
        assert!(cfgs.non_secret_by_pack_id.is_empty());
        assert!(cfgs.runtime_refs_by_pack_id.is_empty());
    }

    #[test]
    fn read_pack_configs_extracts_runtime_refs_by_pack_id() {
        let dir = tempdir().unwrap();
        let env_dir = dir.path();
        let rev = RevisionId::new();

        let cfg = pack_config_with(
            "alpha",
            rev,
            &[],
            &[
                ("alb_dns", "runtime://local/discovered/alb_dns"),
                ("cluster", "runtime://local/discovered/cluster"),
            ],
        );
        let path = write_pack_config(env_dir, "revisions/r/alpha/pack-config.json", &cfg);

        let cfgs = read_revision_pack_configs(&rev, &[path]).unwrap();
        assert!(cfgs.non_secret_by_pack_id.is_empty());
        let refs = cfgs
            .runtime_refs_by_pack_id
            .get("alpha")
            .expect("alpha refs present");
        assert_eq!(refs.len(), 2);
        assert_eq!(
            refs.get("alb_dns").map(String::as_str),
            Some("runtime://local/discovered/alb_dns")
        );
        assert_eq!(
            refs.get("cluster").map(String::as_str),
            Some("runtime://local/discovered/cluster")
        );
    }

    #[test]
    fn read_pack_configs_dedups_pack_id_across_channels() {
        // Same pack_id appearing in two files — once with only non_secret,
        // once with only runtime_refs — must still surface the duplicate
        // bail. Defence-in-depth: one pack-config per pack per revision
        // (deploy-spec §5.6); a tampered or malformed materialization that
        // splits the channels across files must fail closed.
        let dir = tempdir().unwrap();
        let env_dir = dir.path();
        let rev = RevisionId::new();

        let cfg1 = pack_config("alpha", rev, &["k1"]);
        let cfg2 = pack_config_with(
            "alpha",
            rev,
            &[],
            &[("alb_dns", "runtime://local/discovered/alb_dns")],
        );
        let path1 = write_pack_config(env_dir, "revisions/r/alpha-a/pack-config.json", &cfg1);
        let path2 = write_pack_config(env_dir, "revisions/r/alpha-b/pack-config.json", &cfg2);

        let err = read_revision_pack_configs(&rev, &[path1, path2]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("duplicate pack-config"), "got: {msg}");
        assert!(msg.contains("alpha"), "got: {msg}");
    }

    #[test]
    fn read_pack_configs_rejects_revision_id_mismatch() {
        let dir = tempdir().unwrap();
        let env_dir = dir.path();
        let cfg_rev = RevisionId::new();
        let cfg = pack_config("alpha", cfg_rev, &["k"]);
        let path = write_pack_config(env_dir, "revisions/r/alpha/pack-config.json", &cfg);

        // Reference under a different revision id; defence-in-depth check must fire.
        let other = RevisionId::new();
        let err = read_revision_pack_configs(&other, &[path]).unwrap_err();
        assert!(
            err.to_string().contains("pins revision"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn read_pack_configs_rejects_duplicate_pack_id_across_files() {
        let dir = tempdir().unwrap();
        let env_dir = dir.path();
        let rev = RevisionId::new();

        let cfg1 = pack_config("alpha", rev, &["k1"]);
        let cfg2 = pack_config("alpha", rev, &["k2"]);
        let path1 = write_pack_config(env_dir, "revisions/r/alpha/pack-config.json", &cfg1);
        let path2 = write_pack_config(env_dir, "revisions/r/alpha-2/pack-config.json", &cfg2);

        let err = read_revision_pack_configs(&rev, &[path1, path2]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("duplicate pack-config"), "got: {msg}");
        assert!(msg.contains("alpha"), "got: {msg}");
    }

    #[test]
    fn read_pack_configs_rejects_malformed_json() {
        let dir = tempdir().unwrap();
        let env_dir = dir.path();
        let path = env_dir.join("revisions/r/alpha/pack-config.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"{not json").unwrap();

        let err = read_revision_pack_configs(&RevisionId::new(), &[path]).unwrap_err();
        assert!(
            err.to_string().contains("parsing pack-config"),
            "got: {err}"
        );
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
    fn revision_block(
        deployment_id: &DeploymentId,
    ) -> crate::runtime_config::ResolvedRevisionBlock {
        crate::runtime_config::ResolvedRevisionBlock {
            deployment_id: deployment_id.to_string(),
            revision_id: RevisionId::new().to_string(),
            bundle_id: "fast2flow".to_string(),
            pack_list_refs: Vec::new(),
            pack_config_refs: Vec::new(),
            weight_bps: 10_000,
        }
    }

    fn single_revision_rc(deployment_id: &DeploymentId) -> LoadedRuntimeConfig {
        LoadedRuntimeConfig {
            env_id: ENV_ID.to_string(),
            revisions: vec![revision_block(deployment_id)],
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

    /// Real `RuntimeRefResolver` over a throw-away tempdir, for activation
    /// tests that don't exercise runtime-ref resolution. Reuses the
    /// production [`crate::runtime_refs_store::StartRuntimeRefResolver`]
    /// rather than introducing a separate test-only impl.
    fn dummy_resolver() -> std::sync::Arc<dyn greentic_runner_host::runtime_refs::RuntimeRefResolver>
    {
        let dir = tempdir().expect("tempdir for dummy resolver");
        let store = crate::runtime_refs_store::EnvironmentRuntimeStore::open(dir.path(), env_id())
            .expect("dummy env runtime store");
        // tempdir leak intentional — it lives as long as the resolver
        // (which never reads from disk because the activation tests bail
        // before pack loading).
        std::mem::forget(dir);
        std::sync::Arc::new(crate::runtime_refs_store::StartRuntimeRefResolver::new(
            store,
        ))
    }

    fn dummy_pin_store() -> Arc<dyn RevisionPinStore> {
        Arc::new(crate::revision_pin::InMemoryPinStore::new())
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
            None,
            &mismatched,
            dummy_resolver(),
            dummy_pin_store(),
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
            None,
            &env,
            dummy_resolver(),
            dummy_pin_store(),
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
            None,
            &env,
            dummy_resolver(),
            dummy_pin_store(),
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
            None,
            &env,
            dummy_resolver(),
            dummy_pin_store(),
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
            None,
            &env,
            dummy_resolver(),
            dummy_pin_store(),
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
            None,
            &env,
            dummy_resolver(),
            dummy_pin_store(),
        ))
        .expect("empty rc activates");
        assert_eq!(activation.routing.dispatcher.deployment_count(), 0);
        assert_eq!(activation.routing.dispatcher.revision_count(), 0);
        assert_eq!(activation.routing.deployment_routes.len(), 0);
        // Placeholder tenant config keyed by env_id so `build()` succeeds.
        assert!(activation.host.tenant_configs().contains_key(ENV_ID));
    }

    #[test]
    fn vault_scope_refuses_a_foreign_tenant_deployment() {
        // Under a Vault serve scope (one tenant org per worker pod), an env that
        // also serves a deployment for a different tenant must fail closed at
        // activation: the pod's single-tenant Vault manager cannot resolve the
        // foreign tenant's secrets, so silently 404-ing every read at request
        // time is the worse alternative.
        let dir = tempdir().unwrap();
        seed_env_dir(dir.path());
        let own = DeploymentId::new();
        let foreign = DeploymentId::new();
        let env = make_env(vec![
            make_deployment(
                own,
                "acme",
                "cust",
                "fast2flow",
                BundleDeploymentStatus::Active,
            ),
            make_deployment(
                foreign,
                "globex",
                "cust",
                "fast2flow",
                BundleDeploymentStatus::Active,
            ),
        ]);
        let rc = LoadedRuntimeConfig {
            env_id: ENV_ID.to_string(),
            revisions: vec![revision_block(&own), revision_block(&foreign)],
        };

        let err = match block_on(activate_runtime_config(
            dir.path(),
            &rc,
            dummy_secrets(),
            Some("acme"),
            &env,
            dummy_resolver(),
            dummy_pin_store(),
        )) {
            Ok(_) => panic!("expected activation to fail closed on a foreign tenant"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(msg.contains("scoped to tenant `acme`"), "got: {msg}");
        assert!(msg.contains("globex"), "got: {msg}");
    }

    #[test]
    fn vault_scope_admits_its_own_tenant() {
        // A Vault scope matching the single served tenant passes the guard; the
        // activation then proceeds and (with no pinned packs) fails later at
        // pack reading — proving the guard does not block the served tenant's
        // own secret URIs.
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
        let rc = single_revision_rc(&dep_id);

        let err = match block_on(activate_runtime_config(
            dir.path(),
            &rc,
            dummy_secrets(),
            Some("acme"),
            &env,
            dummy_resolver(),
            dummy_pin_store(),
        )) {
            Ok(_) => panic!("expected activation to pass the scope guard and reach pack reading"),
            Err(e) => e,
        };
        let chain = format!("{err:#}");
        assert!(
            chain.contains("no pinned packs"),
            "expected the matching scope to pass the guard and reach pack reading, got: {chain}"
        );
    }
}
