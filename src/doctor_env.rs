//! Environment-store runtime-readiness checks (PR-3 of
//! `plans/env-manifest-apply.md`).
//!
//! `gtc op env apply` verifies its writes at the *store* level; whether the
//! runtime can actually use that state is this module's job. Four gaps the
//! investigation found, each a check here:
//!
//! 1. **Trust root presence/validity** — previously only exercised inside
//!    [`crate::revision_health_gate`] at warm time, where a missing/empty
//!    `trust-root.json` surfaces as an opaque DSSE failure. Doctor checks it
//!    ahead of time: the file must load, every key's PEM must parse and match
//!    its `key_id` derivation, and an empty (closed-by-default) root is an
//!    error once revisions exist.
//! 2. **Messaging-endpoint linkage** — an endpoint with an empty
//!    `linked_bundles` ACL admits nothing
//!    ([`crate::endpoint_admit`] fail-closes), and a linked bundle whose
//!    deployment is not Active or has no Ready revision receiving traffic
//!    serves nothing. Every deployment of a bundle is evaluated (one bundle
//!    can have multiple customer-scoped deployments).
//! 3. **Secret-ref resolvability** — each endpoint `secret_refs` /
//!    `webhook_secret_ref` entry is read through the SAME dev-store reader
//!    the bundle-less boot wires up ([`crate::secrets_client::SecretsClient`]
//!    over [`crate::dev_store_path`]), so doctor's verdict matches what the
//!    runtime will see. Secret *values* are discarded immediately —
//!    diagnostics carry only URIs.
//! 4. **Materialized runtime-config** — the bundle-less runtime boots from
//!    `runtime-config.json` in the env directory. If it is missing, the
//!    runtime serves probes only; if malformed, it cannot boot. Doctor
//!    cross-references the loaded runtime-config with the env-level serving
//!    state so a deployment that claims Ready traffic but has no
//!    runtime-config block is surfaced.
//!
//! Diagnostics flow through the existing `--stage` filter via their
//! [`DiagnosticComponent`]: env resolution/load + trust root + runtime-config
//! are `Runtime`, endpoint linkage is `Routes`, secret resolvability is
//! `Provider` (so `--stage secrets` includes it).
//!
//! `--strict` promotes all `start.env.*` warnings to errors for automation
//! gates (see [`crate::doctor::should_promote_in_strict`]).

use std::path::Path;

use greentic_deploy_spec::{
    BundleDeploymentStatus, BundleId, DeploymentId, Environment, RevisionLifecycle,
};
use greentic_deployer::environment::{EnvironmentStore, LocalFsStore, load_trust_root};
use greentic_distributor_client::signing::key_id_for_public_key_pem;
use greentic_secrets_lib::{SecretError, SecretsManager};
use serde_json::{Value, json};

use crate::doctor::{Diagnostic, DiagnosticComponent, Severity};
use crate::runtime_config::LoadedRuntimeConfig;
use crate::webhook_secret_resolver::secret_ref_to_store_uri;

/// Check id for environment resolution (id validity, store presence).
pub(crate) const CHECK_ENV_RESOLVE: &str = "start.env.resolve";
/// Check id for loading + validating `environment.json`.
pub(crate) const CHECK_ENV_LOAD: &str = "start.env.load";

/// True for diagnostics that mean the env checks could not run at all
/// (environment missing, unsafe id, malformed store file). `run_doctor`
/// must push these past the `--stage` filter — classification lives here,
/// next to the producers, so the routing can't drift out of sync with the
/// check ids.
pub(crate) fn is_prerequisite_failure(diagnostic: &Diagnostic) -> bool {
    diagnostic.severity == Severity::Error
        && (diagnostic.check_id == CHECK_ENV_RESOLVE || diagnostic.check_id == CHECK_ENV_LOAD)
}

/// Run the environment-store readiness checks for `env_id` under
/// `store_root`, returning the diagnostics for the caller to push through
/// the doctor's stage filter. Read-only: never creates the env dir, the
/// dev store, or any state file.
pub(crate) fn environment_diagnostics(store_root: &Path, env_id: &str) -> Vec<Diagnostic> {
    let mut out = Vec::new();

    let env_dir = match crate::runtime_config::env_dir_in(store_root, env_id) {
        Ok(dir) => dir,
        Err(err) => {
            out.push(error(
                CHECK_ENV_RESOLVE,
                DiagnosticComponent::Runtime,
                "Environment id is not a safe store directory segment.",
                json!({ "env_id": env_id, "error": format!("{err:#}") }),
                (
                    json!({ "valid_env_id": true }),
                    json!({ "valid_env_id": false }),
                ),
                Some("Pass a plain identifier environment id (e.g. `local`)."),
            ));
            return out;
        }
    };

    if !env_dir.join("environment.json").exists() {
        out.push(error(
            CHECK_ENV_RESOLVE,
            DiagnosticComponent::Runtime,
            "Environment is not initialized in the local store.",
            json!({ "env_id": env_id, "env_dir": env_dir }),
            (
                json!({ "environment_json": true }),
                json!({ "environment_json": false }),
            ),
            Some("Initialize the environment first: `gtc op env init` (or `gtc op env apply`)."),
        ));
        return out;
    }

    let store = LocalFsStore::new(store_root.to_path_buf());
    let env_typed = match greentic_types::EnvId::new(env_id) {
        Ok(id) => id,
        Err(err) => {
            // `env_dir_in` already validated the segment; this only fires if
            // the two validators ever diverge.
            out.push(error(
                CHECK_ENV_RESOLVE,
                DiagnosticComponent::Runtime,
                "Environment id failed typed-id validation.",
                json!({ "env_id": env_id, "error": err.to_string() }),
                (
                    json!({ "valid_env_id": true }),
                    json!({ "valid_env_id": false }),
                ),
                None,
            ));
            return out;
        }
    };
    let env = match store.load(&env_typed) {
        Ok(env) => env,
        Err(err) => {
            out.push(error(
                CHECK_ENV_LOAD,
                DiagnosticComponent::Runtime,
                "Environment could not be loaded from the store.",
                json!({ "env_id": env_id, "error": err.to_string() }),
                (json!({ "env_loads": true }), json!({ "env_loads": false })),
                Some("Fix or re-apply the environment (`gtc op env apply`); the store file is malformed or violates spec invariants."),
            ));
            return out;
        }
    };
    out.push(info(
        CHECK_ENV_LOAD,
        DiagnosticComponent::Runtime,
        "Environment loaded and validated.",
        json!({
            "env_id": env_id,
            "bundles": env.bundles.len(),
            "revisions": env.revisions.len(),
            "messaging_endpoints": env.messaging_endpoints.len(),
        }),
    ));

    // Finding 1: load the materialized runtime-config once so the serving
    // predicate can cross-reference env-level state against what the runtime
    // will actually boot.
    let runtime_cfg = match crate::runtime_config::load_in(store_root, env_id) {
        Ok(opt) => {
            if let Some(ref cfg) = opt {
                out.push(info(
                    "start.env.runtime_config",
                    DiagnosticComponent::Runtime,
                    "Materialized runtime-config loaded.",
                    json!({ "revision_blocks": cfg.revisions.len() }),
                ));
            }
            opt
        }
        Err(err) => {
            out.push(error(
                "start.env.runtime_config",
                DiagnosticComponent::Runtime,
                "Materialized runtime-config failed to load \u{2014} the runtime cannot boot revisions from it.",
                json!({ "path": env_dir.join("runtime-config.json"), "error": format!("{err:#}") }),
                (
                    json!({ "runtime_config_loads": true }),
                    json!({ "runtime_config_loads": false }),
                ),
                Some("Re-materialize it by re-applying traffic (`gtc op traffic` / `gtc op env apply`)."),
            ));
            None
        }
    };

    check_trust_root(&mut out, &env_dir, &env);
    check_endpoint_linkage(&mut out, &env, runtime_cfg.as_ref());
    check_secret_refs(&mut out, &env_dir, &env);
    out
}

/// Trust-root presence/validity. Closed-by-default semantics: a missing or
/// empty `trust-root.json` makes every DSSE verification fail, so it is an
/// error as soon as the env has revisions to verify (and a warning before).
fn check_trust_root(out: &mut Vec<Diagnostic>, env_dir: &Path, env: &Environment) {
    let trust_root = match load_trust_root(env_dir) {
        Ok(root) => root,
        Err(err) => {
            out.push(error(
                "start.env.trust_root",
                DiagnosticComponent::Runtime,
                "Trust root could not be loaded.",
                json!({ "path": env_dir.join("trust-root.json"), "error": err.to_string() }),
                (
                    json!({ "trust_root_loads": true }),
                    json!({ "trust_root_loads": false }),
                ),
                Some("Fix or regenerate trust-root.json via `gtc op trust-root bootstrap`."),
            ));
            return;
        }
    };

    if trust_root.is_empty() {
        let evidence = json!({
            "path": env_dir.join("trust-root.json"),
            "revisions": env.revisions.len(),
        });
        let fix =
            Some("Seed the operator key into the env trust root: `gtc op trust-root bootstrap`.");
        if env.revisions.is_empty() {
            out.push(warn(
                "start.env.trust_root",
                DiagnosticComponent::Runtime,
                "Trust root is empty; bootstrap it before deploying (signature verification fails closed).",
                evidence,
                fix,
            ));
        } else {
            out.push(error(
                "start.env.trust_root",
                DiagnosticComponent::Runtime,
                "Trust root is empty but the environment has revisions — every revision signature verification will fail closed.",
                evidence,
                (
                    json!({ "trusted_keys_min": 1 }),
                    json!({ "trusted_keys": 0 }),
                ),
                fix,
            ));
        }
        return;
    }

    let mut invalid = 0usize;
    for key in &trust_root.keys {
        match key_id_for_public_key_pem(&key.public_key_pem) {
            Ok(derived) if derived.eq_ignore_ascii_case(&key.key_id) => {}
            Ok(derived) => {
                invalid += 1;
                out.push(error(
                    "start.env.trust_root",
                    DiagnosticComponent::Runtime,
                    "Trusted key_id does not match its public-key derivation — verifiers will never select this key.",
                    json!({ "key_id": key.key_id }),
                    (
                        json!({ "key_id": derived }),
                        json!({ "key_id": key.key_id }),
                    ),
                    Some("Re-add the key via `gtc op trust-root add` so the key_id is re-derived."),
                ));
            }
            Err(err) => {
                invalid += 1;
                out.push(error(
                    "start.env.trust_root",
                    DiagnosticComponent::Runtime,
                    "Trusted public key PEM does not parse as Ed25519 SPKI.",
                    json!({ "key_id": key.key_id, "error": err.to_string() }),
                    (
                        json!({ "pem_parses": true }),
                        json!({ "pem_parses": false }),
                    ),
                    Some("Replace the corrupt key via `gtc op trust-root add`."),
                ));
            }
        }
    }
    if invalid == 0 {
        out.push(info(
            "start.env.trust_root",
            DiagnosticComponent::Runtime,
            "Trust root is present and every key is valid.",
            json!({
                "keys": trust_root
                    .keys
                    .iter()
                    .map(|key| key.key_id.as_str())
                    .collect::<Vec<_>>(),
            }),
        ));
    }
}

/// Messaging-endpoint linkage: each endpoint must admit at least one bundle,
/// and each linked bundle must have an Active deployment with a Ready
/// revision receiving traffic — otherwise the endpoint exists but serves
/// nothing. (`linked_bundles ⊆ env.bundles` membership is already enforced by
/// `Environment::validate` at load time.)
///
/// A single bundle can have MULTIPLE deployments (customer-scoped
/// `(bundle_id, customer_id)`); all of them are evaluated. The all-serving
/// Info only fires when every deployment of every linked bundle is Serving.
fn check_endpoint_linkage(
    out: &mut Vec<Diagnostic>,
    env: &Environment,
    runtime_cfg: Option<&LoadedRuntimeConfig>,
) {
    if env.messaging_endpoints.is_empty() {
        out.push(info(
            "start.env.endpoint_links",
            DiagnosticComponent::Routes,
            "No messaging endpoints declared in this environment.",
            json!({}),
        ));
        return;
    }

    for endpoint in &env.messaging_endpoints {
        let eid = endpoint.endpoint_id.to_string();
        if endpoint.linked_bundles.is_empty() {
            out.push(warn(
                "start.env.endpoint_links",
                DiagnosticComponent::Routes,
                "Messaging endpoint has no linked bundles — the admit gate fail-closes every request asserting it.",
                json!({
                    "endpoint_id": eid,
                    "provider_type": endpoint.provider_type,
                    "provider_id": endpoint.provider_id,
                }),
                Some("Link a deployed bundle: `gtc op messaging endpoint link-bundle`."),
            ));
            continue;
        }

        let mut total_deployments = 0usize;
        let mut serving_deployments = 0usize;
        for bundle_id in &endpoint.linked_bundles {
            let bid = bundle_id.to_string();
            let states = bundle_deployment_states(env, bundle_id, runtime_cfg);
            if states.is_empty() {
                out.push(error(
                    "start.env.endpoint_links",
                    DiagnosticComponent::Routes,
                    "Endpoint links a bundle with no deployment in this environment.",
                    json!({ "endpoint_id": eid, "bundle_id": bid }),
                    (
                        json!({ "deployment_exists": true }),
                        json!({ "deployment_exists": false }),
                    ),
                    Some("Deploy the bundle (`gtc op deploy`) or unlink it from the endpoint."),
                ));
                continue;
            }
            for (deployment_id, state) in &states {
                total_deployments += 1;
                // The non-serving variants differ only in message, fix hint,
                // and one extra evidence key; emit them through one site.
                let (message, hint, status) = match state {
                    ServingState::Serving => {
                        serving_deployments += 1;
                        continue;
                    }
                    ServingState::DeploymentNotActive(status) => (
                        "Endpoint links a bundle whose deployment is not Active — requests for it will not route.",
                        "Reactivate the deployment or unlink the bundle from the endpoint.",
                        Some(format!("{status:?}")),
                    ),
                    ServingState::NoReadyTraffic => (
                        "Endpoint links a bundle with no Ready revision receiving traffic.",
                        "Deploy and warm a revision, then route traffic to it (`gtc op deploy` / `gtc op traffic`).",
                        None,
                    ),
                    ServingState::NotMaterialized => (
                        "Environment claims Ready traffic for this deployment but the materialized runtime-config has no serving revision block — the runtime will not route it.",
                        "Re-apply traffic to re-materialize the runtime-config (`gtc op traffic` / `gtc op env apply`).",
                        None,
                    ),
                };
                let mut evidence = json!({
                    "endpoint_id": eid,
                    "bundle_id": bid,
                    "deployment_id": deployment_id.to_string(),
                });
                if let Some(status) = status {
                    evidence["status"] = Value::String(status);
                }
                out.push(warn(
                    "start.env.endpoint_links",
                    DiagnosticComponent::Routes,
                    message,
                    evidence,
                    Some(hint),
                ));
            }
        }
        if total_deployments > 0 && serving_deployments == total_deployments {
            out.push(info(
                "start.env.endpoint_links",
                DiagnosticComponent::Routes,
                "Every bundle linked to this endpoint has a Ready revision receiving traffic.",
                json!({
                    "endpoint_id": endpoint.endpoint_id.to_string(),
                    "provider_type": endpoint.provider_type,
                    "provider_id": endpoint.provider_id,
                    "linked_bundles": endpoint
                        .linked_bundles
                        .iter()
                        .map(|bundle| bundle.to_string())
                        .collect::<Vec<_>>(),
                }),
            ));
        }
    }
}

enum ServingState {
    Serving,
    DeploymentNotActive(BundleDeploymentStatus),
    NoReadyTraffic,
    /// Env-level state says Ready traffic, but the materialized
    /// runtime-config has no block for this deployment (file absent or no
    /// matching block).
    NotMaterialized,
}

/// Evaluate EVERY deployment of `bundle_id`, returning per-deployment serving
/// states. An empty vec means the bundle has no deployments at all.
fn bundle_deployment_states(
    env: &Environment,
    bundle_id: &BundleId,
    runtime_cfg: Option<&LoadedRuntimeConfig>,
) -> Vec<(DeploymentId, ServingState)> {
    let deployments: Vec<_> = env
        .bundles
        .iter()
        .filter(|d| d.bundle_id == *bundle_id)
        .collect();
    if deployments.is_empty() {
        return Vec::new();
    }
    deployments
        .into_iter()
        .map(|deployment| {
            let state = deployment_serving_state(env, deployment, runtime_cfg);
            (deployment.deployment_id, state)
        })
        .collect()
}

/// Whether a single deployment is actually servable: Active status, at least
/// one traffic-split entry with positive weight pointing at a `Ready`
/// revision, AND a matching block in the materialized runtime-config (when
/// loaded). The runtime-config cross-reference mirrors the real boot path:
/// the runtime serves from `runtime-config.json`, not from
/// `environment.json`.
///
/// The `.to_string()` comparison between `ResolvedRevisionBlock.deployment_id`
/// and `DeploymentId` is safe because both are produced by `DeploymentId::Display`
/// (ULID upper-case), so casing is consistent.
fn deployment_serving_state(
    env: &Environment,
    deployment: &greentic_deploy_spec::BundleDeployment,
    runtime_cfg: Option<&LoadedRuntimeConfig>,
) -> ServingState {
    if deployment.status != BundleDeploymentStatus::Active {
        return ServingState::DeploymentNotActive(deployment.status);
    }
    // Only `Ready` revisions count toward serving. The runtime also keeps
    // draining (non-Ready) revisions in its routing for their wind-down
    // window — deliberately not counted here, since they take no NEW
    // traffic; don't "fix" this to match revision_boot's wider filter.
    let has_ready_traffic = env
        .traffic_splits
        .iter()
        .filter(|split| {
            split.bundle_id == deployment.bundle_id
                && split.deployment_id == deployment.deployment_id
        })
        .flat_map(|split| &split.entries)
        .any(|entry| {
            entry.weight_bps > 0
                && env.revisions.iter().any(|revision| {
                    revision.revision_id == entry.revision_id
                        && revision.lifecycle == RevisionLifecycle::Ready
                })
        });
    if !has_ready_traffic {
        return ServingState::NoReadyTraffic;
    }
    // Cross-reference against the materialized runtime-config: the runtime
    // boots from that file, not from environment.json.
    let deployment_id = deployment.deployment_id.to_string();
    let has_runtime_block = runtime_cfg.is_some_and(|cfg| {
        cfg.revisions.iter().any(|block| {
            // DeploymentId::Display and the block's deployment_id field are
            // both produced via the same ULID Display impl, so the string
            // comparison is casing-consistent.
            block.deployment_id == deployment_id && block.weight_bps > 0
        })
    });
    if has_runtime_block {
        ServingState::Serving
    } else {
        ServingState::NotMaterialized
    }
}

/// Secret-ref resolvability: read every endpoint `secret_refs` /
/// `webhook_secret_ref` entry through the same dev-store reader the
/// bundle-less boot uses. Values are discarded — only URIs appear in
/// diagnostics.
fn check_secret_refs(out: &mut Vec<Diagnostic>, env_dir: &Path, env: &Environment) {
    let refs: Vec<(&greentic_deploy_spec::MessagingEndpoint, String)> = env
        .messaging_endpoints
        .iter()
        .flat_map(|endpoint| {
            endpoint
                .secret_refs
                .iter()
                .chain(endpoint.webhook_secret_ref.as_ref())
                .map(move |secret_ref| (endpoint, secret_ref_to_store_uri(secret_ref)))
        })
        .collect();
    if refs.is_empty() {
        out.push(info(
            "start.env.secrets",
            DiagnosticComponent::Provider,
            "No endpoint secret refs declared in this environment.",
            json!({}),
        ));
        return;
    }

    // Read-only: locate an existing dev store the way the runtime reader
    // does (`SecretsClient::open` honors the same override + candidates),
    // but never create one — doctor must not mutate the env dir.
    let Some(store_path) = crate::dev_store_path::find_existing(env_dir) else {
        out.push(error(
            "start.env.secrets",
            DiagnosticComponent::Provider,
            "Endpoint secret refs are declared but the env has no dev secrets store.",
            json!({
                "expected": crate::dev_store_path::default_path(env_dir),
                "secret_refs": refs.len(),
            }),
            (
                json!({ "dev_store_exists": true }),
                json!({ "dev_store_exists": false }),
            ),
            Some("Seed the secrets via `gtc op env apply` (manifest secrets[]) or `gtc op secrets put`."),
        ));
        return;
    };

    let client = match crate::secrets_client::SecretsClient::open_with_path(store_path.clone()) {
        Ok(client) => client,
        Err(err) => {
            out.push(error(
                "start.env.secrets",
                DiagnosticComponent::Provider,
                "Dev secrets store could not be opened.",
                json!({ "store_path": store_path, "error": format!("{err:#}") }),
                (
                    json!({ "dev_store_opens": true }),
                    json!({ "dev_store_opens": false }),
                ),
                None,
            ));
            return;
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            out.push(error(
                "start.env.secrets",
                DiagnosticComponent::Provider,
                "Could not build the async runtime for secret reads.",
                json!({ "error": err.to_string() }),
                (json!({ "runtime": true }), json!({ "runtime": false })),
                None,
            ));
            return;
        }
    };

    let mut unresolved = 0usize;
    for (endpoint, uri) in &refs {
        // Discard the value immediately: resolvability is the verdict, the
        // bytes must never reach a diagnostic.
        let read = runtime.block_on(async { client.read(uri).await.map(|_| ()) });
        match read {
            Ok(()) => {}
            Err(SecretError::NotFound(_)) => {
                unresolved += 1;
                out.push(error(
                    "start.env.secrets",
                    DiagnosticComponent::Provider,
                    "Endpoint secret ref does not resolve in the dev secrets store.",
                    json!({
                        "endpoint_id": endpoint.endpoint_id.to_string(),
                        "provider_id": endpoint.provider_id,
                        "uri": uri,
                        "store_path": store_path,
                    }),
                    (json!({ "resolves": true }), json!({ "resolves": false })),
                    Some("Seed the secret via `gtc op env apply` (manifest secrets[]) or `gtc op secrets put`."),
                ));
            }
            Err(err) => {
                unresolved += 1;
                out.push(error(
                    "start.env.secrets",
                    DiagnosticComponent::Provider,
                    "Endpoint secret ref read failed against the dev secrets store.",
                    json!({
                        "endpoint_id": endpoint.endpoint_id.to_string(),
                        "uri": uri,
                        "error": err.to_string(),
                    }),
                    (json!({ "resolves": true }), json!({ "resolves": false })),
                    None,
                ));
            }
        }
    }
    if unresolved == 0 {
        out.push(info(
            "start.env.secrets",
            DiagnosticComponent::Provider,
            "Every endpoint secret ref resolves in the dev secrets store.",
            json!({
                "secret_refs": refs.iter().map(|(_, uri)| uri.as_str()).collect::<Vec<_>>(),
                "store_path": store_path,
            }),
        ));
    }
}

pub(crate) fn error(
    check_id: &str,
    component: DiagnosticComponent,
    message: &str,
    evidence: Value,
    expected_actual: (Value, Value),
    fix_hint: Option<&str>,
) -> Diagnostic {
    Diagnostic {
        check_id: check_id.to_string(),
        severity: Severity::Error,
        component,
        message: message.to_string(),
        evidence,
        expected: expected_actual.0,
        actual: expected_actual.1,
        fix_hint: fix_hint.map(str::to_string),
        related_file: None,
        related_pack: None,
        related_component: None,
    }
}

fn warn(
    check_id: &str,
    component: DiagnosticComponent,
    message: &str,
    evidence: Value,
    fix_hint: Option<&str>,
) -> Diagnostic {
    Diagnostic {
        check_id: check_id.to_string(),
        severity: Severity::Warn,
        component,
        message: message.to_string(),
        evidence,
        expected: Value::Null,
        actual: Value::Null,
        fix_hint: fix_hint.map(str::to_string),
        related_file: None,
        related_pack: None,
        related_component: None,
    }
}

fn info(
    check_id: &str,
    component: DiagnosticComponent,
    message: &str,
    evidence: Value,
) -> Diagnostic {
    Diagnostic {
        check_id: check_id.to_string(),
        severity: Severity::Info,
        component,
        message: message.to_string(),
        evidence,
        expected: Value::Null,
        actual: Value::Null,
        fix_hint: None,
        related_file: None,
        related_pack: None,
        related_component: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{endpoint, env_with, telegram_endpoint_with_webhook_secret};
    use greentic_deploy_spec::{
        BundleDeployment, BundleId, CustomerId, DeploymentId, Environment, PackId, PackListEntry,
        PartyId, RevenueShareEntry, Revision, RevisionId, RevisionRuntimeBlock, RouteBinding,
        RuntimeConfig as MaterializedRuntimeConfig, SchemaVersion, SemVer, TenantSelector,
        TrafficSplit, TrafficSplitEntry,
    };
    use greentic_deployer::environment::add_trusted_key;
    use greentic_distributor_client::signing::TrustedKey;
    use greentic_secrets_lib::{SecretFormat, SecretsStore, core::seed::DevStore};
    use greentic_types::EnvId;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use tempfile::TempDir;

    const ENV_ID: &str = "local";

    fn deployment(bundle: &str, status: BundleDeploymentStatus) -> BundleDeployment {
        BundleDeployment {
            schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
            deployment_id: DeploymentId::new(),
            env_id: crate::test_fixtures::env_id(),
            bundle_id: BundleId::new(bundle),
            customer_id: CustomerId::new("local-dev"),
            status,
            current_revisions: Vec::new(),
            route_binding: RouteBinding {
                hosts: vec![format!("{bundle}.local")],
                path_prefixes: Vec::new(),
                tenant_selector: TenantSelector {
                    tenant: "default".to_string(),
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
            config_overrides: BTreeMap::new(),
        }
    }

    fn revision(deployment: &BundleDeployment, lifecycle: RevisionLifecycle) -> Revision {
        Revision {
            pack_config_refs: Vec::new(),
            schema: SchemaVersion::new(SchemaVersion::REVISION_V1),
            revision_id: RevisionId::new(),
            env_id: crate::test_fixtures::env_id(),
            bundle_id: deployment.bundle_id.clone(),
            deployment_id: deployment.deployment_id,
            sequence: 1,
            created_at: chrono::Utc::now(),
            bundle_digest: "sha256:00".to_string(),
            bundle_source_uri: None,
            pack_list: vec![PackListEntry {
                pack_id: PackId::new("greentic.test.pack"),
                version: SemVer::new(1, 0, 0),
                digest: "sha256:00".to_string(),
                source_uri: None,
            }],
            pack_list_lock_ref: PathBuf::from("pack-list.lock"),
            config_digest: "sha256:00".to_string(),
            signature_sidecar_ref: PathBuf::from("rev.sig"),
            lifecycle,
            staged_at: None,
            warmed_at: None,
            drain_seconds: 30,
            abort_metrics: Vec::new(),
        }
    }

    /// Single-entry full-weight split routing the deployment to `revision`.
    fn split(deployment: &BundleDeployment, revision: &Revision) -> TrafficSplit {
        TrafficSplit {
            schema: SchemaVersion::new(SchemaVersion::TRAFFIC_SPLIT_V1),
            env_id: crate::test_fixtures::env_id(),
            deployment_id: deployment.deployment_id,
            bundle_id: deployment.bundle_id.clone(),
            generation: 0,
            entries: vec![TrafficSplitEntry {
                revision_id: revision.revision_id,
                weight_bps: 10_000,
            }],
            updated_at: chrono::Utc::now(),
            updated_by: "test".to_string(),
            idempotency_key: "ik-test".to_string(),
            authorization_ref: PathBuf::from("auth.json"),
            previous_split_ref: None,
        }
    }

    /// Persist `env` under `<store_root>/<env_id>/environment.json` via the
    /// production store (save validates the spec invariants).
    fn save_env(store_root: &Path, env: &Environment) {
        std::fs::create_dir_all(store_root.join(env.environment_id.as_str())).unwrap();
        LocalFsStore::new(store_root.to_path_buf())
            .save(env)
            .unwrap();
    }

    /// The recurring linked-bundle layout: one Active `fast2flow` deployment,
    /// one revision at `lifecycle`, a full-weight split, plus `endpoints`.
    fn env_with_linked_bundle(
        lifecycle: RevisionLifecycle,
        endpoints: Vec<greentic_deploy_spec::MessagingEndpoint>,
    ) -> (Environment, BundleDeployment, Revision) {
        let dep = deployment("fast2flow", BundleDeploymentStatus::Active);
        let rev = revision(&dep, lifecycle);
        let mut env = env_with(endpoints);
        env.traffic_splits = vec![split(&dep, &rev)];
        env.bundles = vec![dep.clone()];
        env.revisions = vec![rev.clone()];
        (env, dep, rev)
    }

    /// Deterministic Ed25519 keypair: `(spki public PEM, key_id)`.
    fn trusted_keypair(seed: u8) -> (String, String) {
        use ed25519_dalek::SigningKey;
        use ed25519_dalek::pkcs8::EncodePublicKey;
        use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pub_pem = sk
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let key_id =
            greentic_distributor_client::signing::key_id_for_public_key_pem(&pub_pem).unwrap();
        (pub_pem, key_id)
    }

    fn by_id<'a>(diags: &'a [Diagnostic], check_id: &str) -> Vec<&'a Diagnostic> {
        diags
            .iter()
            .filter(|diag| diag.check_id == check_id)
            .collect()
    }

    fn severities(diags: &[&Diagnostic]) -> Vec<Severity> {
        diags.iter().map(|diag| diag.severity).collect()
    }

    fn error_count(diags: &[Diagnostic]) -> usize {
        diags
            .iter()
            .filter(|diag| diag.severity == Severity::Error)
            .count()
    }

    fn seed_dev_store(env_dir: &Path, uri: &str, value: &[u8]) {
        let path = env_dir.join(".greentic/dev/.dev.secrets.env");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let store = DevStore::with_path(path).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async { store.put(uri, SecretFormat::Bytes, value).await })
            .unwrap();
    }

    /// Write a valid `runtime-config.json` for a single deployment/revision
    /// pair under `<store_root>/<ENV_ID>/`. Creates the dummy pack-ref files
    /// that `runtime_config::load_in` validates via `normalize_under_root`.
    fn write_runtime_config(store_root: &Path, dep: &BundleDeployment, rev: &Revision) {
        write_runtime_config_blocks(store_root, &[runtime_block(dep, rev)]);
    }

    fn runtime_block(dep: &BundleDeployment, rev: &Revision) -> RevisionRuntimeBlock {
        let rev_dir = format!("revisions/{}", rev.revision_id);
        RevisionRuntimeBlock {
            deployment_id: dep.deployment_id,
            revision_id: rev.revision_id,
            bundle_id: dep.bundle_id.clone(),
            pack_list_refs: vec![PathBuf::from(format!("{rev_dir}/pack.lock"))],
            pack_config_refs: vec![PathBuf::from(format!("{rev_dir}/pack-config.json"))],
            weight_bps: 10_000,
        }
    }

    fn write_runtime_config_blocks(store_root: &Path, blocks: &[RevisionRuntimeBlock]) {
        let env_dir = store_root.join(ENV_ID);
        for block in blocks {
            for r in &block.pack_list_refs {
                let full = env_dir.join(r);
                std::fs::create_dir_all(full.parent().unwrap()).unwrap();
                std::fs::write(&full, "lock").unwrap();
            }
            for r in &block.pack_config_refs {
                let full = env_dir.join(r);
                std::fs::create_dir_all(full.parent().unwrap()).unwrap();
                std::fs::write(&full, "{}").unwrap();
            }
        }
        let cfg = MaterializedRuntimeConfig {
            schema: SchemaVersion::new(SchemaVersion::RUNTIME_CONFIG_V1),
            env_id: EnvId::new(ENV_ID).unwrap(),
            revisions: blocks.to_vec(),
        };
        std::fs::write(
            env_dir.join("runtime-config.json"),
            serde_json::to_string_pretty(&cfg).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn uninitialized_env_reports_resolve_error() {
        let tmp = TempDir::new().unwrap();
        let diags = environment_diagnostics(tmp.path(), ENV_ID);
        let resolve = by_id(&diags, "start.env.resolve");
        assert_eq!(severities(&resolve), vec![Severity::Error]);
        assert!(
            resolve[0]
                .fix_hint
                .as_deref()
                .unwrap_or_default()
                .contains("env init"),
            "fix hint should name env init: {:?}",
            resolve[0].fix_hint
        );
        // Nothing else runs against an uninitialized env.
        assert_eq!(diags.len(), 1);
    }

    #[test]
    fn unsafe_env_id_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let diags = environment_diagnostics(tmp.path(), "..");
        let resolve = by_id(&diags, "start.env.resolve");
        assert_eq!(severities(&resolve), vec![Severity::Error]);
        assert_eq!(diags.len(), 1);
    }

    #[test]
    fn malformed_environment_json_reports_load_error() {
        let tmp = TempDir::new().unwrap();
        let env_dir = tmp.path().join(ENV_ID);
        std::fs::create_dir_all(&env_dir).unwrap();
        std::fs::write(env_dir.join("environment.json"), b"{not json").unwrap();
        let diags = environment_diagnostics(tmp.path(), ENV_ID);
        let load = by_id(&diags, "start.env.load");
        assert_eq!(severities(&load), vec![Severity::Error]);
    }

    #[test]
    fn empty_trust_root_warns_before_any_revision_exists() {
        let tmp = TempDir::new().unwrap();
        save_env(tmp.path(), &env_with(Vec::new()));
        let diags = environment_diagnostics(tmp.path(), ENV_ID);
        let trust = by_id(&diags, "start.env.trust_root");
        assert_eq!(severities(&trust), vec![Severity::Warn]);
        assert_eq!(error_count(&diags), 0, "diags: {diags:#?}");
    }

    #[test]
    fn empty_trust_root_is_error_once_revisions_exist() {
        let tmp = TempDir::new().unwrap();
        let (env, _dep, _rev) = env_with_linked_bundle(RevisionLifecycle::Ready, Vec::new());
        save_env(tmp.path(), &env);
        let diags = environment_diagnostics(tmp.path(), ENV_ID);
        let trust = by_id(&diags, "start.env.trust_root");
        assert_eq!(severities(&trust), vec![Severity::Error]);
        assert!(trust[0].message.contains("fail closed"));
    }

    #[test]
    fn valid_trust_root_passes() {
        let tmp = TempDir::new().unwrap();
        save_env(tmp.path(), &env_with(Vec::new()));
        let (pub_pem, key_id) = trusted_keypair(1);
        add_trusted_key(
            &tmp.path().join(ENV_ID),
            TrustedKey {
                key_id,
                public_key_pem: pub_pem,
            },
        )
        .unwrap();
        let diags = environment_diagnostics(tmp.path(), ENV_ID);
        let trust = by_id(&diags, "start.env.trust_root");
        assert_eq!(severities(&trust), vec![Severity::Info]);
    }

    #[test]
    fn trust_root_key_id_mismatch_is_error() {
        let tmp = TempDir::new().unwrap();
        save_env(tmp.path(), &env_with(Vec::new()));
        let env_dir = tmp.path().join(ENV_ID);
        let (pub_pem, key_id) = trusted_keypair(1);
        add_trusted_key(
            &env_dir,
            TrustedKey {
                key_id,
                public_key_pem: pub_pem,
            },
        )
        .unwrap();
        // Corrupt the stored key_id out-of-band: `add_trusted_key` validates
        // at write time, so the drift the doctor must catch arrives via
        // manual edits or foreign writers.
        let path = env_dir.join("trust-root.json");
        let mut doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        doc["keys"][0]["key_id"] = serde_json::Value::String("deadbeef".to_string());
        std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
        let diags = environment_diagnostics(tmp.path(), ENV_ID);
        let trust = by_id(&diags, "start.env.trust_root");
        assert_eq!(severities(&trust), vec![Severity::Error]);
        assert!(
            trust[0].message.contains("derivation"),
            "{}",
            trust[0].message
        );
    }

    #[test]
    fn unlinked_endpoint_warns() {
        let tmp = TempDir::new().unwrap();
        save_env(tmp.path(), &env_with(vec![endpoint("legal-bot", &[])]));
        let diags = environment_diagnostics(tmp.path(), ENV_ID);
        let links = by_id(&diags, "start.env.endpoint_links");
        assert_eq!(severities(&links), vec![Severity::Warn]);
        assert!(links[0].message.contains("no linked bundles"));
    }

    #[test]
    fn linked_endpoint_with_ready_traffic_passes() {
        let tmp = TempDir::new().unwrap();
        let (env, dep, rev) = env_with_linked_bundle(
            RevisionLifecycle::Ready,
            vec![endpoint("legal-bot", &["fast2flow"])],
        );
        save_env(tmp.path(), &env);
        write_runtime_config(tmp.path(), &dep, &rev);
        let diags = environment_diagnostics(tmp.path(), ENV_ID);
        let links = by_id(&diags, "start.env.endpoint_links");
        assert_eq!(
            severities(&links),
            vec![Severity::Info],
            "diags: {links:#?}"
        );
    }

    #[test]
    fn linked_endpoint_without_ready_revision_warns() {
        let tmp = TempDir::new().unwrap();
        // The split routes full weight to a revision that never reached
        // Ready — spec-valid state, but nothing will serve.
        let (env, _dep, _rev) = env_with_linked_bundle(
            RevisionLifecycle::Staged,
            vec![endpoint("legal-bot", &["fast2flow"])],
        );
        save_env(tmp.path(), &env);
        let diags = environment_diagnostics(tmp.path(), ENV_ID);
        let links = by_id(&diags, "start.env.endpoint_links");
        assert_eq!(severities(&links), vec![Severity::Warn]);
        assert!(links[0].message.contains("no Ready revision"));
    }

    #[test]
    fn linked_endpoint_with_paused_deployment_warns() {
        let tmp = TempDir::new().unwrap();
        let dep = deployment("fast2flow", BundleDeploymentStatus::Paused);
        let mut env = env_with(vec![endpoint("legal-bot", &["fast2flow"])]);
        env.bundles = vec![dep];
        save_env(tmp.path(), &env);
        let diags = environment_diagnostics(tmp.path(), ENV_ID);
        let links = by_id(&diags, "start.env.endpoint_links");
        assert_eq!(severities(&links), vec![Severity::Warn]);
        assert!(links[0].message.contains("not Active"));
    }

    #[test]
    fn secret_ref_without_dev_store_is_error() {
        let _env_guard = crate::test_env_lock().lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let env = env_with(vec![telegram_endpoint_with_webhook_secret("tg-bot", &[])]);
        save_env(tmp.path(), &env);
        let diags = environment_diagnostics(tmp.path(), ENV_ID);
        let secrets = by_id(&diags, "start.env.secrets");
        assert_eq!(severities(&secrets), vec![Severity::Error]);
        assert!(secrets[0].message.contains("no dev secrets store"));
    }

    #[test]
    fn unresolved_secret_ref_is_error() {
        let _env_guard = crate::test_env_lock().lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let env = env_with(vec![telegram_endpoint_with_webhook_secret("tg-bot", &[])]);
        save_env(tmp.path(), &env);
        // A dev store exists but holds only an unrelated secret.
        seed_dev_store(
            &tmp.path().join(ENV_ID),
            "secrets://local/default/_/other-pack/other_key",
            b"unrelated",
        );
        let diags = environment_diagnostics(tmp.path(), ENV_ID);
        let secrets = by_id(&diags, "start.env.secrets");
        assert_eq!(severities(&secrets), vec![Severity::Error]);
        assert!(secrets[0].message.contains("does not resolve"));
        assert!(
            secrets[0].evidence["uri"]
                .as_str()
                .unwrap_or_default()
                .starts_with("secrets://local/default/_/messaging-"),
            "evidence should carry the flipped dev-store URI: {}",
            secrets[0].evidence
        );
    }

    #[test]
    fn resolvable_secret_refs_pass_and_values_never_leak() {
        let _env_guard = crate::test_env_lock().lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let ep = telegram_endpoint_with_webhook_secret("tg-bot", &[]);
        let uri = secret_ref_to_store_uri(ep.webhook_secret_ref.as_ref().unwrap());
        let env = env_with(vec![ep]);
        save_env(tmp.path(), &env);
        const SECRET_VALUE: &[u8] = b"tok-secret-9000";
        seed_dev_store(&tmp.path().join(ENV_ID), &uri, SECRET_VALUE);
        let diags = environment_diagnostics(tmp.path(), ENV_ID);
        let secrets = by_id(&diags, "start.env.secrets");
        assert_eq!(
            severities(&secrets),
            vec![Severity::Info],
            "diags: {secrets:#?}"
        );
        // Redaction: the resolved value must never appear anywhere in the
        // serialized diagnostics.
        let dump = serde_json::to_string(&diags).unwrap();
        assert!(
            !dump.contains(std::str::from_utf8(SECRET_VALUE).unwrap()),
            "secret value leaked into diagnostics"
        );
    }

    #[test]
    fn no_endpoints_yields_infos_only() {
        let tmp = TempDir::new().unwrap();
        save_env(tmp.path(), &env_with(Vec::new()));
        let diags = environment_diagnostics(tmp.path(), ENV_ID);
        assert_eq!(error_count(&diags), 0);
        assert_eq!(
            severities(&by_id(&diags, "start.env.endpoint_links")),
            vec![Severity::Info]
        );
        assert_eq!(
            severities(&by_id(&diags, "start.env.secrets")),
            vec![Severity::Info]
        );
    }

    // ---- runtime-config cross-reference tests (Finding 1) -----------------

    #[test]
    fn ready_traffic_without_runtime_config_warns_not_materialized() {
        // Env claims Ready traffic but NO runtime-config file exists.
        let tmp = TempDir::new().unwrap();
        let (env, _dep, _rev) = env_with_linked_bundle(
            RevisionLifecycle::Ready,
            vec![endpoint("legal-bot", &["fast2flow"])],
        );
        save_env(tmp.path(), &env);
        // No runtime-config.json written.
        let diags = environment_diagnostics(tmp.path(), ENV_ID);
        let links = by_id(&diags, "start.env.endpoint_links");
        // Should get a Warn (NotMaterialized), NOT the all-serving Info.
        assert_eq!(
            severities(&links),
            vec![Severity::Warn],
            "expected NotMaterialized warn, got: {links:#?}"
        );
        assert!(links[0].message.contains("runtime-config"));
    }

    #[test]
    fn ready_traffic_with_valid_runtime_config_serves() {
        // Env + valid runtime-config → all-serving Info.
        let tmp = TempDir::new().unwrap();
        let (env, dep, rev) = env_with_linked_bundle(
            RevisionLifecycle::Ready,
            vec![endpoint("legal-bot", &["fast2flow"])],
        );
        save_env(tmp.path(), &env);
        write_runtime_config(tmp.path(), &dep, &rev);
        let diags = environment_diagnostics(tmp.path(), ENV_ID);
        let links = by_id(&diags, "start.env.endpoint_links");
        assert_eq!(
            severities(&links),
            vec![Severity::Info],
            "diags: {links:#?}"
        );
        // runtime_config check itself should be Info (loaded).
        let rc = by_id(&diags, "start.env.runtime_config");
        assert_eq!(severities(&rc), vec![Severity::Info]);
    }

    #[test]
    fn malformed_runtime_config_is_error() {
        // Test 3: garbage runtime-config.json → Error.
        let tmp = TempDir::new().unwrap();
        save_env(tmp.path(), &env_with(Vec::new()));
        let env_dir = tmp.path().join(ENV_ID);
        std::fs::write(env_dir.join("runtime-config.json"), b"not json at all").unwrap();
        let diags = environment_diagnostics(tmp.path(), ENV_ID);
        let rc = by_id(&diags, "start.env.runtime_config");
        assert_eq!(severities(&rc), vec![Severity::Error]);
        assert!(rc[0].message.contains("runtime-config"));
    }

    // ---- multi-deployment tests (Finding 2) --------------------------------

    #[test]
    fn multi_deployment_partial_serving() {
        // Test 4: two deployments of the same bundle. A fully serving
        // (env + runtime-config), B Active but no traffic → exactly one
        // Warn naming B's deployment_id, no all-serving Info.
        let tmp = TempDir::new().unwrap();
        let dep_a = deployment("fast2flow", BundleDeploymentStatus::Active);
        let rev_a = revision(&dep_a, RevisionLifecycle::Ready);
        let dep_b = deployment("fast2flow", BundleDeploymentStatus::Active);
        // dep_b has no traffic split → NoReadyTraffic.
        let mut env = env_with(vec![endpoint("legal-bot", &["fast2flow"])]);
        env.traffic_splits = vec![split(&dep_a, &rev_a)];
        env.bundles = vec![dep_a.clone(), dep_b.clone()];
        env.revisions = vec![rev_a.clone()];
        save_env(tmp.path(), &env);
        write_runtime_config(tmp.path(), &dep_a, &rev_a);

        let diags = environment_diagnostics(tmp.path(), ENV_ID);
        let links = by_id(&diags, "start.env.endpoint_links");
        // One Warn for dep_b (no Ready traffic), no Info (not all serving).
        let warns: Vec<_> = links
            .iter()
            .filter(|d| d.severity == Severity::Warn)
            .collect();
        assert_eq!(warns.len(), 1, "expected 1 warn, got: {links:#?}");
        assert!(
            warns[0]
                .evidence
                .get("deployment_id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| id == dep_b.deployment_id.to_string())
        );
        assert!(
            links.iter().all(|d| d.severity != Severity::Info),
            "should not get all-serving Info: {links:#?}"
        );

        // Now reverse the deployment order in env.bundles and verify the same verdict.
        let mut env2 = env_with(vec![endpoint("legal-bot", &["fast2flow"])]);
        env2.traffic_splits = vec![split(&dep_a, &rev_a)];
        env2.bundles = vec![dep_b.clone(), dep_a.clone()];
        env2.revisions = vec![rev_a.clone()];
        save_env(tmp.path(), &env2);
        // runtime-config already written for dep_a.
        let diags2 = environment_diagnostics(tmp.path(), ENV_ID);
        let links2 = by_id(&diags2, "start.env.endpoint_links");
        let warns2: Vec<_> = links2
            .iter()
            .filter(|d| d.severity == Severity::Warn)
            .collect();
        assert_eq!(warns2.len(), 1, "reversed order: {links2:#?}");
        assert!(
            warns2[0]
                .evidence
                .get("deployment_id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| id == dep_b.deployment_id.to_string())
        );
    }
}
