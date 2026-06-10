//! Environment-store runtime-readiness checks (PR-3 of
//! `plans/env-manifest-apply.md`).
//!
//! `gtc op env apply` verifies its writes at the *store* level; whether the
//! runtime can actually use that state is this module's job. Three gaps the
//! PR-3 investigation found, each a check here:
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
//!    serves nothing.
//! 3. **Secret-ref resolvability** — each endpoint `secret_refs` /
//!    `webhook_secret_ref` entry is read through the SAME dev-store reader
//!    the bundle-less boot wires up ([`crate::secrets_client::SecretsClient`]
//!    over [`crate::dev_store_path`]), so doctor's verdict matches what the
//!    runtime will see. Secret *values* are discarded immediately —
//!    diagnostics carry only URIs.
//!
//! Diagnostics flow through the existing `--stage` filter via their
//! [`DiagnosticComponent`]: env resolution/load + trust root are `Runtime`,
//! endpoint linkage is `Routes`, secret resolvability is `Provider` (so
//! `--stage secrets` includes it).

use std::path::Path;

use greentic_deploy_spec::{BundleDeploymentStatus, BundleId, Environment, RevisionLifecycle};
use greentic_deployer::environment::{EnvironmentStore, LocalFsStore, load_trust_root};
use greentic_distributor_client::signing::key_id_for_public_key_pem;
use greentic_secrets_lib::{SecretError, SecretsManager};
use serde_json::{Value, json};

use crate::doctor::{Diagnostic, DiagnosticComponent, Severity};
use crate::webhook_secret_resolver::secret_ref_to_store_uri;

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
                "start.env.resolve",
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
            "start.env.resolve",
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
                "start.env.resolve",
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
                "start.env.load",
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
        "start.env.load",
        DiagnosticComponent::Runtime,
        "Environment loaded and validated.",
        json!({
            "env_id": env_id,
            "bundles": env.bundles.len(),
            "revisions": env.revisions.len(),
            "messaging_endpoints": env.messaging_endpoints.len(),
        }),
    ));

    check_trust_root(&mut out, &env_dir, &env);
    check_endpoint_linkage(&mut out, &env);
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
fn check_endpoint_linkage(out: &mut Vec<Diagnostic>, env: &Environment) {
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
        let endpoint_label = json!({
            "endpoint_id": endpoint.endpoint_id.to_string(),
            "provider_type": endpoint.provider_type,
            "provider_id": endpoint.provider_id,
        });
        if endpoint.linked_bundles.is_empty() {
            out.push(warn(
                "start.env.endpoint_links",
                DiagnosticComponent::Routes,
                "Messaging endpoint has no linked bundles — the admit gate fail-closes every request asserting it.",
                endpoint_label,
                Some("Link a deployed bundle: `gtc op messaging endpoint link-bundle`."),
            ));
            continue;
        }

        let mut serving = 0usize;
        for bundle_id in &endpoint.linked_bundles {
            match bundle_serving_state(env, bundle_id) {
                ServingState::Serving => serving += 1,
                ServingState::NotDeployed => out.push(error(
                    "start.env.endpoint_links",
                    DiagnosticComponent::Routes,
                    "Endpoint links a bundle with no deployment in this environment.",
                    json!({
                        "endpoint_id": endpoint.endpoint_id.to_string(),
                        "bundle_id": bundle_id.to_string(),
                    }),
                    (
                        json!({ "deployment_exists": true }),
                        json!({ "deployment_exists": false }),
                    ),
                    Some("Deploy the bundle (`gtc op deploy`) or unlink it from the endpoint."),
                )),
                ServingState::DeploymentNotActive(status) => out.push(warn(
                    "start.env.endpoint_links",
                    DiagnosticComponent::Routes,
                    "Endpoint links a bundle whose deployment is not Active — requests for it will not route.",
                    json!({
                        "endpoint_id": endpoint.endpoint_id.to_string(),
                        "bundle_id": bundle_id.to_string(),
                        "status": format!("{status:?}"),
                    }),
                    Some("Reactivate the deployment or unlink the bundle from the endpoint."),
                )),
                ServingState::NoReadyTraffic => out.push(warn(
                    "start.env.endpoint_links",
                    DiagnosticComponent::Routes,
                    "Endpoint links a bundle with no Ready revision receiving traffic.",
                    json!({
                        "endpoint_id": endpoint.endpoint_id.to_string(),
                        "bundle_id": bundle_id.to_string(),
                    }),
                    Some("Deploy and warm a revision, then route traffic to it (`gtc op deploy` / `gtc op traffic`)."),
                )),
            }
        }
        if serving == endpoint.linked_bundles.len() {
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
    NotDeployed,
    DeploymentNotActive(BundleDeploymentStatus),
    NoReadyTraffic,
}

/// Whether `bundle_id` is actually servable in `env`: an Active deployment
/// plus at least one traffic-split entry with positive weight pointing at a
/// `Ready` revision of that deployment. Mirrors the runtime's routing
/// inputs: [`crate::deployment_routes`] only routes Active deployments, and
/// the dispatcher picks revisions from the traffic split.
fn bundle_serving_state(env: &Environment, bundle_id: &BundleId) -> ServingState {
    let Some(deployment) = env
        .bundles
        .iter()
        .find(|deployment| deployment.bundle_id == *bundle_id)
    else {
        return ServingState::NotDeployed;
    };
    if deployment.status != BundleDeploymentStatus::Active {
        return ServingState::DeploymentNotActive(deployment.status);
    }
    let has_ready_traffic = env
        .traffic_splits
        .iter()
        .filter(|split| {
            split.bundle_id == *bundle_id && split.deployment_id == deployment.deployment_id
        })
        .flat_map(|split| &split.entries)
        .any(|entry| {
            entry.weight_bps > 0
                && env.revisions.iter().any(|revision| {
                    revision.revision_id == entry.revision_id
                        && revision.lifecycle == RevisionLifecycle::Ready
                })
        });
    if has_ready_traffic {
        ServingState::Serving
    } else {
        ServingState::NoReadyTraffic
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

fn error(
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
        PartyId, RevenueShareEntry, Revision, RevisionId, RouteBinding, SchemaVersion, SemVer,
        TenantSelector, TrafficSplit, TrafficSplitEntry,
    };
    use greentic_deployer::environment::add_trusted_key;
    use greentic_distributor_client::signing::TrustedKey;
    use greentic_secrets_lib::{SecretFormat, SecretsStore, core::seed::DevStore};
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
        let dep = deployment("fast2flow", BundleDeploymentStatus::Active);
        let rev = revision(&dep, RevisionLifecycle::Ready);
        let mut env = env_with(Vec::new());
        env.traffic_splits = vec![split(&dep, &rev)];
        env.bundles = vec![dep];
        env.revisions = vec![rev];
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
        let dep = deployment("fast2flow", BundleDeploymentStatus::Active);
        let rev = revision(&dep, RevisionLifecycle::Ready);
        let mut env = env_with(vec![endpoint("legal-bot", &["fast2flow"])]);
        env.traffic_splits = vec![split(&dep, &rev)];
        env.bundles = vec![dep];
        env.revisions = vec![rev];
        save_env(tmp.path(), &env);
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
        let dep = deployment("fast2flow", BundleDeploymentStatus::Active);
        // The split routes full weight to a revision that never reached
        // Ready — spec-valid state, but nothing will serve.
        let rev = revision(&dep, RevisionLifecycle::Staged);
        let mut env = env_with(vec![endpoint("legal-bot", &["fast2flow"])]);
        env.traffic_splits = vec![split(&dep, &rev)];
        env.bundles = vec![dep];
        env.revisions = vec![rev];
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
}
