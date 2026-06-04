//! New-model (revision-serve) provider webhook auto-registration (Phase D).
//!
//! The bundle-less boot serves provider webhooks at synthesized routes
//! (`{prefix}/webhook/<provider>`), but nothing tells the external provider
//! (Telegram, ...) to POST there. This module closes that gap: for every served
//! provider-ingest route it invokes the provider's `setup_webhook` op with the
//! *actual* served URL and the endpoint's `provider_id` as the IID
//! `secret_token`, so inbound webhooks land on the right route and the M1 IID
//! resolver can identify the endpoint.
//!
//! Gated on a configured `PUBLIC_BASE_URL`: the bundle-less boot runs no tunnel,
//! so a configured public address is the only thing we can hand to a provider.
//! With none, registration is skipped (register manually, e.g. via `curl`).
//!
//! Runs at boot (after the revision server is listening) and after every
//! config reload (hot-attach) — see [`post_reload_registration`], which fires
//! only AFTER `server.reload` swapped the new activation in, so the registered
//! URL is live before the provider can validate or deliver to it. Both runs
//! are detached tasks with a per-invocation timeout: a slow or stuck provider
//! API call must never delay the activation swap, the reload watcher, or boot.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use greentic_deploy_spec::{DeploymentId, Environment, MessagingEndpoint};
use serde_json::{Value, json};

use crate::http_routes::{HttpRouteDescriptor, INGEST_HTTP_OP, derive_provider_name};
use crate::operator_log;
use crate::revision_serve::Activation;

/// Provider op that performs the external webhook registration.
const SETUP_WEBHOOK_OP: &str = "setup_webhook";

/// Upper bound per `setup_webhook` invocation. Bounds async waits inside the
/// host; a provider stuck in a blocking in-component HTTP call is additionally
/// bounded by the host HTTP client's own timeouts.
const SETUP_WEBHOOK_TIMEOUT: Duration = Duration::from_secs(30);

/// One planned `setup_webhook` invocation, fully resolved from the served
/// routes + the environment. Kept separate from the invocation loop so the
/// route↔endpoint↔deployment join is unit-testable without a live host.
#[derive(Debug, Clone, PartialEq)]
struct WebhookRegistration {
    tenant: String,
    deployment_id: DeploymentId,
    bundle_id: greentic_deploy_spec::BundleId,
    revision_id: greentic_deploy_spec::RevisionId,
    /// The pack descriptor's `provider_type` (what `invoke_provider_for_revision`
    /// resolves the binding by), e.g. `messaging.telegram`.
    provider_type: String,
    /// Derived provider name, for logging only.
    provider_name: String,
    webhook_url: String,
    /// The IID `secret_token` (endpoint `provider_id`), when an endpoint links
    /// this bundle. `None` ⇒ register URL-only (single-bundle fallback).
    secret_token: Option<String>,
    /// Stable, non-secret instance discriminator for providers that reconcile
    /// registrations by name. Webex prefixes its webhook names with a
    /// tenant+instance string and DELETES stale entries under that prefix —
    /// without a distinct instance every auto-registration collapses to the
    /// provider's `default-default` and deployments sharing one bot delete
    /// each other's webhooks. The matched `endpoint_id` when an endpoint
    /// links the bundle, else the `deployment_id` — both ULIDs.
    instance_id: String,
    /// Count of *additional* same-provider endpoints linked to this bundle
    /// beyond the one we registered. A bot has a single webhook, so we register
    /// the first and warn (never the value — `provider_id` is the secret-token).
    extra_endpoints: usize,
}

impl WebhookRegistration {
    fn payload(&self) -> Vec<u8> {
        let mut body = json!({
            "webhook_url": self.webhook_url,
            "tenant": self.tenant,
            "provider_instance_id": self.instance_id,
        });
        if let Some(token) = &self.secret_token {
            body["secret_token"] = json!(token);
        }
        serde_json::to_vec(&body).unwrap_or_default()
    }
}

/// Register webhooks for every served provider-ingest route. Best-effort: a
/// provider without a `setup_webhook` op, or one whose registration fails, is
/// logged and skipped — registration never fails the boot.
pub(crate) async fn register_new_model_webhooks(
    activation: &Activation,
    environment: &Environment,
    public_base_url: Option<&str>,
) {
    let Some(base) = public_base_url else {
        operator_log::info(
            module_path!(),
            "skipping webhook auto-registration: no configured PUBLIC_BASE_URL \
             (register the provider webhook manually)",
        );
        return;
    };

    let tenant_by_deployment: HashMap<DeploymentId, String> = environment
        .bundles
        .iter()
        .map(|d| {
            (
                d.deployment_id,
                d.route_binding.tenant_selector.tenant.clone(),
            )
        })
        .collect();

    let plans = plan_webhook_registrations(
        activation.routing.http_routes.routes(),
        &environment.messaging_endpoints,
        &tenant_by_deployment,
        base,
    );

    if plans.is_empty() {
        operator_log::info(
            module_path!(),
            "webhook auto-registration: no provider-ingest routes to register",
        );
        return;
    }

    for plan in plans {
        if plan.extra_endpoints > 0 {
            operator_log::warn(
                module_path!(),
                format!(
                    "provider={} bundle has {} additional endpoint(s) linked beyond the one \
                     auto-registered; a bot has a single webhook — register the others manually",
                    plan.provider_name, plan.extra_endpoints,
                ),
            );
        }
        let invoke = activation.host.invoke_provider_for_revision(
            &plan.tenant,
            plan.deployment_id,
            plan.bundle_id.clone(),
            plan.revision_id,
            &plan.provider_type,
            SETUP_WEBHOOK_OP,
            plan.payload(),
            None,
            None,
        );
        match tokio::time::timeout(SETUP_WEBHOOK_TIMEOUT, invoke).await {
            Err(_elapsed) => {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "webhook registration timed out after {}s: provider={} url={} \
                         (the provider may or may not have stored the webhook)",
                        SETUP_WEBHOOK_TIMEOUT.as_secs(),
                        plan.provider_name,
                        plan.webhook_url,
                    ),
                );
            }
            Ok(Ok(output)) => {
                // `setup_webhook` may run yet report a logical failure as
                // `{"ok": false}` (bad token, provider API error, ...).
                let ok = output.get("ok").and_then(Value::as_bool).unwrap_or(true);
                if ok {
                    operator_log::info(
                        module_path!(),
                        format!(
                            "webhook registered: provider={} url={} deployment={} secret_token={}",
                            plan.provider_name,
                            plan.webhook_url,
                            plan.deployment_id,
                            plan.secret_token.is_some(),
                        ),
                    );
                } else {
                    let err = output
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    operator_log::warn(
                        module_path!(),
                        format!(
                            "webhook registration reported failure: provider={} url={} error={}",
                            plan.provider_name, plan.webhook_url, err,
                        ),
                    );
                }
            }
            Ok(Err(err)) => {
                // No `setup_webhook` op, missing creds, etc. — not fatal.
                operator_log::debug(
                    module_path!(),
                    format!(
                        "setup_webhook unavailable for provider={} deployment={}: {err:#}",
                        plan.provider_name, plan.deployment_id,
                    ),
                );
            }
        }
    }
}

/// Pure join: served routes × endpoints × deployment-tenant map → registrations.
///
/// One registration per `(deployment, revision, provider-name)`: a deployment
/// with multiple `path_prefixes` synthesizes multiple routes, but a bot has a
/// single webhook, so we register the first prefix and drop the rest.
fn plan_webhook_registrations(
    routes: &[HttpRouteDescriptor],
    endpoints: &[MessagingEndpoint],
    tenant_by_deployment: &HashMap<DeploymentId, String>,
    base: &str,
) -> Vec<WebhookRegistration> {
    let base = base.trim_end_matches('/');
    let mut seen: HashSet<(DeploymentId, greentic_deploy_spec::RevisionId, String)> =
        HashSet::new();
    let mut plans = Vec::new();

    for route in routes {
        if route.provider_op != INGEST_HTTP_OP {
            continue;
        }
        let Some(scope) = route.scope.as_ref() else {
            continue;
        };
        let Some(provider_type) = route.provider_type.as_deref() else {
            continue;
        };
        let Some(name) = derive_provider_name(provider_type) else {
            continue;
        };

        if !seen.insert((scope.deployment_id, scope.revision_id, name.clone())) {
            continue;
        }

        let Some(tenant) = tenant_by_deployment.get(&scope.deployment_id) else {
            // Route belongs to a deployment with no env binding — shouldn't
            // happen (routes are synthesized from the same env), but skip
            // rather than guess a tenant.
            continue;
        };

        // Endpoints that link this bundle for this provider supply the IID
        // secret_token. Matched on the canonical provider name so the route's
        // descriptor type (`messaging.telegram`) and the endpoint's class
        // (`telegram`) reconcile. A bot has ONE webhook, so we register the
        // first matching endpoint and surface a count of any extras (their
        // `provider_id`s are secret-tokens — never logged).
        let matching: Vec<&MessagingEndpoint> = endpoints
            .iter()
            .filter(|e| {
                e.linked_bundles.iter().any(|b| b == &scope.bundle_id)
                    && derive_provider_name(&e.provider_type).as_deref() == Some(name.as_str())
            })
            .collect();
        let secret_token = matching.first().map(|e| e.provider_id.clone());
        let instance_id = matching
            .first()
            .map(|e| e.endpoint_id.to_string())
            .unwrap_or_else(|| scope.deployment_id.to_string());
        let extra_endpoints = matching.len().saturating_sub(1);

        plans.push(WebhookRegistration {
            tenant: tenant.clone(),
            deployment_id: scope.deployment_id,
            bundle_id: scope.bundle_id.clone(),
            revision_id: scope.revision_id,
            provider_type: provider_type.to_string(),
            provider_name: name,
            webhook_url: format!("{base}{}", route.pattern),
            secret_token,
            instance_id,
            extra_endpoints,
        });
    }

    plans
}

/// Build the runtime-config watcher's post-reload hook: after a reload that
/// actually changed config (`Ok(Some(..))` rebuild) swapped a new activation
/// into the server, re-register webhooks against it. Running AFTER the swap
/// matters: a provider that validates the URL during `setup_webhook` (or
/// delivers immediately) must hit the newly-served routes, not the superseded
/// activation. The registration itself runs as a detached task so the watcher
/// thread stays free to process the next reload event. Idempotent for
/// unchanged paths; covers hot-attached deployments; failures are best-effort
/// logged — the next config reload re-registers.
pub(crate) fn post_reload_registration(
    store_root: PathBuf,
    env_id: String,
    public_base_url: Option<String>,
    rt: tokio::runtime::Handle,
) -> impl FnMut(&Activation) + Send + 'static {
    move |activation: &Activation| {
        let env = match load_environment(&store_root, &env_id) {
            Ok(env) => env,
            Err(err) => {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "skipping webhook re-registration after reload: \
                         cannot load environment `{env_id}`: {err:#}"
                    ),
                );
                return;
            }
        };
        let activation = activation.clone();
        let public_base_url = public_base_url.clone();
        rt.spawn(async move {
            register_new_model_webhooks(&activation, &env, public_base_url.as_deref()).await;
        });
    }
}

/// Load the env the same way the bundle-less cold start does.
fn load_environment(store_root: &Path, env_id: &str) -> Result<Environment> {
    let env_store = greentic_deployer::environment::LocalFsStore::new(store_root.to_path_buf());
    let env_typed = greentic_types::EnvId::new(env_id)
        .with_context(|| format!("invalid environment id `{env_id}`"))?;
    greentic_deployer::environment::EnvironmentStore::load(&env_store, &env_typed)
        .with_context(|| format!("loading environment `{env_id}`"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_routes::{RevisionScope, provider_descriptor_for_test};
    use greentic_deploy_spec::{
        BundleId, DeploymentId, MessagingEndpoint, MessagingEndpointId, RevisionId, SchemaVersion,
    };
    use greentic_types::EnvId;

    fn scope(deployment: DeploymentId, bundle: &str, revision: RevisionId) -> RevisionScope {
        RevisionScope {
            deployment_id: deployment,
            bundle_id: BundleId::new(bundle),
            revision_id: revision,
        }
    }

    fn endpoint(provider_type: &str, provider_id: &str, linked: &[&str]) -> MessagingEndpoint {
        let now = chrono::Utc::now();
        MessagingEndpoint {
            schema: SchemaVersion::new(SchemaVersion::MESSAGING_ENDPOINT_V1),
            env_id: EnvId::try_from("local").unwrap(),
            endpoint_id: MessagingEndpointId::new(),
            provider_id: provider_id.to_string(),
            provider_type: provider_type.to_string(),
            display_name: "test".to_string(),
            secret_refs: Vec::new(),
            linked_bundles: linked.iter().map(|b| BundleId::new(*b)).collect(),
            welcome_flow: None,
            generation: 1,
            created_at: now,
            updated_at: now,
            updated_by: "test".to_string(),
        }
    }

    #[test]
    fn builds_url_from_served_pattern_and_carries_endpoint_secret_token() {
        let dep = DeploymentId::new();
        let rev = RevisionId::new();
        let routes = vec![provider_descriptor_for_test(
            "/bot/webhook/telegram",
            "messaging.telegram",
            scope(dep, "realbot-pack", rev),
        )];
        let endpoints = vec![endpoint("telegram", "tg-secret-token", &["realbot-pack"])];
        let eid = endpoints[0].endpoint_id.to_string();
        let tenants = HashMap::from([(dep, "default".to_string())]);

        let plans = plan_webhook_registrations(&routes, &endpoints, &tenants, "https://host/");
        assert_eq!(plans.len(), 1);
        let p = &plans[0];
        assert_eq!(p.webhook_url, "https://host/bot/webhook/telegram");
        assert_eq!(p.secret_token.as_deref(), Some("tg-secret-token"));
        assert_eq!(p.tenant, "default");
        assert_eq!(p.provider_type, "messaging.telegram");
        let body: Value = serde_json::from_slice(&p.payload()).unwrap();
        assert_eq!(body["webhook_url"], "https://host/bot/webhook/telegram");
        assert_eq!(body["secret_token"], "tg-secret-token");
        // Identity fields: webex derives its reconciliation instance from
        // tenant + provider_instance_id; without them every registration
        // collapses to `default-default` and deployments sharing one bot
        // delete each other's webhooks.
        assert_eq!(body["tenant"], "default");
        assert_eq!(body["provider_instance_id"], eid.as_str());
    }

    #[test]
    fn registers_url_only_when_no_endpoint_links_the_bundle() {
        let dep = DeploymentId::new();
        let rev = RevisionId::new();
        let routes = vec![provider_descriptor_for_test(
            "/bot/webhook/telegram",
            "messaging.telegram",
            scope(dep, "realbot-pack", rev),
        )];
        // endpoint links a DIFFERENT bundle
        let endpoints = vec![endpoint("telegram", "tg-secret-token", &["other-pack"])];
        let tenants = HashMap::from([(dep, "default".to_string())]);

        let plans = plan_webhook_registrations(&routes, &endpoints, &tenants, "https://host");
        assert_eq!(plans.len(), 1);
        assert!(plans[0].secret_token.is_none());
        let body: Value = serde_json::from_slice(&plans[0].payload()).unwrap();
        assert!(body.get("secret_token").is_none());
        // No endpoint → the deployment id is the stable instance discriminator.
        assert_eq!(body["provider_instance_id"], dep.to_string().as_str());
    }

    #[test]
    fn multiple_same_provider_endpoints_register_first_and_count_extras() {
        let dep = DeploymentId::new();
        let rev = RevisionId::new();
        let routes = vec![provider_descriptor_for_test(
            "/bot/webhook/telegram",
            "messaging.telegram.bot",
            scope(dep, "realbot-pack", rev),
        )];
        let endpoints = vec![
            endpoint("telegram", "tok-a", &["realbot-pack"]),
            endpoint("telegram", "tok-b", &["realbot-pack"]),
        ];
        let tenants = HashMap::from([(dep, "default".to_string())]);
        let plans = plan_webhook_registrations(&routes, &endpoints, &tenants, "https://host");
        assert_eq!(plans.len(), 1, "one webhook per provider route");
        assert_eq!(
            plans[0].secret_token.as_deref(),
            Some("tok-a"),
            "first wins"
        );
        assert_eq!(
            plans[0].extra_endpoints, 1,
            "second endpoint counted as extra"
        );
    }

    #[test]
    fn dedups_multiple_prefixes_to_one_registration_per_provider() {
        let dep = DeploymentId::new();
        let rev = RevisionId::new();
        let routes = vec![
            provider_descriptor_for_test(
                "/bot/webhook/telegram",
                "messaging.telegram",
                scope(dep, "p", rev),
            ),
            provider_descriptor_for_test(
                "/api/bot/webhook/telegram",
                "messaging.telegram",
                scope(dep, "p", rev),
            ),
        ];
        let tenants = HashMap::from([(dep, "default".to_string())]);
        let plans = plan_webhook_registrations(&routes, &[], &tenants, "https://host");
        assert_eq!(
            plans.len(),
            1,
            "one webhook per (deployment, revision, provider)"
        );
    }

    #[test]
    fn skips_non_ingest_routes_and_unknown_deployments() {
        let dep = DeploymentId::new();
        let rev = RevisionId::new();
        let routes = vec![provider_descriptor_for_test(
            "/bot/webhook/telegram",
            "messaging.telegram",
            scope(dep, "p", rev),
        )];
        // tenant map does NOT contain `dep` → skipped (no tenant to run under)
        let plans = plan_webhook_registrations(&routes, &[], &HashMap::new(), "https://host");
        assert!(plans.is_empty());
    }
}
