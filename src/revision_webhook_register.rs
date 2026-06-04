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
//! Runs at boot and after every config reload (hot-attach) — see
//! [`rebuild_with_registration`].

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use greentic_deploy_spec::{DeploymentId, Environment, MessagingEndpoint};
use serde_json::{Value, json};

use crate::http_routes::{HttpRouteDescriptor, INGEST_HTTP_OP, derive_provider_name};
use crate::operator_log;
use crate::revision_serve::Activation;

/// Provider op that performs the external webhook registration.
const SETUP_WEBHOOK_OP: &str = "setup_webhook";

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
}

impl WebhookRegistration {
    fn payload(&self) -> Vec<u8> {
        let mut body = json!({ "webhook_url": self.webhook_url });
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
        match activation
            .host
            .invoke_provider_for_revision(
                &plan.tenant,
                plan.deployment_id,
                plan.bundle_id.clone(),
                plan.revision_id,
                &plan.provider_type,
                SETUP_WEBHOOK_OP,
                plan.payload(),
                None,
                None,
            )
            .await
        {
            Ok(output) => {
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
            Err(err) => {
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

        // The endpoint that links this bundle for this provider supplies the
        // IID secret_token. Matched on the canonical provider name so the
        // route's descriptor type (`messaging.telegram`) and the endpoint's
        // class (`telegram`) reconcile.
        let secret_token = endpoints
            .iter()
            .find(|e| {
                e.linked_bundles.iter().any(|b| b == &scope.bundle_id)
                    && derive_provider_name(&e.provider_type).as_deref() == Some(name.as_str())
            })
            .map(|e| e.provider_id.clone());

        plans.push(WebhookRegistration {
            tenant: tenant.clone(),
            deployment_id: scope.deployment_id,
            bundle_id: scope.bundle_id.clone(),
            revision_id: scope.revision_id,
            provider_type: provider_type.to_string(),
            provider_name: name,
            webhook_url: format!("{base}{}", route.pattern),
            secret_token,
        });
    }

    plans
}

/// Wrap a rebuild closure so a successful reload (`Ok(Some(activation))`, i.e.
/// the config actually changed) re-registers webhooks against the new
/// activation. Idempotent for unchanged paths; covers hot-attached deployments.
pub(crate) fn rebuild_with_registration<R>(
    mut base_rebuild: R,
    store_root: PathBuf,
    env_id: String,
    public_base_url: Option<String>,
    rt: tokio::runtime::Handle,
) -> impl FnMut() -> Result<Option<Activation>> + Send + 'static
where
    R: FnMut() -> Result<Option<Activation>> + Send + 'static,
{
    move || {
        let result = base_rebuild()?;
        if let Some(activation) = result.as_ref() {
            match load_environment(&store_root, &env_id) {
                Ok(env) => {
                    rt.block_on(register_new_model_webhooks(
                        activation,
                        &env,
                        public_base_url.as_deref(),
                    ));
                }
                Err(err) => {
                    operator_log::warn(
                        module_path!(),
                        format!(
                            "skipping webhook re-registration after reload: \
                             cannot load environment `{env_id}`: {err:#}"
                        ),
                    );
                }
            }
        }
        Ok(result)
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
        let tenants = HashMap::from([(dep, "default".to_string())]);

        let plans = plan_webhook_registrations(&routes, &endpoints, &tenants, "https://host/");
        assert_eq!(plans.len(), 1);
        let p = &plans[0];
        assert_eq!(p.webhook_url, "https://host/bot/webhook/telegram");
        assert_eq!(p.secret_token.as_deref(), Some("tg-secret-token"));
        assert_eq!(p.tenant, "default");
        assert_eq!(p.provider_type, "messaging.telegram");
        // payload carries both fields
        let body: Value = serde_json::from_slice(&p.payload()).unwrap();
        assert_eq!(body["webhook_url"], "https://host/bot/webhook/telegram");
        assert_eq!(body["secret_token"], "tg-secret-token");
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
