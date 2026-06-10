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
//! Gated on a resolved public base URL — a tunnel started by the boot
//! (`--cloudflared on` / `--ngrok on`, see `env_tunnel`), else the env-store
//! `public_base_url`, else the `PUBLIC_BASE_URL` env var. With none,
//! registration is skipped (register manually, e.g. via `curl`).
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
use futures_util::future::join_all;
use greentic_deploy_spec::{DeploymentId, Environment, MessagingEndpoint, SecretRef};
use serde_json::{Value, json};

use crate::http_routes::{HttpRouteDescriptor, INGEST_HTTP_OP, derive_provider_name};
use crate::operator_log;
use crate::revision_serve::Activation;
use crate::secrets_gate::DynSecretsManager;
use crate::webhook_secret_resolver::secret_ref_to_store_uri;

/// Provider op that performs the external webhook registration.
const SETUP_WEBHOOK_OP: &str = "setup_webhook";

/// Upper bound per `setup_webhook` invocation. Bounds async waits inside the
/// host; a provider stuck in a blocking in-component HTTP call is additionally
/// bounded by the host HTTP client's own timeouts.
const SETUP_WEBHOOK_TIMEOUT: Duration = Duration::from_secs(30);

/// Source of the IID `secret_token` planted by [`SETUP_WEBHOOK_OP`] on the
/// provider side. The dispatcher's auth gate constant-time compares the
/// inbound provider header against the same value, so the source choice here
/// determines which posture the endpoint runs in:
///
/// - [`SecretTokenSource::WebhookSecretRef`] — endpoint's
///   [`MessagingEndpoint::webhook_secret_ref`] resolves to a high-entropy
///   per-endpoint value. Decouples auth from routing identity.
/// - [`SecretTokenSource::ProviderIdFallback`] — endpoint has no ref; the
///   legacy posture uses `provider_id` as both routing discriminator AND
///   authenticator. Kept for envs that haven't been re-deployed since
///   PR #246 added `webhook_secret_ref`.
/// - [`SecretTokenSource::None`] — no endpoint links this bundle (single
///   bundle, no IID at all). Webhook registers URL-only.
#[derive(Debug, Clone, PartialEq)]
enum SecretTokenSource {
    WebhookSecretRef(SecretRef),
    ProviderIdFallback(String),
    None,
}

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
    /// IID `secret_token` source — resolved at invocation time (see
    /// [`SecretTokenSource`]). A ref-backed token is read through the env's
    /// secrets backend per-call so a value rotated on disk is picked up on the
    /// next reload-driven re-registration.
    secret_token_source: SecretTokenSource,
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
    fn payload(&self, resolved_secret_token: Option<&str>) -> Vec<u8> {
        let mut body = json!({
            "webhook_url": self.webhook_url,
            "tenant": self.tenant,
            "provider_instance_id": self.instance_id,
        });
        if let Some(token) = resolved_secret_token {
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

    let secrets = activation.host.secrets_manager();

    // Plans are independent — different `(deployment, provider)` tuples with
    // no shared state. Run them concurrently so N providers don't add
    // N × SETUP_WEBHOOK_TIMEOUT to boot/reload latency. `join_all` runs each
    // plan-future on the current task without spawning, keeping log ordering
    // attached to this caller's tracing context.
    join_all(
        plans
            .into_iter()
            .map(|plan| register_one(activation, &secrets, plan)),
    )
    .await;
}

/// Resolve + invoke `setup_webhook` for a single plan. Errors are logged here
/// and never bubble out — registration is best-effort, the next reload retries.
async fn register_one(
    activation: &Activation,
    secrets: &DynSecretsManager,
    plan: WebhookRegistration,
) {
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
    let resolved_token = resolve_secret_token_source(&plan, secrets).await;
    let token_value = match resolved_token {
        ResolvedSecretToken::Ready(ref v) => v.as_deref(),
        ResolvedSecretToken::Unresolved => {
            // The endpoint declared a webhook_secret_ref but the secrets
            // backend couldn't resolve it. SKIP registration entirely:
            // invoking setup_webhook URL-only would mutate the provider
            // to stop sending the secret-token header, while the auth
            // gate still enforces the ref → 401 on every delivery.
            // The provider's existing config stays intact until the next
            // reload successfully resolves the value.
            operator_log::warn(
                module_path!(),
                format!(
                    "skipping webhook registration for provider={} url={} deployment={}: \
                     webhook_secret_ref could not be resolved \
                     (provider keeps existing config until next reload)",
                    plan.provider_name, plan.webhook_url, plan.deployment_id,
                ),
            );
            return;
        }
    };
    let payload = plan.payload(token_value);
    let invoke = activation.host.invoke_provider_for_revision(
        &plan.tenant,
        plan.deployment_id,
        plan.bundle_id.clone(),
        plan.revision_id,
        &plan.provider_type,
        SETUP_WEBHOOK_OP,
        payload,
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
                let token_source = match &plan.secret_token_source {
                    SecretTokenSource::WebhookSecretRef(_) => "webhook_secret_ref",
                    SecretTokenSource::ProviderIdFallback(_) => "provider_id",
                    SecretTokenSource::None => "none",
                };
                operator_log::info(
                    module_path!(),
                    format!(
                        "webhook registered: provider={} url={} deployment={} \
                         secret_token={} token_source={token_source}",
                        plan.provider_name,
                        plan.webhook_url,
                        plan.deployment_id,
                        token_value.is_some(),
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

/// Outcome of resolving a plan's [`SecretTokenSource`] at invocation time.
///
/// Distinguishes "we deliberately have no secret_token (URL-only is correct)"
/// from "we expected a secret_token but couldn't resolve it". The caller MUST
/// skip `setup_webhook` on [`ResolvedSecretToken::Unresolved`]: invoking it
/// URL-only would mutate the provider to stop sending the secret-token header,
/// while the auth gate in `provider_auth.rs` still enforces the ref — every
/// legitimate delivery would be rejected with 401 until a later successful
/// re-registration.
#[derive(Debug, Clone, PartialEq)]
enum ResolvedSecretToken {
    /// Secret token resolved (or deliberately absent). Safe to invoke
    /// `setup_webhook` with `value.as_deref()`.
    Ready(Option<String>),
    /// A `WebhookSecretRef` was present but the secrets backend failed to
    /// resolve it (read error or non-UTF8). The caller MUST skip registration
    /// for this plan — the provider's existing webhook config stays intact
    /// until the next reload picks up the resolved value.
    Unresolved,
}

/// Resolve a plan's [`SecretTokenSource`] into the actual on-wire value at
/// invocation time. `WebhookSecretRef` reads the dev-store backend; a read
/// failure returns [`ResolvedSecretToken::Unresolved`] so the caller skips
/// registration rather than mutating the provider to a URL-only posture that
/// the auth gate will reject. We never fall back to the legacy `provider_id`
/// token, because mixing the two postures would silently break the
/// dispatcher's auth gate (it would expect the new secret while the provider
/// sends the old one).
async fn resolve_secret_token_source(
    plan: &WebhookRegistration,
    secrets: &DynSecretsManager,
) -> ResolvedSecretToken {
    match &plan.secret_token_source {
        SecretTokenSource::None => ResolvedSecretToken::Ready(None),
        SecretTokenSource::ProviderIdFallback(value) => {
            ResolvedSecretToken::Ready(Some(value.clone()))
        }
        SecretTokenSource::WebhookSecretRef(secret_ref) => {
            let uri = secret_ref_to_store_uri(secret_ref);
            match secrets.read(&uri).await {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(value) => ResolvedSecretToken::Ready(Some(value)),
                    Err(_) => {
                        operator_log::warn(
                            module_path!(),
                            format!(
                                "webhook secret at `{uri}` is not valid UTF-8; \
                                 skipping registration for provider={} url={} \
                                 (provider keeps existing webhook config until next reload)",
                                plan.provider_name, plan.webhook_url
                            ),
                        );
                        ResolvedSecretToken::Unresolved
                    }
                },
                Err(err) => {
                    operator_log::warn(
                        module_path!(),
                        format!(
                            "could not resolve webhook secret at `{uri}`: {err}; \
                             skipping registration for provider={} url={} \
                             (provider keeps existing webhook config until next reload)",
                            plan.provider_name, plan.webhook_url
                        ),
                    );
                    ResolvedSecretToken::Unresolved
                }
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
        // Prefer the explicit per-endpoint webhook_secret_ref over the legacy
        // `provider_id` token. Falling back to `provider_id` keeps envs that
        // were deployed before PR #246 (added the field) on the existing
        // posture; mixed envs work because each endpoint resolves
        // independently.
        let secret_token_source = match matching.first() {
            None => SecretTokenSource::None,
            Some(ep) => match &ep.webhook_secret_ref {
                Some(ref_) => SecretTokenSource::WebhookSecretRef(ref_.clone()),
                None => SecretTokenSource::ProviderIdFallback(ep.provider_id.clone()),
            },
        };
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
            secret_token_source,
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
///
/// URL precedence per reload: `tunnel_url` (a tunnel started by this boot —
/// process-local, never persisted) wins; otherwise the URL is resolved
/// freshly from the just-loaded `environment.json`, with a fallback to the
/// `PUBLIC_BASE_URL` env var. The fresh resolve ensures that
/// `gtc op env set-public-url <NEW>` takes effect on the next reload without
/// a process restart (when no tunnel is running).
pub(crate) fn post_reload_registration(
    store_root: PathBuf,
    env_id: String,
    rt: tokio::runtime::Handle,
    tunnel_url: Option<String>,
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
        let public_base_url = reload_public_base_url(tunnel_url.as_deref(), &env);
        let activation = activation.clone();
        rt.spawn(async move {
            register_new_model_webhooks(&activation, &env, public_base_url.as_deref()).await;
        });
    }
}

/// Per-reload URL precedence: a boot-started tunnel (process-local) wins,
/// else the freshly-loaded environment / env var via
/// [`resolve_public_base_url_for_reload`].
fn reload_public_base_url(tunnel_url: Option<&str>, env: &Environment) -> Option<String> {
    tunnel_url
        .map(str::to_string)
        .or_else(|| resolve_public_base_url_for_reload(env))
}

/// Resolve the public base URL from a freshly-loaded environment, with a
/// fallback to the `PUBLIC_BASE_URL` env var. Delegates to the canonical
/// helper in `startup_contract` and discards any error via `.ok().flatten()` —
/// the watcher is intentionally fail-soft (see header in `revision_reload`),
/// so a malformed env var is treated as "no URL" rather than failing the
/// reload. The boot path in `lib.rs` calls the same helper and propagates.
fn resolve_public_base_url_for_reload(env: &Environment) -> Option<String> {
    crate::startup_contract::resolve_public_base_url(env)
        .ok()
        .flatten()
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
    use crate::test_fixtures::{
        FakeSecrets, endpoint_typed as endpoint, env_with, telegram_endpoint_with_webhook_secret,
    };
    use greentic_deploy_spec::{BundleId, DeploymentId, RevisionId};

    fn scope(deployment: DeploymentId, bundle: &str, revision: RevisionId) -> RevisionScope {
        RevisionScope {
            deployment_id: deployment,
            bundle_id: BundleId::new(bundle),
            revision_id: revision,
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
        // Legacy posture: endpoint has NO webhook_secret_ref → planner uses
        // `provider_id` as the IID token (back-compat).
        let endpoints = vec![endpoint("telegram", "tg-secret-token", &["realbot-pack"])];
        let eid = endpoints[0].endpoint_id.to_string();
        let tenants = HashMap::from([(dep, "default".to_string())]);

        let plans = plan_webhook_registrations(&routes, &endpoints, &tenants, "https://host/");
        assert_eq!(plans.len(), 1);
        let p = &plans[0];
        assert_eq!(p.webhook_url, "https://host/bot/webhook/telegram");
        assert!(matches!(
            &p.secret_token_source,
            SecretTokenSource::ProviderIdFallback(s) if s == "tg-secret-token"
        ));
        assert_eq!(p.tenant, "default");
        assert_eq!(p.provider_type, "messaging.telegram");
        let body: Value = serde_json::from_slice(&p.payload(Some("tg-secret-token"))).unwrap();
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
        assert_eq!(plans[0].secret_token_source, SecretTokenSource::None);
        let body: Value = serde_json::from_slice(&plans[0].payload(None)).unwrap();
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
        assert!(matches!(
            &plans[0].secret_token_source,
            SecretTokenSource::ProviderIdFallback(s) if s == "tok-a"
        ));
        assert_eq!(
            plans[0].extra_endpoints, 1,
            "second endpoint counted as extra"
        );
    }

    fn plan_with_source(source: SecretTokenSource) -> WebhookRegistration {
        WebhookRegistration {
            tenant: "default".to_string(),
            deployment_id: DeploymentId::new(),
            bundle_id: BundleId::new("p"),
            revision_id: RevisionId::new(),
            provider_type: "messaging.telegram".to_string(),
            provider_name: "telegram".to_string(),
            webhook_url: "https://host/bot/webhook/telegram".to_string(),
            secret_token_source: source,
            instance_id: "instance".to_string(),
            extra_endpoints: 0,
        }
    }

    #[tokio::test]
    async fn resolves_webhook_secret_ref_through_secrets_manager() {
        let ref_ =
            SecretRef::try_new("secret://local/default/_/messaging-abc/webhook_secret".to_string())
                .unwrap();
        let uri = crate::webhook_secret_resolver::secret_ref_to_store_uri(&ref_);
        let secrets: DynSecretsManager = std::sync::Arc::new(FakeSecrets(HashMap::from([(
            uri,
            b"resolved-value".to_vec(),
        )])));
        let plan = plan_with_source(SecretTokenSource::WebhookSecretRef(ref_));
        assert_eq!(
            resolve_secret_token_source(&plan, &secrets).await,
            ResolvedSecretToken::Ready(Some("resolved-value".to_string()))
        );
    }

    #[tokio::test]
    async fn resolves_provider_id_fallback_inline() {
        let secrets: DynSecretsManager = std::sync::Arc::new(FakeSecrets(HashMap::new()));
        let plan = plan_with_source(SecretTokenSource::ProviderIdFallback(
            "legacy-tok".to_string(),
        ));
        assert_eq!(
            resolve_secret_token_source(&plan, &secrets).await,
            ResolvedSecretToken::Ready(Some("legacy-tok".to_string()))
        );
    }

    #[tokio::test]
    async fn missing_webhook_secret_returns_unresolved_so_caller_skips_setup_webhook() {
        // Source is WebhookSecretRef but the store has nothing at that URI:
        // the resolver returns Unresolved so the caller skips `setup_webhook`
        // entirely. Invoking URL-only would mutate the provider to stop
        // sending the secret-token header, while the auth gate still enforces
        // the ref — every delivery would be rejected with 401. Falling back
        // to `provider_id` would silently break the auth gate too, which
        // expects the new value.
        let ref_ = SecretRef::try_new(
            "secret://local/default/_/messaging-missing/webhook_secret".to_string(),
        )
        .unwrap();
        let secrets: DynSecretsManager = std::sync::Arc::new(FakeSecrets(HashMap::new()));
        let plan = plan_with_source(SecretTokenSource::WebhookSecretRef(ref_));
        assert_eq!(
            resolve_secret_token_source(&plan, &secrets).await,
            ResolvedSecretToken::Unresolved
        );
    }

    #[tokio::test]
    async fn non_utf8_webhook_secret_returns_unresolved_so_caller_skips_setup_webhook() {
        // The secrets backend returns raw bytes that aren't valid UTF-8.
        // Same safety invariant as a missing secret: the caller MUST skip
        // `setup_webhook` rather than registering URL-only, which would
        // mutate the provider to stop sending the secret-token header while
        // the auth gate still enforces the ref.
        let ref_ =
            SecretRef::try_new("secret://local/default/_/messaging-bad/webhook_secret".to_string())
                .unwrap();
        let uri = crate::webhook_secret_resolver::secret_ref_to_store_uri(&ref_);
        let secrets: DynSecretsManager = std::sync::Arc::new(FakeSecrets(HashMap::from([(
            uri,
            vec![0xFF, 0xFE, 0x00], // invalid UTF-8
        )])));
        let plan = plan_with_source(SecretTokenSource::WebhookSecretRef(ref_));
        assert_eq!(
            resolve_secret_token_source(&plan, &secrets).await,
            ResolvedSecretToken::Unresolved
        );
    }

    #[tokio::test]
    async fn no_endpoint_source_resolves_to_ready_none() {
        // SecretTokenSource::None means no endpoint links this bundle (single
        // bundle, no IID). The resolver returns Ready(None) — URL-only
        // registration is deliberately correct, not a resolution failure.
        let secrets: DynSecretsManager = std::sync::Arc::new(FakeSecrets(HashMap::new()));
        let plan = plan_with_source(SecretTokenSource::None);
        assert_eq!(
            resolve_secret_token_source(&plan, &secrets).await,
            ResolvedSecretToken::Ready(None)
        );
    }

    #[test]
    fn prefers_webhook_secret_ref_over_provider_id_when_endpoint_carries_one() {
        // New posture: endpoint with `webhook_secret_ref` set takes priority.
        // The planner emits `WebhookSecretRef(_)`; the async invoker resolves
        // through the env's secrets backend, so the `provider_id` is NOT
        // planted as a fallback (mixing postures would silently break the
        // auth gate).
        let dep = DeploymentId::new();
        let rev = RevisionId::new();
        let routes = vec![provider_descriptor_for_test(
            "/bot/webhook/telegram",
            "messaging.telegram",
            scope(dep, "realbot-pack", rev),
        )];
        let endpoints = vec![telegram_endpoint_with_webhook_secret(
            "tg-legacy-id",
            &["realbot-pack"],
        )];
        let tenants = HashMap::from([(dep, "default".to_string())]);

        let plans = plan_webhook_registrations(&routes, &endpoints, &tenants, "https://host");
        assert_eq!(plans.len(), 1);
        assert!(matches!(
            &plans[0].secret_token_source,
            SecretTokenSource::WebhookSecretRef(_)
        ));
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

    #[test]
    fn resolve_public_base_url_uses_fresh_env_not_captured_boot_value() {
        // Regression: `post_reload_registration` used to capture the boot-time
        // `public_base_url` and reuse it on every reload, ignoring changes
        // written to `environment.json` by `gtc op env set-public-url`. The
        // helper `resolve_public_base_url_for_reload` now reads the URL from
        // the freshly-loaded env on each call.
        let mut env_old = env_with(vec![]);
        env_old.host_config.public_base_url = Some("https://old.example.com".to_string());
        assert_eq!(
            resolve_public_base_url_for_reload(&env_old),
            Some("https://old.example.com".to_string()),
        );

        let mut env_new = env_with(vec![]);
        env_new.host_config.public_base_url = Some("https://new.example.com".to_string());
        assert_eq!(
            resolve_public_base_url_for_reload(&env_new),
            Some("https://new.example.com".to_string()),
            "must reflect the freshly-loaded env, not a stale captured value",
        );
    }

    #[test]
    fn reload_url_precedence_tunnel_wins_over_env_store() {
        let mut env = env_with(vec![]);
        env.host_config.public_base_url = Some("https://persisted.example.com".to_string());

        assert_eq!(
            reload_public_base_url(Some("https://live.trycloudflare.com"), &env),
            Some("https://live.trycloudflare.com".to_string()),
            "a boot-started tunnel must win over the persisted env-store URL",
        );
        assert_eq!(
            reload_public_base_url(None, &env),
            Some("https://persisted.example.com".to_string()),
            "without a tunnel the persisted env-store URL applies",
        );
    }
}
