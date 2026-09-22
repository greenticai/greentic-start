//! `<deployment-prefix>/trigger/<trigger_id>` (contract §6.3.2–§6.3.5, §7.2,
//! §7.3).
//!
//! Order matters and is the contract's: cheap refusals before the body is
//! read, the size limit before verification, verification before anything
//! that costs a flow run. An unauthenticated flood therefore costs a hash, not
//! an LLM call. Every refusal is a bare status — the route is public, and a
//! detailed error is a free probe of the configuration.
//!
//! A verification failure NEVER runs the flow (§7.3, decision D3).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use greentic_deploy_spec::DeploymentId;
use greentic_runner_host::RunnerHost;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Bytes};
use hyper::{Request, Response, StatusCode, header};
use tokio::sync::OwnedSemaphorePermit;

use super::dispatch::{self, Firing};
use super::field_ref::RequestView;
use super::schema::{Challenge, TriggerKind, Verify, WebhookSpec};
use super::store::{self, TriggerStore};
use super::table::LoadedTrigger;
use super::verify::{self, ChallengeOutcome};
use super::{limits, telemetry};
use crate::deployment_routes::RevisionIngressRouting;
use crate::revision_dispatcher::DispatchRequest;

/// What the trigger paths need from the runner: read a trigger's secret, and
/// start a firing. A trait so the whole refusal order below is tested against
/// a fake — it is the security-critical part of the route, and exercising it
/// must not need a loaded pack.
#[async_trait]
pub(crate) trait TriggerHost: Send + Sync {
    async fn read_secret(
        &self,
        loaded: &LoadedTrigger,
        secret_ref: &str,
    ) -> anyhow::Result<Vec<u8>>;
    /// Start `firing` without waiting for it; `permit` is held until it ends.
    fn spawn_fire(&self, loaded: Arc<LoadedTrigger>, firing: Firing, permit: OwnedSemaphorePermit);
}

/// The production [`TriggerHost`]: the live activation's runner.
pub(crate) struct RunnerTriggerHost(pub Arc<RunnerHost>);

#[async_trait]
impl TriggerHost for RunnerTriggerHost {
    async fn read_secret(
        &self,
        loaded: &LoadedTrigger,
        secret_ref: &str,
    ) -> anyhow::Result<Vec<u8>> {
        dispatch::read_secret(&self.0, loaded, secret_ref).await
    }

    fn spawn_fire(&self, loaded: Arc<LoadedTrigger>, firing: Firing, permit: OwnedSemaphorePermit) {
        let host = Arc::clone(&self.0);
        let kind = loaded.spec.kind.name();
        tokio::spawn(async move {
            let _permit = permit;
            match dispatch::fire(&host, &loaded, firing).await {
                Ok(()) => telemetry::record(&loaded, "fired", kind),
                Err(err) => {
                    crate::operator_log::warn(
                        module_path!(),
                        format!(
                            "trigger `{}` firing failed: {err:#}",
                            loaded.spec.trigger_id
                        ),
                    );
                    telemetry::record(&loaded, "failed", kind);
                }
            }
        });
    }
}

/// Serve one request to a trigger route: pick the revision, then
/// [`handle_selected`].
pub(crate) async fn handle<B>(
    req: Request<B>,
    host: Arc<RunnerHost>,
    routing: Arc<RevisionIngressRouting>,
    store: Arc<dyn TriggerStore>,
    deployment_id: DeploymentId,
    tenant: &str,
    trigger_id: &str,
) -> Response<Full<Bytes>>
where
    B: Body<Data = Bytes> + Send,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let env = routing.dispatcher.env_id().to_string();
    let Some(loaded) = select(&routing, &env, deployment_id, tenant, trigger_id).await else {
        return status(StatusCode::NOT_FOUND);
    };
    handle_selected(req, &RunnerTriggerHost(host), store.as_ref(), &env, loaded).await
}

/// Everything after the revision is picked.
pub(crate) async fn handle_selected<B>(
    req: Request<B>,
    host: &dyn TriggerHost,
    store: &dyn TriggerStore,
    env: &str,
    loaded: Arc<LoadedTrigger>,
) -> Response<Full<Bytes>>
where
    B: Body<Data = Bytes> + Send,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let TriggerKind::Webhook(spec) = &loaded.spec.kind else {
        return status(StatusCode::NOT_FOUND);
    };
    if !loaded.spec.enabled {
        telemetry::record(&loaded, "skipped", "disabled");
        return status(StatusCode::NOT_FOUND);
    }
    if loaded.unavailable.is_some() {
        telemetry::record(&loaded, "skipped", "unavailable");
        return status(StatusCode::SERVICE_UNAVAILABLE);
    }

    let method = req.method().as_str().to_ascii_uppercase();
    let query = parse_query(req.uri().query());
    let headers = collect_headers(req.headers());

    // The subscription handshake owns GET whenever a challenge is declared.
    if method == "GET"
        && let Some(Challenge::MetaHub { verify_token_ref }) = &spec.challenge
    {
        return challenge(host, &loaded, verify_token_ref, &query).await;
    }
    if !spec.methods.iter().any(|m| m == &method) {
        return status(StatusCode::METHOD_NOT_ALLOWED);
    }

    let body = match Limited::new(req.into_body(), spec.max_body_bytes)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            telemetry::audit_rejection(&loaded, "body_too_large");
            return status(StatusCode::PAYLOAD_TOO_LARGE);
        }
    };

    if let Err(response) = verify_request(host, &loaded, spec, &headers, &body).await {
        return response;
    }

    let body_json: Option<serde_json::Value> = serde_json::from_slice(&body).ok();
    let view = RequestView {
        headers: &headers,
        query: &query,
        body: body_json.as_ref(),
    };

    if let Some(idem) = &spec.idempotency {
        match idem.key.resolve(&view) {
            Some(delivery_key) => {
                let key = store::key(
                    "seen",
                    env,
                    &loaded.scope.deployment_id.to_string(),
                    &loaded.spec.trigger_id,
                    &delivery_key,
                );
                match store.claim(&key, Duration::from_secs(idem.ttl_s)).await {
                    Ok(true) => {}
                    Ok(false) => {
                        telemetry::record(&loaded, "deduplicated", "idempotency");
                        return status(StatusCode::OK);
                    }
                    // At-least-once beats at-most-once for an inbound event:
                    // a store outage must not drop deliveries on the floor.
                    Err(err) => crate::operator_log::warn(
                        module_path!(),
                        format!(
                            "trigger `{}`: idempotency store unavailable ({err:#}); firing \
                             without deduplication",
                            loaded.spec.trigger_id
                        ),
                    ),
                }
            }
            None => crate::operator_log::warn(
                module_path!(),
                format!(
                    "trigger `{}`: delivery had no identity (idempotency key did not \
                     resolve); firing without deduplication",
                    loaded.spec.trigger_id
                ),
            ),
        }
    }

    if !limits::within_budget(store, env, &loaded).await {
        telemetry::record(&loaded, "skipped", "budget");
        return too_many();
    }
    let Some(permit) = limits::try_acquire(&loaded) else {
        telemetry::record(&loaded, "skipped", "overlap");
        return too_many();
    };

    let firing_id = dispatch::new_firing_id();
    let firing = Firing {
        session_hint: dispatch::session_hint(&loaded.spec, &firing_id, Some(&view)),
        payload: dispatch::webhook_payload(
            &loaded.spec,
            &firing_id,
            Utc::now(),
            &method,
            &view,
            &body,
        ),
        firing_id,
    };
    // Answer once the firing is accepted, not when the flow ends: senders
    // (Meta included) retry or disable a subscription that answers slowly.
    host.spawn_fire(loaded, firing, permit);
    status(StatusCode::OK)
}

/// The declaration of the revision the traffic split picks. `None` when no
/// revision serves the deployment, or the picked one does not declare this
/// trigger — both are "no such endpoint here", i.e. 404.
async fn select(
    routing: &RevisionIngressRouting,
    env: &str,
    deployment_id: DeploymentId,
    tenant: &str,
    trigger_id: &str,
) -> Option<Arc<LoadedTrigger>> {
    let request = DispatchRequest {
        env_id: env,
        tenant,
        deployment_id,
        session_hint: None,
        defer_pin: true,
        trusted: false,
        header_revision: None,
        cookie: None,
    };
    let mut rng: rand::rngs::SmallRng = rand::make_rng();
    let outcome = routing.dispatcher.dispatch(&request, &mut rng).await.ok()?;
    routing
        .triggers
        .for_revision(deployment_id, outcome.revision_id, trigger_id)
}

async fn challenge(
    host: &dyn TriggerHost,
    loaded: &LoadedTrigger,
    verify_token_ref: &str,
    query: &[(String, String)],
) -> Response<Full<Bytes>> {
    let Ok(token) = host.read_secret(loaded, verify_token_ref).await else {
        telemetry::audit_rejection(loaded, "secret_unavailable");
        return status(StatusCode::SERVICE_UNAVAILABLE);
    };
    match verify::meta_hub_challenge(query, &token) {
        ChallengeOutcome::Echo(value) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from(value)))
            .unwrap_or_else(|_| status(StatusCode::INTERNAL_SERVER_ERROR)),
        ChallengeOutcome::Forbidden => {
            telemetry::audit_rejection(loaded, "challenge_token");
            status(StatusCode::FORBIDDEN)
        }
        ChallengeOutcome::NotAChallenge => status(StatusCode::METHOD_NOT_ALLOWED),
    }
}

/// `Err` carries the response to send. A secret that cannot be read is a 503,
/// never a fall-through to "unverified": failing open on a missing secret would
/// publish an unauthenticated endpoint (§8).
async fn verify_request(
    host: &dyn TriggerHost,
    loaded: &LoadedTrigger,
    spec: &WebhookSpec,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(), Response<Full<Bytes>>> {
    let header_value = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    let outcome = match &spec.verify {
        Verify::None => return Ok(()),
        Verify::Hmac {
            algo,
            header,
            prefix,
            encoding,
            secret_ref,
        } => {
            let secret = read(host, loaded, secret_ref).await?;
            verify::verify_hmac(algo, &secret, body, header_value(header), prefix, encoding)
        }
        Verify::Bearer { header, secret_ref } => {
            let secret = read(host, loaded, secret_ref).await?;
            verify::verify_bearer(header, &secret, header_value(header))
        }
    };
    outcome.map_err(|_| {
        telemetry::audit_rejection(loaded, "verification");
        status(StatusCode::UNAUTHORIZED)
    })
}

async fn read(
    host: &dyn TriggerHost,
    loaded: &LoadedTrigger,
    secret_ref: &str,
) -> Result<Vec<u8>, Response<Full<Bytes>>> {
    host.read_secret(loaded, secret_ref).await.map_err(|err| {
        crate::operator_log::warn(
            module_path!(),
            format!("trigger `{}` refused: {err:#}", loaded.spec.trigger_id),
        );
        telemetry::audit_rejection(loaded, "secret_unavailable");
        status(StatusCode::SERVICE_UNAVAILABLE)
    })
}

fn collect_headers(headers: &header::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_string(), v.to_string()))
        })
        .collect()
}

/// `application/x-www-form-urlencoded` query decoding, `+` as space.
pub(crate) fn parse_query(query: Option<&str>) -> Vec<(String, String)> {
    let Some(query) = query else {
        return Vec::new();
    };
    let decode = |s: &str| {
        let spaced = s.replace('+', " ");
        urlencoding::decode(&spaced)
            .map(|c| c.into_owned())
            .unwrap_or(spaced)
    };
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (decode(k), decode(v)),
            None => (decode(pair), String::new()),
        })
        .collect()
}

fn status(code: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(code)
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

fn too_many() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(header::RETRY_AFTER, "5")
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| status(StatusCode::TOO_MANY_REQUESTS))
}

#[cfg(test)]
#[path = "webhook_tests.rs"]
mod tests;
