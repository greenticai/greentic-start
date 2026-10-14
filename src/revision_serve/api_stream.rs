//! The API channel's SSE route on the revision path.
//!
//! `GET .../conversations/{id}/stream` on a route owned by a `messaging.api`
//! provider. The route is resolved, the conversation pinned and the provider's
//! config read exactly as the Direct Line WebSocket upgrade does; what differs
//! is the credential: the provider verifies the caller's API key (this host
//! holds no copy of it), through a request it answers with `401` for a bad key.

use super::{ServeState, error_response, header_str};
use crate::api_channel::event::{POLL_EVENTS_OP, PollEventsRequest, PollEventsResponse};
use crate::api_channel::limits;
use crate::api_channel::source::{ApiChannelBackend, BackendError};
use crate::api_channel::sse::{ApiChannelState, SseBody, SseConfig, StreamRequest, handle_stream};
use crate::http_routes::RevisionScope;
use crate::operator_log;
use async_trait::async_trait;
use greentic_deploy_spec::ids::{BundleId, DeploymentId, RevisionId};
use greentic_runner_host::RunnerHost;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode, header};
use serde_json::{Value, json};
use std::sync::Arc;

/// The provider type of the `messaging-api` pack.
pub(super) const API_PROVIDER_TYPE: &str = "messaging.api";

/// Is this request for the API channel's stream? Path shape only; the provider
/// route check happens when the request is served.
pub(super) fn is_api_stream_request(method: &hyper::Method, path: &str) -> bool {
    method == hyper::Method::GET && crate::api_channel::stream_conversation_id(path).is_some()
}

struct RevisionApiBackend {
    host: Arc<RunnerHost>,
    deployment_id: DeploymentId,
    bundle_id: BundleId,
    revision_id: RevisionId,
    tenant: String,
    team: String,
    /// The caller's bearer token, forwarded to the provider. Never logged.
    bearer: String,
    path: String,
    config: Option<Value>,
}

impl RevisionApiBackend {
    async fn invoke(&self, op: &str, input: Vec<u8>) -> Result<Value, BackendError> {
        self.host
            .invoke_provider_for_revision(
                &self.tenant,
                self.deployment_id,
                self.bundle_id.clone(),
                self.revision_id,
                API_PROVIDER_TYPE,
                op,
                input,
                None,
                None,
            )
            .await
            .map_err(|_| {
                // The error text can carry provider output; log only the op.
                operator_log::warn(
                    module_path!(),
                    format!("[api-channel] provider op {op} failed"),
                );
                BackendError::Unavailable
            })
    }
}

#[async_trait]
impl ApiChannelBackend for RevisionApiBackend {
    async fn authorize(&self) -> Result<(), BackendError> {
        // The provider's `ingest_http` verifies the bearer before anything
        // else and answers `401` for a wrong or missing key.
        let payload = json!({
            "v": 1,
            "provider": API_PROVIDER_TYPE,
            "route": Value::Null,
            "binding_id": Value::Null,
            "tenant_hint": self.tenant,
            "team_hint": self.team,
            "method": "GET",
            "path": self.path,
            "query": "",
            "headers": [["Authorization", format!("Bearer {}", self.bearer)]],
            "body_b64": "",
            "config": self.config.clone().unwrap_or(Value::Null),
        });
        let input = serde_json::to_vec(&payload).map_err(|_| BackendError::Unavailable)?;
        let output = match self.invoke("ingest-http", input.clone()).await {
            Ok(v) => v,
            Err(_) => self.invoke("ingest_http", input).await?,
        };
        let status = output.get("status").and_then(Value::as_u64).unwrap_or(200);
        match status {
            200..=299 => Ok(()),
            401 | 403 => Err(BackendError::Unauthorized),
            404 => Err(BackendError::NotFound),
            _ => Err(BackendError::Unavailable),
        }
    }

    async fn poll_events(
        &self,
        conversation_id: &str,
        since: u64,
    ) -> Result<PollEventsResponse, BackendError> {
        let request = PollEventsRequest {
            conversation_id: conversation_id.to_string(),
            since,
        };
        let input = serde_json::to_vec(&request).map_err(|_| BackendError::Unavailable)?;
        let output = self.invoke(POLL_EVENTS_OP, input).await?;
        serde_json::from_value(output).map_err(|_| BackendError::Unavailable)
    }
}

fn bearer_token(headers: &hyper::HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim().to_string())
        .filter(|t| !t.is_empty())
}

fn boxed(response: Response<http_body_util::Full<hyper::body::Bytes>>) -> Response<SseBody> {
    response.map(|body| body.boxed())
}

/// Serve one API-channel stream request.
pub(super) async fn handle_api_stream(
    req: Request<Incoming>,
    path: &str,
    state: Arc<ServeState>,
) -> Response<SseBody> {
    let Some(conversation_id) = crate::api_channel::stream_conversation_id(path) else {
        return boxed(error_response(StatusCode::NOT_FOUND, "invalid stream path"));
    };
    let activation = state.current();
    let host_header = header_str(req.headers(), header::HOST.as_str());

    let Some((deployment_id, tenant)) = activation
        .routing
        .deployment_routes
        .resolve(host_header.as_deref(), path)
        .map(|(deployment_id, tenant)| (deployment_id, tenant.to_string()))
    else {
        return boxed(error_response(
            StatusCode::NOT_FOUND,
            "no deployment is bound here",
        ));
    };
    let is_api_route = activation
        .routing
        .http_routes
        .provider_type_for(path, "GET", deployment_id)
        == Some(API_PROVIDER_TYPE);
    if !is_api_route {
        return boxed(error_response(
            StatusCode::NOT_FOUND,
            "no API channel route matches",
        ));
    }

    // Everything below acts for the bearer's holder only after the provider
    // accepts it (`handle_stream` authorizes first), but the pin and config
    // reads are cheap and credential-independent, so they come first.
    let team = "default";
    let session_hint = format!("api:{conversation_id}");
    let mut rng: rand::rngs::SmallRng = rand::make_rng();
    let Some((bundle_id, revision_id)) = activation
        .routing
        .dispatcher
        .establish_pin(&tenant, deployment_id, &session_hint, &mut rng)
        .await
    else {
        return boxed(error_response(
            StatusCode::NOT_FOUND,
            "no revision is available to serve this conversation",
        ));
    };

    let revision_scope = RevisionScope {
        deployment_id,
        bundle_id: bundle_id.clone(),
        revision_id,
    };
    let provider_pack = activation
        .routing
        .http_routes
        .match_request_for_revision(path, "GET", &revision_scope)
        .map(|route| {
            crate::revision_provider_config::RevisionProviderPack::from_descriptor(route.descriptor)
        });
    let config = match provider_pack {
        Some(pack) => match crate::revision_provider_config::resolve_revision_provider_config(
            &activation.host.secrets_manager(),
            pack,
            &tenant,
            Some(team),
        )
        .await
        {
            Ok(config) => config,
            Err(err) => {
                operator_log::error(
                    module_path!(),
                    format!("could not resolve config for the API channel provider: {err:#}"),
                );
                return boxed(error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "provider config could not be resolved",
                ));
            }
        },
        None => None,
    };

    let bearer = bearer_token(req.headers());
    let last_event_id = header_str(req.headers(), "last-event-id");
    let backend = Arc::new(RevisionApiBackend {
        host: Arc::clone(&activation.host),
        deployment_id,
        bundle_id,
        revision_id,
        tenant: tenant.clone(),
        team: team.to_string(),
        bearer: bearer.clone().unwrap_or_default(),
        path: path.to_string(),
        config,
    });
    let stream_state = ApiChannelState {
        notifier: Arc::clone(&state.notifier),
        limits: limits::shared(),
        config: SseConfig::default(),
    };
    handle_stream(
        StreamRequest {
            tenant_id: tenant,
            conversation_id,
            bearer,
            last_event_id,
        },
        backend,
        &stream_state,
    )
    .await
}
