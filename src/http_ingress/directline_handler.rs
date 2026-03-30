use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
};
use serde_json::json;

use crate::domains::Domain;
use crate::ingress_dispatch::dispatch_http_ingress;
use crate::ingress_types::IngressRequestV1;
use crate::operator_log;
use crate::runner_host::{DemoRunnerHost, OperatorContext};

use super::HttpIngressState;
use super::helpers::{collect_queries, error_response, json_response};
use super::messaging::route_messaging_envelopes;

/// Parse WebChat Direct Line routes: /v1/messaging/webchat/{tenant}/token or /v1/messaging/webchat/{tenant}/v3/directline/*
/// Returns (tenant, directline_path) if matched
pub(super) fn parse_webchat_directline_route(path: &str) -> Option<(String, String)> {
    // Pattern: /v1/messaging/webchat/{tenant}/token
    // Pattern: /v1/messaging/webchat/{tenant}/v3/directline/{*path}
    let prefix = "/v1/messaging/webchat/";
    if !path.starts_with(prefix) {
        return None;
    }
    let rest = &path[prefix.len()..];
    let mut parts = rest.splitn(2, '/');
    let tenant = parts.next()?;
    if tenant.is_empty() {
        return None;
    }
    let remainder = parts.next().unwrap_or("");

    // Check if it's a Direct Line or auth config route
    if remainder == "token" {
        Some((tenant.to_string(), "/token".to_string()))
    } else if remainder.starts_with("v3/directline") {
        Some((tenant.to_string(), format!("/{}", remainder)))
    } else if remainder == "auth/config" {
        Some((tenant.to_string(), "/auth/config".to_string()))
    } else {
        None
    }
}

/// Extract conversation ID from DirectLine URL paths.
///
/// - `/v3/directline/conversations/{id}/activities` -> `Some(id)`
/// - `/v3/directline/conversations/{id}`            -> `Some(id)`
/// - `/v3/directline/conversations`                 -> `None`
pub(super) fn parse_directline_conversation_id(path: &str) -> Option<String> {
    let prefix = "/v3/directline/conversations/";
    if !path.starts_with(prefix) {
        return None;
    }
    let rest = &path[prefix.len()..];
    let conv_id = rest.split('/').next().unwrap_or("");
    if conv_id.is_empty() {
        return None;
    }
    Some(conv_id.to_string())
}

pub(super) async fn handle_directline_request(
    req: Request<Incoming>,
    path: &str,
    explicit_tenant: Option<String>,
    state: Arc<HttpIngressState>,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    let method = req.method().clone();
    let query_string = req.uri().query().map(String::from);
    let queries = collect_queries(query_string.as_deref());

    // Use webchat-gui provider for tenant-scoped routes, webchat for legacy
    let is_tenant_scoped = explicit_tenant.is_some();
    let provider = if is_tenant_scoped {
        "messaging-webchat-gui".to_string()
    } else {
        "messaging-webchat".to_string()
    };

    // Use explicit tenant from URL path, or fall back to query param
    let tenant = explicit_tenant.unwrap_or_else(|| {
        queries
            .iter()
            .find(|(k, _)| k == "tenant")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "default".to_string())
    });
    if !state.domains.contains(&Domain::Messaging) {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "messaging domain disabled",
        ));
    }

    // Intercept /token to generate JWT natively
    if path == "/token" {
        return generate_directline_token(&tenant, &provider, &state.runner_host).await;
    }

    // Intercept /auth/config
    if path == "/auth/config" {
        operator_log::debug(
            module_path!(),
            format!("[webchat] auth/config request for tenant={tenant}"),
        );
        return Ok(json_response(StatusCode::OK, json!({})));
    }

    operator_log::info(
        module_path!(),
        format!(
            "[webchat] directline request: method={method} tenant={tenant} path={path} provider={provider}"
        ),
    );

    let dl_state = &state.dl_state;
    let conv_id = parse_directline_conversation_id(path);

    // POST /v3/directline/conversations — create new conversation
    if method == Method::POST && path == "/v3/directline/conversations" {
        let ctx = OperatorContext {
            tenant: tenant.clone(),
            team: Some("default".to_string()),
            correlation_id: None,
        };
        let signing_key = state
            .runner_host
            .get_secret(&provider, "jwt_signing_key", &ctx)
            .map_err(|err| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to fetch jwt_signing_key: {err}"),
                )
            })?
            .ok_or_else(|| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "jwt_signing_key secret not configured",
                )
            })?;
        let body = crate::directline::handle_create_conversation(
            dl_state,
            &tenant,
            "default",
            &signing_key,
        );
        operator_log::info(
            module_path!(),
            format!(
                "[webchat] created conversation id={} tenant={tenant}",
                body["conversationId"]
            ),
        );
        return Ok(json_response(StatusCode::CREATED, body));
    }

    // POST /v3/directline/conversations/{convId}/activities — post user activity
    if method == Method::POST
        && let Some(ref cid) = conv_id
        && path.ends_with("/activities")
    {
        let payload_bytes = req
            .into_body()
            .collect()
            .await
            .map(|collected| collected.to_bytes())
            .unwrap_or_default();

        let body: serde_json::Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| error_response(StatusCode::BAD_REQUEST, format!("invalid json: {e}")))?;

        // 1. Store user activity in DirectLine state
        let activity_result = crate::directline::handle_post_activity(dl_state, cid, &body)
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "conversation not found"))?;

        let activity_id = activity_result["id"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        operator_log::info(
            module_path!(),
            format!("[webchat] stored user activity id={activity_id} conv={cid} tenant={tenant}"),
        );

        // 2. Build an ingress request and route to flow engine so the
        //    messaging pipeline processes the user message. We pass the
        //    original body to dispatch_http_ingress which will parse the
        //    ChannelMessageEnvelope from it.
        let context = OperatorContext {
            tenant: tenant.clone(),
            team: Some("default".to_string()),
            correlation_id: None,
        };

        let ingress_request = IngressRequestV1 {
            v: 1,
            domain: "messaging".to_string(),
            provider: provider.clone(),
            handler: None,
            tenant: tenant.clone(),
            team: Some("default".to_string()),
            method: "POST".to_string(),
            path: format!("/v3/directline/conversations/{cid}/activities"),
            query: queries,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: payload_bytes.to_vec(),
            correlation_id: None,
            remote_addr: None,
        };

        let dl_state_clone = dl_state.clone();
        let conv_id_clone = cid.clone();
        let bundle = state.runner_host.bundle_root().to_path_buf();
        let runner_host = state.runner_host.clone();
        let provider_clone = provider.clone();

        std::thread::spawn(move || {
            // Dispatch to WASM ingress to parse envelopes, then route
            // through the messaging pipeline.
            let result = dispatch_http_ingress(
                runner_host.as_ref(),
                Domain::Messaging,
                &ingress_request,
                &context,
            );

            match result {
                Ok(result) if !result.messaging_envelopes.is_empty() => {
                    if let Err(err) = route_messaging_envelopes(
                        &bundle,
                        &runner_host,
                        &provider_clone,
                        &context,
                        result.messaging_envelopes,
                        Some((&dl_state_clone, &conv_id_clone)),
                    ) {
                        operator_log::error(
                            module_path!(),
                            format!(
                                "[webchat] messaging pipeline failed conv={conv_id_clone} err={err}"
                            ),
                        );
                    }
                }
                Ok(_) => {
                    operator_log::debug(
                        module_path!(),
                        format!(
                            "[webchat] no messaging envelopes from ingress conv={conv_id_clone}"
                        ),
                    );
                }
                Err(err) => {
                    operator_log::error(
                        module_path!(),
                        format!("[webchat] ingress dispatch failed conv={conv_id_clone} err={err}"),
                    );
                }
            }
        });

        // 3. Return activity ID to client (201 Created)
        return Ok(json_response(StatusCode::CREATED, activity_result));
    }

    // GET /v3/directline/conversations/{convId}/activities — poll activities
    if method == Method::GET
        && let Some(ref cid) = conv_id
    {
        if path.ends_with("/activities") {
            let watermark: Option<u64> = queries
                .iter()
                .find(|(k, _)| k == "watermark")
                .and_then(|(_, v)| v.parse().ok());

            let body = crate::directline::handle_get_activities(dl_state, cid, watermark)
                .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "conversation not found"))?;

            return Ok(json_response(StatusCode::OK, body));
        }

        // GET /v3/directline/conversations/{convId} — reconnect / exists check
        if dl_state.conversation_exists(cid) {
            let body = json!({
                "conversationId": cid,
                "token": "",
                "streamUrl": null
            });
            return Ok(json_response(StatusCode::OK, body));
        }
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "conversation not found",
        ));
    }

    // Fallback — unrecognised DirectLine path
    Err(error_response(
        StatusCode::NOT_FOUND,
        format!("unrecognised directline path: {path}"),
    ))
}

async fn generate_directline_token(
    tenant: &str,
    provider: &str,
    runner_host: &DemoRunnerHost,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    let ctx = OperatorContext {
        tenant: tenant.to_string(),
        team: Some("default".to_string()),
        correlation_id: None,
    };
    let signing_key = runner_host
        .get_secret(provider, "jwt_signing_key", &ctx)
        .map_err(|err| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to fetch jwt_signing_key: {err}"),
            )
        })?
        .ok_or_else(|| {
            operator_log::warn(
                module_path!(),
                format!("[webchat] token generation failed: jwt_signing_key not found for provider={provider}"),
            );
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "jwt_signing_key secret not configured",
            )
        })?;

    let token = crate::directline::generate_jwt(&signing_key, tenant, "default", "anonymous", None);

    let body = json!({
        "token": token,
        "expires_in": 1800,
        "conversationId": ""
    });

    operator_log::info(
        module_path!(),
        format!("[webchat] token generated for tenant={tenant} expires_in=1800"),
    );

    Ok(json_response(StatusCode::OK, body))
}
