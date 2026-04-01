use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Body, Bytes},
};
use serde_json::json;

use crate::domains::Domain;
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

pub(super) async fn handle_directline_request<B>(
    req: Request<B>,
    path: &str,
    explicit_tenant: Option<String>,
    state: Arc<HttpIngressState>,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
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

        // 2. Build a ChannelMessageEnvelope directly and route to the
        //    app flow engine. We bypass WASM ingest_http entirely since
        //    the webchat-gui component doesn't support that operation.
        let text = body.get("text").and_then(|v| v.as_str()).map(String::from);
        let from_id = body
            .get("from")
            .and_then(|f| f.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("anonymous")
            .to_string();

        let mut metadata = std::collections::BTreeMap::new();
        metadata.insert("provider".to_string(), provider.clone());
        metadata.insert("tenant".to_string(), tenant.clone());
        // Forward locale from activity for i18n resolution
        if let Some(locale) = body.get("locale").and_then(|v| v.as_str()) {
            metadata.insert("locale".to_string(), locale.to_string());
        }
        // Forward Action.Submit value fields as metadata (for card routing, MCP actions, etc.)
        if let Some(value_obj) = body.get("value").and_then(|v| v.as_object()) {
            for (k, v) in value_obj {
                let val_str = match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                metadata.insert(k.clone(), val_str);
            }
        }

        let envelope: greentic_types::ChannelMessageEnvelope =
            serde_json::from_value(serde_json::json!({
                "id": format!("webchat-{cid}"),
                "tenant": {
                    "env": "dev",
                    "tenant": &tenant,
                    "tenant_id": &tenant,
                    "team": "default",
                    "attempt": 0
                },
                "channel": cid,
                "session_id": cid,
                "from": {
                    "id": &from_id,
                    "kind": "user"
                },
                "text": text,
                "metadata": metadata
            }))
            .map_err(|e| {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("build envelope: {e}"),
                )
            })?;

        let context = OperatorContext {
            tenant: tenant.clone(),
            team: Some("default".to_string()),
            correlation_id: None,
        };

        let dl_state_clone = dl_state.clone();
        let conv_id_clone = cid.clone();
        let bundle = state.runner_host.bundle_root().to_path_buf();
        let runner_host = state.runner_host.clone();
        let provider_clone = provider.clone();

        std::thread::spawn(move || {
            if let Err(err) = route_messaging_envelopes(
                &bundle,
                &runner_host,
                &provider_clone,
                &context,
                vec![envelope],
                Some((&dl_state_clone, &conv_id_clone)),
            ) {
                operator_log::error(
                    module_path!(),
                    format!("[webchat] messaging pipeline failed conv={conv_id_clone} err={err}"),
                );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets_gate;
    use crate::secrets_gate::canonical_secret_uri;
    use http_body_util::{BodyExt, Full};
    use hyper::{Request, StatusCode, body::Bytes};
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use tempfile::tempdir;
    use tokio::runtime::Runtime;
    use zip::write::FileOptions;

    fn test_state(domains: Vec<Domain>) -> Arc<HttpIngressState> {
        let dir = tempdir().unwrap();
        let discovery = crate::discovery::discover(dir.path()).unwrap();
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(dir.path(), "demo", Some("default")).unwrap();
        let runner_host = Arc::new(
            DemoRunnerHost::new(
                dir.path().to_path_buf(),
                &discovery,
                None,
                secrets_handle,
                false,
            )
            .unwrap(),
        );
        Arc::new(HttpIngressState {
            runner_host,
            domains,
            active_route_table: crate::static_routes::ActiveRouteTable::default(),
            dl_state: crate::directline::DirectLineState::new(),
        })
    }

    fn empty_request(method: Method, path: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Full::from(Bytes::new()))
            .unwrap()
    }

    async fn response_json(response: Response<Full<Bytes>>) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn body_request(method: Method, path: &str, body: &str) -> Request<Full<Bytes>> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Full::from(Bytes::from(body.to_string())))
            .unwrap()
    }

    fn env_backed_state(root: &Path) -> Arc<HttpIngressState> {
        let pack_path = root.join("env-backend.gtpack");
        let file = File::create(&pack_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("assets/secrets_backend.json", FileOptions::<()>::default())
            .unwrap();
        zip.write_all(br#"{"backend":"env"}"#).unwrap();
        zip.finish().unwrap();
        unsafe {
            std::env::set_var("GREENTIC_SECRETS_MANAGER_PACK", &pack_path);
        }

        let discovery = crate::discovery::discover(root).unwrap();
        let secrets_handle =
            secrets_gate::resolve_secrets_manager(root, "demo", Some("default")).unwrap();
        Arc::new(HttpIngressState {
            runner_host: Arc::new(
                DemoRunnerHost::new(root.to_path_buf(), &discovery, None, secrets_handle, false)
                    .unwrap(),
            ),
            domains: vec![Domain::Messaging],
            active_route_table: crate::static_routes::ActiveRouteTable::default(),
            dl_state: crate::directline::DirectLineState::new(),
        })
    }

    #[test]
    fn parses_tenant_scoped_webchat_routes() {
        assert_eq!(
            parse_webchat_directline_route("/v1/messaging/webchat/acme/token"),
            Some(("acme".to_string(), "/token".to_string()))
        );
        assert_eq!(
            parse_webchat_directline_route("/v1/messaging/webchat/acme/auth/config"),
            Some(("acme".to_string(), "/auth/config".to_string()))
        );
        assert_eq!(
            parse_webchat_directline_route(
                "/v1/messaging/webchat/acme/v3/directline/conversations"
            ),
            Some((
                "acme".to_string(),
                "/v3/directline/conversations".to_string()
            ))
        );
    }

    #[test]
    fn rejects_invalid_webchat_routes() {
        assert_eq!(
            parse_webchat_directline_route("/v1/messaging/webchat//token"),
            None
        );
        assert_eq!(
            parse_webchat_directline_route("/v1/messaging/webchat/acme/unknown"),
            None
        );
        assert_eq!(parse_webchat_directline_route("/v1/other/acme/token"), None);
    }

    #[test]
    fn parses_directline_conversation_ids_only_when_present() {
        assert_eq!(
            parse_directline_conversation_id("/v3/directline/conversations/conv-123"),
            Some("conv-123".to_string())
        );
        assert_eq!(
            parse_directline_conversation_id("/v3/directline/conversations/conv-123/activities"),
            Some("conv-123".to_string())
        );
        assert_eq!(
            parse_directline_conversation_id("/v3/directline/conversations/"),
            None
        );
        assert_eq!(
            parse_directline_conversation_id("/v3/directline/tokens/conv-123"),
            None
        );
    }

    #[test]
    fn handle_directline_request_rejects_disabled_domain_and_unknown_paths() {
        let runtime = Runtime::new().unwrap();

        let disabled = runtime
            .block_on(handle_directline_request(
                empty_request(Method::GET, "/auth/config"),
                "/auth/config",
                Some("demo".to_string()),
                test_state(vec![]),
            ))
            .unwrap_err();
        assert_eq!(disabled.status(), StatusCode::NOT_FOUND);

        let unknown = runtime
            .block_on(handle_directline_request(
                empty_request(Method::GET, "/v3/directline/unknown"),
                "/v3/directline/unknown",
                Some("demo".to_string()),
                test_state(vec![Domain::Messaging]),
            ))
            .unwrap_err();
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn handle_directline_request_serves_auth_config_and_missing_conversation_errors() {
        let runtime = Runtime::new().unwrap();
        let state = test_state(vec![Domain::Messaging]);

        let auth_config = runtime
            .block_on(handle_directline_request(
                empty_request(Method::GET, "/auth/config"),
                "/auth/config",
                Some("demo".to_string()),
                state.clone(),
            ))
            .unwrap();
        assert_eq!(auth_config.status(), StatusCode::OK);

        let missing_conversation = runtime
            .block_on(handle_directline_request(
                empty_request(Method::GET, "/v3/directline/conversations/missing"),
                "/v3/directline/conversations/missing",
                Some("demo".to_string()),
                state,
            ))
            .unwrap_err();
        assert_eq!(missing_conversation.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn handle_directline_request_creates_conversation_and_lists_empty_activity_set() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        let env_guard = crate::test_env_lock().lock().unwrap();
        let state = env_backed_state(dir.path());
        let secret_uri = canonical_secret_uri(
            "dev",
            "demo",
            Some("default"),
            "messaging-webchat-gui",
            "jwt_signing_key",
        );
        unsafe {
            std::env::set_var(&secret_uri, "test-signing-key");
        }

        let created = runtime
            .block_on(handle_directline_request(
                empty_request(Method::POST, "/v3/directline/conversations"),
                "/v3/directline/conversations",
                Some("demo".to_string()),
                state.clone(),
            ))
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let created_body = runtime.block_on(response_json(created));
        let conversation_id = created_body["conversationId"].as_str().unwrap().to_string();
        assert!(!conversation_id.is_empty());

        let reconnect_path = format!("/v3/directline/conversations/{conversation_id}");
        let reconnect = runtime
            .block_on(handle_directline_request(
                empty_request(Method::GET, &reconnect_path),
                &reconnect_path,
                Some("demo".to_string()),
                state.clone(),
            ))
            .unwrap();
        assert_eq!(reconnect.status(), StatusCode::OK);

        let activities_path = format!("/v3/directline/conversations/{conversation_id}/activities");
        let activities = runtime
            .block_on(handle_directline_request(
                empty_request(Method::GET, &activities_path),
                &activities_path,
                Some("demo".to_string()),
                state,
            ))
            .unwrap();
        assert_eq!(activities.status(), StatusCode::OK);
        let body = runtime.block_on(response_json(activities));
        assert_eq!(
            body["activities"].as_array().map(std::vec::Vec::len),
            Some(0)
        );

        unsafe {
            std::env::remove_var(&secret_uri);
            std::env::remove_var("GREENTIC_SECRETS_MANAGER_PACK");
        }
        drop(env_guard);
    }

    #[test]
    fn handle_directline_request_generates_tokens_and_validates_activity_posts() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        let env_guard = crate::test_env_lock().lock().unwrap();
        let state = env_backed_state(dir.path());
        let secret_uri = canonical_secret_uri(
            "dev",
            "demo",
            Some("default"),
            "messaging-webchat-gui",
            "jwt_signing_key",
        );
        unsafe {
            std::env::set_var(&secret_uri, "test-signing-key");
        }

        let token = runtime
            .block_on(handle_directline_request(
                empty_request(Method::GET, "/token"),
                "/token",
                Some("demo".to_string()),
                state.clone(),
            ))
            .unwrap();
        assert_eq!(token.status(), StatusCode::OK);
        let token_body = runtime.block_on(response_json(token));
        assert!(
            token_body["token"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        assert_eq!(token_body["expires_in"], 1800);

        state.dl_state.create_conversation("conv-1");
        let invalid_json = runtime
            .block_on(handle_directline_request(
                body_request(
                    Method::POST,
                    "/v3/directline/conversations/conv-1/activities",
                    "{not-json",
                ),
                "/v3/directline/conversations/conv-1/activities",
                Some("demo".to_string()),
                state.clone(),
            ))
            .unwrap_err();
        assert_eq!(invalid_json.status(), StatusCode::BAD_REQUEST);

        let missing_conversation = runtime
            .block_on(handle_directline_request(
                body_request(
                    Method::POST,
                    "/v3/directline/conversations/missing/activities",
                    r#"{"text":"hello"}"#,
                ),
                "/v3/directline/conversations/missing/activities",
                Some("demo".to_string()),
                state.clone(),
            ))
            .unwrap_err();
        assert_eq!(missing_conversation.status(), StatusCode::NOT_FOUND);

        unsafe {
            std::env::remove_var(&secret_uri);
        }

        let missing_key = runtime
            .block_on(handle_directline_request(
                empty_request(Method::GET, "/token"),
                "/token",
                Some("demo".to_string()),
                state,
            ))
            .unwrap_err();
        assert_eq!(missing_key.status(), StatusCode::INTERNAL_SERVER_ERROR);

        unsafe {
            std::env::remove_var("GREENTIC_SECRETS_MANAGER_PACK");
        }
        drop(env_guard);
    }
}
