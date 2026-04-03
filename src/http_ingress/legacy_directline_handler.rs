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

pub(super) async fn handle_legacy_directline_request<B>(
    req: Request<B>,
    path: &str,
    explicit_tenant: Option<String>,
    explicit_team: Option<String>,
    explicit_provider: Option<String>,
    state: Arc<HttpIngressState>,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let method = req.method().clone();
    let query_string = req.uri().query().map(String::from);
    let queries = collect_queries(query_string.as_deref());

    // Provider resolution priority:
    // 1) explicit provider from route handoff (e.g. matched static route pack_id),
    // 2) `provider=` query parameter override.
    let provider = explicit_provider.or_else(|| {
        queries
            .iter()
            .find(|(k, _)| k == "provider")
            .map(|(_, v)| v.clone())
    });

    // Use explicit scope from route handoff, or fall back to query params.
    let tenant = explicit_tenant.unwrap_or_else(|| {
        queries
            .iter()
            .find(|(k, _)| k == "tenant")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "default".to_string())
    });
    let team = explicit_team.unwrap_or_else(|| {
        queries
            .iter()
            .find(|(k, _)| k == "team")
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
        let provider =
            require_directline_provider(provider.as_deref()).map_err(|response| *response)?;
        return generate_directline_token(&tenant, &team, provider, &state.runner_host).await;
    }

    // Intercept /auth/config — read OAuth settings from secrets store
    if path == "/auth/config" {
        let provider =
            require_directline_provider(provider.as_deref()).map_err(|response| *response)?;
        operator_log::debug(
            module_path!(),
            format!("[directline] auth/config request for tenant={tenant} provider={provider}"),
        );
        return generate_auth_config(&tenant, provider, &state.runner_host);
    }

    operator_log::info(
        module_path!(),
        format!(
            "[directline] request: method={method} tenant={tenant} path={path} provider={}",
            provider.as_deref().unwrap_or("<unspecified>")
        ),
    );

    let dl_compat = state.legacy_directline_compat();
    let conv_id = parse_directline_conversation_id(path);

    // POST /v3/directline/conversations — create new conversation
    if method == Method::POST && path == "/v3/directline/conversations" {
        let provider =
            require_directline_provider(provider.as_deref()).map_err(|response| *response)?;
        let ctx = OperatorContext {
            tenant: tenant.clone(),
            team: Some(team.clone()),
            correlation_id: None,
        };
        let signing_key = state
            .runner_host
            .get_secret(provider, "jwt_signing_key", &ctx)
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
        let body = dl_compat.create_conversation_response(&tenant, &team, &signing_key);
        operator_log::info(
            module_path!(),
            format!(
                "[directline] created conversation id={} tenant={tenant}",
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
        let provider = require_directline_provider(provider.as_deref())
            .map_err(|response| *response)?
            .to_string();
        let payload_bytes = req
            .into_body()
            .collect()
            .await
            .map(|collected| collected.to_bytes())
            .unwrap_or_default();

        let body: serde_json::Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| error_response(StatusCode::BAD_REQUEST, format!("invalid json: {e}")))?;

        // 1. Store user activity in DirectLine state
        let activity_result = dl_compat
            .post_activity_response(cid, &body)
            .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "conversation not found"))?;

        let activity_id = activity_result["id"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        operator_log::info(
            module_path!(),
            format!(
                "[directline] stored user activity id={activity_id} conv={cid} tenant={tenant}"
            ),
        );

        let envelope = super::legacy_directline::LegacyDirectLineCompat::build_user_envelope(
            &tenant, &team, &provider, cid, &body,
        )
        .map_err(|e| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("build envelope: {e}"),
            )
        })?;

        let context = OperatorContext {
            tenant: tenant.clone(),
            team: Some(team.clone()),
            correlation_id: None,
        };

        let dl_compat_clone = dl_compat.clone();
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
                Some(dl_compat_clone.reply_target(&conv_id_clone)),
            ) {
                operator_log::error(
                    module_path!(),
                    format!(
                        "[directline] messaging pipeline failed conv={conv_id_clone} err={err}"
                    ),
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

            let body = dl_compat
                .get_activities_response(cid, watermark)
                .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "conversation not found"))?;

            return Ok(json_response(StatusCode::OK, body));
        }

        // GET /v3/directline/conversations/{convId} — reconnect / exists check
        if dl_compat.conversation_exists(cid) {
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

fn require_directline_provider(
    provider: Option<&str>,
) -> std::result::Result<&str, Box<Response<Full<Bytes>>>> {
    provider.ok_or_else(|| {
        Box::new(error_response(
            StatusCode::BAD_REQUEST,
            "provider must be supplied by the route or query",
        ))
    })
}

async fn generate_directline_token(
    tenant: &str,
    team: &str,
    provider: &str,
    runner_host: &DemoRunnerHost,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    let ctx = OperatorContext {
        tenant: tenant.to_string(),
        team: Some(team.to_string()),
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
                format!(
                    "[directline] token generation failed: jwt_signing_key not found for provider={provider}"
                ),
            );
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "jwt_signing_key secret not configured",
            )
        })?;

    let body = super::legacy_directline::LegacyDirectLineCompat::token_response(
        tenant,
        team,
        &signing_key,
    );

    operator_log::info(
        module_path!(),
        format!("[directline] token generated for tenant={tenant} expires_in=1800"),
    );

    Ok(json_response(StatusCode::OK, body))
}

/// Build OAuth auth config from provider secrets.
///
/// Reads `oauth_enabled`, `oauth_enable_google`, `oauth_google_client_id`, etc.
/// from the secrets store and returns an auth config payload for the webchat GUI.
#[allow(clippy::result_large_err)]
fn generate_auth_config(
    tenant: &str,
    provider: &str,
    runner_host: &DemoRunnerHost,
) -> Result<Response<Full<Bytes>>, Response<Full<Bytes>>> {
    let ctx = OperatorContext {
        tenant: tenant.to_string(),
        team: Some("default".to_string()),
        correlation_id: None,
    };

    let get = |key: &str| -> Option<String> {
        runner_host
            .get_secret(provider, key, &ctx)
            .ok()
            .flatten()
            .and_then(|bytes| String::from_utf8(bytes).ok())
    };

    let oauth_enabled = get("oauth_enabled").map(|v| v == "true").unwrap_or(false);

    if !oauth_enabled {
        return Ok(json_response(StatusCode::OK, json!({ "enabled": false })));
    }

    let public_base_url =
        get("public_base_url").unwrap_or_else(|| "http://localhost:8080".to_string());
    let redirect_base = format!(
        "{}/v1/web/webchat/{}/",
        public_base_url.trim_end_matches('/'),
        tenant,
    );

    let mut providers = Vec::new();

    // Guest/demo login (always available)
    providers.push(json!({
        "id": format!("{tenant}-demo"),
        "label": "Continue as Guest",
        "type": "dummy",
        "enabled": true
    }));

    struct OidcDef {
        suffix: &'static str,
        label: &'static str,
        enable_key: &'static str,
        client_id_key: &'static str,
        auth_url: &'static str,
        scope: &'static str,
    }

    let oidc_providers = [
        OidcDef {
            suffix: "google",
            label: "Sign in with Google",
            enable_key: "oauth_enable_google",
            client_id_key: "oauth_google_client_id",
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
            scope: "openid profile email",
        },
        OidcDef {
            suffix: "microsoft",
            label: "Sign in with Microsoft",
            enable_key: "oauth_enable_microsoft",
            client_id_key: "oauth_microsoft_client_id",
            auth_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            scope: "openid profile email",
        },
        OidcDef {
            suffix: "github",
            label: "Sign in with GitHub",
            enable_key: "oauth_enable_github",
            client_id_key: "oauth_github_client_id",
            auth_url: "https://github.com/login/oauth/authorize",
            scope: "read:user user:email",
        },
    ];

    for def in &oidc_providers {
        let enabled = get(def.enable_key).map(|v| v == "true").unwrap_or(false);
        let client_id = get(def.client_id_key).unwrap_or_default();

        providers.push(json!({
            "id": format!("{tenant}-{}", def.suffix),
            "label": def.label,
            "type": "oidc",
            "enabled": enabled,
            "authorizationUrl": def.auth_url,
            "clientId": client_id,
            "redirectUri": &redirect_base,
            "scope": def.scope,
            "responseType": "code"
        }));
    }

    // Custom OIDC
    let custom_enabled = get("oauth_enable_custom")
        .map(|v| v == "true")
        .unwrap_or(false);
    if custom_enabled {
        let label = get("oauth_custom_label").unwrap_or_else(|| "SSO Login".to_string());
        let auth_url = get("oauth_custom_auth_url").unwrap_or_default();
        let client_id = get("oauth_custom_client_id").unwrap_or_default();
        let scopes =
            get("oauth_custom_scopes").unwrap_or_else(|| "openid profile email".to_string());

        providers.push(json!({
            "id": format!("{tenant}-custom-oidc"),
            "label": label,
            "type": "oidc",
            "enabled": true,
            "authorizationUrl": auth_url,
            "clientId": client_id,
            "redirectUri": &redirect_base,
            "scope": scopes,
            "responseType": "code"
        }));
    }

    operator_log::info(
        module_path!(),
        format!(
            "[webchat] auth/config for tenant={tenant}: enabled={oauth_enabled} providers={}",
            providers.len()
        ),
    );

    Ok(json_response(
        StatusCode::OK,
        json!({
            "enabled": true,
            "providers": providers
        }),
    ))
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

    use super::super::parse_provider_directline_http_response;

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
            legacy_directline: crate::http_ingress::legacy_directline::LegacyDirectLineCompat::new(
            ),
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
            legacy_directline: crate::http_ingress::legacy_directline::LegacyDirectLineCompat::new(
            ),
        })
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
    fn handle_legacy_directline_request_rejects_disabled_domain_and_unknown_paths() {
        let runtime = Runtime::new().unwrap();

        let disabled = runtime
            .block_on(handle_legacy_directline_request(
                empty_request(Method::GET, "/auth/config"),
                "/auth/config",
                Some("demo".to_string()),
                None,
                None,
                test_state(vec![]),
            ))
            .unwrap_err();
        assert_eq!(disabled.status(), StatusCode::NOT_FOUND);

        let unknown = runtime
            .block_on(handle_legacy_directline_request(
                empty_request(Method::GET, "/v3/directline/unknown"),
                "/v3/directline/unknown",
                Some("demo".to_string()),
                None,
                None,
                test_state(vec![Domain::Messaging]),
            ))
            .unwrap_err();
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn handle_legacy_directline_request_serves_auth_config_and_missing_conversation_errors() {
        let runtime = Runtime::new().unwrap();
        let state = test_state(vec![Domain::Messaging]);

        let auth_config = runtime
            .block_on(handle_legacy_directline_request(
                empty_request(Method::GET, "/auth/config"),
                "/auth/config",
                Some("demo".to_string()),
                None,
                Some("messaging-webchat".to_string()),
                state.clone(),
            ))
            .unwrap();
        assert_eq!(auth_config.status(), StatusCode::OK);

        let missing_conversation = runtime
            .block_on(handle_legacy_directline_request(
                empty_request(Method::GET, "/v3/directline/conversations/missing"),
                "/v3/directline/conversations/missing",
                Some("demo".to_string()),
                None,
                None,
                state,
            ))
            .unwrap_err();
        assert_eq!(missing_conversation.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn handle_legacy_directline_request_creates_conversation_and_lists_empty_activity_set() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        let env_guard = crate::test_env_lock().lock().unwrap();
        let state = env_backed_state(dir.path());
        let secret_uri = canonical_secret_uri(
            "dev",
            "demo",
            Some("default"),
            "messaging-webchat",
            "jwt_signing_key",
        );
        unsafe {
            std::env::set_var(&secret_uri, "test-signing-key");
        }

        let created = runtime
            .block_on(handle_legacy_directline_request(
                empty_request(Method::POST, "/v3/directline/conversations"),
                "/v3/directline/conversations",
                Some("demo".to_string()),
                None,
                Some("messaging-webchat".to_string()),
                state.clone(),
            ))
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let created_body = runtime.block_on(response_json(created));
        let conversation_id = created_body["conversationId"].as_str().unwrap().to_string();
        assert!(!conversation_id.is_empty());

        let reconnect_path = format!("/v3/directline/conversations/{conversation_id}");
        let reconnect = runtime
            .block_on(handle_legacy_directline_request(
                empty_request(Method::GET, &reconnect_path),
                &reconnect_path,
                Some("demo".to_string()),
                None,
                Some("messaging-webchat".to_string()),
                state.clone(),
            ))
            .unwrap();
        assert_eq!(reconnect.status(), StatusCode::OK);

        let activities_path = format!("/v3/directline/conversations/{conversation_id}/activities");
        let activities = runtime
            .block_on(handle_legacy_directline_request(
                empty_request(Method::GET, &activities_path),
                &activities_path,
                Some("demo".to_string()),
                None,
                Some("messaging-webchat".to_string()),
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
    fn handle_legacy_directline_request_generates_tokens_and_validates_activity_posts() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        let env_guard = crate::test_env_lock().lock().unwrap();
        let state = env_backed_state(dir.path());
        let secret_uri = canonical_secret_uri(
            "dev",
            "demo",
            Some("default"),
            "messaging-webchat",
            "jwt_signing_key",
        );
        unsafe {
            std::env::set_var(&secret_uri, "test-signing-key");
        }

        let token = runtime
            .block_on(handle_legacy_directline_request(
                empty_request(Method::GET, "/token"),
                "/token",
                Some("demo".to_string()),
                None,
                Some("messaging-webchat".to_string()),
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

        state
            .legacy_directline_compat()
            .create_conversation("conv-1");
        let invalid_json = runtime
            .block_on(handle_legacy_directline_request(
                body_request(
                    Method::POST,
                    "/v3/directline/conversations/conv-1/activities",
                    "{not-json",
                ),
                "/v3/directline/conversations/conv-1/activities",
                Some("demo".to_string()),
                None,
                Some("messaging-webchat".to_string()),
                state.clone(),
            ))
            .unwrap_err();
        assert_eq!(invalid_json.status(), StatusCode::BAD_REQUEST);

        let missing_conversation = runtime
            .block_on(handle_legacy_directline_request(
                body_request(
                    Method::POST,
                    "/v3/directline/conversations/missing/activities",
                    r#"{"text":"hello"}"#,
                ),
                "/v3/directline/conversations/missing/activities",
                Some("demo".to_string()),
                None,
                Some("messaging-webchat".to_string()),
                state.clone(),
            ))
            .unwrap_err();
        assert_eq!(missing_conversation.status(), StatusCode::NOT_FOUND);

        unsafe {
            std::env::remove_var(&secret_uri);
        }

        let missing_key = runtime
            .block_on(handle_legacy_directline_request(
                empty_request(Method::GET, "/token"),
                "/token",
                Some("demo".to_string()),
                None,
                Some("messaging-webchat".to_string()),
                state,
            ))
            .unwrap_err();
        assert_eq!(missing_key.status(), StatusCode::INTERNAL_SERVER_ERROR);

        unsafe {
            std::env::remove_var("GREENTIC_SECRETS_MANAGER_PACK");
        }
        drop(env_guard);
    }

    #[test]
    fn directline_token_requires_route_or_query_provider() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        let env_guard = crate::test_env_lock().lock().unwrap();
        let state = env_backed_state(dir.path());

        let webchat_secret_uri = canonical_secret_uri(
            "dev",
            "demo",
            Some("default"),
            "messaging-webchat",
            "jwt_signing_key",
        );
        unsafe {
            std::env::set_var(&webchat_secret_uri, "legacy-webchat-signing-key");
        }

        let legacy_ok = runtime
            .block_on(handle_legacy_directline_request(
                empty_request(Method::GET, "/token?tenant=demo&provider=messaging-webchat"),
                "/token",
                None,
                None,
                None,
                state.clone(),
            ))
            .unwrap();
        assert_eq!(legacy_ok.status(), StatusCode::OK);

        let missing_provider = runtime
            .block_on(handle_legacy_directline_request(
                empty_request(Method::GET, "/token"),
                "/token",
                Some("demo".to_string()),
                None,
                None,
                state,
            ))
            .unwrap_err();
        assert_eq!(missing_provider.status(), StatusCode::BAD_REQUEST);

        unsafe {
            std::env::remove_var(&webchat_secret_uri);
            std::env::remove_var("GREENTIC_SECRETS_MANAGER_PACK");
        }
        drop(env_guard);
    }

    #[test]
    fn explicit_provider_is_used_for_tenant_scoped_token_generation() {
        let runtime = Runtime::new().unwrap();
        let dir = tempdir().unwrap();
        let env_guard = crate::test_env_lock().lock().unwrap();
        let state = env_backed_state(dir.path());

        let gui_secret_uri = canonical_secret_uri(
            "dev",
            "demo",
            Some("default"),
            "messaging-webchat-gui",
            "jwt_signing_key",
        );
        unsafe {
            std::env::set_var(&gui_secret_uri, "gui-signing-key");
        }

        let token = runtime
            .block_on(handle_legacy_directline_request(
                empty_request(Method::GET, "/token"),
                "/token",
                Some("demo".to_string()),
                None,
                Some("messaging-webchat-gui".to_string()),
                state,
            ))
            .unwrap();
        assert_eq!(token.status(), StatusCode::OK);

        unsafe {
            std::env::remove_var(&gui_secret_uri);
            std::env::remove_var("GREENTIC_SECRETS_MANAGER_PACK");
        }
        drop(env_guard);
    }

    #[test]
    fn parse_provider_directline_http_response_accepts_response_envelope() {
        let response = parse_provider_directline_http_response(&json!({
            "response": {
                "status": 202,
                "headers": { "content-type": "application/json" },
                "body_json": { "ok": true }
            }
        }))
        .expect("response");
        assert_eq!(response.status, 202);
        assert_eq!(
            response.headers,
            vec![("content-type".to_string(), "application/json".to_string())]
        );
        assert_eq!(response.body, Some(br#"{"ok":true}"#.to_vec()));
    }
}
