//! HTTP handler for `/v1/oauth/callback/{provider_id}`.
//!
//! Phase 3 of the OAuth card full round-trip fix. Receives the OAuth
//! authorization code from a redirect, exchanges it for an access token
//! via inline reqwest, persists the token, and injects an
//! `oauth_login_success` activity into the originating conversation so
//! the flow router can advance.

use anyhow::{Result, anyhow};
use http_body_util::Full;
use hyper::body::Bytes;
use std::path::Path;
use url::form_urlencoded;

use crate::oauth_envelope::{self, OauthProviderConfig};
use crate::oauth_session_store::OauthSessionStore;
use crate::oauth_session_store::PersistedSession;
use crate::runner_host::DemoRunnerHost;

pub struct OauthCallbackContext<'a> {
    pub bundle_root: &'a Path,
    pub session_store: &'a OauthSessionStore,
    pub runner_host: &'a DemoRunnerHost,
    pub gateway_port: u16,
}

pub async fn handle_oauth_callback(
    ctx: OauthCallbackContext<'_>,
    provider_id: &str,
    query_string: &str,
) -> hyper::Response<Full<Bytes>> {
    match handle_oauth_callback_inner(ctx, provider_id, query_string).await {
        Ok(html) => html_response(200, &html),
        Err(err) => {
            crate::operator_log::warn(
                module_path!(),
                format!("[oauth callback] failed: {err:#}"),
            );
            html_response(
                400,
                &error_html(&format!("OAuth callback failed: {err}")),
            )
        }
    }
}

struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

fn parse_callback_query(query_string: &str) -> CallbackParams {
    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut error_description = None;
    for (k, v) in form_urlencoded::parse(query_string.as_bytes()) {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            "error" => error = Some(v.into_owned()),
            "error_description" => error_description = Some(v.into_owned()),
            _ => {}
        }
    }
    CallbackParams {
        code,
        state,
        error,
        error_description,
    }
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

async fn exchange_code_for_token(
    provider: &OauthProviderConfig,
    redirect_uri: &str,
    code: &str,
    code_verifier: &str,
) -> Result<TokenResponse> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|err| anyhow!("build reqwest client: {err}"))?;

    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", provider.client_id.as_str()),
        ("client_secret", provider.client_secret.as_str()),
        ("code_verifier", code_verifier),
    ];

    let resp = client
        .post(&provider.token_url)
        .header("Accept", "application/json")
        .header("User-Agent", "greentic-start/oauth-callback")
        .form(&form)
        .send()
        .await
        .map_err(|err| anyhow!("token endpoint request failed: {err}"))?;

    let status = resp.status();
    let body_text = resp
        .text()
        .await
        .map_err(|err| anyhow!("read token response body: {err}"))?;

    // GitHub returns either JSON (when Accept: application/json) or form-encoded.
    let parsed: TokenResponse = if body_text.trim_start().starts_with('{') {
        serde_json::from_str(&body_text).map_err(|err| {
            anyhow!("token response not valid JSON: {err} — body: {body_text}")
        })?
    } else {
        // form-encoded fallback
        let mut access_token = None;
        let mut token_type = None;
        let mut scope = None;
        let mut refresh_token = None;
        let mut error = None;
        let mut error_description = None;
        for (k, v) in form_urlencoded::parse(body_text.as_bytes()) {
            match k.as_ref() {
                "access_token" => access_token = Some(v.into_owned()),
                "token_type" => token_type = Some(v.into_owned()),
                "scope" => scope = Some(v.into_owned()),
                "refresh_token" => refresh_token = Some(v.into_owned()),
                "error" => error = Some(v.into_owned()),
                "error_description" => error_description = Some(v.into_owned()),
                _ => {}
            }
        }
        TokenResponse {
            access_token,
            token_type,
            scope,
            refresh_token,
            error,
            error_description,
        }
    };

    if let Some(err) = parsed.error.as_deref() {
        return Err(anyhow!(
            "token endpoint returned error {err}: {}",
            parsed.error_description.as_deref().unwrap_or("")
        ));
    }
    if !status.is_success() {
        return Err(anyhow!(
            "token endpoint HTTP {status}: {body_text}"
        ));
    }
    if parsed.access_token.is_none() {
        return Err(anyhow!("token response missing access_token"));
    }
    Ok(parsed)
}

async fn handle_oauth_callback_inner(
    ctx: OauthCallbackContext<'_>,
    provider_id: &str,
    query_string: &str,
) -> Result<String> {
    let params = parse_callback_query(query_string);

    if let Some(err) = params.error {
        let detail = params
            .error_description
            .unwrap_or_else(|| "OAuth provider returned an error".to_string());
        return Err(anyhow!("provider error: {err} — {detail}"));
    }

    let state = params
        .state
        .ok_or_else(|| anyhow!("callback missing 'state' query param"))?;
    let code = params
        .code
        .ok_or_else(|| anyhow!("callback missing 'code' query param"))?;

    let session: PersistedSession = ctx
        .session_store
        .consume(&state)
        .map_err(|err| anyhow!("session not found or already used: {err}"))?;

    if session.provider_id != provider_id {
        return Err(anyhow!(
            "provider_id mismatch: callback path says {provider_id}, session says {}",
            session.provider_id
        ));
    }

    let provider_cfg =
        oauth_envelope::load_provider_config(ctx.bundle_root, &session.provider_pack_id)?;
    let redirect_uri = format!(
        "http://127.0.0.1:{}/v1/oauth/callback/{}",
        ctx.gateway_port, provider_id,
    );
    let token_resp =
        exchange_code_for_token(&provider_cfg, &redirect_uri, &code, &session.code_verifier)
            .await?;
    let access_token = token_resp
        .access_token
        .as_ref()
        .ok_or_else(|| anyhow!("access_token missing after exchange"))?
        .clone();

    crate::operator_log::info(
        module_path!(),
        format!(
            "[oauth callback] token exchanged for provider={provider_id} tenant={} conv={}",
            session.tenant, session.conversation_id
        ),
    );

    let secret_uri = persist_access_token(ctx.runner_host, &session, &access_token).await?;
    crate::operator_log::info(
        module_path!(),
        format!("[oauth callback] persisted access_token to {secret_uri}"),
    );

    if let Err(err) = inject_oauth_login_success_activity(
        ctx.gateway_port,
        &session.tenant,
        &session.conversation_id,
    )
    .await
    {
        crate::operator_log::warn(
            module_path!(),
            format!("[oauth callback] activity injection failed (non-fatal): {err}"),
        );
    }

    Ok(success_html(&session.tenant))
}

fn html_response(status: u16, body: &str) -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(status)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("build hyper response")
}

fn error_html(message: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Greentic OAuth — Error</title>
<style>body {{ font-family: system-ui; padding: 3rem; text-align: center; color: #1f2937; }} h1 {{ color: #dc2626; }}</style>
</head>
<body><h1>Login failed</h1><p>{message}</p><p><a href="/v1/web/webchat/demo/">Return to chat</a></p></body>
</html>"#,
        message = html_escape(message),
    )
}

fn success_html(tenant: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Greentic OAuth — Login Successful</title>
<meta http-equiv="refresh" content="2;url=/v1/web/webchat/{tenant}/">
<style>body {{ font-family: system-ui; padding: 3rem; text-align: center; color: #1f2937; }} h1 {{ color: #16a34a; }}</style>
</head>
<body><h1>Login successful</h1><p>You can close this window and return to the chat.</p>
<p><a href="/v1/web/webchat/{tenant}/">Return to chat</a></p>
<script>setTimeout(() => window.close(), 1500);</script>
</body>
</html>"#,
    )
}

async fn persist_access_token(
    runner_host: &DemoRunnerHost,
    session: &PersistedSession,
    access_token: &str,
) -> Result<String> {
    use greentic_secrets_lib::{
        ApplyOptions, DevStore, SecretFormat, SeedDoc, SeedEntry, SeedValue, apply_seed,
    };

    let env = std::env::var("GREENTIC_ENV").unwrap_or_else(|_| "dev".to_string());
    let team = session.team.as_deref().unwrap_or("_");
    let uri = format!(
        "secrets://{env}/{}/{}/{}/access_token",
        session.tenant, team, session.provider_pack_id,
    );

    let entry = SeedEntry {
        uri: uri.clone(),
        format: SecretFormat::Text,
        value: SeedValue::Text {
            text: access_token.to_string(),
        },
        description: Some(format!(
            "OAuth access_token for {} (callback)",
            session.provider_id
        )),
    };

    let dev_store_path = runner_host
        .secrets_handle()
        .dev_store_path
        .as_deref()
        .ok_or_else(|| anyhow!("no dev store path available to persist access_token"))?;

    let store = DevStore::with_path(dev_store_path)
        .map_err(|err| anyhow!("failed to open dev store at {}: {err}", dev_store_path.display()))?;

    let report = apply_seed(
        &store,
        &SeedDoc {
            entries: vec![entry],
        },
        ApplyOptions::default(),
    )
    .await;

    if !report.failed.is_empty() {
        return Err(anyhow!(
            "failed to persist access_token: {:?}",
            report.failed
        ));
    }
    Ok(uri)
}

async fn inject_oauth_login_success_activity(
    gateway_port: u16,
    tenant: &str,
    conversation_id: &str,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|err| anyhow!("build reqwest client: {err}"))?;

    // Step 1: mint a Direct Line token via the local webchat-gui endpoint.
    let token_url = format!(
        "http://127.0.0.1:{gateway_port}/v1/messaging/webchat/{tenant}/token?tenant={tenant}",
    );
    let token_resp = client
        .post(&token_url)
        .send()
        .await
        .map_err(|err| anyhow!("mint token POST failed: {err}"))?;
    let token_status = token_resp.status();
    let token_body = token_resp
        .text()
        .await
        .map_err(|err| anyhow!("read token body: {err}"))?;
    if !token_status.is_success() {
        return Err(anyhow!("mint token HTTP {token_status}: {token_body}"));
    }
    let token_json: serde_json::Value = serde_json::from_str(&token_body)
        .map_err(|err| anyhow!("token response not JSON: {err} — body: {token_body}"))?;
    let token = token_json
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("token response missing `token` field"))?;

    // Step 2: POST the synthetic activity to the existing conversation.
    let activities_url = format!(
        "http://127.0.0.1:{gateway_port}/v1/messaging/webchat/{tenant}/v3/directline/conversations/{conversation_id}/activities?tenant={tenant}",
    );
    let body = serde_json::json!({
        "type": "message",
        "from": {"id": "system", "name": "OAuth Callback"},
        "text": "oauth_login_success"
    });
    let post_resp = client
        .post(&activities_url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|err| anyhow!("inject activities POST failed: {err}"))?;
    let post_status = post_resp.status();
    if !post_status.is_success() {
        let post_body = post_resp.text().await.unwrap_or_default();
        return Err(anyhow!(
            "inject activities HTTP {post_status}: {post_body}"
        ));
    }
    Ok(())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_basic() {
        assert_eq!(html_escape("a<b>&c"), "a&lt;b&gt;&amp;c");
    }

    #[test]
    fn success_html_includes_tenant_and_redirect() {
        let h = success_html("demo");
        assert!(h.contains("/v1/web/webchat/demo/"));
        assert!(h.contains("Login successful"));
    }

    #[test]
    fn parse_callback_query_extracts_code_and_state() {
        let p = parse_callback_query("code=abc&state=xyz&unrelated=1");
        assert_eq!(p.code.as_deref(), Some("abc"));
        assert_eq!(p.state.as_deref(), Some("xyz"));
        assert!(p.error.is_none());
    }

    #[test]
    fn parse_callback_query_extracts_error_fields() {
        let p = parse_callback_query("error=access_denied&error_description=user+canceled");
        assert_eq!(p.error.as_deref(), Some("access_denied"));
        assert_eq!(p.error_description.as_deref(), Some("user canceled"));
        assert!(p.code.is_none());
    }
}
