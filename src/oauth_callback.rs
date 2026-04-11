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

    // Tasks 13-15 will fill in the rest. For now, just acknowledge.
    let _ = code;
    let _ = ctx.runner_host;
    let _ = ctx.bundle_root;
    let _ = ctx.gateway_port;
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
