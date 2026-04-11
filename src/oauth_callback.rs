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

use crate::oauth_session_store::OauthSessionStore;
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

async fn handle_oauth_callback_inner(
    _ctx: OauthCallbackContext<'_>,
    _provider_id: &str,
    _query_string: &str,
) -> Result<String> {
    Err(anyhow!("not implemented yet"))
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

#[allow(dead_code)]
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
}
