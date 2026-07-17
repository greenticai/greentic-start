// Re-export pure HTTP helpers from the hoisted top-level module so
// consumers within `http_ingress` keep compiling without import changes.
pub(super) use crate::http_helpers::{
    ParsedIngressRoute, build_http_response, collect_headers, collect_queries,
    cors_preflight_response, domain_name, error_response, handle_builtin_health_request,
    handle_oauth_token_exchange, parse_domain, parse_route_segments, with_cors,
};

// ---------------------------------------------------------------------------
// OAuth callback — coupled to HttpIngressState / trigger_oauth_resume; stays
// here until the later OAuth PR decouples it.
// ---------------------------------------------------------------------------

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};

/// URL-decode a query component (minimal: handles %XX and `+`).
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(b);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let mut it = pair.splitn(2, '=');
        if it.next()? == key {
            Some(url_decode(it.next().unwrap_or("")))
        } else {
            None
        }
    })
}

/// Our own OAuth callback: `GET /oauth/callback/<provider>?code=&state=`.
/// `state` is the host-minted signed token (see `crate::oauth_state`) carrying
/// the full context. We verify it, read the PACK-SCOPED `client_id`/`client_secret`
/// the bundle author provided at setup, exchange the code, and persist the token
/// at the pack-scoped `access_token` key the MCP adapter reads — for any pack /
/// provider / tenant, with CSRF protection from the signature.
pub(super) async fn handle_oauth_callback(
    query: &str,
    _provider: &str,
    manager: crate::secrets_gate::DynSecretsManager,
    ingress: &std::sync::Arc<super::HttpIngressState>,
) -> Response<Full<Bytes>> {
    let code = query_param(query, "code").unwrap_or_default();
    let state = query_param(query, "state").unwrap_or_default();
    if code.is_empty() {
        return oauth_callback_page(false, "Missing authorization code.");
    }
    let Some(ctx) = crate::oauth_state::verify(&state) else {
        return oauth_callback_page(
            false,
            "Invalid or expired sign-in state — please retry sign-in from the chat.",
        );
    };

    // Same env resolution the runner scopes component secrets with, so the key we
    // write matches the key the adapter reads.
    let env = crate::secrets_setup::resolve_env(None);
    let team_seg = crate::oauth_state::team_segment(&ctx.team);
    // Secrets are stored under the canonicalized provider/pack segment (see the
    // secrets-gate `canonicalize_provider_segment`, #271). The MCP adapter reads
    // through that gate so it resolves a hyphenated pack id like
    // `github-review-pack` against the stored `github_review_pack`. This callback
    // reads the dev store directly (no gate), so canonicalize the pack segment
    // here too — otherwise the raw hyphenated id misses the stored key and we
    // wrongly report "client_id not configured".
    let pack_seg = crate::oauth_state::canonical_secret_name(&ctx.pack);
    // Pack-scoped secret URI for `auth.oauth2.<scheme>.<suffix>`.
    let key_uri = |suffix: &str| -> String {
        let canon = crate::oauth_state::canonical_secret_name(&format!(
            "auth.oauth2.{}.{}",
            ctx.scheme, suffix
        ));
        format!(
            "secrets://{}/{}/{}/{}/{}",
            env, ctx.tenant, team_seg, pack_seg, canon
        )
    };
    let read = |uri: String| {
        let m = manager.clone();
        async move {
            m.read(&uri)
                .await
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
        }
    };
    let cid = read(key_uri("client_id")).await.unwrap_or_default();
    let csec = read(key_uri("client_secret")).await.unwrap_or_default();
    if cid.is_empty() {
        return oauth_callback_page(
            false,
            "OAuth client_id not configured for this pack — run gtc setup and enter it.",
        );
    }

    // Provider profile drives the token endpoint + whether this is a PKCE flow.
    let Some(profile) = crate::oauth_engine::provider_profile(&ctx.provider) else {
        return oauth_callback_page(false, "Unsupported provider.");
    };
    let token_url = profile.token_url.to_string();

    // client_secret is optional — omit it for a PKCE public client. For PKCE we
    // replay the server-side verifier stashed under the state `jti`. redirect_uri is
    // sent only when the provider requires it (Google) and must match the authorize
    // request + the registered URI; GitHub omits it (implicit registered callback).
    let secret_owned: Option<String> = (!csec.is_empty()).then(|| csec.clone());
    let verifier_owned: Option<String> = if profile.uses_pkce {
        crate::oauth_engine::take_verifier(&ctx.jti)
    } else {
        None
    };
    let redirect_owned: Option<String> = profile
        .redirect_uri_required
        .then(|| crate::oauth_engine::callback_redirect_uri(&ctx.provider));
    let code_owned = code.clone();
    let cid_owned = cid.clone();
    let exchanged = tokio::task::spawn_blocking(move || {
        crate::oauth_engine::exchange_code(
            &token_url,
            &code_owned,
            &cid_owned,
            secret_owned.as_deref(),
            redirect_owned.as_deref(),
            verifier_owned.as_deref(),
        )
    })
    .await;
    let tokens = match exchanged {
        Ok(Ok(t)) => t,
        Ok(Err(err)) => {
            return oauth_callback_page(false, &format!("Token exchange failed: {err}"));
        }
        Err(err) => return oauth_callback_page(false, &format!("Exchange task error: {err}")),
    };

    // Persist at the pack-scoped keys the MCP adapter reads. Store the refresh token
    // too (when the provider returns one) so the runtime can refresh silently later.
    let key = key_uri("access_token");
    if let Err(err) = manager.write(&key, tokens.access_token.as_bytes()).await {
        return oauth_callback_page(false, &format!("Failed to persist token: {err}"));
    }
    if let Some(rt) = tokens.refresh_token.as_deref() {
        let _ = manager
            .write(&key_uri("refresh_token"), rt.as_bytes())
            .await;
    }
    // Persist absolute expiry so the runtime can refresh-on-read before it lapses.
    if let Some(secs) = tokens.expires_in {
        let exp = chrono::Utc::now().timestamp() + secs as i64;
        let _ = manager
            .write(&key_uri("expires_at"), exp.to_string().as_bytes())
            .await;
    }
    crate::operator_log::info(
        module_path!(),
        format!("[oauth-callback] persisted {} token at {key}", ctx.provider),
    );
    // Auto-advance: if the Connect card came from a live webchat conversation, push a
    // synthetic resume into it so the flow re-runs (token now present) and the next
    // card lands without the user re-typing. Best-effort — the page below is the
    // fallback when there's no conversation to resume.
    if ctx.conv.is_some() {
        super::trigger_oauth_resume(ingress, &ctx).await;
        return oauth_callback_page(true, "Signed in — returning you to the chat…");
    }
    oauth_callback_page(true, "Signed in. Return to the chat and ask again.")
}

fn oauth_callback_page(ok: bool, msg: &str) -> Response<Full<Bytes>> {
    let title = if ok { "Connected" } else { "Sign-in failed" };
    let html = format!(
        "<!doctype html><html><head><meta charset=utf-8><title>{title}</title></head>\
         <body style=\"font-family:system-ui;max-width:32rem;margin:4rem auto;text-align:center\">\
         <h2>{title}</h2><p>{msg}</p><p>You can close this tab.</p></body></html>"
    );
    Response::builder()
        .status(if ok {
            StatusCode::OK
        } else {
            StatusCode::BAD_REQUEST
        })
        .header("Content-Type", "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(html)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from(msg.to_string()))))
}
