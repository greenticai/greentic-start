//! Native OAuth/OIDC engine — the runtime side of the `greentic:oauth` capability.
//!
//! Provider-agnostic primitives the runtime uses to run the OAuth dance without a
//! bundled OIDC component: PKCE, consent-URL construction, code→token exchange
//! (client_secret optional, PKCE supported), and refresh. Signed-state CSRF lives
//! in [`crate::oauth_state`]. HTTP uses the runtime's native client, so none of
//! this needs WASM. See `docs/proposals/hybrid-auth.md` in component-oauth-card.

#![allow(dead_code)] // engine API; wired into callback/refresh in the next step

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// PKCE verifier + S256 challenge pair (RFC 7636).
#[derive(Clone, Debug)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

/// Generate a PKCE pair: a 43-char base64url verifier and its S256 challenge.
pub fn pkce() -> Pkce {
    let bytes: [u8; 32] = rand::random();
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(digest);
    Pkce {
        verifier,
        challenge,
    }
}

/// Percent-encode a query/form value (unreserved chars pass through).
pub fn enc(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

/// Build an Authorization Code consent URL.
///
/// `redirect_uri = None` lets the provider use the app's registered callback.
/// `pkce_challenge = Some(..)` adds `code_challenge` + `code_challenge_method=S256`
/// (public client, no secret). `extra` carries provider-specific params, e.g.
/// Google's `access_type=offline` + `prompt=consent` for a refresh token.
pub fn build_consent_url(
    auth_url: &str,
    client_id: &str,
    scopes: &[String],
    redirect_uri: Option<&str>,
    state: &str,
    pkce_challenge: Option<&str>,
    extra: &[(&str, &str)],
) -> String {
    let mut q = vec![
        ("response_type".to_string(), "code".to_string()),
        ("client_id".to_string(), client_id.to_string()),
        ("state".to_string(), state.to_string()),
    ];
    if !scopes.is_empty() {
        q.push(("scope".to_string(), scopes.join(" ")));
    }
    if let Some(r) = redirect_uri {
        q.push(("redirect_uri".to_string(), r.to_string()));
    }
    if let Some(ch) = pkce_challenge {
        q.push(("code_challenge".to_string(), ch.to_string()));
        q.push(("code_challenge_method".to_string(), "S256".to_string()));
    }
    for (k, v) in extra {
        q.push(((*k).to_string(), (*v).to_string()));
    }
    let qs = q
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&");
    let sep = if auth_url.contains('?') { '&' } else { '?' };
    format!("{auth_url}{sep}{qs}")
}

/// Token endpoint response (the fields we care about).
#[derive(Clone, Debug, Default, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

fn post_form(token_url: &str, form: String) -> Result<TokenResponse, String> {
    let url = token_url.to_string();
    let body = std::thread::spawn(move || {
        ureq::post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .send(form.as_bytes())
            .and_then(|mut r| r.body_mut().read_to_string())
    })
    .join()
    .map_err(|_| "token request thread panicked".to_string())?
    .map_err(|e| format!("token request failed: {e}"))?;
    let parsed: TokenResponse = serde_json::from_str(&body)
        .map_err(|e| format!("token response parse failed: {e}; body={body}"))?;
    if parsed.access_token.trim().is_empty() {
        return Err(format!("no access_token in response: {body}"));
    }
    Ok(parsed)
}

/// Exchange an authorization `code` for tokens. `client_secret`/`redirect_uri`/
/// `code_verifier` are each optional — omit the secret for a PKCE public client.
pub fn exchange_code(
    token_url: &str,
    code: &str,
    client_id: &str,
    client_secret: Option<&str>,
    redirect_uri: Option<&str>,
    code_verifier: Option<&str>,
) -> Result<TokenResponse, String> {
    let mut form = format!(
        "grant_type=authorization_code&code={}&client_id={}",
        enc(code),
        enc(client_id)
    );
    if let Some(s) = client_secret {
        form.push_str(&format!("&client_secret={}", enc(s)));
    }
    if let Some(r) = redirect_uri {
        form.push_str(&format!("&redirect_uri={}", enc(r)));
    }
    if let Some(v) = code_verifier {
        form.push_str(&format!("&code_verifier={}", enc(v)));
    }
    post_form(token_url, form)
}

/// Refresh an access token using a stored refresh token.
pub fn refresh(
    token_url: &str,
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token: &str,
) -> Result<TokenResponse, String> {
    let mut form = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}",
        enc(refresh_token),
        enc(client_id)
    );
    if let Some(s) = client_secret {
        form.push_str(&format!("&client_secret={}", enc(s)));
    }
    post_form(token_url, form)
}

/// Per-provider OAuth profile. `token_url` is the token endpoint; `uses_pkce`
/// drives the no-secret public-client flow; `authorize_extra` are provider-specific
/// authorize-request params (e.g. Google's offline-access knobs for a refresh token).
pub struct ProviderProfile {
    pub token_url: &'static str,
    pub uses_pkce: bool,
    /// Whether `redirect_uri` must be sent on the authorize + token requests and
    /// match a registered URI (Google requires it; GitHub lets it be implicit).
    pub redirect_uri_required: bool,
    pub authorize_extra: &'static [(&'static str, &'static str)],
}

/// Look up the OAuth profile for a provider id, or `None` if unsupported.
pub fn provider_profile(provider: &str) -> Option<ProviderProfile> {
    match provider {
        // GitHub OAuth apps require the client_secret, don't support PKCE, and let
        // the registered callback be implicit (no redirect_uri on the request).
        "github" => Some(ProviderProfile {
            token_url: "https://github.com/login/oauth/access_token",
            uses_pkce: false,
            redirect_uri_required: false,
            authorize_extra: &[],
        }),
        // Google (Desktop client): PKCE + offline for a refresh token, and it
        // REQUIRES redirect_uri on both authorize + token (must match registered).
        "google" => Some(ProviderProfile {
            token_url: "https://oauth2.googleapis.com/token",
            uses_pkce: true,
            redirect_uri_required: true,
            authorize_extra: &[("access_type", "offline"), ("prompt", "consent")],
        }),
        _ => None,
    }
}

/// The OAuth callback URL the runtime serves for `provider` (`/oauth/callback/<provider>`),
/// used as `redirect_uri` for providers that require it. Base from
/// `GREENTIC_PUBLIC_BASE_URL` (set this for ngrok/public), else the loopback default.
pub fn callback_redirect_uri(provider: &str) -> String {
    let base = std::env::var("GREENTIC_PUBLIC_BASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string());
    format!("{}/oauth/callback/{provider}", base.trim_end_matches('/'))
}

// --- PKCE verifier store ----------------------------------------------------
// The verifier is generated when the consent URL is built and must NOT travel the
// front channel, so we hold it server-side keyed by the state's `jti` until the
// callback exchanges the code. In-process + TTL'd (a dev runtime is single-process).
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

fn verifier_store() -> &'static Mutex<HashMap<String, (String, Instant)>> {
    static S: OnceLock<Mutex<HashMap<String, (String, Instant)>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Stash a PKCE verifier under the state `jti` (evicts entries older than 10 min).
pub fn store_verifier(jti: &str, verifier: &str) {
    let mut m = verifier_store().lock().expect("verifier store poisoned");
    let now = Instant::now();
    m.retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(600));
    m.insert(jti.to_string(), (verifier.to_string(), now));
}

/// Take (consume) the PKCE verifier for a state `jti`, if present.
pub fn take_verifier(jti: &str) -> Option<String> {
    verifier_store()
        .lock()
        .expect("verifier store poisoned")
        .remove(jti)
        .map(|(v, _)| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_s256_of_verifier() {
        let p = pkce();
        assert_eq!(p.verifier.len(), 43); // 32 bytes base64url-no-pad
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(p.verifier.as_bytes()));
        assert_eq!(p.challenge, expected);
        // distinct each call
        assert_ne!(pkce().verifier, p.verifier);
    }

    #[test]
    fn consent_url_has_pkce_offline_and_scopes() {
        let url = build_consent_url(
            "https://accounts.google.com/o/oauth2/v2/auth",
            "client-123",
            &[
                "https://www.googleapis.com/auth/spreadsheets.readonly".to_string(),
                "openid".to_string(),
            ],
            None,
            "signed-state",
            Some("chal"),
            &[("access_type", "offline"), ("prompt", "consent")],
        );
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=client-123"));
        assert!(url.contains("state=signed-state"));
        assert!(url.contains("code_challenge=chal"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("access_type=offline"));
        assert!(url.contains("prompt=consent"));
        // scopes space-joined then percent-encoded
        assert!(url.contains(
            "scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fspreadsheets.readonly%20openid"
        ));
        assert!(!url.contains("redirect_uri")); // omitted -> app default callback
    }

    #[test]
    fn enc_encodes_reserved() {
        assert_eq!(enc("a b/c?"), "a%20b%2Fc%3F");
        assert_eq!(enc("safe-_.~"), "safe-_.~");
    }
}
