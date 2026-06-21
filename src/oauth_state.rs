//! Signed OAuth `state` token for the bake-in card flow.
//!
//! greentic-start mints this when it surfaces the Connect card (it knows the run
//! context: pack/flow/tenant/team + scheme/provider from the card), and
//! `/oauth/callback` verifies it. Carrying the full context in a signed `state`
//! is the future-proof design: the pack-agnostic callback can resolve the right
//! pack-scoped `client_secret` + persist the token to the right key, for any
//! number of OAuth-declaring packs / providers / tenants — and the signature
//! gives CSRF protection. HS256, same primitive as the DirectLine token.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::OnceLock;

/// Everything the callback needs to resolve pack-scoped secrets + persist the token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthStateContext {
    /// App pack id (the secret scope segment), e.g. `github-review-pack`.
    pub pack: String,
    /// OpenAPI security-scheme name, e.g. `githubOAuth`.
    pub scheme: String,
    /// Provider id, e.g. `github`.
    pub provider: String,
    pub tenant: String,
    pub team: String,
    pub subject: String,
    /// Unique id binding a server-side PKCE verifier to this sign-in (empty when
    /// the provider doesn't use PKCE).
    #[serde(default)]
    pub jti: String,
    /// Expiry (unix seconds).
    pub exp: i64,
}

fn signing_key() -> &'static [u8] {
    static KEY: OnceLock<Vec<u8>> = OnceLock::new();
    KEY.get_or_init(|| {
        std::env::var("GREENTIC_OAUTH_STATE_KEY")
            .ok()
            .filter(|k| !k.is_empty())
            .map(String::into_bytes)
            // Dev default — fine for local; production should set the env/secret.
            .unwrap_or_else(|| b"greentic-oauth-state-signing-key-dev".to_vec())
    })
}

/// Mint a signed, URL-safe `state` token: `<base64url(json)>.<base64url(hmac)>`.
pub fn mint(ctx: &OAuthStateContext) -> String {
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(ctx).unwrap_or_default());
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(signing_key()).expect("hmac accepts any key len");
    mac.update(payload.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{payload}.{sig}")
}

/// Verify signature + expiry and return the context, else `None`.
pub fn verify(token: &str) -> Option<OAuthStateContext> {
    let (payload, sig) = token.split_once('.')?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig).ok()?;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(signing_key()).ok()?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&sig_bytes).ok()?;
    let ctx: OAuthStateContext =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    if ctx.exp < chrono::Utc::now().timestamp() {
        return None;
    }
    Some(ctx)
}

/// Normalize the team segment the way the secret scope does (`default`/empty → `_`).
pub fn team_segment(team: &str) -> String {
    let t = team.trim();
    if t.is_empty() || t.eq_ignore_ascii_case("default") {
        "_".to_string()
    } else {
        t.to_string()
    }
}

/// Canonicalize a logical secret key the way the runner host secret store does
/// (lowercase; non-alphanumeric → `_`). e.g. `auth.oauth2.githubOAuth.client_id`
/// → `auth_oauth2_githuboauth_client_id`.
pub fn canonical_secret_name(key: &str) -> String {
    key.trim()
        .chars()
        .map(|c| {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_then_verify_roundtrips() {
        let ctx = OAuthStateContext {
            pack: "github-review-pack".into(),
            scheme: "githubOAuth".into(),
            provider: "github".into(),
            tenant: "demo".into(),
            team: "_".into(),
            subject: "user".into(),
            jti: String::new(),
            exp: chrono::Utc::now().timestamp() + 600,
        };
        let tok = mint(&ctx);
        let got = verify(&tok).expect("valid");
        assert_eq!(got.pack, "github-review-pack");
        assert_eq!(got.scheme, "githubOAuth");
    }

    #[test]
    fn tampered_or_expired_rejected() {
        let mut ctx = OAuthStateContext {
            pack: "p".into(),
            scheme: "s".into(),
            provider: "github".into(),
            tenant: "demo".into(),
            team: "_".into(),
            subject: "user".into(),
            jti: String::new(),
            exp: chrono::Utc::now().timestamp() + 600,
        };
        let tok = mint(&ctx);
        assert!(
            verify(&format!("{tok}x")).is_none(),
            "tampered sig rejected"
        );
        ctx.exp = chrono::Utc::now().timestamp() - 1;
        assert!(verify(&mint(&ctx)).is_none(), "expired rejected");
    }

    #[test]
    fn canonical_matches_store() {
        assert_eq!(
            canonical_secret_name("auth.oauth2.githubOAuth.client_id"),
            "auth_oauth2_githuboauth_client_id"
        );
        assert_eq!(team_segment("default"), "_");
    }
}
