//! DirectLine JWT types and verification logic shared by both the legacy
//! `http_ingress` server and the revision-path `revision_serve` runtime.
//!
//! Hoisted from `http_ingress/helpers.rs` (A.1) so the WebSocket upgrade
//! handler can import these types from a top-level module without reaching
//! into the legacy ingress.

use serde::Deserialize;

/// Nested context block carried inside DirectLine JWTs issued by the
/// `messaging-provider-webchat` WASM component.
#[derive(Debug, Deserialize)]
pub struct DirectLineTokenContext {
    #[serde(default)]
    pub env: Option<String>,
    pub tenant: String,
    #[serde(default)]
    pub team: Option<String>,
}

/// DirectLine JWT claims as actually issued by the WASM provider.
/// Mirror of `messaging_provider_webchat::directline::jwt::TokenClaims`:
/// `{ iss, aud, sub: <user_id>, iat, nbf, exp, ctx: { env, tenant, team }, conv: <conv_id> }`.
#[derive(Debug, Deserialize)]
pub struct DirectLineTokenClaims {
    pub sub: String, // user_id (NOT conversation_id; conversation lives in `conv`)
    pub exp: i64,
    pub ctx: DirectLineTokenContext,
    #[serde(default)]
    pub conv: Option<String>,
}

// Variants are surfaced by the WS upgrade handler (Task 9). Until that lands
// they are only consumed in tests, so silence dead_code warnings on the lib build.
#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum TokenVerifyError {
    #[error("malformed token")]
    Malformed,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("token expired")]
    Expired,
    #[error("conversation mismatch")]
    ConversationMismatch,
    #[error("tenant mismatch")]
    TenantMismatch,
    #[error("missing signing key")]
    MissingKey,
}

/// Verify a DirectLine JWT and check it matches the expected route context.
/// Returns the parsed claims on success.
///
/// `signing_key` is the same shared secret the WASM provider uses to sign
/// (loaded from secrets capability under `jwt_signing_key`).
// Consumed by tests today; the WS upgrade handler (Task 9) will call it next.
#[allow(dead_code)]
pub fn verify_directline_token(
    token: &str,
    expected_conv_id: &str,
    expected_tenant: &str,
    signing_key: &[u8],
) -> Result<DirectLineTokenClaims, TokenVerifyError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(TokenVerifyError::Malformed);
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| TokenVerifyError::Malformed)?;

    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(signing_key)
        .map_err(|_| TokenVerifyError::MissingKey)?;
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&signature_bytes)
        .map_err(|_| TokenVerifyError::InvalidSignature)?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| TokenVerifyError::Malformed)?;
    let claims: DirectLineTokenClaims =
        serde_json::from_slice(&payload_bytes).map_err(|_| TokenVerifyError::Malformed)?;

    let now = chrono::Utc::now().timestamp();
    if claims.exp < now {
        return Err(TokenVerifyError::Expired);
    }
    let bound_conv = claims
        .conv
        .as_deref()
        .ok_or(TokenVerifyError::ConversationMismatch)?;
    if bound_conv != expected_conv_id {
        return Err(TokenVerifyError::ConversationMismatch);
    }
    if claims.ctx.tenant != expected_tenant {
        return Err(TokenVerifyError::TenantMismatch);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    fn make_token(claims_json: &str, key: &[u8]) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());
        let signing_input = format!("{header}.{payload}");
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
        mac.update(signing_input.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{signing_input}.{sig}")
    }

    fn make_claims(conv: &str, tenant: &str, exp: i64) -> String {
        format!(
            r#"{{"sub":"user1","exp":{exp},"ctx":{{"env":"prod","tenant":"{tenant}"}},"conv":"{conv}"}}"#
        )
    }

    #[test]
    fn valid_token_passes() {
        let key = b"test-key";
        let exp = chrono::Utc::now().timestamp() + 60;
        let token = make_token(&make_claims("conv1", "t1", exp), key);
        let result = verify_directline_token(&token, "conv1", "t1", key);
        assert!(result.is_ok(), "got {:?}", result);
    }

    #[test]
    fn expired_token_rejected() {
        let key = b"test-key";
        let exp = chrono::Utc::now().timestamp() - 1;
        let token = make_token(&make_claims("conv1", "t1", exp), key);
        assert!(matches!(
            verify_directline_token(&token, "conv1", "t1", key),
            Err(TokenVerifyError::Expired)
        ));
    }

    #[test]
    fn wrong_conv_rejected() {
        let key = b"test-key";
        let exp = chrono::Utc::now().timestamp() + 60;
        let token = make_token(&make_claims("convX", "t1", exp), key);
        assert!(matches!(
            verify_directline_token(&token, "conv1", "t1", key),
            Err(TokenVerifyError::ConversationMismatch)
        ));
    }

    #[test]
    fn missing_conv_rejected() {
        let key = b"test-key";
        let exp = chrono::Utc::now().timestamp() + 60;
        // No `conv` field at all (e.g. an unbound bootstrap token).
        let claims =
            format!(r#"{{"sub":"user1","exp":{exp},"ctx":{{"env":"prod","tenant":"t1"}}}}"#);
        let token = make_token(&claims, key);
        assert!(matches!(
            verify_directline_token(&token, "conv1", "t1", key),
            Err(TokenVerifyError::ConversationMismatch)
        ));
    }

    #[test]
    fn wrong_tenant_rejected() {
        let key = b"test-key";
        let exp = chrono::Utc::now().timestamp() + 60;
        let token = make_token(&make_claims("conv1", "tX", exp), key);
        assert!(matches!(
            verify_directline_token(&token, "conv1", "t1", key),
            Err(TokenVerifyError::TenantMismatch)
        ));
    }

    #[test]
    fn invalid_signature_rejected() {
        let key = b"test-key";
        let exp = chrono::Utc::now().timestamp() + 60;
        let token = make_token(&make_claims("conv1", "t1", exp), key);
        assert!(matches!(
            verify_directline_token(&token, "conv1", "t1", b"different-key"),
            Err(TokenVerifyError::InvalidSignature)
        ));
    }
}
