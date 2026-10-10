//! Microsoft Teams (Bot Framework) request verification.
//!
//! The Bot Framework Connector signs every activity it sends a bot with an
//! RS256 JWT in `Authorization: Bearer …`. This host checks it per the
//! connector authentication contract (public cloud only):
//!
//! 1. no bot app id configured → not configured (and no key fetch);
//! 2. the header is present, `Bearer`, non-empty and at most
//!    [`MAX_AUTH_HEADER_BYTES`];
//! 3. the token header names `alg: RS256` exactly and a `kid` — checked
//!    BEFORE any key lookup, so `none`, `HS256` key confusion and other
//!    families never reach the key set;
//! 4. the `kid` is in the Bot Framework key set (unreadable set → unavailable,
//!    never a failed proof);
//! 5. signature, `iss` = [`BF_ISSUER`], `aud` = the bot app id, `exp` / `nbf`
//!    within [`CLOCK_SKEW_SECS`];
//! 6. only now is the body parsed: the token's `serviceurl` claim must equal
//!    the activity's `serviceUrl`;
//! 7. the activity's `channelId` must be among the signing key's
//!    endorsements (`403` otherwise).

use std::collections::BTreeMap;

use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde_json::Value;

use super::RefusalCode;
use super::bf_keys::{BF_ISSUER, BfKeyLookup, BfKeySource};

/// Where the bot app id is read from the pack's non-secret config: what the
/// Teams setup wizard writes, then a generic fallback.
pub(crate) const APP_ID_KEYS: &[&str] = &["ms_bot_app_id", "bot_app_id"];
pub(crate) const CLOCK_SKEW_SECS: u64 = 300;
pub(crate) const MAX_AUTH_HEADER_BYTES: usize = 16 * 1024;

#[derive(Debug)]
pub(crate) enum BfOutcome {
    Verified,
    NotConfigured,
    Unavailable,
    Refused(RefusalCode),
}

/// The key set, as a trait so tests inject keys.
#[async_trait::async_trait]
pub(crate) trait BfKeys: Send + Sync {
    async fn key(&self, kid: &str) -> BfKeyLookup;
}

#[async_trait::async_trait]
impl BfKeys for BfKeySource {
    async fn key(&self, kid: &str) -> BfKeyLookup {
        BfKeySource::key(self, kid).await
    }
}

/// The first non-empty string among [`APP_ID_KEYS`].
pub(crate) fn configured_app_id(
    pack_non_secret: Option<&BTreeMap<String, Value>>,
) -> Option<String> {
    let config = pack_non_secret?;
    APP_ID_KEYS.iter().find_map(|key| {
        config
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

/// `keys` is `None` when no key source could be built (unavailable).
pub(crate) async fn check(
    app_id: Option<&str>,
    headers: &[(String, String)],
    body: &[u8],
    keys: Option<&dyn BfKeys>,
    now: u64,
) -> BfOutcome {
    let Some(app_id) = app_id else {
        return BfOutcome::NotConfigured;
    };
    let Some(token) = bearer(headers) else {
        return BfOutcome::Refused(RefusalCode::MissingToken);
    };
    let Ok(header) = decode_header(token) else {
        return BfOutcome::Refused(RefusalCode::BadToken);
    };
    if header.alg != Algorithm::RS256 {
        return BfOutcome::Refused(RefusalCode::BadToken);
    }
    let Some(kid) = header.kid.as_deref().filter(|kid| !kid.is_empty()) else {
        return BfOutcome::Refused(RefusalCode::BadToken);
    };
    let Some(keys) = keys else {
        return BfOutcome::Unavailable;
    };
    let key = match keys.key(kid).await {
        BfKeyLookup::Found(key) => key,
        BfKeyLookup::UnknownKid => return BfOutcome::Refused(RefusalCode::BadToken),
        BfKeyLookup::Unavailable => return BfOutcome::Unavailable,
    };
    let Ok(claims) = decode::<Value>(token, &key.key, &validation(app_id)).map(|data| data.claims)
    else {
        return BfOutcome::Refused(RefusalCode::TokenClaims);
    };
    if !within_clock(&claims, now) {
        return BfOutcome::Refused(RefusalCode::TokenClaims);
    }
    // The body is parsed only after the token proved itself.
    let Ok(activity) = serde_json::from_slice::<Value>(body) else {
        return BfOutcome::Refused(RefusalCode::TokenClaims);
    };
    let claim_url = claims
        .get("serviceurl")
        .or_else(|| claims.get("serviceUrl"))
        .and_then(Value::as_str);
    let activity_url = activity.get("serviceUrl").and_then(Value::as_str);
    match (claim_url, activity_url) {
        (Some(claim), Some(activity)) if same_service_url(claim, activity) => {}
        _ => return BfOutcome::Refused(RefusalCode::TokenClaims),
    }
    let channel = activity
        .get("channelId")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .filter(|channel| !channel.is_empty());
    let endorsed = channel.is_some_and(|channel| {
        key.endorsements
            .iter()
            .any(|endorsement| endorsement.to_ascii_lowercase() == channel)
    });
    if !endorsed {
        return BfOutcome::Refused(RefusalCode::Endorsement);
    }
    BfOutcome::Verified
}

/// Signature, `iss` and `aud` by the library; the clock is checked by
/// [`within_clock`] against the caller's `now`, so it is testable and uses the
/// same leeway both ways.
fn validation(app_id: &str) -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[BF_ISSUER]);
    validation.set_audience(&[app_id]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.leeway = CLOCK_SKEW_SECS;
    validation
}

fn within_clock(claims: &Value, now: u64) -> bool {
    let Some(exp) = numeric(claims.get("exp")) else {
        return false;
    };
    if exp.saturating_add(CLOCK_SKEW_SECS) < now {
        return false;
    }
    match claims.get("nbf") {
        None => true,
        Some(nbf) => {
            numeric(Some(nbf)).is_some_and(|nbf| nbf <= now.saturating_add(CLOCK_SKEW_SECS))
        }
    }
}

fn numeric(value: Option<&Value>) -> Option<u64> {
    let value = value?;
    value
        .as_u64()
        .or_else(|| value.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64))
}

fn same_service_url(claim: &str, activity: &str) -> bool {
    let strip = |url: &str| url.strip_suffix('/').unwrap_or(url).to_string();
    strip(claim.trim()) == strip(activity.trim())
}

/// The token from the first `Authorization` header, when it is a non-empty
/// `Bearer` value within [`MAX_AUTH_HEADER_BYTES`].
fn bearer(headers: &[(String, String)]) -> Option<&str> {
    let value = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.as_str())?;
    if value.len() > MAX_AUTH_HEADER_BYTES {
        return None;
    }
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?
        .trim();
    (!token.is_empty()).then_some(token)
}
