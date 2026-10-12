//! Who may call `POST /mcp` (worker-interop contract D2).
//!
//! TWO credentials are accepted and only one is advertised:
//!
//! - an **OAuth 2.1 access token** (RS256 JWT) minted by the tenant's
//!   authorization server — what the RFC 9728 document and the `401`'s
//!   `WWW-Authenticate` point a client at, because Claude.ai's connector has
//!   no header field and Cursor ignores headers once OAuth is advertised;
//! - the **A2A bearer** staged for the unit, accepted server-side so an
//!   operator's own script (and anything already holding that token) can call
//!   the same surface. It is deliberately NOT advertised: moving clients from
//!   bearer to OAuth later would be a breaking change, so OAuth ships as the
//!   published contract from the start.
//!
//! The bearer is tried FIRST because it costs one hash compare and no I/O; a
//! JWT never matches a staged hash, so the order changes no outcome. Both
//! yield a caller key, which is the rate limiter's bucket and the conversation
//! namespace: the `sub` for OAuth (minted per authorization, so per
//! connection) and the credential id for a bearer.
//!
//! Fail CLOSED everywhere. The one outcome that is not a `401` is an issuer
//! that could not be reached to verify a token at all — nothing is known to be
//! wrong with the caller's credential there, and a `401` would send it off to
//! re-authenticate against the very thing not answering.

use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde::Deserialize;

use super::jwks;
use crate::interop::config::InteropConfig;

/// The claims this resource server consumes. Extra claims are ignored.
#[derive(Debug, Deserialize)]
struct McpClaims {
    sub: String,
    /// The tenant SLUG, which MUST equal the unit's staged `tenant_slug`.
    tenant: String,
}

/// Who the request authenticated as. One type for both interop surfaces; see
/// [`crate::interop::caller::Caller`].
pub(crate) use crate::interop::caller::Caller as McpCaller;

/// What the gate decided.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum McpAuth {
    Allowed(McpCaller),
    /// `401`, with the metadata URL in `WWW-Authenticate`.
    Unauthorized,
    /// `503`: the authorization server could not be reached to verify a token
    /// that is otherwise well-formed.
    IssuerUnavailable,
}

/// The gate with the unit's own policy and the A2A bearer's rules, for the
/// tests that predate the shared [`crate::interop::auth::authenticate`]. A
/// test unit is private, so no client label is needed.
#[cfg(test)]
pub(crate) async fn authenticate(
    config: &InteropConfig,
    resource: Option<&str>,
    authorization: Option<&str>,
    now_ms: u64,
) -> McpAuth {
    crate::interop::auth::authenticate(config, resource, authorization, now_ms, "test").await
}

/// The OAuth half. Every refusal is the same `401` to the caller; the detail
/// goes to the log.
pub(crate) async fn verify_oauth(
    config: &InteropConfig,
    resource: Option<&str>,
    authorization: Option<&str>,
) -> McpAuth {
    // No issuer staged means this unit has no authorization server, and no
    // resource identifier means there is no audience to check a token
    // against. Either way no JWT can be verified here, so refuse rather than
    // guess one — a caller holding the staged A2A bearer has already been
    // admitted above and is unaffected.
    let (Some(issuer), Some(tenant_slug), Some(resource)) = (
        config.issuer.as_deref(),
        config.tenant_slug.as_deref(),
        resource,
    ) else {
        return McpAuth::Unauthorized;
    };
    let Some(token) = bearer_token(authorization) else {
        return McpAuth::Unauthorized;
    };
    let Ok(header) = decode_header(token) else {
        return McpAuth::Unauthorized;
    };
    let Some(kid) = header.kid else {
        return McpAuth::Unauthorized;
    };
    let key = match jwks::decoding_key(issuer, &kid).await {
        jwks::KeyLookup::Found(key) => key,
        // The issuer's key set was read and carries no such key: a fact about
        // the token, so the caller is told its credential is not valid.
        jwks::KeyLookup::UnknownKid => return McpAuth::Unauthorized,
        // Could not verify at all — not the caller's fault, and a `401` would
        // send it to re-authenticate against the issuer that is not answering.
        jwks::KeyLookup::Unavailable => return McpAuth::IssuerUnavailable,
    };

    // The algorithm comes from OUR validation, never from the token's own
    // header: honouring a caller-declared `alg` is how the `none` and
    // RS256→HS256 confusion attacks land.
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[resource]);
    // BOTH spellings of the issuer origin. A `url::Url` round-trip adds the
    // trailing slash and `set_issuer` is an exact string match, so an admin
    // minting `iss: "https://admin.example/"` would otherwise have every one
    // of its tokens refused with nothing naming a one-character difference.
    // The two strings denote the same origin, so accepting both removes a
    // cross-repo requirement rather than documenting one.
    let issuer_trimmed = issuer.trim_end_matches('/').to_string();
    let issuer_with_slash = format!("{issuer_trimmed}/");
    validation.set_issuer(&[issuer_trimmed.as_str(), issuer_with_slash.as_str()]);
    validation.validate_exp = true;
    // `jsonwebtoken` defaults `leeway` to SIXTY seconds. Five is enough for
    // clock skew between two NTP-synced hosts and short enough that "expired"
    // means expired.
    validation.leeway = 5;
    // `set_audience`/`set_issuer` alone do not reject a token that OMITS the
    // claim — they compare it when present.
    validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);

    let Ok(data) = decode::<McpClaims>(token, &key, &validation) else {
        return McpAuth::Unauthorized;
    };
    // The `sub` is the rate-limit bucket AND the caller segment of every
    // session hint this connection produces, so it obeys the same rule a
    // staged credential id does. A blank one would share both with every
    // other blank-subject token; one carrying a COLON would let subject `u1`
    // reach subject `u1:x`'s conversations by asking for `x:<their id>` (see
    // `crate::interop::valid_caller_key`). Neither is the caller's doing —
    // the token is signed — which is exactly why an issuer bug must refuse
    // rather than degrade. A service client's `svc:<id>@<tenant>` subject is
    // the one accepted exception, and it is MAPPED, not admitted as-is.
    let Some(caller_key) = caller_key_for_sub(&data.claims.sub, tenant_slug) else {
        crate::operator_log::warn(
            module_path!(),
            "MCP: a validly-signed token carried a `sub` that is empty, too long, or \
             outside [A-Za-z0-9_-] (and not a service-client subject); refusing rather \
             than namespacing a session with it",
        );
        return McpAuth::Unauthorized;
    };
    // The tenant claim is the cross-tenant boundary: a token minted for
    // another workspace must not run a turn here, however valid its signature.
    if data.claims.tenant.trim() != tenant_slug.trim() {
        crate::operator_log::warn(
            module_path!(),
            "MCP: a validly-signed token named another tenant; refusing",
        );
        return McpAuth::Unauthorized;
    }
    McpAuth::Allowed(McpCaller::Oauth(caller_key))
}

/// The caller key an OAuth `sub` namespaces its sessions under.
///
/// A user `sub` is its own key when it passes
/// [`crate::interop::valid_caller_key`]. A service client's subject,
/// `svc:<client_id>@<tenant_slug>` (access-policy spec §5.2), contains a colon
/// and so can never pass it: a colon in a caller key is what lets two
/// different `(caller, conversation)` pairs build one session hint. It is
/// mapped to `svc~<client_id>~<tenant_slug>` instead. `~` is outside the
/// alphabet every other key obeys, so the mapped key cannot equal any user's,
/// and it has no colon, so the hint stays injective. The slug in the subject
/// must be this unit's own tenant: a service token for another workspace is
/// refused even though its `tenant` claim was checked separately.
pub(crate) fn caller_key_for_sub(sub: &str, tenant_slug: &str) -> Option<String> {
    let sub = sub.trim();
    if crate::interop::valid_caller_key(sub) {
        return Some(sub.to_string());
    }
    let (client_id, slug) = sub.strip_prefix("svc:")?.split_once('@')?;
    (crate::interop::valid_caller_key(client_id)
        && crate::interop::valid_caller_key(slug)
        && slug == tenant_slug.trim())
    .then(|| format!("svc~{client_id}~{slug}"))
}

/// The token of an `Authorization: Bearer <token>` header. The scheme is
/// case-insensitive (RFC 7235); an empty token is no token. Only
/// `Authorization` is ever read — a cookie fallback here would make the
/// surface drivable cross-origin by any logged-in browser.
pub(crate) fn bearer_token(authorization: Option<&str>) -> Option<&str> {
    let raw = authorization?.trim();
    let (scheme, token) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod auth_tests;
