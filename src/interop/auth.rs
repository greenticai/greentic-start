//! The one credential gate behind `/a2a` and `/mcp` (access-policy spec §6.2).
//!
//! What a request may present is decided by the unit's staged
//! [`AccessPolicy`](super::config::AccessPolicy):
//!
//! - a **private** unit needs a credential, of a mechanism the policy lists;
//! - a **public** unit serves a request that presents NO credential as
//!   anonymous, within its limits.
//!
//! **A credential that is presented and does not verify is a refusal, on a
//! public unit too.** Falling back to anonymous would bill a typo in a
//! client's key as a public call and hide it; the caller learns about it
//! from the `401` instead. Two exceptions are deliberate and narrow, both
//! about what counts as "presented":
//!
//! - an empty `Authorization` header is no credential;
//! - a token that is a Direct Line (HS256) token is not a credential for this
//!   surface at all. Webchat holds one for its own conversation and a browser
//!   can send it anywhere; it identifies nobody here, so it is treated as
//!   absent — refused on a private unit, anonymous on a public one, and
//!   never an identity. See [`is_direct_line_token`].

use jsonwebtoken::{Algorithm, decode_header};

use super::caller::Caller;
use super::config::{InteropConfig, Mechanism, Visibility};
use super::mcp::auth::{McpAuth, bearer_token, verify_oauth};

/// What the gate decided. The same type for both surfaces.
pub(crate) type Auth = McpAuth;

/// What the request put in `Authorization`.
enum Presented<'a> {
    /// Nothing, or only whitespace.
    Nothing,
    /// Something that is not `Bearer <token>`.
    Malformed,
    Token(&'a str),
}

fn presented(authorization: Option<&str>, unreadable: bool) -> Presented<'_> {
    // A header that is there but is not text (non-ASCII bytes) is a credential
    // the caller tried to present, not an absent one: on a public unit it must
    // be a 401, not anonymous.
    if unreadable {
        return Presented::Malformed;
    }
    match authorization.map(str::trim) {
        None | Some("") => Presented::Nothing,
        Some(_) => match bearer_token(authorization) {
            Some(token) => Presented::Token(token),
            None => Presented::Malformed,
        },
    }
}

/// Whether `token` is a JWT signed with an HMAC algorithm.
///
/// Direct Line tokens are HS256 under the provider's `jwt_signing_key`. Our
/// authorization server signs RS256, and the verifier fixes the algorithm on
/// OUR side, so such a token could never verify; this exists only to say what
/// the gate does with one — see the module docs.
pub(crate) fn is_direct_line_token(token: &str) -> bool {
    decode_header(token).is_ok_and(|header| {
        matches!(
            header.alg,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        )
    })
}

/// Whether this unit can verify an OAuth token on a surface whose audience is
/// `audience`: it needs an issuer, a tenant and an audience.
fn oauth_available(config: &InteropConfig, audience: Option<&str>) -> bool {
    config.issuer.is_some() && config.tenant_slug.is_some() && audience.is_some()
}

/// Authenticate one interop request.
///
/// `audience` is the surface's own resource URL (`mcp_resource` or
/// `a2a_resource`). **The policy is strict**: a mechanism the policy does not
/// list is never accepted, and OAuth that cannot be verified on this surface
/// (no issuer, tenant or audience) is a refusal, not a reason to accept the
/// staged bearer instead. The designer guarantees it stages an OAuth-only
/// policy only together with what OAuth needs; a document that breaks that is
/// refused (and logged once) rather than quietly weakened. The default policy
/// (no `access` block) lists both mechanisms, so its bearer is accepted
/// whether or not OAuth is available, exactly as before the policy existed.
/// `client` labels the peer for an anonymous caller. `unreadable` says the
/// request carried an `Authorization` header that could not be read as text.
pub(crate) async fn authenticate(
    config: &InteropConfig,
    audience: Option<&str>,
    authorization: Option<&str>,
    unreadable: bool,
    now_ms: u64,
    client: &str,
) -> Auth {
    let public = config.access.visibility == Visibility::Public;
    let anonymous = || McpAuth::Allowed(Caller::anonymous(client));
    let token = match presented(authorization, unreadable) {
        Presented::Nothing => {
            return if public {
                anonymous()
            } else {
                McpAuth::Unauthorized
            };
        }
        Presented::Malformed => return McpAuth::Unauthorized,
        Presented::Token(token) => token,
    };
    if is_direct_line_token(token) {
        return if public {
            anonymous()
        } else {
            McpAuth::Unauthorized
        };
    }
    if !config.access.allows(Mechanism::ApiKey) && !oauth_available(config, audience) {
        // OAuth-only, and OAuth cannot run here: nothing can authenticate.
        log_unusable_policy_once(config, audience);
        return McpAuth::Unauthorized;
    }
    // Cheap first: a staged credential is a constant-time hash compare with no
    // I/O, and a JWT cannot match one.
    if config.access.allows(Mechanism::ApiKey)
        && let Ok(id) = crate::ingress_auth::verify_bearer(config, authorization, now_ms)
    {
        return McpAuth::Allowed(Caller::Bearer(id.to_string()));
    }
    if config.access.allows(Mechanism::Oauth) {
        return verify_oauth(config, audience, authorization).await;
    }
    McpAuth::Unauthorized
}

/// Say once per unit and surface why an OAuth-only policy refuses everyone.
fn log_unusable_policy_once(config: &InteropConfig, audience: Option<&str>) {
    use std::collections::HashSet;
    use std::sync::{LazyLock, Mutex};
    static SAID: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(Mutex::default);
    let key = format!(
        "{}|{}|{}",
        config.tenant_slug.as_deref().unwrap_or(""),
        config.issuer.as_deref().unwrap_or(""),
        audience.unwrap_or("")
    );
    let first = SAID
        .lock()
        .is_ok_and(|mut said| said.len() < 1024 && said.insert(key));
    if first {
        let missing: Vec<&str> = [
            ("issuer", config.issuer.is_none()),
            ("tenant_slug", config.tenant_slug.is_none()),
            ("the surface's resource URL", audience.is_none()),
        ]
        .iter()
        .filter_map(|(name, absent)| absent.then_some(*name))
        .collect();
        crate::operator_log::error(
            module_path!(),
            format!(
                "interop: this unit's access policy allows only OAuth but the document does not \
                 stage what OAuth needs (missing: {}); every request is refused",
                missing.join(", ")
            ),
        );
    }
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod auth_tests;
