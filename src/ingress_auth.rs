//! Bearer authentication for the generic JSON ingress and the interop paths
//! (worker-interop contract D1 and D7).
//!
//! Until this module, the generic JSON branch of the revision ingress ran a
//! flow turn for ANY remote caller. On Cloud Run the service is public by
//! default, so that branch was an unauthenticated turn runner on the internet.
//! No legitimate remote caller of it exists — the designer, the deployer and
//! the e2e suites all use loopback or GET probes — so D7 closes it for every
//! deployment and every non-loopback peer, failing closed:
//!
//! | situation | answer |
//! |---|---|
//! | loopback-trusted peer | unchanged, no bearer needed |
//! | no config staged, or no credential in it | `401` |
//! | wrong, missing or expired token | `401` |
//! | the secrets backend cannot be read | `503` |
//! | a matching, unexpired credential | the request proceeds |
//!
//! The credential lives in the unit's staged interop config
//! ([`crate::interop::config`]), read from
//! `secrets://<env>/<tenant>/_/ingress/<canonical(bundle id)>` — see
//! [`ingress_secret_uri`]. Only SHA-256 hashes are staged; the presented token
//! is hashed and compared in constant time.
//!
//! `GREENTIC_GENERIC_INGRESS_AUTH=off` is a HOST-LOCAL escape hatch for the
//! generic branch only. It never reaches the interop paths, which always need
//! a bearer.

use greentic_secrets_lib::SecretsManager;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::interop::config::{self, InteropConfig};
use crate::operator_log;

/// The secrets category every unit's interop config is staged under.
pub(crate) const INGRESS_SECRET_CATEGORY: &str = "ingress";

/// The env var that switches the generic-ingress gate off for one host.
pub(crate) const GENERIC_INGRESS_AUTH_ENV: &str = "GREENTIC_GENERIC_INGRESS_AUTH";

/// The URI a unit's interop config is read from.
///
/// `tenant` is the DEPLOYMENT's tenant — the same string every other secret
/// this workload reads is scoped by, and on a remote (Cloud Run / k8s) runtime
/// the `default` the designer stages under. The team is always the `_`
/// placeholder. The name is the unit's bundle id through the ecosystem-wide
/// [`crate::secret_name::canonical_secret_name`] (via
/// [`crate::secrets_gate::canonical_secret_uri`]), the same function the
/// deployer's `op secrets put` applies, so a producer and this reader cannot
/// derive the name differently.
pub(crate) fn ingress_secret_uri(env: &str, tenant: &str, bundle_id: &str) -> String {
    crate::secrets_gate::canonical_secret_uri(env, tenant, None, INGRESS_SECRET_CATEGORY, bundle_id)
}

/// Why the unit's config could not be decided. Only a READ failure lands here:
/// a config that is absent, or present but unusable, is `Ok(None)`.
#[derive(Debug)]
pub(crate) struct ConfigUnavailable(pub String);

/// Read and parse one unit's staged interop config.
///
/// `Ok(None)` for "not staged" (the store answered not-found) and for a
/// document [`config::parse`] refuses. `Err` only when the store could not
/// answer, which the callers turn into `503`: treating an unreadable store as
/// "no config" would be harmless for the generic gate (it answers 401 either
/// way) but would silently un-reserve the interop paths, so the two stay
/// distinct. Mirrors `revision_serve::is_backend_failure`: anything but
/// `NotFound` is a failure, including `Permission`.
pub(crate) async fn load_unit_config(
    secrets: &dyn SecretsManager,
    env: &str,
    tenant: &str,
    bundle_id: &str,
) -> Result<Option<InteropConfig>, ConfigUnavailable> {
    let uri = ingress_secret_uri(env, tenant, bundle_id);
    match secrets.read(&uri).await {
        Ok(bytes) => Ok(config::parse(&bytes, bundle_id)),
        Err(greentic_secrets_lib::SecretError::NotFound(_)) => Ok(None),
        Err(err) => Err(ConfigUnavailable(err.to_string())),
    }
}

/// Why a presented bearer was refused. Deliberately coarse: the HTTP answer
/// carries the status only.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BearerRejection {
    /// The unit accepts no credential at all.
    NoCredentialConfigured,
    /// No `Authorization: Bearer …` header.
    Missing,
    /// A token that matches no live credential.
    Invalid,
}

/// Verify an `Authorization` header value against the config's credentials.
/// Returns the matching credential's id.
///
/// The token is hashed and the digest compared against EVERY credential with
/// `subtle`, so the time taken does not depend on which credential (if any)
/// matched or how many bytes of a guess were right. An expired credential is
/// never a match; the expiry itself is not secret.
pub(crate) fn verify_bearer<'a>(
    config: &'a InteropConfig,
    authorization: Option<&str>,
    now_ms: u64,
) -> Result<&'a str, BearerRejection> {
    if config.credentials.is_empty() {
        return Err(BearerRejection::NoCredentialConfigured);
    }
    let token = bearer_token(authorization).ok_or(BearerRejection::Missing)?;
    let presented: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    let mut matched: Option<&str> = None;
    for credential in &config.credentials {
        let equal = bool::from(credential.sha256.ct_eq(&presented));
        let live = credential
            .expires_at_ms
            .is_none_or(|expiry| now_ms < expiry);
        if equal && live && matched.is_none() {
            matched = Some(credential.id.as_str());
        }
    }
    matched.ok_or(BearerRejection::Invalid)
}

/// The token of an `Authorization: Bearer <token>` header. The scheme is
/// case-insensitive (RFC 7235); an empty token is no token.
fn bearer_token(authorization: Option<&str>) -> Option<&str> {
    let raw = authorization?.trim();
    let (scheme, token) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}

/// Milliseconds since the Unix epoch, saturating at 0 for a clock before it.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Parse `GREENTIC_GENERIC_INGRESS_AUTH`. Defensive: only an explicit
/// `off`/`false`/`0`/`no`/`disabled` (any case, surrounding whitespace ignored)
/// turns the gate off. Anything else — absent, empty, a typo — keeps it ON,
/// because a misspelled kill switch must never publish an unauthenticated
/// turn runner.
pub(crate) fn generic_ingress_auth_enabled(raw: Option<&str>) -> bool {
    let Some(raw) = raw else {
        return true;
    };
    !matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "off" | "false" | "0" | "no" | "disabled"
    )
}

/// Read the escape hatch from the process environment, logging once when it
/// is off so the choice is visible in the boot log.
pub(crate) fn generic_ingress_auth_enabled_from_env() -> bool {
    let raw = std::env::var(GENERIC_INGRESS_AUTH_ENV).ok();
    let enabled = generic_ingress_auth_enabled(raw.as_deref());
    if !enabled {
        operator_log::warn(
            module_path!(),
            format!(
                "{GENERIC_INGRESS_AUTH_ENV}=off: the generic JSON ingress accepts \
                 unauthenticated remote callers on this host"
            ),
        );
    }
    enabled
}

/// The generic-ingress gate's verdict.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GenericGate {
    /// Proceed with the turn.
    Allow,
    /// `401`: no credential configured, or the bearer does not match.
    Unauthorized,
    /// `503`: the store could not be read, so the answer is unknown.
    Unavailable,
}

/// Decide whether a request may run the generic JSON branch. Pure over its
/// inputs so every row of the module-level table is testable without a
/// listener.
pub(crate) fn decide_generic(
    peer_is_loopback: bool,
    gate_enabled: bool,
    config: &Result<Option<InteropConfig>, ConfigUnavailable>,
    authorization: Option<&str>,
    now_ms: u64,
) -> GenericGate {
    if peer_is_loopback || !gate_enabled {
        return GenericGate::Allow;
    }
    match config {
        Err(_) => GenericGate::Unavailable,
        Ok(None) => GenericGate::Unauthorized,
        Ok(Some(config)) => match verify_bearer(config, authorization, now_ms) {
            Ok(_) => GenericGate::Allow,
            Err(_) => GenericGate::Unauthorized,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interop::config::Credential;

    fn sha(token: &str) -> [u8; 32] {
        Sha256::digest(token.as_bytes()).into()
    }

    fn config_with(creds: &[(&str, &str, Option<u64>)]) -> InteropConfig {
        InteropConfig {
            credentials: creds
                .iter()
                .map(|(id, token, expiry)| Credential {
                    id: (*id).to_string(),
                    sha256: sha(token),
                    expires_at_ms: *expiry,
                })
                .collect(),
            ..InteropConfig::default()
        }
    }

    #[test]
    fn the_secret_uri_uses_the_ingress_category_and_the_canonical_bundle_id() {
        assert_eq!(
            ingress_secret_uri("prod", "default", "Support-Bot.v2"),
            "secrets://prod/default/_/ingress/support_bot_v2"
        );
    }

    #[test]
    fn a_matching_token_is_accepted_and_names_its_credential() {
        let config = config_with(&[("c1", "gtw_one", None), ("c2", "gtw_two", None)]);
        assert_eq!(verify_bearer(&config, Some("Bearer gtw_two"), 0), Ok("c2"));
        assert_eq!(verify_bearer(&config, Some("bearer gtw_one"), 0), Ok("c1"));
    }

    #[test]
    fn a_wrong_or_missing_token_is_refused() {
        let config = config_with(&[("c1", "gtw_one", None)]);
        assert_eq!(
            verify_bearer(&config, Some("Bearer gtw_nope"), 0),
            Err(BearerRejection::Invalid)
        );
        assert_eq!(
            verify_bearer(&config, None, 0),
            Err(BearerRejection::Missing)
        );
        assert_eq!(
            verify_bearer(&config, Some("Basic gtw_one"), 0),
            Err(BearerRejection::Missing)
        );
        assert_eq!(
            verify_bearer(&config, Some("Bearer "), 0),
            Err(BearerRejection::Missing)
        );
    }

    #[test]
    fn no_credential_refuses_everything() {
        let config = InteropConfig::default();
        assert_eq!(
            verify_bearer(&config, Some("Bearer anything"), 0),
            Err(BearerRejection::NoCredentialConfigured)
        );
    }

    #[test]
    fn an_expired_previous_credential_stops_working_at_its_expiry() {
        let config = config_with(&[("new", "gtw_new", None), ("old", "gtw_old", Some(1_000))]);
        assert_eq!(
            verify_bearer(&config, Some("Bearer gtw_old"), 999),
            Ok("old")
        );
        assert_eq!(
            verify_bearer(&config, Some("Bearer gtw_old"), 1_000),
            Err(BearerRejection::Invalid)
        );
        assert_eq!(
            verify_bearer(&config, Some("Bearer gtw_new"), 5_000),
            Ok("new")
        );
    }

    /// The comparison runs over fixed-length digests, never over the raw
    /// token, so a prefix of a real token is just another non-matching digest.
    #[test]
    fn the_comparison_path_compares_digests_not_tokens() {
        // A token that is a PREFIX of a credential's token must not match —
        // what a naive `starts_with`/early-exit byte compare gets wrong.
        let config = config_with(&[("c1", "gtw_abcdef", None)]);
        assert_eq!(
            verify_bearer(&config, Some("Bearer gtw_abc"), 0),
            Err(BearerRejection::Invalid)
        );
        // Duplicate hashes: the FIRST live one wins deterministically.
        let dup = config_with(&[("a", "gtw_x", Some(1)), ("b", "gtw_x", None)]);
        assert_eq!(verify_bearer(&dup, Some("Bearer gtw_x"), 10), Ok("b"));
    }

    #[test]
    fn the_escape_hatch_is_parsed_defensively() {
        assert!(generic_ingress_auth_enabled(None));
        assert!(generic_ingress_auth_enabled(Some("")));
        assert!(generic_ingress_auth_enabled(Some("of")));
        assert!(generic_ingress_auth_enabled(Some("on")));
        assert!(generic_ingress_auth_enabled(Some("enabled")));
        for off in ["off", "OFF", " Off ", "false", "0", "no", "disabled"] {
            assert!(!generic_ingress_auth_enabled(Some(off)), "{off}");
        }
    }

    #[test]
    fn the_generic_gate_table() {
        let config = config_with(&[("c1", "gtw_one", None)]);
        let ok: Result<Option<InteropConfig>, ConfigUnavailable> = Ok(Some(config));
        let absent: Result<Option<InteropConfig>, ConfigUnavailable> = Ok(None);
        let down: Result<Option<InteropConfig>, ConfigUnavailable> =
            Err(ConfigUnavailable("backend".into()));
        let good = Some("Bearer gtw_one");

        // Loopback and the host-local hatch are exempt, even with no config.
        assert_eq!(
            decide_generic(true, true, &absent, None, 0),
            GenericGate::Allow
        );
        assert_eq!(
            decide_generic(false, false, &down, None, 0),
            GenericGate::Allow
        );
        // Remote peers.
        assert_eq!(
            decide_generic(false, true, &ok, good, 0),
            GenericGate::Allow
        );
        assert_eq!(
            decide_generic(false, true, &ok, None, 0),
            GenericGate::Unauthorized
        );
        assert_eq!(
            decide_generic(false, true, &absent, good, 0),
            GenericGate::Unauthorized
        );
        assert_eq!(
            decide_generic(false, true, &down, good, 0),
            GenericGate::Unavailable
        );
    }
}
