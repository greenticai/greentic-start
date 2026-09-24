//! Exposing a deployed worker to other agents (worker-interop contract).
//!
//! The runtime half of the contract: the staged per-unit config
//! ([`config`]) and the process-wide state the interop surfaces share.
//! Authentication of the generic ingress lives in [`crate::ingress_auth`].

pub(crate) mod a2a;
pub(crate) mod config;
pub(crate) mod config_cache;
pub(crate) mod input_request;
pub(crate) mod limits;
pub(crate) mod mcp;
pub(crate) mod metering;
pub(crate) mod reply;

/// Longest caller key accepted. A caller key is a session-namespace segment
/// AND a rate-limit map key, so it is bounded on both counts.
pub(crate) const MAX_CALLER_KEY_LEN: usize = 128;

/// Whether `key` may be used as the CALLER segment of a session hint.
///
/// `[A-Za-z0-9_-]`, non-empty, at most [`MAX_CALLER_KEY_LEN`]. The excluded
/// character that matters is the COLON: [`session_hint`] joins the caller and
/// the conversation with one, and a caller key that could contain a colon
/// makes two different pairs produce the same hint — `("u1", "x:conv")` and
/// `("u1:x", "conv")` — which is one caller resuming another's parked flow.
/// A conversation id may contain colons precisely because the caller segment
/// cannot: the first colon after the protocol always ends the caller.
///
/// Applied to BOTH caller kinds: a staged credential id (the designer writes
/// it) and an OAuth `sub` (the authorization server writes it, and a
/// compromised or careless one must not be able to mint a colliding subject).
pub(crate) fn valid_caller_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_CALLER_KEY_LEN
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// Build the session hint one turn runs under: `<protocol>:<caller>:<id>`.
///
/// The ONE place the namespace is spelled, so the A2A and MCP surfaces cannot
/// drift into different escaping rules. `caller` must have passed
/// [`valid_caller_key`]; see there for why that is what makes the namespace
/// injective.
pub(crate) fn session_hint(protocol: &str, caller: &str, conversation: &str) -> String {
    format!("{protocol}:{caller}:{conversation}")
}

/// A test-only replacement for running a turn against a loaded revision, so
/// listener-level tests can drive the whole ingress without a WASM pack.
#[cfg(test)]
pub(crate) type TurnOverride = std::sync::Arc<
    dyn Fn(&greentic_runner_host::Activity) -> Vec<greentic_runner_host::Activity> + Send + Sync,
>;

/// Interop state shared by every connection of one revision listener.
pub(crate) struct InteropState {
    /// `false` only when the host-local `GREENTIC_GENERIC_INGRESS_AUTH=off`
    /// escape hatch is set. Resolved once at boot.
    pub generic_auth_enabled: bool,
    /// The public base URL resolved at boot
    /// (`startup_contract::resolve_public_base_url`), when one was known
    /// there. On Cloud Run it is not: the listener's deferred
    /// [`crate::revision_serve::PublicUrlCapture`] supplies it instead. Never
    /// the request's own `Host` header, which any caller controls.
    pub public_base_url: Option<String>,
    /// A short TTL over each unit's staged config, so an authenticated
    /// surface does not read the secrets store on every request.
    pub configs: config_cache::UnitConfigCache,
    /// Per-credential token buckets, shared by every interop surface so one
    /// caller's budget is the same whichever binding it uses.
    pub limiter: std::sync::Arc<limits::RateLimiter>,
    /// The per-deployment concurrent-turn cap. `Arc` because the MCP tool
    /// runs inside an `rmcp` handler that outlives the request borrow.
    pub turns: std::sync::Arc<limits::TurnGate>,
    /// The bounded queue interop turns record their usage on. Process-wide
    /// because the bound is what matters; each event carries its own unit's
    /// endpoint. See [`metering`].
    pub meter: std::sync::Arc<metering::Meter>,
    /// See [`TurnOverride`].
    #[cfg(test)]
    pub turn_override: Option<TurnOverride>,
}

impl InteropState {
    /// Production state: the escape hatch read from the environment, plus the
    /// boot-resolved public base URL.
    pub(crate) fn from_env(public_base_url: Option<String>) -> Self {
        Self {
            generic_auth_enabled: crate::ingress_auth::generic_ingress_auth_enabled_from_env(),
            public_base_url,
            configs: config_cache::UnitConfigCache::default(),
            limiter: std::sync::Arc::new(limits::RateLimiter::default()),
            turns: std::sync::Arc::new(limits::TurnGate::new(limits::max_concurrent_turns(
                std::env::var(limits::MAX_CONCURRENT_TURNS_ENV)
                    .ok()
                    .as_deref(),
            ))),
            meter: std::sync::Arc::new(metering::Meter::default()),
            #[cfg(test)]
            turn_override: None,
        }
    }
}

impl Default for InteropState {
    /// The gate ON — the safe default every test starts from.
    fn default() -> Self {
        Self {
            generic_auth_enabled: true,
            public_base_url: None,
            configs: config_cache::UnitConfigCache::default(),
            limiter: std::sync::Arc::new(limits::RateLimiter::default()),
            turns: std::sync::Arc::new(limits::TurnGate::new(limits::DEFAULT_MAX_CONCURRENT_TURNS)),
            meter: std::sync::Arc::new(metering::Meter::default()),
            #[cfg(test)]
            turn_override: None,
        }
    }
}

#[cfg(test)]
#[path = "live_e2e_tests.rs"]
mod live_e2e;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_caller_key_is_bounded_and_colon_free() {
        assert!(valid_caller_key("c_01J"));
        assert!(valid_caller_key("u-test-1"));
        assert!(valid_caller_key(&"a".repeat(MAX_CALLER_KEY_LEN)));
        assert!(!valid_caller_key(""));
        assert!(!valid_caller_key(&"a".repeat(MAX_CALLER_KEY_LEN + 1)));
        for bad in ["a:b", "a b", "a/b", "a.b", "é", "a\nb"] {
            assert!(!valid_caller_key(bad), "{bad}");
        }
    }

    /// The attack the caller-key alphabet exists to stop: subject `u1` asking
    /// for conversation `x:<victim>` must NOT land in subject `u1:x`'s
    /// namespace. It cannot, because `u1:x` is not an acceptable caller key —
    /// so the colliding hint is unreachable from the other side.
    #[test]
    fn two_callers_cannot_be_made_to_share_a_namespace() {
        let victim = session_hint("mcp", "u1x", "conv");
        let attacker = session_hint("mcp", "u1", "x:conv");
        assert_ne!(victim, attacker);
        // The only spelling that WOULD collide is a caller key with a colon,
        // and that is refused before a hint is ever built.
        assert_eq!(session_hint("mcp", "u1:x", "conv"), attacker);
        assert!(!valid_caller_key("u1:x"));
    }

    /// A conversation id may carry colons: the caller segment cannot, so the
    /// first colon after the protocol always ends the caller and the rest is
    /// the conversation, whatever it contains.
    #[test]
    fn a_conversation_id_may_contain_colons_without_ambiguity() {
        let hint = session_hint("a2a", "c1", "a:b:c");
        assert_eq!(hint, "a2a:c1:a:b:c");
        let (protocol, rest) = hint.split_once(':').expect("protocol");
        let (caller, conversation) = rest.split_once(':').expect("caller");
        assert_eq!((protocol, caller, conversation), ("a2a", "c1", "a:b:c"));
    }
}
