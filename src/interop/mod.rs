//! Exposing a deployed worker to other agents (worker-interop contract).
//!
//! The runtime half of the contract: the staged per-unit config
//! ([`config`]) and the process-wide state the interop surfaces share.
//! Authentication of the generic ingress lives in [`crate::ingress_auth`].

pub(crate) mod a2a;
pub(crate) mod config;
pub(crate) mod limits;
pub(crate) mod reply;

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
    /// Per-credential token buckets, shared by every interop surface so one
    /// caller's budget is the same whichever binding it uses.
    pub limiter: limits::RateLimiter,
    /// The per-deployment concurrent-turn cap.
    pub turns: limits::TurnGate,
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
            limiter: limits::RateLimiter::default(),
            turns: limits::TurnGate::new(limits::max_concurrent_turns(
                std::env::var(limits::MAX_CONCURRENT_TURNS_ENV)
                    .ok()
                    .as_deref(),
            )),
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
            limiter: limits::RateLimiter::default(),
            turns: limits::TurnGate::new(limits::DEFAULT_MAX_CONCURRENT_TURNS),
            #[cfg(test)]
            turn_override: None,
        }
    }
}
