//! Exposing a deployed worker to other agents (worker-interop contract).
//!
//! The runtime half of the contract: the staged per-unit config
//! ([`config`]) and the process-wide state the interop surfaces share.
//! Authentication of the generic ingress lives in [`crate::ingress_auth`].

pub(crate) mod config;

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
    /// See [`TurnOverride`].
    #[cfg(test)]
    pub turn_override: Option<TurnOverride>,
}

impl InteropState {
    /// Production state: the escape hatch read from the environment.
    pub(crate) fn from_env() -> Self {
        Self {
            generic_auth_enabled: crate::ingress_auth::generic_ingress_auth_enabled_from_env(),
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
            #[cfg(test)]
            turn_override: None,
        }
    }
}
