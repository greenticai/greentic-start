//! The shared state backend a worker needs before it can run more than one
//! instance, and how a deployed workload is told where it is.
//!
//! # Why this exists
//!
//! A deployed workload receives NO arbitrary environment variables from the
//! Greentic Designer: credentials travel through the staged `op` secret store.
//! The Redis variables this crate has always honoured
//! (`GREENTIC_TRIGGER_REDIS_URL`, `GREENTIC_RUNNER_*`,
//! `GREENTIC_REVISION_PIN_REDIS_URL`) were therefore unreachable on exactly the
//! lanes that need them. This module reads ONE secret and fans it out.
//!
//! # The contract
//!
//! ```text
//! secrets://{env}/{tenant}/_/shared_state/redis_url   (UTF-8 Redis URL)
//! ```
//!
//! Staged with `op secrets put` like any other credential. The served tenant is
//! tried first, then `default` (what a remote lane's runtime carries).
//!
//! When present it supplies, for every setting the operator did NOT set in the
//! environment:
//!
//! * the trigger store (cron claim, webhook idempotency, hourly budget);
//! * the session-pin store (revision affinity);
//! * the conversation-state stores: sessions AND flow state, both switched to
//!   `redis` against this URL.
//!
//! **Environment variables always win.** Any of the existing variables set
//! explicitly overrides the shared value for that one setting, so an operator
//! can split backends or opt a store back to memory.
//!
//! # Fail loudly
//!
//! A URL that came from this secret is an explicit request for sharing. If it
//! is unreadable (store error) or the backend is unreachable, the boot FAILS;
//! falling back to in-memory would start a second instance that double-fires
//! cron ticks and loses parked conversations while every probe stays green.
//! See `docs/shared-state-backend.md` for which stores must be shared.

use anyhow::{Context, Result};

use crate::secrets_gate::DynSecretsManager;

/// Capability name reported by `greentic-start capabilities`.
pub const CAPABILITY_SHARED_STATE_BACKEND: &str = "shared-state-backend";

/// Schema tag of the capabilities document.
pub const CAPABILITIES_SCHEMA: &str = "greentic.start.capabilities.v1";

/// Secret provider segment and key of the shared Redis URL.
pub(crate) const SECRET_PROVIDER: &str = "shared_state";
pub(crate) const SECRET_KEY: &str = "redis_url";

/// The tenant a remote lane's runtime carries.
const REMOTE_TENANT: &str = "default";

/// The shared backend this process was told about by the secret store.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SharedBackend {
    url: Option<String>,
}

impl SharedBackend {
    /// No shared backend configured (the single-instance default).
    pub(crate) fn none() -> Self {
        Self::default()
    }

    /// A configured backend. A blank URL reads as none.
    pub(crate) fn from_url(url: Option<String>) -> Self {
        Self {
            url: url.map(|u| u.trim().to_string()).filter(|u| !u.is_empty()),
        }
    }

    pub(crate) fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    /// Read the staged secret. `Ok(none)` only when every candidate answered
    /// not-found; any other store error is an error (a store that failed has
    /// not shown that sharing is unconfigured).
    pub(crate) async fn read(secrets: &DynSecretsManager, env: &str, tenant: &str) -> Result<Self> {
        let mut tenants = vec![tenant];
        if tenant != REMOTE_TENANT {
            tenants.push(REMOTE_TENANT);
        }
        for tenant in tenants {
            for uri in
                crate::runner_host::secret_read_uris(env, tenant, None, SECRET_PROVIDER, SECRET_KEY)
            {
                match secrets.read(&uri).await {
                    Ok(bytes) => {
                        let text = String::from_utf8(bytes)
                            .context("the shared-state redis_url secret is not UTF-8 text")?;
                        let backend = Self::from_url(Some(text));
                        if backend.url.is_some() {
                            return Ok(backend);
                        }
                    }
                    Err(err)
                        if matches!(err, greentic_secrets_lib::SecretError::NotFound(_))
                            || crate::runner_host::is_secret_not_found(&err) => {}
                    Err(err) => {
                        return Err(anyhow::anyhow!("{err}")).context(
                            "the shared-state redis_url secret could not be read; refusing to \
                             boot as if sharing were not configured",
                        );
                    }
                }
            }
        }
        Ok(Self::none())
    }
}

/// Conversation-state settings after the shared backend has filled in what the
/// environment left unset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StorageVars {
    pub(crate) session_backend: Option<String>,
    pub(crate) state_backend: Option<String>,
    pub(crate) redis_url: Option<String>,
}

/// Pure merge: environment first, shared backend for the gaps.
pub(crate) fn merge_storage_vars(
    env_session: Option<String>,
    env_state: Option<String>,
    env_url: Option<String>,
    shared: &SharedBackend,
) -> StorageVars {
    let named = |v: &Option<String>| v.as_deref().is_some_and(|s| !s.trim().is_empty());
    let Some(shared_url) = shared.url() else {
        return StorageVars {
            session_backend: env_session,
            state_backend: env_state,
            redis_url: env_url,
        };
    };
    let redis = || Some("redis".to_string());
    StorageVars {
        session_backend: if named(&env_session) {
            env_session
        } else {
            redis()
        },
        state_backend: if named(&env_state) {
            env_state
        } else {
            redis()
        },
        redis_url: if named(&env_url) {
            env_url
        } else {
            Some(shared_url.to_string())
        },
    }
}

/// The `capabilities` document: stable JSON a deployer can gate on.
pub(crate) fn capabilities_json() -> String {
    serde_json::json!({
        "schema": CAPABILITIES_SCHEMA,
        "version": env!("CARGO_PKG_VERSION"),
        "capabilities": [CAPABILITY_SHARED_STATE_BACKEND],
    })
    .to_string()
}

#[cfg(test)]
mod tests;
