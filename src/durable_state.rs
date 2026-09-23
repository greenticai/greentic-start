//! Where a deployed worker's parked conversations live.
//!
//! A conversation that is waiting on the person — a card awaiting its submit, a
//! `session.wait` — is a [`FlowSnapshot`] in the runner host's SESSION store.
//! In memory that store dies with the process, so a revision rollout or a Cloud
//! Run cold start silently restarts every conversation in flight. Nothing is
//! red: the deploy succeeds, `/livez` answers, and the next message lands on
//! the entry card as though the person had never typed anything. This module is
//! how an operator asks for something durable instead.
//!
//! # The two halves
//!
//! * **Sessions** — the parked snapshot. This is the half durability is FOR.
//! * **Flow state** — the per-session key/value a flow's `state` operations
//!   read and write. Useful to keep, but see the caveat below.
//!
//! Each is selected independently
//! (`GREENTIC_RUNNER_SESSION_BACKEND` / `GREENTIC_RUNNER_STATE_BACKEND`), and
//! naming neither leaves this binary byte-for-byte on the behaviour it had
//! before this module existed.
//!
//! # Why the namespace carries the revision
//!
//! `revision_boot` gives every pack REVISION its own session store on purpose:
//! two revisions serving the same tenant/user/conversation must not resume each
//! other's snapshot against a different flow graph, which
//! `shared_revision_store_leaks_across_revisions` calls "the bug". A
//! greentic-session Redis key carries the environment but not the revision, so
//! one environment-wide keyspace would re-create exactly what those per-revision
//! stores prevent. [`DurableStorage::stores_for`] therefore folds the revision's
//! identity into the keyspace prefix — see [`revision_namespace`].
//!
//! Durability and that isolation are not in tension. A per-revision keyspace
//! still survives a process restart and a cold start, which is what durability
//! is for; what it does not do is carry a half-finished conversation onto a
//! different flow graph.
//!
//! # The flow-state caveat, stated rather than hidden
//!
//! `greentic-state` composes its own key
//! (`greentic:state:<env>:<tenant>[:<team>][:<user>]:runner:pack/<pack>/flow/<flow>/session/<hint>`)
//! and `RedisStateStore::from_url` takes no namespace, so there is nowhere to
//! fold a revision in. A Redis flow-state backend is therefore SHARED between
//! two live revisions of one pack. That is a smaller hazard than a shared resume
//! snapshot — the two revisions are the same flow, and the state is keyed by
//! pack/flow/session rather than by node — but it is a real difference from the
//! in-memory default, so [`DurableStorage::log_once`] says so out loud instead
//! of leaving an operator to find out.
//!
//! [`FlowSnapshot`]: greentic_runner_host::runner::engine::FlowSnapshot

use anyhow::{Context, Result};
use greentic_runner_host::storage::{
    DynSessionStore, DynStateStore, SessionBackend, StateBackend, StorageConfig, new_session_store,
    new_state_store, session_store_from_config, state_store_from_config,
};
use sha2::{Digest, Sha256};

use crate::revision_pin::{PIN_REDIS_URL_ENV, redact_redis_url};

/// The storage choice for this process, resolved once at boot.
///
/// Cloned into the activation path; the clone is a `StorageConfig`, not a
/// connection, so each revision opens its own store from it.
#[derive(Clone, Debug)]
pub(crate) struct DurableStorage {
    config: StorageConfig,
}

impl DurableStorage {
    /// Both stores in memory — the pre-existing behaviour, and what every test
    /// that does not care about durability should use.
    ///
    /// Test-only: production reaches the same state through
    /// [`resolve`](Self::resolve) naming no backend, which is the path that has
    /// to keep working.
    #[cfg(test)]
    pub(crate) fn in_memory() -> Self {
        Self {
            config: StorageConfig::in_memory(),
        }
    }

    /// Resolve the storage choice from the process environment.
    ///
    /// `env_id` is the environment this boot resolved (flag > env > `local`),
    /// not `std::env::var("GREENTIC_ENV")`: a boot that took `--env` may have no
    /// such variable set, and deriving a keyspace from a variable the operator
    /// did not set is how two environments end up sharing one.
    ///
    /// # Fail LOUDLY, unlike `resolve_pin_store`
    ///
    /// [`crate::revision_pin::resolve_pin_store`] fails OPEN — an unreachable
    /// Redis there warns and falls back to in-memory pins — and that is right
    /// for what it stores: a pin is a ROUTING HINT, and losing one re-picks a
    /// revision for a conversation that still works. Losing conversation STATE
    /// is not a hint, it is the conversation. An operator who configured a
    /// durable session store and got an in-memory one would have a worker that
    /// boots, serves, passes every probe, and silently restarts every parked
    /// conversation — the exact failure this module exists to remove. So a
    /// backend that was NAMED and cannot be built is a boot failure.
    ///
    /// A backend that was not named is not a failure: it resolves to memory,
    /// never to Redis just because a URL happens to be in the environment.
    pub(crate) fn resolve(env_id: &str) -> Result<Self> {
        let var = |name: &str| std::env::var(name).ok();
        let config = StorageConfig::from_vars(
            var(greentic_runner_host::storage::config::ENV_SESSION_BACKEND).as_deref(),
            var(greentic_runner_host::storage::config::ENV_STATE_BACKEND).as_deref(),
            var(greentic_runner_host::storage::config::ENV_REDIS_URL).as_deref(),
            var(greentic_runner_host::storage::config::ENV_SESSION_NAMESPACE).as_deref(),
            Some(env_id),
            var(greentic_runner_host::storage::config::ENV_SESSION_WAIT_TTL_SECS).as_deref(),
        )
        .context(
            // Deliberately covers the typo'd-backend-name case too (`memry`),
            // not only a named-but-unbuildable Redis: either way the operator
            // asked for something this boot cannot honour, and the alternative
            // to refusing is starting on in-memory state that looks healthy.
            "refusing to boot: the conversation-state configuration could not be honoured, and \
             starting on in-memory state would silently lose every parked conversation",
        )?;
        Ok(Self { config })
    }

    /// `true` when either store performs network I/O.
    pub(crate) fn is_durable(&self) -> bool {
        self.config.is_durable()
    }

    /// One boot line naming what was chosen. Names only — never the URL, which
    /// may carry `redis://user:password@host`.
    pub(crate) fn log_once(&self) {
        if !self.is_durable() {
            crate::operator_log::info(
                module_path!(),
                "conversation state: in-memory (a parked conversation does not survive a restart)",
            );
            return;
        }
        crate::operator_log::info(
            module_path!(),
            format!(
                "conversation state: sessions {}, flow state {} (parked conversations survive a \
                 restart)",
                self.config.session.describe(),
                self.config.state.describe(),
            ),
        );
        if self.config.state.is_durable() {
            crate::operator_log::warn(
                module_path!(),
                "durable flow state is NOT scoped per revision: greentic-state composes its own \
                 key from env/tenant/pack/flow/session and takes no namespace, so two live \
                 revisions of one pack share it. Parked SESSIONS stay isolated per revision; only \
                 the flow-state key/value is shared",
            );
        }
    }

    /// Durable conversations that can land on a different revision than they
    /// parked on are a new failure mode, not a fix.
    ///
    /// Interop callers get no stickiness cookie at all — `revision_serve` hands
    /// the dispatcher `cookie: None, defer_pin: false` — so
    /// [`PIN_REDIS_URL_ENV`] is the ONLY thing that keeps a conversation on the
    /// revision it parked on once more than one replica is serving. Configured
    /// without it, a resumed turn can be weighted onto another revision, find no
    /// snapshot under that revision's keyspace, and restart the conversation:
    /// the same symptom the operator just configured Redis to remove, now
    /// intermittent instead of certain.
    ///
    /// A warning rather than a refusal: a single-replica, single-revision
    /// deployment is a legitimate configuration in which pinning buys nothing,
    /// and refusing to boot one would be wrong.
    pub(crate) fn warn_if_no_revision_affinity(&self) {
        if let Some(warning) =
            self.revision_affinity_warning(std::env::var(PIN_REDIS_URL_ENV).ok().as_deref())
        {
            crate::operator_log::warn(module_path!(), warning);
        }
    }

    /// The pure half of [`warn_if_no_revision_affinity`], so the decision is
    /// testable without mutating process-global state.
    ///
    /// [`warn_if_no_revision_affinity`]: Self::warn_if_no_revision_affinity
    fn revision_affinity_warning(&self, pin_url: Option<&str>) -> Option<String> {
        if !self.config.session.is_durable() {
            return None;
        }
        if pin_url.is_some_and(|value| !value.trim().is_empty()) {
            return None;
        }
        Some(format!(
            "durable sessions are configured ({session}) but revision affinity is not: \
             {PIN_REDIS_URL_ENV} is unset, and an interop caller carries no stickiness cookie, \
             so a resumed turn may be routed to a different revision — which keeps its own \
             keyspace and will restart the conversation. Set {PIN_REDIS_URL_ENV} (the same Redis \
             is fine) whenever more than one revision serves traffic",
            session = self.config.session.describe(),
        ))
    }

    /// Prove the configured backends are reachable, at BOOT, before anything
    /// serves.
    ///
    /// [`stores_for`](Self::stores_for) probes too — but only when a revision
    /// is activated, and an environment with no revision attached activates
    /// none. Without this, a worker configured against a dead Redis would boot
    /// clean, log that parked conversations survive a restart, and fail its
    /// first deploy instead of its own startup.
    ///
    /// The probe writes nothing: both stores read one key that is never
    /// written, so this leaves no litter under the keyspace.
    pub(crate) fn ensure_reachable(&self) -> Result<()> {
        if !self.is_durable() {
            return Ok(());
        }
        let session = self.session_backend_for("boot-probe")?;
        build_stores(session, self.config.state.clone()).context(
            "the configured conversation-state backend is unreachable; refusing to boot on \
             in-memory state, which would silently lose every parked conversation",
        )?;
        Ok(())
    }

    /// Build the session and flow-state stores for ONE revision.
    ///
    /// Blocking work — `greentic-session` and `greentic-state` are synchronous
    /// traits over a blocking `redis::Connection`, and both stores probe their
    /// backend at construction so an unreachable Redis fails here rather than
    /// mid-turn in front of a user. The durable arm therefore runs on
    /// `spawn_blocking`; the in-memory arm allocates two maps and does not.
    pub(crate) async fn stores_for(
        &self,
        namespace_suffix: &str,
    ) -> Result<(DynSessionStore, DynStateStore)> {
        if !self.is_durable() {
            return Ok((new_session_store(), new_state_store()));
        }
        let session = self.session_backend_for(namespace_suffix)?;
        let state = self.config.state.clone();
        tokio::task::spawn_blocking(move || build_stores(session, state))
            .await
            .context("the durable store builder task failed")?
    }

    /// The session backend for one revision: the resolved keyspace with the
    /// revision's identity folded in.
    fn session_backend_for(&self, namespace_suffix: &str) -> Result<SessionBackend> {
        match &self.config.session {
            SessionBackend::InMemory => Ok(SessionBackend::InMemory),
            SessionBackend::Redis {
                url,
                namespace,
                wait_ttl,
            } => SessionBackend::redis_with_ttl(
                url.clone(),
                revision_namespace(namespace, namespace_suffix),
                *wait_ttl,
            )
            .with_context(|| {
                format!(
                    "building the Redis session backend for `{}`",
                    redact_redis_url(url)
                )
            }),
        }
    }
}

/// Compose one revision's session keyspace: `<base>:<suffix>`.
///
/// The suffix is a digest rather than the identity spelled out, because the
/// identity that decides isolation is a six-field key (deployment, revision,
/// tenant, team, customer, bundle) and any readable rendering of it either
/// drops a field — silently merging two keyspaces that must stay apart — or
/// produces a prefix long enough that a Redis key is mostly prefix. The
/// revision id is kept in the clear in front of it so an operator reading
/// `SCAN` output can still tell which revision a key belongs to.
pub(crate) fn revision_namespace(base: &str, suffix: &str) -> String {
    format!("{}:{}", base.trim_end_matches(':'), suffix)
}

/// The per-revision suffix: the revision id, then a digest of the full
/// isolation identity.
///
/// Stable across restarts by construction — every field comes from
/// `runtime-config.json` and `environment.json` on disk, not from anything
/// this process minted — which is what makes a durable store resumable at all.
pub(crate) fn isolation_suffix(fields: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for field in fields {
        // Length-prefixed so `("a", "bc")` and `("ab", "c")` cannot digest the
        // same, which would merge two revisions' keyspaces.
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    let digest = hasher.finalize();
    let readable: String = fields
        .first()
        .map(|first| {
            first
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .take(26)
                .collect()
        })
        .unwrap_or_default();
    format!("{readable}-{}", hex12(&digest))
}

fn hex12(digest: &[u8]) -> String {
    digest
        .iter()
        .take(6)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn build_stores(
    session: SessionBackend,
    state: StateBackend,
) -> Result<(DynSessionStore, DynStateStore)> {
    if let SessionBackend::Redis { url, .. } = &session {
        // rustls provider for `rediss://`; a no-op for plaintext URLs.
        crate::redis_tls::ensure_crypto_provider_for(url);
    }
    if let StateBackend::Redis { url } = &state {
        crate::redis_tls::ensure_crypto_provider_for(url);
    }
    let session_store = session_store_from_config(&session)
        .context("failed to open the durable session store for a revision")?;
    let state_store = state_store_from_config(&state)
        .context("failed to open the durable flow-state store for a revision")?;
    Ok((session_store, state_store))
}

#[cfg(test)]
mod tests;
