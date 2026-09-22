//! Flow triggers: starting a flow from outside a conversation, on a cron
//! schedule or when a verified webhook arrives.
//!
//! Implements contract `greentic.triggers.v1` (`docs/trigger-contract-v1.md`
//! in greentic-designer, which writes the `assets/triggers.json` this reads).
//!
//! - [`schema`] / [`field_ref`] — parse and validate the declaration;
//! - [`table`] — load it per revision; the table travels in
//!   `RevisionIngressRouting` so a reload swaps it with everything else;
//! - [`scheduler`] — the cron loop, one task for the server's life;
//! - [`webhook`] + [`verify`] — the `/trigger/<id>` route;
//! - [`dispatch`] — firing → `IngressEnvelope` at the declared entry node;
//! - [`store`] / [`limits`] — cross-replica claim, idempotency, budget,
//!   in-flight limits;
//! - [`telemetry`] — counters, per-firing log line, rejection audit.

pub(crate) mod cron;
pub(crate) mod dispatch;
pub(crate) mod field_ref;
pub(crate) mod limits;
pub(crate) mod scheduler;
pub(crate) mod schema;
pub(crate) mod store;
pub(crate) mod table;
pub(crate) mod telemetry;
pub(crate) mod verify;
pub(crate) mod webhook;

use std::sync::{Arc, OnceLock};

pub(crate) use table::{TriggerTable, load_revision_triggers};

static STORE: OnceLock<Arc<dyn store::TriggerStore>> = OnceLock::new();

/// Install the process's trigger store. Called once when the revision server
/// starts; a second call is ignored (the first store stays authoritative).
pub(crate) fn install_store(store: Arc<dyn store::TriggerStore>) {
    let _ = STORE.set(store);
}

/// The installed store, or a process-local in-memory one if none was
/// installed (tests, or a code path that serves triggers before boot finished
/// resolving Redis).
pub(crate) fn store() -> Arc<dyn store::TriggerStore> {
    Arc::clone(STORE.get_or_init(|| Arc::new(store::InMemoryTriggerStore::default())))
}
