//! One unit's attachments decision, taken once at activation, and the table
//! the inbound path reads it from.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use greentic_deploy_spec::ids::{DeploymentId, RevisionId};

use super::ingest::Pipeline;

/// Why a unit runs without attachments. Each is reported to the agent per
/// attachment (a note), never silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Off {
    /// The unit stages no metering block, so there is no door.
    NoDoor,
    /// The door answered `403 purpose_not_granted`: the unit did not opt in.
    NotGranted,
    /// The door could not be used at activation (down, `5xx`, `429`, a bare
    /// `404`, a probe that ran out of time). The unit serves without
    /// attachments while a background re-probe waits for the door.
    DoorUnavailable,
}

impl Off {
    /// The fixed reason the agent reads in a note.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Off::NoDoor => "this worker has no file storage configured",
            Off::NotGranted => "file attachments are not enabled for this worker",
            Off::DoorUnavailable => "file storage is temporarily unavailable for this worker",
        }
    }
}

pub(crate) enum UnitAttachments {
    Enabled { pipeline: Arc<Pipeline> },
    Off(Off),
}

/// One revision's decision, which a background re-probe may replace once
/// ([`super::recovery`]): `Off(DoorUnavailable)` -> `Enabled` or
/// `Off(NotGranted)`. Readers take a snapshot per request.
pub(crate) struct UnitCell {
    state: RwLock<Arc<UnitAttachments>>,
}

impl UnitCell {
    pub(crate) fn new(state: UnitAttachments) -> Self {
        Self {
            state: RwLock::new(Arc::new(state)),
        }
    }

    pub(crate) fn current(&self) -> Arc<UnitAttachments> {
        match self.state.read() {
            Ok(guard) => Arc::clone(&guard),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    pub(crate) fn set(&self, state: UnitAttachments) {
        let next = Arc::new(state);
        match self.state.write() {
            Ok(mut guard) => *guard = next,
            Err(poisoned) => *poisoned.into_inner() = next,
        }
    }
}

/// Each loaded revision's decision. A revision missing from it is treated as
/// [`Off::NoDoor`] by the hook.
#[derive(Clone, Default)]
pub(crate) struct AttachmentsTable(Arc<HashMap<(DeploymentId, RevisionId), Arc<UnitCell>>>);

impl AttachmentsTable {
    pub(crate) fn new(entries: HashMap<(DeploymentId, RevisionId), Arc<UnitCell>>) -> Self {
        Self(Arc::new(entries))
    }

    pub(crate) fn get(
        &self,
        deployment_id: DeploymentId,
        revision_id: RevisionId,
    ) -> Option<Arc<UnitAttachments>> {
        self.0
            .get(&(deployment_id, revision_id))
            .map(|cell| cell.current())
    }
}

impl std::fmt::Debug for AttachmentsTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentsTable")
            .field("revisions", &self.0.len())
            .finish()
    }
}
