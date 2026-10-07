//! One unit's attachments decision, taken once at activation, and the table
//! the inbound path reads it from.

use std::collections::HashMap;
use std::sync::Arc;

use greentic_deploy_spec::ids::{DeploymentId, RevisionId};

use super::host_access::HostArtifactAccess;
use super::ingest::Pipeline;

/// Why a unit runs without attachments. Each is reported to the agent per
/// attachment (a note), never silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Off {
    /// The unit stages no metering block, so there is no door.
    NoDoor,
    /// The door answered `403 purpose_not_granted`: the unit did not opt in.
    NotGranted,
}

impl Off {
    /// The fixed reason the agent reads in a note.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Off::NoDoor => "this worker has no file storage configured",
            Off::NotGranted => "file attachments are not enabled for this worker",
        }
    }
}

pub(crate) enum UnitAttachments {
    Enabled {
        pipeline: Arc<Pipeline>,
        /// The agent reader and extension port over the SAME door the
        /// pipeline writes through.
        host: HostArtifactAccess,
    },
    Off(Off),
}

impl UnitAttachments {
    /// What this unit's runner gets from its door; `None` when attachments
    /// are off, so the agent gets no reader and extensions no port.
    pub(crate) fn host_access(&self) -> Option<&HostArtifactAccess> {
        match self {
            UnitAttachments::Enabled { host, .. } => Some(host),
            UnitAttachments::Off(_) => None,
        }
    }
}

/// Each loaded revision's decision. A revision missing from it is treated as
/// [`Off::NoDoor`] by the hook.
#[derive(Clone, Default)]
pub(crate) struct AttachmentsTable(Arc<HashMap<(DeploymentId, RevisionId), Arc<UnitAttachments>>>);

impl AttachmentsTable {
    pub(crate) fn new(entries: HashMap<(DeploymentId, RevisionId), Arc<UnitAttachments>>) -> Self {
        Self(Arc::new(entries))
    }

    pub(crate) fn get(
        &self,
        deployment_id: DeploymentId,
        revision_id: RevisionId,
    ) -> Option<Arc<UnitAttachments>> {
        self.0.get(&(deployment_id, revision_id)).cloned()
    }
}

impl std::fmt::Debug for AttachmentsTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentsTable")
            .field("revisions", &self.0.len())
            .finish()
    }
}
