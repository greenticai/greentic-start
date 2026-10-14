//! What one unit's runner gets from its artifacts door: the agent's READER
//! (opening an `artifact://` attachment) and the extensions' PORT (creating
//! one). Both are built from the door this unit's activation probed and
//! accepted, so they reach that unit's door with that unit's token and no
//! other: the door derives the tenant from the token, so neither can read or
//! write another tenant's artifact, and neither can reach another unit's door.

use std::sync::{Arc, Weak};

use greentic_aw_runtime::{ArtifactClientError, ArtifactReader, HttpArtifactReader};
use greentic_ext_runtime::host_ports::ArtifactPort;

use super::boot::Door;
use super::port::DoorArtifactPort;
use super::recent_puts::RecentPuts;
use super::store::ArtifactStore;
use super::unit::UnitCell;

#[derive(Clone)]
pub(crate) struct HostArtifactAccess {
    store: Arc<dyn ArtifactStore>,
    door: Door,
    /// The unit's live decision, read by the port on every call.
    unit: Option<Weak<UnitCell>>,
    /// What this unit's port created; shared by every clone of this access.
    recent: Arc<RecentPuts>,
}

impl std::fmt::Debug for HostArtifactAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `Door`'s own Debug redacts the token.
        f.debug_struct("HostArtifactAccess")
            .field("door", &self.door)
            .finish_non_exhaustive()
    }
}

impl HostArtifactAccess {
    /// `store` is the client the inbound pipeline writes through, `door` the
    /// door it was built over: one unit, one door, one token.
    pub(crate) fn new(store: Arc<dyn ArtifactStore>, door: Door) -> Self {
        Self {
            store,
            door,
            unit: None,
            recent: Arc::new(RecentPuts::default()),
        }
    }

    /// Ties the port to the unit's live decision (`cell`), which a re-probe
    /// may change after the runtime was loaded.
    pub(crate) fn bound_to(mut self, cell: &Arc<UnitCell>) -> Self {
        self.unit = Some(Arc::downgrade(cell));
        self
    }

    /// The extension port, over the SAME store the inbound pipeline uses, so
    /// a file an extension creates lands in the same tenant as the files the
    /// unit received.
    pub(crate) fn port(&self) -> Arc<dyn ArtifactPort> {
        let port =
            DoorArtifactPort::new(Arc::clone(&self.store)).with_recent(Arc::clone(&self.recent));
        match self.unit.as_ref().and_then(Weak::upgrade) {
            Some(cell) => Arc::new(port.gated_by(&cell)),
            None => Arc::new(port),
        }
    }

    /// Writes into `recent` instead of this access's own record: every
    /// revision of one deployment shares the deployment's record.
    pub(crate) fn with_recent(mut self, recent: Arc<RecentPuts>) -> Self {
        self.recent = recent;
        self
    }

    /// The record of what this unit's port created (outbound link provenance).
    pub(crate) fn recent_puts(&self) -> Arc<RecentPuts> {
        Arc::clone(&self.recent)
    }

    /// The agent's reader. Fallible: an unusable token is an error, never a
    /// default client. The error names neither the door nor the token.
    pub(crate) fn reader(&self) -> Result<Arc<dyn ArtifactReader>, ArtifactClientError> {
        HttpArtifactReader::new(self.door.url.clone(), self.door.token.clone())
            .map(|reader| Arc::new(reader) as Arc<dyn ArtifactReader>)
    }
}
