//! Each unit's link signer, keyed by deployment, on the routing snapshot
//! (docs/outbound-artifacts.md).
//!
//! An entry exists only for a unit that has an artifacts door, a staged
//! metering block and a usable reader. It holds that unit's derived link key,
//! its door reader and the record of what its port created; it never holds
//! another unit's. A deployment without an entry, or whose unit currently
//! runs without attachments, answers `None`: the route then refuses every
//! link of it with the uniform 404 and outbound shaping falls back to a fixed
//! sentence.

// Staged: the serving route and outbound shaping (outbound-delivery plan
// Tasks 4 and 6) are the readers of `get` and the unit's fields.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Weak};

use greentic_aw_runtime::ArtifactReader;
use greentic_deploy_spec::ids::DeploymentId;

use super::host_access::HostArtifactAccess;
use super::link::LinkKey;
use super::recent_puts::RecentPuts;
use super::unit::{UnitAttachments, UnitCell};
use crate::interop::metering::MeteringConfig;
use crate::operator_log;

/// One unit's signer, reader and provenance record.
pub(crate) struct LinkUnit {
    pub key: LinkKey,
    pub reader: Arc<dyn ArtifactReader>,
    /// The DEPLOYMENT's record: every revision of a traffic split writes here.
    pub recent: Arc<RecentPuts>,
    /// Each revision's live attachments decision (a re-probe may change it).
    /// The signer serves while any of them is enabled.
    pub cells: Vec<Weak<UnitCell>>,
    /// The deployment ULID as text, as it appears in the link path.
    pub deployment: String,
}

impl std::fmt::Debug for LinkUnit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `LinkKey`'s own Debug redacts; the reader holds the token and is
        // never printed.
        f.debug_struct("LinkUnit")
            .field("deployment", &self.deployment)
            .finish_non_exhaustive()
    }
}

impl LinkUnit {
    /// The signer for `deployment`, or `None` (with one fixed-code `warn`)
    /// when the unit has no staged metering block or its reader cannot be
    /// built. The key is derived from the unit's OWN token, bound to its
    /// tenant slug, bundle and deployment.
    pub(crate) fn build(
        metering: Option<&MeteringConfig>,
        access: &HostArtifactAccess,
        cell: &Arc<UnitCell>,
        bundle_id: &str,
        deployment: DeploymentId,
    ) -> Option<Self> {
        let Some(metering) = metering else {
            unavailable(bundle_id, "no_metering_block");
            return None;
        };
        let Ok(reader) = access.reader() else {
            unavailable(bundle_id, "reader_unavailable");
            return None;
        };
        let deployment = deployment.to_string();
        Some(Self {
            key: LinkKey::derive(
                metering.token.expose(),
                &metering.tenant_slug,
                bundle_id,
                &deployment,
            ),
            reader,
            recent: access.recent_puts(),
            cells: vec![Arc::downgrade(cell)],
            deployment,
        })
    }

    fn enabled(&self) -> bool {
        self.cells.iter().any(|cell| {
            cell.upgrade()
                .is_some_and(|cell| matches!(*cell.current(), UnitAttachments::Enabled { .. }))
        })
    }
}

/// Fixed code and bundle id only: never the token, door URL or key.
fn unavailable(bundle_id: &str, reason: &str) {
    operator_log::warn(
        module_path!(),
        format!("artifact_links_unavailable for unit `{bundle_id}` ({reason})"),
    );
}

/// Builds the table during activation, one revision at a time.
///
/// A deployment may run several revisions at once (a traffic split). They
/// share the unit's token, so ONE signer per deployment, but each revision
/// has its own access and its own attachments decision. So every revision's
/// access is given the deployment's one provenance record (a file the canary
/// creates is as linkable as one the stable revision creates), and the signer
/// is gated on every revision's decision.
#[derive(Default)]
pub(crate) struct LinkTableBuilder {
    units: HashMap<DeploymentId, LinkUnit>,
    recent: HashMap<DeploymentId, Arc<RecentPuts>>,
}

impl LinkTableBuilder {
    /// `access` writing into `deployment`'s one provenance record. Call it
    /// before the revision's port is built.
    pub(crate) fn share_recent(
        &mut self,
        deployment: DeploymentId,
        access: HostArtifactAccess,
    ) -> HostArtifactAccess {
        let recent = self.recent.entry(deployment).or_default();
        access.with_recent(Arc::clone(recent))
    }

    /// `true` until a signer is built for `deployment` (then the metering
    /// block need not be read again).
    pub(crate) fn needs_signer(&self, deployment: &DeploymentId) -> bool {
        !self.units.contains_key(deployment)
    }

    /// Adds one revision: builds the deployment's signer when there is none
    /// yet, otherwise gates the existing signer on this revision's decision.
    pub(crate) fn add_revision(
        &mut self,
        deployment: DeploymentId,
        metering: Option<&MeteringConfig>,
        access: &HostArtifactAccess,
        cell: &Arc<UnitCell>,
        bundle_id: &str,
    ) {
        if let Some(unit) = self.units.get_mut(&deployment) {
            unit.cells.push(Arc::downgrade(cell));
            return;
        }
        if let Some(unit) = LinkUnit::build(metering, access, cell, bundle_id, deployment) {
            self.units.insert(deployment, unit);
        }
    }

    pub(crate) fn finish(self) -> ArtifactLinkTable {
        ArtifactLinkTable::new(
            self.units
                .into_iter()
                .map(|(id, unit)| (id, Arc::new(unit)))
                .collect(),
        )
    }
}

/// Every unit's signer, keyed by deployment. Revision-derived like
/// `AttachmentsTable`: a routing-only reload carries it over unchanged.
#[derive(Clone, Default)]
pub(crate) struct ArtifactLinkTable(Arc<HashMap<DeploymentId, Arc<LinkUnit>>>);

impl ArtifactLinkTable {
    pub(crate) fn new(map: HashMap<DeploymentId, Arc<LinkUnit>>) -> Self {
        Self(Arc::new(map))
    }

    /// `None` when the deployment is unknown, or its unit currently runs
    /// without attachments.
    pub(crate) fn get(&self, deployment: &DeploymentId) -> Option<Arc<LinkUnit>> {
        self.0
            .get(deployment)
            .filter(|unit| unit.enabled())
            .map(Arc::clone)
    }
}

impl std::fmt::Debug for ArtifactLinkTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArtifactLinkTable")
            .field("units", &self.0.len())
            .finish()
    }
}
