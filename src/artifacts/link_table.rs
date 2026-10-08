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
    pub recent: Arc<RecentPuts>,
    /// The unit's live attachments decision (a re-probe may turn it off).
    pub cell: Weak<UnitCell>,
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
            cell: Arc::downgrade(cell),
            deployment,
        })
    }

    fn enabled(&self) -> bool {
        self.cell
            .upgrade()
            .is_some_and(|cell| matches!(*cell.current(), UnitAttachments::Enabled { .. }))
    }
}

/// Fixed code and bundle id only: never the token, door URL or key.
fn unavailable(bundle_id: &str, reason: &str) {
    operator_log::warn(
        module_path!(),
        format!("artifact_links_unavailable for unit `{bundle_id}` ({reason})"),
    );
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
