//! The per-unit attachments decision, taken at activation. A function of its
//! own so the refusal rules are testable without standing up a revision.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};

use crate::interop::metering::MeteringConfig;

use super::boot::{DoorProbe, door_for, probe_door};
use super::fetch::{HttpFetcher, SecretLookup};
use super::host_access::HostArtifactAccess;
use super::ingest::Pipeline;
use super::store::{ArtifactStore, HttpArtifactStore};
use super::unit::{Off, UnitAttachments};

/// Bounds one door request end to end.
const DOOR_TIMEOUT: Duration = Duration::from_secs(20);

/// - no metering block: [`Off::NoDoor`];
/// - the door answers `403 purpose_not_granted`: [`Off::NotGranted`] (warned
///   once by the probe);
/// - the door is usable: attachments on;
/// - anything else (an endpoint that cannot be derived, a dead door, `401`,
///   `5xx`, a `404` the door did not write): `Err`, and the revision does not
///   activate. There is no in-memory fallback.
pub(crate) async fn activate(
    revision_id: &str,
    metering: Option<&MeteringConfig>,
    secrets: Arc<dyn SecretLookup>,
) -> anyhow::Result<UnitAttachments> {
    let refusal = || format!("preparing inbound attachments for revision `{revision_id}`");
    let Some(door) = door_for(metering)
        .map_err(|err| anyhow!(err))
        .with_context(refusal)?
    else {
        return Ok(UnitAttachments::Off(Off::NoDoor));
    };
    let http = HttpArtifactStore::new(door.url.clone(), door.token.clone(), DOOR_TIMEOUT)
        .map_err(|_| anyhow!("the artifacts door client could not be built; refusing to serve"))
        .with_context(refusal)?;
    match probe_door(&http, &door.url).await.with_context(refusal)? {
        DoorProbe::NotGranted => Ok(UnitAttachments::Off(Off::NotGranted)),
        DoorProbe::Enabled => {
            // A fresh client for serving: activation runs on its own runtime,
            // which may be gone by the first message, and a connection the
            // probe pooled there would be dead.
            drop(http);
            let serving =
                HttpArtifactStore::new(door.url.clone(), door.token.clone(), DOOR_TIMEOUT)
                    .map_err(|_| {
                        anyhow!("the artifacts door client could not be built; refusing to serve")
                    })
                    .with_context(refusal)?;
            let store: Arc<dyn ArtifactStore> = Arc::new(serving);
            let fetcher = HttpFetcher::new(secrets)
                .map_err(|_| anyhow!("the attachment download client could not be built"))
                .with_context(refusal)?;
            let pipeline = Arc::new(Pipeline::new(Arc::clone(&store), Arc::new(fetcher)));
            let host = HostArtifactAccess::new(store, door);
            Ok(UnitAttachments::Enabled { pipeline, host })
        }
    }
}
