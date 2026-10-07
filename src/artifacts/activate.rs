//! The per-unit attachments decision, taken at activation. A function of its
//! own so the refusal rules are testable without standing up a revision.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};

use crate::interop::metering::MeteringConfig;
use crate::operator_log;

use super::boot::{Door, DoorProbe, door_for, probe_door};
use super::fetch::{HttpFetcher, SecretLookup};
use super::host_access::HostArtifactAccess;
use super::ingest::Pipeline;
use super::store::{ArtifactStore, HttpArtifactStore};
use super::unit::{Off, UnitAttachments};

/// Bounds one door request end to end.
pub(crate) const DOOR_TIMEOUT: Duration = Duration::from_secs(20);
/// Bounds the whole activation probe of one revision, retries included.
pub(crate) const PROBE_BUDGET: Duration = Duration::from_secs(8);

/// One revision's activation outcome.
pub(crate) struct ActivatedUnit {
    /// What the inbound path does with this revision's attachments now.
    pub state: UnitAttachments,
    /// The agent reader and extension port over this unit's door: present
    /// whenever the unit HAS a usable door configuration (attachments on, or
    /// the door down for now), absent for `NoDoor` and `NotGranted`.
    pub host: Option<HostArtifactAccess>,
    /// Owed when the door was down: what the background re-probe needs.
    pub recovery: Option<Recovery>,
}

/// What a re-probe needs to turn attachments on later.
pub(crate) struct Recovery {
    pub(crate) revision_id: String,
    pub(crate) door: Door,
    pub(crate) pipeline: Arc<Pipeline>,
}

impl std::fmt::Debug for Recovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `Door`'s Debug redacts the token.
        f.debug_struct("Recovery")
            .field("revision_id", &self.revision_id)
            .field("door", &self.door)
            .finish_non_exhaustive()
    }
}

/// [`activate_with`] at the production probe budget.
#[cfg(test)]
pub(crate) async fn activate(
    revision_id: &str,
    metering: Option<&MeteringConfig>,
    secrets: Arc<dyn SecretLookup>,
) -> anyhow::Result<ActivatedUnit> {
    activate_with(revision_id, metering, secrets, PROBE_BUDGET).await
}

/// - no metering block: [`Off::NoDoor`];
/// - the door answers `403 purpose_not_granted`: [`Off::NotGranted`];
/// - the door is usable: attachments on;
/// - the door cannot be used right now: [`Off::DoorUnavailable`] (one warning
///   for this revision) plus a [`Recovery`];
/// - a misconfiguration (an endpoint that cannot be derived, is not safe, or
///   carries credentials; a `401`): `Err`, and the revision does not
///   activate.
pub(crate) async fn activate_with(
    revision_id: &str,
    metering: Option<&MeteringConfig>,
    secrets: Arc<dyn SecretLookup>,
    budget: Duration,
) -> anyhow::Result<ActivatedUnit> {
    let refusal = || format!("preparing inbound attachments for revision `{revision_id}`");
    let Some(door) = door_for(metering)
        .map_err(|err| anyhow!(err))
        .with_context(refusal)?
    else {
        return Ok(off(Off::NoDoor));
    };
    let client = || {
        HttpArtifactStore::new(door.url.clone(), door.token.clone(), DOOR_TIMEOUT)
            .map_err(|_| anyhow!("the artifacts door client could not be built; refusing to serve"))
            .with_context(refusal)
    };
    let probe = client()?;
    let found = probe_door(&probe, &door.url, budget)
        .await
        .with_context(refusal)?;
    // A fresh client for serving: a connection the probe pooled belongs to
    // the runtime the probe ran on.
    drop(probe);
    let build_pipeline = |store: Arc<dyn ArtifactStore>| -> anyhow::Result<Arc<Pipeline>> {
        let fetcher = HttpFetcher::new(Arc::clone(&secrets))
            .map_err(|_| anyhow!("the attachment download client could not be built"))
            .with_context(refusal)?;
        Ok(Arc::new(Pipeline::new(store, Arc::new(fetcher))))
    };
    match found {
        DoorProbe::NotGranted => Ok(off(Off::NotGranted)),
        DoorProbe::Enabled => {
            let store: Arc<dyn ArtifactStore> = Arc::new(client()?);
            let pipeline = build_pipeline(Arc::clone(&store))?;
            Ok(ActivatedUnit {
                state: UnitAttachments::Enabled { pipeline },
                host: Some(HostArtifactAccess::new(store, door)),
                recovery: None,
            })
        }
        DoorProbe::Unavailable(code) => {
            // Fixed code and the revision only: never the door URL or token.
            operator_log::warn(
                module_path!(),
                format!(
                    "the artifacts door is not usable for revision `{revision_id}` ({code}); \
                     it serves without inbound attachments and turns them on when the door \
                     answers"
                ),
            );
            let store: Arc<dyn ArtifactStore> = Arc::new(client()?);
            let pipeline = build_pipeline(Arc::clone(&store))?;
            Ok(ActivatedUnit {
                state: UnitAttachments::Off(Off::DoorUnavailable),
                host: Some(HostArtifactAccess::new(store, door.clone())),
                recovery: Some(Recovery {
                    revision_id: revision_id.to_string(),
                    door,
                    pipeline,
                }),
            })
        }
    }
}

fn off(reason: Off) -> ActivatedUnit {
    ActivatedUnit {
        state: UnitAttachments::Off(reason),
        host: None,
        recovery: None,
    }
}

/// Activates every revision side by side (each probe bounded by `budget`),
/// so a slow door costs boot one budget, not one per revision. The first
/// misconfiguration refuses the whole activation, as before.
pub(crate) async fn activate_all<K: Eq + Hash>(
    items: Vec<(K, String, Option<MeteringConfig>)>,
    secrets: Arc<dyn SecretLookup>,
    budget: Duration,
) -> anyhow::Result<HashMap<K, ActivatedUnit>> {
    let probes = items.into_iter().map(|(key, revision_id, metering)| {
        let secrets = Arc::clone(&secrets);
        async move {
            activate_with(&revision_id, metering.as_ref(), secrets, budget)
                .await
                .map(|unit| (key, unit))
        }
    });
    Ok(futures_util::future::try_join_all(probes)
        .await?
        .into_iter()
        .collect())
}
