//! The per-unit attachments decision, taken at activation. A function of its
//! own so the refusal rules are testable without standing up a revision.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use futures_util::StreamExt;

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
/// Bounds the whole activation probe pass, however many doors it has.
pub(crate) const ACTIVATION_DEADLINE: Duration = Duration::from_secs(10);
/// Probes in flight at once: below the admin's four concurrent transfers.
pub(crate) const PROBE_CONCURRENCY: usize = 3;

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
#[cfg(test)]
pub(crate) async fn activate_with(
    revision_id: &str,
    metering: Option<&MeteringConfig>,
    secrets: Arc<dyn SecretLookup>,
    budget: Duration,
) -> anyhow::Result<ActivatedUnit> {
    let Some(door) = door_of(revision_id, metering)? else {
        return Ok(off(Off::NoDoor));
    };
    let deadline = tokio::time::Instant::now() + budget;
    let found = probe_one(&door, budget, deadline).await;
    unit_from(revision_id, door, found, &secrets)
}

/// The door a revision's metering block names, or a refusal naming the
/// revision.
fn door_of(revision_id: &str, metering: Option<&MeteringConfig>) -> anyhow::Result<Option<Door>> {
    door_for(metering)
        .map_err(|err| anyhow!(err))
        .with_context(|| refusal(revision_id))
}

fn refusal(revision_id: &str) -> String {
    format!("preparing inbound attachments for revision `{revision_id}`")
}

fn door_client(door: &Door) -> anyhow::Result<HttpArtifactStore> {
    HttpArtifactStore::new(door.url.clone(), door.token.clone(), DOOR_TIMEOUT)
        .map_err(|_| anyhow!("the artifacts door client could not be built; refusing to serve"))
}

/// One probe of one door, within `budget` and never past `deadline`. The
/// error (a `401`, a client that cannot be built) names the door, never the
/// token; it is a `String` so one probe can answer several revisions.
async fn probe_one(
    door: &Door,
    budget: Duration,
    deadline: tokio::time::Instant,
) -> Result<DoorProbe, String> {
    let left = deadline.saturating_duration_since(tokio::time::Instant::now());
    if left.is_zero() {
        return Ok(DoorProbe::Unavailable("timeout"));
    }
    let probe = door_client(door).map_err(|err| format!("{err:#}"))?;
    // The probe's client is dropped here: a connection it pooled belongs to
    // the runtime the probe ran on, and serving uses a fresh client.
    probe_door(&probe, &door.url, budget.min(left))
        .await
        .map_err(|err| format!("{err:#}"))
}

/// The unit a probe answer makes of one revision.
fn unit_from(
    revision_id: &str,
    door: Door,
    found: Result<DoorProbe, String>,
    secrets: &Arc<dyn SecretLookup>,
) -> anyhow::Result<ActivatedUnit> {
    let found = found
        .map_err(|err| anyhow!(err))
        .with_context(|| refusal(revision_id))?;
    let build_pipeline = |store: Arc<dyn ArtifactStore>| -> anyhow::Result<Arc<Pipeline>> {
        let fetcher = HttpFetcher::new(Arc::clone(secrets))
            .map_err(|_| anyhow!("the attachment download client could not be built"))
            .with_context(|| refusal(revision_id))?;
        Ok(Arc::new(Pipeline::new(store, Arc::new(fetcher))))
    };
    match found {
        DoorProbe::NotGranted => Ok(off(Off::NotGranted)),
        DoorProbe::Enabled => {
            let store: Arc<dyn ArtifactStore> =
                Arc::new(door_client(&door).with_context(|| refusal(revision_id))?);
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
            let store: Arc<dyn ArtifactStore> =
                Arc::new(door_client(&door).with_context(|| refusal(revision_id))?);
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

/// [`activate_all_within`] at the production deadline.
pub(crate) async fn activate_all<K: Eq + Hash>(
    items: Vec<(K, String, Option<MeteringConfig>)>,
    secrets: Arc<dyn SecretLookup>,
    budget: Duration,
) -> anyhow::Result<HashMap<K, ActivatedUnit>> {
    activate_all_within(items, secrets, budget, ACTIVATION_DEADLINE).await
}

/// Activates every revision. Each distinct door (URL and token) is probed
/// ONCE however many revisions share it; at most [`PROBE_CONCURRENCY`] probes
/// run at a time (the admin runs four transfers per process and refuses the
/// rest); each probe is bounded by `budget` and the whole pass by `deadline`,
/// after which a door not yet probed is reported unavailable without a probe
/// (it recovers in the background). The first misconfiguration refuses the
/// whole activation, as before.
pub(crate) async fn activate_all_within<K: Eq + Hash>(
    items: Vec<(K, String, Option<MeteringConfig>)>,
    secrets: Arc<dyn SecretLookup>,
    budget: Duration,
    deadline: Duration,
) -> anyhow::Result<HashMap<K, ActivatedUnit>> {
    let deadline = tokio::time::Instant::now() + deadline;
    let mut planned = Vec::with_capacity(items.len());
    let mut doors: Vec<Door> = Vec::new();
    for (key, revision_id, metering) in items {
        let door = door_of(&revision_id, metering.as_ref())?;
        if let Some(door) = &door
            && !doors.iter().any(|d| same_door(d, door))
        {
            doors.push(door.clone());
        }
        planned.push((key, revision_id, door));
    }
    let answers: Vec<(Door, Result<DoorProbe, String>)> = futures_util::stream::iter(doors)
        .map(|door| async move {
            let found = probe_one(&door, budget, deadline).await;
            (door, found)
        })
        .buffer_unordered(PROBE_CONCURRENCY)
        .collect()
        .await;
    let mut units = HashMap::with_capacity(planned.len());
    for (key, revision_id, door) in planned {
        let unit = match door {
            None => off(Off::NoDoor),
            Some(door) => {
                let found = answers
                    .iter()
                    .find(|(probed, _)| same_door(probed, &door))
                    .map(|(_, found)| found.clone())
                    .unwrap_or(Ok(DoorProbe::Unavailable("timeout")));
                unit_from(&revision_id, door, found, &secrets)?
            }
        };
        units.insert(key, unit);
    }
    Ok(units)
}

fn same_door(a: &Door, b: &Door) -> bool {
    a.url == b.url && a.token == b.token
}
