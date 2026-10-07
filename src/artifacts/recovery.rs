//! The background re-probe of a unit whose artifacts door was down at
//! activation: waits (30 s, doubling to 5 min), probes with a client of its
//! own, and on the door's answer swaps the unit's decision in place, so
//! attachments come on without a restart. It ends on any decisive answer or
//! when the activation that owns the unit is gone (it holds only a `Weak`).

use std::sync::{Arc, Weak};
use std::time::Duration;

use crate::operator_log;

use super::activate::{DOOR_TIMEOUT, PROBE_BUDGET, Recovery};
use super::boot::{DoorProbe, probe_door};
use super::store::HttpArtifactStore;
use super::unit::{Off, UnitAttachments, UnitCell};

#[derive(Debug, Clone, Copy)]
pub(crate) struct Backoff {
    pub first: Duration,
    pub max: Duration,
    /// Bounds one probe end to end.
    pub budget: Duration,
}

pub(crate) const RECOVERY_BACKOFF: Backoff = Backoff {
    first: Duration::from_secs(30),
    max: Duration::from_secs(300),
    budget: PROBE_BUDGET,
};

pub(crate) fn next_wait(wait: Duration, backoff: &Backoff) -> Duration {
    wait.saturating_mul(2).min(backoff.max)
}

/// Spawns the re-probe on the current runtime (the activation runtime, which
/// lives for the environment's lifetime).
pub(crate) fn spawn_recovery(
    cell: Weak<UnitCell>,
    recovery: Recovery,
    backoff: Backoff,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run(cell, recovery, backoff))
}

async fn run(cell: Weak<UnitCell>, recovery: Recovery, backoff: Backoff) {
    let Recovery {
        revision_id,
        door,
        pipeline,
    } = recovery;
    let mut wait = backoff.first;
    loop {
        tokio::time::sleep(wait).await;
        if cell.strong_count() == 0 {
            return;
        }
        // Its own client: nothing it pools is shared with the serving one.
        let Ok(probe) = HttpArtifactStore::new(door.url.clone(), door.token.clone(), DOOR_TIMEOUT)
        else {
            wait = next_wait(wait, &backoff);
            continue;
        };
        let found = probe_door(&probe, &door.url, backoff.budget).await;
        let Some(cell) = cell.upgrade() else {
            return;
        };
        match found {
            Ok(DoorProbe::Enabled) => {
                cell.set(UnitAttachments::Enabled {
                    pipeline: Arc::clone(&pipeline),
                });
                operator_log::info(
                    module_path!(),
                    format!(
                        "the artifacts door answered; inbound attachments enabled for revision \
                         `{revision_id}`"
                    ),
                );
                return;
            }
            Ok(DoorProbe::NotGranted) => {
                cell.set(UnitAttachments::Off(Off::NotGranted));
                return;
            }
            // Still down, or a credential the door now rejects: keep the unit
            // serving without attachments and keep asking, more slowly.
            Ok(DoorProbe::Unavailable(_)) | Err(_) => {
                wait = next_wait(wait, &backoff);
            }
        }
    }
}
