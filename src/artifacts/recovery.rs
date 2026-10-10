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

/// Where the re-probe reports a decisive refusal: the revision id and a fixed
/// code (`rejected_token`, `purpose_not_granted`), never a URL or token.
pub(crate) type Reporter = Arc<dyn Fn(&str, &'static str) + Send + Sync>;

/// Spawns the re-probe on the current runtime (the activation runtime, which
/// lives for the environment's lifetime), reporting to the operator log.
pub(crate) fn spawn_recovery(
    cell: Weak<UnitCell>,
    recovery: Recovery,
    backoff: Backoff,
) -> tokio::task::JoinHandle<()> {
    spawn_recovery_reporting(cell, recovery, backoff, Arc::new(operator_report))
}

fn operator_report(revision_id: &str, code: &'static str) {
    let what = match code {
        "rejected_token" => {
            "the artifacts door now rejects this unit's credential; inbound attachments stay \
             off and the door keeps being asked (a redeploy with a valid token fixes it)"
        }
        _ => "the unit's credential carries no artifacts purpose; inbound attachments stay off",
    };
    operator_log::warn(
        module_path!(),
        format!("{what} (revision `{revision_id}`, {code})"),
    );
}

pub(crate) fn spawn_recovery_reporting(
    cell: Weak<UnitCell>,
    recovery: Recovery,
    backoff: Backoff,
    report: Reporter,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run(cell, recovery, backoff, report))
}

async fn run(cell: Weak<UnitCell>, recovery: Recovery, backoff: Backoff, report: Reporter) {
    let Recovery {
        revision_id,
        door,
        pipeline,
    } = recovery;
    let mut wait = backoff.first;
    let mut rejected_said = false;
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
                report(&revision_id, "purpose_not_granted");
                return;
            }
            // A credential the door now rejects (`401`): said once, then the
            // same as down — the unit serves without attachments and the door
            // keeps being asked, more slowly.
            Err(_) => {
                if !rejected_said {
                    rejected_said = true;
                    report(&revision_id, "rejected_token");
                }
                wait = next_wait(wait, &backoff);
            }
            Ok(DoorProbe::Unavailable(_)) => {
                wait = next_wait(wait, &backoff);
            }
        }
    }
}
