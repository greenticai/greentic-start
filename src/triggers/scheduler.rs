//! The cron trigger loop: one task for the life of the revision server.
//!
//! Deliberately NOT one task per revision. Each second the loop reads the
//! CURRENT activation, so a reload is picked up on the next tick with nothing
//! to start or stop, and a firing is served by the revision the traffic split
//! would pick for a request at that moment (§7.1). Shutdown is aborting this
//! one task.
//!
//! Per due tick, in order:
//! 1. pick the revision once per `(deployment, trigger, tick)` — several
//!    revisions of one deployment may declare the same trigger during a
//!    split, and each must not roll its own dice;
//! 2. only the entry declared by the picked revision may fire;
//! 3. claim the tick in the shared store — one firer across replicas;
//! 4. budget, then an in-flight permit (overlap skips, §6.3.1);
//! 5. dispatch in a spawned task holding the permit.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use greentic_deploy_spec::{DeploymentId, RevisionId};
use greentic_runner_host::RunnerHost;

use super::cron::latest_due;
use super::dispatch::{self, Firing};
use super::schema::TriggerKind;
use super::store::{self, TriggerStore};
use super::table::LoadedTrigger;
use super::webhook::TriggerHost;
use super::{limits, telemetry};
use crate::deployment_routes::RevisionIngressRouting;
use crate::revision_dispatcher::DispatchRequest;

/// A claimed tick stays claimed well past any replica's clock skew.
const TICK_CLAIM_TTL: Duration = Duration::from_secs(3_600);

/// Run until aborted. `current` returns the live activation's host and
/// routing each time it is called.
pub(crate) async fn run<F>(current: F, store: Arc<dyn TriggerStore>)
where
    F: Fn() -> (Arc<RunnerHost>, Arc<RevisionIngressRouting>) + Send + Sync + 'static,
{
    let mut last = Utc::now();
    loop {
        let now = Utc::now();
        let to_next_second = 1_000 - u64::from(now.timestamp_subsec_millis());
        tokio::time::sleep(Duration::from_millis(to_next_second.max(1))).await;
        let now = Utc::now();
        let (host, routing) = current();
        tick(&host, &routing, &store, last, now).await;
        last = now;
    }
}

async fn tick(
    host: &Arc<RunnerHost>,
    routing: &Arc<RevisionIngressRouting>,
    store: &Arc<dyn TriggerStore>,
    after: DateTime<Utc>,
    upto: DateTime<Utc>,
) {
    let env = routing.dispatcher.env_id().to_string();
    let mut picks: HashMap<(DeploymentId, String, i64), Option<RevisionId>> = HashMap::new();
    for entry in routing.triggers.cron_entries() {
        let TriggerKind::Cron(cron) = &entry.spec.kind else {
            continue;
        };
        let Some(due) = latest_due(&cron.schedule, cron.timezone, after, upto) else {
            continue;
        };
        let pick_key = (
            entry.scope.deployment_id,
            entry.spec.trigger_id.clone(),
            due.timestamp(),
        );
        let picked = match picks.get(&pick_key) {
            Some(picked) => *picked,
            None => {
                let picked = pick_revision(routing, &env, entry).await;
                picks.insert(pick_key, picked);
                picked
            }
        };
        if picked != Some(entry.scope.revision_id) {
            continue;
        }
        fire_due(host, store, &env, entry, cron, due).await;
    }
}

/// The revision the traffic split serves right now. No session hint, so the
/// pick is the weighted one and writes no pin.
async fn pick_revision(
    routing: &RevisionIngressRouting,
    env: &str,
    entry: &LoadedTrigger,
) -> Option<RevisionId> {
    let request = DispatchRequest {
        env_id: env,
        tenant: &entry.tenant,
        deployment_id: entry.scope.deployment_id,
        session_hint: None,
        defer_pin: true,
        trusted: false,
        header_revision: None,
        cookie: None,
    };
    let mut rng: rand::rngs::SmallRng = rand::make_rng();
    match routing.dispatcher.dispatch(&request, &mut rng).await {
        Ok(outcome) => Some(outcome.revision_id),
        Err(err) => {
            crate::operator_log::warn(
                module_path!(),
                format!(
                    "trigger `{}`: no revision to serve deployment {} ({err:#})",
                    entry.spec.trigger_id, entry.scope.deployment_id
                ),
            );
            None
        }
    }
}

async fn fire_due(
    host: &Arc<RunnerHost>,
    store: &Arc<dyn TriggerStore>,
    env: &str,
    entry: &Arc<LoadedTrigger>,
    cron: &super::schema::CronSpec,
    due: DateTime<Utc>,
) {
    if !entry.spec.enabled {
        telemetry::record(entry, "skipped", "disabled");
        return;
    }
    if entry.unavailable.is_some() {
        telemetry::record(entry, "skipped", "unavailable");
        return;
    }
    // One firer per tick. A store ERROR skips the tick: firing anyway would
    // let every replica fire it, which multiplies whatever the flow does.
    let claim_key = store::key(
        "fire",
        env,
        &entry.scope.deployment_id.to_string(),
        &entry.spec.trigger_id,
        &due.timestamp().to_string(),
    );
    match store.claim(&claim_key, TICK_CLAIM_TTL).await {
        Ok(true) => {}
        Ok(false) => return,
        Err(err) => {
            crate::operator_log::warn(
                module_path!(),
                format!(
                    "trigger `{}`: tick {due} skipped, store unavailable ({err:#})",
                    entry.spec.trigger_id
                ),
            );
            telemetry::record(entry, "skipped", "store_unavailable");
            return;
        }
    }
    if !limits::within_budget(store.as_ref(), env, entry).await {
        telemetry::record(entry, "skipped", "budget");
        return;
    }
    let Some(permit) = limits::try_acquire(entry) else {
        telemetry::record(entry, "skipped", "overlap");
        return;
    };
    let firing_id = dispatch::new_firing_id();
    let firing = Firing {
        session_hint: dispatch::session_hint(&entry.spec, &firing_id, None),
        payload: dispatch::cron_payload(&entry.spec, cron, &firing_id, Utc::now(), due),
        firing_id,
    };
    super::webhook::RunnerTriggerHost(Arc::clone(host)).spawn_fire(
        Arc::clone(entry),
        firing,
        permit,
    );
}
