//! Per-trigger concurrency and hourly budget (contract §6.6).
//!
//! Concurrency is enforced per process: an in-flight permit is held for the
//! whole flow run, and a firing that finds none free is skipped (cron) or
//! answered 429 (webhook). The budget is counted in the shared trigger store,
//! so with Redis it holds across replicas.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use chrono::Utc;
use dashmap::DashMap;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::store::{self, TriggerStore};
use super::table::LoadedTrigger;

static IN_FLIGHT: LazyLock<DashMap<String, Arc<Semaphore>>> = LazyLock::new(DashMap::new);

/// Budget windows are clock hours; the key outlives its hour slightly so a
/// counter is never read after it expired mid-hour.
const BUDGET_TTL: Duration = Duration::from_secs(3_700);

/// Try to take one in-flight slot for this trigger on this revision. The limit
/// is part of the key, so a revision that changes `max_concurrency` gets a
/// fresh semaphore rather than inheriting the old size.
pub(crate) fn try_acquire(loaded: &LoadedTrigger) -> Option<OwnedSemaphorePermit> {
    let key = format!(
        "{}:{}:{}:{}",
        loaded.scope.deployment_id,
        loaded.scope.revision_id,
        loaded.spec.trigger_id,
        loaded.spec.max_concurrency
    );
    let semaphore = IN_FLIGHT
        .entry(key)
        .or_insert_with(|| Arc::new(Semaphore::new(loaded.spec.max_concurrency as usize)))
        .clone();
    semaphore.try_acquire_owned().ok()
}

/// Whether one more firing fits this hour's budget. Counts the attempt.
///
/// Fails OPEN on a store error, with a warning: a budget is a cost guard, and
/// an unreachable Redis silencing every trigger would be the larger outage.
/// The fire-once lock and the idempotency set make the opposite choice for the
/// opposite reason — see the scheduler and the webhook handler.
pub(crate) async fn within_budget(
    store: &dyn TriggerStore,
    env: &str,
    loaded: &LoadedTrigger,
) -> bool {
    let Some(max) = loaded.spec.max_firings_per_hour else {
        return true;
    };
    let hour = Utc::now().format("%Y%m%d%H").to_string();
    let key = store::key(
        "budget",
        env,
        &loaded.scope.deployment_id.to_string(),
        &loaded.spec.trigger_id,
        &hour,
    );
    match store.incr(&key, BUDGET_TTL).await {
        Ok(count) => count <= u64::from(max),
        Err(err) => {
            crate::operator_log::warn(
                module_path!(),
                format!(
                    "trigger `{}`: budget store unavailable ({err:#}); firing without the \
                     hourly cap",
                    loaded.spec.trigger_id
                ),
            );
            true
        }
    }
}
