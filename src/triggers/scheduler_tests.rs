use std::sync::Arc;

use chrono::{TimeZone, Utc};

use super::scheduler::claim_tick;
use super::store::{InMemoryTriggerStore, TriggerStore};

/// Two replicas, one backend. The shared `Arc` plays the part of the Redis both
/// replicas point at: the store trait is the whole seam the scheduler depends
/// on, so this exercises the same claim path production takes.
#[tokio::test]
async fn two_instances_sharing_a_backend_fire_each_tick_once() {
    let shared: Arc<dyn TriggerStore> = Arc::new(InMemoryTriggerStore::default());
    for minute in 0..20 {
        let due = Utc.timestamp_opt(1_800_000_000 + minute * 60, 0).unwrap();
        let a = Arc::clone(&shared);
        let b = Arc::clone(&shared);
        let first =
            tokio::spawn(
                async move { claim_tick(a.as_ref(), "prod", "dep-1", "nightly", due).await },
            );
        let second =
            tokio::spawn(
                async move { claim_tick(b.as_ref(), "prod", "dep-1", "nightly", due).await },
            );
        let first = first.await.unwrap().unwrap();
        let second = second.await.unwrap().unwrap();
        assert!(
            first ^ second,
            "exactly one instance may fire tick {minute}: first={first} second={second}"
        );
    }
}

/// The contrast that makes the sharing meaningful: per-instance stores (the
/// default without a shared backend) both win the same tick.
#[tokio::test]
async fn instances_with_separate_stores_both_fire_the_same_tick() {
    let a = InMemoryTriggerStore::default();
    let b = InMemoryTriggerStore::default();
    let due = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
    assert!(
        claim_tick(&a, "prod", "dep-1", "nightly", due)
            .await
            .unwrap()
    );
    assert!(
        claim_tick(&b, "prod", "dep-1", "nightly", due)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_different_trigger_or_tick_is_claimed_independently() {
    let store = InMemoryTriggerStore::default();
    let t0 = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
    let t1 = Utc.timestamp_opt(1_800_000_060, 0).unwrap();
    assert!(claim_tick(&store, "prod", "dep-1", "a", t0).await.unwrap());
    assert!(claim_tick(&store, "prod", "dep-1", "b", t0).await.unwrap());
    assert!(claim_tick(&store, "prod", "dep-1", "a", t1).await.unwrap());
    assert!(!claim_tick(&store, "prod", "dep-1", "a", t0).await.unwrap());
}
