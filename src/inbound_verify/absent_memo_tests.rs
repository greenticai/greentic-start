//! An unauthenticated POST must not cost up to eight secret-store reads every
//! time when the channel simply has no secret: "absent" is remembered briefly.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use greentic_deploy_spec::DeploymentId;
use greentic_secrets_lib::{SecretError, SecretsManager};

use super::absent_memo::{ABSENT_TTL, AbsentMemo};
use super::mod_tests::inbound;
use super::notices::Notices;
use super::{Deps, Verdict, verify_with};
use crate::secrets_gate::DynSecretsManager;

/// Counts reads; answers `value` for every URI when set, else `NotFound`.
struct Counting {
    reads: Mutex<usize>,
    value: Mutex<Option<String>>,
}

#[async_trait::async_trait]
impl SecretsManager for Counting {
    async fn read(&self, path: &str) -> greentic_secrets_lib::Result<Vec<u8>> {
        *self.reads.lock().unwrap() += 1;
        match self.value.lock().unwrap().clone() {
            Some(v) => Ok(v.into_bytes()),
            None => Err(SecretError::NotFound(path.to_string())),
        }
    }
    async fn write(&self, _: &str, _: &[u8]) -> greentic_secrets_lib::Result<()> {
        Ok(())
    }
    async fn delete(&self, _: &str) -> greentic_secrets_lib::Result<()> {
        Ok(())
    }
}

/// The verdict, or `None` when the request was refused (a configured
/// channel and no signature).
async fn post_at(store: &Arc<Counting>, memo: &AbsentMemo, at: Instant) -> Option<Verdict> {
    post_at_clocks(store, memo, 1_000, at).await
}

/// With the wall clock (`now`, token checks) and the monotonic clock (`at`,
/// the memo) set separately.
async fn post_at_clocks(
    store: &Arc<Counting>,
    memo: &AbsentMemo,
    now: u64,
    at: Instant,
) -> Option<Verdict> {
    let manager: DynSecretsManager = store.clone();
    let (notices, _) = Notices::recording();
    let deps = Deps {
        secrets: &manager,
        env: "local",
        notices: &notices,
        bf_keys: None,
        now,
        instant: at,
        teams_service_hosts: &[],
        absent_memo: memo,
    };
    verify_with(
        inbound(
            "messaging.whatsapp",
            "POST",
            &[],
            b"{}",
            DeploymentId::new(),
        ),
        &deps,
    )
    .await
    .ok()
}

fn reads(store: &Arc<Counting>) -> usize {
    *store.reads.lock().unwrap()
}

#[tokio::test]
async fn an_absent_secret_is_remembered_for_a_few_seconds() {
    let store = Arc::new(Counting {
        reads: Mutex::new(0),
        value: Mutex::new(None),
    });
    let memo = AbsentMemo::default();
    let t0 = Instant::now();
    assert_eq!(
        post_at(&store, &memo, t0).await,
        Some(Verdict::NotConfigured)
    );
    let first = reads(&store);
    assert!(first > 0);
    assert_eq!(
        post_at(&store, &memo, t0 + ABSENT_TTL - Duration::from_millis(1)).await,
        Some(Verdict::NotConfigured)
    );
    assert_eq!(
        reads(&store),
        first,
        "the store was read again inside the window"
    );
    post_at(&store, &memo, t0 + ABSENT_TTL).await;
    assert!(reads(&store) > first, "never re-read after the window");
}

#[tokio::test]
async fn a_found_secret_is_never_remembered() {
    let store = Arc::new(Counting {
        reads: Mutex::new(0),
        value: Mutex::new(Some("app-secret".into())),
    });
    let memo = AbsentMemo::default();
    let t0 = Instant::now();
    assert_eq!(
        post_at(&store, &memo, t0).await,
        None,
        "refused: no signature"
    );
    let first = reads(&store);
    assert_eq!(
        post_at(&store, &memo, t0 + Duration::from_secs(1)).await,
        None
    );
    assert_eq!(
        reads(&store),
        2 * first,
        "a stored secret is read every time"
    );
}

#[test]
fn the_window_is_between_five_and_ten_seconds() {
    assert!((5..=10).contains(&ABSENT_TTL.as_secs()));
}

#[test]
fn the_memo_is_bounded() {
    let memo = AbsentMemo::default();
    for i in 0..(super::absent_memo::MAX_ENTRIES + 10) {
        memo.record(format!("k{i}"), Instant::now());
    }
    assert!(memo.len() <= super::absent_memo::MAX_ENTRIES);
}

/// Re-review G4 M6: the memo runs on the MONOTONIC clock. A wall clock that
/// steps backwards (NTP) must not make "absent" stick past its window, and one
/// that steps forwards must not expire it early.
#[tokio::test]
async fn the_window_ignores_wall_clock_steps() {
    let store = Arc::new(Counting {
        reads: Mutex::new(0),
        value: Mutex::new(None),
    });
    let memo = AbsentMemo::default();
    let t0 = Instant::now();
    post_at_clocks(&store, &memo, 1_000, t0).await;
    let first = reads(&store);
    // Wall clock jumped forward an hour, monotonic barely moved: still absent.
    post_at_clocks(&store, &memo, 4_600, t0 + Duration::from_secs(1)).await;
    assert_eq!(reads(&store), first, "a forward wall step expired the memo");
    // Wall clock stepped back, monotonic past the window: re-read.
    post_at_clocks(&store, &memo, 900, t0 + ABSENT_TTL).await;
    assert!(reads(&store) > first, "a backward wall step froze the memo");
}
