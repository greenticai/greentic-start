//! A unit whose door was down at boot turns attachments on by itself once the
//! door answers, without a restart, and stops probing when it does or when
//! its activation is gone.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use crate::interop::metering::testkit::{StubAdmin, metering_for};

use super::activate::activate_with;
use super::fetch::SecretLookup;
use super::origin::SecretScope;
use super::recovery::{Backoff, Reporter, next_wait, spawn_recovery, spawn_recovery_reporting};
use super::time_testkit::within_ceiling;
use super::unit::{Off, UnitAttachments, UnitCell};

struct NoSecrets;

#[async_trait]
impl SecretLookup for NoSecrets {
    async fn get(&self, _: &SecretScope, _: &str) -> Option<String> {
        None
    }
}

const FAST: Backoff = Backoff {
    first: Duration::from_millis(20),
    max: Duration::from_millis(80),
    budget: Duration::from_secs(2),
};

const NOT_FOUND: &str = r#"{"error":{"code":"not_found"}}"#;

type Reports = Arc<Mutex<Vec<(String, &'static str)>>>;

fn recording() -> (Reporter, Reports) {
    let reports: Reports = Arc::default();
    let sink = Arc::clone(&reports);
    let reporter: Reporter = Arc::new(move |revision: &str, code: &'static str| {
        sink.lock().unwrap().push((revision.to_string(), code));
    });
    (reporter, reports)
}

/// Activates against `stub` (whose FIRST answer must make the door
/// unavailable) and starts the re-probe, reporting into `reporter`.
async fn unavailable_unit_reporting(
    stub: &StubAdmin,
    reporter: Reporter,
) -> (Arc<UnitCell>, tokio::task::JoinHandle<()>) {
    let port = reqwest::Url::parse(&stub.url).unwrap().port().unwrap();
    let metering = metering_for(&format!(
        "http://127.0.0.1:{port}/api/v1/ingest/worker-usage"
    ));
    let unit = activate_with("rev-1", Some(&metering), Arc::new(NoSecrets), FAST.budget)
        .await
        .expect("activates");
    let cell = Arc::new(UnitCell::new(unit.state));
    let task = spawn_recovery_reporting(
        Arc::downgrade(&cell),
        unit.recovery.expect("a re-probe is owed"),
        FAST,
        reporter,
    );
    (cell, task)
}

/// A token the door starts rejecting while the unit waits is said ONCE (a
/// fixed code and the revision), the unit stays off, and the re-probe keeps
/// going: a rotated token is fixed by a redeploy, a flapping admin by time.
#[tokio::test]
async fn a_rejected_token_during_the_re_probe_is_warned_once_and_retried() {
    let stub = StubAdmin::answering_in_turn(&[
        ("HTTP/1.1 500 Internal Server Error", "", "{}"),
        ("HTTP/1.1 401 Unauthorized", "", "{}"),
    ])
    .await;
    let (reporter, reports) = recording();
    let (cell, task) = unavailable_unit_reporting(&stub, reporter).await;
    within_ceiling(async {
        while stub.count() < 5 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(matches!(
        *cell.current(),
        UnitAttachments::Off(Off::DoorUnavailable)
    ));
    assert_eq!(
        *reports.lock().unwrap(),
        [("rev-1".to_string(), "rejected_token")],
        "one warning, not one per attempt"
    );
    assert!(!task.is_finished(), "a 401 keeps the re-probe going");
    task.abort();
}

#[tokio::test]
async fn a_re_probe_ending_without_the_purpose_says_so_once() {
    let stub = StubAdmin::answering_in_turn(&[
        ("HTTP/1.1 500 Internal Server Error", "", "{}"),
        (
            "HTTP/1.1 403 Forbidden",
            "",
            r#"{"error":{"code":"purpose_not_granted"}}"#,
        ),
    ])
    .await;
    let (reporter, reports) = recording();
    let (_cell, task) = unavailable_unit_reporting(&stub, reporter).await;
    within_ceiling(task).await.expect("the re-probe ends");
    assert_eq!(
        *reports.lock().unwrap(),
        [("rev-1".to_string(), "purpose_not_granted")]
    );
}

/// Activates against `stub` (whose FIRST answer must make the door
/// unavailable) and starts the re-probe.
async fn unavailable_unit(stub: &StubAdmin) -> (Arc<UnitCell>, tokio::task::JoinHandle<()>) {
    let port = reqwest::Url::parse(&stub.url).unwrap().port().unwrap();
    let metering = metering_for(&format!(
        "http://127.0.0.1:{port}/api/v1/ingest/worker-usage"
    ));
    let unit = activate_with("rev-1", Some(&metering), Arc::new(NoSecrets), FAST.budget)
        .await
        .expect("activates");
    assert!(matches!(
        unit.state,
        UnitAttachments::Off(Off::DoorUnavailable)
    ));
    let cell = Arc::new(UnitCell::new(unit.state));
    let task = spawn_recovery(
        Arc::downgrade(&cell),
        unit.recovery.expect("a re-probe is owed"),
        FAST,
    );
    (cell, task)
}

async fn until(cell: &UnitCell, want: fn(&UnitAttachments) -> bool) {
    within_ceiling(async {
        while !want(&cell.current()) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
}

#[tokio::test]
async fn a_door_that_comes_back_turns_attachments_on_without_a_restart() {
    let stub = StubAdmin::answering_in_turn(&[
        ("HTTP/1.1 500 Internal Server Error", "", "{}"),
        ("HTTP/1.1 500 Internal Server Error", "", "{}"),
        ("HTTP/1.1 404 Not Found", "", NOT_FOUND),
    ])
    .await;
    let (cell, task) = unavailable_unit(&stub).await;
    until(&cell, |s| matches!(s, UnitAttachments::Enabled { .. })).await;
    within_ceiling(task)
        .await
        .expect("the re-probe ends on success");
    let probes = stub.count();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(stub.count(), probes, "no probe after success");
}

#[tokio::test]
async fn a_door_that_comes_back_without_the_purpose_turns_attachments_off_for_good() {
    let stub = StubAdmin::answering_in_turn(&[
        ("HTTP/1.1 500 Internal Server Error", "", "{}"),
        (
            "HTTP/1.1 403 Forbidden",
            "",
            r#"{"error":{"code":"purpose_not_granted"}}"#,
        ),
    ])
    .await;
    let (cell, task) = unavailable_unit(&stub).await;
    within_ceiling(task).await.expect("the re-probe ends");
    assert!(matches!(
        *cell.current(),
        UnitAttachments::Off(Off::NotGranted)
    ));
}

#[tokio::test]
async fn the_re_probe_stops_when_its_activation_is_gone() {
    let stub = StubAdmin::answering("HTTP/1.1 500 Internal Server Error", "", "{}").await;
    let (cell, task) = unavailable_unit(&stub).await;
    drop(cell);
    within_ceiling(task)
        .await
        .expect("the re-probe ends once nobody holds the unit");
}

#[test]
fn the_wait_doubles_up_to_the_cap() {
    let backoff = Backoff {
        first: Duration::from_secs(30),
        max: Duration::from_secs(300),
        budget: Duration::from_secs(8),
    };
    let mut wait = backoff.first;
    let mut seen = vec![wait];
    for _ in 0..6 {
        wait = next_wait(wait, &backoff);
        seen.push(wait);
    }
    let secs: Vec<u64> = seen.iter().map(Duration::as_secs).collect();
    assert_eq!(secs, [30, 60, 120, 240, 300, 300, 300]);
}
