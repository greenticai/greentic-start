use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::interop::metering::testkit::{
    StubAdmin, TEST_TOKEN, closed_port, metering_for, silent_peer,
};

use super::activate::{ActivatedUnit, activate, activate_all, activate_with};
use super::fetch::SecretLookup;
use super::origin::SecretScope;
use super::time_testkit::within_ceiling;
use super::unit::{Off, UnitAttachments};

struct NoSecrets;

#[async_trait]
impl SecretLookup for NoSecrets {
    async fn get(&self, _: &SecretScope, _: &str) -> Option<String> {
        None
    }
}

fn staged_at(port: u16) -> crate::interop::metering::MeteringConfig {
    metering_for(&format!(
        "http://127.0.0.1:{port}/api/v1/ingest/worker-usage"
    ))
}

fn port_of(stub: &StubAdmin) -> u16 {
    reqwest::Url::parse(&stub.url).unwrap().port().unwrap()
}

const BUDGET: Duration = Duration::from_secs(3);

async fn activate_at(port: u16) -> anyhow::Result<ActivatedUnit> {
    within_ceiling(activate_with(
        "rev-1",
        Some(&staged_at(port)),
        Arc::new(NoSecrets),
        BUDGET,
    ))
    .await
}

#[tokio::test]
async fn no_metering_block_means_no_door() {
    let got = activate("rev-1", None, Arc::new(NoSecrets)).await.unwrap();
    assert!(matches!(got.state, UnitAttachments::Off(Off::NoDoor)));
    assert!(got.host.is_none() && got.recovery.is_none());
}

/// A door that is down at boot (Cloud Run cold start, an admin deploy) must
/// not take the unit down: it serves without attachments and recovers.
#[tokio::test]
async fn a_dead_door_runs_the_unit_without_attachments_and_recovers_later() {
    let closed = closed_port().await;
    let got = activate_at(closed.port)
        .await
        .expect("a door that is down is not a misconfiguration");
    assert!(matches!(
        got.state,
        UnitAttachments::Off(Off::DoorUnavailable)
    ));
    assert!(got.recovery.is_some(), "a background re-probe is owed");
    assert!(
        got.host.is_some(),
        "the reader and port are installed; they answer per call"
    );
    assert!(!format!("{:?}", got.recovery).contains(TEST_TOKEN));
}

#[tokio::test]
async fn transient_door_answers_run_the_unit_without_attachments() {
    for status in [
        "HTTP/1.1 500 Internal Server Error",
        "HTTP/1.1 404 Not Found",
        "HTTP/1.1 429 Too Many Requests",
    ] {
        let stub = StubAdmin::answering(status, "", "{}").await;
        let got = activate_at(port_of(&stub)).await.expect(status);
        assert!(
            matches!(got.state, UnitAttachments::Off(Off::DoorUnavailable)),
            "{status}"
        );
    }
}

#[tokio::test]
async fn an_unauthorised_token_refuses_activation_without_printing_it() {
    let stub = StubAdmin::answering("HTTP/1.1 401 Unauthorized", "", "{}").await;
    let err = activate_at(port_of(&stub))
        .await
        .err()
        .expect("a bad token is a misconfiguration");
    let text = format!("{err:#}");
    assert!(
        text.contains("rev-1") && text.contains("refusing to serve"),
        "{text}"
    );
    assert!(!text.contains(TEST_TOKEN), "{text}");
}

#[tokio::test]
async fn an_unsafe_or_credential_carrying_endpoint_refuses_activation() {
    for endpoint in [
        "http://admin.example/api/v1/ingest/worker-usage",
        "https://user:hunter2@admin.example/api/v1/ingest/worker-usage",
    ] {
        let err = activate("rev-1", Some(&metering_for(endpoint)), Arc::new(NoSecrets))
            .await
            .err()
            .unwrap_or_else(|| panic!("{endpoint} accepted"));
        assert!(!format!("{err:#}").contains("hunter2"));
    }
}

#[tokio::test]
async fn a_token_without_the_purpose_activates_with_attachments_off() {
    let body = r#"{"error":{"code":"purpose_not_granted"}}"#;
    let stub = StubAdmin::answering("HTTP/1.1 403 Forbidden", "", body).await;
    let got = activate_at(port_of(&stub))
        .await
        .expect("an opted-out unit still activates");
    assert!(matches!(got.state, UnitAttachments::Off(Off::NotGranted)));
    assert!(got.host.is_none() && got.recovery.is_none());
}

#[tokio::test]
async fn a_reachable_door_turns_attachments_on() {
    let body = r#"{"error":{"code":"not_found"}}"#;
    let stub = StubAdmin::answering("HTTP/1.1 404 Not Found", "", body).await;
    let got = activate_at(port_of(&stub))
        .await
        .expect("a reachable door activates");
    assert!(matches!(got.state, UnitAttachments::Enabled { .. }));
    assert!(got.recovery.is_none());
    assert!(stub.count() >= 1, "the probe reached the door");
}

/// The agent reader an enabled unit hands its runner asks the door this
/// activation probed, with this unit's staged token; an off unit hands none.
#[tokio::test(flavor = "multi_thread")]
async fn an_enabled_units_reader_uses_the_probed_door_and_the_staged_token() {
    let body = r#"{"error":{"code":"not_found"}}"#;
    let stub = StubAdmin::answering("HTTP/1.1 404 Not Found", "", body).await;
    let got = activate_at(port_of(&stub)).await.expect("activates");
    let probes = stub.count();
    let reader = got
        .host
        .as_ref()
        .expect("attachments on")
        .reader()
        .expect("reader");
    let id = "artifact://cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let _ = reader.get(id).await;
    let raw = stub.received();
    let last = raw.get(probes).expect("the reader reached the door");
    assert!(
        last.starts_with("POST /api/v1/ingest/artifacts/get "),
        "{last}"
    );
    assert!(last.contains(&format!("Bearer {TEST_TOKEN}")), "{last}");
}

/// Revisions are probed side by side (at most `PROBE_CONCURRENCY` at once):
/// four hanging doors cost two budgets in total, not four. Virtual time, so
/// a loaded machine cannot make it flaky.
#[tokio::test(start_paused = true)]
async fn revisions_are_probed_in_parallel_and_each_probe_is_bounded() {
    let mut items = Vec::new();
    for n in 0..4 {
        items.push((n, format!("rev-{n}"), Some(staged_at(silent_peer().await))));
    }
    let budget = Duration::from_millis(500);
    let started = tokio::time::Instant::now();
    let got = within_ceiling(activate_all(items, Arc::new(NoSecrets), budget))
        .await
        .expect("hanging doors are unavailable, not refusals");
    assert!(
        started.elapsed() <= budget * 2 + Duration::from_millis(100),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(got.len(), 4);
    for unit in got.values() {
        assert!(matches!(
            unit.state,
            UnitAttachments::Off(Off::DoorUnavailable)
        ));
    }
}

#[tokio::test]
async fn one_misconfigured_revision_refuses_the_activation() {
    let unauthorised = StubAdmin::answering("HTTP/1.1 401 Unauthorized", "", "{}").await;
    let items = vec![
        (0, "rev-0".to_string(), None),
        (
            1,
            "rev-1".to_string(),
            Some(staged_at(port_of(&unauthorised))),
        ),
    ];
    let err = within_ceiling(activate_all(items, Arc::new(NoSecrets), BUDGET))
        .await
        .err()
        .expect("a 401 refuses");
    assert!(format!("{err:#}").contains("rev-1"));
}
