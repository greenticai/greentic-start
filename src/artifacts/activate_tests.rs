use std::sync::Arc;

use async_trait::async_trait;

use crate::interop::metering::testkit::{StubAdmin, TEST_TOKEN, closed_port, metering_for};

use super::activate::activate;
use super::fetch::SecretLookup;
use super::origin::SecretScope;
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

#[tokio::test]
async fn no_metering_block_means_no_door() {
    let got = activate("rev-1", None, Arc::new(NoSecrets)).await.unwrap();
    assert!(matches!(got, UnitAttachments::Off(Off::NoDoor)));
}

#[tokio::test]
async fn a_dead_door_refuses_activation_and_never_prints_the_token() {
    let port = closed_port().await;
    let err = activate("rev-1", Some(&staged_at(port)), Arc::new(NoSecrets))
        .await
        .err()
        .expect("a dead door must refuse activation");
    let text = format!("{err:#}");
    assert!(text.contains("artifacts door"), "{text}");
    assert!(text.contains("refusing to serve"), "{text}");
    assert!(text.contains("rev-1"), "{text}");
    assert!(!text.contains(TEST_TOKEN), "{text}");
}

#[tokio::test]
async fn an_unauthorised_token_refuses_activation() {
    let stub = StubAdmin::answering("HTTP/1.1 401 Unauthorized", "", "{}").await;
    assert!(
        activate(
            "rev-1",
            Some(&staged_at(port_of(&stub))),
            Arc::new(NoSecrets)
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn a_token_without_the_purpose_activates_with_attachments_off() {
    let body = r#"{"error":{"code":"purpose_not_granted"}}"#;
    let stub = StubAdmin::answering("HTTP/1.1 403 Forbidden", "", body).await;
    let got = activate(
        "rev-1",
        Some(&staged_at(port_of(&stub))),
        Arc::new(NoSecrets),
    )
    .await
    .expect("an opted-out unit still activates");
    assert!(matches!(got, UnitAttachments::Off(Off::NotGranted)));
}

#[tokio::test]
async fn a_reachable_door_turns_attachments_on() {
    let body = r#"{"error":{"code":"not_found"}}"#;
    let stub = StubAdmin::answering("HTTP/1.1 404 Not Found", "", body).await;
    let got = activate(
        "rev-1",
        Some(&staged_at(port_of(&stub))),
        Arc::new(NoSecrets),
    )
    .await
    .expect("a reachable door activates");
    assert!(matches!(got, UnitAttachments::Enabled { .. }));
    assert!(stub.count() >= 1, "the probe reached the door");
}
