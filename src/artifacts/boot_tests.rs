use std::time::Duration;

use crate::interop::metering::testkit::{StubAdmin, TEST_TOKEN, closed_port, metering_for};

use super::boot::*;
use super::store::HttpArtifactStore;

fn door(endpoint: &str) -> Result<Option<Door>, SelectError> {
    door_for(Some(&metering_for(endpoint)))
}

#[test]
fn no_metering_block_means_no_artifacts() {
    assert!(door_for(None).unwrap().is_none());
}

#[test]
fn the_door_is_the_sibling_of_worker_usage() {
    let d = door("https://admin.example/api/v1/ingest/worker-usage")
        .unwrap()
        .unwrap();
    assert_eq!(d.url, "https://admin.example/api/v1/ingest/artifacts");
    assert_eq!(d.token, TEST_TOKEN);
    let d = door("https://admin.example/api/v1/ingest/worker-usage/")
        .unwrap()
        .unwrap();
    assert_eq!(d.url, "https://admin.example/api/v1/ingest/artifacts");
}

#[test]
fn a_foreign_endpoint_is_refused_not_guessed() {
    for bad in ["https://admin.example/other", "not a url"] {
        assert!(matches!(door(bad), Err(SelectError::Endpoint(_))), "{bad}");
    }
}

#[test]
fn cleartext_http_off_the_host_is_refused() {
    for bad in [
        "http://admin.example/api/v1/ingest/worker-usage",
        "http://127.0.0.1.evil.example/api/v1/ingest/worker-usage",
        "http://localhost.evil.example/api/v1/ingest/worker-usage",
        "http://localhost@evil.example/api/v1/ingest/worker-usage",
        "ftp://admin.example/api/v1/ingest/worker-usage",
    ] {
        assert!(
            matches!(door(bad), Err(SelectError::UnsafeEndpoint(_))),
            "{bad}"
        );
    }
    for good in [
        "http://127.0.0.1:9/api/v1/ingest/worker-usage",
        "http://localhost:9/api/v1/ingest/worker-usage",
        "http://[::1]:9/api/v1/ingest/worker-usage",
    ] {
        assert!(door(good).unwrap().is_some(), "{good}");
    }
}

#[test]
fn neither_a_refusal_nor_a_door_prints_the_token() {
    let err = door("http://admin.example/api/v1/ingest/worker-usage")
        .err()
        .unwrap();
    assert!(err.to_string().contains("refusing to serve"));
    assert!(!err.to_string().contains(TEST_TOKEN));
    let d = door("https://admin.example/api/v1/ingest/worker-usage")
        .unwrap()
        .unwrap();
    assert!(!format!("{d:?}").contains(TEST_TOKEN));
}

fn store_at(url: &str) -> HttpArtifactStore {
    HttpArtifactStore::new(url.into(), TEST_TOKEN.into(), Duration::from_secs(2))
        .unwrap()
        .with_backoff(Duration::from_millis(5))
}

#[tokio::test]
async fn a_dead_door_refuses_activation_and_names_it_without_the_token() {
    let url = format!("http://127.0.0.1:{}/ingest/artifacts", closed_port().await);
    let err = probe_door(&store_at(&url), &url).await.err().unwrap();
    let text = format!("{err:#}");
    assert!(
        text.contains("artifacts door") && text.contains(&url),
        "{text}"
    );
    assert!(text.contains("refusing to serve"), "{text}");
    assert!(!text.contains(TEST_TOKEN), "{text}");
}

#[tokio::test]
async fn an_unauthorised_token_refuses_activation() {
    let stub = StubAdmin::answering("HTTP/1.1 401 Unauthorized", "", "{}").await;
    assert!(probe_door(&store_at(&stub.url), &stub.url).await.is_err());
}

#[tokio::test]
async fn a_failing_door_refuses_activation() {
    let stub = StubAdmin::answering("HTTP/1.1 500 Internal Server Error", "", "{}").await;
    assert!(probe_door(&store_at(&stub.url), &stub.url).await.is_err());
}

#[tokio::test]
async fn a_token_without_the_purpose_activates_without_attachments() {
    let body = r#"{"error":{"code":"purpose_not_granted"}}"#;
    let stub = StubAdmin::answering("HTTP/1.1 403 Forbidden", "", body).await;
    assert_eq!(
        probe_door(&store_at(&stub.url), &stub.url).await.unwrap(),
        DoorProbe::NotGranted
    );
}

#[tokio::test]
async fn a_reachable_door_enables_attachments() {
    let body = r#"{"error":{"code":"not_found"}}"#;
    let stub = StubAdmin::answering("HTTP/1.1 404 Not Found", "", body).await;
    assert_eq!(
        probe_door(&store_at(&stub.url), &stub.url).await.unwrap(),
        DoorProbe::Enabled
    );
    assert!(stub.count() >= 1, "the probe reached the door");
}

#[tokio::test]
async fn any_other_403_or_404_refuses_activation_naming_the_door() {
    for (status, body) in [
        ("HTTP/1.1 403 Forbidden", "{}"),
        (
            "HTTP/1.1 403 Forbidden",
            r#"{"error":{"code":"invalid_usage_token"}}"#,
        ),
        ("HTTP/1.1 404 Not Found", "{}"),
        ("HTTP/1.1 404 Not Found", "<html>no route</html>"),
    ] {
        let stub = StubAdmin::answering(status, "", body).await;
        let err = probe_door(&store_at(&stub.url), &stub.url)
            .await
            .expect_err(status);
        let text = format!("{err:#}");
        assert!(
            text.contains("artifacts door") && text.contains("refusing to serve"),
            "{text}"
        );
        assert!(
            !text.contains(TEST_TOKEN) && !text.contains("no route"),
            "{text}"
        );
    }
}
