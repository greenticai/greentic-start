use std::time::Duration;

use crate::interop::metering::testkit::{StubAdmin, TEST_TOKEN, closed_port, metering_for};

use super::boot::*;
use super::store::HttpArtifactStore;
use super::time_testkit::within_ceiling;
use crate::interop::metering::testkit::silent_peer;

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
        assert!(matches!(door(bad), Err(SelectError::Endpoint)), "{bad}");
    }
}

#[test]
fn cleartext_http_off_the_host_is_refused() {
    for bad in [
        "http://admin.example/api/v1/ingest/worker-usage",
        "http://127.0.0.1.evil.example/api/v1/ingest/worker-usage",
        "http://localhost.evil.example/api/v1/ingest/worker-usage",
        "ftp://admin.example/api/v1/ingest/worker-usage",
    ] {
        assert!(
            matches!(door(bad), Err(SelectError::UnsafeEndpoint)),
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

const BUDGET: Duration = Duration::from_secs(3);

async fn probe(stub_url: &str) -> anyhow::Result<DoorProbe> {
    within_ceiling(probe_door(&store_at(stub_url), stub_url, BUDGET)).await
}

/// A door that is down for now is not a misconfiguration: the unit runs
/// without attachments while the door recovers.
#[tokio::test]
async fn a_dead_door_is_unavailable_not_a_refusal() {
    let closed = closed_port().await;
    let url = format!("http://127.0.0.1:{}/ingest/artifacts", closed.port);
    assert!(matches!(
        probe(&url).await.unwrap(),
        DoorProbe::Unavailable(_)
    ));
}

#[tokio::test]
async fn an_unauthorised_token_refuses_activation_naming_the_door_not_the_token() {
    let stub = StubAdmin::answering("HTTP/1.1 401 Unauthorized", "", "{}").await;
    let err = probe(&stub.url)
        .await
        .expect_err("a bad token is a misconfiguration");
    let text = format!("{err:#}");
    assert!(
        text.contains("artifacts door") && text.contains(&stub.url),
        "{text}"
    );
    assert!(text.contains("refusing to serve"), "{text}");
    assert!(!text.contains(TEST_TOKEN), "{text}");
}

#[tokio::test]
async fn transient_door_answers_are_unavailable() {
    for (status, body) in [
        ("HTTP/1.1 500 Internal Server Error", "{}"),
        ("HTTP/1.1 502 Bad Gateway", "{}"),
        ("HTTP/1.1 429 Too Many Requests", "{}"),
        (
            "HTTP/1.1 503 Service Unavailable",
            r#"{"error":{"code":"artifact_busy"}}"#,
        ),
        ("HTTP/1.1 404 Not Found", "{}"),
        ("HTTP/1.1 404 Not Found", "<html>no route</html>"),
        ("HTTP/1.1 403 Forbidden", "{}"),
    ] {
        let stub = StubAdmin::answering(status, "", body).await;
        assert!(
            matches!(probe(&stub.url).await.unwrap(), DoorProbe::Unavailable(_)),
            "{status} {body}"
        );
    }
}

/// A door that accepts the connection and never answers is bounded by the
/// probe budget, not by the client's per-attempt timeout times its retries.
#[tokio::test]
async fn a_hanging_door_is_bounded_by_the_probe_budget() {
    let url = format!("http://127.0.0.1:{}/ingest/artifacts", silent_peer().await);
    let store =
        HttpArtifactStore::new(url.clone(), TEST_TOKEN.into(), Duration::from_secs(30)).unwrap();
    let started = std::time::Instant::now();
    let got = within_ceiling(probe_door(&store, &url, Duration::from_millis(300)))
        .await
        .unwrap();
    assert!(matches!(got, DoorProbe::Unavailable("timeout")), "{got:?}");
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn a_token_without_the_purpose_activates_without_attachments() {
    let body = r#"{"error":{"code":"purpose_not_granted"}}"#;
    let stub = StubAdmin::answering("HTTP/1.1 403 Forbidden", "", body).await;
    assert_eq!(probe(&stub.url).await.unwrap(), DoorProbe::NotGranted);
}

#[tokio::test]
async fn a_reachable_door_enables_attachments() {
    let body = r#"{"error":{"code":"not_found"}}"#;
    let stub = StubAdmin::answering("HTTP/1.1 404 Not Found", "", body).await;
    assert_eq!(probe(&stub.url).await.unwrap(), DoorProbe::Enabled);
    assert!(stub.count() >= 1, "the probe reached the door");
}

#[test]
fn a_door_url_with_credentials_or_a_query_is_refused_without_printing_it() {
    for bad in [
        "https://user:hunter2@admin.example/api/v1/ingest/worker-usage",
        "https://hunter2@admin.example/api/v1/ingest/worker-usage",
        "https://admin.example/api/v1/ingest/worker-usage?key=hunter2",
        "https://admin.example/api/v1/ingest/worker-usage#hunter2",
        "http://hunter2@127.0.0.1:9/api/v1/ingest/worker-usage",
        "http://localhost@evil.example/api/v1/ingest/worker-usage",
    ] {
        let err = door(bad).err().unwrap_or_else(|| panic!("{bad} accepted"));
        let text = err.to_string();
        assert!(text.contains("refusing to serve"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
    }
    // No refusal prints the endpoint it refused.
    for bad in [
        "https://admin.example/other",
        "http://admin.example/api/v1/ingest/worker-usage",
    ] {
        let text = door(bad).err().unwrap().to_string();
        assert!(!text.contains("admin.example"), "{text}");
    }
}
