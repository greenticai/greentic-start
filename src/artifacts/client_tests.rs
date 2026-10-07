use std::sync::atomic::Ordering;
use std::time::Duration;

use reqwest::Url;

use crate::interop::metering::testkit::StubAdmin;

use super::client::*;
use super::host_policy::{Blocked, HostPolicy};

const OK: &str = "HTTP/1.1 200 OK";

fn url(s: &str) -> Url {
    Url::parse(s).unwrap()
}

fn production() -> AttachmentClient {
    attachment_client(HostPolicy::from_value(None), Duration::from_secs(2)).unwrap()
}

#[tokio::test]
async fn ip_literals_are_refused_before_any_connection() {
    // The connector never asks the resolver about an IP literal, so the policy
    // check is the only thing between a provider URL and an internal address.
    let stub = StubAdmin::answering(OK, "", "{}").await;
    let port = url(&stub.url).port().unwrap();
    for target in [
        format!("https://127.0.0.1:{port}/x"),
        format!("http://127.0.0.1:{port}/x"),
        "https://169.254.169.254/latest/meta-data".to_string(),
        "https://[::1]/x".to_string(),
    ] {
        let err = production()
            .get(&url(&target), Auth::None)
            .await
            .unwrap_err();
        assert!(matches!(err, RequestError::Blocked(_)), "{target}: {err:?}");
    }
    assert_eq!(stub.count(), 0);
}

#[tokio::test]
async fn a_credential_is_refused_for_a_host_outside_its_list() {
    let err = production()
        .get(
            &url("https://tenant.sharepoint.com/f"),
            Auth::Bearer {
                name: "SLACK_BOT_TOKEN",
                token: "xoxb-secret",
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        RequestError::Blocked(Blocked::HostNotAllowed)
    ));
}

#[tokio::test]
async fn the_bearer_reaches_an_allowed_host_and_nothing_else_does() {
    let stub = StubAdmin::answering(OK, "", "{}").await;
    let target = url(&stub.url);
    let client = AttachmentClient::loopback_for_tests(Duration::from_secs(2)).unwrap();
    client
        .get(
            &target,
            Auth::Bearer {
                name: "SLACK_BOT_TOKEN",
                token: "xoxb-secret",
            },
        )
        .await
        .unwrap();
    client.get(&target, Auth::None).await.unwrap();
    let raw = stub.received();
    assert!(
        raw[0]
            .to_lowercase()
            .contains("authorization: bearer xoxb-secret")
    );
    assert!(!raw[1].to_lowercase().contains("authorization"));
}

#[tokio::test]
async fn redirects_are_returned_not_followed() {
    let elsewhere = StubAdmin::answering(OK, "", "{}").await;
    let location = format!("Location: {}\r\n", elsewhere.url);
    let stub = StubAdmin::answering("HTTP/1.1 302 Found", &location, "{}").await;
    let client = AttachmentClient::loopback_for_tests(Duration::from_secs(2)).unwrap();
    let response = client.get(&url(&stub.url), Auth::None).await.unwrap();
    assert_eq!(response.status().as_u16(), 302);
    assert_eq!(elsewhere.count(), 0);
}

#[tokio::test]
async fn transport_errors_name_no_url_or_token() {
    let client = AttachmentClient::loopback_for_tests(Duration::from_millis(300)).unwrap();
    let closed = crate::interop::metering::testkit::closed_port().await;
    let port = closed.port;
    let err = client
        .get(
            &url(&format!("http://127.0.0.1:{port}/file/botSECRET/x")),
            Auth::InUrl {
                name: "TELEGRAM_BOT_TOKEN",
            },
        )
        .await
        .unwrap_err();
    let text = format!("{err:?}{err}");
    assert!(!text.contains("SECRET"), "{text}");
    assert!(!text.contains("127.0.0.1"), "{text}");
}

#[test]
fn auth_debug_never_shows_the_token() {
    let auth = Auth::Bearer {
        name: "SLACK_BOT_TOKEN",
        token: "xoxb-secret",
    };
    let text = format!("{auth:?}");
    assert!(!text.contains("xoxb-secret"), "{text}");
    assert!(text.contains("SLACK_BOT_TOKEN"));
}

#[tokio::test]
async fn the_production_client_ignores_the_proxy_environment() {
    use super::proxy_testkit::{fake_proxy, run_child_behind_proxy};
    let (proxy, proxied) = fake_proxy().await;
    assert!(
        run_child_behind_proxy(
            "artifacts::client_tests::production_get_from_the_proxy_environment",
            &proxy,
            "https://proxy-test.invalid/x",
        )
        .await,
        "the child test did not run"
    );
    assert_eq!(proxied.load(Ordering::SeqCst), 0, "the proxy was used");
}

/// Child half of the test above; runs only inside its proxied environment.
/// `.invalid` never resolves (RFC 2606), so a client that ignores the proxy
/// fails at name resolution and contacts nothing.
#[tokio::test]
#[ignore = "run by the_production_client_ignores_the_proxy_environment"]
async fn production_get_from_the_proxy_environment() {
    let target = std::env::var(super::proxy_testkit::TARGET_ENV).unwrap();
    let client = attachment_client(
        HostPolicy::from_value(Some("proxy-test.invalid")),
        Duration::from_secs(2),
    )
    .unwrap();
    let _ = client.get(&url(&target), Auth::None).await;
}
