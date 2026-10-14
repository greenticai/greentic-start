//! The fetcher reads only the receiving pack's secrets, and only the
//! credential that belongs to the receiving channel (confused deputy).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use crate::interop::metering::testkit::StubAdmin;

use super::client::AttachmentClient;
use super::fetch::{FetchError, Fetcher, HttpFetcher, SecretLookup};
use super::fetch_ref::FetchRef;
use super::host_policy::HostPolicy;
use super::origin::{Origin, SecretScope};

#[derive(Default)]
struct Recording {
    asked: Mutex<Vec<(SecretScope, String)>>,
}

#[async_trait]
impl SecretLookup for Recording {
    async fn get(&self, scope: &SecretScope, name: &str) -> Option<String> {
        self.asked
            .lock()
            .unwrap()
            .push((scope.clone(), name.into()));
        Some("tok".into())
    }
}

fn fetcher(secrets: Arc<Recording>) -> HttpFetcher {
    let client = AttachmentClient::loopback_for_tests(Duration::from_secs(3)).unwrap();
    HttpFetcher::with_client(client, secrets)
}

#[tokio::test]
async fn a_reference_naming_another_channels_credential_reads_no_secret() {
    let secrets = Arc::new(Recording::default());
    let whatsapp = Origin::new(
        "messaging.whatsapp",
        "messaging-provider-whatsapp",
        "acme",
        None,
    );
    for reference in [
        FetchRef::Bearer {
            url: "https://files.slack.com/x".into(),
            secret_key: "SLACK_BOT_TOKEN".into(),
        },
        FetchRef::TelegramFile {
            file_id: "f".into(),
        },
    ] {
        let err = fetcher(secrets.clone())
            .fetch(&whatsapp, &reference)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::NotThisChannel), "{err:?}");
    }
    assert!(
        secrets.asked.lock().unwrap().is_empty(),
        "a secret was read"
    );
}

#[tokio::test]
async fn the_secret_is_read_in_the_receiving_packs_scope() {
    let stub = StubAdmin::answering("HTTP/1.1 200 OK", "", "BODY").await;
    let port = reqwest::Url::parse(&stub.url).unwrap().port().unwrap();
    let policy = HostPolicy::named_for_tests(&[("SLACK_BOT_TOKEN", &["a.test"])], &[]);
    let client = AttachmentClient::named_for_tests(
        policy,
        &[("a.test", SocketAddr::from(([127, 0, 0, 1], port)))],
        Duration::from_secs(3),
    )
    .unwrap();
    let secrets = Arc::new(Recording::default());
    let slack = Origin::new(
        "messaging.slack.api",
        "messaging-provider-slack",
        "acme",
        Some("ops"),
    );
    let got = HttpFetcher::with_client(client, secrets.clone())
        .fetch(
            &slack,
            &FetchRef::Bearer {
                url: format!("http://a.test:{port}/file"),
                secret_key: "SLACK_BOT_TOKEN".into(),
            },
        )
        .await
        .expect("downloaded");
    assert_eq!(got.bytes, b"BODY");
    let asked = secrets.asked.lock().unwrap().clone();
    assert_eq!(
        asked,
        vec![(slack.scope().clone(), "SLACK_BOT_TOKEN".to_string())]
    );
}
