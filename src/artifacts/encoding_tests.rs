//! Neither the attachment client nor the door client negotiates content
//! encoding: a compressed answer would be inflated past every byte cap (the
//! caps count what is read, and a small gzip body inflates a thousandfold).
//! These clients ask for identity bytes and never decode what comes back.

use std::time::Duration;

use crate::interop::metering::testkit::{StubAdmin, TEST_TOKEN};

use super::client::AttachmentClient;
use super::fetch::{Fetcher, HttpFetcher, SecretLookup};
use super::fetch_ref::FetchRef;
use super::origin::SecretScope;
use super::store::{ArtifactStore, HttpArtifactStore};

struct NoSecrets;

#[async_trait::async_trait]
impl SecretLookup for NoSecrets {
    async fn get(&self, _: &SecretScope, _: &str) -> Option<String> {
        None
    }
}

fn request_headers(stub: &StubAdmin) -> String {
    stub.received()[0]
        .split("\r\n\r\n")
        .next()
        .unwrap_or_default()
        .to_lowercase()
}

#[tokio::test]
async fn a_download_asks_for_no_encoding_and_decodes_none() {
    // Not valid gzip: a decoding client would fail; this one returns it as is.
    let stub = StubAdmin::answering("HTTP/1.1 200 OK", "content-encoding: gzip\r\n", "PLAIN").await;
    let client = AttachmentClient::loopback_for_tests(Duration::from_secs(3)).unwrap();
    let fetcher = HttpFetcher::with_client(client, std::sync::Arc::new(NoSecrets));
    let got = fetcher
        .fetch(
            &super::ingest_testkit::slack(),
            &FetchRef::Public {
                url: stub.url.clone(),
            },
        )
        .await
        .expect("the body is returned undecoded");
    assert_eq!(got.bytes, b"PLAIN");
    assert!(!request_headers(&stub).contains("accept-encoding"));
}

#[tokio::test]
async fn the_door_client_asks_for_no_encoding_and_decodes_none() {
    let body = r#"{"id":"artifact://0000000000000000000000000000000000000000000000000000000000000000","sha256":"ff","size_bytes":1,"kind":"document","mime_type":"text/plain"}"#;
    let stub = StubAdmin::answering("HTTP/1.1 200 OK", "content-encoding: br\r\n", body).await;
    let store = HttpArtifactStore::new(stub.url.clone(), TEST_TOKEN.into(), Duration::from_secs(3))
        .unwrap();
    let put = super::store::PutRequest {
        name: "a.txt",
        mime: "text/plain",
        bytes: b"x",
        derived_from: None,
        conversation_id: None,
    };
    store.put(put).await.expect("the answer is read undecoded");
    assert!(!request_headers(&stub).contains("accept-encoding"));
}
