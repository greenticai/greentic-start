//! The unit's reader and port reach that unit's door, with that unit's token,
//! and nothing else.

use std::sync::Arc;
use std::time::Duration;

use greentic_aw_runtime::ArtifactError;
use greentic_ext_runtime::host_ports::{ArtifactPutRequest, HostCallContext};

use crate::interop::metering::testkit::{StubAdmin, TEST_TENANT};

use super::boot::Door;
use super::host_access::HostArtifactAccess;
use super::store::HttpArtifactStore;

const ID: &str = "artifact://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn access(stub: &StubAdmin, token: &str) -> HostArtifactAccess {
    let store = HttpArtifactStore::new(stub.url.clone(), token.into(), Duration::from_secs(2))
        .expect("client");
    HostArtifactAccess::new(
        Arc::new(store),
        Door {
            url: stub.url.clone(),
            token: token.into(),
        },
    )
}

fn get_body() -> String {
    // base64("hi")
    r#"{"mime_type":"text/plain","name":"a.txt","size_bytes":2,"data_base64":"aGk="}"#.into()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_reader_asks_this_units_door_with_this_units_token_and_no_tenant() {
    let unit_a = StubAdmin::answering("HTTP/1.1 200 OK", "", &get_body()).await;
    let unit_b = StubAdmin::answering("HTTP/1.1 200 OK", "", &get_body()).await;
    let reader = access(&unit_a, "gtm_token-a").reader().expect("reader");
    let got = reader.get(ID).await.expect("read");
    assert_eq!(got.bytes, b"hi");
    let raw = unit_a.received().join("\n");
    assert!(raw.contains("/ingest/get HTTP/1.1"), "{raw}");
    assert!(raw.contains("Bearer gtm_token-a"), "{raw}");
    assert!(raw.contains(ID), "{raw}");
    // Which tenant may read the id is decided by the door from the token;
    // nothing in the request can name another tenant.
    assert!(!raw.contains(TEST_TENANT), "{raw}");
    assert!(!raw.contains("tenant"), "{raw}");
    assert_eq!(unit_b.count(), 0, "unit B's door saw nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_id_the_door_does_not_hold_for_this_token_reads_as_not_found() {
    // The door answers 404 for another tenant's id exactly as for an absent one.
    let stub = StubAdmin::answering(
        "HTTP/1.1 404 Not Found",
        "",
        r#"{"error":{"code":"not_found"}}"#,
    )
    .await;
    let reader = access(&stub, "gtm_token-a").reader().expect("reader");
    let err = reader.get(ID).await.unwrap_err();
    assert!(matches!(err, ArtifactError::NotFound), "{err:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_port_writes_through_this_units_door() {
    let ok = format!(
        r#"{{"id":"{ID}","sha256":"ff","size_bytes":2,"kind":"document","mime_type":"text/plain"}}"#
    );
    let unit_a = StubAdmin::answering("HTTP/1.1 200 OK", "", &ok).await;
    let unit_b = StubAdmin::answering("HTTP/1.1 200 OK", "", &ok).await;
    let port = access(&unit_a, "gtm_token-a").port();
    let ctx = HostCallContext {
        tenant: Some("acme".into()),
        ..Default::default()
    };
    let id = tokio::task::spawn_blocking(move || {
        port.put(
            "greentic.media",
            &ctx,
            ArtifactPutRequest {
                bytes: b"hi".to_vec(),
                mime_type: "text/plain".into(),
                name: "a.txt".into(),
            },
        )
    })
    .await
    .expect("join")
    .expect("stored");
    assert_eq!(id, ID);
    assert!(unit_a.received().join("\n").contains("Bearer gtm_token-a"));
    assert_eq!(unit_b.count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unusable_token_builds_no_reader_and_debug_never_names_the_token() {
    let stub = StubAdmin::answering("HTTP/1.1 200 OK", "", &get_body()).await;
    assert!(access(&stub, "   ").reader().is_err());
    assert!(access(&stub, "tok\nen").reader().is_err());
    let rendered = format!("{:?}", access(&stub, "gtm_secret-token"));
    assert!(!rendered.contains("gtm_secret-token"), "{rendered}");
}
