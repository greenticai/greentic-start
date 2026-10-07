//! `DoorArtifactPort`: the extension host's `artifact.put`, backed by ONE
//! unit's artifacts door.

use std::sync::Arc;
use std::time::Duration;

use greentic_ext_runtime::host_ports::{
    ArtifactPort, ArtifactPortError, ArtifactPutRequest, HostCallContext,
};

use crate::interop::metering::testkit::{StubAdmin, TEST_TENANT, TEST_TOKEN};

use super::port::{DoorArtifactPort, MAX_PUT_BYTES};
use super::store::{ArtifactStore, HttpArtifactStore};

const ID: &str = "artifact://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn ok_body() -> String {
    format!(
        r#"{{"id":"{ID}","sha256":"ff","size_bytes":3,"kind":"document","mime_type":"text/plain"}}"#
    )
}

async fn ok_stub() -> StubAdmin {
    StubAdmin::answering("HTTP/1.1 200 OK", "", &ok_body()).await
}

fn store_with(stub: &StubAdmin, token: &str) -> Arc<dyn ArtifactStore> {
    Arc::new(
        HttpArtifactStore::new(stub.url.clone(), token.to_string(), Duration::from_secs(2))
            .expect("client")
            .with_backoff(Duration::from_millis(1)),
    )
}

fn store_for(stub: &StubAdmin) -> Arc<dyn ArtifactStore> {
    store_with(stub, TEST_TOKEN)
}

fn ctx(tenant: Option<&str>) -> HostCallContext {
    HostCallContext {
        tenant: tenant.map(str::to_string),
        ..Default::default()
    }
}

fn request(bytes: &[u8], mime: &str, name: &str) -> ArtifactPutRequest {
    ArtifactPutRequest {
        bytes: bytes.to_vec(),
        mime_type: mime.into(),
        name: name.into(),
    }
}

fn hey() -> ArtifactPutRequest {
    request(b"hey", "text/plain", "a.txt")
}

/// Runs a sync port call the way the runner does: on a blocking-pool thread
/// of the multi-thread serving runtime.
async fn put_blocking(
    port: Arc<DoorArtifactPort>,
    tenant: Option<&str>,
    request: ArtifactPutRequest,
) -> Result<String, ArtifactPortError> {
    let ctx = ctx(tenant);
    tokio::task::spawn_blocking(move || port.put("greentic.media", &ctx, request))
        .await
        .expect("join")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_put_reaches_the_door_with_the_units_token_and_returns_the_id() {
    let stub = ok_stub().await;
    let port = Arc::new(DoorArtifactPort::new(store_for(&stub)));
    let id = put_blocking(port, Some("someone-else"), hey())
        .await
        .expect("stored");
    assert_eq!(id, ID);
    let raw = stub.received().join("\n");
    assert!(raw.contains("/ingest/put HTTP/1.1"), "{raw}");
    assert!(raw.contains(&format!("Bearer {TEST_TOKEN}")), "{raw}");
    assert!(raw.contains("aGV5"), "the bytes travel base64: {raw}");
    // The tenant is decided by the door from the token: the call's tenant is
    // never sent, so a call claiming another tenant cannot write there.
    assert!(!raw.contains("someone-else"), "{raw}");
    assert!(!raw.contains(TEST_TENANT), "{raw}");
    assert!(
        !raw.contains("conversation_id"),
        "an extension put belongs to no conversation: {raw}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_worker_thread_call_also_works() {
    let stub = ok_stub().await;
    let port = DoorArtifactPort::new(store_for(&stub));
    let id = port
        .put("greentic.media", &ctx(Some("acme")), hey())
        .expect("stored");
    assert_eq!(id, ID);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_without_a_tenant_is_refused_before_any_network_call() {
    let stub = ok_stub().await;
    let port = Arc::new(DoorArtifactPort::new(store_for(&stub)));
    for tenant in [None, Some(""), Some("   ")] {
        let err = put_blocking(Arc::clone(&port), tenant, hey())
            .await
            .unwrap_err();
        assert!(matches!(err, ArtifactPortError::Unavailable(_)), "{err:?}");
    }
    assert_eq!(stub.count(), 0, "the door was never called");
}

#[tokio::test(flavor = "multi_thread")]
async fn one_units_port_never_writes_through_another_units_door() {
    let unit_a = ok_stub().await;
    let unit_b = ok_stub().await;
    let port_a = Arc::new(DoorArtifactPort::new(store_with(&unit_a, "gtm_token-a")));
    put_blocking(port_a, Some("acme"), hey())
        .await
        .expect("stored");
    assert_eq!(unit_b.count(), 0, "unit B's door saw nothing");
    let raw = unit_a.received().join("\n");
    assert!(raw.contains("Bearer gtm_token-a"), "{raw}");
}

#[tokio::test(flavor = "multi_thread")]
async fn door_errors_map_to_typed_errors_without_leaking_the_token_or_url() {
    let cases = [
        ("HTTP/1.1 415 Unsupported Media Type", "InvalidMediaType"),
        ("HTTP/1.1 422 Unprocessable Entity", "QuotaExceeded"),
        ("HTTP/1.1 413 Payload Too Large", "Unavailable"),
        ("HTTP/1.1 401 Unauthorized", "Unavailable"),
        ("HTTP/1.1 403 Forbidden", "Unavailable"),
        ("HTTP/1.1 500 Internal Server Error", "Unavailable"),
        ("HTTP/1.1 503 Service Unavailable", "Unavailable"),
    ];
    for (status, want) in cases {
        let body = format!(r#"{{"error":{{"code":"x","message":"{TEST_TOKEN}"}}}}"#);
        let stub = StubAdmin::answering(status, "", &body).await;
        let port = Arc::new(DoorArtifactPort::new(store_for(&stub)));
        let err = put_blocking(port, Some("acme"), hey()).await.unwrap_err();
        let text = format!("{err:?} {err}");
        assert!(text.starts_with(want), "{status}: {text}");
        assert!(!text.contains(TEST_TOKEN), "{status}: {text}");
        assert!(
            !text.contains("127.0.0.1"),
            "no URL reaches the guest: {text}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_and_oversized_bytes_are_refused_without_calling_the_door() {
    let stub = ok_stub().await;
    let port = Arc::new(DoorArtifactPort::new(store_for(&stub)));
    for bytes in [Vec::new(), vec![0u8; MAX_PUT_BYTES + 1]] {
        let err = put_blocking(
            Arc::clone(&port),
            Some("acme"),
            request(&bytes, "text/plain", "a.txt"),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ArtifactPortError::Unavailable(_)), "{err:?}");
    }
    assert_eq!(stub.count(), 0, "the door was never called");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_name_is_cleaned_before_it_reaches_the_door() {
    let cases = [
        ("../../etc/passwd", ".._.._etc_passwd"),
        ("a\\b.txt", "a_b.txt"),
        ("evil\u{202e}txt.exe", "eviltxt.exe"),
        ("line\nbreak\u{0}.txt", "linebreak.txt"),
        ("zero\u{200b}width.png", "zerowidth.png"),
        ("  padded.txt  ", "padded.txt"),
        ("..", "file"),
        ("\u{200b}", "file"),
    ];
    for (given, sent) in cases {
        let stub = ok_stub().await;
        let port = Arc::new(DoorArtifactPort::new(store_for(&stub)));
        put_blocking(port, Some("acme"), request(b"hey", "text/plain", given))
            .await
            .expect("stored");
        let raw = stub.received().join("\n");
        assert!(
            raw.contains(&format!(r#""name":"{sent}""#)),
            "{given:?} -> {sent:?}: {raw}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_long_name_is_capped_on_a_char_boundary() {
    let stub = ok_stub().await;
    let port = Arc::new(DoorArtifactPort::new(store_for(&stub)));
    let long = "é".repeat(300);
    put_blocking(port, Some("acme"), request(b"hey", "text/plain", &long))
        .await
        .expect("stored");
    let raw = stub.received().join("\n");
    let sent = format!(r#""name":"{}""#, "é".repeat(127));
    assert!(raw.contains(&sent), "254 bytes of two-byte chars: {raw}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_media_type_is_normalised_and_a_malformed_one_never_reaches_the_door() {
    let stub = ok_stub().await;
    let port = Arc::new(DoorArtifactPort::new(store_for(&stub)));
    put_blocking(
        Arc::clone(&port),
        Some("acme"),
        request(b"hey", " TEXT/Plain; charset=utf-8 ", "a.txt"),
    )
    .await
    .expect("stored");
    let raw = stub.received().join("\n");
    assert!(raw.contains(r#""mime_type":"text/plain""#), "{raw}");
    for bad in ["", "text", "text/", "/plain", "te xt/plain", "text/pl\"ain"] {
        let err = put_blocking(
            Arc::clone(&port),
            Some("acme"),
            request(b"hey", bad, "a.txt"),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ArtifactPortError::InvalidMediaType),
            "{bad:?}: {err:?}"
        );
    }
    assert_eq!(stub.count(), 1, "only the well-formed put reached the door");
}

#[tokio::test(flavor = "current_thread")]
async fn a_current_thread_runtime_is_refused_instead_of_panicking() {
    let stub = ok_stub().await;
    let port = DoorArtifactPort::new(store_for(&stub));
    let err = port
        .put("greentic.media", &ctx(Some("acme")), hey())
        .unwrap_err();
    assert!(matches!(err, ArtifactPortError::Unavailable(_)), "{err:?}");
    assert_eq!(stub.count(), 0);
}

#[test]
fn a_call_outside_any_runtime_is_refused() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let stub = runtime.block_on(ok_stub());
    let port = DoorArtifactPort::new(store_for(&stub));
    let err = port
        .put("greentic.media", &ctx(Some("acme")), hey())
        .unwrap_err();
    assert!(matches!(err, ArtifactPortError::Unavailable(_)), "{err:?}");
    assert_eq!(stub.count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn debug_never_names_the_token() {
    let stub = ok_stub().await;
    let port = DoorArtifactPort::new(store_for(&stub));
    let rendered = format!("{port:?}");
    assert!(!rendered.contains(TEST_TOKEN), "{rendered}");
}

/// A unit whose re-probe ended `purpose_not_granted` keeps the port it was
/// loaded with; that port now answers `unsupported` at once: no door call, no
/// warning per call. While the door is merely down, or attachments are on,
/// the port still asks the door.
#[tokio::test(flavor = "multi_thread")]
async fn a_port_of_a_unit_without_the_purpose_answers_unsupported_without_a_door_call() {
    use super::unit::{Off, UnitAttachments, UnitCell};

    let stub = ok_stub().await;
    let cell = Arc::new(UnitCell::new(UnitAttachments::Off(Off::DoorUnavailable)));
    let port = Arc::new(DoorArtifactPort::new(store_for(&stub)).gated_by(&cell));
    put_blocking(Arc::clone(&port), Some(TEST_TENANT), hey())
        .await
        .expect("a door that was down is still asked");
    assert_eq!(stub.count(), 1);

    cell.set(UnitAttachments::Off(Off::NotGranted));
    let err = put_blocking(port, Some(TEST_TENANT), hey())
        .await
        .expect_err("not granted");
    assert!(matches!(err, ArtifactPortError::Unsupported), "{err:?}");
    assert_eq!(stub.count(), 1, "no door call once the unit is not granted");
}
