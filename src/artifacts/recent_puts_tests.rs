//! `RecentPuts`: the bounded record of what a unit's port created, and the
//! port writing to it.

use std::sync::Arc;
use std::time::Duration;

use greentic_ext_runtime::host_ports::{ArtifactPort, ArtifactPutRequest, HostCallContext};

use crate::interop::metering::testkit::{StubAdmin, TEST_TOKEN};

use super::port::DoorArtifactPort;
use super::recent_puts::{PutRecord, RecentPuts};
use super::store::{ArtifactStore, HttpArtifactStore};

const ID: &str = "artifact://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn record(at: u64) -> PutRecord {
    PutRecord {
        mime_type: "image/png".into(),
        name: "a.png".into(),
        size_bytes: 3,
        at,
    }
}

fn id(n: usize) -> String {
    format!("artifact://{n:064x}")
}

#[test]
fn a_recorded_put_is_found_and_an_unknown_one_is_not() {
    let puts = RecentPuts::default();
    puts.record(ID, record(100));
    assert_eq!(puts.lookup(ID, 100, 60), Some(record(100)));
    assert_eq!(puts.lookup(&id(1), 100, 60), None);
}

#[test]
fn a_record_older_than_max_age_is_not_returned() {
    let puts = RecentPuts::default();
    puts.record(ID, record(100));
    assert!(puts.lookup(ID, 160, 60).is_some());
    assert!(puts.lookup(ID, 161, 60).is_none());
}

#[test]
fn capacity_keeps_the_newest_records() {
    let puts = RecentPuts::default();
    let total = RecentPuts::CAPACITY + 10;
    for n in 0..total {
        puts.record(&id(n), record(1));
    }
    for n in 0..10 {
        assert!(puts.lookup(&id(n), 1, 60).is_none(), "{n} evicted");
    }
    for n in 10..total {
        assert!(puts.lookup(&id(n), 1, 60).is_some(), "{n} kept");
    }
}

#[test]
fn re_recording_an_id_makes_it_newest_without_a_duplicate() {
    let puts = RecentPuts::default();
    puts.record(&id(0), record(1));
    for n in 1..RecentPuts::CAPACITY {
        puts.record(&id(n), record(1));
    }
    // Refreshing id 0 must protect it from the next eviction, which then
    // takes id 1 instead.
    puts.record(&id(0), record(2));
    puts.record(&id(RecentPuts::CAPACITY), record(2));
    assert_eq!(puts.lookup(&id(0), 2, 60), Some(record(2)));
    assert!(puts.lookup(&id(1), 2, 60).is_none());
}

#[test]
fn debug_prints_a_count_only() {
    let puts = RecentPuts::default();
    puts.record(ID, record(1));
    let printed = format!("{puts:?}");
    assert!(!printed.contains("bbbb"), "{printed}");
    assert!(!printed.contains("a.png"), "{printed}");
}

fn store_for(stub: &StubAdmin) -> Arc<dyn ArtifactStore> {
    Arc::new(
        HttpArtifactStore::new(
            stub.url.clone(),
            TEST_TOKEN.to_string(),
            Duration::from_secs(2),
        )
        .expect("client")
        .with_backoff(Duration::from_millis(1)),
    )
}

async fn put(
    port: Arc<DoorArtifactPort>,
    mime: &str,
    name: &str,
) -> Result<String, greentic_ext_runtime::host_ports::ArtifactPortError> {
    let request = ArtifactPutRequest {
        bytes: b"hey".to_vec(),
        mime_type: mime.into(),
        name: name.into(),
    };
    let ctx = HostCallContext {
        tenant: Some("acme".into()),
        ..Default::default()
    };
    tokio::task::spawn_blocking(move || port.put("greentic.media", &ctx, request))
        .await
        .expect("join")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_port_put_records_the_doors_answer_not_the_callers_claim() {
    let body = format!(
        r#"{{"id":"{ID}","sha256":"ff","size_bytes":3,"kind":"document","mime_type":"text/plain"}}"#
    );
    let stub = StubAdmin::answering("HTTP/1.1 200 OK", "", &body).await;
    let recent = Arc::new(RecentPuts::default());
    let port = Arc::new(DoorArtifactPort::new(store_for(&stub)).with_recent(Arc::clone(&recent)));
    let stored = put(port, "text/markdown", "re\u{202E}port.md").await;
    assert_eq!(stored.ok().as_deref(), Some(ID));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let got = recent.lookup(ID, now, 300).expect("recorded");
    assert_eq!(got.mime_type, "text/plain", "the door's sniffed type wins");
    assert_eq!(got.name, "report.md", "the port's cleaned name");
    assert_eq!(got.size_bytes, 3);
    assert!(got.at <= now && got.at + 300 >= now);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_put_records_nothing() {
    let stub = StubAdmin::answering("HTTP/1.1 413 Payload Too Large", "", "{}").await;
    let recent = Arc::new(RecentPuts::default());
    let port = Arc::new(DoorArtifactPort::new(store_for(&stub)).with_recent(Arc::clone(&recent)));
    assert!(put(port, "text/plain", "a.txt").await.is_err());
    assert_eq!(format!("{recent:?}"), "RecentPuts { len: 0 }");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invalid_id_from_the_door_records_nothing() {
    let body = r#"{"id":"artifact://00ff","sha256":"ff","size_bytes":3,"kind":"document","mime_type":"text/plain"}"#;
    let stub = StubAdmin::answering("HTTP/1.1 200 OK", "", body).await;
    let recent = Arc::new(RecentPuts::default());
    let port = Arc::new(DoorArtifactPort::new(store_for(&stub)).with_recent(Arc::clone(&recent)));
    assert!(put(port, "text/plain", "a.txt").await.is_err());
    assert_eq!(format!("{recent:?}"), "RecentPuts { len: 0 }");
}

fn access_for(stub: &StubAdmin) -> super::host_access::HostArtifactAccess {
    let store = HttpArtifactStore::new(stub.url.clone(), TEST_TOKEN.into(), Duration::from_secs(2))
        .expect("client");
    super::host_access::HostArtifactAccess::new(
        Arc::new(store),
        super::boot::Door {
            url: stub.url.clone(),
            token: TEST_TOKEN.into(),
        },
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn each_units_port_records_into_that_units_record_only() {
    let body = format!(
        r#"{{"id":"{ID}","sha256":"ff","size_bytes":3,"kind":"document","mime_type":"text/plain"}}"#
    );
    let stub_a = StubAdmin::answering("HTTP/1.1 200 OK", "", &body).await;
    let stub_b = StubAdmin::answering("HTTP/1.1 200 OK", "", &body).await;
    let unit_a = access_for(&stub_a);
    let unit_b = access_for(&stub_b);
    // A clone of the access (as the boot path makes) shares the unit's record.
    let port = unit_a.clone().port();
    let ctx = HostCallContext {
        tenant: Some("acme".into()),
        ..Default::default()
    };
    let request = ArtifactPutRequest {
        bytes: b"hey".to_vec(),
        mime_type: "text/plain".into(),
        name: "a.txt".into(),
    };
    tokio::task::spawn_blocking(move || port.put("greentic.media", &ctx, request))
        .await
        .expect("join")
        .expect("stored");
    assert_eq!(
        format!("{:?}", unit_a.recent_puts()),
        "RecentPuts { len: 1 }"
    );
    assert_eq!(
        format!("{:?}", unit_b.recent_puts()),
        "RecentPuts { len: 0 }"
    );
}
