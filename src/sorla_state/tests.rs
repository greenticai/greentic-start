//! Tests for [`crate::sorla_state`], against an in-process fake of the admin's
//! state door (a plain `TcpListener`; no mock framework, no network).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use greentic_state::{StateKey, StateStore, TenantCtx};
use greentic_types::{EnvId, TenantId};
use serde_json::{Value, json};

use super::config::{SorlaStateSelection, StateConfigError};
use super::store::HttpStateStore;
use crate::interop::metering::{MeteringConfig, resolve_metering};

const TOKEN: &str = "gtm_super_secret_token_value";

// ---- fake door -------------------------------------------------------------

#[derive(Default)]
struct Door {
    values: Mutex<BTreeMap<String, Vec<u8>>>,
    /// Every request: (path, authorization header, body).
    seen: Mutex<Vec<(String, String, Value)>>,
    hits: AtomicUsize,
    /// When set, every call answers this status instead of working.
    fail_with: Mutex<Option<u16>>,
    /// Delay before answering.
    delay_ms: AtomicUsize,
    down: AtomicBool,
}

struct FakeDoor {
    door: Arc<Door>,
    base: String,
}

fn serve(door: Arc<Door>) -> FakeDoor {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!(
        "http://{}/api/v1/ingest/state",
        listener.local_addr().expect("addr")
    );
    let shared = Arc::clone(&door);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let door = Arc::clone(&shared);
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head_end, content_len) = loop {
                    let Ok(n) = stream.read(&mut chunk) else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..pos]).to_lowercase();
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        break (pos + 4, len);
                    }
                };
                while buf.len() < head_end + content_len {
                    let Ok(n) = stream.read(&mut chunk) else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let path = head
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("")
                    .to_string();
                let auth = head
                    .lines()
                    .find_map(|l| {
                        let lower = l.to_lowercase();
                        lower
                            .starts_with("authorization:")
                            .then(|| l["authorization:".len()..].trim().to_string())
                    })
                    .unwrap_or_default();
                let body: Value = serde_json::from_slice(&buf[head_end..head_end + content_len])
                    .unwrap_or(Value::Null);
                door.hits.fetch_add(1, Ordering::SeqCst);
                if let Ok(mut seen) = door.seen.lock() {
                    seen.push((path.clone(), auth, body.clone()));
                }
                let delay = door.delay_ms.load(Ordering::SeqCst);
                if delay > 0 {
                    std::thread::sleep(Duration::from_millis(delay as u64));
                }
                let (status, payload) = respond(&door, &path, &body);
                let reason = match status {
                    200 => "OK",
                    204 => "No Content",
                    404 => "Not Found",
                    _ => "Err",
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                    payload.len()
                );
                let _ = stream.write_all(response.as_bytes());
            });
        }
    });
    FakeDoor { door, base }
}

fn respond(door: &Door, path: &str, body: &Value) -> (u16, String) {
    if door.down.load(Ordering::SeqCst) {
        return (503, String::new());
    }
    if let Ok(Some(status)) = door.fail_with.lock().map(|s| *s) {
        return (status, "boom".into());
    }
    let key = body["key"].as_str().unwrap_or_default().to_string();
    let Ok(mut values) = door.values.lock() else {
        return (500, String::new());
    };
    match path.rsplit('/').next().unwrap_or("") {
        "read" => match values.get(&key) {
            Some(bytes) => (200, json!({ "value": B64.encode(bytes) }).to_string()),
            None => (404, String::new()),
        },
        "write" => {
            let bytes = B64
                .decode(body["value"].as_str().unwrap_or(""))
                .unwrap_or_default();
            values.insert(key, bytes);
            (204, String::new())
        }
        "delete" => {
            values.remove(&key);
            (204, String::new())
        }
        _ => (404, String::new()),
    }
}

// ---- helpers ---------------------------------------------------------------

fn metering_at(base: &str) -> MeteringConfig {
    // The door is derived from a `worker-usage` endpoint beside it.
    let endpoint = base.replace("/state", "/worker-usage");
    resolve_metering(
        json!({ "endpoint": endpoint, "token": TOKEN }),
        Some("acme"),
    )
    .expect("loopback http metering")
}

fn selection(base: &str, extra: Value) -> SorlaStateSelection {
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    if let Some(object) = extra.as_object() {
        for (k, v) in object {
            map.insert(k.clone(), v.clone());
        }
    }
    SorlaStateSelection::resolve(&map, Some(&metering_at(base))).expect("selection")
}

fn tenant(name: &str) -> TenantCtx {
    TenantCtx::new(
        EnvId::from_str("prod").expect("env"),
        TenantId::from_str(name).expect("tenant"),
    )
}

fn key(k: &str) -> StateKey {
    StateKey::from(k)
}

fn connect(base: &str, extra: Value) -> HttpStateStore {
    HttpStateStore::connect(&selection(base, extra), "rev-a-123").expect("connect")
}

// ---- config ----------------------------------------------------------------

#[test]
fn the_door_is_derived_from_the_metering_endpoint() {
    let metering = resolve_metering(
        json!({"endpoint": "https://admin.example/api/v1/ingest/worker-usage", "token": TOKEN}),
        Some("acme"),
    )
    .expect("metering");
    let selection = SorlaStateSelection::resolve(&BTreeMap::new(), Some(&metering)).expect("ok");
    assert_eq!(
        selection.door.base_url,
        "https://admin.example/api/v1/ingest/state"
    );
    assert_eq!(selection.config.cache_max_entries, 1024);
    assert_eq!(
        selection.config.request_timeout,
        Duration::from_millis(5000)
    );
    assert!(selection.config.default_ttl_seconds.is_none());
}

#[test]
fn a_named_backend_without_a_token_or_a_derivable_door_is_refused() {
    assert_eq!(
        SorlaStateSelection::resolve(&BTreeMap::new(), None).unwrap_err(),
        StateConfigError::NoMetering
    );
    let odd = resolve_metering(
        json!({"endpoint": "https://admin.example/somewhere/else", "token": TOKEN}),
        Some("acme"),
    )
    .expect("metering");
    assert!(matches!(
        SorlaStateSelection::resolve(&BTreeMap::new(), Some(&odd)).unwrap_err(),
        StateConfigError::NotWorkerUsage(_)
    ));
}

#[test]
fn bad_config_values_are_refused_not_defaulted() {
    let metering = metering_at("http://127.0.0.1:1/api/v1/ingest/state");
    for bad in [
        json!({"request_timeout_ms": 5}),
        json!({"request_timeout_ms": "soon"}),
        json!({"cache_max_entries": 100_000_000u64}),
        json!({"key_prefix": 7}),
    ] {
        let map: BTreeMap<String, Value> = bad
            .as_object()
            .expect("object")
            .clone()
            .into_iter()
            .collect();
        assert!(
            SorlaStateSelection::resolve(&map, Some(&metering)).is_err(),
            "{bad} must be refused"
        );
    }
}

#[test]
fn an_explicit_cleartext_endpoint_off_loopback_is_refused() {
    let metering = metering_at("http://127.0.0.1:1/api/v1/ingest/state");
    let map: BTreeMap<String, Value> = [(
        "endpoint".to_string(),
        json!("http://door.example.com/state"),
    )]
    .into();
    assert!(matches!(
        SorlaStateSelection::resolve(&map, Some(&metering)).unwrap_err(),
        StateConfigError::UnsafeEndpoint(_)
    ));
}

// ---- store -----------------------------------------------------------------

#[test]
fn a_write_reads_back_and_carries_the_bearer_and_a_revision_scoped_key() {
    let fake = serve(Arc::default());
    let store = connect(
        &fake.base,
        json!({"key_prefix": "chat", "default_ttl_seconds": 3600}),
    );
    store
        .set_json(
            &tenant("acme"),
            "runner",
            &key("conv/1"),
            None,
            &json!({"a": 1}),
            None,
        )
        .expect("write");
    // A second store (no shared cache) reads it from the door.
    let other = connect(
        &fake.base,
        json!({"key_prefix": "chat", "default_ttl_seconds": 3600}),
    );
    let value = other
        .get_json(&tenant("acme"), "runner", &key("conv/1"), None)
        .expect("read");
    assert_eq!(value, Some(json!({"a": 1})));

    let seen = fake.door.seen.lock().expect("seen");
    let (path, auth, body) = seen
        .iter()
        .find(|(p, _, _)| p.ends_with("/write"))
        .expect("a write was sent");
    assert_eq!(path, "/api/v1/ingest/state/write");
    assert_eq!(auth, &format!("Bearer {TOKEN}"));
    let door_key = body["key"].as_str().expect("key");
    assert!(
        door_key.starts_with("chat:rev-a-123:"),
        "revision-scoped: {door_key}"
    );
    assert!(door_key.contains("acme"), "tenant-scoped: {door_key}");
    assert_eq!(body["ttl_secs"], json!(3600));
}

#[test]
fn two_revisions_never_share_a_door_key() {
    let fake = serve(Arc::default());
    let a = HttpStateStore::connect(&selection(&fake.base, json!({})), "rev-a").expect("a");
    let b = HttpStateStore::connect(&selection(&fake.base, json!({})), "rev-b").expect("b");
    a.set_json(&tenant("acme"), "runner", &key("k"), None, &json!(1), None)
        .expect("write a");
    assert_eq!(
        b.get_json(&tenant("acme"), "runner", &key("k"), None)
            .expect("read b"),
        None,
        "revision B must not see revision A's state"
    );
}

#[test]
fn a_missing_key_is_none_not_an_error() {
    let fake = serve(Arc::default());
    let store = connect(&fake.base, json!({}));
    assert_eq!(
        store
            .get_json(&tenant("acme"), "runner", &key("nope"), None)
            .expect("404 is a miss"),
        None
    );
}

#[test]
fn delete_removes_the_value() {
    let fake = serve(Arc::default());
    let store = connect(&fake.base, json!({"cache_max_entries": 0}));
    store
        .set_json(
            &tenant("acme"),
            "runner",
            &key("k"),
            None,
            &json!("v"),
            None,
        )
        .expect("write");
    store
        .del(&tenant("acme"), "runner", &key("k"))
        .expect("delete");
    assert_eq!(
        store
            .get_json(&tenant("acme"), "runner", &key("k"), None)
            .expect("read"),
        None
    );
}

#[test]
fn a_fresh_read_is_served_from_the_cache_without_asking_the_door() {
    let fake = serve(Arc::default());
    let store = connect(&fake.base, json!({}));
    store
        .set_json(
            &tenant("acme"),
            "runner",
            &key("k"),
            None,
            &json!({"x": 1}),
            None,
        )
        .expect("write");
    let before = fake.door.hits.load(Ordering::SeqCst);
    for _ in 0..3 {
        assert_eq!(
            store
                .get_json(&tenant("acme"), "runner", &key("k"), None)
                .expect("read"),
            Some(json!({"x": 1}))
        );
    }
    assert_eq!(
        fake.door.hits.load(Ordering::SeqCst),
        before,
        "no door traffic for cached reads"
    );
}

#[test]
fn the_cache_is_bounded() {
    let fake = serve(Arc::default());
    let store = connect(&fake.base, json!({"cache_max_entries": 2}));
    for i in 0..5 {
        store
            .set_json(
                &tenant("acme"),
                "runner",
                &key(&format!("k{i}")),
                None,
                &json!(i),
                None,
            )
            .expect("write");
    }
    let before = fake.door.hits.load(Ordering::SeqCst);
    // k0 was evicted, so reading it goes to the door; k4 is still cached.
    store
        .get_json(&tenant("acme"), "runner", &key("k4"), None)
        .expect("cached");
    assert_eq!(fake.door.hits.load(Ordering::SeqCst), before);
    store
        .get_json(&tenant("acme"), "runner", &key("k0"), None)
        .expect("evicted");
    assert_eq!(fake.door.hits.load(Ordering::SeqCst), before + 1);
}

#[test]
fn a_server_error_fails_the_write_loudly_and_never_leaks_the_token() {
    let fake = serve(Arc::default());
    let store = connect(&fake.base, json!({}));
    *fake.door.fail_with.lock().expect("lock") = Some(500);
    let err = store
        .set_json(&tenant("acme"), "runner", &key("k"), None, &json!(1), None)
        .expect_err("a 500 must fail the write");
    let text = format!("{err} {err:?} {store:?}");
    assert!(text.contains("500"), "{text}");
    assert!(!text.contains(TOKEN), "the token must never appear: {text}");
}

#[test]
fn a_server_error_fails_an_uncached_read() {
    let fake = serve(Arc::default());
    let store = connect(&fake.base, json!({}));
    *fake.door.fail_with.lock().expect("lock") = Some(502);
    assert!(
        store
            .get_json(&tenant("acme"), "runner", &key("never-cached"), None)
            .is_err(),
        "an uncached read must not pretend the key is absent"
    );
}

#[test]
fn a_rejected_credential_is_named_as_such() {
    let fake = serve(Arc::default());
    let store = connect(&fake.base, json!({}));
    *fake.door.fail_with.lock().expect("lock") = Some(401);
    let err = store
        .get_json(&tenant("acme"), "runner", &key("k"), None)
        .expect_err("401");
    assert!(
        err.to_string().contains("rejected the unit's credential"),
        "{err}"
    );
}

#[test]
fn a_slow_door_times_out_instead_of_hanging() {
    let fake = serve(Arc::default());
    let store = connect(&fake.base, json!({"request_timeout_ms": 150}));
    fake.door.delay_ms.store(1500, Ordering::SeqCst);
    let started = std::time::Instant::now();
    let err = store
        .get_json(&tenant("acme"), "runner", &key("k"), None)
        .expect_err("must time out");
    assert!(
        started.elapsed() < Duration::from_millis(1200),
        "timeout honoured"
    );
    assert!(err.to_string().contains("did not answer"), "{err}");
}

#[test]
fn a_cached_read_survives_an_outage_with_a_warning_but_a_write_does_not() {
    let fake = serve(Arc::default());
    // Freshness 0: every read consults the door first; the stale entry only
    // answers when the door cannot.
    let store = HttpStateStore::connect_with_cache_policy(
        &selection(&fake.base, json!({})),
        "rev-a-123",
        Duration::ZERO,
        Duration::from_secs(60),
    )
    .expect("store");
    store
        .set_json(
            &tenant("acme"),
            "runner",
            &key("k"),
            None,
            &json!({"kept": true}),
            None,
        )
        .expect("write");
    fake.door.down.store(true, Ordering::SeqCst);
    assert_eq!(
        store
            .get_json(&tenant("acme"), "runner", &key("k"), None)
            .expect("served from cache"),
        Some(json!({"kept": true}))
    );
    assert!(
        store
            .get_json(&tenant("acme"), "runner", &key("other"), None)
            .is_err(),
        "an uncached key has nothing to fall back on"
    );
    assert!(
        store
            .set_json(&tenant("acme"), "runner", &key("k"), None, &json!(2), None)
            .is_err(),
        "writes are never buffered"
    );
}

#[test]
fn a_failed_write_drops_the_cached_copy_so_it_cannot_answer_for_unknown_state() {
    let fake = serve(Arc::default());
    let store = connect(&fake.base, json!({}));
    store
        .set_json(&tenant("acme"), "runner", &key("k"), None, &json!(1), None)
        .expect("write");
    *fake.door.fail_with.lock().expect("lock") = Some(500);
    assert!(
        store
            .set_json(&tenant("acme"), "runner", &key("k"), None, &json!(2), None)
            .is_err()
    );
    *fake.door.fail_with.lock().expect("lock") = None;
    fake.door.hits.store(0, Ordering::SeqCst);
    store
        .get_json(&tenant("acme"), "runner", &key("k"), None)
        .expect("read");
    assert_eq!(
        fake.door.hits.load(Ordering::SeqCst),
        1,
        "the read went to the door"
    );
}

#[test]
fn the_boot_probe_fails_loudly_for_a_dead_or_unauthorised_door() {
    // Nothing listens on this port.
    let dead = "http://127.0.0.1:1/api/v1/ingest/state";
    let Err(err) =
        HttpStateStore::connect(&selection(dead, json!({"request_timeout_ms": 300})), "rev")
    else {
        panic!("a dead door must fail the connect");
    };
    let text = format!("{err:#}");
    assert!(
        text.contains("refusing to serve on in-memory state"),
        "{text}"
    );
    assert!(!text.contains(TOKEN));

    let fake = serve(Arc::default());
    *fake.door.fail_with.lock().expect("lock") = Some(403);
    assert!(HttpStateStore::connect(&selection(&fake.base, json!({})), "rev").is_err());
}

#[test]
fn prefix_deletion_and_path_writes_are_refused_not_faked() {
    let fake = serve(Arc::default());
    let store = connect(&fake.base, json!({}));
    assert!(store.del_prefix(&tenant("acme"), "runner").is_err());
    let path = greentic_state::StatePath::from_pointer("/a");
    assert!(
        store
            .set_json(
                &tenant("acme"),
                "runner",
                &key("k"),
                Some(&path),
                &json!(1),
                None
            )
            .is_err()
    );
}

#[tokio::test]
async fn durable_storage_builds_the_sorla_store_and_it_serves_state() {
    let fake = serve(Arc::default());
    let storage = crate::durable_state::DurableStorage::in_memory();
    let selection = selection(&fake.base, json!({}));
    let (_session, state) = storage
        .stores_for("rev-x", Some(&selection))
        .await
        .expect("sorla store");
    let value = tokio::task::spawn_blocking(move || {
        state
            .set_json(
                &tenant("acme"),
                "runner",
                &key("k"),
                None,
                &json!({"ok": true}),
                None,
            )
            .expect("write");
        state
            .get_json(&tenant("acme"), "runner", &key("k"), None)
            .expect("read")
    })
    .await
    .expect("join");
    assert_eq!(value, Some(json!({"ok": true})));
    assert!(
        fake.door
            .seen
            .lock()
            .expect("seen")
            .iter()
            .any(|(p, _, _)| p.ends_with("/write")),
        "the write reached the door, not memory"
    );

    // And a door that is down fails the activation rather than falling back.
    fake.door.down.store(true, Ordering::SeqCst);
    let failed = crate::durable_state::DurableStorage::in_memory()
        .stores_for("rev-y", Some(&selection))
        .await;
    assert!(failed.is_err(), "no silent fallback to memory");
}

// ---- selection by pack list -----------------------------------------------

fn ids(list: &[&str]) -> std::collections::BTreeSet<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn carrying_the_pack_selects_the_backend_even_with_no_config_at_all() {
    let metering = metering_at("http://127.0.0.1:1/api/v1/ingest/state");
    let selected = super::select(
        &ids(&["messaging-webchat-gui", "state-sorla"]),
        None,
        Some(&metering),
    )
    .expect("resolves")
    .expect("selected");
    assert_eq!(selected.config.key_prefix, "greentic-state");
    assert_eq!(
        selected.door.base_url,
        "http://127.0.0.1:1/api/v1/ingest/state"
    );
    // An explicitly empty map is the same thing as no map.
    let empty = BTreeMap::new();
    assert!(
        super::select(&ids(&["state-sorla"]), Some(&empty), Some(&metering))
            .expect("resolves")
            .is_some()
    );
}

#[test]
fn a_revision_without_the_pack_keeps_the_existing_state_backend() {
    let metering = metering_at("http://127.0.0.1:1/api/v1/ingest/state");
    assert!(
        super::select(
            &ids(&["messaging-webchat-gui", "state-memory"]),
            None,
            Some(&metering)
        )
        .expect("not an error")
        .is_none()
    );
}

#[test]
fn carrying_the_pack_without_metering_refuses_instead_of_serving_memory() {
    assert_eq!(
        super::select(&ids(&["state-sorla"]), None, None).unwrap_err(),
        StateConfigError::NoMetering
    );
}
