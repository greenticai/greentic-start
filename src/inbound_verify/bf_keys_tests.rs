use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::interop::mcp::testkit::{TEST_JWKS_E, TEST_JWKS_N};

/// A raw-TCP stub answering per PATH and counting every request per path.
/// `routes` receives the stub's own port so a metadata body can point at it.
struct Stub {
    port: u16,
    hits: Arc<Mutex<HashMap<String, usize>>>,
}

impl Stub {
    async fn serve(routes: impl FnOnce(u16) -> Vec<(&'static str, String)>) -> Self {
        Self::serve_after(std::time::Duration::ZERO, routes).await
    }

    /// Like [`Stub::serve`], answering each request only after `delay`, so
    /// concurrent callers really overlap.
    async fn serve_after(
        delay: std::time::Duration,
        routes: impl FnOnce(u16) -> Vec<(&'static str, String)>,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let routes: Arc<HashMap<String, String>> = Arc::new(
            routes(port)
                .into_iter()
                .map(|(path, response)| (path.to_string(), response))
                .collect(),
        );
        let hits = Arc::new(Mutex::new(HashMap::new()));
        let counted = Arc::clone(&hits);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let routes = Arc::clone(&routes);
                let counted = Arc::clone(&counted);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let read = stream.read(&mut buf).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..read]).to_string();
                    let path = request.split_whitespace().nth(1).unwrap_or("").to_string();
                    *counted.lock().unwrap().entry(path.clone()).or_insert(0) += 1;
                    tokio::time::sleep(delay).await;
                    let response = routes
                        .get(&path)
                        .cloned()
                        .unwrap_or_else(|| status("404 Not Found", "", "{}"));
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });
        Self { port, hits }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn hits(&self, path: &str) -> usize {
        self.hits.lock().unwrap().get(path).copied().unwrap_or(0)
    }

    fn total(&self) -> usize {
        self.hits.lock().unwrap().values().sum()
    }
}

fn status(line: &str, extra_headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {line}\r\nContent-Type: application/json\r\n{extra_headers}\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn ok_json(body: &str) -> String {
    status("200 OK", "", body)
}

fn metadata(jwks_uri: &str) -> String {
    ok_json(
        &json!({
            "issuer": BF_ISSUER,
            "jwks_uri": jwks_uri,
            "id_token_signing_alg_values_supported": ["RS256"],
        })
        .to_string(),
    )
}

fn rsa_key(kid: &str, endorsements: &[&str]) -> serde_json::Value {
    json!({
        "kty": "RSA", "use": "sig", "kid": kid, "n": TEST_JWKS_N, "e": TEST_JWKS_E,
        "endorsements": endorsements,
    })
}

fn key_set(keys: Vec<serde_json::Value>) -> String {
    ok_json(&json!({ "keys": keys }).to_string())
}

/// Metadata at `/meta` naming `/keys` on the same stub; the key set holds one
/// usable RSA key `k1` plus two that must be dropped.
async fn standard_stub() -> Stub {
    Stub::serve(|port| {
        let mut hs = rsa_key("hs", &["msteams"]);
        hs["alg"] = json!("HS256");
        vec![
            ("/meta", metadata(&format!("http://127.0.0.1:{port}/keys"))),
            (
                "/keys",
                key_set(vec![
                    rsa_key("k1", &["msteams", "skype"]),
                    json!({"kty": "oct", "kid": "sym", "k": "c2VjcmV0"}),
                    hs,
                ]),
            ),
        ]
    })
    .await
}

fn source_for(stub: &Stub) -> BfKeySource {
    BfKeySource::for_tests(stub.url("/meta"), "127.0.0.1".to_string(), None)
}

fn found(lookup: BfKeyLookup) -> Option<BfKey> {
    match lookup {
        BfKeyLookup::Found(key) => Some(key),
        _ => None,
    }
}

fn is_unknown(lookup: &BfKeyLookup) -> bool {
    matches!(lookup, BfKeyLookup::UnknownKid)
}

fn is_unavailable(lookup: &BfKeyLookup) -> bool {
    matches!(lookup, BfKeyLookup::Unavailable)
}

#[tokio::test]
async fn metadata_and_keys_round_trip_with_endorsements() {
    let stub = standard_stub().await;
    let key = found(source_for(&stub).key("k1").await).expect("k1");
    assert_eq!(
        &*key.endorsements,
        &["msteams".to_string(), "skype".to_string()]
    );
    assert_eq!((stub.hits("/meta"), stub.hits("/keys")), (1, 1));
}

#[tokio::test]
async fn an_unknown_kid_after_a_successful_fetch_is_unknown() {
    let stub = standard_stub().await;
    let source = source_for(&stub);
    assert!(is_unknown(&source.key("nope").await));
}

#[tokio::test]
async fn symmetric_and_non_rs256_keys_are_dropped() {
    let stub = standard_stub().await;
    let source = source_for(&stub);
    assert!(found(source.key("k1").await).is_some());
    assert!(is_unknown(&source.key("sym").await));
    assert!(is_unknown(&source.key("hs").await));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn twenty_concurrent_cold_lookups_make_one_fetch() {
    let stub = Stub::serve_after(std::time::Duration::from_millis(200), |port| {
        vec![
            ("/meta", metadata(&format!("http://127.0.0.1:{port}/keys"))),
            ("/keys", key_set(vec![rsa_key("k1", &["msteams"])])),
        ]
    })
    .await;
    let source = Arc::new(source_for(&stub));
    // Collected, so all twenty are spawned before the first is awaited.
    let lookups: Vec<_> = (0..20)
        .map(|_| {
            let source = Arc::clone(&source);
            tokio::spawn(async move { found(source.key("k1").await).is_some() })
        })
        .collect();
    for lookup in lookups {
        assert!(lookup.await.expect("task"), "every caller gets the key");
    }
    assert_eq!((stub.hits("/meta"), stub.hits("/keys")), (1, 1));
}

#[tokio::test]
async fn unknown_kids_within_the_floor_make_no_new_request() {
    let stub = standard_stub().await;
    let source = source_for(&stub);
    assert!(is_unknown(&source.key("attacker-1").await));
    for i in 2..50 {
        assert!(is_unknown(&source.key(&format!("attacker-{i}")).await));
    }
    assert_eq!(stub.total(), 2, "one metadata + one key-set fetch in total");
}

#[tokio::test]
async fn a_jwks_uri_on_another_host_is_never_fetched() {
    let other = standard_stub().await;
    let stub = Stub::serve({
        let elsewhere = other.url("/keys").replace("127.0.0.1", "localhost");
        move |_| vec![("/meta", metadata(&elsewhere))]
    })
    .await;
    let source = source_for(&stub);
    assert!(is_unavailable(&source.key("k1").await));
    assert_eq!(other.total(), 0, "the foreign key host was never asked");
}

#[tokio::test]
async fn a_redirect_from_the_key_url_is_not_followed() {
    let target = standard_stub().await;
    let stub = Stub::serve({
        let location = target.url("/keys");
        move |port| {
            vec![
                ("/meta", metadata(&format!("http://127.0.0.1:{port}/keys"))),
                (
                    "/keys",
                    status("302 Found", &format!("Location: {location}\r\n"), "{}"),
                ),
            ]
        }
    })
    .await;
    assert!(is_unavailable(&source_for(&stub).key("k1").await));
    assert_eq!(target.total(), 0, "the redirect target was never asked");
}

#[tokio::test]
async fn an_oversized_key_set_is_unavailable() {
    let stub = Stub::serve(|port| {
        let padding = "x".repeat(300 * 1024);
        let body = json!({ "keys": [rsa_key("k1", &["msteams"])], "pad": padding }).to_string();
        vec![
            ("/meta", metadata(&format!("http://127.0.0.1:{port}/keys"))),
            ("/keys", ok_json(&body)),
        ]
    })
    .await;
    assert!(is_unavailable(&source_for(&stub).key("k1").await));
}

#[tokio::test]
async fn metadata_without_rs256_is_unavailable() {
    let stub = Stub::serve(|port| {
        let body = json!({
            "jwks_uri": format!("http://127.0.0.1:{port}/keys"),
            "id_token_signing_alg_values_supported": ["HS256"],
        })
        .to_string();
        vec![
            ("/meta", ok_json(&body)),
            ("/keys", key_set(vec![rsa_key("k1", &["msteams"])])),
        ]
    })
    .await;
    assert!(is_unavailable(&source_for(&stub).key("k1").await));
    assert_eq!(stub.hits("/keys"), 0);
}

/// The client resolves names through the public-only resolver: a name that
/// resolves only to a private address is never connected to.
#[tokio::test]
async fn a_name_resolving_to_a_private_address_is_never_reached() {
    struct Loopback;
    impl crate::artifacts::dns::Lookup for Loopback {
        fn lookup<'a>(&'a self, _host: &'a str) -> crate::artifacts::dns::LookupFuture<'a> {
            Box::pin(async { Ok(vec!["127.0.0.1:0".parse().expect("addr")]) })
        }
    }
    let stub = standard_stub().await;
    let client = BfKeySource::test_client_builder()
        .dns_resolver(Arc::new(
            crate::artifacts::dns::PublicOnlyResolver::with_lookup(Loopback),
        ))
        .build()
        .expect("client");
    let source = BfKeySource::for_tests(
        format!("http://bf.test:{}/meta", stub.port),
        "bf.test".to_string(),
        Some(client),
    );
    assert!(is_unavailable(&source.key("k1").await));
    assert_eq!(stub.total(), 0);
}

#[test]
fn the_production_rule_accepts_only_https_on_the_bot_framework_host() {
    let source = BfKeySource::new(
        reqwest::Client::new(),
        BF_METADATA_URL.to_string(),
        KeyHostRule {
            host: BF_KEY_HOST.to_string(),
            https_only: true,
            allow_port: false,
        },
    );
    for ok in [
        "https://login.botframework.com/v1/.well-known/keys",
        "https://LOGIN.botframework.com/v1/.well-known/keys",
        "https://login.botframework.com:443/v1/.well-known/keys",
    ] {
        assert!(source.accept_jwks_uri(ok).is_some(), "{ok}");
    }
    for refused in [
        "http://login.botframework.com/v1/.well-known/keys",
        "https://login.botframework.com:8443/v1/.well-known/keys",
        "https://user:pw@login.botframework.com/v1/.well-known/keys",
        "https://login.botframework.com.evil.example/keys",
        "https://evil.example/login.botframework.com/keys",
        "https://x.login.botframework.com/keys",
        "https://127.0.0.1/keys",
        "not a url",
    ] {
        assert!(source.accept_jwks_uri(refused).is_none(), "{refused}");
    }
}

#[test]
fn debug_never_prints_keys() {
    let source = BfKeySource::for_tests("http://127.0.0.1:1/meta".into(), "127.0.0.1".into(), None);
    let printed = format!("{source:?}");
    assert!(printed.contains("metadata_url"), "{printed}");
    assert!(!printed.contains("cache"), "{printed}");
}

/// The production client is the one thing the stub tests cannot drive (they
/// talk plain http to loopback), so its settings are pinned in the source:
/// public-only resolution, https only, no proxy, no redirect.
#[test]
fn the_production_client_is_locked_down() {
    let source = include_str!("bf_keys.rs");
    let production = &source[source
        .find("pub(crate) fn production()")
        .expect("production()")..];
    let production = &production[..production.find("\n    }\n").expect("end")];
    assert!(production.contains("with_public_only_resolver(base_builder())"));
    assert!(production.contains(".https_only(true)"));
    assert!(production.contains("host: BF_KEY_HOST.to_string()"));
    assert!(production.contains("https_only: true"));
    assert!(production.contains("allow_port: false"));
    let base = &source[source.find("fn base_builder()").expect("base_builder")..];
    let base = &base[..base.find("\n}\n").expect("end")];
    assert!(base.contains(".redirect(reqwest::redirect::Policy::none())"));
    assert!(base.contains(".no_proxy()"));
    assert!(base.contains(".timeout(FETCH_TIMEOUT)"));
}

/// Review G4 #1: a follower that waited on a leader whose fetch succeeded
/// must not be told `Unavailable` (admitted unverified) for a forged `kid`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_forged_kids_after_a_successful_fetch_are_all_unknown() {
    let stub = Stub::serve_after(std::time::Duration::from_millis(200), |port| {
        vec![
            ("/meta", metadata(&format!("http://127.0.0.1:{port}/keys"))),
            ("/keys", key_set(vec![rsa_key("k1", &["msteams"])])),
        ]
    })
    .await;
    let source = Arc::new(source_for(&stub));
    let lookups: Vec<_> = (0..10)
        .map(|i| {
            let source = Arc::clone(&source);
            tokio::spawn(async move { source.key(&format!("forged-{i}")).await })
        })
        .collect();
    let mut unavailable = 0;
    for lookup in lookups {
        let got = lookup.await.expect("task");
        assert!(!matches!(got, BfKeyLookup::Found(_)));
        if is_unavailable(&got) {
            unavailable += 1;
        }
    }
    assert_eq!(unavailable, 0, "a forged kid was admitted unverified");
    assert_eq!((stub.hits("/meta"), stub.hits("/keys")), (1, 1));
}

/// Review G4 #2: with no trusted key set, a lookup inside the refresh floor
/// is `Unavailable`, never a refusal: a Bot Framework outage must not turn
/// every genuine token into a `401`.
#[tokio::test]
async fn an_outage_on_a_cold_start_is_unavailable_inside_the_floor_too() {
    let stub = Stub::serve(|_| vec![("/meta", status("503 Service Unavailable", "", "{}"))]).await;
    let source = source_for(&stub);
    assert!(is_unavailable(&source.key("k1").await));
    for _ in 0..5 {
        assert!(is_unavailable(&source.key("k1").await), "refused in outage");
    }
    assert_eq!(stub.total(), 1, "the floor still holds the retry storm");
}

/// Seed `source` with the standard key set as of the real `now`, behind an
/// outage stub, and return a clock `offset` later.
async fn outage_source_seeded(offset: Duration) -> (Stub, BfKeySource, impl Fn() -> Instant) {
    let stub = Stub::serve(|_| vec![("/meta", status("503 Service Unavailable", "", "{}"))]).await;
    let source = source_for(&stub);
    let seed = found(standard_key_lookup().await).expect("a key to seed");
    let seeded_at = Instant::now();
    source.cache.store_keys(
        &source.metadata_url,
        HashMap::from([("k1".to_string(), seed)]),
        seeded_at,
    );
    (stub, source, move || seeded_at + offset)
}

/// Re-review G4 I1: a Bot Framework outage that outlasts the 12 h TTL must not
/// turn every Teams activity (forged ones included) into "admitted
/// unverified". A key the expired set carries is still verified against it,
/// inside the floor and out of it.
#[tokio::test]
async fn an_outage_past_the_ttl_still_verifies_a_kid_the_stale_set_carries() {
    let (stub, source, clock) = outage_source_seeded(Duration::from_secs(13 * 3600)).await;
    assert!(found(source.key_at("k1", &clock).await).is_some());
    assert!(
        found(source.key_at("k1", &clock).await).is_some(),
        "inside the floor"
    );
    assert_eq!(stub.total(), 1, "the refresh was attempted once and failed");
}

/// A `kid` the stale set lacks proves nothing (the set may simply be old), so
/// it stays `Unavailable`, never `UnknownKid`.
#[tokio::test]
async fn an_outage_past_the_ttl_is_unavailable_for_a_kid_the_stale_set_lacks() {
    let (_stub, source, clock) = outage_source_seeded(Duration::from_secs(13 * 3600)).await;
    assert!(is_unavailable(&source.key_at("other", &clock).await));
    assert!(
        is_unavailable(&source.key_at("other", &clock).await),
        "inside the floor"
    );
}

/// Past [`STALE_KEY_SET_MAX_AGE`] the old set is not used at all.
#[tokio::test]
async fn an_outage_past_the_stale_limit_is_unavailable() {
    let (_stub, source, clock) =
        outage_source_seeded(STALE_KEY_SET_MAX_AGE + Duration::from_secs(1)).await;
    assert!(is_unavailable(&source.key_at("k1", &clock).await));
}

/// A refresh that SUCCEEDS past the TTL replaces the stale set: a kid only
/// the old set carried is then unknown, not served from the old set.
#[tokio::test]
async fn a_successful_refresh_past_the_ttl_replaces_the_stale_set() {
    let stub = standard_stub().await;
    let source = source_for(&stub);
    let seed = found(standard_key_lookup().await).expect("a key to seed");
    let seeded_at = Instant::now();
    source.cache.store_keys(
        &source.metadata_url,
        HashMap::from([("old-only".to_string(), seed)]),
        seeded_at,
    );
    let clock = move || seeded_at + Duration::from_secs(13 * 3600);
    assert!(found(source.key_at("k1", &clock).await).is_some());
    assert!(is_unknown(&source.key_at("old-only", &clock).await));
}

/// A trusted (fresh) key set still refuses an unknown kid inside the floor.
#[tokio::test]
async fn a_fresh_key_set_still_refuses_an_unknown_kid_inside_the_floor() {
    let stub = standard_stub().await;
    let source = source_for(&stub);
    assert!(found(source.key("k1").await).is_some());
    assert!(is_unknown(&source.key("nope-1").await));
    assert!(is_unknown(&source.key("nope-2").await));
    assert_eq!(stub.total(), 2);
}

async fn standard_key_lookup() -> BfKeyLookup {
    let stub = standard_stub().await;
    source_for(&stub).key("k1").await
}
