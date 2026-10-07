use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::dns::*;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn private_loopback_link_local_and_special_ranges_are_not_public() {
    for s in [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "100.127.255.254",
        "0.0.0.0",
        "0.1.2.3",
        "255.255.255.255",
        "224.0.0.1",
        "240.0.0.1",
        "192.0.0.8",
        "192.0.2.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "192.88.99.1",
        "::1",
        "::",
        "fd00::1",
        "fc00::1",
        "fe80::1",
        "febf::1",
        "ff02::1",
        "::ffff:10.0.0.1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "::10.0.0.1",
        "::127.0.0.1",
        "64:ff9b::a00:1",
        "64:ff9b:1::1",
        "2002:a00:1::",
        "2001::1",
        "2001:db8::1",
        "100::1",
    ] {
        assert!(!is_public_ip(ip(s)), "{s} must not be public");
    }
}

#[test]
fn ordinary_addresses_are_public() {
    for s in [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "100.128.0.1",
        "172.32.0.1",
        "2606:4700:4700::1111",
        "2a03:2880:f12f:83:face:b00c::25de",
        "::ffff:8.8.8.8",
    ] {
        assert!(is_public_ip(ip(s)), "{s} must be public");
    }
}

#[tokio::test]
async fn a_name_that_resolves_only_to_loopback_is_refused() {
    assert!(resolve_public("localhost").await.is_err());
}

/// A resolver double: `name` answers whatever the closure says, counting calls.
fn double(answer: Vec<&str>) -> (FixedLookup, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let addrs = answer.iter().map(|s| SocketAddr::new(ip(s), 443)).collect();
    (
        FixedLookup {
            addrs,
            calls: Arc::clone(&calls),
        },
        calls,
    )
}

#[tokio::test]
async fn only_public_addresses_survive_a_mixed_answer() {
    let (lookup, _) = double(vec!["10.0.0.1", "93.184.216.34", "169.254.169.254", "::1"]);
    let got = resolve_public_with(&lookup, "files.slack.com")
        .await
        .unwrap();
    assert_eq!(got, vec![SocketAddr::new(ip("93.184.216.34"), 443)]);
}

#[tokio::test]
async fn an_all_private_answer_is_refused() {
    let (lookup, _) = double(vec!["10.0.0.1", "169.254.169.254", "fd00::1"]);
    assert!(
        resolve_public_with(&lookup, "files.slack.com")
            .await
            .is_err()
    );
    let (lookup, _) = double(vec![]);
    assert!(
        resolve_public_with(&lookup, "files.slack.com")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn the_client_connects_only_to_the_addresses_it_validated() {
    // DNS rebinding: a name that answers a private address at connect time.
    // The client resolves through the public-only resolver ONCE and connects
    // to what it returned, so the private answer is never dialled.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((_stream, _)) = listener.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
        }
    });
    let (lookup, calls) = double(vec!["127.0.0.1"]);
    let client = reqwest::Client::builder()
        .dns_resolver(Arc::new(PublicOnlyResolver::with_lookup(lookup)))
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let result = client
        .get(format!("http://rebind.example:{port}/x"))
        .send()
        .await;
    assert!(result.is_err());
    assert!(calls.load(Ordering::SeqCst) >= 1, "the resolver was asked");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "a private address was dialled"
    );
}

#[tokio::test]
async fn the_error_names_no_address() {
    let (lookup, _) = double(vec!["10.0.0.1"]);
    let err = resolve_public_with(&lookup, "files.slack.com")
        .await
        .unwrap_err();
    assert!(!err.to_string().contains("10.0.0.1"));
}

/// Test lookup: a fixed answer for every name.
pub(crate) struct FixedLookup {
    addrs: Vec<SocketAddr>,
    calls: Arc<AtomicUsize>,
}

impl Lookup for FixedLookup {
    fn lookup<'a>(&'a self, _host: &'a str) -> LookupFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let addrs = self.addrs.clone();
        Box::pin(async move { Ok(addrs) })
    }
}
