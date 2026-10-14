//! The activation probe pass: one probe per distinct door (URL + token), at
//! most [`PROBE_CONCURRENCY`] in flight (the admin runs four transfers per
//! process and refuses the rest), and the whole pass inside one deadline.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::interop::metering::MeteringConfig;
use crate::interop::metering::testkit::{
    StubAdmin, metering_for, metering_with_token, silent_peer,
};

use super::activate::{PROBE_CONCURRENCY, activate_all, activate_all_within};
use super::fetch::SecretLookup;
use super::origin::SecretScope;
use super::time_testkit::within_ceiling;
use super::unit::{Off, UnitAttachments};

struct NoSecrets;

#[async_trait]
impl SecretLookup for NoSecrets {
    async fn get(&self, _: &SecretScope, _: &str) -> Option<String> {
        None
    }
}

fn endpoint(port: u16) -> String {
    format!("http://127.0.0.1:{port}/api/v1/ingest/worker-usage")
}

fn with_token(port: u16, token: &str) -> MeteringConfig {
    metering_with_token(&endpoint(port), token)
}

const NOT_FOUND: &str = r#"{"error":{"code":"not_found"}}"#;

#[tokio::test]
async fn revisions_sharing_one_door_and_token_are_probed_once() {
    let stub = StubAdmin::answering("HTTP/1.1 404 Not Found", "", NOT_FOUND).await;
    let port = reqwest::Url::parse(&stub.url).unwrap().port().unwrap();
    let items = (0..5)
        .map(|n| (n, format!("rev-{n}"), Some(metering_for(&endpoint(port)))))
        .collect();
    let got = within_ceiling(activate_all(
        items,
        Arc::new(NoSecrets),
        Duration::from_secs(3),
    ))
    .await
    .expect("activates");
    assert_eq!(got.len(), 5);
    for unit in got.values() {
        assert!(matches!(unit.state, UnitAttachments::Enabled { .. }));
    }
    assert_eq!(stub.count(), 1, "one door, one token: one probe");
}

/// A door that answers slowly and counts how many requests it holds at once.
async fn counting_door(peak: Arc<AtomicUsize>) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let current = Arc::new(AtomicUsize::new(0));
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let current = Arc::clone(&current);
            let peak = Arc::clone(&peak);
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut buf = [0u8; 1024];
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                let now = current.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(150)).await;
                current.fetch_sub(1, Ordering::SeqCst);
                let answer = format!(
                    "HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{NOT_FOUND}",
                    NOT_FOUND.len()
                );
                let _ = stream.write_all(answer.as_bytes()).await;
            });
        }
    });
    port
}

/// Eight units with their own tokens on one admin: the admin runs four
/// transfers at a time and refuses the rest, so the probes must stay below.
#[tokio::test]
async fn probes_stay_under_the_admins_transfer_limit() {
    let peak = Arc::new(AtomicUsize::new(0));
    let port = counting_door(Arc::clone(&peak)).await;
    let items = (0..8)
        .map(|n| {
            (
                n,
                format!("rev-{n}"),
                Some(with_token(port, &format!("gtm_unit_{n}"))),
            )
        })
        .collect();
    let got = within_ceiling(activate_all(
        items,
        Arc::new(NoSecrets),
        Duration::from_secs(3),
    ))
    .await
    .expect("activates");
    for unit in got.values() {
        assert!(matches!(unit.state, UnitAttachments::Enabled { .. }));
    }
    let peak = peak.load(Ordering::SeqCst);
    assert!(peak >= 1);
    assert!(
        peak <= PROBE_CONCURRENCY && PROBE_CONCURRENCY < 4,
        "peak {peak} probes at once"
    );
}

/// However many distinct doors hang, the whole pass ends by its deadline: a
/// door not yet probed by then is reported unavailable without a probe.
#[tokio::test(start_paused = true)]
async fn the_whole_probe_pass_ends_by_its_deadline() {
    let mut items = Vec::new();
    for n in 0..9 {
        items.push((
            n,
            format!("rev-{n}"),
            Some(metering_for(&endpoint(silent_peer().await))),
        ));
    }
    let started = tokio::time::Instant::now();
    let got = within_ceiling(activate_all_within(
        items,
        Arc::new(NoSecrets),
        Duration::from_secs(8),
        Duration::from_secs(10),
    ))
    .await
    .expect("hanging doors are unavailable, not refusals");
    assert!(
        started.elapsed() <= Duration::from_secs(10) + Duration::from_millis(100),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(got.len(), 9);
    for unit in got.values() {
        assert!(matches!(
            unit.state,
            UnitAttachments::Off(Off::DoorUnavailable)
        ));
    }
}
