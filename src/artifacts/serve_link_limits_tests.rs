//! The signed-link route's limits: a bounded door read, per-link and
//! per-client windows, read slots and the hourly egress budget.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use hyper::{Method, StatusCode};

use super::serve_link_limits::LinkLimits;
use super::serve_link_testkit::*;
use crate::http_ingress::limits::ClientKey;

#[tokio::test(start_paused = true)]
async fn a_door_that_never_answers_is_bounded() {
    let f = fixture(Arc::new(HangingReader));
    // Virtual time: a route without its own bound would outlive this.
    let answer = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        f.request(Method::GET, &f.link().to_path(), &limits()),
    )
    .await
    .expect("the door read was not bounded");
    assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn one_link_answers_at_most_thirty_times_a_minute() {
    let f = fixture(StubReader::file("image/png", None, b"IMG"));
    let limits = limits();
    let path = f.link().to_path();
    for i in 0..30 {
        let answer = f.request(Method::GET, &path, &limits).await;
        assert_eq!(answer.status, StatusCode::OK, "request {i}");
    }
    let answer = f.request(Method::GET, &path, &limits).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(answer.header("retry-after").is_some());
    assert_security_headers(&answer);
    // Another link of the same unit has its own window.
    let other = f.link_for(
        "artifact://eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        NOW,
        TTL,
    );
    let answer = f.request(Method::GET, &other.to_path(), &limits).await;
    assert_eq!(answer.status, StatusCode::OK);
}

#[tokio::test]
async fn busy_reads_answer_503_retry_after_two() {
    let f = fixture(StubReader::file("image/png", None, b"IMG"));
    let limits = LinkLimits::new(1, 1 << 30);
    let held = limits.try_read_slot().expect("one slot");
    let answer = f.request(Method::GET, &f.link().to_path(), &limits).await;
    assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(answer.header("retry-after"), Some("2"));
    drop(held);
    let answer = f.request(Method::GET, &f.link().to_path(), &limits).await;
    assert_eq!(answer.status, StatusCode::OK);
}

#[tokio::test]
async fn a_units_hourly_egress_budget_is_enforced() {
    let f = fixture(StubReader::file("image/png", None, &[7u8; 100]));
    let limits = LinkLimits::new(2, 250);
    let path = f.link().to_path();
    for _ in 0..3 {
        assert_eq!(
            f.request(Method::GET, &path, &limits).await.status,
            StatusCode::OK
        );
    }
    let answer = f.request(Method::GET, &path, &limits).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    // The next hour has a fresh budget.
    let next = f
        .request_with(Method::GET, &path, &limits, None, true, NOW + 3_600)
        .await;
    assert_eq!(next.status, StatusCode::OK);
}

#[tokio::test]
async fn a_head_request_spends_no_egress() {
    let f = fixture(StubReader::file("image/png", None, &[7u8; 100]));
    let limits = LinkLimits::new(2, 150);
    let path = f.link().to_path();
    for _ in 0..5 {
        assert_eq!(
            f.request(Method::HEAD, &path, &limits).await.status,
            StatusCode::OK
        );
    }
    assert_eq!(
        f.request(Method::GET, &path, &limits).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_per_client_limit_applies_only_to_an_identified_client() {
    let f = fixture(StubReader::file("image/png", None, b"IMG"));
    let limits = LinkLimits::new(2, 1 << 30);
    let client = ClientKey::of(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));
    // 121 distinct links from one client: the client window, not the link one.
    let mut refused = 0;
    for i in 0..121u64 {
        let link = f.link_for(&format!("artifact://{i:064x}"), NOW, TTL);
        let answer = f
            .request_with(
                Method::GET,
                &link.to_path(),
                &limits,
                Some(client),
                true,
                NOW,
            )
            .await;
        if answer.status == StatusCode::TOO_MANY_REQUESTS {
            refused += 1;
        }
    }
    assert_eq!(refused, 1);
    // Without a client key nothing is counted per client.
    let limits = LinkLimits::new(2, 1 << 30);
    for i in 0..121u64 {
        let link = f.link_for(&format!("artifact://{i:064x}"), NOW, TTL);
        let answer = f
            .request_with(Method::GET, &link.to_path(), &limits, None, true, NOW)
            .await;
        assert_eq!(answer.status, StatusCode::OK);
    }
}
