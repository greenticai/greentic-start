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
    // The process's only slot, held by ANOTHER unit.
    let held = limits.try_read_slot("another-unit").expect("one slot");
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
    let limits = LinkLimits::with_budgets(2, 300, 1 << 30, 100);
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

/// The door has no HEAD: a HEAD reads the whole file, so it is charged like
/// a GET. Past the budget a valid link is 429; a bad MAC is still the 404.
#[tokio::test]
async fn a_head_request_spends_egress_like_a_get() {
    let f = fixture(StubReader::file("image/png", None, &[7u8; 100]));
    let limits = LinkLimits::with_budgets(2, 300, 1 << 30, 100);
    let path = f.link().to_path();
    for _ in 0..3 {
        assert_eq!(
            f.request(Method::HEAD, &path, &limits).await.status,
            StatusCode::OK
        );
    }
    let answer = f.request(Method::HEAD, &path, &limits).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        f.request(Method::GET, &path, &limits).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    let mut forged = f.link();
    forged.mac_hex = "0".repeat(32);
    let answer = f.request(Method::HEAD, &forged.to_path(), &limits).await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    assert_eq!(answer.body.as_ref(), NOT_FOUND_BODY);
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

#[tokio::test]
async fn one_unit_holds_at_most_one_read_slot() {
    let a = fixture(StubReader::file("image/png", None, b"IMG"));
    let b = fixture(StubReader::file("image/png", None, b"IMG"));
    let limits = limits();
    let held = limits.try_read_slot(&a.unit.deployment).expect("a's slot");
    let answer = a.request(Method::GET, &a.link().to_path(), &limits).await;
    assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(answer.header("retry-after"), Some("2"));
    // Another unit still gets the process's second slot.
    let answer = b.request(Method::GET, &b.link().to_path(), &limits).await;
    assert_eq!(answer.status, StatusCode::OK);
    drop(held);
    let answer = a.request(Method::GET, &a.link().to_path(), &limits).await;
    assert_eq!(answer.status, StatusCode::OK);
}

/// The largest file is reserved before the door read and the unused part
/// is given back: 100-byte files against a 400-byte budget and a 200-byte
/// reservation serve three times (charging the reservation would stop at two).
#[tokio::test]
async fn the_budget_is_reserved_before_the_read_and_the_rest_refunded() {
    let f = fixture(StubReader::file("image/png", None, &[7u8; 100]));
    let limits = LinkLimits::with_budgets(2, 400, 1 << 30, 200);
    let path = f.link().to_path();
    for i in 0..3 {
        let answer = f.request(Method::GET, &path, &limits).await;
        assert_eq!(answer.status, StatusCode::OK, "request {i}");
    }
    let answer = f.request(Method::GET, &path, &limits).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
}

/// A read still in flight counts against the budget before it finishes.
#[tokio::test]
async fn a_held_reservation_counts_against_the_budget() {
    let f = fixture(StubReader::file("image/png", None, &[7u8; 100]));
    let limits = LinkLimits::with_budgets(2, 150, 1 << 30, 100);
    let path = f.link().to_path();
    let held = limits
        .reserve(&f.unit.deployment, "other-link", NOW)
        .expect("first reservation");
    let answer = f.request(Method::GET, &path, &limits).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    drop(held);
    let answer = f.request(Method::GET, &path, &limits).await;
    assert_eq!(answer.status, StatusCode::OK);
}

/// A read that served nothing gives its whole reservation back.
#[tokio::test]
async fn a_failed_read_spends_nothing() {
    let f = fixture(StubReader::new(vec![
        Err(greentic_aw_runtime::ArtifactError::NotFound),
        Err(greentic_aw_runtime::ArtifactError::NotFound),
        Ok(("image/png".into(), None, vec![7u8; 100])),
    ]));
    let limits = LinkLimits::with_budgets(2, 150, 1 << 30, 100);
    let path = f.link().to_path();
    for _ in 0..2 {
        let answer = f.request(Method::GET, &path, &limits).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND);
    }
    let answer = f.request(Method::GET, &path, &limits).await;
    assert_eq!(answer.status, StatusCode::OK);
}

/// One link cannot spend its unit's whole budget.
#[tokio::test]
async fn one_link_has_its_own_hourly_byte_budget() {
    let f = fixture(StubReader::file("image/png", None, &[7u8; 100]));
    let limits = LinkLimits::with_budgets(2, 1 << 30, 250, 100);
    let path = f.link().to_path();
    for i in 0..2 {
        let answer = f.request(Method::GET, &path, &limits).await;
        assert_eq!(answer.status, StatusCode::OK, "request {i}");
    }
    let answer = f.request(Method::GET, &path, &limits).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    let other = f.link_for(
        "artifact://eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        NOW,
        TTL,
    );
    let answer = f.request(Method::GET, &other.to_path(), &limits).await;
    assert_eq!(answer.status, StatusCode::OK);
    let next = f
        .request_with(Method::GET, &path, &limits, None, true, NOW + 3_600)
        .await;
    assert_eq!(next.status, StatusCode::OK);
}
