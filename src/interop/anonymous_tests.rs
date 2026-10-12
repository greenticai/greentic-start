use std::time::Duration;

use hyper::HeaderMap;

use super::*;
use crate::interop::limits::{CHEAP_COST, Charge};

const UNIT: &str = "dep-1";

fn limits(burst: u32, rate_per_min: u32, cap: Option<u32>) -> PublicLimits {
    PublicLimits {
        rate_per_min,
        burst,
        daily_turn_cap: cap,
    }
}

fn headers(xff: &[&str]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for line in xff {
        map.append("x-forwarded-for", line.parse().expect("header value"));
    }
    map
}

const T0: u64 = 1_800_000_000_000; // an arbitrary instant, ms since the epoch

/// The unit's bucket holds `burst` turns however many distinct clients ask,
/// and a refusal names a Retry-After of at least a second.
#[test]
fn the_unit_bucket_binds_every_client_together() {
    let limiter = AnonymousLimiter::default();
    let now = Instant::now();
    let l = limits(6, 60, None);
    let mut served = 0;
    for i in 0..30 {
        match limiter.check(
            UNIT,
            Some(&format!("client-{i}")),
            &l,
            Charge::TURN,
            now,
            T0,
        ) {
            Ok(()) => served += 1,
            Err(retry) => assert!(retry >= 1),
        }
    }
    assert_eq!(served, 6);
}

/// A lone client gets half the unit's burst: fairness, not the guarantee.
#[test]
fn one_client_cannot_take_the_whole_unit_allowance() {
    let limiter = AnonymousLimiter::default();
    let now = Instant::now();
    let l = limits(10, 60, None);
    let served = (0..20)
        .filter(|_| {
            limiter
                .check(UNIT, Some("client-a"), &l, Charge::TURN, now, T0)
                .is_ok()
        })
        .count();
    assert_eq!(served, 5, "half of the burst of 10");
    // Another client still has its own share of what remains in the unit.
    assert!(
        limiter
            .check(UNIT, Some("client-b"), &l, Charge::TURN, now, T0)
            .is_ok()
    );
}

#[test]
fn the_bucket_refills_at_the_configured_rate() {
    let limiter = AnonymousLimiter::default();
    let start = Instant::now();
    let l = limits(2, 60, None); // 1 turn a second
    // Two distinct clients drain the unit's burst of 2.
    assert!(
        limiter
            .check(UNIT, Some("a"), &l, Charge::TURN, start, T0)
            .is_ok()
    );
    assert!(
        limiter
            .check(UNIT, Some("b"), &l, Charge::TURN, start, T0)
            .is_ok()
    );
    assert_eq!(
        limiter.check(UNIT, Some("c"), &l, Charge::TURN, start, T0),
        Err(1)
    );
    let later = start + Duration::from_secs(1);
    assert!(
        limiter
            .check(UNIT, Some("c"), &l, Charge::TURN, later, T0)
            .is_ok()
    );
    assert!(
        limiter
            .check(UNIT, Some("d"), &l, Charge::TURN, later, T0)
            .is_err()
    );
}

#[test]
fn a_changed_policy_resizes_the_buckets_without_forgiving_a_spender() {
    let limiter = AnonymousLimiter::default();
    let now = Instant::now();
    let generous = limits(40, 600, None);
    for i in 0..40 {
        let _ = limiter.check(
            UNIT,
            Some(&format!("c{i}")),
            &generous,
            Charge::TURN,
            now,
            T0,
        );
    }
    // The operator tightens the policy while the process keeps running.
    let tight = limits(2, 60, None);
    assert!(
        limiter
            .check(UNIT, Some("fresh"), &tight, Charge::TURN, now, T0)
            .is_err()
    );
}

#[test]
fn the_client_table_is_hard_bounded() {
    let limiter = AnonymousLimiter::default();
    let now = Instant::now();
    // A huge burst so the unit bucket does not stop the flood first.
    let l = limits(u32::MAX / 4, 60_000, None);
    for i in 0..(MAX_CLIENT_BUCKETS * 4) {
        let _ = limiter.check(
            UNIT,
            Some(&format!("spoofed-{i}")),
            &l,
            Charge::CHEAP,
            now,
            T0,
        );
    }
    assert!(
        limiter.client_buckets() <= MAX_CLIENT_BUCKETS,
        "{} per-client buckets",
        limiter.client_buckets()
    );
}

/// A full table of ACTIVE clients refuses a new client a bucket (the unit
/// bucket still governs it); once they have gone idle the sweep reclaims them.
#[test]
fn idle_client_buckets_are_swept_above_the_threshold() {
    let limiter = AnonymousLimiter::default();
    let start = Instant::now();
    let l = limits(1000, 6000, None);
    for i in 0..MAX_CLIENT_BUCKETS {
        let _ = limiter.check(UNIT, Some(&format!("c{i}")), &l, Charge::CHEAP, start, T0);
    }
    assert_eq!(limiter.client_buckets(), MAX_CLIENT_BUCKETS);
    // Still full of active entries: a new client gets no bucket of its own.
    let _ = limiter.check(UNIT, Some("newcomer"), &l, Charge::CHEAP, start, T0);
    assert_eq!(limiter.client_buckets(), MAX_CLIENT_BUCKETS);
    // A minute later every bucket has refilled; the sweep drops them.
    let later = start + Duration::from_secs(60);
    let _ = limiter.check(UNIT, Some("newcomer"), &l, Charge::CHEAP, later, T0);
    assert!(limiter.client_buckets() < MAX_CLIENT_BUCKETS);
    assert!(limiter.client_buckets() >= 1);
}

#[test]
fn the_daily_cap_counts_turns_only_and_resets_at_utc_midnight() {
    let limiter = AnonymousLimiter::default();
    let now = Instant::now();
    let l = limits(100, 6000, Some(3));
    let midnight = (T0 / 86_400_000 + 1) * 86_400_000;
    let noon = midnight - 43_200_000;

    // Requests that are not turns never touch the cap.
    for i in 0..10 {
        assert!(
            limiter
                .check(UNIT, Some(&format!("n{i}")), &l, Charge::CHEAP, now, noon)
                .is_ok()
        );
    }
    for i in 0..3 {
        assert!(
            limiter
                .check(UNIT, Some(&format!("t{i}")), &l, Charge::TURN, now, noon)
                .is_ok()
        );
    }
    let refused = limiter.check(UNIT, Some("t9"), &l, Charge::TURN, now, noon);
    assert_eq!(
        refused,
        Err(43_200),
        "twelve hours to the next UTC midnight"
    );
    // A non-turn is still served once the cap is reached.
    assert!(
        limiter
            .check(UNIT, Some("n99"), &l, Charge::CHEAP, now, noon)
            .is_ok()
    );
    // The next UTC day starts a fresh count.
    assert!(
        limiter
            .check(UNIT, Some("t10"), &l, Charge::TURN, now, midnight + 1_000)
            .is_ok()
    );
}

#[test]
fn a_refused_request_spends_none_of_the_daily_cap() {
    let limiter = AnonymousLimiter::default();
    let now = Instant::now();
    let l = limits(2, 60, Some(5));
    let mut served = 0;
    for i in 0..20 {
        if limiter
            .check(UNIT, Some(&format!("c{i}")), &l, Charge::TURN, now, T0)
            .is_ok()
        {
            served += 1;
        }
    }
    assert_eq!(served, 2, "the burst stopped the rest");
    // 3 of the 5 turns are still available once the bucket refills.
    let later = now + Duration::from_secs(10);
    let mut more = 0;
    for i in 0..20 {
        if limiter
            .check(UNIT, Some(&format!("d{i}")), &l, Charge::TURN, later, T0)
            .is_ok()
        {
            more += 1;
        }
    }
    assert_eq!(more, 2);
    assert!(
        limiter
            .check(
                UNIT,
                Some("z"),
                &l,
                Charge::TURN,
                later + Duration::from_secs(10),
                T0
            )
            .is_ok()
    );
    assert!(
        limiter
            .check(
                UNIT,
                Some("z2"),
                &l,
                Charge::TURN,
                later + Duration::from_secs(20),
                T0
            )
            .is_err(),
        "5 turns served in total"
    );
}

#[test]
fn units_have_independent_allowances() {
    let limiter = AnonymousLimiter::default();
    let now = Instant::now();
    let l = limits(1, 60, Some(1));
    assert!(
        limiter
            .check("unit-a", Some("c"), &l, Charge::TURN, now, T0)
            .is_ok()
    );
    assert!(
        limiter
            .check("unit-a", Some("d"), &l, Charge::TURN, now, T0)
            .is_err()
    );
    assert!(
        limiter
            .check("unit-b", Some("c"), &l, Charge::TURN, now, T0)
            .is_ok()
    );
}

#[test]
fn the_remainder_of_a_turn_counts_as_a_turn_and_a_cheap_request_does_not() {
    assert_eq!((Charge::TURN.turn, Charge::CHEAP.turn), (true, false));
    assert!(Charge::priced(crate::interop::limits::TURN_COST).turn);
    assert!(!Charge::priced(CHEAP_COST).turn);
    assert!(Charge::remainder(CHEAP_COST).turn);
}

// ---- the client behind a request --------------------------------------------

fn ip(s: &str) -> IpAddr {
    s.parse().expect("ip")
}

const PUBLIC_PEER: &str = "8.8.8.8";

#[test]
fn with_no_trusted_proxy_a_public_peer_is_the_client_and_the_header_is_ignored() {
    let label = client_label(Some(ip(PUBLIC_PEER)), &headers(&["1.1.1.1"]), 0);
    assert_eq!(label.as_deref(), Some(PUBLIC_PEER));
}

/// Behind a load balancer that is not trusted for `X-Forwarded-For`, the TCP
/// peer is the balancer: every caller would look like one client.
#[test]
fn a_non_public_peer_hides_the_client() {
    for peer in [
        "10.0.0.1",
        "127.0.0.1",
        "172.16.4.2",
        "192.168.1.9",
        "100.64.0.3",
        "fd00::1",
    ] {
        assert_eq!(
            client_label(Some(ip(peer)), &headers(&["1.1.1.1"]), 0),
            None,
            "{peer}"
        );
        assert_eq!(
            client_label(Some(ip(peer)), &headers(&[]), 1),
            None,
            "{peer}"
        );
    }
}

/// Behind one trusted proxy the client is the right-most entry — the one the
/// proxy appended. Whatever a caller wrote to its left changes nothing.
#[test]
fn a_spoofed_leading_entry_does_not_change_the_client() {
    let honest = client_label(Some(ip("10.0.0.1")), &headers(&["203.0.113.7"]), 1);
    let spoofed = client_label(
        Some(ip("10.0.0.1")),
        &headers(&["1.2.3.4, 5.6.7.8", "203.0.113.7"]),
        1,
    );
    assert_eq!(honest.as_deref(), Some("203.0.113.7"));
    assert_eq!(spoofed, honest);
}

#[test]
fn an_unusable_header_falls_back_to_a_public_peer_and_no_address_is_unknown() {
    assert_eq!(
        client_label(Some(ip(PUBLIC_PEER)), &headers(&["not-an-ip"]), 1).as_deref(),
        Some(PUBLIC_PEER)
    );
    assert_eq!(
        client_label(Some(ip("10.0.0.1")), &headers(&["not-an-ip"]), 1),
        None
    );
    assert_eq!(client_label(None, &headers(&[]), 1), None);
    assert_eq!(client_label(None, &headers(&[]), 0), None);
}

#[test]
fn an_ipv6_client_is_counted_per_slash_64() {
    let a = client_label(None, &headers(&["2001:db8:1:2:aaaa::1"]), 1);
    let b = client_label(None, &headers(&["2001:db8:1:2:bbbb::9"]), 1);
    assert!(a.is_some());
    assert_eq!(a, b);
}

/// No identifiable client means no per-client bucket: the unit bucket alone
/// governs, and nobody shares a bucket labelled "unknown".
#[test]
fn an_unidentifiable_client_has_no_bucket_of_its_own() {
    let limiter = AnonymousLimiter::default();
    let now = Instant::now();
    let l = limits(4, 60, None);
    let served = (0..10)
        .filter(|_| limiter.check(UNIT, None, &l, Charge::TURN, now, T0).is_ok())
        .count();
    assert_eq!(served, 4, "the unit's whole burst, not a client's half");
    assert_eq!(limiter.client_buckets(), 0);
}
