use std::net::{IpAddr, Ipv4Addr};

use hyper::HeaderMap;

use super::client_key::*;

fn xff(lines: &[&str]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for line in lines {
        headers.append("x-forwarded-for", line.parse().unwrap());
    }
    headers
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

#[test]
fn explicit_value_wins_including_zero() {
    assert_eq!(resolve_hops(Some("0"), true), (0, HopsSource::Explicit));
    assert_eq!(resolve_hops(Some("2"), false), (2, HopsSource::Explicit));
    assert_eq!(resolve_hops(Some(" 3 "), true), (3, HopsSource::Explicit));
}

/// An operator who tried to set it gets the safe value, never the platform
/// default: a typo must not quietly trust a header.
#[test]
fn unparsable_explicit_is_zero_not_the_platform_default() {
    for bad in ["x", "-1", "1.5", "one"] {
        assert_eq!(
            resolve_hops(Some(bad), true),
            (0, HopsSource::Unparsable),
            "{bad}"
        );
    }
}

/// An empty value is how a deploy template renders "not set".
#[test]
fn an_empty_value_is_unset() {
    assert_eq!(resolve_hops(Some(""), true), (1, HopsSource::CloudRun));
    assert_eq!(resolve_hops(Some("  "), false), (0, HopsSource::Default));
}

#[test]
fn cloud_run_without_explicit_is_one() {
    assert_eq!(resolve_hops(None, true), (1, HopsSource::CloudRun));
}

#[test]
fn elsewhere_without_explicit_is_zero() {
    assert_eq!(resolve_hops(None, false), (0, HopsSource::Default));
}

/// Cloud Run's front end appends the address it received the connection
/// from, so with one trusted hop the right-most entry is the client and
/// anything the client wrote stays to its left.
#[test]
fn a_spoofed_header_on_cloud_run_cannot_change_the_key() {
    let (hops, _) = resolve_hops(None, true);
    let private_peer = Some(v4(169, 254, 1, 1));
    let client = v4(198, 51, 100, 7);
    for spoof in ["1.2.3.4", "1.2.3.4, 5.6.7.8", "garbage"] {
        let headers = xff(&[&format!("{spoof}, {client}")]);
        assert_eq!(
            client_key(private_peer, &headers, hops),
            Some(ClientKey::of(client)),
            "{spoof}"
        );
    }
    // A lone value is taken only because it is the right-most: the front
    // end always appends, so a header the client wrote alone never arrives
    // (the assumption S0 step 3 measures, O-1).
    assert_eq!(
        client_key(private_peer, &xff(&["1.2.3.4"]), hops),
        Some(ClientKey::of(v4(1, 2, 3, 4)))
    );
}

#[test]
fn the_effective_line_names_the_count_and_its_source() {
    assert!(hops_line(1, HopsSource::CloudRun).contains("1 (cloud_run)"));
    assert!(hops_line(0, HopsSource::Default).contains("0 (default)"));
    assert!(hops_line(2, HopsSource::Explicit).contains("2 (explicit)"));
    let unparsable = hops_line(0, HopsSource::Unparsable);
    assert!(unparsable.contains("0 (unparsable)"), "{unparsable}");
    assert!(
        unparsable.contains("GREENTIC_TRUSTED_PROXY_HOPS"),
        "{unparsable}"
    );
}
