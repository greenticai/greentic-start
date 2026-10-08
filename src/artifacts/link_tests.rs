use super::link::{
    DEFAULT_TTL_SECS, LINK_PREFIX, LinkKey, LinkPath, MAX_TTL_SECS, MIN_TTL_SECS, SKEW_SECS,
    Verdict, mint, ttl_from, verify,
};

const TOKEN: &str = "gtm_test_token";
const TENANT: &str = "acme";
const BUNDLE: &str = "b1";
const DEPLOYMENT: &str = "01J0000000000000000000000A";
const NOW: u64 = 1_800_000_000;
const TTL: u64 = 86_400;

fn artifact() -> String {
    format!("artifact://{}", "a".repeat(64))
}

fn key() -> LinkKey {
    LinkKey::derive(TOKEN, TENANT, BUNDLE, DEPLOYMENT)
}

fn minted() -> LinkPath {
    mint(&key(), DEPLOYMENT, &artifact(), NOW, TTL).expect("valid id mints")
}

fn is_valid(verdict: Verdict) -> bool {
    matches!(verdict, Verdict::Valid { .. })
}

/// Pins the derivation across refactors and releases: links already sent must
/// keep verifying after an upgrade. Expected MAC computed independently:
///
/// ```text
/// K=$(printf 'greentic/artifact-link/v1\x1facme\x1fb1\x1f01J0000000000000000000000A' \
///     | openssl dgst -sha256 -mac HMAC -macopt key:gtm_test_token -hex | awk '{print $NF}')
/// A=$(printf 'a%.0s' $(seq 64))
/// printf "v1\x1f01J0000000000000000000000A\x1f$A\x1f1800086400" \
///     | openssl dgst -sha256 -mac HMAC -macopt hexkey:$K -hex   # first 32 hex chars
/// ```
#[test]
fn golden_vector_is_stable() {
    let expected = format!(
        "/v1/artifacts/{DEPLOYMENT}/{}/1800086400/156579ac611915e88411f0fb25e8dde7",
        "a".repeat(64)
    );
    assert_eq!(minted().to_path(), expected);
}

#[test]
fn round_trip_verifies_with_the_same_id() {
    let path = minted().to_path();
    assert!(path.starts_with(LINK_PREFIX));
    let parsed = LinkPath::parse(&path).expect("own path parses");
    match verify(&key(), &parsed, NOW, TTL) {
        Verdict::Valid { artifact_id } => assert_eq!(artifact_id, artifact()),
        Verdict::Invalid => panic!("a fresh link must verify"),
    }
}

#[test]
fn mint_refuses_an_id_that_is_not_an_artifact_id() {
    for bad in [
        "artifact://00ff",
        "artifact://AAAA",
        "https://example.com/x",
        "",
        &format!("artifact://{}", "A".repeat(64)),
    ] {
        assert!(mint(&key(), DEPLOYMENT, bad, NOW, TTL).is_none(), "{bad}");
    }
}

fn flip_hex(c: char) -> char {
    if c == '0' { '1' } else { '0' }
}

fn flip_at(s: &str, i: usize) -> String {
    s.chars()
        .enumerate()
        .map(|(n, c)| if n == i { flip_hex(c) } else { c })
        .collect()
}

#[test]
fn a_changed_field_never_verifies() {
    let link = minted();
    let mut tampered = Vec::new();
    for i in [0, 31, 63] {
        let mut l = link.clone();
        l.artifact_hex = flip_at(&l.artifact_hex, i);
        tampered.push(l);
    }
    for i in [0, 15, 31] {
        let mut l = link.clone();
        l.mac_hex = flip_at(&l.mac_hex, i);
        tampered.push(l);
    }
    let mut l = link.clone();
    l.exp -= 1;
    tampered.push(l);
    let mut l = link.clone();
    l.deployment = "01J0000000000000000000000B".to_string();
    tampered.push(l);
    for l in tampered {
        // Every tampered link still has a valid shape: the MAC is what refuses it.
        let reparsed = LinkPath::parse(&l.to_path()).expect("shape stays valid");
        assert!(!is_valid(verify(&key(), &reparsed, NOW, TTL)), "{l:?}");
    }
}

#[test]
fn malformed_paths_do_not_parse() {
    let link = minted();
    let good = link.to_path();
    let d = DEPLOYMENT;
    let a = "a".repeat(64);
    let m = link.mac_hex.as_str();
    assert!(
        m.bytes().any(|b| b.is_ascii_alphabetic()),
        "the case test needs a letter"
    );
    let cases = vec![
        good.replace(m, &m.to_ascii_uppercase()),
        good.replace(d, &d.to_ascii_lowercase()),
        format!("/v1/artifacts/{}/{a}/1800086400/{m}", &d[..25]),
        format!("/v1/artifacts/{d}A/{a}/1800086400/{m}"),
        format!("/v1/artifacts/01J000000000000000000000IA/{a}/1800086400/{m}"),
        format!("/v1/artifacts/01J000000000000000000000LA/{a}/1800086400/{m}"),
        format!("/v1/artifacts/01J000000000000000000000OA/{a}/1800086400/{m}"),
        format!("/v1/artifacts/01J000000000000000000000UA/{a}/1800086400/{m}"),
        format!("/v1/artifacts/{d}/{a}/01800086400/{m}"),
        format!("/v1/artifacts/{d}/{a}/180008640000/{m}"),
        format!("/v1/artifacts/{d}/{a}/0/{m}"),
        format!("/v1/artifacts/{d}/{a}/1800086400/{m}/x"),
        format!("{good}/"),
        format!("/v1/artifacts/{d}%2F/{a}/1800086400/{m}"),
        format!("/v1/artifacts/{d}/{}%2F/1800086400/{m}", &a[..61]),
        format!("/v1/artifacts/{d}//1800086400/{m}"),
        format!("/v1/artifacts/{d}/{a}//{m}"),
        format!("/v1/artifacts/{d}/{}/1800086400/{m}", &a[..63]),
        format!("/v1/artifacts/{d}/{a}A/1800086400/{m}"),
        format!("/v1/artifacts/{d}/{a}/1800086400/{}", &m[..31]),
        format!("/v1/artifacts/{d}/{a}/+1800086400/{m}"),
        format!("/v1/Artifacts/{d}/{a}/1800086400/{m}"),
        format!("/v1/artifacts/{d}/{a}/1800086400"),
        String::new(),
        "/v1/artifacts/".to_string(),
    ];
    for case in cases {
        assert!(LinkPath::parse(&case).is_none(), "{case}");
    }
    assert!(LinkPath::parse(&good).is_some());
}

#[test]
fn expiry_has_a_bounded_skew() {
    let link = minted();
    assert!(is_valid(verify(&key(), &link, link.exp + SKEW_SECS, TTL)));
    assert!(!is_valid(verify(
        &key(),
        &link,
        link.exp + SKEW_SECS + 1,
        TTL
    )));
}

#[test]
fn lowering_the_ttl_revokes_longer_links_already_sent() {
    let link = minted();
    assert!(!is_valid(verify(&key(), &link, NOW, 3_600)));
    // Exactly at the bound (now + ttl_max + skew) it still verifies.
    assert!(is_valid(verify(&key(), &link, NOW, TTL - SKEW_SECS)));
    assert!(!is_valid(verify(&key(), &link, NOW, TTL - SKEW_SECS - 1)));
}

#[test]
fn a_key_for_another_unit_or_tenant_never_verifies() {
    let link = minted();
    let others = [
        LinkKey::derive("gtm_other_token", TENANT, BUNDLE, DEPLOYMENT),
        LinkKey::derive(TOKEN, "acme2", BUNDLE, DEPLOYMENT),
        LinkKey::derive(TOKEN, TENANT, "b2", DEPLOYMENT),
        LinkKey::derive(TOKEN, TENANT, BUNDLE, "01J0000000000000000000000B"),
        // Separator injection: moving a field boundary must change the key.
        LinkKey::derive(TOKEN, "acme\u{1f}b1", "", DEPLOYMENT),
    ];
    for other in others {
        assert!(!is_valid(verify(&other, &link, NOW, TTL)));
    }
}

#[test]
fn debug_reveals_nothing_about_the_key() {
    let printed = format!("{:?}", key());
    assert!(!printed.contains("d360c2c6"), "{printed}");
    assert!(!printed.to_ascii_lowercase().contains("d360"), "{printed}");
    assert!(!printed.contains(TOKEN));
    assert!(printed.contains("redacted"));
}

#[test]
fn ttl_is_clamped_and_defaults_when_unparsable() {
    assert_eq!(ttl_from(None), DEFAULT_TTL_SECS);
    assert_eq!(DEFAULT_TTL_SECS, 86_400);
    assert_eq!(ttl_from(Some("")), DEFAULT_TTL_SECS);
    assert_eq!(ttl_from(Some("abc")), DEFAULT_TTL_SECS);
    assert_eq!(ttl_from(Some("-5")), DEFAULT_TTL_SECS);
    assert_eq!(ttl_from(Some("1")), MIN_TTL_SECS);
    assert_eq!(ttl_from(Some("99999999")), MAX_TTL_SECS);
    assert_eq!(ttl_from(Some(" 3600 ")), 3_600);
    assert_eq!((MIN_TTL_SECS, MAX_TTL_SECS), (300, 604_800));
}

#[test]
fn key_normalisation_matches_hmac_for_short_and_long_tokens() {
    use hmac::{Hmac, KeyInit, Mac};
    for token in [
        "",
        "gtm_x",
        &"t".repeat(64),
        &"t".repeat(65),
        &"t".repeat(200),
    ] {
        let mut reference =
            <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(token.as_bytes()).expect("any length");
        reference.update(b"greentic/artifact-link/v1\x1facme\x1fb1\x1f01J0000000000000000000000A");
        let reference_key = reference.finalize().into_bytes();
        let ours = LinkKey::derive(token, TENANT, BUNDLE, DEPLOYMENT);
        assert_eq!(
            ours.expose_for_test(),
            reference_key.as_slice(),
            "len {}",
            token.len()
        );
    }
}

/// Pinned OFF until the WebChat reconnect-token hardening (gap G2) ships: a
/// hijacked WebChat conversation would otherwise expose every link it holds.
/// Flipping this is a release decision, not a refactor.
#[test]
#[allow(clippy::assertions_on_constants)] // the constant IS what is pinned
fn outbound_links_are_off_in_code_until_g2_ships() {
    assert!(!super::link::OUTBOUND_LINKS_ENABLED);
    assert_eq!(super::link::LINKS_ENV, "GREENTIC_ARTIFACT_LINKS");
}

#[test]
fn the_env_can_only_force_links_on() {
    use super::link::links_enabled_with;
    // Code default OFF: only an explicit "on" value enables.
    for on in ["1", "true", "TRUE", "yes", "On", " on "] {
        assert!(links_enabled_with(false, Some(on)), "{on}");
    }
    for not_on in [
        None,
        Some(""),
        Some("0"),
        Some("off"),
        Some("false"),
        Some("enable"),
    ] {
        assert!(!links_enabled_with(false, not_on), "{not_on:?}");
    }
    // Code default ON: no value turns it off (there is no off-override).
    for any in [None, Some("off"), Some("0"), Some("false"), Some("no")] {
        assert!(links_enabled_with(true, any), "{any:?}");
    }
}

#[test]
fn links_enabled_from_applies_the_code_default() {
    use super::link::{OUTBOUND_LINKS_ENABLED, links_enabled_from};
    assert_eq!(links_enabled_from(None), OUTBOUND_LINKS_ENABLED);
    assert!(links_enabled_from(Some("on")));
}
