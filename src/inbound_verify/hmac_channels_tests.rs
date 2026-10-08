use base64::Engine;
use serde::Deserialize;

use super::RefusalCode;
use super::hmac_channels::{HmacOutcome, check_webex, check_whatsapp};
use super::secrets::ChannelSecret;

const WHATSAPP_FIXTURE: &str = include_str!("fixtures/inbound-auth-v1/whatsapp.json");
const WEBEX_FIXTURE: &str = include_str!("fixtures/inbound-auth-v1/webex.json");
const CHECKSUMS: &str = include_str!("fixtures/inbound-auth-v1/CHECKSUMS.sha256");

/// A shared signature vector (`fixtures/inbound-auth-v1/`). The same files
/// are meant to live in greentic-messaging-providers, recomputed there with
/// the provider's own HMAC, so both sides prove the same bytes.
#[derive(Deserialize)]
struct Vector {
    secret: String,
    body_base64: String,
    header_name: String,
    header: String,
}

impl Vector {
    fn load(raw: &str) -> Self {
        serde_json::from_str(raw).expect("fixture")
    }
    fn body(&self) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.body_base64)
            .expect("base64 body")
    }
    fn secret(&self) -> ChannelSecret {
        ChannelSecret::new(self.secret.clone())
    }
    fn headers(&self) -> Vec<(String, String)> {
        vec![(self.header_name.clone(), self.header.clone())]
    }
}

type Check = fn(Option<&ChannelSecret>, &[(String, String)], &[u8]) -> HmacOutcome;

fn schemes() -> [(&'static str, Vector, Check); 2] {
    [
        ("whatsapp", Vector::load(WHATSAPP_FIXTURE), check_whatsapp),
        ("webex", Vector::load(WEBEX_FIXTURE), check_webex),
    ]
}

fn is_verified(outcome: HmacOutcome) -> bool {
    matches!(outcome, HmacOutcome::Verified)
}

fn refused(outcome: HmacOutcome) -> Option<RefusalCode> {
    match outcome {
        HmacOutcome::Refused(code) => Some(code),
        _ => None,
    }
}

#[test]
fn the_fixtures_match_their_checksums() {
    use sha2::{Digest, Sha256};
    for (name, raw) in [
        ("whatsapp.json", WHATSAPP_FIXTURE),
        ("webex.json", WEBEX_FIXTURE),
    ] {
        let digest = Sha256::digest(raw.as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            CHECKSUMS
                .lines()
                .any(|line| line == format!("{hex}  {name}")),
            "{name} differs from CHECKSUMS.sha256 ({hex})"
        );
    }
}

#[test]
fn the_shared_fixture_vector_verifies() {
    for (scheme, v, check) in schemes() {
        assert!(
            is_verified(check(Some(&v.secret()), &v.headers(), &v.body())),
            "{scheme}"
        );
    }
}

#[test]
fn one_changed_body_byte_is_refused() {
    for (scheme, v, check) in schemes() {
        let mut body = v.body();
        let last = body.len() - 2;
        body[last] ^= 0x01;
        assert_eq!(
            refused(check(Some(&v.secret()), &v.headers(), &body)),
            Some(RefusalCode::BadSignature),
            "{scheme}"
        );
    }
}

#[test]
fn a_reserialised_body_is_refused() {
    // Proves the RAW bytes are verified: the same JSON, re-serialised with
    // pretty whitespace, is a different message as far as the MAC goes.
    for (scheme, v, check) in schemes() {
        let parsed: serde_json::Value = serde_json::from_slice(&v.body()).expect("json");
        let reserialised = serde_json::to_vec_pretty(&parsed).expect("json");
        assert_ne!(reserialised, v.body());
        assert_eq!(
            refused(check(Some(&v.secret()), &v.headers(), &reserialised)),
            Some(RefusalCode::BadSignature),
            "{scheme}"
        );
    }
}

#[test]
fn a_missing_header_is_refused_when_configured() {
    for (scheme, v, check) in schemes() {
        assert_eq!(
            refused(check(Some(&v.secret()), &[], &v.body())),
            Some(RefusalCode::MissingSignature),
            "{scheme}"
        );
    }
}

#[test]
fn no_secret_is_not_configured_even_with_a_valid_looking_header() {
    for (scheme, v, check) in schemes() {
        assert!(
            matches!(
                check(None, &v.headers(), &v.body()),
                HmacOutcome::NotConfigured
            ),
            "{scheme}"
        );
    }
}

#[test]
fn a_wrong_secret_is_refused() {
    for (scheme, v, check) in schemes() {
        let wrong = ChannelSecret::new("not-the-secret");
        assert_eq!(
            refused(check(Some(&wrong), &v.headers(), &v.body())),
            Some(RefusalCode::BadSignature),
            "{scheme}"
        );
    }
}

#[test]
fn an_uppercase_hex_digest_verifies_and_the_header_name_is_case_insensitive() {
    for (scheme, v, check) in schemes() {
        let header = match v.header.strip_prefix("sha256=") {
            Some(hex) => format!("sha256={}", hex.to_ascii_uppercase()),
            None => v.header.to_ascii_uppercase(),
        };
        let headers = vec![(v.header_name.to_ascii_uppercase(), header)];
        assert!(
            is_verified(check(Some(&v.secret()), &headers, &v.body())),
            "{scheme}"
        );
    }
}

#[test]
fn a_truncated_or_odd_length_digest_is_refused() {
    for (scheme, v, check) in schemes() {
        for cut in [1, 2, v.header.len() / 2] {
            let header = v.header[..v.header.len() - cut].to_string();
            let headers = vec![(v.header_name.clone(), header)];
            assert_eq!(
                refused(check(Some(&v.secret()), &headers, &v.body())),
                Some(RefusalCode::BadSignature),
                "{scheme} cut {cut}"
            );
        }
    }
}

#[test]
fn the_wrong_algorithm_prefix_is_refused() {
    let v = Vector::load(WHATSAPP_FIXTURE);
    let hex = v.header.trim_start_matches("sha256=");
    for header in [format!("sha1={hex}"), hex.to_string()] {
        let headers = vec![(v.header_name.clone(), header.clone())];
        assert_eq!(
            refused(check_whatsapp(Some(&v.secret()), &headers, &v.body())),
            Some(RefusalCode::BadSignature),
            "{header}"
        );
    }
    // The legacy SHA-1 `X-Hub-Signature` header proves nothing on its own.
    let legacy = vec![("x-hub-signature".to_string(), format!("sha1={hex}"))];
    assert_eq!(
        refused(check_whatsapp(Some(&v.secret()), &legacy, &v.body())),
        Some(RefusalCode::MissingSignature)
    );
}

#[test]
fn the_secret_never_appears_in_debug_or_error_text() {
    for (scheme, v, check) in schemes() {
        for outcome in [
            check(Some(&v.secret()), &v.headers(), &v.body()),
            check(Some(&v.secret()), &[], &v.body()),
            check(Some(&v.secret()), &v.headers(), b"tampered"),
        ] {
            let printed = format!("{outcome:?}");
            assert!(!printed.contains(&v.secret), "{scheme}: {printed}");
        }
    }
}

#[test]
fn x_webex_signature_is_accepted_when_spark_is_absent() {
    let v = Vector::load(WEBEX_FIXTURE);
    let headers = vec![("x-webex-signature".to_string(), v.header.clone())];
    assert!(is_verified(check_webex(
        Some(&v.secret()),
        &headers,
        &v.body()
    )));
}

#[test]
fn both_webex_headers_present_spark_wins() {
    // Mirrors the provider's own order (`x-spark-signature` first).
    let v = Vector::load(WEBEX_FIXTURE);
    let good_spark = vec![
        ("x-webex-signature".to_string(), "00".repeat(20)),
        ("x-spark-signature".to_string(), v.header.clone()),
    ];
    assert!(is_verified(check_webex(
        Some(&v.secret()),
        &good_spark,
        &v.body()
    )));
    let bad_spark = vec![
        ("x-spark-signature".to_string(), "00".repeat(20)),
        ("x-webex-signature".to_string(), v.header.clone()),
    ];
    assert_eq!(
        refused(check_webex(Some(&v.secret()), &bad_spark, &v.body())),
        Some(RefusalCode::BadSignature)
    );
}
