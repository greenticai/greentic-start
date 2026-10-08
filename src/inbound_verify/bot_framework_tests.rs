use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
use serde_json::{Value, json};

use super::RefusalCode;
use super::bf_keys::{BF_ISSUER, BfKey, BfKeyLookup};
use super::bot_framework::{BfKeys, BfOutcome, MAX_AUTH_HEADER_BYTES, check, configured_app_id};
use crate::interop::mcp::testkit::{TEST_JWKS_E, TEST_JWKS_N, TEST_PRIVATE_KEY_PEM};

/// A throw-away key generated for this test suite only, never used for
/// anything else: a valid RS256 signature from a key that is NOT in the set.
const UNRELATED_KEY_PEM: &str = include_str!("fixtures/bf/unrelated_test_key.pem");

const APP_ID: &str = "9f6b3c2e-1d4a-4b7f-8e2a-5c1d0e9f7a3b";
const SERVICE_URL: &str = "https://smba.trafficmanager.net/emea/";
const KID: &str = "bf-test-key";
const NOW: u64 = 1_800_000_000;

/// Injected key set: `KID` endorsed for `endorsements`, counting lookups.
struct StubKeys {
    keys: HashMap<String, BfKey>,
    unavailable: bool,
    calls: AtomicUsize,
}

impl StubKeys {
    fn with(endorsements: &[&str]) -> Self {
        let key = BfKey {
            key: Arc::new(DecodingKey::from_rsa_components(TEST_JWKS_N, TEST_JWKS_E).expect("key")),
            endorsements: endorsements
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .into(),
        };
        Self {
            keys: HashMap::from([(KID.to_string(), key)]),
            unavailable: false,
            calls: AtomicUsize::new(0),
        }
    }
    fn teams() -> Self {
        Self::with(&["msteams"])
    }
    fn unavailable() -> Self {
        Self {
            unavailable: true,
            ..Self::teams()
        }
    }
}

#[async_trait::async_trait]
impl BfKeys for StubKeys {
    async fn key(&self, kid: &str) -> BfKeyLookup {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.unavailable {
            return BfKeyLookup::Unavailable;
        }
        match self.keys.get(kid) {
            Some(key) => BfKeyLookup::Found(key.clone()),
            None => BfKeyLookup::UnknownKid,
        }
    }
}

fn claims() -> Value {
    json!({
        "iss": BF_ISSUER,
        "aud": APP_ID,
        "exp": NOW + 3600,
        "nbf": NOW - 60,
        "serviceurl": SERVICE_URL,
    })
}

fn sign_with(pem: &str, kid: &str, claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    jsonwebtoken::encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(pem.as_bytes()).expect("test key"),
    )
    .expect("token")
}

fn token(claims: &Value) -> String {
    sign_with(TEST_PRIVATE_KEY_PEM, KID, claims)
}

fn activity() -> Vec<u8> {
    json!({
        "type": "message",
        "channelId": "msteams",
        "serviceUrl": SERVICE_URL,
        "text": "hello",
    })
    .to_string()
    .into_bytes()
}

fn auth(token: &str) -> Vec<(String, String)> {
    vec![("authorization".to_string(), format!("Bearer {token}"))]
}

async fn run(token: &str, body: &[u8], keys: &StubKeys) -> BfOutcome {
    check(Some(APP_ID), &auth(token), body, Some(keys), NOW).await
}

fn refused(outcome: &BfOutcome) -> Option<RefusalCode> {
    match outcome {
        BfOutcome::Refused(code) => Some(*code),
        _ => None,
    }
}

fn b64(value: &Value) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
}

#[tokio::test]
async fn a_valid_token_for_this_bot_and_channel_is_verified() {
    let keys = StubKeys::teams();
    assert!(matches!(
        run(&token(&claims()), &activity(), &keys).await,
        BfOutcome::Verified
    ));
}

#[tokio::test]
async fn alg_none_is_refused_before_any_key_lookup() {
    let keys = StubKeys::teams();
    let unsigned = format!(
        "{}.{}.",
        b64(&json!({"alg": "none", "typ": "JWT", "kid": KID})),
        b64(&claims())
    );
    let outcome = run(&unsigned, &activity(), &keys).await;
    assert_eq!(refused(&outcome), Some(RefusalCode::BadToken));
    assert_eq!(keys.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn hs256_signed_with_the_public_key_bytes_is_refused() {
    // Key confusion: an attacker who knows the RSA public key signs HS256
    // with it as the HMAC secret.
    let keys = StubKeys::teams();
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(KID.to_string());
    let forged = jsonwebtoken::encode(
        &header,
        &claims(),
        &EncodingKey::from_secret(TEST_JWKS_N.as_bytes()),
    )
    .expect("token");
    let outcome = run(&forged, &activity(), &keys).await;
    assert_eq!(refused(&outcome), Some(RefusalCode::BadToken));
    assert_eq!(keys.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn other_algorithm_families_are_refused() {
    for alg in ["RS512", "ES256", "PS256"] {
        let forged = format!(
            "{}.{}.c2ln",
            b64(&json!({"alg": alg, "kid": KID})),
            b64(&claims())
        );
        let outcome = run(&forged, &activity(), &StubKeys::teams()).await;
        assert_eq!(refused(&outcome), Some(RefusalCode::BadToken), "{alg}");
    }
}

#[tokio::test]
async fn a_valid_signature_from_another_key_reusing_a_known_kid_is_refused() {
    let forged = sign_with(UNRELATED_KEY_PEM, KID, &claims());
    let outcome = run(&forged, &activity(), &StubKeys::teams()).await;
    assert_eq!(refused(&outcome), Some(RefusalCode::TokenClaims));
}

#[tokio::test]
async fn an_unknown_kid_is_refused() {
    let token = sign_with(TEST_PRIVATE_KEY_PEM, "rotated-out", &claims());
    let outcome = run(&token, &activity(), &StubKeys::teams()).await;
    assert_eq!(refused(&outcome), Some(RefusalCode::BadToken));
}

#[tokio::test]
async fn a_token_for_another_bot_is_refused() {
    let mut other = claims();
    other["aud"] = json!("00000000-0000-0000-0000-000000000000");
    let outcome = run(&token(&other), &activity(), &StubKeys::teams()).await;
    assert_eq!(refused(&outcome), Some(RefusalCode::TokenClaims));
}

/// `jsonwebtoken` accepts an `aud` ARRAY when it contains our app id (any
/// intersection). Recorded rather than changed: the token is still signed by
/// Microsoft for this bot.
#[tokio::test]
async fn an_audience_array_containing_this_bot_is_accepted() {
    let mut both = claims();
    both["aud"] = json!([APP_ID, "00000000-0000-0000-0000-000000000000"]);
    assert!(matches!(
        run(&token(&both), &activity(), &StubKeys::teams()).await,
        BfOutcome::Verified
    ));
}

#[tokio::test]
async fn the_emulator_issuer_is_refused() {
    let mut emulator = claims();
    emulator["iss"] = json!("https://sts.windows.net/f8cdef31-a31e-4b4a-93e4-5f571e91255a/");
    let outcome = run(&token(&emulator), &activity(), &StubKeys::teams()).await;
    assert_eq!(refused(&outcome), Some(RefusalCode::TokenClaims));
}

#[tokio::test]
async fn expiry_is_checked_with_five_minutes_of_leeway() {
    let mut expired = claims();
    expired["exp"] = json!(NOW - 301);
    let outcome = run(&token(&expired), &activity(), &StubKeys::teams()).await;
    assert_eq!(refused(&outcome), Some(RefusalCode::TokenClaims));

    let mut recent = claims();
    recent["exp"] = json!(NOW - 299);
    assert!(matches!(
        run(&token(&recent), &activity(), &StubKeys::teams()).await,
        BfOutcome::Verified
    ));
}

#[tokio::test]
async fn a_token_not_yet_valid_beyond_the_leeway_is_refused() {
    let mut future = claims();
    future["nbf"] = json!(NOW + 301);
    let outcome = run(&token(&future), &activity(), &StubKeys::teams()).await;
    assert_eq!(refused(&outcome), Some(RefusalCode::TokenClaims));

    let mut soon = claims();
    soon["nbf"] = json!(NOW + 299);
    assert!(matches!(
        run(&token(&soon), &activity(), &StubKeys::teams()).await,
        BfOutcome::Verified
    ));
}

#[tokio::test]
async fn a_token_without_exp_is_refused() {
    let mut no_exp = claims();
    no_exp.as_object_mut().expect("object").remove("exp");
    let outcome = run(&token(&no_exp), &activity(), &StubKeys::teams()).await;
    assert_eq!(refused(&outcome), Some(RefusalCode::TokenClaims));
}

#[tokio::test]
async fn a_service_url_other_than_the_activitys_is_refused() {
    let mut elsewhere = claims();
    elsewhere["serviceurl"] = json!("https://attacker.example/");
    let outcome = run(&token(&elsewhere), &activity(), &StubKeys::teams()).await;
    assert_eq!(refused(&outcome), Some(RefusalCode::TokenClaims));

    let mut missing = claims();
    missing
        .as_object_mut()
        .expect("object")
        .remove("serviceurl");
    let outcome = run(&token(&missing), &activity(), &StubKeys::teams()).await;
    assert_eq!(refused(&outcome), Some(RefusalCode::TokenClaims));
}

#[tokio::test]
async fn one_trailing_slash_and_the_camel_case_claim_are_tolerated() {
    let mut camel = claims();
    let object = camel.as_object_mut().expect("object");
    object.remove("serviceurl");
    object.insert(
        "serviceUrl".into(),
        json!(SERVICE_URL.trim_end_matches('/')),
    );
    assert!(matches!(
        run(&token(&camel), &activity(), &StubKeys::teams()).await,
        BfOutcome::Verified
    ));
}

#[tokio::test]
async fn a_channel_the_key_is_not_endorsed_for_is_forbidden() {
    let outcome = run(&token(&claims()), &activity(), &StubKeys::with(&["skype"])).await;
    assert_eq!(refused(&outcome), Some(RefusalCode::Endorsement));
    let mut body: Value = serde_json::from_slice(&activity()).expect("json");
    body.as_object_mut().expect("object").remove("channelId");
    let outcome = run(
        &token(&claims()),
        &serde_json::to_vec(&body).expect("json"),
        &StubKeys::teams(),
    )
    .await;
    assert_eq!(refused(&outcome), Some(RefusalCode::Endorsement));
}

#[tokio::test]
async fn a_body_that_is_not_json_after_a_valid_token_is_refused() {
    let outcome = run(&token(&claims()), b"not json", &StubKeys::teams()).await;
    assert_eq!(refused(&outcome), Some(RefusalCode::TokenClaims));
}

#[tokio::test]
async fn a_missing_empty_foreign_or_oversized_authorization_is_refused_without_decoding() {
    let keys = StubKeys::teams();
    let oversized = format!("Bearer {}", "a".repeat(MAX_AUTH_HEADER_BYTES + 1));
    for headers in [
        vec![],
        vec![("authorization".to_string(), "Bearer ".to_string())],
        vec![(
            "authorization".to_string(),
            format!("Basic {}", token(&claims())),
        )],
        vec![("authorization".to_string(), oversized)],
    ] {
        let outcome = check(Some(APP_ID), &headers, &activity(), Some(&keys), NOW).await;
        assert_eq!(refused(&outcome), Some(RefusalCode::MissingToken));
    }
    assert_eq!(keys.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn no_app_id_is_not_configured_and_fetches_no_key() {
    let keys = StubKeys::teams();
    let outcome = check(
        None,
        &auth(&token(&claims())),
        &activity(),
        Some(&keys),
        NOW,
    )
    .await;
    assert!(matches!(outcome, BfOutcome::NotConfigured));
    assert_eq!(keys.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn an_unreadable_key_set_is_unavailable_not_refused() {
    let outcome = run(&token(&claims()), &activity(), &StubKeys::unavailable()).await;
    assert!(matches!(outcome, BfOutcome::Unavailable));
    let outcome = check(
        Some(APP_ID),
        &auth(&token(&claims())),
        &activity(),
        None,
        NOW,
    )
    .await;
    assert!(matches!(outcome, BfOutcome::Unavailable));
}

#[test]
fn the_app_id_comes_from_the_wizards_key_then_the_fallback() {
    let config = |pairs: &[(&str, Value)]| -> BTreeMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    };
    assert_eq!(configured_app_id(None), None);
    assert_eq!(
        configured_app_id(Some(&config(&[("ms_bot_app_id", json!(" id-1 "))]))),
        Some("id-1".into())
    );
    assert_eq!(
        configured_app_id(Some(&config(&[
            ("ms_bot_app_id", json!("  ")),
            ("bot_app_id", json!("id-2"))
        ]))),
        Some("id-2".into())
    );
    assert_eq!(
        configured_app_id(Some(&config(&[("ms_bot_app_id", json!(42))]))),
        None
    );
}

#[tokio::test]
async fn no_token_appears_in_the_outcome_debug() {
    let token = token(&claims());
    for outcome in [
        run(&token, &activity(), &StubKeys::teams()).await,
        run(&token, &activity(), &StubKeys::with(&["skype"])).await,
        run(&token, b"x", &StubKeys::teams()).await,
    ] {
        let printed = format!("{outcome:?}");
        assert!(!printed.contains(&token[..20]), "{printed}");
    }
}
