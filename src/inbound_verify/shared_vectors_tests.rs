//! The inbound signature vectors are owned by greentic-messaging-providers
//! (`crates/provider-tests/tests/fixtures/inbound-auth-v1/`, commit
//! `26521200`) and copied here BYTE FOR BYTE by
//! `scripts/sync-inbound-auth-fixtures.sh`. These tests pin that the copy is
//! the providers' set, and that the Teams vector verifies on this host.

use std::collections::HashMap;

use base64::Engine;
use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use std::sync::Arc;

use super::bf_keys::{BfKey, BfKeyLookup};
use super::bot_framework::{BfKeys, BfOutcome, check};

const WHATSAPP: &str = include_str!("fixtures/inbound-auth-v1/whatsapp.json");
const WEBEX: &str = include_str!("fixtures/inbound-auth-v1/webex.json");
const TEAMS: &str = include_str!("fixtures/inbound-auth-v1/teams.json");
const CHECKSUMS: &str = include_str!("fixtures/inbound-auth-v1/CHECKSUMS.sha256");

/// `CHECKSUMS.sha256` in providers at `26521200`, verbatim. A change there
/// is copied with the sync script and this constant moves in the same commit.
const PROVIDERS_CHECKSUMS: &str = "\
a5a551da43da49b81f82b6a26752e4a7bfee3be4c0595b851e8d788fd909e4bb  whatsapp.json
55f21af6503fbfaee93d147587331373a1c5e45c42357b1ba657525e3f7b3350  webex.json
18044bf7abdfae15760abf52336f74758adfd81eeaebee1936d815182ef967a9  teams.json
";

fn sha256_hex(raw: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(raw.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn the_checksums_are_the_providers_checksums() {
    assert_eq!(CHECKSUMS, PROVIDERS_CHECKSUMS);
}

#[test]
fn every_vector_matches_the_providers_checksum() {
    for (name, raw) in [
        ("whatsapp.json", WHATSAPP),
        ("webex.json", WEBEX),
        ("teams.json", TEAMS),
    ] {
        let line = format!("{}  {name}", sha256_hex(raw));
        assert!(
            PROVIDERS_CHECKSUMS.lines().any(|l| l == line),
            "{name} is not the providers' copy ({line})"
        );
    }
}

#[derive(Deserialize)]
struct TeamsVector {
    app_id: String,
    now: u64,
    header_name: String,
    header: String,
    jwks: Jwks,
    body_base64: String,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    n: String,
    e: String,
    endorsements: Vec<String>,
}

struct VectorKeys(HashMap<String, BfKey>);

#[async_trait::async_trait]
impl BfKeys for VectorKeys {
    async fn key(&self, kid: &str) -> BfKeyLookup {
        match self.0.get(kid) {
            Some(key) => BfKeyLookup::Found(key.clone()),
            None => BfKeyLookup::UnknownKid,
        }
    }
}

fn teams() -> (TeamsVector, VectorKeys, Vec<u8>) {
    let v: TeamsVector = serde_json::from_str(TEAMS).expect("teams vector");
    let keys = v
        .jwks
        .keys
        .iter()
        .map(|k| {
            (
                k.kid.clone(),
                BfKey {
                    key: Arc::new(DecodingKey::from_rsa_components(&k.n, &k.e).expect("rsa")),
                    endorsements: k.endorsements.clone().into(),
                },
            )
        })
        .collect();
    let body = base64::engine::general_purpose::STANDARD
        .decode(&v.body_base64)
        .expect("base64 body");
    (v, VectorKeys(keys), body)
}

#[tokio::test]
async fn the_shared_teams_vector_verifies() {
    let (v, keys, body) = teams();
    let headers = vec![(v.header_name.clone(), v.header.clone())];
    let outcome = check(Some(&v.app_id), &headers, &body, Some(&keys), v.now).await;
    assert!(matches!(outcome, BfOutcome::Verified), "{outcome:?}");
}

#[tokio::test]
async fn the_shared_teams_vector_is_refused_for_another_bot_or_a_changed_body() {
    let (v, keys, body) = teams();
    let headers = vec![(v.header_name.clone(), v.header.clone())];
    let other_bot = check(
        Some("00000000-0000-4000-8000-000000000000"),
        &headers,
        &body,
        Some(&keys),
        v.now,
    )
    .await;
    assert!(matches!(other_bot, BfOutcome::Refused(_)), "{other_bot:?}");
    let moved = String::from_utf8(body).unwrap().replace(
        "smba.trafficmanager.net/amer/",
        "smba.trafficmanager.net/emea/",
    );
    let changed = check(
        Some(&v.app_id),
        &headers,
        moved.as_bytes(),
        Some(&keys),
        v.now,
    )
    .await;
    assert!(matches!(changed, BfOutcome::Refused(_)), "{changed:?}");
}
