//! The acceptance rules for a forwarded caller block, one rule per test.

use serde_json::{Value, json};

use super::*;
use crate::interop::config::Credential;

fn config(flags: &[(&str, bool)]) -> InteropConfig {
    InteropConfig {
        a2a: true,
        credentials: flags
            .iter()
            .map(|(id, flag)| Credential {
                id: (*id).into(),
                sha256: [0; 32],
                expires_at_ms: None,
                forwards_caller: *flag,
            })
            .collect(),
        ..InteropConfig::default()
    }
}

fn valid() -> Value {
    json!({
        "sub": "u-1",
        "iss": "https://idp.example",
        "teams": ["sales", "hr"],
        "groups": ["g1"],
        "role": "member",
        "user_verified": true,
    })
}

fn accept_block(cfg: &InteropConfig, caller: &Caller, block: Value) -> (Option<Value>, bool) {
    let mut metadata = Some(json!({ "caller": block, "other": 1 }));
    let accepted = accept(cfg, caller, &mut metadata);
    let left_in_request = metadata
        .as_ref()
        .and_then(|m| m.get(METADATA_KEY))
        .is_some();
    (accepted, left_in_request)
}

#[test]
fn a_flagged_credential_with_a_valid_block_is_accepted_with_via() {
    let cfg = config(&[("router1", true)]);
    let (accepted, left) = accept_block(&cfg, &Caller::Bearer("router1".into()), valid());
    let block = accepted.expect("accepted");
    assert!(!left, "the raw key must be removed from the request");
    assert_eq!(block["sub"], "u-1");
    assert_eq!(block["teams"], json!(["sales", "hr"]));
    assert_eq!(block["groups"], json!(["g1"]));
    assert_eq!(block["role"], "member");
    assert_eq!(block["iss"], "https://idp.example");
    assert_eq!(block["user_verified"], true);
    assert_eq!(block["via"], "router:router1");
}

#[test]
fn optional_fields_may_be_absent_and_lists_default_to_empty() {
    let cfg = config(&[("r", true)]);
    let (accepted, _) = accept_block(
        &cfg,
        &Caller::Bearer("r".into()),
        json!({"sub": "u", "user_verified": true}),
    );
    let block = accepted.expect("accepted");
    assert_eq!(block["teams"], json!([]));
    assert_eq!(block["groups"], json!([]));
    assert!(block.get("role").is_none() && block.get("iss").is_none());
}

#[test]
fn an_unflagged_credential_is_dropped_and_the_key_is_still_removed() {
    let cfg = config(&[("plain", false)]);
    let (accepted, left) = accept_block(&cfg, &Caller::Bearer("plain".into()), valid());
    assert!(accepted.is_none());
    assert!(!left);
}

#[test]
fn only_a_staged_bearer_can_forward() {
    let cfg = config(&[("r", true)]);
    for caller in [
        Caller::Oauth("r".into()),
        Caller::anonymous(Some("c")),
        Caller::Bearer("unknown".into()),
    ] {
        let (accepted, left) = accept_block(&cfg, &caller, valid());
        assert!(accepted.is_none(), "{caller:?}");
        assert!(!left);
    }
}

#[test]
fn a_rotated_pair_with_a_mixed_flag_reads_as_unflagged() {
    let cfg = config(&[("r", true), ("r", false)]);
    let (accepted, _) = accept_block(&cfg, &Caller::Bearer("r".into()), valid());
    assert!(accepted.is_none());
}

#[test]
fn invalid_blocks_are_dropped_whole() {
    let cfg = config(&[("r", true)]);
    let caller = Caller::Bearer("r".into());
    let long = "a".repeat(MAX_STRING_CHARS + 1);
    let many: Vec<String> = (0..=MAX_LIST_ENTRIES).map(|i| format!("t{i}")).collect();
    let cases: Vec<(&str, Value)> = vec![
        ("unverified", json!({"sub": "u", "user_verified": false})),
        ("no flag", json!({"sub": "u"})),
        ("string flag", json!({"sub": "u", "user_verified": "true"})),
        ("empty sub", json!({"sub": "  ", "user_verified": true})),
        ("no sub", json!({"user_verified": true})),
        (
            "foreign field",
            json!({"sub": "u", "user_verified": true, "admin": true}),
        ),
        (
            "team key",
            json!({"sub": "u", "user_verified": true, "team": "x"}),
        ),
        ("long sub", json!({"sub": long, "user_verified": true})),
        (
            "too many teams",
            json!({"sub": "u", "user_verified": true, "teams": many}),
        ),
        (
            "too many groups",
            json!({"sub": "u", "user_verified": true, "groups": many}),
        ),
        (
            "non-string team",
            json!({"sub": "u", "user_verified": true, "teams": [1]}),
        ),
        ("control char", json!({"sub": "u\n", "user_verified": true})),
        (
            "oversized json",
            json!({"sub": "u", "user_verified": true, "groups": vec!["g".repeat(200); 30]}),
        ),
        ("not an object", json!("u")),
    ];
    for (name, block) in cases {
        let (accepted, left) = accept_block(&config_clone(&cfg), &caller, block);
        assert!(accepted.is_none(), "{name}");
        assert!(!left, "{name}: raw key left in the request");
    }
}

fn config_clone(cfg: &InteropConfig) -> InteropConfig {
    config(
        &cfg.credentials
            .iter()
            .map(|c| (c.id.as_str(), c.forwards_caller))
            .collect::<Vec<_>>(),
    )
}

#[test]
fn limits_are_inclusive_at_the_boundary() {
    let cfg = config(&[("r", true)]);
    let teams: Vec<String> = (0..MAX_LIST_ENTRIES).map(|i| format!("t{i}")).collect();
    let (accepted, _) = accept_block(
        &cfg,
        &Caller::Bearer("r".into()),
        json!({"sub": "a".repeat(MAX_STRING_CHARS), "user_verified": true, "teams": teams}),
    );
    assert!(accepted.is_some());
}

#[test]
fn no_metadata_or_no_caller_key_is_a_quiet_none() {
    let cfg = config(&[("r", true)]);
    let caller = Caller::Bearer("r".into());
    assert!(accept(&cfg, &caller, &mut None).is_none());
    assert!(accept(&cfg, &caller, &mut Some(json!({"k": 1}))).is_none());
}
