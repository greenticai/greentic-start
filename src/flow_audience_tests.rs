use super::*;
use serde_json::json;

fn envelope(extensions: Value, metadata: Value) -> ChannelMessageEnvelope {
    serde_json::from_value(json!({
        "id": "m1",
        "tenant": {"env": "dev", "tenant": "acme", "tenant_id": "acme", "attempt": 0},
        "channel": "webchat",
        "session_id": "s1",
        "text": "hello",
        "metadata": metadata,
        "extensions": extensions,
    }))
    .expect("envelope")
}

fn meta(audience: &[&str]) -> FlowMeta {
    FlowMeta {
        audience: audience.iter().map(|s| s.to_string()).collect(),
        example_requests: Vec::new(),
    }
}

#[test]
fn parse_reads_audience_and_ignores_unknown_fields() {
    let parsed = FlowMeta::parse(
        br#"{"version":1,"audience":[" Sales ","support",""],"example_requests":["a"],"future":1}"#,
    )
    .expect("parse");
    assert_eq!(parsed.audience, vec!["sales", "support"]);
    assert_eq!(parsed.example_requests, vec!["a"]);
}

#[test]
fn parse_refuses_unknown_version_and_garbage() {
    assert!(FlowMeta::parse(br#"{"version":2,"audience":["a"]}"#).is_err());
    assert!(FlowMeta::parse(br#"{"audience":["a"]}"#).is_err());
    assert!(FlowMeta::parse(b"nope").is_err());
}

fn teams(slugs: &[&str]) -> Vec<String> {
    slugs.iter().map(|s| s.to_string()).collect()
}

fn verified(caller: Value) -> ChannelMessageEnvelope {
    let mut block = json!({"user_verified": true, "sub": "u"});
    if let (Some(dst), Some(src)) = (block.as_object_mut(), caller.as_object()) {
        dst.extend(src.clone());
    }
    envelope(json!({"caller": block}), json!({}))
}

#[test]
fn empty_audience_never_restricts() {
    let m = meta(&[]);
    assert_eq!(decide(Some(&m), &teams(&["sales"])), Decision::Allow);
    assert_eq!(decide(Some(&m), &[]), Decision::Allow);
    assert_eq!(decide(None, &teams(&["sales"])), Decision::Allow);
}

#[test]
fn listed_team_is_allowed_unlisted_is_denied() {
    let m = meta(&["sales"]);
    assert_eq!(decide(Some(&m), &teams(&["Sales "])), Decision::Allow);
    assert_eq!(
        decide(Some(&m), &teams(&["hr"])),
        Decision::Deny {
            teams: teams(&["hr"])
        }
    );
}

#[test]
fn one_match_among_many_allows() {
    let m = meta(&["sales"]);
    assert_eq!(
        decide(Some(&m), &teams(&["hr", "ops", "sales"])),
        Decision::Allow
    );
}

#[test]
fn no_match_among_many_is_denied() {
    let m = meta(&["sales"]);
    assert_eq!(
        decide(Some(&m), &teams(&["hr", "ops"])),
        Decision::Deny {
            teams: teams(&["hr", "ops"])
        }
    );
}

#[test]
fn unknown_team_fails_open() {
    let m = meta(&["sales"]);
    assert_eq!(decide(Some(&m), &[]), Decision::AllowUnknownTeam);
}

#[test]
fn caller_teams_requires_a_verified_block() {
    let v = verified(json!({"team": "Sales"}));
    assert_eq!(caller_teams(&v), teams(&["sales"]));

    let unverified = envelope(
        json!({"caller": {"team": "sales", "teams": ["sales"]}}),
        json!({}),
    );
    assert!(caller_teams(&unverified).is_empty());
    assert!(
        caller_teams(&envelope(
            json!({"caller": {"user_verified": true}}),
            json!({})
        ))
        .is_empty()
    );
    assert!(caller_teams(&verified(json!({"team": "  "}))).is_empty());
    assert!(caller_teams(&envelope(json!({}), json!({}))).is_empty());
}

#[test]
fn legacy_team_without_teams_still_works() {
    let e = verified(json!({"team": "sales"}));
    assert_eq!(caller_teams(&e), teams(&["sales"]));
    let m = meta(&["sales"]);
    assert!(matches!(apply(Some(&m), &e, "t"), Applied::Proceed(_)));
}

#[test]
fn teams_are_merged_deduped_and_validated() {
    let e = verified(json!({
        "team": "Sales",
        "teams": ["sales", "ops", "Bad Slug", "-x", "x-", "", 7, "UPPER", "a".repeat(51)]
    }));
    assert_eq!(caller_teams(&e), teams(&["sales", "ops", "upper"]));
}

#[test]
fn only_the_first_fifty_teams_are_read() {
    let many: Vec<String> = (0..60).map(|i| format!("t{i}")).collect();
    let e = verified(json!({"teams": many}));
    assert_eq!(caller_teams(&e).len(), MAX_CALLER_TEAMS);
}

#[test]
fn all_invalid_or_empty_teams_fail_open() {
    let m = meta(&["sales"]);
    for caller in [
        json!({"teams": []}),
        json!({"teams": ["Bad Slug", "", "-"]}),
        json!({"teams": "sales"}),
    ] {
        let e = verified(caller);
        assert!(caller_teams(&e).is_empty());
        assert!(matches!(apply(Some(&m), &e, "t"), Applied::Proceed(_)));
    }
}

#[test]
fn hint_prefers_a_team_in_the_audience_else_the_first() {
    let m = meta(&["sales"]);
    let t = teams(&["hr", "sales", "ops"]);
    assert_eq!(hint_team(Some(&m), &t).as_deref(), Some("sales"));
    assert_eq!(hint_team(Some(&meta(&["x"])), &t).as_deref(), Some("hr"));
    assert_eq!(hint_team(None, &t).as_deref(), Some("hr"));
    assert_eq!(hint_team(Some(&m), &[]), None);
}

#[test]
fn apply_stamps_the_matching_team_and_overwrites_a_forged_hint() {
    let m = meta(&["sales"]);
    let e = envelope(
        json!({"caller": {"user_verified": true, "team": "hr", "teams": ["hr", "sales"]}}),
        json!({"team_hint": "ceo"}),
    );
    match apply(Some(&m), &e, "t") {
        Applied::Proceed(e) => assert_eq!(
            e.metadata.get(TEAM_HINT_KEY).map(String::as_str),
            Some("sales")
        ),
        other => panic!("expected proceed, got {other:?}"),
    }
    let denied = verified(json!({"teams": ["hr", "ops"]}));
    assert!(matches!(apply(Some(&m), &denied, "t"), Applied::Denied(_)));
}

#[test]
fn stamp_overwrites_a_forged_hint_and_removes_it_when_unknown() {
    let forged = envelope(json!({}), json!({"team_hint": "ceo"}));
    let stamped = stamp_team_hint(&forged, Some("sales"));
    assert_eq!(
        stamped.metadata.get(TEAM_HINT_KEY).map(String::as_str),
        Some("sales")
    );
    let cleared = stamp_team_hint(&forged, None);
    assert!(!cleared.metadata.contains_key(TEAM_HINT_KEY));
}

#[test]
fn denied_reply_carries_the_fixed_text_and_no_hint() {
    let inbound = envelope(json!({}), json!({"team_hint": "hr", "adaptive_card": "{}"}));
    let reply = denied_reply(&inbound);
    assert_eq!(reply.text.as_deref(), Some(DENIED_REPLY_TEXT));
    assert!(!reply.metadata.contains_key(TEAM_HINT_KEY));
    assert!(!reply.metadata.contains_key("adaptive_card"));
}

#[test]
fn apply_denies_proceeds_and_fails_open() {
    let m = meta(&["sales"]);
    let hr = envelope(
        json!({"caller": {"user_verified": true, "team": "hr"}}),
        json!({}),
    );
    assert!(matches!(apply(Some(&m), &hr, "t"), Applied::Denied(_)));

    let sales = envelope(
        json!({"caller": {"user_verified": true, "team": "sales"}}),
        json!({}),
    );
    match apply(Some(&m), &sales, "t") {
        Applied::Proceed(e) => assert_eq!(
            e.metadata.get(TEAM_HINT_KEY).map(String::as_str),
            Some("sales")
        ),
        other => panic!("expected proceed, got {other:?}"),
    }

    let anon = envelope(json!({}), json!({"team_hint": "forged"}));
    match apply(Some(&m), &anon, "t") {
        Applied::Proceed(e) => assert!(!e.metadata.contains_key(TEAM_HINT_KEY)),
        other => panic!("expected proceed, got {other:?}"),
    }
    assert!(matches!(apply(None, &hr, "t"), Applied::Proceed(_)));
}
