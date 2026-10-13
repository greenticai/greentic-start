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

#[test]
fn empty_audience_never_restricts() {
    let m = meta(&[]);
    assert_eq!(decide(Some(&m), Some("sales")), Decision::Allow);
    assert_eq!(decide(Some(&m), None), Decision::Allow);
    assert_eq!(decide(None, Some("sales")), Decision::Allow);
}

#[test]
fn listed_team_is_allowed_unlisted_is_denied() {
    let m = meta(&["sales"]);
    assert_eq!(decide(Some(&m), Some("Sales ")), Decision::Allow);
    assert_eq!(
        decide(Some(&m), Some("hr")),
        Decision::Deny { team: "hr".into() }
    );
}

#[test]
fn unknown_team_fails_open() {
    let m = meta(&["sales"]);
    assert_eq!(decide(Some(&m), None), Decision::AllowUnknownTeam);
}

#[test]
fn caller_team_requires_a_verified_block() {
    let verified = envelope(
        json!({"caller": {"user_verified": true, "sub": "u", "team": "Sales"}}),
        json!({}),
    );
    assert_eq!(caller_team(&verified).as_deref(), Some("sales"));

    let unverified = envelope(json!({"caller": {"team": "sales"}}), json!({}));
    assert_eq!(caller_team(&unverified), None);

    let no_team = envelope(json!({"caller": {"user_verified": true}}), json!({}));
    assert_eq!(caller_team(&no_team), None);

    let blank = envelope(
        json!({"caller": {"user_verified": true, "team": "  "}}),
        json!({}),
    );
    assert_eq!(caller_team(&blank), None);

    assert_eq!(caller_team(&envelope(json!({}), json!({}))), None);
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
