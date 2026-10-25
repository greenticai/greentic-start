use super::*;
use crate::triggers::schema::{self, TriggerKind};
use serde_json::json;

const FIXTURE: &str = include_str!("../../tests/fixtures/triggers/triggers_v1_email_imap.json");

fn block(patch: Value) -> Value {
    let mut base = json!({
        "host": "imap.acme.example",
        "username": "support@acme.example",
        "password_ref": "mail/imap_password",
    });
    for (k, v) in patch.as_object().unwrap() {
        base[k] = v.clone();
    }
    base
}

#[test]
fn the_fixture_parses_as_an_email_imap_trigger() {
    let parsed = schema::parse(FIXTURE.as_bytes(), "pack.acme.support").expect("parses");
    assert!(parsed.skipped.is_empty());
    let spec = &parsed.triggers[0];
    assert_eq!(spec.kind.name(), "email_imap");
    assert_eq!(spec.max_concurrency, 1);
    let TriggerKind::EmailImap(m) = &spec.kind else {
        panic!("wrong kind");
    };
    assert_eq!((m.port, m.tls), (993, TlsMode::Tls));
    assert_eq!(m.search.from.as_deref(), Some("customer@example.com"));
    assert_eq!(m.on_success, OnSuccess::MarkSeen);
}

#[test]
fn defaults_are_secure_and_conservative() {
    let m = parse(&block(json!({}))).expect("parses");
    assert_eq!((m.tls, m.port), (TlsMode::Tls, 993));
    assert_eq!(m.mailbox, "INBOX");
    assert_eq!(m.poll_interval_s, 60);
    assert!(m.search.unseen);
    assert!(!m.include_html);
    assert_eq!(m.attachments, AttachmentMode::None);
    assert_eq!(parse(&block(json!({"tls": "starttls"}))).unwrap().port, 143);
}

#[test]
fn the_poll_interval_has_a_floor() {
    assert!(parse(&block(json!({"poll_interval_s": 5}))).is_err());
    assert!(parse(&block(json!({"poll_interval_s": 30}))).is_ok());
}

#[test]
fn there_is_no_plaintext_mode() {
    let err = parse(&block(json!({"tls": "none"}))).unwrap_err();
    assert!(err.to_string().contains("tls"), "{err:#}");
}

#[test]
fn a_pasted_password_is_refused_without_echoing_it() {
    let err = parse(&block(json!({"password_ref": "hunter2-correct-horse"}))).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("secret reference"), "{text}");
    assert!(!text.contains("hunter2"), "{text}");
}

#[test]
fn search_text_cannot_carry_imap_syntax() {
    let search = json!({"search": {"subject": "x\" OR ALL"}});
    assert!(parse(&block(search)).is_err());
    assert!(parse(&block(json!({"mailbox": "INBOX\r\nA1 DELETE x"}))).is_err());
    assert!(parse(&block(json!({"host": "evil.example\r\nX"}))).is_err());
}

#[test]
fn move_needs_a_target_and_none_needs_unseen_off() {
    assert!(parse(&block(json!({"on_success": "move"}))).is_err());
    let moved = parse(&block(
        json!({"on_success": "move", "move_to": "Processed"}),
    ))
    .unwrap();
    assert_eq!(moved.on_success, OnSuccess::MoveTo("Processed".into()));
    assert!(parse(&block(json!({"on_success": "none"}))).is_err());
    let ok = json!({"on_success": "none", "search": {"unseen": false}});
    assert!(parse(&block(ok)).is_ok());
}
