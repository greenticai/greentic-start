use std::collections::BTreeMap;

use serde_json::json;

use super::fetch_ref::*;

fn ext(value: serde_json::Value) -> BTreeMap<String, serde_json::Value> {
    let mut ext = BTreeMap::new();
    ext.insert("attachment_fetch".to_string(), value);
    ext
}

#[test]
fn parses_all_five_kinds_by_index() {
    let refs = parse_refs(&ext(json!([
        {"kind": "bearer", "url": "https://files.slack.com/x", "secret_key": "SLACK_BOT_TOKEN"},
        {"kind": "telegram_file", "file_id": "AgAD"},
        {"kind": "whatsapp_media", "media_id": "123"},
        {"kind": "public", "url": "https://example.com/a.png"},
        {"kind": "inline"},
        {"kind": "something_new"}
    ])));
    assert_eq!(refs.len(), 6);
    assert!(matches!(refs[0], Some(FetchRef::Bearer { .. })));
    assert!(matches!(refs[1], Some(FetchRef::TelegramFile { .. })));
    assert!(matches!(refs[2], Some(FetchRef::WhatsappMedia { .. })));
    assert!(matches!(refs[3], Some(FetchRef::Public { .. })));
    assert!(matches!(refs[4], Some(FetchRef::Inline)));
    assert!(refs[5].is_none(), "an unknown kind is skipped, not fatal");
}

#[test]
fn missing_or_malformed_extension_is_empty() {
    assert!(parse_refs(&BTreeMap::new()).is_empty());
    assert!(parse_refs(&ext(json!("nope"))).is_empty());
}

#[test]
fn none_null_and_absent_entries_mean_never_fetch() {
    let refs = parse_refs(&ext(json!([
        {"kind": "none"},
        null,
        {"kind": "public", "url": "https://example.com/a.png"}
    ])));
    assert_eq!(refs.len(), 3);
    assert!(refs[0].is_none());
    assert!(refs[1].is_none());
    // An attachment past the end of the list has no entry at all.
    assert!(refs.get(3).is_none());
}

#[test]
fn non_https_urls_are_refused_at_parse_time() {
    let refs = parse_refs(&ext(
        json!([{"kind": "public", "url": "http://example.com/a.png"}]),
    ));
    assert!(refs[0].is_none());
}

#[test]
fn ids_that_could_reshape_a_url_are_refused() {
    let refs = parse_refs(&ext(json!([
        {"kind": "telegram_file", "file_id": "a&b=c"},
        {"kind": "whatsapp_media", "media_id": "../../x"},
        {"kind": "whatsapp_media", "media_id": "1234567890"},
        {"kind": "telegram_file", "file_id": ""},
        {"kind": "telegram_file", "file_id": "x".repeat(257)},
        {"kind": "bearer", "url": "https://files.slack.com/x", "secret_key": ""}
    ])));
    assert!(refs[0].is_none());
    assert!(refs[1].is_none());
    assert!(refs[2].is_some());
    assert!(refs[3].is_none());
    assert!(refs[4].is_none());
    assert!(refs[5].is_none());
}
