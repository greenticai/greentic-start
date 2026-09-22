use super::*;
use serde_json::json;

/// The contract's own conformance fixtures, copied verbatim from
/// greentic-designer's `tests/fixtures/triggers/`. A fixture this parser
/// rejects is a disagreement between the two repos, not a test to loosen.
const CRON: &str = include_str!("../../tests/fixtures/triggers/triggers_v1_cron.json");
const META: &str = include_str!("../../tests/fixtures/triggers/triggers_v1_meta_webhook.json");
const GENERIC: &str =
    include_str!("../../tests/fixtures/triggers/triggers_v1_generic_webhook.json");

fn pack_of(fixture: &str) -> String {
    let v: Value = serde_json::from_str(fixture).expect("fixture json");
    v["pack_id"].as_str().expect("pack_id").to_string()
}

#[test]
fn the_cron_fixture_parses_into_one_cron_trigger_in_its_timezone() {
    let parsed = parse(CRON.as_bytes(), &pack_of(CRON)).expect("cron fixture");
    assert!(parsed.skipped.is_empty());
    let [t] = parsed.triggers.as_slice() else {
        panic!("one trigger expected")
    };
    assert_eq!(t.trigger_id, "weekday_digest");
    assert_eq!(t.entry_node, "collect_mentions");
    assert_eq!(t.max_concurrency, 1);
    let TriggerKind::Cron(c) = &t.kind else {
        panic!("cron kind")
    };
    assert_eq!(c.timezone, chrono_tz::Europe::Amsterdam);
}

#[test]
fn the_meta_fixture_parses_hmac_and_the_hub_challenge() {
    let parsed = parse(META.as_bytes(), &pack_of(META)).expect("meta fixture");
    let [t] = parsed.triggers.as_slice() else {
        panic!("one trigger expected")
    };
    let TriggerKind::Webhook(w) = &t.kind else {
        panic!("webhook kind")
    };
    assert!(matches!(
        &w.verify,
        Verify::Hmac { algo: HmacAlgo::Sha256, header, prefix, secret_ref, .. }
            if header == "X-Hub-Signature-256" && prefix == "sha256=" && secret_ref == "threads/app_secret"
    ));
    assert!(matches!(
        &w.challenge,
        Some(Challenge::MetaHub { verify_token_ref }) if verify_token_ref == "threads/verify_token"
    ));
    assert_eq!(t.max_firings_per_hour, Some(600));
    assert_eq!(w.methods, vec!["POST".to_string()]);
}

#[test]
fn the_generic_fixture_parses_bearer_idempotency_and_a_per_key_session() {
    let parsed = parse(GENERIC.as_bytes(), &pack_of(GENERIC)).expect("generic fixture");
    let [t] = parsed.triggers.as_slice() else {
        panic!("one trigger expected")
    };
    assert!(matches!(t.session, SessionSpec::PerKey(_)));
    let TriggerKind::Webhook(w) = &t.kind else {
        panic!("webhook kind")
    };
    assert!(matches!(&w.verify, Verify::Bearer { header, .. } if header == "Authorization"));
    assert_eq!(w.idempotency.as_ref().map(|i| i.ttl_s), Some(86_400));
    assert_eq!(w.allowed_sources, vec!["203.0.113.0/24".to_string()]);
}

#[test]
fn a_file_for_another_pack_starts_nothing() {
    // §6.1: the pack segment secrets resolve under comes from pack_id, so a
    // file naming another pack could read that pack's secrets.
    let err = parse(META.as_bytes(), "pack.someone.else").unwrap_err();
    assert!(err.to_string().contains("does not match"), "{err:#}");
}

#[test]
fn a_newer_schema_is_refused_whole() {
    let doc = json!({"schema": "greentic.triggers.v2", "pack_id": "p", "triggers": []});
    assert!(parse(doc.to_string().as_bytes(), "p").is_err());
}

#[test]
fn an_unknown_kind_is_skipped_and_the_other_triggers_still_start() {
    // §11: an older host keeps serving what it understands.
    let mut doc: Value = serde_json::from_str(CRON).unwrap();
    doc["triggers"].as_array_mut().unwrap().push(json!({
        "trigger_id": "from_the_future", "kind": "mqtt", "flow_id": "main",
        "entry_node": "n", "source": {"extension_id": "x", "node_id": "y"}
    }));
    let parsed = parse(doc.to_string().as_bytes(), &pack_of(CRON)).expect("parses");
    assert_eq!(parsed.triggers.len(), 1);
    assert_eq!(parsed.skipped.len(), 1);
    assert!(parsed.skipped[0].contains("mqtt"));
}

#[test]
fn an_unknown_verify_scheme_skips_only_that_entry() {
    let mut doc: Value = serde_json::from_str(META).unwrap();
    doc["triggers"][0]["webhook"]["verify"]["scheme"] = json!("ed25519");
    let parsed = parse(doc.to_string().as_bytes(), &pack_of(META)).expect("parses");
    assert!(parsed.triggers.is_empty());
    assert_eq!(parsed.skipped.len(), 1);
}

#[test]
fn a_webhook_without_verify_is_refused_there_is_no_default() {
    let mut doc: Value = serde_json::from_str(META).unwrap();
    doc["triggers"][0]["webhook"]
        .as_object_mut()
        .unwrap()
        .remove("verify");
    assert!(parse(doc.to_string().as_bytes(), &pack_of(META)).is_err());
}

#[test]
fn a_pasted_credential_in_a_secret_ref_is_refused_without_being_echoed() {
    let mut doc: Value = serde_json::from_str(META).unwrap();
    doc["triggers"][0]["webhook"]["verify"]["secret_ref"] = json!("EAAGm0PX4ZCpsBAO");
    let err = parse(doc.to_string().as_bytes(), &pack_of(META)).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("secret reference"), "{text}");
    assert!(
        !text.contains("EAAGm0PX4ZCpsBAO"),
        "the value must never be logged: {text}"
    );
}

#[test]
fn duplicate_trigger_ids_refuse_the_file() {
    let mut doc: Value = serde_json::from_str(CRON).unwrap();
    let copy = doc["triggers"][0].clone();
    doc["triggers"].as_array_mut().unwrap().push(copy);
    assert!(parse(doc.to_string().as_bytes(), &pack_of(CRON)).is_err());
}

#[test]
fn get_is_refused_as_a_firing_method_when_a_challenge_is_declared() {
    let mut doc: Value = serde_json::from_str(META).unwrap();
    doc["triggers"][0]["webhook"]["methods"] = json!(["POST", "GET"]);
    assert!(parse(doc.to_string().as_bytes(), &pack_of(META)).is_err());
}

#[test]
fn a_bad_cron_or_timezone_refuses_the_file() {
    for (field, value) in [("expr", "not a cron"), ("timezone", "Mars/Olympus")] {
        let mut doc: Value = serde_json::from_str(CRON).unwrap();
        doc["triggers"][0]["cron"][field] = json!(value);
        assert!(
            parse(doc.to_string().as_bytes(), &pack_of(CRON)).is_err(),
            "{field}={value}"
        );
    }
}

#[test]
fn a_five_field_cron_gains_a_seconds_field_like_the_runner() {
    assert_eq!(normalize_cron("*/15 * * * *"), "0 */15 * * * *");
    assert_eq!(normalize_cron("0 0 9 * * MON-FRI"), "0 0 9 * * MON-FRI");
}

#[test]
fn unknown_fields_are_ignored() {
    let mut doc: Value = serde_json::from_str(CRON).unwrap();
    doc["future_top_level"] = json!(true);
    doc["triggers"][0]["future_field"] = json!({"x": 1});
    assert!(parse(doc.to_string().as_bytes(), &pack_of(CRON)).is_ok());
}
