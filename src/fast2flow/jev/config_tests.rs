use super::*;

fn block(json: &str) -> JevBlock {
    serde_json::from_str(json).expect("block")
}

#[test]
fn no_block_anywhere_is_off() {
    assert_eq!(effective(None, None), Ok(None));
}

#[test]
fn an_empty_block_turns_the_tier_on_with_the_documented_defaults() {
    let got = effective(Some(&block("{}")), None).unwrap().unwrap();
    assert_eq!(got.endpoint, DEFAULT_ENDPOINT);
    assert_eq!(got.secret_name, "jev/api_key");
    assert_eq!(got.timeout, Duration::from_millis(2_000));
    assert_eq!(got.min_confidence, 0.5);
    assert_eq!(got.model, None);
}

#[test]
fn a_literal_key_is_a_parse_error_not_an_ignored_field() {
    assert!(serde_json::from_str::<JevBlock>(r#"{"api_key":"sk-live"}"#).is_err());
    assert!(serde_json::from_str::<JevBlock>(r#"{"key":"sk-live"}"#).is_err());
}

#[test]
fn the_pack_overrides_single_values_of_the_operators_block() {
    let op = block(r#"{"timeout_ms":3000,"min_confidence":0.7,"model":"jev-1"}"#);
    let pack = block(r#"{"min_confidence":0.4}"#);
    let got = effective(Some(&op), Some(&pack)).unwrap().unwrap();
    assert_eq!(got.timeout, Duration::from_millis(3_000));
    assert_eq!(got.min_confidence, 0.4);
    assert_eq!(got.model.as_deref(), Some("jev-1"));
}

#[test]
fn a_pack_alone_can_turn_the_tier_on() {
    let pack = block(r#"{"api_key_secret":"jev/router_key"}"#);
    let got = effective(None, Some(&pack)).unwrap().unwrap();
    assert_eq!(got.secret_name, "jev/router_key");
}

#[test]
fn the_operator_can_veto_a_pack() {
    let op = block(r#"{"enabled":false}"#);
    let pack = block(r#"{}"#);
    assert_eq!(effective(Some(&op), Some(&pack)), Ok(None));
    let off = block(r#"{"enabled":false}"#);
    assert_eq!(effective(None, Some(&off)), Ok(None));
}

#[test]
fn a_pack_cannot_choose_the_endpoint() {
    let pack = block(r#"{"endpoint":"https://evil.example/v1"}"#);
    assert!(effective(None, Some(&pack)).is_err());
    let op = block(r#"{"endpoint":"https://proxy.corp.example/jev"}"#);
    let got = effective(Some(&op), None).unwrap().unwrap();
    assert_eq!(got.endpoint, "https://proxy.corp.example/jev");
}

#[test]
fn a_pack_cannot_name_a_secret_outside_the_jev_namespace() {
    for name in ["slack/bot_token", "api_key", "../jev/x", " "] {
        let pack = JevBlock {
            api_key_secret: Some(name.to_string()),
            ..Default::default()
        };
        // A blank name is "not set" (the default applies); the rest are refused.
        let got = effective(None, Some(&pack));
        if name.trim().is_empty() {
            assert_eq!(got.unwrap().unwrap().secret_name, "jev/api_key");
        } else {
            assert!(got.is_err(), "{name}");
        }
    }
    // The operator is trusted with any name.
    let op = block(r#"{"api_key_secret":"JEV_KEY"}"#);
    assert_eq!(
        effective(Some(&op), None).unwrap().unwrap().secret_name,
        "JEV_KEY"
    );
}

#[test]
fn the_key_only_travels_over_tls_or_loopback() {
    for ok in [
        "https://api.typesafe.ai/v1/systemone",
        "http://127.0.0.1:8080/x",
        "http://localhost/x",
    ] {
        assert!(check_endpoint(ok).is_ok(), "{ok}");
    }
    for bad in [
        "http://api.typesafe.ai/v1/systemone",
        "ftp://x",
        "api.typesafe.ai",
        "http://127.0.0.1@evil.example/x",
    ] {
        assert!(check_endpoint(bad).is_err(), "{bad}");
    }
}

#[test]
fn timeout_is_clamped_and_confidence_is_validated() {
    let low = block(r#"{"timeout_ms":1}"#);
    assert_eq!(
        effective(Some(&low), None).unwrap().unwrap().timeout,
        Duration::from_millis(100)
    );
    let high = block(r#"{"timeout_ms":600000}"#);
    assert_eq!(
        effective(Some(&high), None).unwrap().unwrap().timeout,
        Duration::from_millis(10_000)
    );
    assert!(effective(Some(&block(r#"{"min_confidence":1.5}"#)), None).is_err());
}

#[test]
fn the_pack_block_is_read_from_the_shared_config_entry() {
    assert_eq!(parse_pack_block(br#"{"strategy":"bm25"}"#), Ok(None));
    let got =
        parse_pack_block(br#"{"schema":"greentic.fast2flow-config.v1","jev":{"timeout_ms":900}}"#)
            .unwrap()
            .unwrap();
    assert_eq!(got.timeout_ms, Some(900));
    assert!(parse_pack_block(br#"{"schema":"other.v9","jev":{}}"#).is_err());
    assert!(parse_pack_block(br#"{"jev":{"api_key":"x"}}"#).is_err());
    assert!(parse_pack_block(b"nope").is_err());
}
