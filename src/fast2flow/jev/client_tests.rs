use super::*;

fn candidates() -> Vec<Candidate> {
    vec![
        Candidate {
            target: "support/refund_flow/ask_refund".into(),
            title: "Refund".into(),
            hints: vec!["I want my money back".into(), "refund please".into()],
        },
        Candidate {
            target: "sales/pricing/ask_sales".into(),
            title: String::new(),
            hints: vec![],
        },
    ]
}

#[test]
fn the_body_matches_the_decide_tools_contract() {
    let body = build_body("refund me", &candidates(), None);
    assert_eq!(body["state"], "refund me");
    assert_eq!(body["model"], DEFAULT_MODEL);
    let q = &body["questions"][QUESTION_ID];
    assert_eq!(q["type"], "choice");
    assert!(!q["instructions"].as_str().unwrap().trim().is_empty());
    let criteria = q["criteria"].as_object().unwrap();
    // two destinations + the abstain option: a choice needs at least two.
    assert_eq!(criteria.len(), 3);
    assert_eq!(
        criteria["opt_1"],
        "Refund - e.g. I want my money back; refund please"
    );
    // a candidate with no title or hints is described by its target.
    assert_eq!(criteria["opt_2"], "sales/pricing/ask_sales");
    assert!(criteria.contains_key(NONE_OPTION));
}

#[test]
fn an_explicit_model_wins_and_a_long_message_is_cut() {
    let long = "x".repeat(MAX_STATE_CHARS + 500);
    let body = build_body(&long, &candidates(), Some(" jev-1.13.0 "));
    assert_eq!(body["model"], "jev-1.13.0");
    assert_eq!(
        body["state"].as_str().unwrap().chars().count(),
        MAX_STATE_CHARS
    );
}

#[test]
fn a_choice_answer_maps_with_its_confidence() {
    let raw = br#"{"model":"jev-1.13.0","answers":{"route":{"type":"choice","choice":"opt_1","confidence":0.91,"probabilities":{"opt_1":0.91,"none":0.09}}},"usage":{"input_tokens":4}}"#;
    assert_eq!(
        map_response(raw),
        Ok(JevChoice {
            option: "opt_1".into(),
            confidence: 0.91
        })
    );
}

#[test]
fn the_probability_stands_in_for_a_missing_confidence() {
    let raw = br#"{"answers":{"route":{"choice":"opt_2","probabilities":{"opt_2":0.7}}}}"#;
    assert_eq!(map_response(raw).unwrap().confidence, 0.7);
}

#[test]
fn an_answer_that_cannot_be_trusted_is_refused() {
    for raw in [
        &br#"{"answers":{"route":{"choice":"opt_1"}}}"#[..],
        br#"{"answers":{"route":{"choice":"opt_1","confidence":1.7}}}"#,
        br#"{"answers":{"route":{"choice":"","confidence":0.9}}}"#,
        br#"{"answers":{"other":{"choice":"opt_1","confidence":0.9}}}"#,
        br#"{"answers":{}}"#,
        br#"{"message":"bad state"}"#,
    ] {
        assert_eq!(map_response(raw), Err(JevError::NoAnswer), "{raw:?}");
    }
    assert_eq!(map_response(b"{bad"), Err(JevError::Decode));
}

#[test]
fn error_text_carries_no_payload() {
    for e in [
        JevError::Timeout,
        JevError::Transport,
        JevError::Status(503),
        JevError::Decode,
        JevError::NoAnswer,
    ] {
        let text = format!("{} {:?}", e.describe(), e);
        assert!(!text.contains("Bearer"), "{text}");
    }
    assert_eq!(JevError::Status(503).class(), "server_error");
    assert_eq!(JevError::Status(401).class(), "auth");
}
