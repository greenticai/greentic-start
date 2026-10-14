//! Outbound plumbing: the raw-id strip, the out-of-band side table, and the
//! hooks that tie them to the pipeline and the kill switch.

use greentic_types::Attachment;
use greentic_types::messaging::extensions::ext_keys;
use serde_json::json;

use super::link;
use super::link_base::LinkBase;
use super::outbound::{C5Ref, OutboundCtx, OutboundFile, OutboundSide, Resolved};
use super::outbound_shape::{safe_name, shape, strip_raw_artifact_urls};
use super::outbound_tests::{envelope, ids};

const A: &str = "artifact://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "artifact://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn raw_artifact_urls_are_stripped_and_nothing_else_moves() {
    let mut env = envelope("hi");
    env.attachments = vec![
        Attachment {
            mime_type: "image/png".into(),
            url: Some(A.into()),
            ..Default::default()
        },
        Attachment {
            mime_type: "image/png".into(),
            url: Some("https://cdn.example/ok.png".into()),
            ..Default::default()
        },
    ];
    env.extensions.insert(
        ext_keys::ATTACHMENTS.into(),
        json!([{"contentUrl": " ARTIFACT://x"}, {"contentUrl": "https://ok"}]),
    );
    let mut expected = env.clone();
    expected.attachments.remove(0);
    expected.extensions.insert(
        ext_keys::ATTACHMENTS.into(),
        json!([{"contentUrl": "https://ok"}]),
    );
    assert_eq!(strip_raw_artifact_urls(&mut env), 2);
    assert_eq!(env, expected);
}

#[test]
fn the_side_table_carries_refs_out_of_band() {
    let side = OutboundSide::default();
    side.record(&[envelope("a")], vec![C5Ref { id: A.into() }]);
    side.record(&[], vec![C5Ref { id: B.into() }]);
    side.record(&[envelope("b")], Vec::new());
    assert_eq!(ids(&side.take("other")), Vec::<&str>::new());
    assert_eq!(ids(&side.take("reply-1")), [A]);
    assert_eq!(ids(&side.take("reply-1")), Vec::<&str>::new());
    assert_eq!(ids(&side.take_orphans()), [B]);
}

/// The kill switch is read by the context itself.
#[test]
fn the_context_reads_the_kill_switch() {
    const SOURCE: &str = include_str!("outbound.rs");
    let new = SOURCE.find("pub(crate) fn new(").expect("ctor");
    assert!(SOURCE[new..].contains("enabled: link::links_enabled(),"));
    let ctx = OutboundCtx::new(None, LinkBase::RelativeOnly);
    assert_eq!(ctx.enabled, link::links_enabled());
}

/// The pipeline hook: refs are collected in the reply closure (out of band)
/// and every reply passes `prepare_replies` before the provider egress.
#[test]
fn the_pipeline_shapes_every_reply_before_egress() {
    const SERVE: &str = include_str!("../revision_serve.rs");
    let one = |needle: &str| {
        assert_eq!(SERVE.matches(needle).count(), 1, "`{needle}`");
        SERVE.find(needle).expect("present")
    };
    let ctx = one("let outbound_ctx = crate::artifacts::outbound::OutboundCtx::new(");
    let record = one("outbound_side.record(&envelopes, files);");
    let prepare = one("let reply_envelopes = crate::artifacts::outbound::prepare_replies(");
    let egress =
        one("        for reply_envelope in reply_envelopes {\n            match run_reply_egress(");
    assert!(ctx < record && record < prepare && prepare < egress);
}

/// A raw id is removed wherever it hides in the outgoing envelope: the text,
/// the card (metadata string or extension JSON) and any other metadata.
/// Invisible characters inside the scheme do not hide it; prose that merely
/// says "artifact:" is left alone.
#[test]
fn raw_ids_in_text_card_and_metadata_are_removed() {
    const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let mut env = envelope(&format!(
        "See {A} and ARTIFACT://x, or art\u{200B}ifact://{C}. The artifact: stays."
    ));
    env.metadata.insert(
        "adaptive_card".into(),
        json!({"body": [{"type": "Image", "url": B}]}).to_string(),
    );
    env.metadata.insert("note".into(), format!("ref {A}"));
    env.extensions.insert(
        ext_keys::ADAPTIVE_CARD.into(),
        json!({"body": [{"type": "Image", "url": A}, {"type": "TextBlock", "text": "keep"}]}),
    );
    assert_eq!(strip_raw_artifact_urls(&mut env), 6);
    let serialised = serde_json::to_string(&env).unwrap().to_lowercase();
    assert!(!serialised.contains("artifact://"), "{serialised}");
    assert!(!serialised.contains("aaaaaaaa"), "{serialised}");
    assert!(!serialised.contains("bbbbbbbb"), "{serialised}");
    assert!(!serialised.contains("cccccccc"), "{serialised}");
    let text = env.text.as_deref().unwrap();
    assert!(text.starts_with("See "), "{text}");
    assert!(text.ends_with("The artifact: stays."), "{text}");
    assert_eq!(
        env.extensions[ext_keys::ADAPTIVE_CARD]["body"][1]["text"],
        json!("keep")
    );
    // The card metadata stays a JSON document.
    serde_json::from_str::<serde_json::Value>(&env.metadata["adaptive_card"]).unwrap();
    assert_eq!(env.metadata["route"], "r1");
}

#[test]
fn debug_never_prints_a_signed_link() {
    let file = OutboundFile {
        name: "a.png".into(),
        mime_type: "image/png".into(),
        size_bytes: 3,
        url: "https://svc.example/v1/artifacts/SECRETLINK".into(),
    };
    let resolved = Resolved {
        files: vec![file.clone()],
        refused: Vec::new(),
    };
    for printed in [
        format!("{file:?}"),
        format!("{resolved:?}"),
        format!("{resolved:#?}"),
    ] {
        assert!(!printed.contains("SECRETLINK"), "{printed}");
        assert!(printed.contains("<redacted>"), "{printed}");
        assert!(printed.contains("a.png"), "{printed}");
    }
}

/// The WebChat typed attachment and the raw DirectLine entry carry the same
/// cleaned name the text uses, never the record's raw one.
#[test]
fn webchat_attachment_names_are_safe() {
    let resolved = Resolved {
        files: vec![OutboundFile {
            name: "cat <b>\"x\".png".into(),
            mime_type: "image/png".into(),
            size_bytes: 3,
            url: "/v1/artifacts/x".into(),
        }],
        refused: Vec::new(),
    };
    let mut env = envelope("Here.");
    env.extensions
        .insert(ext_keys::ATTACHMENTS.into(), json!([]));
    let out = shape(env, "messaging.webchat", &resolved);
    let expected = safe_name("cat <b>\"x\".png");
    assert_eq!(expected, "cat _b__x_.png");
    assert_eq!(
        out[0].attachments[0].name.as_deref(),
        Some(expected.as_str())
    );
    assert_eq!(
        out[0].extensions[ext_keys::ATTACHMENTS][0]["name"],
        json!(expected)
    );
}
