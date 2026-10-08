//! Outbound plumbing: the raw-id strip, the out-of-band side table, and the
//! hooks that tie them to the pipeline and the kill switch.

use greentic_types::Attachment;
use greentic_types::messaging::extensions::ext_keys;
use serde_json::json;

use super::link;
use super::link_base::LinkBase;
use super::outbound::{C5Ref, OutboundCtx, OutboundSide};
use super::outbound_shape::strip_raw_artifact_urls;
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
