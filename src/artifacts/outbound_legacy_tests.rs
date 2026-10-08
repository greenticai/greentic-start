//! The legacy `--bundle` lane delivers no file: raw ids never leave, and a
//! reply that names a file says it could not be sent.

use greentic_types::Attachment;
use serde_json::json;

use super::outbound::{LEGACY_UNSENT, declare_legacy_unsent, strip_logged};
use super::outbound_tests::envelope;

const A: &str = "artifact://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn agent_reply_with_file() -> serde_json::Value {
    json!({"reply": "Done.", "trail": [
        {"kind": "tool_call", "name": "generate_image", "call_id": "c1",
         "result": {"ok": true, "artifact": {"id": A}}}
    ]})
}

#[test]
fn a_reply_that_names_a_file_says_it_was_not_sent() {
    let mut envelopes = vec![envelope("Done."), envelope("second")];
    assert!(declare_legacy_unsent(
        &agent_reply_with_file(),
        &mut envelopes
    ));
    assert_eq!(
        envelopes[0].text.as_deref(),
        Some(format!("Done.\n\n{LEGACY_UNSENT}").as_str())
    );
    assert_eq!(envelopes[1].text.as_deref(), Some("second"));
    let mut empty_text = vec![envelope("")];
    declare_legacy_unsent(&agent_reply_with_file(), &mut empty_text);
    assert_eq!(empty_text[0].text.as_deref(), Some(LEGACY_UNSENT));
}

#[test]
fn a_reply_without_files_is_untouched() {
    let mut envelopes = vec![envelope("Done.")];
    let before = envelopes.clone();
    assert!(!declare_legacy_unsent(
        &json!({"reply": "Done.", "trail": []}),
        &mut envelopes
    ));
    assert_eq!(envelopes, before);
}

#[test]
fn raw_ids_are_stripped_on_the_legacy_lane() {
    let mut env = envelope("x");
    env.attachments.push(Attachment {
        mime_type: "image/png".into(),
        url: Some(A.into()),
        ..Default::default()
    });
    assert_eq!(strip_logged(&mut env), 1);
    assert!(env.attachments.is_empty());
}

/// Both hooks sit on the legacy path: the flow output is read where it still
/// exists (`run_app_flow`), and every envelope is stripped before egress.
#[test]
fn the_legacy_lane_is_hooked() {
    const APP: &str = include_str!("../messaging_app.rs");
    let run = APP.find("pub fn run_app_flow(").expect("run_app_flow");
    let hook = APP
        .find("crate::artifacts::outbound::declare_legacy_unsent(&value, &mut envelopes);")
        .expect("legacy hook");
    assert!(run < hook);
    const LANE: &str = include_str!("../http_ingress/messaging.rs");
    let strip = LANE
        .find("crate::artifacts::outbound::strip_logged(&mut out_envelope);")
        .expect("strip hook");
    let egress = LANE
        .find("let message_value = serde_json::to_value(&out_envelope)?;")
        .expect("egress serialisation");
    assert!(strip < egress);
}
