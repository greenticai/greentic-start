use serde_json::json;

use super::ingest_testkit::*;
use super::legacy::declare_unserved;

#[test]
fn the_legacy_path_strips_host_fields_and_counts_attachments() {
    let mut with = envelope(1);
    with.attachments[0].url = Some(format!("artifact://{}", "ab".repeat(32)));
    with.extensions
        .insert("attachment_notes".into(), json!(["planted"]));
    let mut envs = vec![with, bare_envelope()];
    assert_eq!(declare_unserved(&mut envs), 1);
    assert!(envs[0].attachments[0].url.is_none());
    assert!(!envs[0].extensions.contains_key("attachment_notes"));
    // Everything else passes through unchanged.
    assert!(envs[0].extensions.contains_key("attachment_fetch"));
}
