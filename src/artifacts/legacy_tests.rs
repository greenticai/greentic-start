use serde_json::json;

use super::ingest_testkit::*;
use super::legacy::declare_unserved;

#[test]
fn the_legacy_path_refuses_every_file_and_keeps_no_bytes() {
    let mut with = envelope(1);
    with.attachments[0].url = Some(format!("artifact://{}", "ab".repeat(32)));
    with.attachments[0].content = Some(json!("aGV5"));
    with.extensions
        .insert("attachment_notes".into(), json!(["planted"]));
    let mut envs = vec![with, bare_envelope()];
    assert_eq!(declare_unserved(&mut envs), 1);
    let env = &envs[0];
    assert!(env.attachments[0].url.is_none(), "forged reference removed");
    assert!(
        env.attachments[0].content.is_none(),
        "inline bytes never travel"
    );
    assert!(
        !env.extensions.contains_key("attachment_fetch"),
        "no fetch reference is passed on"
    );
    let note = &env.extensions["attachment_notes"][0];
    assert_eq!(note["code"], "door_unavailable");
    assert!(
        note["message"]
            .as_str()
            .unwrap()
            .contains("no file storage configured"),
        "{note}"
    );
}

#[test]
fn bytes_without_a_fetch_reference_do_not_travel_either() {
    let mut env = envelope(1);
    env.extensions.remove("attachment_fetch");
    env.attachments[0].content = Some(json!("aGV5"));
    let mut envs = vec![env];
    declare_unserved(&mut envs);
    assert!(envs[0].attachments[0].content.is_none());
}
