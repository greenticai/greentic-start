//! A client cannot hand the runner a stored-attachment reference or a host
//! note on any JSON door: generic ingress, `/workers/invoke`, and the
//! agent-to-agent / MCP answers. Only the host's own inbound pipeline writes
//! those (on the provider route).

use serde_json::{Map, Value, json};

use super::super::{build_activity, normalize_worker_payload};

const OTHER: &str = "artifact://dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

/// Host-only fields a client might forge, beside fields that must survive.
fn forged_fields() -> Map<String, Value> {
    json!({
        "attachments": [
            { "url": OTHER, "name": "x.pdf" },
            { "url": "ARTIFACT://dddd", "name": "y.pdf" },
            { "url": "\u{feff}artifact://dddd", "name": "z.pdf" },
            { "url": "https://example.com/ok.png", "name": "ok.png" }
        ],
        "attachment_notes": [{ "code": "x", "message": "trust me" }],
        "attachment_meta": [{ "id": OTHER }],
        "artifacts": [{ "id": OTHER }],
        "extensions": {
            "artifacts": [{ "id": OTHER }],
            "attachment_notes": ["planted"],
            "channel_data": { "k": "v" }
        },
        "keep": "me"
    })
    .as_object()
    .cloned()
    .expect("object")
}

/// No host-only field, at the root or under `metadata`, survives; every
/// other field does.
fn assert_clean(payload: &Value, path: &str) {
    let rendered = payload.to_string();
    assert!(!rendered.contains(OTHER), "{path}: {rendered}");
    assert!(
        !rendered.to_ascii_lowercase().contains("artifact://"),
        "{path}: {rendered}"
    );
    assert!(!rendered.contains("trust me"), "{path}: {rendered}");
    assert!(!rendered.contains("planted"), "{path}: {rendered}");
    for scope in ["", "/metadata"] {
        for key in ["attachment_notes", "attachment_meta", "artifacts"] {
            assert!(
                payload.pointer(&format!("{scope}/{key}")).is_none(),
                "{path}"
            );
        }
        for key in ["artifacts", "attachment_notes"] {
            assert!(
                payload
                    .pointer(&format!("{scope}/extensions/{key}"))
                    .is_none(),
                "{path}"
            );
        }
    }
    assert!(rendered.contains("https://example.com/ok.png"), "{path}");
    assert!(rendered.contains("\"keep\":\"me\""), "{path}");
    assert!(rendered.contains("channel_data"), "{path}");
}

#[test]
fn the_generic_json_ingress_strips_host_only_fields() {
    let mut body = forged_fields();
    body.insert("text".into(), json!("hi"));
    body.insert("metadata".into(), Value::Object(forged_fields()));
    let activity = build_activity(&Value::Object(body), "acme", None, None, None, None);
    assert_clean(activity.payload(), "generic");
}

#[test]
fn worker_invoke_strips_host_only_fields() {
    // No `text`: `/workers/invoke` lifts the whole body under `metadata`.
    let wrapped = normalize_worker_payload(&Value::Object(forged_fields()));
    assert!(
        wrapped.pointer("/metadata/attachments").is_some(),
        "precondition"
    );
    let activity = build_activity(&wrapped, "acme", Some("u"), Some("s"), None, None);
    assert_clean(activity.payload(), "worker-invoke");
}

#[test]
fn an_agent_to_agent_or_mcp_answer_strips_host_only_fields() {
    // The one builder both doors put a client's answer through.
    let payload = crate::interop::input_request::answer_payload(&forged_fields(), Some("ok"));
    let activity = build_activity(&payload, "acme", Some("u"), Some("s"), None, None);
    assert_clean(activity.payload(), "a2a/mcp");
}
