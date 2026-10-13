//! Delivery of a plain flow's `media.create` file (greentic-runner#850).
//!
//! The node's result is a C5 value, `{ok, artifact, artifacts, warnings}`. With
//! no `output:` key and the node ending the flow, that value IS the final reply
//! payload, so `outbound::collect` finds `artifact` at the top level and the
//! provenance gate links it when this deployment's port stored it.
//!
//! A node that binds its result under `output:`, or is followed by other nodes,
//! is delivered through the runner's `created_artifacts` list on the final
//! reply (greentic-runner `media_node::attach_created`): the runner records
//! every file it created this turn, whatever the node's binding. The mid-flow
//! cases are at the end of this file.

use std::sync::Arc;

use hyper::{Method, StatusCode};
use serde_json::{Value, json};

use super::ingest_testkit::envelope;
use super::link_base::LinkBase;
use super::outbound::{OutboundCtx, OutboundSide, collect, prepare_replies};
use super::recent_puts::PutRecord;
use super::serve_link_testkit::{ID, NOW, StubReader, fixture, limits};

const PROVIDER: &str = "messaging.webchat-gui";
const BASE: &str = "https://svc.example";
const PDF: &[u8] = b"%PDF-1.7 claim summary";

/// Exactly what the runner's `media.create` answers on success.
fn node_result() -> Value {
    json!({
        "ok": true,
        "artifact": {"id": ID, "mime_type": "application/pdf", "name": "Claim Summary.pdf"},
        "artifacts": [{"id": ID, "mime_type": "application/pdf", "name": "Claim Summary.pdf"}],
        "warnings": [],
    })
}

#[test]
fn the_node_result_as_the_final_reply_names_its_file() {
    let refs = collect(&node_result());
    assert_eq!(refs.len(), 1, "artifact and artifacts[] are one file");
    assert_eq!(refs[0].id, ID);
}

#[test]
fn an_output_bound_result_alone_is_not_collected() {
    // `output: file` nests the value under the key. A node merely MENTIONING
    // a file is not delivered: only the runner's own list (below) is.
    assert!(collect(&json!({"file": node_result()})).is_empty());
}

#[test]
fn a_failed_node_names_nothing() {
    let failed = json!({"ok": false, "error": {"code": "invalid_input", "message": "empty"}});
    assert!(collect(&failed).is_empty());
}

#[tokio::test]
async fn the_file_reaches_webchat_as_an_attachment_that_downloads() {
    let fx = fixture(StubReader::file(
        "application/pdf",
        Some("Claim Summary.pdf"),
        PDF,
    ));
    // The runner's artifact port stored it through this unit's port.
    fx.unit.recent.record(
        ID,
        PutRecord {
            mime_type: "application/pdf".into(),
            name: "Claim Summary.pdf".into(),
            size_bytes: PDF.len() as u64,
            at: NOW - 5,
        },
    );
    let ingress = envelope(1);
    let side = OutboundSide::default();
    let mut reply = crate::messaging_app::base_reply_envelope(&ingress);
    reply.text = None;
    side.record(std::slice::from_ref(&reply), collect(&node_result()));
    let ctx = OutboundCtx {
        unit: Some(Arc::clone(&fx.unit)),
        base: LinkBase::Absolute(BASE.into()),
        enabled: true,
    };
    let out = prepare_replies(vec![reply], &side, &ingress, PROVIDER, &ctx, NOW);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].attachments.len(),
        1,
        "WebChat gets a typed attachment"
    );
    let url = out[0].attachments[0].url.clone().expect("signed link");
    assert!(!url.contains("artifact://"), "raw id leaked: {url}");
    let serialised = serde_json::to_string(&out[0]).expect("json");
    assert!(!serialised.contains("artifact://"), "{serialised}");
    let path = url.strip_prefix(BASE).unwrap_or(&url);
    let answer = fx.request(Method::GET, path, &limits()).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body.as_ref(), PDF);
}

#[test]
fn a_file_this_unit_never_stored_is_refused() {
    let fx = fixture(StubReader::file("application/pdf", None, PDF));
    let ingress = envelope(1);
    let side = OutboundSide::default();
    let reply = crate::messaging_app::base_reply_envelope(&ingress);
    side.record(std::slice::from_ref(&reply), collect(&node_result()));
    let ctx = OutboundCtx {
        unit: Some(Arc::clone(&fx.unit)),
        base: LinkBase::Absolute(BASE.into()),
        enabled: true,
    };
    let out = prepare_replies(vec![reply], &side, &ingress, PROVIDER, &ctx, NOW);
    assert!(out.iter().all(|e| e.attachments.is_empty()));
}

// ── a file created mid-flow (runner `created_artifacts` list) ────────────────

fn listed(ids: &[&str]) -> Value {
    json!(
        ids.iter()
            .map(|id| json!({"id": id, "mime_type": "application/pdf", "name": "n.pdf"}))
            .collect::<Vec<_>>()
    )
}

fn other_id(n: u8) -> String {
    format!("artifact://{}", format!("{n:x}").repeat(64))
}

#[test]
fn the_runner_list_names_files_whatever_the_node_binding_was() {
    // `output: file` and a following node that answered text.
    let reply = json!({
        "text": "Here is your summary",
        "created_artifacts": listed(&[ID]),
    });
    let refs = collect(&reply);
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].id, ID);
}

#[test]
fn two_files_keep_their_order_and_a_repeat_is_one_file() {
    let (a, b) = (other_id(1), other_id(2));
    let reply = json!({"created_artifacts": listed(&[&a, &b, &a]), "artifact": {"id": a}});
    let ids: Vec<_> = collect(&reply).into_iter().map(|r| r.id).collect();
    assert_eq!(ids, vec![a, b]);
}

#[test]
fn the_per_reply_cap_applies_to_the_list() {
    let ids: Vec<String> = (1..=8).map(other_id).collect();
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    let reply = json!({"created_artifacts": listed(&refs)});
    assert_eq!(collect(&reply).len(), super::outbound::MAX_OUTBOUND);
}

#[test]
fn malformed_entries_name_nothing() {
    let reply = json!({"created_artifacts": [
        {"id": "artifact://short"},
        {"id": 7},
        {"name": "no id"},
        "artifact://not-an-object",
    ]});
    assert!(collect(&reply).is_empty());
    assert!(collect(&json!({"created_artifacts": "nope"})).is_empty());
}

#[test]
fn a_reply_that_is_a_full_envelope_names_only_the_runner_list() {
    let ingress = envelope(1);
    let mut reply = serde_json::to_value(&ingress).expect("envelope json");
    reply["artifact"] = json!({"id": other_id(3)});
    assert!(collect(&reply).is_empty(), "a flow cannot ask for a link");
    reply["created_artifacts"] = listed(&[ID]);
    let refs = collect(&reply);
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].id, ID);
}

#[test]
fn the_list_is_removed_before_a_reply_is_shaped() {
    let mut payload = json!({"text": "hi", "created_artifacts": listed(&[ID])});
    super::outbound::strip_created_list(&mut payload);
    assert_eq!(payload, json!({"text": "hi"}));
    let mut pending =
        json!({"status": "pending", "response": {"created_artifacts": listed(&[ID])}});
    super::outbound::strip_created_list(&mut pending);
    assert!(pending["response"].get("created_artifacts").is_none());
}

#[tokio::test]
async fn a_mid_flow_file_reaches_webchat_and_downloads() {
    let fx = fixture(StubReader::file(
        "application/pdf",
        Some("Claim Summary.pdf"),
        PDF,
    ));
    fx.unit.recent.record(
        ID,
        PutRecord {
            mime_type: "application/pdf".into(),
            name: "Claim Summary.pdf".into(),
            size_bytes: PDF.len() as u64,
            at: NOW - 5,
        },
    );
    let ingress = envelope(1);
    let side = OutboundSide::default();
    let mut reply = crate::messaging_app::base_reply_envelope(&ingress);
    reply.text = Some("Here is your summary".into());
    let payload = json!({"text": "Here is your summary", "created_artifacts": listed(&[ID])});
    side.record(std::slice::from_ref(&reply), collect(&payload));
    let ctx = OutboundCtx {
        unit: Some(Arc::clone(&fx.unit)),
        base: LinkBase::Absolute(BASE.into()),
        enabled: true,
    };
    let out = prepare_replies(vec![reply], &side, &ingress, PROVIDER, &ctx, NOW);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].attachments.len(),
        1,
        "WebChat gets a typed attachment"
    );
    assert!(
        out[0]
            .text
            .as_deref()
            .unwrap_or("")
            .contains("Here is your summary")
    );
    let url = out[0].attachments[0].url.clone().expect("signed link");
    assert!(!url.contains("artifact://"), "raw id leaked: {url}");
    let path = url.strip_prefix(BASE).unwrap_or(&url);
    let answer = fx.request(Method::GET, path, &limits()).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body.as_ref(), PDF);
}

#[test]
fn an_unknown_id_in_the_list_is_refused_by_the_provenance_gate() {
    // The id is well-formed and listed, but this unit's port never stored it.
    let fx = fixture(StubReader::file("application/pdf", None, PDF));
    let ingress = envelope(1);
    let side = OutboundSide::default();
    let reply = crate::messaging_app::base_reply_envelope(&ingress);
    let payload = json!({"text": "x", "created_artifacts": listed(&[&other_id(9)])});
    side.record(std::slice::from_ref(&reply), collect(&payload));
    let ctx = OutboundCtx {
        unit: Some(Arc::clone(&fx.unit)),
        base: LinkBase::Absolute(BASE.into()),
        enabled: true,
    };
    let out = prepare_replies(vec![reply], &side, &ingress, PROVIDER, &ctx, NOW);
    assert!(out.iter().all(|e| e.attachments.is_empty()));
    let text: String = out.iter().filter_map(|e| e.text.clone()).collect();
    assert!(text.contains("A file could not be sent."), "{text}");
}
