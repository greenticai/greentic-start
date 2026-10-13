//! Delivery of a plain flow's `media.create` file (greentic-runner#850).
//!
//! The node's result is a C5 value, `{ok, artifact, artifacts, warnings}`. With
//! no `output:` key and the node ending the flow, that value IS the flow's
//! final reply payload, so `outbound::collect` finds `artifact` at the top
//! level and the provenance gate links it when this deployment's port stored it.
//! A node that binds its result under `output:` nests it one key deeper, which
//! nothing collects: v1 delivers only a node that ends the flow.

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
fn an_output_bound_result_is_not_collected() {
    // `output: file` nests the value under the key; v1 delivers only a node
    // that ends the flow, so this names nothing.
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
