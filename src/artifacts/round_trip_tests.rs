//! Inbound verification, inbound files and outbound links, end to end across
//! both halves (stub provider, stub agent, stub door):
//!
//! signed WhatsApp request -> `inbound_verify` -> `Origin::verified_by_host`
//! -> the inbound hook stores the file -> the agent sees `artifact://` and
//! writes a file of its own -> `outbound::prepare_replies` turns that into a
//! signed link -> `/v1/artifacts/` serves the agent's bytes.
//!
//! The production seams are the ones `revision_serve::dispatch_provider_route`
//! and `run_provider_inbound_pipeline` call; their ORDER there is pinned by
//! `inbound_verify::wiring_tests` and `artifacts::wiring_tests`.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine as _;
use greentic_deploy_spec::DeploymentId;
use hyper::{Method, StatusCode};
use serde_json::json;

use super::hook::prepare;
use super::ingest::Pipeline;
use super::ingest_testkit::{FakeFetcher, FakeStore, envelope, note, ok, png};
use super::link_base::LinkBase;
use super::origin::{Origin, RequestVerification};
use super::outbound::{OutboundCtx, OutboundSide, collect, prepare_replies};
use super::recent_puts::PutRecord;
use super::serve_link_testkit::{ID, NOW, fixture, limits};
use super::unit::UnitAttachments;
use crate::inbound_verify::{Inbound, Verdict, verify_inbound};
use crate::secrets_gate::DynSecretsManager;

const WHATSAPP: &str = include_str!("../inbound_verify/fixtures/inbound-auth-v1/whatsapp.json");
const PROVIDER: &str = "messaging.whatsapp.cloud";
const PACK: &str = "messaging-pack";
const BASE: &str = "https://svc.example";
const AGENT_BYTES: &[u8] = b"%PDF-1.7 the agent's report";

struct Signed {
    secret: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn signed() -> Signed {
    let v: serde_json::Value = serde_json::from_str(WHATSAPP).expect("fixture");
    let text = |key: &str| v[key].as_str().expect("field").to_string();
    Signed {
        secret: text("secret"),
        headers: vec![(text("header_name"), text("header"))],
        body: base64::engine::general_purpose::STANDARD
            .decode(text("body_base64"))
            .expect("body"),
    }
}

/// A store holding the WhatsApp app secret where the provider reads it.
fn store_with(secret: Option<&str>) -> DynSecretsManager {
    let mut values = HashMap::new();
    if let Some(secret) = secret {
        let uri = crate::runner_host::secret_read_uris(
            "local",
            "default",
            None,
            PACK,
            "WHATSAPP_APP_SECRET",
        )
        .last()
        .cloned()
        .expect("uri");
        values.insert(uri, secret.as_bytes().to_vec());
    }
    Arc::new(crate::test_fixtures::FakeSecrets(values))
}

/// The request through the production verification seam. `unit` is unique
/// per call: the process-wide absent-secret memo is keyed on it.
async fn verify(
    store: &DynSecretsManager,
    signed: &Signed,
    unit: &str,
) -> Result<Verdict, StatusCode> {
    verify_inbound(
        Inbound {
            provider_type: PROVIDER,
            method: "POST",
            headers: &signed.headers,
            body: &signed.body,
            pack_id: PACK,
            unit_id: unit,
            tenant: "default",
            pack_non_secret: None,
            deployment_id: DeploymentId::new(),
        },
        store,
        "local",
    )
    .await
    .map_err(|refusal| refusal.status())
}

/// What `run_provider_inbound_pipeline` builds from the verdict.
fn origin(verdict: Verdict) -> Origin {
    Origin::new(PROVIDER, PACK, "default", Some("default")).verified_by_host(
        RequestVerification::from_gates(
            verdict == Verdict::Verified,
            verdict == Verdict::Unavailable,
        ),
    )
}

fn inbound_unit(store: Arc<FakeStore>) -> UnitAttachments {
    UnitAttachments::Enabled {
        pipeline: Arc::new(Pipeline::new(store, FakeFetcher::new(vec![ok(png(7))]))),
    }
}

#[tokio::test]
async fn a_verified_inbound_file_reaches_the_agent_and_its_own_file_leaves_as_a_link() {
    let request = signed();
    let secrets = store_with(Some(&request.secret));
    let verdict = verify(&secrets, &request, "unit-round-trip")
        .await
        .expect("a correctly signed request is admitted");
    assert_eq!(verdict, Verdict::Verified);

    // Inbound: the provider's fetch reference is read and stored.
    let door = Arc::new(FakeStore::default());
    let mut envelopes = vec![envelope(1)];
    prepare(
        Some(&inbound_unit(door.clone())),
        &mut envelopes,
        &origin(verdict),
    )
    .await;
    let ingress = &envelopes[0];
    assert_eq!(
        ingress.attachments[0].url.as_deref(),
        Some("artifact://id1")
    );
    assert_eq!(door.puts().len(), 1, "the inbound file was stored once");

    // The agent (stub) reads the stored file and writes one of its own
    // through the unit's port, which records the put for provenance.
    let fx = fixture(super::serve_link_testkit::StubReader::file(
        "application/pdf",
        Some("report.pdf"),
        AGENT_BYTES,
    ));
    fx.unit.recent.record(
        ID,
        PutRecord {
            mime_type: "application/pdf".into(),
            name: "report.pdf".into(),
            size_bytes: AGENT_BYTES.len() as u64,
            at: NOW - 5,
        },
    );
    let agent_output = json!({
        "reply": "Here is the summary.",
        "trail": [{"kind": "tool_call", "name": "write_report", "call_id": "c1",
                   "result": {"ok": true, "artifact": {"id": ID, "mime_type": "application/pdf"}}}],
        "terminated_by": "final_answer",
    });
    let mut reply = crate::messaging_app::base_reply_envelope(ingress);
    reply.text = Some("Here is the summary.".into());
    let side = OutboundSide::default();
    side.record(std::slice::from_ref(&reply), collect(&agent_output));

    // Outbound: the reply carries a signed link, never the raw id.
    let ctx = OutboundCtx {
        unit: Some(Arc::clone(&fx.unit)),
        base: LinkBase::Absolute(BASE.into()),
        enabled: true,
    };
    let out = prepare_replies(vec![reply], &side, ingress, PROVIDER, &ctx, NOW);
    assert_eq!(out.len(), 1);
    let text = out[0].text.as_deref().expect("reply text");
    assert!(!text.contains("artifact://"), "raw id leaked: {text}");
    let url = text
        .lines()
        .find_map(|line| line.strip_prefix("report.pdf: "))
        .expect("one link line");
    let path = url.strip_prefix(BASE).expect("absolute link");

    // The link serves the agent's bytes.
    let answer = fx.request(Method::GET, path, &limits()).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body.as_ref(), AGENT_BYTES);
}

#[tokio::test]
async fn a_badly_signed_request_never_reaches_the_pipeline() {
    let mut request = signed();
    request.body[10] ^= 0x01;
    let secrets = store_with(Some(&request.secret));
    assert_eq!(
        verify(&secrets, &request, "unit-round-trip-bad").await,
        Err(StatusCode::UNAUTHORIZED)
    );
}

#[tokio::test]
async fn an_unconfigured_channel_keeps_text_and_withholds_files() {
    let request = signed();
    let verdict = verify(&store_with(None), &request, "unit-round-trip-unset")
        .await
        .expect("admitted");
    assert_eq!(verdict, Verdict::NotConfigured);
    let door = Arc::new(FakeStore::default());
    let mut envelopes = vec![envelope(1)];
    prepare(
        Some(&inbound_unit(door.clone())),
        &mut envelopes,
        &origin(verdict),
    )
    .await;
    assert!(envelopes[0].attachments[0].url.is_none());
    assert_eq!(envelopes[0].text.as_deref(), Some("hello"));
    assert!(door.puts().is_empty(), "nothing was fetched or stored");
    assert!(
        note(&envelopes[0], 0)["message"]
            .as_str()
            .unwrap_or_default()
            .contains("not set up to verify"),
    );
}
