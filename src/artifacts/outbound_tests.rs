//! Turning a reply's C5 tool results into delivered files: collection, the
//! provenance gate, per-channel shape, and the raw-id strip.

use std::collections::BTreeMap;
use std::sync::Arc;

use greentic_deploy_spec::ids::DeploymentId;
use greentic_types::messaging::extensions::ext_keys;
use greentic_types::{Attachment, ChannelMessageEnvelope, TenantCtx};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::ingest_testkit::{FakeStore, pipeline};
use super::link::{self, LinkKey, LinkPath, Verdict};
use super::link_base::LinkBase;
use super::link_table::LinkUnit;
use super::outbound::{
    C5Ref, LINKS_OFF, MAX_OUTBOUND, NO_PUBLIC_ADDRESS, NOT_FROM_THIS_WORKER, OutboundCtx,
    OutboundSide, Undeliverable, collect, prepare_replies, resolve,
};
use super::outbound_shape::{shape, strip_raw_artifact_urls};
use super::recent_puts::{PutRecord, RecentPuts};
use super::unit::{UnitAttachments, UnitCell};

const FIXTURE: &str = include_str!("../../tests/fixtures/attachments-v1/outbound-tool-result.json");
const CHECKSUMS: &str = include_str!("../../tests/fixtures/attachments-v1/CHECKSUMS.sha256");
const FIXTURE_ID: &str =
    "artifact://0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
const A: &str = "artifact://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "artifact://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const NOW: u64 = 1_800_000_000;
const TTL: u64 = 86_400;
const BASE: &str = "https://svc.example";

fn hex_id(n: u64) -> String {
    format!("artifact://{n:064x}")
}

fn tool_step(result: Value) -> Value {
    json!({"kind": "tool_call", "name": "generate_image", "call_id": "c1", "result": result})
}

fn ok_result(id: &str) -> Value {
    json!({"ok": true, "artifact": {"id": id, "mime_type": "image/png", "name": "x.png"}})
}

fn agent_reply(steps: Vec<Value>) -> Value {
    json!({"reply": "Done.", "trail": steps, "terminated_by": "final_answer"})
}

pub(super) fn ids(refs: &[C5Ref]) -> Vec<&str> {
    refs.iter().map(|r| r.id.as_str()).collect()
}

#[test]
fn the_shared_fixture_is_byte_identical_to_the_designer_copy() {
    let digest: String = Sha256::digest(FIXTURE.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let line = CHECKSUMS
        .lines()
        .find(|line| line.ends_with("outbound-tool-result.json"))
        .expect("checksum line");
    assert_eq!(line.split_whitespace().next(), Some(digest.as_str()));
}

#[test]
fn the_c6_fixture_in_a_trail_names_its_file() {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("fixture json");
    assert_eq!(
        ids(&collect(&agent_reply(vec![tool_step(fixture)]))),
        [FIXTURE_ID]
    );
}

#[test]
fn only_successful_tool_calls_with_a_valid_id_count() {
    let payload = agent_reply(vec![
        tool_step(ok_result(A)),
        tool_step(json!({"ok": false, "artifact": {"id": B}})),
        json!({"kind": "tool_call_reused", "name": "generate_image", "call_id": "c2"}),
        json!({"kind": "reply", "result": ok_result(B)}),
        tool_step(ok_result("artifact://00ff")),
        tool_step(ok_result("https://evil.example/x.png")),
        tool_step(json!({"artifact": {"id": B}})),
    ]);
    assert_eq!(ids(&collect(&payload)), [A]);
}

#[test]
fn a_string_encoded_result_is_read() {
    let raw = ok_result(A).to_string();
    assert_eq!(
        ids(&collect(&agent_reply(vec![tool_step(json!(raw))]))),
        [A]
    );
}

#[test]
fn at_most_five_distinct_files() {
    let mut steps: Vec<Value> = (0..7).map(|n| tool_step(ok_result(&hex_id(n)))).collect();
    steps.push(tool_step(ok_result(&hex_id(0))));
    let refs = collect(&agent_reply(steps));
    assert_eq!(refs.len(), MAX_OUTBOUND);
    let dup = collect(&agent_reply(vec![
        tool_step(ok_result(A)),
        tool_step(ok_result(A)),
    ]));
    assert_eq!(ids(&dup), [A]);
}

#[test]
fn a_top_level_or_parked_artifact_counts() {
    assert_eq!(ids(&collect(&json!({"artifact": {"id": A}}))), [A]);
    assert_eq!(
        ids(&collect(&json!({"response": {"artifact": {"id": B}}}))),
        [B]
    );
}

#[test]
fn a_flow_authored_full_envelope_cannot_ask_for_a_link() {
    let mut payload = serde_json::to_value(envelope("text")).expect("envelope json");
    payload["trail"] = json!([tool_step(ok_result(A))]);
    payload["artifact"] = json!({"id": B});
    assert!(collect(&payload).is_empty());
}

pub(super) fn envelope(text: &str) -> ChannelMessageEnvelope {
    ChannelMessageEnvelope {
        id: "reply-1".into(),
        tenant: TenantCtx::new("local".try_into().unwrap(), "acme".try_into().unwrap()),
        channel: "conv-1".into(),
        session_id: "conv-1".into(),
        reply_scope: None,
        from: None,
        to: Vec::new(),
        correlation_id: None,
        text: (!text.is_empty()).then(|| text.to_string()),
        attachments: Vec::new(),
        metadata: BTreeMap::from([("route".to_string(), "r1".to_string())]),
        extensions: BTreeMap::new(),
    }
}

struct Unit {
    unit: Arc<LinkUnit>,
    _cell: Arc<UnitCell>,
}

fn unit() -> Unit {
    let cell = Arc::new(UnitCell::new(UnitAttachments::Enabled {
        pipeline: Arc::new(pipeline(vec![], Arc::new(FakeStore::default()))),
    }));
    let deployment = DeploymentId::new().to_string();
    let recent = Arc::new(RecentPuts::default());
    recent.record(
        A,
        PutRecord {
            mime_type: "image/png".into(),
            name: "cat <b>.png".into(),
            size_bytes: 42,
            at: NOW - 10,
        },
    );
    struct Nobody;
    impl greentic_aw_runtime::ArtifactReader for Nobody {
        fn get<'a>(
            &'a self,
            _id: &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            greentic_aw_runtime::ArtifactBytes,
                            greentic_aw_runtime::ArtifactError,
                        >,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Err(greentic_aw_runtime::ArtifactError::NotFound) })
        }
    }
    Unit {
        unit: Arc::new(LinkUnit {
            key: LinkKey::derive("gtm_t", "acme", "b1", &deployment),
            reader: Arc::new(Nobody),
            recent,
            cells: vec![Arc::downgrade(&cell)],
            deployment,
        }),
        _cell: cell,
    }
}

fn ctx(unit: &Unit, base: LinkBase, enabled: bool) -> OutboundCtx {
    OutboundCtx {
        unit: Some(Arc::clone(&unit.unit)),
        base,
        enabled,
    }
}

fn absolute() -> LinkBase {
    LinkBase::Absolute(BASE.into())
}

#[test]
fn a_file_this_unit_created_is_signed_with_the_door_record() {
    let u = unit();
    let refs = [C5Ref { id: A.into() }];
    let resolved = resolve(&refs, &ctx(&u, absolute(), true), false, NOW, TTL);
    assert!(resolved.refused.is_empty());
    let file = &resolved.files[0];
    assert_eq!(file.mime_type, "image/png");
    assert_eq!(
        file.name, "cat <b>.png",
        "the record's name, not the tool's"
    );
    assert_eq!(file.size_bytes, 42);
    let path = file.url.strip_prefix(BASE).expect("absolute");
    let link = LinkPath::parse(path).expect("well-formed link");
    match link::verify(&u.unit.key, &link, NOW, TTL) {
        Verdict::Valid { artifact_id } => assert_eq!(artifact_id, A),
        Verdict::Invalid => panic!("the minted link must verify"),
    }
}

#[test]
fn every_refusal_has_its_reason() {
    let u = unit();
    let refs = [C5Ref { id: B.into() }];
    let r = resolve(&refs, &ctx(&u, absolute(), true), false, NOW, TTL);
    assert_eq!(r.refused, [Undeliverable::NotFromThisWorker]);
    // Recorded, but longer ago than the link TTL.
    let r = resolve(
        &[C5Ref { id: A.into() }],
        &ctx(&u, absolute(), true),
        false,
        NOW + TTL,
        TTL,
    );
    assert_eq!(r.refused, [Undeliverable::NotFromThisWorker]);
    let none = OutboundCtx {
        unit: None,
        base: absolute(),
        enabled: true,
    };
    let r = resolve(&[C5Ref { id: A.into() }], &none, false, NOW, TTL);
    assert_eq!(r.refused, [Undeliverable::LinksOff]);
    let r = resolve(
        &[C5Ref { id: A.into() }],
        &ctx(&u, absolute(), false),
        true,
        NOW,
        TTL,
    );
    assert_eq!(r.refused, [Undeliverable::LinksOff]);
    let r = resolve(
        &[C5Ref { id: A.into() }],
        &ctx(&u, LinkBase::RelativeOnly, true),
        false,
        NOW,
        TTL,
    );
    assert_eq!(r.refused, [Undeliverable::NoPublicAddress]);
    let r = resolve(
        &[C5Ref { id: A.into() }],
        &ctx(&u, LinkBase::RelativeOnly, true),
        true,
        NOW,
        TTL,
    );
    assert!(
        r.files[0].url.starts_with(link::LINK_PREFIX),
        "WebChat gets a relative link"
    );
}

fn resolved_one(u: &Unit) -> super::outbound::Resolved {
    resolve(
        &[C5Ref { id: A.into() }],
        &ctx(u, absolute(), true),
        false,
        NOW,
        TTL,
    )
}

#[test]
fn webchat_gets_a_typed_attachment_and_never_a_raw_id() {
    let u = unit();
    let resolved = resolved_one(&u);
    let url = resolved.files[0].url.clone();
    let mut env = envelope("Here you go.");
    env.extensions.insert(
        ext_keys::ATTACHMENTS.to_string(),
        json!([{"contentType": "text/plain", "contentUrl": A}]),
    );
    strip_raw_artifact_urls(&mut env);
    let out = shape(env, "messaging.webchat-gui", &resolved);
    assert_eq!(out.len(), 1);
    let env = &out[0];
    assert_eq!(env.text.as_deref(), Some("Here you go."));
    assert_eq!(env.attachments.len(), 1);
    assert_eq!(env.attachments[0].url.as_deref(), Some(url.as_str()));
    assert_eq!(env.attachments[0].mime_type, "image/png");
    let raw = env.extensions[ext_keys::ATTACHMENTS].as_array().unwrap();
    assert_eq!(raw.len(), 1);
    assert_eq!(raw[0]["contentUrl"], json!(url));
    let serialised = serde_json::to_string(env).unwrap();
    assert!(!serialised.contains("artifact://"), "{serialised}");
}

#[test]
fn webchat_with_no_text_says_which_file() {
    let u = unit();
    let out = shape(envelope(""), "messaging.webchat", &resolved_one(&u));
    assert_eq!(
        out[0].text.as_deref(),
        Some("Here is your file: cat _b_.png")
    );
}

#[test]
fn other_channels_get_the_link_in_the_text() {
    let u = unit();
    let resolved = resolved_one(&u);
    let url = &resolved.files[0].url;
    for provider in [
        "messaging.slack",
        "messaging.telegram",
        "messaging.whatsapp",
        "messaging.webex",
        "messaging.teams",
    ] {
        let out = shape(envelope("Done."), provider, &resolved);
        assert_eq!(out.len(), 1, "{provider}");
        assert!(
            out[0].attachments.is_empty(),
            "{provider}: no typed attachment"
        );
        assert_eq!(
            out[0].text.as_deref(),
            Some(format!("Done.\n\ncat _b_.png: {url}").as_str()),
            "{provider}"
        );
    }
}

#[test]
fn a_card_keeps_its_message_and_the_links_follow() {
    let u = unit();
    let resolved = resolved_one(&u);
    let mut env = envelope("");
    env.metadata
        .insert("adaptive_card".into(), "{\"type\":\"AdaptiveCard\"}".into());
    env.extensions.insert(
        ext_keys::ADAPTIVE_CARD.into(),
        json!({"type": "AdaptiveCard"}),
    );
    let out = shape(env.clone(), "messaging.telegram", &resolved);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0], env, "the card message is unchanged");
    let follow = &out[1];
    assert_ne!(follow.id, env.id);
    assert_eq!(follow.session_id, env.session_id);
    assert_eq!(follow.metadata.get("route").map(String::as_str), Some("r1"));
    assert!(follow.extensions.is_empty() && !follow.metadata.contains_key("adaptive_card"));
    assert_eq!(
        follow.text.as_deref(),
        Some(format!("cat _b_.png: {}", resolved.files[0].url).as_str())
    );
}

#[test]
fn refused_files_become_their_sentences_once() {
    let u = unit();
    let refs = [C5Ref { id: B.into() }, C5Ref { id: hex_id(9) }];
    let resolved = resolve(&refs, &ctx(&u, absolute(), true), false, NOW, TTL);
    let out = shape(envelope("Done."), "messaging.slack", &resolved);
    assert_eq!(
        out[0].text.as_deref(),
        Some(format!("Done.\n\n{NOT_FROM_THIS_WORKER}").as_str())
    );
    let off = resolve(&refs[..1], &ctx(&u, absolute(), false), true, NOW, TTL);
    let out = shape(envelope(""), "messaging.webchat", &off);
    assert_eq!(out[0].text.as_deref(), Some(LINKS_OFF));
    let none = resolve(
        &[C5Ref { id: A.into() }],
        &ctx(&u, LinkBase::RelativeOnly, true),
        false,
        NOW,
        TTL,
    );
    let out = shape(envelope("Done."), "messaging.teams", &none);
    assert!(out[0].text.as_deref().unwrap().ends_with(NO_PUBLIC_ADDRESS));
    assert!(!out[0].text.as_deref().unwrap().contains("/v1/artifacts/"));
}

#[test]
fn a_file_only_turn_is_still_delivered() {
    let u = unit();
    let side = OutboundSide::default();
    side.record(&[], vec![C5Ref { id: A.into() }]);
    let mut ingress = envelope("draw a cat");
    ingress.id = "inbound".into();
    let out = prepare_replies(
        Vec::new(),
        &side,
        &ingress,
        "messaging.webchat-gui",
        &ctx(&u, absolute(), true),
        NOW,
    );
    assert_eq!(out.len(), 1);
    assert_ne!(out[0].id, "inbound");
    assert_eq!(out[0].attachments.len(), 1);
    assert_eq!(
        out[0].text.as_deref(),
        Some("Here is your file: cat _b_.png")
    );
}

#[test]
fn every_reply_is_stripped_even_without_files() {
    let u = unit();
    let mut forged = envelope("x");
    forged.attachments.push(Attachment {
        mime_type: "image/png".into(),
        url: Some(B.into()),
        ..Default::default()
    });
    let out = prepare_replies(
        vec![forged],
        &OutboundSide::default(),
        &envelope(""),
        "messaging.slack",
        &ctx(&u, absolute(), true),
        NOW,
    );
    assert!(out[0].attachments.is_empty());
}
