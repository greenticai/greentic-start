//! End to end against a REAL admin artifacts door (ignored; local only).
//!
//! The link modules are crate-private, so this lives in the library rather
//! than under `tests/`. It needs a local admin with the artifacts door live
//! (in-memory blob backend is fine) and a unit token minted with the
//! `artifacts` purpose:
//!
//! ```text
//! GREENTIC_E2E_ARTIFACT_DOOR=http://127.0.0.1:<port>/api/v1/ingest/artifacts \
//! GREENTIC_E2E_ARTIFACT_TOKEN=gtm_... \
//! GREENTIC_E2E_ARTIFACT_TOKEN_OTHER=gtm_...   # optional: another tenant's unit
//! cargo test -p greentic-start --lib artifacts::links_e2e -- --ignored --nocapture
//! ```
//!
//! Put a PNG through the unit's port (recorded as this unit's), build a
//! `dw.agent` reply whose trail carries the C5 result, shape it for WebChat
//! and Slack, then fetch each link through the route over the real reader:
//! 200 with the same bytes and the serving-rule headers; a tampered link and
//! another tenant's token both answer the one 404.

use std::sync::Arc;
use std::time::Duration;

use greentic_deploy_spec::ids::DeploymentId;
use greentic_ext_runtime::host_ports::{ArtifactPutRequest, HostCallContext};
use http_body_util::BodyExt;
use hyper::{Method, StatusCode};
use serde_json::json;

use super::boot::Door;
use super::host_access::HostArtifactAccess;
use super::ingest_testkit::{FakeStore, pipeline};
use super::link::{self, LinkKey, LinkPath};
use super::link_base::LinkBase;
use super::link_table::LinkUnit;
use super::outbound::{OutboundCtx, OutboundSide, collect, prepare_replies};
use super::outbound_tests::envelope;
use super::serve_link::{LinkRequest, serve_link, unix_now};
use super::serve_link_limits::LinkLimits;
use super::store::HttpArtifactStore;
use super::unit::{UnitAttachments, UnitCell};

const BASE: &str = "https://e2e.example";
/// A minimal PNG: signature, IHDR (1x1 RGBA), IDAT, IEND.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
    0x42, 0x60, 0x82,
];

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn door_access(door: &str, token: &str) -> HostArtifactAccess {
    let store = HttpArtifactStore::new(door.into(), token.into(), Duration::from_secs(20))
        .expect("store client");
    HostArtifactAccess::new(
        Arc::new(store),
        Door {
            url: door.into(),
            token: token.into(),
        },
    )
}

fn link_unit(access: &HostArtifactAccess, token: &str, cell: &Arc<UnitCell>) -> Arc<LinkUnit> {
    let deployment = DeploymentId::new().to_string();
    Arc::new(LinkUnit {
        key: LinkKey::derive(token, "e2e", "b1", &deployment),
        reader: access.reader().expect("reader"),
        recent: access.recent_puts(),
        cells: vec![Arc::downgrade(cell)],
        deployment,
    })
}

async fn fetch(unit: &Arc<LinkUnit>, path: &str) -> (StatusCode, hyper::HeaderMap, Vec<u8>) {
    let target = Arc::clone(unit);
    let response = serve_link(
        LinkRequest {
            method: &Method::GET,
            path,
            client: None,
            now: unix_now(),
            ttl_max: link::DEFAULT_TTL_SECS,
            links_on: true,
        },
        move |id: &DeploymentId| (id.to_string() == target.deployment).then(|| Arc::clone(&target)),
        &LinkLimits::new(2, 1 << 30),
    )
    .await;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, headers, body.to_vec())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a local admin artifacts door: see the module doc"]
async fn a_created_png_reaches_webchat_and_slack_and_downloads() {
    let door = env("GREENTIC_E2E_ARTIFACT_DOOR").expect("GREENTIC_E2E_ARTIFACT_DOOR");
    let token = env("GREENTIC_E2E_ARTIFACT_TOKEN").expect("GREENTIC_E2E_ARTIFACT_TOKEN");
    let cell = Arc::new(UnitCell::new(UnitAttachments::Enabled {
        pipeline: Arc::new(pipeline(vec![], Arc::new(FakeStore::default()))),
    }));
    let access = door_access(&door, &token).bound_to(&cell);
    let port = access.port();
    let id = tokio::task::spawn_blocking(move || {
        port.put(
            "greentic.media",
            &HostCallContext {
                tenant: Some("e2e".into()),
                ..Default::default()
            },
            ArtifactPutRequest {
                bytes: PNG.to_vec(),
                mime_type: "image/png".into(),
                name: "generated.png".into(),
            },
        )
    })
    .await
    .expect("join")
    .expect("the door stored the file");
    let unit = link_unit(&access, &token, &cell);
    let reply = json!({"reply": "Here.", "trail": [
        {"kind": "tool_call", "name": "generate_image", "call_id": "c1",
         "result": {"ok": true, "artifact": {"id": id, "mime_type": "image/png"}}}
    ]});
    let ctx = OutboundCtx {
        unit: Some(Arc::clone(&unit)),
        base: LinkBase::Absolute(BASE.into()),
        enabled: true,
    };
    let mut links = Vec::new();
    for provider in ["messaging.webchat-gui", "messaging.slack"] {
        let side = OutboundSide::default();
        let shaped = envelope("Here.");
        side.record(std::slice::from_ref(&shaped), collect(&reply));
        let out = prepare_replies(
            vec![shaped],
            &side,
            &envelope(""),
            provider,
            &ctx,
            unix_now(),
        );
        let url = if provider.starts_with("messaging.webchat") {
            out[0].attachments[0].url.clone().expect("typed url")
        } else {
            let text = out[0].text.clone().expect("text");
            text.lines()
                .find_map(|line| line.split(": ").nth(1).map(str::to_string))
                .expect("a link line")
        };
        println!("{provider}: link minted");
        links.push(url.strip_prefix(BASE).expect("absolute").to_string());
    }
    for path in &links {
        let (status, headers, body) = fetch(&unit, path).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, PNG);
        assert_eq!(headers["content-type"], "image/png");
        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert_eq!(headers["cache-control"], "private, no-store");
        assert!(
            headers["content-disposition"]
                .to_str()
                .unwrap()
                .starts_with("inline")
        );
        assert!(headers.get("set-cookie").is_none());
    }
    let mut tampered = LinkPath::parse(&links[0]).expect("own link parses");
    tampered.exp += 1;
    assert_eq!(
        fetch(&unit, &tampered.to_path()).await.0,
        StatusCode::NOT_FOUND
    );

    if let Some(other) = env("GREENTIC_E2E_ARTIFACT_TOKEN_OTHER") {
        // Another tenant's unit, its own key, signs a link to this id: the
        // door answers 404 for that token, and so does the route.
        let other_access = door_access(&door, &other).bound_to(&cell);
        let other_unit = link_unit(&other_access, &other, &cell);
        let path = link::mint(
            &other_unit.key,
            &other_unit.deployment,
            &id,
            unix_now(),
            link::DEFAULT_TTL_SECS,
        )
        .expect("mint")
        .to_path();
        assert_eq!(fetch(&other_unit, &path).await.0, StatusCode::NOT_FOUND);
    }
}
