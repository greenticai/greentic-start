//! The per-unit link table: an entry only for a unit with a door, a metering
//! block and attachments on; one unit's key never verifies another's links.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use greentic_deploy_spec::ids::DeploymentId;

use crate::interop::metering::testkit::{TEST_TENANT, TEST_TOKEN, metering_with_token};

use super::boot::Door;
use super::host_access::HostArtifactAccess;
use super::ingest_testkit::{FakeStore, pipeline};
use super::link::{Verdict, mint, verify};
use super::link_table::{ArtifactLinkTable, LinkTableBuilder, LinkUnit};
use super::store::HttpArtifactStore;
use super::unit::{Off, UnitAttachments, UnitCell};

const ID: &str = "artifact://cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const NOW: u64 = 1_800_000_000;

fn access(token: &str) -> HostArtifactAccess {
    let store = HttpArtifactStore::new(
        "http://127.0.0.1:9/api/v1/ingest/artifacts".into(),
        token.into(),
        Duration::from_secs(1),
    )
    .expect("client");
    HostArtifactAccess::new(
        Arc::new(store),
        Door {
            url: "http://127.0.0.1:9/api/v1/ingest/artifacts".into(),
            token: token.into(),
        },
    )
}

fn enabled() -> Arc<UnitCell> {
    Arc::new(UnitCell::new(UnitAttachments::Enabled {
        pipeline: Arc::new(pipeline(vec![], Arc::new(FakeStore::default()))),
    }))
}

fn unit(token: &str, bundle: &str, deployment: DeploymentId, cell: &Arc<UnitCell>) -> LinkUnit {
    let metering = metering_with_token("http://127.0.0.1:9/x", token);
    LinkUnit::build(Some(&metering), &access(token), cell, bundle, deployment)
        .expect("a unit with a metering block builds")
}

fn table(entries: Vec<(DeploymentId, LinkUnit)>) -> ArtifactLinkTable {
    ArtifactLinkTable::new(
        entries
            .into_iter()
            .map(|(id, unit)| (id, Arc::new(unit)))
            .collect::<HashMap<_, _>>(),
    )
}

#[test]
fn an_unknown_deployment_has_no_signer() {
    let cell = enabled();
    let known = DeploymentId::new();
    let t = table(vec![(known, unit(TEST_TOKEN, "b1", known, &cell))]);
    assert!(t.get(&known).is_some());
    assert!(t.get(&DeploymentId::new()).is_none());
}

#[test]
fn a_unit_running_without_attachments_has_no_signer() {
    for off in [Off::NoDoor, Off::NotGranted, Off::DoorUnavailable] {
        let cell = Arc::new(UnitCell::new(UnitAttachments::Off(off)));
        let id = DeploymentId::new();
        let t = table(vec![(id, unit(TEST_TOKEN, "b1", id, &cell))]);
        assert!(t.get(&id).is_none(), "{off:?}");
    }
}

#[test]
fn a_re_probe_that_turns_attachments_off_withdraws_the_signer() {
    let cell = enabled();
    let id = DeploymentId::new();
    let t = table(vec![(id, unit(TEST_TOKEN, "b1", id, &cell))]);
    assert!(t.get(&id).is_some());
    cell.set(UnitAttachments::Off(Off::NotGranted));
    assert!(t.get(&id).is_none());
}

#[test]
fn a_dropped_unit_cell_withdraws_the_signer() {
    let cell = enabled();
    let id = DeploymentId::new();
    let t = table(vec![(id, unit(TEST_TOKEN, "b1", id, &cell))]);
    drop(cell);
    assert!(t.get(&id).is_none());
}

#[test]
fn no_metering_block_means_no_signer() {
    let cell = enabled();
    assert!(LinkUnit::build(None, &access(TEST_TOKEN), &cell, "b1", DeploymentId::new()).is_none());
}

#[test]
fn the_key_is_the_units_own_derived_key() {
    let cell = enabled();
    let id = DeploymentId::new();
    let t = table(vec![(id, unit(TEST_TOKEN, "b1", id, &cell))]);
    let signer = t.get(&id).expect("enabled");
    assert_eq!(signer.deployment, id.to_string());
    let reference = super::link::LinkKey::derive(TEST_TOKEN, TEST_TENANT, "b1", &id.to_string());
    let link = mint(&reference, &signer.deployment, ID, NOW, 3_600).expect("mint");
    assert!(matches!(
        verify(&signer.key, &link, NOW, 3_600),
        Verdict::Valid { .. }
    ));
}

#[test]
fn one_units_link_never_verifies_with_another_units_key() {
    let cell = enabled();
    let (a, b, c) = (
        DeploymentId::new(),
        DeploymentId::new(),
        DeploymentId::new(),
    );
    let t = table(vec![
        (a, unit("gtm_token-a", "bundle-a", a, &cell)),
        // Same token and bundle on another deployment: still a different key.
        (b, unit("gtm_token-a", "bundle-a", b, &cell)),
        (c, unit("gtm_token-c", "bundle-c", c, &cell)),
    ]);
    let unit_a = t.get(&a).expect("a");
    let link = mint(&unit_a.key, &unit_a.deployment, ID, NOW, 3_600).expect("mint");
    assert!(matches!(
        verify(&unit_a.key, &link, NOW, 3_600),
        Verdict::Valid { .. }
    ));
    for other in [b, c] {
        let other = t.get(&other).expect("other");
        assert!(matches!(
            verify(&other.key, &link, NOW, 3_600),
            Verdict::Invalid
        ));
    }
}

#[test]
fn each_unit_reads_its_own_provenance_record() {
    let cell = enabled();
    let (a, b) = (DeploymentId::new(), DeploymentId::new());
    let t = table(vec![
        (a, unit("gtm_token-a", "bundle-a", a, &cell)),
        (b, unit("gtm_token-b", "bundle-b", b, &cell)),
    ]);
    let record = super::recent_puts::PutRecord {
        mime_type: "image/png".into(),
        name: "a.png".into(),
        size_bytes: 1,
        at: NOW,
    };
    t.get(&a).expect("a").recent.record(ID, record);
    assert!(t.get(&a).expect("a").recent.lookup(ID, NOW, 60).is_some());
    assert!(t.get(&b).expect("b").recent.lookup(ID, NOW, 60).is_none());
}

#[test]
fn debug_prints_no_key_or_token() {
    let cell = enabled();
    let id = DeploymentId::new();
    let t = table(vec![(id, unit("gtm_secret_value", "b1", id, &cell))]);
    let printed = format!("{t:?} {:?}", t.get(&id).expect("enabled"));
    assert!(!printed.contains("gtm_secret_value"), "{printed}");
    let key_hex: String = t
        .get(&id)
        .expect("enabled")
        .key
        .expose_for_test()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(!printed.contains(&key_hex[..8]), "{printed}");
}

#[test]
fn the_signer_reads_the_record_the_units_port_writes() {
    let cell = enabled();
    let access = access(TEST_TOKEN);
    let metering = metering_with_token("http://127.0.0.1:9/x", TEST_TOKEN);
    let unit = LinkUnit::build(Some(&metering), &access, &cell, "b1", DeploymentId::new())
        .expect("builds");
    assert!(Arc::ptr_eq(&unit.recent, &access.recent_puts()));
}

/// Activation builds the table from each unit's own decision, and a
/// routing-only reload carries it over (no harness drives a real activation
/// with a door, so this pins the wiring in `revision_boot.rs`).
#[test]
fn activation_builds_and_a_routing_only_reload_carries_the_table() {
    const BOOT: &str = include_str!("../revision_boot.rs");
    let one = |needle: &str| {
        assert_eq!(BOOT.matches(needle).count(), 1, "`{needle}`");
        BOOT.find(needle).expect("present")
    };
    let shared = one("link_units.share_recent(deployment_id, access.bound_to(&unit_cell))");
    let add = one("link_units.add_revision(");
    let options = one("unit_artifacts.as_ref(),\n            )\n            .await;");
    let routing = one("artifact_links: link_units.finish(),");
    // The shared record is in place before the revision's port is built.
    assert!(shared < add && add < options && options < routing);
    one("artifact_links: prev.artifact_links.clone(),");
}

fn put_ok_body() -> String {
    format!(
        r#"{{"id":"{ID}","sha256":"ff","size_bytes":2,"kind":"document","mime_type":"text/plain"}}"#
    )
}

fn stub_access(
    stub: &crate::interop::metering::testkit::StubAdmin,
    token: &str,
) -> HostArtifactAccess {
    let store = HttpArtifactStore::new(stub.url.clone(), token.into(), Duration::from_secs(2))
        .expect("client");
    HostArtifactAccess::new(
        Arc::new(store),
        Door {
            url: stub.url.clone(),
            token: token.into(),
        },
    )
}

/// A traffic split: two revisions of ONE deployment. A file the canary
/// revision's extension creates is linkable, because every revision of a
/// deployment writes into the deployment's one provenance record.
#[tokio::test(flavor = "multi_thread")]
async fn a_put_on_the_second_revision_of_a_split_is_linkable() {
    use greentic_ext_runtime::host_ports::{ArtifactPutRequest, HostCallContext};

    let stub = crate::interop::metering::testkit::StubAdmin::answering(
        "HTTP/1.1 200 OK",
        "",
        &put_ok_body(),
    )
    .await;
    let metering = metering_with_token("http://127.0.0.1:9/x", TEST_TOKEN);
    let deployment = DeploymentId::new();
    let mut builder = LinkTableBuilder::default();
    let (cell_a, cell_b) = (enabled(), enabled());
    for cell in [&cell_a, &cell_b] {
        let shared =
            builder.share_recent(deployment, stub_access(&stub, TEST_TOKEN).bound_to(cell));
        let metering = builder.needs_signer(&deployment).then_some(&metering);
        builder.add_revision(deployment, metering, &shared, cell, "b1");
        if Arc::ptr_eq(cell, &cell_b) {
            let port = shared.port();
            let ctx = HostCallContext {
                tenant: Some(TEST_TENANT.into()),
                ..Default::default()
            };
            tokio::task::spawn_blocking(move || {
                port.put(
                    "greentic.media",
                    &ctx,
                    ArtifactPutRequest {
                        bytes: b"hi".to_vec(),
                        mime_type: "text/plain".into(),
                        name: "a.txt".into(),
                    },
                )
            })
            .await
            .expect("join")
            .expect("stored");
        }
    }
    let table = builder.finish();
    let unit = table.get(&deployment).expect("signer");
    assert!(unit.recent.lookup(ID, unix_now(), 60).is_some());
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// The signer serves while ANY revision of the deployment has attachments
/// on: the first revision's door may be down while the canary's is up.
#[test]
fn the_gate_follows_every_revision_of_the_deployment() {
    let metering = metering_with_token("http://127.0.0.1:9/x", TEST_TOKEN);
    let deployment = DeploymentId::new();
    let first = Arc::new(UnitCell::new(UnitAttachments::Off(Off::DoorUnavailable)));
    let second = enabled();
    let mut builder = LinkTableBuilder::default();
    for cell in [&first, &second] {
        let shared = builder.share_recent(deployment, access(TEST_TOKEN).bound_to(cell));
        let metering = builder.needs_signer(&deployment).then_some(&metering);
        builder.add_revision(deployment, metering, &shared, cell, "b1");
    }
    let table = builder.finish();
    assert!(
        table.get(&deployment).is_some(),
        "second revision is enabled"
    );
    second.set(UnitAttachments::Off(Off::NotGranted));
    assert!(table.get(&deployment).is_none(), "no revision is enabled");
    first.set(UnitAttachments::Enabled {
        pipeline: Arc::new(pipeline(vec![], Arc::new(FakeStore::default()))),
    });
    assert!(table.get(&deployment).is_some(), "first revision recovered");
}

/// Each deployment keeps its own record even through the builder.
#[test]
fn two_deployments_never_share_a_record() {
    let mut builder = LinkTableBuilder::default();
    let (a, b) = (DeploymentId::new(), DeploymentId::new());
    let ra = builder.share_recent(a, access(TEST_TOKEN)).recent_puts();
    let ra2 = builder.share_recent(a, access(TEST_TOKEN)).recent_puts();
    let rb = builder.share_recent(b, access(TEST_TOKEN)).recent_puts();
    assert!(Arc::ptr_eq(&ra, &ra2));
    assert!(!Arc::ptr_eq(&ra, &rb));
}
