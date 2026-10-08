//! The inbound hook lives in `revision_serve.rs`, which has no harness that
//! can drive a real provider. These checks read that file and pin WHERE the
//! hook sits, because each placement is a security property:
//! - after the request was authenticated (the verdict is what the hook reads),
//! - after the approval intercept (an approval click never reaches it),
//! - inside the task spawned after the HTTP ack (a webhook is never held up),
//! - before the first turn.

const SOURCE: &str = include_str!("../revision_serve.rs");

fn at(needle: &str) -> usize {
    let first = SOURCE
        .find(needle)
        .unwrap_or_else(|| panic!("`{needle}` is gone from revision_serve.rs"));
    assert_eq!(
        SOURCE.matches(needle).count(),
        1,
        "`{needle}` appears more than once; the order checks would be ambiguous"
    );
    first
}

#[test]
fn the_hook_runs_after_verification_and_the_approval_intercept() {
    let verified = at("crate::inbound_verify::verify_inbound(");
    let intercept = at("crate::approval_rail::intercept_inbound(");
    let spawn = at("run_provider_inbound_pipeline(\n                    pipeline_activation,");
    assert!(verified < intercept && intercept < spawn);
}

#[test]
fn the_hook_runs_in_the_detached_pipeline_before_the_first_turn() {
    let pipeline = at("async fn run_provider_inbound_pipeline(");
    let hook = at("crate::artifacts::hook::prepare(");
    let turns = at("    for ingress in &envelopes {\n        // Per-envelope flow targeting");
    assert!(pipeline < hook && hook < turns);
}

#[test]
fn foreign_whatsapp_numbers_are_dropped_before_the_pipeline_is_spawned() {
    let intercept = at("crate::approval_rail::intercept_inbound(");
    let check = at("crate::artifacts::instance_check::drop_foreign_numbers(");
    let spawn = at("run_provider_inbound_pipeline(\n                    pipeline_activation,");
    assert!(intercept < check && check < spawn);
}

#[test]
fn every_provider_route_body_is_read_under_the_ingress_limits() {
    let body = at("crate::http_ingress::limits::read_ingress_body(req, &effective_path)");
    let peer = at("crate::http_ingress::limits::PeerIp(peer.ip())");
    assert!(peer < body);
}

/// The agent reader and the extension port each unit's runtime loads with
/// come from THAT revision's own attachments decision (its own door and
/// token), taken just before its host options are built, and nowhere else:
/// never a host-wide `HostBuilder` port (the revision path never reads one),
/// never another unit's door.
#[test]
fn each_revision_loads_with_the_artifact_access_its_own_activation_decided() {
    const BOOT: &str = include_str!("../revision_boot.rs");
    let find = |needle: &str| {
        assert_eq!(
            BOOT.matches(needle).count(),
            1,
            "`{needle}` must appear exactly once in revision_boot.rs"
        );
        BOOT.find(needle).unwrap_or_default()
    };
    let decided = find("crate::artifacts::activate::activate_all(");
    let taken = find("host: unit_artifacts,");
    // Bound to the revision's own live cell, so a re-probe that ends
    // `purpose_not_granted` reaches the port it was loaded with.
    let cell = find("let unit_cell = Arc::new(crate::artifacts::unit::UnitCell::new(unit_state));");
    let bound = find("unit_artifacts.map(|access| access.bound_to(&unit_cell));");
    let passed =
        find("                unit_artifacts.as_ref(),\n            )\n            .await;");
    let loaded = find("let runtime = TenantRuntime::load_revision_with(");
    assert!(decided < taken && taken < passed && passed < loaded);
    assert!(taken < cell && cell < bound && bound < passed);
    for host_wide in ["with_ext_artifact_port", "with_artifact_reader"] {
        assert!(
            !BOOT.contains(host_wide),
            "`{host_wide}` belongs on the unit's RevisionHostOptions, not in revision_boot.rs"
        );
    }
}

/// A door that is down at boot leaves the revision serving and owes a
/// background re-probe holding the revision's OWN cell (weakly).
#[test]
fn a_revision_whose_door_is_down_gets_a_re_probe_over_its_own_cell() {
    const BOOT: &str = include_str!("../revision_boot.rs");
    let spawn = BOOT
        .find(
            "        if let Some(recovery) = unit_recovery {\n            \
             crate::artifacts::recovery::spawn_recovery(\n                Arc::downgrade(&unit_cell),",
        )
        .expect("the re-probe is spawned over this revision's cell");
    let insert = BOOT
        .find("attachments.insert((deployment_id, revision_id), unit_cell);")
        .expect("the same cell is what the table serves");
    assert!(spawn < insert);
}

/// Every activation names the channel classes whose files are not served.
#[test]
fn activation_names_the_unserved_channel_classes() {
    const BOOT: &str = include_str!("../revision_boot.rs");
    let warned = BOOT
        .find("crate::artifacts::unserved::warn_unserved_channels(env);")
        .expect("activation warns about unserved channels");
    let activated = BOOT
        .find("crate::artifacts::activate::activate_all(")
        .expect("activation");
    assert!(warned < activated);
}
