use super::*;
use crate::messaging_app::AppFlowInfo;
use greentic_deploy_spec::BundleId;
use ulid::Ulid;

const META: &str = include_str!("../../tests/fixtures/triggers/triggers_v1_meta_webhook.json");
const CRON: &str = include_str!("../../tests/fixtures/triggers/triggers_v1_cron.json");
const GENERIC: &str =
    include_str!("../../tests/fixtures/triggers/triggers_v1_generic_webhook.json");

fn scope() -> RevisionScope {
    RevisionScope {
        deployment_id: DeploymentId(Ulid::new()),
        bundle_id: BundleId::new("bundle"),
        revision_id: RevisionId(Ulid::new()),
    }
}

fn flow(id: &str, nodes: &[&str]) -> AppFlowInfo {
    AppFlowInfo {
        id: id.into(),
        kind: "messaging".into(),
        subscribes_to: Vec::new(),
        node_ids: nodes.iter().map(|n| n.to_string()).collect(),
    }
}

#[test]
fn a_webhook_trigger_is_routed_under_every_deployment_prefix() {
    let s = scope();
    let loaded = load_pack(
        META.as_bytes(),
        "pack.acme.community",
        &[flow("main", &["normalize_event"])],
        &s,
        "acme",
    )
    .expect("loads");
    let prefixes = HashMap::from([(s.deployment_id, vec!["/".to_string(), "/bot".to_string()])]);
    let table = TriggerTable::build(loaded, &prefixes);

    assert_eq!(
        table.webhook_trigger_for(s.deployment_id, "/trigger/threads_replies"),
        Some("threads_replies")
    );
    assert_eq!(
        table.webhook_trigger_for(s.deployment_id, "/bot/trigger/threads_replies/"),
        Some("threads_replies")
    );
    // Never a prefix match: extra segments are a different path.
    assert_eq!(
        table.webhook_trigger_for(s.deployment_id, "/trigger/threads_replies/extra"),
        None
    );
    let status = table.status_json();
    assert_eq!(
        status[0]["webhook"]["routes"],
        serde_json::json!(["/bot/trigger/threads_replies", "/trigger/threads_replies"])
    );
    // Never another deployment's trigger.
    assert_eq!(
        table.webhook_trigger_for(DeploymentId(Ulid::new()), "/trigger/threads_replies"),
        None
    );
}

#[test]
fn a_cron_trigger_has_no_webhook_route() {
    let s = scope();
    let loaded = load_pack(
        CRON.as_bytes(),
        "pack.acme.reports",
        &[flow("main", &["collect_mentions"])],
        &s,
        "acme",
    )
    .expect("loads");
    let table = TriggerTable::build(loaded, &HashMap::new());
    assert_eq!(table.cron_entries().count(), 1);
    let status = table.status_json();
    assert_eq!(status[0]["kind"], "cron");
    assert_eq!(status[0]["cron"]["timezone"], "Europe/Amsterdam");
    assert!(status[0].get("webhook").is_none());
}

#[test]
fn a_trigger_naming_a_missing_flow_refuses_the_pack() {
    let err = load_pack(
        META.as_bytes(),
        "pack.acme.community",
        &[flow("other", &[])],
        &scope(),
        "acme",
    )
    .unwrap_err();
    assert!(err.to_string().contains("does not contain"), "{err:#}");
}

#[test]
fn an_entry_node_the_flow_does_not_declare_refuses_the_pack() {
    let err = load_pack(
        META.as_bytes(),
        "pack.acme.community",
        &[flow("main", &["something_else"])],
        &scope(),
        "acme",
    )
    .unwrap_err();
    assert!(err.to_string().contains("normalize_event"), "{err:#}");
}

#[test]
fn an_empty_node_table_is_not_read_as_a_missing_entry_node() {
    assert!(
        load_pack(
            META.as_bytes(),
            "pack.acme.community",
            &[flow("main", &[])],
            &scope(),
            "acme",
        )
        .is_ok()
    );
}

#[test]
fn allowed_sources_marks_the_trigger_unavailable_instead_of_serving_it_unchecked() {
    let loaded = load_pack(
        GENERIC.as_bytes(),
        "pack.acme.orders",
        &[flow("intake", &["classify_order"])],
        &scope(),
        "acme",
    )
    .expect("loads");
    assert!(loaded[0].unavailable.is_some());
}

#[test]
fn for_revision_returns_only_that_revisions_declaration() {
    let s = scope();
    let loaded = load_pack(
        META.as_bytes(),
        "pack.acme.community",
        &[flow("main", &["normalize_event"])],
        &s,
        "acme",
    )
    .expect("loads");
    let table = TriggerTable::build(loaded, &HashMap::new());
    assert!(
        table
            .for_revision(s.deployment_id, s.revision_id, "threads_replies")
            .is_some()
    );
    assert!(
        table
            .for_revision(s.deployment_id, RevisionId(Ulid::new()), "threads_replies")
            .is_none()
    );
}

#[test]
fn trigger_path_mirrors_the_provider_webhook_prefix_rules() {
    assert_eq!(trigger_path("", "x"), "/trigger/x");
    assert_eq!(trigger_path("/", "x"), "/trigger/x");
    assert_eq!(trigger_path("bot", "x"), "/bot/trigger/x");
    assert_eq!(trigger_path("/bot/", "x"), "/bot/trigger/x");
}
