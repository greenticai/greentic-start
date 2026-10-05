//! Per-revision app-pack index and revision-qualified index scope.

use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use tempfile::tempdir;
use zip::write::FileOptions;

use super::*;
use crate::fast2flow::Fast2FlowConfig;
use crate::fast2flow::gate::BundleCapabilityGate;
use crate::runner_host::OperatorContext;

const BUNDLE: &str = "fast2flow";

/// A pack with the given messaging flows, plus `assets/intent-index.json`
/// carrying `index` when given.
fn write_pack(path: &Path, pack_id: &str, flows: &[&str], index: Option<&str>) {
    use greentic_types::pack_manifest::{PackFlowEntry, PackKind, PackManifest, PackSignatures};
    use greentic_types::{Flow, FlowId, FlowKind, PackId};

    let entry = |id: &str| PackFlowEntry {
        id: FlowId::new(id).expect("flow id"),
        kind: FlowKind::Messaging,
        flow: Flow {
            schema_version: "flow-v1".to_string(),
            id: FlowId::new(id).expect("flow id"),
            kind: FlowKind::Messaging,
            entrypoints: std::collections::BTreeMap::from([(
                "default".to_string(),
                serde_json::Value::Null,
            )]),
            nodes: Default::default(),
            metadata: Default::default(),
        },
        tags: vec![],
        entrypoints: vec!["default".to_string()],
    };
    let manifest = PackManifest {
        agents: Default::default(),
        schema_version: "pack-v1".into(),
        pack_id: PackId::new(pack_id).expect("pack id"),
        name: Some(pack_id.into()),
        version: semver::Version::parse("0.1.0").expect("version"),
        kind: PackKind::Application,
        publisher: "demo".into(),
        components: Vec::new(),
        flows: flows.iter().map(|f| entry(f)).collect(),
        dependencies: Vec::new(),
        capabilities: Vec::new(),
        secret_requirements: Vec::new(),
        signatures: PackSignatures::default(),
        bootstrap: None,
        extensions: None,
    };
    let mut zip = zip::ZipWriter::new(std::fs::File::create(path).expect("create pack"));
    zip.start_file("manifest.cbor", FileOptions::<()>::default())
        .expect("manifest");
    zip.write_all(&greentic_types::encode_pack_manifest(&manifest).expect("encode"))
        .expect("write manifest");
    if let Some(index) = index {
        zip.start_file("assets/intent-index.json", FileOptions::<()>::default())
            .expect("index");
        zip.write_all(index.as_bytes()).expect("write index");
    }
    zip.finish().expect("finish");
}

fn add(
    packs: &mut RevisionAppPacks,
    cache: &mut AppPackInfoCache,
    revision: RevisionId,
    paths: &[PathBuf],
) {
    let infos = cache.infos(paths);
    packs.insert_revision(
        BUNDLE,
        revision,
        infos.iter().map(|(p, i)| (p.as_path(), i)),
    );
}

#[test]
fn two_revisions_of_one_bundle_resolve_to_their_own_app_pack() {
    let dir = tempdir().expect("tempdir");
    let a = dir.path().join("a.gtpack");
    let b = dir.path().join("b.gtpack");
    write_pack(&a, "sales-v1", &["default"], None);
    write_pack(&b, "sales-v2", &["default"], None);
    let (rev_a, rev_b) = (RevisionId::new(), RevisionId::new());

    let mut packs = RevisionAppPacks::default();
    let mut cache = AppPackInfoCache::default();
    add(&mut packs, &mut cache, rev_a, std::slice::from_ref(&a));
    add(&mut packs, &mut cache, rev_b, std::slice::from_ref(&b));

    let got_a = packs.get(BUNDLE, rev_a).expect("rev a");
    let got_b = packs.get(BUNDLE, rev_b).expect("rev b");
    assert_eq!(got_a.pack_id, "sales-v1");
    assert_eq!(got_a.pack_path, a);
    assert_eq!(got_a.revision_id, rev_a);
    assert_eq!(got_b.pack_id, "sales-v2");
    assert_eq!(got_b.pack_path, b);
    assert_eq!(got_b.info.flows[0].id, "default");
    assert_eq!(packs.len(), 2);
    assert!(packs.get("other-bundle", rev_a).is_none());
}

#[test]
fn revisions_pinning_the_same_pack_file_read_it_once() {
    let dir = tempdir().expect("tempdir");
    let a = dir.path().join("a.gtpack");
    write_pack(&a, "sales", &["default"], None);
    let mut packs = RevisionAppPacks::default();
    let mut cache = AppPackInfoCache::default();
    add(
        &mut packs,
        &mut cache,
        RevisionId::new(),
        std::slice::from_ref(&a),
    );
    add(
        &mut packs,
        &mut cache,
        RevisionId::new(),
        std::slice::from_ref(&a),
    );
    assert_eq!(cache.reads(), 1);
    assert_eq!(packs.len(), 2);
}

#[test]
fn only_the_pack_resolving_a_default_flow_is_the_app_pack() {
    let dir = tempdir().expect("tempdir");
    let provider = dir.path().join("provider.gtpack");
    let app = dir.path().join("app.gtpack");
    let broken = dir.path().join("broken.gtpack");
    write_pack(&provider, "messaging-webchat", &[], None);
    write_pack(&app, "sales", &["default", "refund"], None);
    std::fs::write(&broken, b"not a zip").expect("broken");
    let rev = RevisionId::new();

    let mut packs = RevisionAppPacks::default();
    add(
        &mut packs,
        &mut AppPackInfoCache::default(),
        rev,
        &[provider, broken, app.clone()],
    );
    let got = packs.get(BUNDLE, rev).expect("app pack");
    assert_eq!(got.pack_id, "sales");
    assert_eq!(got.pack_path, app);
}

#[test]
fn two_packs_claiming_a_default_flow_leave_no_app_pack() {
    let dir = tempdir().expect("tempdir");
    let a = dir.path().join("a.gtpack");
    let b = dir.path().join("b.gtpack");
    write_pack(&a, "sales", &["default"], None);
    write_pack(&b, "support", &["main"], None);
    let rev = RevisionId::new();
    let mut packs = RevisionAppPacks::default();
    add(&mut packs, &mut AppPackInfoCache::default(), rev, &[a, b]);
    assert!(packs.get(BUNDLE, rev).is_none());
    assert!(packs.is_empty());
}

/// Mirror of `fast2flow_contracts::validate_scope` (greentic-fast2flow
/// `ec88623`): the routing host refuses any other shape.
fn host_accepts_scope(scope: &str) -> bool {
    if scope.is_empty() || scope.len() > 512 {
        return false;
    }
    let Some((left, right)) = scope.split_once(':') else {
        return false;
    };
    if right.contains(':') || left.is_empty() || right.is_empty() {
        return false;
    }
    [left, right].iter().all(|seg| {
        seg.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            && !seg.starts_with('.')
            && !seg.ends_with('.')
    })
}

#[test]
fn revision_scope_is_one_the_routing_host_accepts() {
    let rev = RevisionId::new();
    let scope = revision_index_scope("acme", Some("sales"), BUNDLE, rev);
    assert!(scope.starts_with("acme:sales--"), "{scope}");
    assert!(host_accepts_scope(&scope), "{scope}");
    // The readable four-part form would be refused by the host.
    assert!(!host_accepts_scope(&format!("acme:sales:{BUNDLE}:{rev}")));
    // Hostile or awkward ids still produce a valid, traversal-free scope.
    for (tenant, team) in [
        ("../etc", Some("a/b")),
        (".", Some("..")),
        ("", None),
        ("tenant:x", Some("team:y")),
    ] {
        let scope = revision_index_scope(tenant, team, "b/../c", rev);
        assert!(host_accepts_scope(&scope), "{scope}");
        assert!(!scope.contains('/'), "{scope}");
    }
    assert_eq!(
        revision_index_scope("acme", None, BUNDLE, rev),
        revision_index_scope("acme", Some("default"), BUNDLE, rev)
    );
}

#[test]
fn revision_scope_is_distinct_per_bundle_and_revision_and_stable() {
    let (r1, r2) = (RevisionId::new(), RevisionId::new());
    let s = |tenant: &str, bundle: &str, rev| revision_index_scope(tenant, None, bundle, rev);
    assert_eq!(s("acme", BUNDLE, r1), s("acme", BUNDLE, r1));
    assert_ne!(s("acme", BUNDLE, r1), s("acme", BUNDLE, r2));
    assert_ne!(s("acme", BUNDLE, r1), s("acme", "other", r1));
    // Sanitizing collapses `a/b` and `a-b` to the same text; the digest does not.
    assert_ne!(s("a/b", BUNDLE, r1), s("a-b", BUNDLE, r1));
}

#[test]
fn each_revision_materializes_its_own_index() {
    let packs_dir = tempdir().expect("packs");
    let old = packs_dir.path().join("old.gtpack");
    let new = packs_dir.path().join("new.gtpack");
    write_pack(&old, "sales", &["default"], Some(r#"{"rev":"old"}"#));
    write_pack(&new, "sales", &["default"], Some(r#"{"rev":"new"}"#));
    let indexes = tempdir().expect("indexes");
    let cfg = Fast2FlowConfig {
        host_bin: PathBuf::from("/nonexistent"),
        registry_path: PathBuf::from("/tmp/registry"),
        indexes_path: Some(indexes.path().to_path_buf()),
        time_budget_ms: 500,
        gate: Arc::new(BundleCapabilityGate),
    };
    let ctx = OperatorContext {
        tenant: "acme".to_string(),
        team: None,
        correlation_id: None,
    };
    let (r_old, r_new) = (RevisionId::new(), RevisionId::new());
    let scope_old = revision_index_scope("acme", None, BUNDLE, r_old);
    let scope_new = revision_index_scope("acme", None, BUNDLE, r_new);

    let path_old = crate::fast2flow::resolve_index_path(&cfg, &ctx, &old, Some(&scope_old))
        .expect("old index");
    let path_new = crate::fast2flow::resolve_index_path(&cfg, &ctx, &new, Some(&scope_new))
        .expect("new index");

    assert_ne!(path_old, path_new);
    assert_eq!(
        std::fs::read_to_string(&path_old).expect("old"),
        r#"{"rev":"old"}"#
    );
    // The new revision is NOT served the index the old one materialized first.
    assert_eq!(
        std::fs::read_to_string(&path_new).expect("new"),
        r#"{"rev":"new"}"#
    );
    assert_eq!(path_new, indexes.path().join(&scope_new).join("index.json"));
}
