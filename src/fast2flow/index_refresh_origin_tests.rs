//! Where an UNMARKED installed index came from, told apart by what it says
//! about itself rather than by an operator setting.
//!
//! Every index the greentic-fast2flow indexer writes records the scope it was
//! built FOR, and that is the directory it is installed under:
//! `fast2flow_indexer::build_index` writes `<indexes_root>/<scope>/index.json`
//! with `"scope": "<scope>"`, and `greentic-fast2flow bundle index` writes
//! `"scope": "<tenant>:<team>"` for the documented
//! `cp index.json /mnt/indexes/<tenant>:<team>/index.json`. An older
//! greentic-start copied the pack's `assets/intent-index.json` verbatim into
//! the `--bundle` path's legacy `<tenant>:<team>` directory; its `scope` is
//! whatever the pack author wrote. Revision scopes never carry an old copy.

use std::io::Write;
use std::path::{Path, PathBuf};

use tempfile::tempdir;
use zip::write::FileOptions;

use super::*;

/// What `fast2flow_indexer::build_index` writes for `scope` (its
/// `serde_json::to_string_pretty(&IndexManifestV2)`), built from the flows in
/// greentic-fast2flow `tests/fixtures/flows.json` (develop @ 41d0cf6).
fn indexer_v2(scope: &str) -> Vec<u8> {
    format!(
        r#"{{
  "version": "v2",
  "scope": "{scope}",
  "generated_at_ms": 1759622400000,
  "entries": [
    {{
      "flow_id": "refund_flow",
      "pack_id": "support",
      "target": "support/refund_flow",
      "title": "Refund Request",
      "tags": [
        "refund",
        "payment",
        "billing"
      ],
      "node_ids": [
        "start",
        "collect_order",
        "issue_refund"
      ],
      "flow_type": "deterministic"
    }}
  ]
}}"#
    )
    .into_bytes()
}

/// What `greentic-fast2flow bundle index --tenant acme --team default` writes
/// (fast2flow-bundle `IndexManifest`, version "1.0"), trimmed to one flow.
fn bundle_index_v1(tenant: &str, team: &str) -> Vec<u8> {
    format!(
        r#"{{
  "version": "1.0",
  "scope": "{tenant}:{team}",
  "last_updated": "2026-10-05T00:00:00+00:00",
  "flows": [
    {{
      "pack_id": "support",
      "flow_id": "refund",
      "title": "Refund Request",
      "description": "",
      "tags": [],
      "keywords": ["refund"],
      "execution_type": "deterministic"
    }}
  ],
  "term_frequencies": {{}},
  "document_frequencies": {{}}
}}"#
    )
    .into_bytes()
}

/// A pack-shipped `assets/intent-index.json` in the shape greentic-demo's
/// `apps/pet-daycare-app/assets/intent-index.json` has: v2, an author-chosen
/// `scope`, `generated_at_ms: 0`. `title` tells two versions apart.
fn pack_index(title: &str) -> Vec<u8> {
    format!(
        r#"{{
  "version": "v2",
  "scope": "demo:default",
  "generated_at_ms": 0,
  "entries": [
    {{
      "flow_id": "intent-checkin",
      "pack_id": "greentic.pet-daycare.demo",
      "target": "greentic.pet-daycare.demo/default/checkin_card",
      "title": "{title}",
      "utterances": ["check in {{{{person}}}}"]
    }}
  ]
}}"#
    )
    .into_bytes()
}

fn write_pack(path: &Path, index: &[u8]) {
    let mut zip = zip::ZipWriter::new(std::fs::File::create(path).expect("create pack"));
    zip.start_file("assets/intent-index.json", FileOptions::<()>::default())
        .expect("index entry");
    zip.write_all(index).expect("write index");
    zip.finish().expect("finish");
}

/// `<root>/<scope>/index.json` holding `installed`, and no marker.
fn seed(root: &Path, scope: &str, installed: &[u8]) -> PathBuf {
    let target = root.join("idx").join(scope).join("index.json");
    std::fs::create_dir_all(target.parent().expect("parent")).expect("dir");
    std::fs::write(&target, installed).expect("seed");
    // What the older greentic-start wrote beside the index.
    std::fs::write(target.with_file_name("latest"), "index.json\n").expect("latest");
    target
}

const REVISION_SCOPE: &str = "acme:default--0123456789abcdef0123456789abcdef";

/// The shape older greentic-start builds actually left: the `--bundle` path's
/// legacy `<tenant>:<team>` directory holding a verbatim pack index whose
/// author-chosen scope names another tenant/team.
#[test]
fn an_index_left_by_an_older_start_is_refreshed_without_the_opt_in() {
    let dir = tempdir().expect("dir");
    let pack = dir.path().join("p.gtpack");
    write_pack(&pack, &pack_index("Check in a pet (v2)"));
    let target = seed(dir.path(), "petshop:default", &pack_index("Check in a pet"));

    assert_eq!(sync_index_with(&pack, &target, false), IndexSync::Replaced);
    assert_eq!(
        std::fs::read(&target).expect("index"),
        pack_index("Check in a pet (v2)")
    );
    let owner = std::fs::read_to_string(target.with_file_name(SOURCE_MARKER)).expect("marker");
    assert_eq!(
        PathBuf::from(owner.trim()),
        std::fs::canonicalize(&pack).expect("canonical"),
        "the adopted index is owned from now on"
    );
    // And a later update keeps refreshing it.
    write_pack(&pack, &pack_index("Check in a pet (v3)"));
    assert_eq!(sync_index_with(&pack, &target, false), IndexSync::Replaced);
}

#[test]
fn an_older_start_copy_under_the_legacy_scope_is_refreshed() {
    let dir = tempdir().expect("dir");
    let pack = dir.path().join("p.gtpack");
    write_pack(&pack, &pack_index("new"));
    let target = seed(dir.path(), "acme:default", &pack_index("old"));

    assert_eq!(sync_index_with(&pack, &target, false), IndexSync::Replaced);
    assert_eq!(std::fs::read(&target).expect("index"), pack_index("new"));
}

#[test]
fn an_indexer_built_index_is_kept() {
    let dir = tempdir().expect("dir");
    let pack = dir.path().join("p.gtpack");
    write_pack(&pack, &pack_index("pack"));
    for (scope, bytes) in [
        ("acme:default", indexer_v2("acme:default")),
        (REVISION_SCOPE, indexer_v2(REVISION_SCOPE)),
        ("acme:default", bundle_index_v1("acme", "default")),
    ] {
        let target = seed(dir.path(), scope, &bytes);
        assert_eq!(
            sync_index_with(&pack, &target, false),
            IndexSync::DeployerPlaced,
            "{scope}"
        );
        assert_eq!(std::fs::read(&target).expect("index"), bytes);
        assert!(!target.with_file_name(SOURCE_MARKER).exists());
        // The opt-in still overrides.
        assert_eq!(sync_index_with(&pack, &target, true), IndexSync::Replaced);
        std::fs::remove_dir_all(target.parent().expect("parent")).expect("reset");
    }
}

/// The pack's own scope string IS the directory (pack scoped `demo:default`
/// served as tenant `demo`, team `default`): an indexer run for that scope
/// and an older copy of the pack look the same, so it is kept — whatever
/// `generated_at_ms` says. A zero timestamp is NOT read as "pack-shipped": the
/// indexer CLI's `index build --now-unix-ms` defaults to 0.
#[test]
fn an_index_naming_both_its_directory_and_the_pack_scope_is_kept() {
    let dir = tempdir().expect("dir");
    let pack = dir.path().join("p.gtpack");
    write_pack(&pack, &pack_index("new"));
    let stamped = String::from_utf8(pack_index("old"))
        .expect("utf8")
        .replace(
            "\"generated_at_ms\": 0",
            "\"generated_at_ms\": 1759622400000",
        )
        .into_bytes();
    assert_ne!(stamped, pack_index("old"));
    for installed in [pack_index("old"), stamped] {
        let target = seed(dir.path(), "demo:default", &installed);
        assert_eq!(
            sync_index_with(&pack, &target, false),
            IndexSync::DeployerPlaced
        );
        assert_eq!(std::fs::read(&target).expect("index"), installed);
        std::fs::remove_dir_all(target.parent().expect("parent")).expect("reset");
    }
}

/// What `greentic-fast2flow index build` writes with its default
/// `--now-unix-ms 0`: an indexer-built index with a zero timestamp. Kept.
#[test]
fn an_indexer_built_index_with_a_zero_timestamp_is_kept() {
    let dir = tempdir().expect("dir");
    let pack = dir.path().join("p.gtpack");
    write_pack(&pack, &pack_index("pack"));
    let zero = String::from_utf8(indexer_v2("acme:default"))
        .expect("utf8")
        .replace("1759622400000", "0")
        .into_bytes();
    let target = seed(dir.path(), "acme:default", &zero);
    assert_eq!(
        sync_index_with(&pack, &target, false),
        IndexSync::DeployerPlaced
    );
    assert_eq!(std::fs::read(&target).expect("index"), zero);
}

/// A pack author who changed the scope string between versions leaves the
/// old copy unrecognisable: classified Unknown and kept.
#[test]
fn an_old_copy_under_a_since_renamed_pack_scope_is_kept() {
    let dir = tempdir().expect("dir");
    let pack = dir.path().join("p.gtpack");
    let renamed = String::from_utf8(pack_index("new"))
        .expect("utf8")
        .replace("demo:default", "pets:default")
        .into_bytes();
    write_pack(&pack, &renamed);
    let target = seed(dir.path(), "petshop:default", &pack_index("old"));
    assert_eq!(
        sync_index_with(&pack, &target, false),
        IndexSync::DeployerPlaced
    );
}

#[test]
fn an_unreadable_or_foreign_index_is_kept() {
    let dir = tempdir().expect("dir");
    let pack = dir.path().join("p.gtpack");
    write_pack(&pack, &pack_index("pack"));
    let other_scope = indexer_v2("other:team");
    for bytes in [b"not json".to_vec(), br#"{"v":1}"#.to_vec(), other_scope] {
        let target = seed(dir.path(), REVISION_SCOPE, &bytes);
        assert_eq!(
            sync_index_with(&pack, &target, false),
            IndexSync::DeployerPlaced
        );
        assert_eq!(std::fs::read(&target).expect("index"), bytes);
        std::fs::remove_dir_all(target.parent().expect("parent")).expect("reset");
    }
}

#[test]
fn unmarked_origin_reads_the_recorded_scope() {
    let pack = pack_index("p");
    assert_eq!(
        unmarked_origin(&pack_index("old"), &pack, "petshop:default"),
        UnmarkedOrigin::OlderStartCopy
    );
    assert_eq!(
        unmarked_origin(&indexer_v2("acme:default"), &pack, "acme:default"),
        UnmarkedOrigin::BuiltForScope
    );
    assert_eq!(
        unmarked_origin(&pack_index("old"), &pack, "demo:default"),
        UnmarkedOrigin::BuiltForScope
    );
    assert_eq!(
        unmarked_origin(b"{}", &pack, "acme:default"),
        UnmarkedOrigin::Unknown
    );
    // A pack whose index records no scope cannot vouch for anything.
    assert_eq!(
        unmarked_origin(&pack_index("old"), br#"{"v":1}"#, "petshop:default"),
        UnmarkedOrigin::Unknown
    );
}
