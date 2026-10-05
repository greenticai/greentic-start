//! Index materialization: create, refresh on change, never a partial read.

use std::io::Write;
use std::path::Path;

use tempfile::tempdir;
use zip::write::FileOptions;

use super::*;

/// A pack zip whose `assets/intent-index.json` is `index`.
fn write_pack(path: &Path, index: &[u8]) {
    // Write beside and rename, the way a pack is replaced in place: a reader
    // of the pack never sees a half-written zip either.
    let tmp = path.with_extension("tmp");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&tmp).expect("create pack"));
    zip.start_file("assets/intent-index.json", FileOptions::<()>::default())
        .expect("index entry");
    zip.write_all(index).expect("write index");
    zip.finish().expect("finish");
    std::fs::rename(&tmp, path).expect("rename pack");
}

fn modified(path: &Path) -> std::time::SystemTime {
    std::fs::metadata(path)
        .expect("meta")
        .modified()
        .expect("mtime")
}

#[test]
fn an_absent_index_is_created_from_the_pack() {
    let dir = tempdir().expect("dir");
    let pack = dir.path().join("p.gtpack");
    write_pack(&pack, br#"{"v":1}"#);
    let target = dir
        .path()
        .join("idx")
        .join("acme:default")
        .join("index.json");

    assert_eq!(sync_index_from_pack(&pack, &target), IndexSync::Created);
    assert_eq!(std::fs::read(&target).expect("index"), br#"{"v":1}"#);
    assert_eq!(
        std::fs::read_to_string(target.parent().expect("parent").join("latest")).expect("latest"),
        "index.json\n"
    );
}

#[test]
fn an_identical_index_is_not_rewritten() {
    let dir = tempdir().expect("dir");
    let pack = dir.path().join("p.gtpack");
    write_pack(&pack, br#"{"v":1}"#);
    let target = dir.path().join("scope").join("index.json");
    assert_eq!(sync_index_from_pack(&pack, &target), IndexSync::Created);
    let before = modified(&target);
    std::thread::sleep(std::time::Duration::from_millis(20));

    assert_eq!(sync_index_from_pack(&pack, &target), IndexSync::Unchanged);
    assert_eq!(
        modified(&target),
        before,
        "an unchanged index must not be rewritten"
    );
}

#[test]
fn an_updated_pack_replaces_the_installed_index() {
    let dir = tempdir().expect("dir");
    let pack = dir.path().join("p.gtpack");
    write_pack(&pack, br#"{"v":"old"}"#);
    let target = dir.path().join("scope").join("index.json");
    assert_eq!(sync_index_from_pack(&pack, &target), IndexSync::Created);

    write_pack(&pack, br#"{"v":"new"}"#);
    assert_eq!(sync_index_from_pack(&pack, &target), IndexSync::Replaced);
    assert_eq!(std::fs::read(&target).expect("index"), br#"{"v":"new"}"#);
}

#[test]
fn a_pack_without_an_index_leaves_the_installed_one_alone() {
    let dir = tempdir().expect("dir");
    let target = dir.path().join("scope").join("index.json");
    std::fs::create_dir_all(target.parent().expect("parent")).expect("dir");
    std::fs::write(&target, b"operator-placed").expect("seed");

    assert_eq!(
        sync_index_from_pack(&dir.path().join("missing.gtpack"), &target),
        IndexSync::NoPackIndex
    );
    assert_eq!(std::fs::read(&target).expect("index"), b"operator-placed");
}

#[test]
fn no_temp_file_is_left_behind() {
    let dir = tempdir().expect("dir");
    let pack = dir.path().join("p.gtpack");
    write_pack(&pack, br#"{"v":1}"#);
    let target = dir.path().join("scope").join("index.json");
    sync_index_from_pack(&pack, &target);
    write_pack(&pack, br#"{"v":2}"#);
    sync_index_from_pack(&pack, &target);

    let mut names: Vec<String> = std::fs::read_dir(target.parent().expect("parent"))
        .expect("read dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            SOURCE_MARKER.to_string(),
            "index.json".to_string(),
            "latest".to_string()
        ]
    );
}

/// A probe reading the index while another replaces it sees the whole old
/// index or the whole new one — never a truncated or interleaved file.
#[test]
fn a_concurrent_reader_never_sees_a_partial_index() {
    let dir = tempdir().expect("dir");
    let pack = dir.path().join("p.gtpack");
    // Large enough that a non-atomic write would be observable mid-way.
    let old = vec![b'a'; 512 * 1024];
    let new = vec![b'b'; 768 * 1024];
    write_pack(&pack, &old);
    let target = dir.path().join("scope").join("index.json");
    assert_eq!(sync_index_from_pack(&pack, &target), IndexSync::Created);

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader = {
        let (stop, target, old, new) = (stop.clone(), target.clone(), old.clone(), new.clone());
        std::thread::spawn(move || {
            let mut reads = 0u32;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let bytes = std::fs::read(&target).expect("index must always exist");
                assert!(
                    bytes == old || bytes == new,
                    "partial index observed: {} bytes",
                    bytes.len()
                );
                reads += 1;
            }
            reads
        })
    };
    for round in 0..20 {
        write_pack(&pack, if round % 2 == 0 { &new } else { &old });
        assert_eq!(sync_index_from_pack(&pack, &target), IndexSync::Replaced);
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let reads = reader.join().expect("reader must not panic");
    assert!(reads > 0);
}

/// Two different packs resolving to one shared (legacy `<tenant>:<team>`)
/// scope: the first one installed keeps the index, the second neither
/// overwrites it nor flips it back and forth on every turn.
#[test]
fn two_packs_sharing_a_scope_do_not_thrash() {
    let dir = tempdir().expect("dir");
    let (a, b) = (dir.path().join("a.gtpack"), dir.path().join("b.gtpack"));
    write_pack(&a, br#"{"pack":"a"}"#);
    write_pack(&b, br#"{"pack":"b"}"#);
    let target = dir.path().join("acme:default").join("index.json");

    assert_eq!(sync_index_from_pack(&a, &target), IndexSync::Created);
    for _ in 0..3 {
        assert_eq!(
            sync_index_from_pack(&b, &target),
            IndexSync::OwnedByOtherPack
        );
        assert_eq!(sync_index_from_pack(&a, &target), IndexSync::Unchanged);
    }
    assert_eq!(std::fs::read(&target).expect("index"), br#"{"pack":"a"}"#);
}

/// The owning pack updated in place still refreshes the index even after a
/// second pack asked for the same scope.
#[test]
fn the_owning_pack_still_refreshes_when_another_shares_the_scope() {
    let dir = tempdir().expect("dir");
    let (a, b) = (dir.path().join("a.gtpack"), dir.path().join("b.gtpack"));
    write_pack(&a, br#"{"pack":"a1"}"#);
    write_pack(&b, br#"{"pack":"b"}"#);
    let target = dir.path().join("scope").join("index.json");
    sync_index_from_pack(&a, &target);
    sync_index_from_pack(&b, &target);

    write_pack(&a, br#"{"pack":"a2"}"#);
    assert_eq!(sync_index_from_pack(&a, &target), IndexSync::Replaced);
    assert_eq!(std::fs::read(&target).expect("index"), br#"{"pack":"a2"}"#);
}

/// An index installed by an older build carries no source marker; it is
/// treated as the resolving pack's own, so an updated pack replaces it.
#[test]
fn a_legacy_index_without_a_marker_is_replaced_when_different() {
    let dir = tempdir().expect("dir");
    let pack = dir.path().join("p.gtpack");
    write_pack(&pack, br#"{"v":"new"}"#);
    let target = dir.path().join("scope").join("index.json");
    std::fs::create_dir_all(target.parent().expect("parent")).expect("dir");
    std::fs::write(&target, br#"{"v":"old"}"#).expect("seed legacy index");

    assert_eq!(sync_index_from_pack(&pack, &target), IndexSync::Replaced);
    assert_eq!(std::fs::read(&target).expect("index"), br#"{"v":"new"}"#);
    // ...and from now on it is owned: another pack cannot take it.
    let other = dir.path().join("other.gtpack");
    write_pack(&other, br#"{"v":"other"}"#);
    assert_eq!(
        sync_index_from_pack(&other, &target),
        IndexSync::OwnedByOtherPack
    );
}

/// A marker naming a pack that no longer exists cannot cause thrash (nothing
/// can resolve it any more), so the scope is taken over rather than stranded.
#[test]
fn a_scope_whose_owning_pack_is_gone_is_taken_over() {
    let dir = tempdir().expect("dir");
    let (old, new) = (dir.path().join("v1.gtpack"), dir.path().join("v2.gtpack"));
    write_pack(&old, br#"{"v":1}"#);
    write_pack(&new, br#"{"v":2}"#);
    let target = dir.path().join("scope").join("index.json");
    sync_index_from_pack(&old, &target);
    std::fs::remove_file(&old).expect("remove old pack");

    assert_eq!(sync_index_from_pack(&new, &target), IndexSync::Replaced);
    assert_eq!(std::fs::read(&target).expect("index"), br#"{"v":2}"#);
}

#[test]
fn a_conflict_is_reported_once_per_scope_and_pack() {
    let key = |s: &str| {
        (
            std::path::PathBuf::from(s),
            std::path::PathBuf::from("pack"),
        )
    };
    let seen = WarnOnce::default();
    assert!(seen.first(key("/x/scope-a")));
    assert!(!seen.first(key("/x/scope-a")));
    assert!(seen.first(key("/x/scope-b")));
}

/// Readable by other uids sharing `GREENTIC_FAST2FLOW_INDEXES_PATH`, as the
/// old `fs::write` (umask default) was — `tempfile` alone creates 0600.
#[cfg(unix)]
#[test]
fn written_files_are_world_readable() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().expect("dir");
    let pack = dir.path().join("p.gtpack");
    write_pack(&pack, br#"{"v":1}"#);
    let target = dir.path().join("scope").join("index.json");
    sync_index_from_pack(&pack, &target);
    write_pack(&pack, br#"{"v":2}"#);
    assert_eq!(sync_index_from_pack(&pack, &target), IndexSync::Replaced);

    let parent = target.parent().expect("parent");
    for name in ["index.json", "latest", SOURCE_MARKER] {
        let mode = std::fs::metadata(parent.join(name))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644, "{name}: {mode:o}");
    }
}

/// A write that keeps failing (read-only or full indexes path) is reported
/// once per scope and error kind, not on every turn.
#[test]
fn a_persistent_write_failure_is_reported_once() {
    let dir = tempdir().expect("dir");
    let pack = dir.path().join("p.gtpack");
    write_pack(&pack, br#"{"v":1}"#);
    // The scope "directory" is a plain file, so the index can never be written.
    let blocker = dir.path().join("scope");
    std::fs::write(&blocker, b"not a directory").expect("blocker");
    let target = blocker.join("index.json");

    assert_eq!(sync_index_from_pack(&pack, &target), IndexSync::WriteFailed);
    assert_eq!(sync_index_from_pack(&pack, &target), IndexSync::WriteFailed);
    let err = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    let other = dir.path().join("elsewhere").join("index.json");
    assert!(report_write_failure(&other, &err), "first report logs");
    assert!(!report_write_failure(&other, &err), "repeat is silent");
}
