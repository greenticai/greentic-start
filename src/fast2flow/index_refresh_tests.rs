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
    assert_eq!(names, vec!["index.json".to_string(), "latest".to_string()]);
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
