//! Keeps a scope's installed routing index in step with its pack.
//!
//! A pack ships its routing catalog as `assets/intent-index.json`; the
//! routing host and the embedded LLM fallback read a copy at
//! `<indexes_path>/<scope>/index.json`. That copy used to be written only when
//! absent, so a pack updated in place (same scope) kept being routed against
//! the index of the pack it replaced, with nothing reporting it.
//!
//! Now the copy is compared with the pack's by SHA-256 on every resolve and
//! replaced when they differ. The replacement is written to a temporary file
//! in the same directory and renamed over the old one, so a probe reading the
//! index concurrently sees the whole old index or the whole new one — never a
//! truncated file. An identical index is left untouched (no write at all).

use std::io::Write;
use std::path::Path;

use sha2::{Digest, Sha256};

/// The pack entry the index is read from.
const PACK_INDEX_ENTRY: &str = "assets/intent-index.json";

/// What [`sync_index_from_pack`] did to the installed index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndexSync {
    /// There was no installed index; the pack's was written.
    Created,
    /// The installed index differed from the pack's and was replaced.
    Replaced,
    /// The installed index already matched the pack's; nothing was written.
    Unchanged,
    /// The pack carries no readable index. Any installed index is kept
    /// (it may have been placed by an operator or an external deployer).
    NoPackIndex,
    /// The pack has an index but writing it failed; the installed index (if
    /// any) is untouched. The reason is logged where it is produced.
    WriteFailed,
}

/// Make `target_index` hold exactly the pack's `assets/intent-index.json`.
pub(crate) fn sync_index_from_pack(pack_path: &Path, target_index: &Path) -> IndexSync {
    let Some(pack_index) = read_pack_index(pack_path) else {
        return IndexSync::NoPackIndex;
    };
    let existed = target_index.is_file();
    if existed
        && let Ok(installed) = std::fs::read(target_index)
        && Sha256::digest(&installed) == Sha256::digest(&pack_index)
    {
        return IndexSync::Unchanged;
    }
    if let Err(err) = write_atomically(target_index, &pack_index) {
        crate::operator_log::warn(
            module_path!(),
            format!(
                "[fast2flow:gate] index write failed path={} err={err}",
                target_index.display()
            ),
        );
        return IndexSync::WriteFailed;
    }
    if let Some(parent) = target_index.parent() {
        let latest = parent.join("latest");
        let current = std::fs::read(&latest).ok();
        if current.as_deref() != Some(b"index.json\n".as_slice()) {
            // Best effort, as before: the index itself is what is read.
            let _ = write_atomically(&latest, b"index.json\n");
        }
    }
    if existed {
        IndexSync::Replaced
    } else {
        IndexSync::Created
    }
}

/// The pack's index bytes, or `None` when the pack or the entry is unreadable.
fn read_pack_index(pack_path: &Path) -> Option<Vec<u8>> {
    let file = std::fs::File::open(pack_path).ok()?;
    let mut archive = zip::ZipArchive::new(file).ok()?;
    let mut entry = archive.by_name(PACK_INDEX_ENTRY).ok()?;
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut entry, &mut buf).ok()?;
    Some(buf)
}

/// Write `bytes` to a temp file beside `target`, then rename it over `target`.
/// Rename within one directory is atomic, so readers never see a partial file.
fn write_atomically(target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = target
        .parent()
        .ok_or_else(|| std::io::Error::other("index path has no parent directory"))?;
    std::fs::create_dir_all(parent)?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".index-refresh-")
        .tempfile_in(parent)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(target).map_err(|err| err.error)?;
    Ok(())
}

#[cfg(test)]
#[path = "index_refresh_tests.rs"]
mod tests;
