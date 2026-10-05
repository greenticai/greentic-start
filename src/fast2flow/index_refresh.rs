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
//!
//! One scope can be resolved by more than one pack: the legacy
//! `<tenant>:<team>` scope is shared by every app pack of a tenant/team.
//! Refreshing on every difference would make two such packs overwrite each
//! other's index every turn. So the pack that installed an index is recorded
//! in a marker beside it ([`SOURCE_MARKER`], the canonical pack path), and
//! only that pack may replace it. Another pack keeps the installed index (the
//! first-wins behaviour of the old copy-if-absent) and is reported once per
//! (scope, pack). An index with no marker was installed by an older build and
//! is treated as the resolving pack's own; a marker naming a pack that no
//! longer exists is taken over, since nothing can resolve that pack any more.
//!
//! The index and the marker are two renames, not one. Two packs creating one
//! scope at the same instant can leave the marker naming the pack whose index
//! lost the race; the next turn of the marked pack then replaces the index,
//! so the scope converges on one pack instead of thrashing.

use std::collections::HashSet;
use std::hash::Hash;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use sha2::{Digest, Sha256};

/// The pack entry the index is read from.
const PACK_INDEX_ENTRY: &str = "assets/intent-index.json";

/// Beside `index.json`: the canonical path of the pack that installed it.
pub(crate) const SOURCE_MARKER: &str = ".index-source";

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
    /// The installed index belongs to a different pack that shares this
    /// scope; it is kept. Reported once per (scope, pack).
    OwnedByOtherPack,
    /// The pack has an index but writing it failed; the installed index (if
    /// any) is untouched. The reason is logged where it is produced.
    WriteFailed,
}

/// Make `target_index` hold the pack's `assets/intent-index.json`, unless the
/// installed index belongs to another pack sharing the scope.
pub(crate) fn sync_index_from_pack(pack_path: &Path, target_index: &Path) -> IndexSync {
    let Some(pack_index) = read_pack_index(pack_path) else {
        return IndexSync::NoPackIndex;
    };
    let source = canonical(pack_path);
    let marker = marker_path(target_index);
    let existed = target_index.is_file();
    if existed
        && let Some(owner) = installed_owner(&marker)
        && owner != source
        && owner.exists()
    {
        if CONFLICTS.first((target_index.to_path_buf(), source.clone())) {
            crate::operator_log::warn(
                module_path!(),
                format!(
                    "[fast2flow:gate] index {} belongs to pack {}; pack {} shares the scope and is routed against it (reported once)",
                    target_index.display(),
                    owner.display(),
                    source.display()
                ),
            );
        }
        return IndexSync::OwnedByOtherPack;
    }
    let owner_recorded = installed_owner(&marker).as_deref() == Some(source.as_path());
    if existed
        && let Ok(installed) = std::fs::read(target_index)
        && Sha256::digest(&installed) == Sha256::digest(&pack_index)
    {
        if !owner_recorded {
            // A legacy index (no marker) that already matches: adopt it.
            let _ = write_atomically(&marker, source.to_string_lossy().as_bytes());
        }
        return IndexSync::Unchanged;
    }
    if let Err(err) = write_atomically(target_index, &pack_index) {
        report_write_failure(target_index, &err);
        return IndexSync::WriteFailed;
    }
    if !owner_recorded {
        let _ = write_atomically(&marker, source.to_string_lossy().as_bytes());
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

/// Log a failed index write once per (index path, error kind): a read-only
/// or full indexes path fails the same way on every turn. Returns whether
/// this call logged.
fn report_write_failure(target_index: &Path, err: &std::io::Error) -> bool {
    let first = WRITE_FAILURES.first((target_index.to_path_buf(), err.kind()));
    if first {
        crate::operator_log::warn(
            module_path!(),
            format!(
                "[fast2flow:gate] index write failed path={} err={err} (reported once per error kind)",
                target_index.display()
            ),
        );
    }
    first
}

/// Process-wide "already reported" set for failed index writes.
static WRITE_FAILURES: LazyLock<WarnOnce<(PathBuf, std::io::ErrorKind)>> =
    LazyLock::new(WarnOnce::default);

/// Process-wide "already reported" set for scope/pack conflicts.
static CONFLICTS: LazyLock<WarnOnce<(PathBuf, PathBuf)>> = LazyLock::new(WarnOnce::default);

/// Remembers which keys were already reported, so a condition that holds on
/// every turn is logged once, not per turn.
pub(crate) struct WarnOnce<K> {
    seen: Mutex<HashSet<K>>,
}

impl<K> Default for WarnOnce<K> {
    fn default() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
        }
    }
}

impl<K: Eq + Hash> WarnOnce<K> {
    /// `true` the first time `key` is seen.
    pub(crate) fn first(&self, key: K) -> bool {
        match self.seen.lock() {
            Ok(mut seen) => seen.insert(key),
            // A poisoned set only means a panic elsewhere; reporting again is
            // harmless, staying silent is not.
            Err(poisoned) => poisoned.into_inner().insert(key),
        }
    }
}

fn marker_path(target_index: &Path) -> PathBuf {
    target_index.with_file_name(SOURCE_MARKER)
}

fn canonical(pack_path: &Path) -> PathBuf {
    std::fs::canonicalize(pack_path).unwrap_or_else(|_| pack_path.to_path_buf())
}

/// The pack recorded as the installed index's source; `None` when there is no
/// (readable, non-empty) marker — an index installed by an older build.
fn installed_owner(marker: &Path) -> Option<PathBuf> {
    let raw = std::fs::read_to_string(marker).ok()?;
    let raw = raw.trim();
    (!raw.is_empty()).then(|| PathBuf::from(raw))
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
    // `tempfile` creates 0600; the index is read by the routing host, which a
    // deployer may run as another uid sharing the indexes path. Match what the
    // previous plain `fs::write` produced under the usual 022 umask.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    tmp.as_file().sync_all()?;
    tmp.persist(target).map_err(|err| err.error)?;
    Ok(())
}

#[cfg(test)]
#[path = "index_refresh_tests.rs"]
mod tests;
