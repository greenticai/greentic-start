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
//! (scope, pack). A marker naming a pack that no longer exists is taken over,
//! since nothing can resolve that pack any more.
//!
//! An index with NO marker was placed by someone else: an operator or an
//! external deployer pinning `GREENTIC_FAST2FLOW_INDEXES_PATH`, or a build
//! older than the marker. If it matches the pack's index it is adopted (the
//! marker is written). If it differs, the `scope` it records tells the two
//! apart ([`UnmarkedOrigin`]): a copy left by an older greentic-start records
//! the pack's own scope and is adopted and refreshed; anything else is kept
//! and reported once per scope. `GREENTIC_FAST2FLOW_INDEX_REFRESH_UNMARKED=1`
//! remains an override that lets the pack replace any unmarked index.
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

/// Opt-in: let a pack replace an unmarked index that differs from its own.
pub(crate) const ENV_REFRESH_UNMARKED: &str = "GREENTIC_FAST2FLOW_INDEX_REFRESH_UNMARKED";

/// `1`/`true`/`yes`/`on` (trimmed, any case) enable; anything else, or unset,
/// keeps an unmarked index.
fn parse_refresh_unmarked(raw: Option<&str>) -> bool {
    raw.map(str::trim).is_some_and(|v| {
        ["1", "true", "yes", "on"]
            .iter()
            .any(|on| v.eq_ignore_ascii_case(on))
    })
}

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
    /// An index with no source marker that differs from the pack's and is not
    /// recognisably a copy left by an older greentic-start (see
    /// [`UnmarkedOrigin`]): placed by an operator or a deployer. Kept
    /// (reported once per scope) unless [`ENV_REFRESH_UNMARKED`] opts in.
    DeployerPlaced,
    /// The pack has an index but writing it failed; the installed index (if
    /// any) is untouched. The reason is logged where it is produced.
    WriteFailed,
}

/// Make `target_index` hold the pack's `assets/intent-index.json`, unless the
/// installed index belongs to another pack sharing the scope or was placed by
/// someone else (see the module doc). Reads [`ENV_REFRESH_UNMARKED`].
pub(crate) fn sync_index_from_pack(pack_path: &Path, target_index: &Path) -> IndexSync {
    let refresh_unmarked =
        parse_refresh_unmarked(std::env::var(ENV_REFRESH_UNMARKED).ok().as_deref());
    sync_index_with(pack_path, target_index, refresh_unmarked)
}

/// [`sync_index_from_pack`] with the unmarked-index opt-in passed explicitly.
fn sync_index_with(pack_path: &Path, target_index: &Path, refresh_unmarked: bool) -> IndexSync {
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
    let owner = installed_owner(&marker);
    let owner_recorded = owner.as_deref() == Some(source.as_path());
    let installed = if existed {
        std::fs::read(target_index).ok()
    } else {
        None
    };
    if let Some(installed) = &installed
        && Sha256::digest(installed) == Sha256::digest(&pack_index)
    {
        if !owner_recorded {
            // An unmarked (or orphaned) index that already matches: adopt it.
            let _ = write_atomically(&marker, source.to_string_lossy().as_bytes());
        }
        return IndexSync::Unchanged;
    }
    if existed && owner.is_none() && !refresh_unmarked {
        let scope_dir = target_index
            .parent()
            .and_then(Path::file_name)
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let origin = installed
            .as_deref()
            .map_or(UnmarkedOrigin::Unknown, |installed| {
                unmarked_origin(installed, &pack_index, &scope_dir)
            });
        if origin == UnmarkedOrigin::OlderStartCopy {
            if ADOPTED.first(target_index.to_path_buf()) {
                crate::operator_log::info(
                    module_path!(),
                    format!(
                        "[fast2flow:gate] index {} has no {SOURCE_MARKER} marker and records the pack's own scope, \
                         not its directory's: a copy left by an older greentic-start. Pack {} adopts and refreshes it (reported once)",
                        target_index.display(),
                        source.display()
                    ),
                );
            }
        } else {
            if UNMARKED.first(target_index.to_path_buf()) {
                crate::operator_log::warn(
                    module_path!(),
                    format!(
                        "[fast2flow:gate] index {} has no {SOURCE_MARKER} marker and differs from pack {}'s; \
                         keeping it as operator/deployer-placed ({}). Delete it, or set {ENV_REFRESH_UNMARKED}=1, \
                         to let the pack replace it (reported once)",
                        target_index.display(),
                        source.display(),
                        origin.describe()
                    ),
                );
            }
            return IndexSync::DeployerPlaced;
        }
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

/// Process-wide "already reported" set for kept unmarked indexes.
static UNMARKED: LazyLock<WarnOnce<PathBuf>> = LazyLock::new(WarnOnce::default);

/// Process-wide "already reported" set for adopted older-start copies. Separate
/// from [`UNMARKED`] so reporting one never suppresses the other.
static ADOPTED: LazyLock<WarnOnce<PathBuf>> = LazyLock::new(WarnOnce::default);

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

/// Where an installed index with no [`SOURCE_MARKER`] came from, read from the
/// `scope` it records about itself.
///
/// Every index the greentic-fast2flow indexer writes records the scope it was
/// built FOR, and is installed under that scope's directory:
/// `fast2flow_indexer::build_index` writes `<root>/<scope>/index.json` with
/// `"scope": "<scope>"`, and `greentic-fast2flow bundle index` writes
/// `"scope": "<tenant>:<team>"` for `cp index.json <root>/<tenant>:<team>/`.
/// An older greentic-start (before the marker) copied the pack's
/// `assets/intent-index.json` verbatim, so that copy records the scope the
/// pack AUTHOR wrote — the same string the current pack's index records — and
/// not the directory.
///
/// Old copies exist only under legacy `<tenant>:<team>` directories (the
/// `--bundle` path); revision scopes are fresh per revision and never carry
/// one. `generated_at_ms == 0` is NOT a signal: the indexer CLI's
/// `index build --now-unix-ms` defaults to 0, so indexer output carries it too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnmarkedOrigin {
    /// Records the pack's scope and not its directory's: a copy of (an older
    /// version of) the pack's index. Adopted and refreshed.
    OlderStartCopy,
    /// Records its directory's scope: built for this scope by the indexer or a
    /// deployer. Kept. Also when the pack's scope string IS the directory,
    /// since the two origins then look the same.
    BuiltForScope,
    /// No readable scope, or a scope that is neither. Kept.
    Unknown,
}

impl UnmarkedOrigin {
    fn describe(self) -> &'static str {
        match self {
            Self::OlderStartCopy => "a copy of the pack's index",
            Self::BuiltForScope => "it records this scope, as an indexer-built index does",
            Self::Unknown => "its origin cannot be told from its contents",
        }
    }
}

/// Classify an unmarked installed index; see [`UnmarkedOrigin`].
pub(crate) fn unmarked_origin(
    installed: &[u8],
    pack_index: &[u8],
    scope_dir: &str,
) -> UnmarkedOrigin {
    let Some(installed_scope) = recorded_scope(installed) else {
        return UnmarkedOrigin::Unknown;
    };
    if installed_scope == scope_dir {
        return UnmarkedOrigin::BuiltForScope;
    }
    match recorded_scope(pack_index) {
        Some(pack_scope) if pack_scope == installed_scope => UnmarkedOrigin::OlderStartCopy,
        _ => UnmarkedOrigin::Unknown,
    }
}

/// The non-empty top-level `scope` string an index manifest records.
fn recorded_scope(bytes: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let scope = value.get("scope")?.as_str()?.trim();
    (!scope.is_empty()).then(|| scope.to_string())
}

#[cfg(test)]
#[path = "index_refresh_origin_tests.rs"]
mod origin_tests;
