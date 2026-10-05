//! Per-revision app-pack index for the revision-serve path.
//!
//! The legacy messaging ingress has ONE app pack per process. Revision mode
//! serves several bundles, and several revisions of one bundle during a
//! traffic split, so the pack a Fast2Flow probe routes against must be the
//! one of the revision actually serving the turn. [`RevisionAppPacks`] is
//! keyed by `(bundle_id, revision_id)` for exactly that reason; it is NOT
//! deduped per bundle the way the webchat `FlowIndex` is, because two
//! revisions of one bundle may pin different packs.
//!
//! Built during activation from the `AppPackInfo`s the flow index already
//! reads ([`AppPackInfoCache`] reads each pack path once per activation), and
//! carried unchanged by a routing-only reload.

// The revision-serve Fast2Flow hook that reads this index lands separately;
// until then the lookup side is exercised by tests only.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use greentic_deploy_spec::RevisionId;
use sha2::{Digest, Sha256};

use crate::messaging_app::{AppPackInfo, load_app_pack_info, select_app_flow};

/// The app pack of one loaded revision: the single pack in it that resolves a
/// default messaging flow (the same pack the webchat `FlowIndex` registers as
/// the bundle default).
#[derive(Clone, Debug)]
pub(crate) struct RevisionAppPack {
    pub pack_id: String,
    pub pack_path: PathBuf,
    pub info: AppPackInfo,
    pub revision_id: RevisionId,
}

/// `(bundle_id, revision_id) -> app pack`. Entries are `Arc`ed so the
/// routing-only reload's clone is a map of pointer copies.
#[derive(Clone, Debug, Default)]
pub(crate) struct RevisionAppPacks {
    by_revision: HashMap<(String, RevisionId), Arc<RevisionAppPack>>,
}

impl RevisionAppPacks {
    /// The app pack of `revision_id` of `bundle_id`, if that revision has one.
    pub(crate) fn get(&self, bundle_id: &str, revision_id: RevisionId) -> Option<&RevisionAppPack> {
        self.by_revision
            .get(&(bundle_id.to_string(), revision_id))
            .map(Arc::as_ref)
    }

    pub(crate) fn len(&self) -> usize {
        self.by_revision.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.by_revision.is_empty()
    }

    /// Register the app pack of one revision from its packs' infos. A
    /// revision with no pack resolving a default flow, or with SEVERAL (the
    /// same ambiguity the `FlowIndex` tombstones), gets no entry: a probe
    /// against a guessed pack would route into the wrong catalog.
    pub(crate) fn insert_revision<'a>(
        &mut self,
        bundle_id: &str,
        revision_id: RevisionId,
        packs: impl IntoIterator<Item = (&'a Path, &'a AppPackInfo)>,
    ) {
        if let Some(app) = select_revision_app_pack(revision_id, packs) {
            self.by_revision
                .insert((bundle_id.to_string(), revision_id), Arc::new(app));
        }
    }
}

/// The single pack among `packs` that declares flows and resolves a default
/// one; `None` when there is none or more than one.
fn select_revision_app_pack<'a>(
    revision_id: RevisionId,
    packs: impl IntoIterator<Item = (&'a Path, &'a AppPackInfo)>,
) -> Option<RevisionAppPack> {
    let mut candidates = packs
        .into_iter()
        .filter(|(_, info)| !info.flows.is_empty() && select_app_flow(info).is_ok());
    let (path, info) = candidates.next()?;
    if candidates.any(|(_, other)| other.pack_id != info.pack_id) {
        tracing::debug!(
            revision_id = %revision_id,
            "several packs resolve a default flow; no fast2flow app pack for this revision"
        );
        return None;
    }
    Some(RevisionAppPack {
        pack_id: info.pack_id.clone(),
        pack_path: path.to_path_buf(),
        info: info.clone(),
        revision_id,
    })
}

/// `load_app_pack_info` memoized per pack path for one activation, so the
/// flow index and the per-revision app-pack index share one disk read, and
/// revisions pinning the same pack file do not re-read it. A pack that fails
/// to load is remembered as such (logged once at debug, as before).
#[derive(Default)]
pub(crate) struct AppPackInfoCache {
    by_path: HashMap<PathBuf, Option<AppPackInfo>>,
    #[cfg_attr(not(test), allow(dead_code))] // read only by tests
    reads: usize,
}

impl AppPackInfoCache {
    /// The loadable infos of `paths`, in order, paired with their path.
    pub(crate) fn infos(&mut self, paths: &[PathBuf]) -> Vec<(PathBuf, AppPackInfo)> {
        let mut out = Vec::with_capacity(paths.len());
        for path in paths {
            if !self.by_path.contains_key(path) {
                self.reads += 1;
                let loaded = match load_app_pack_info(path) {
                    Ok(info) => Some(info),
                    Err(err) => {
                        tracing::debug!(
                            pack = %path.display(),
                            "skipping app-pack info for pack: {err:#}"
                        );
                        None
                    }
                };
                self.by_path.insert(path.clone(), loaded);
            }
            if let Some(Some(info)) = self.by_path.get(path) {
                out.push((path.clone(), info.clone()));
            }
        }
        out
    }

    /// Disk reads performed so far (one per distinct path).
    #[cfg(test)]
    pub(crate) fn reads(&self) -> usize {
        self.reads
    }
}

/// The Fast2Flow index scope for one revision of one bundle.
///
/// The routing host validates every scope with `fast2flow_contracts::
/// validate_scope` (greentic-fast2flow `ec88623`,
/// `crates/fast2flow-contracts/src/lib.rs:135`, applied by
/// `fast2flow_indexer::load_latest` and the WIT entrypoint): EXACTLY one
/// colon, each side non-empty, only `[A-Za-z0-9._-]`, no leading/trailing
/// dot, at most 512 characters. A failing scope makes the host answer
/// `Continue`. So the readable `tenant:team:<bundle>:<revision>` form is NOT
/// usable; instead the scope is `<tenant>:<team>--<digest>`, where both sides
/// are sanitized to that alphabet and `<digest>` is 32 hex characters of a
/// length-prefixed SHA-256 over the raw `(tenant, team, bundle, revision)`.
/// The digest keeps scopes distinct even when sanitizing collapses two
/// tenants or teams to the same text, and gives each revision its own index
/// directory, so the first-copy materialization of `assets/intent-index.json`
/// can never serve a previous revision's index.
pub(crate) fn revision_index_scope(
    tenant: &str,
    team: Option<&str>,
    bundle_id: &str,
    revision_id: RevisionId,
) -> String {
    let team = team.unwrap_or("default");
    let revision = revision_id.to_string();
    let mut hasher = Sha256::new();
    for field in [tenant, team, bundle_id, revision.as_str()] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    let digest = hasher.finalize();
    let hex: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}:{}--{hex}",
        scope_segment(tenant, "tenant"),
        scope_segment(team, "default")
    )
}

/// `value` mapped into the scope alphabet: other characters become `-`,
/// leading/trailing dots are dropped, capped at 128 characters, `fallback`
/// when nothing is left.
fn scope_segment(value: &str, fallback: &str) -> String {
    let mapped: String = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .take(128)
        .collect();
    let trimmed = mapped.trim_matches('.');
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
#[path = "revision_packs_tests.rs"]
mod tests;
