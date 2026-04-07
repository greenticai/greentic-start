//! Pack dependency checker at startup.
//!
//! Scans all discovered `.gtpack` files for declared dependencies (via
//! `PackManifest.dependencies`), checks whether each dependency is already
//! satisfied by another pack in the bundle, and reports missing ones.
//!
//! This module is a **checker only** — it warns about missing dependencies
//! but does not auto-install. The actual resolver belongs in greentic-dev
//! wizard (at answer/setup time), where the user can choose between
//! alternatives (e.g. state-memory vs state-redis).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Context;
use greentic_types::decode_pack_manifest;
use zip::ZipArchive;

use crate::operator_log;

/// Result of dependency checking across all packs in the bundle.
#[derive(Debug, Default)]
pub struct CheckReport {
    /// Dependencies that are satisfied by a pack in the bundle.
    pub satisfied: Vec<SatisfiedDep>,
    /// Dependencies that are missing — no pack in the bundle provides them.
    pub missing: Vec<MissingDep>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct SatisfiedDep {
    pub pack_id: String,
    pub satisfied_by: PathBuf,
    /// `true` when satisfied by capability match rather than exact pack_id.
    pub by_capability: bool,
}

#[derive(Debug)]
pub struct MissingDep {
    pub pack_id: String,
    pub required_by: String,
    pub required_capabilities: Vec<String>,
}

/// Check all pack dependencies in the given bundle root.
///
/// 1. Build an index of all pack_ids present in the bundle.
/// 2. Read dependencies from each pack's `manifest.cbor`.
/// 3. Report which are satisfied and which are missing.
pub fn check_all(bundle_root: &Path) -> anyhow::Result<CheckReport> {
    let mut report = CheckReport::default();

    let pack_paths = collect_all_gtpacks(bundle_root);
    if pack_paths.is_empty() {
        return Ok(report);
    }

    let pack_index = build_pack_index(&pack_paths);
    let capability_index = build_capability_index(&pack_paths);

    // Collect all dependency requirements.
    let mut requirements: Vec<(String, String, Vec<String>)> = Vec::new();
    for pack_path in &pack_paths {
        match read_dependencies(pack_path) {
            Ok(deps) => {
                let pack_id = pack_index
                    .iter()
                    .find(|(_, p)| *p == pack_path)
                    .map(|(id, _)| id.clone())
                    .unwrap_or_else(|| pack_path.display().to_string());
                for dep in deps {
                    requirements.push((
                        dep.pack_id.to_string(),
                        pack_id.clone(),
                        dep.required_capabilities,
                    ));
                }
            }
            Err(err) => {
                operator_log::debug(
                    module_path!(),
                    format!(
                        "failed to read dependencies from {}: {err:#}",
                        pack_path.display()
                    ),
                );
            }
        }
    }

    // De-duplicate by pack_id.
    let mut seen = BTreeSet::new();
    requirements.retain(|(dep, _, _)| seen.insert(dep.clone()));

    for (dep_pack_id, required_by, required_caps) in requirements {
        if let Some(path) = pack_index.get(&dep_pack_id) {
            // Exact pack_id match.
            report.satisfied.push(SatisfiedDep {
                pack_id: dep_pack_id,
                satisfied_by: path.clone(),
                by_capability: false,
            });
        } else if !required_caps.is_empty() {
            // Capability-based matching: check if all required capabilities
            // are provided by some pack in the bundle.
            let all_satisfied = required_caps
                .iter()
                .all(|cap| capability_index.contains_key(cap));
            if all_satisfied {
                let provider_path = required_caps
                    .first()
                    .and_then(|cap| capability_index.get(cap))
                    .cloned()
                    .unwrap_or_default();
                operator_log::info(
                    module_path!(),
                    format!(
                        "dependency {dep_pack_id} satisfied by capability match \
                         (required: {})",
                        required_caps.join(", ")
                    ),
                );
                report.satisfied.push(SatisfiedDep {
                    pack_id: dep_pack_id,
                    satisfied_by: provider_path,
                    by_capability: true,
                });
            } else {
                let missing_caps: Vec<_> = required_caps
                    .iter()
                    .filter(|cap| !capability_index.contains_key(cap.as_str()))
                    .cloned()
                    .collect();
                report.missing.push(MissingDep {
                    pack_id: dep_pack_id,
                    required_by,
                    required_capabilities: missing_caps,
                });
            }
        } else {
            report.missing.push(MissingDep {
                pack_id: dep_pack_id,
                required_by,
                required_capabilities: required_caps,
            });
        }
    }

    Ok(report)
}

/// Collect all `.gtpack` files from `providers/*/` and `packs/`.
fn collect_all_gtpacks(bundle_root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let providers_root = bundle_root.join("providers");
    if let Ok(entries) = std::fs::read_dir(&providers_root) {
        for entry in entries.flatten() {
            if entry.path().is_dir()
                && let Ok(sub_entries) = std::fs::read_dir(entry.path())
            {
                for sub in sub_entries.flatten() {
                    let p = sub.path();
                    if p.extension().is_some_and(|e| e == "gtpack") {
                        paths.push(p);
                    }
                }
            }
        }
    }
    let packs_dir = bundle_root.join("packs");
    if let Ok(entries) = std::fs::read_dir(&packs_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().is_some_and(|e| e == "gtpack") {
                paths.push(p);
            }
        }
    }
    paths
}

/// Build pack_id -> path index from a list of .gtpack paths.
fn build_pack_index(paths: &[PathBuf]) -> BTreeMap<String, PathBuf> {
    let mut index = BTreeMap::new();
    for path in paths {
        if let Ok(pack_id) = read_pack_id(path) {
            index.insert(pack_id, path.clone());
        } else if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            index.insert(stem.to_string(), path.clone());
        }
    }
    index
}

/// Build capability_name -> pack_path index from all packs.
fn build_capability_index(paths: &[PathBuf]) -> BTreeMap<String, PathBuf> {
    let mut index = BTreeMap::new();
    for path in paths {
        if let Ok(manifest) = read_manifest(path) {
            for cap in &manifest.capabilities {
                index.entry(cap.name.clone()).or_insert_with(|| path.clone());
            }
        }
    }
    index
}

fn read_pack_id(path: &Path) -> anyhow::Result<String> {
    let manifest = read_manifest(path)?;
    Ok(manifest.pack_id.to_string())
}

fn read_dependencies(
    path: &Path,
) -> anyhow::Result<Vec<greentic_types::pack_manifest::PackDependency>> {
    let manifest = read_manifest(path)?;
    Ok(manifest.dependencies)
}

fn read_manifest(path: &Path) -> anyhow::Result<greentic_types::pack_manifest::PackManifest> {
    let file = std::fs::File::open(path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut entry = archive.by_name("manifest.cbor").map_err(|err| {
        anyhow::anyhow!("failed to open manifest.cbor in {}: {err}", path.display())
    })?;
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes)?;
    decode_pack_manifest(&bytes)
        .with_context(|| format!("failed to decode manifest in {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_gtpacks_finds_provider_and_pack_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("providers/messaging")).unwrap();
        std::fs::create_dir_all(root.join("packs")).unwrap();
        std::fs::write(root.join("providers/messaging/a.gtpack"), b"").unwrap();
        std::fs::write(root.join("packs/b.gtpack"), b"").unwrap();
        std::fs::write(root.join("packs/not-a-pack.txt"), b"").unwrap();

        let paths = collect_all_gtpacks(root);
        assert_eq!(paths.len(), 2);
        assert!(paths.iter().any(|p| p.ends_with("a.gtpack")));
        assert!(paths.iter().any(|p| p.ends_with("b.gtpack")));
    }

    #[test]
    fn empty_bundle_produces_empty_report() {
        let dir = tempfile::tempdir().unwrap();
        let report = check_all(dir.path()).unwrap();
        assert!(report.satisfied.is_empty());
        assert!(report.missing.is_empty());
    }

    #[test]
    fn build_pack_index_falls_back_to_file_stem() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("my-pack.gtpack");
        std::fs::write(&fake, b"not a real zip").unwrap();
        let index = build_pack_index(&[fake]);
        assert!(index.contains_key("my-pack"));
    }
}
