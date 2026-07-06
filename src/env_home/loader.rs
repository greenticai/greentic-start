//! Boot a `(DemoPaths, DemoConfig)` pair from a greentic-deployer environment
//! home, by selecting the routed revision, verifying its pinned packs, and
//! reusing greentic-start's existing bundle-directory config resolver.
//!
//! An env-home's routed revision already contains a fully-extracted,
//! normalized bundle at `<store-root>/<env>/revisions/<rev>/bundle/`
//! (`bundle-manifest.json`, `packs/*.gtpack`, and a bundle config yaml) — the
//! same shape greentic-start's `--bundle` path already knows how to load. So
//! this module does not build a synthetic directory or re-implement pack
//! loading: it verifies the pinned packs in place, then points
//! [`bundle_config::resolve_bundle_dir_paths`] at `<rev>/bundle/` and calls
//! the unchanged [`bundle_config::load_runtime_demo_config`].

use std::path::{Path, PathBuf};

use super::{
    EnvHomeError, PackListLock, parse_runtime_config, select_routed_revisions, verify_pack_list,
};
use crate::StartRequest;
use crate::bundle_config::{self, DemoPaths};
use crate::config::DemoConfig;

/// Boot from `<store_root>/<env>`.
///
/// Reads `runtime-config.json`, selects the routed revision (slice 1a: a
/// single fully-weighted revision per deployment), verifies every pack
/// pinned by that revision's `pack_list_refs` lockfiles against their
/// on-disk digest, then resolves and loads the routed revision's
/// `<rev>/bundle/` directory exactly as the existing `--bundle` boot path
/// does.
///
/// Never falls back to another boot mode: any parse, schema, traffic-split,
/// missing-artifact, or digest-mismatch error aborts the boot.
// Consumed by run_start in Task 6; not yet wired in-crate.
#[allow(dead_code)]
pub(crate) fn load_env_home(
    store_root: &Path,
    env: &str,
    request: &StartRequest,
) -> anyhow::Result<(DemoPaths, DemoConfig)> {
    let env_home = store_root.join(env);
    let rc_path = env_home.join("runtime-config.json");
    if !rc_path.exists() {
        return Err(EnvHomeError::NotDeployed {
            env: env.to_string(),
            path: rc_path,
        }
        .into());
    }

    let rc_bytes = std::fs::read(&rc_path).map_err(EnvHomeError::from)?;
    let rc = parse_runtime_config(&rc_bytes)?;
    let routed = select_routed_revisions(&rc)?;
    let block = routed
        .first()
        .copied()
        .ok_or_else(|| EnvHomeError::NoRoutedRevision {
            env: env.to_string(),
        })?;

    for lock_ref in &block.pack_list_refs {
        let lock_path = env_home.join(lock_ref);
        let lock_bytes = std::fs::read(&lock_path)
            .map_err(|_| EnvHomeError::MissingArtifact(lock_path.clone()))?;
        let lock: PackListLock =
            serde_json::from_slice(&lock_bytes).map_err(|source| EnvHomeError::Json {
                path: lock_path.clone(),
                source,
            })?;
        verify_pack_list(&env_home, &lock)?;
    }

    let bundle_dir: PathBuf = env_home
        .join("revisions")
        .join(&block.revision_id)
        .join("bundle");
    let paths = bundle_config::resolve_bundle_dir_paths(&bundle_dir)?;
    let config = bundle_config::load_runtime_demo_config(&paths, request)?;
    Ok((paths, config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_home::EnvHomeError;
    use crate::{CloudflaredModeArg, NatsModeArg, NgrokModeArg};
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;

    fn test_request() -> StartRequest {
        StartRequest {
            bundle: None,
            store_root: None,
            env: "local".to_string(),
            tenant: None,
            team: None,
            no_nats: false,
            nats: NatsModeArg::Off,
            nats_url: None,
            config: None,
            cloudflared: CloudflaredModeArg::Off,
            cloudflared_binary: None,
            ngrok: NgrokModeArg::Off,
            ngrok_binary: None,
            runner_binary: None,
            restart: Vec::new(),
            log_dir: None,
            verbose: false,
            quiet: false,
            no_browser: false,
            admin: false,
            admin_port: 9443,
            admin_certs_dir: None,
            admin_allowed_clients: Vec::new(),
            tunnel_explicit: true,
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut out = String::with_capacity("sha256:".len() + digest.len() * 2);
        out.push_str("sha256:");
        for byte in digest {
            let _ = write!(&mut out, "{byte:02x}");
        }
        out
    }

    /// Build a minimal env-home: `runtime-config.json` +
    /// `revisions/r1/{pack-list.lock, bundle/...}`, where `bundle/` is shaped
    /// exactly as `bundle_config::resolve_bundle_dir_paths` (the
    /// `NormalizedBundle` inference path) requires: a `bundle.yaml` plus a
    /// `bundle-manifest.json` sentinel (its content is never parsed, only its
    /// presence is checked).
    fn fixture_env_home() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let env = dir.path().join("local");
        let rev = env.join("revisions/r1");
        let bundle_dir = rev.join("bundle");
        let packs = bundle_dir.join("packs");
        std::fs::create_dir_all(&packs).unwrap();

        let pack_bytes = b"pack-bytes";
        std::fs::write(packs.join("a.gtpack"), pack_bytes).unwrap();
        let digest = sha256_hex(pack_bytes);

        std::fs::write(
            bundle_dir.join("bundle.yaml"),
            "tenant: acme\nteam: default\n",
        )
        .unwrap();
        // Sentinel that marks this bundle.yaml as a normalized-bundle payload
        // (see bundle_config::normalized_bundle_has_runtime_payload).
        std::fs::write(bundle_dir.join("bundle-manifest.json"), "{}").unwrap();

        std::fs::write(
            rev.join("pack-list.lock"),
            format!(
                r#"{{"schema":"greentic.pack-list-lock.v1","revision_id":"r1","packs":[{{"pack_id":"a","path":"revisions/r1/bundle/packs/a.gtpack","digest":"{digest}"}}]}}"#
            ),
        )
        .unwrap();

        std::fs::write(
            env.join("runtime-config.json"),
            r#"{"schema":"greentic.runtime-config.v1","env_id":"local","revisions":[{"deployment_id":"d1","revision_id":"r1","bundle_id":"app","pack_list_refs":["revisions/r1/pack-list.lock"],"pack_config_refs":[],"weight_bps":10000}]}"#,
        )
        .unwrap();

        dir
    }

    #[test]
    fn load_env_home_points_root_at_revision_bundle_dir() {
        let dir = fixture_env_home();
        let req = test_request();
        let (paths, config) = load_env_home(dir.path(), "local", &req).expect("load");
        assert!(paths.root_dir.ends_with("revisions/r1/bundle"));
        assert_eq!(config.tenant, "acme");
        assert_eq!(config.team, "default");
    }

    #[test]
    fn not_deployed_when_runtime_config_absent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("local")).unwrap();
        let req = test_request();
        let err = load_env_home(dir.path(), "local", &req).unwrap_err();
        assert!(
            err.downcast_ref::<EnvHomeError>()
                .map(|e| matches!(e, EnvHomeError::NotDeployed { .. }))
                .unwrap_or(false)
        );
    }

    #[test]
    fn digest_mismatch_rejects_tampered_pack() {
        let dir = fixture_env_home();
        // Tamper with the pack after the lockfile has pinned its digest.
        std::fs::write(
            dir.path().join("local/revisions/r1/bundle/packs/a.gtpack"),
            b"tampered",
        )
        .unwrap();
        let req = test_request();
        let err = load_env_home(dir.path(), "local", &req).unwrap_err();
        assert!(
            err.downcast_ref::<EnvHomeError>()
                .map(|e| matches!(e, EnvHomeError::DigestMismatch { .. }))
                .unwrap_or(false)
        );
    }
}
