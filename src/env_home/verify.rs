//! Verify on-disk `.gtpack` artifacts against the digests pinned in a
//! `pack-list.lock` document.
//!
//! `greentic-deployer` writes a `PackListLock` per revision, pinning each
//! pack's env-relative path and expected `sha256:<hex>` content digest. Before
//! `greentic-start` boots a revision's packs, it must recompute each pack's
//! digest and compare against the pinned value, refusing to start on any
//! mismatch or missing artifact.

use super::{EnvHomeError, LockedPack, PackListLock};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Stream-hash `path` with SHA-256, returning `"sha256:<lowercase-hex>"`.
///
/// Reads in fixed-size chunks rather than loading the whole file into memory,
/// since `.gtpack` artifacts may be large.
fn sha256_hex(path: &Path) -> Result<String, EnvHomeError> {
    let mut file =
        std::fs::File::open(path).map_err(|_| EnvHomeError::MissingArtifact(path.to_path_buf()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut output = String::with_capacity("sha256:".len() + digest.len() * 2);
    output.push_str("sha256:");
    for byte in digest {
        let _ = write!(&mut output, "{byte:02x}");
    }
    Ok(output)
}

/// Verify every pack pinned in `lock` is present under `env_home` and its
/// on-disk content digest matches the pinned digest.
///
/// Returns the verified absolute paths (in `lock.packs` order) on success.
/// Errors on the first `LockedPack` that is missing on disk
/// ([`EnvHomeError::MissingArtifact`]) or whose recomputed digest doesn't
/// match the pinned one ([`EnvHomeError::DigestMismatch`]).
pub fn verify_pack_list(
    env_home: &Path,
    lock: &PackListLock,
) -> Result<Vec<PathBuf>, EnvHomeError> {
    let mut verified = Vec::with_capacity(lock.packs.len());
    for LockedPack {
        pack_id,
        path,
        digest,
    } in &lock.packs
    {
        let abs = env_home.join(path);
        if !abs.exists() {
            return Err(EnvHomeError::MissingArtifact(abs));
        }
        let actual = sha256_hex(&abs)?;
        if &actual != digest {
            return Err(EnvHomeError::DigestMismatch {
                pack_id: pack_id.clone(),
                expected: digest.clone(),
                actual,
            });
        }
        verified.push(abs);
    }
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_home::{EnvHomeError, LockedPack, PACK_LIST_LOCK_SCHEMA, PackListLock};
    use std::io::Write;

    fn write_pack(dir: &std::path::Path, rel: &str, bytes: &[u8]) -> String {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::File::create(&p).unwrap().write_all(bytes).unwrap();
        let mut h = <sha2::Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut h, bytes);
        let digest = sha2::Digest::finalize(h);
        let mut hex = String::with_capacity("sha256:".len() + digest.len() * 2);
        hex.push_str("sha256:");
        for byte in digest {
            let _ = write!(&mut hex, "{byte:02x}");
        }
        hex
    }

    fn lock_with(packs: Vec<LockedPack>) -> PackListLock {
        PackListLock {
            schema: PACK_LIST_LOCK_SCHEMA.to_string(),
            revision_id: "r1".to_string(),
            packs,
        }
    }

    #[test]
    fn verifies_matching_digest() {
        let dir = tempfile::tempdir().unwrap();
        let digest = write_pack(dir.path(), "revisions/r1/bundle/packs/a.gtpack", b"hello");
        let lock = lock_with(vec![LockedPack {
            pack_id: "a".into(),
            path: "revisions/r1/bundle/packs/a.gtpack".into(),
            digest,
        }]);
        let out = verify_pack_list(dir.path(), &lock).expect("verify");
        assert_eq!(out.len(), 1);
        assert!(out[0].ends_with("a.gtpack"));
    }

    #[test]
    fn rejects_tampered_pack() {
        let dir = tempfile::tempdir().unwrap();
        let digest = write_pack(dir.path(), "p/a.gtpack", b"hello");
        // overwrite with different bytes -> digest no longer matches
        std::fs::write(dir.path().join("p/a.gtpack"), b"tampered").unwrap();
        let lock = lock_with(vec![LockedPack {
            pack_id: "a".into(),
            path: "p/a.gtpack".into(),
            digest,
        }]);
        assert!(matches!(
            verify_pack_list(dir.path(), &lock).unwrap_err(),
            EnvHomeError::DigestMismatch { .. }
        ));
    }

    #[test]
    fn rejects_missing_pack() {
        let dir = tempfile::tempdir().unwrap();
        let lock = lock_with(vec![LockedPack {
            pack_id: "a".into(),
            path: "nope/a.gtpack".into(),
            digest: "sha256:00".into(),
        }]);
        assert!(matches!(
            verify_pack_list(dir.path(), &lock).unwrap_err(),
            EnvHomeError::MissingArtifact(_)
        ));
    }
}
