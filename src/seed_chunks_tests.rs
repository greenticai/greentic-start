use super::*;
use greentic_deploy_spec::secret_chunks::{self as protocol, ChunkManifest};
use tempfile::tempdir;

fn staged(seed: &Path, len: usize) -> Vec<u8> {
    let mut state = 0xa3bf1897u32;
    let bytes: Vec<_> = (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let versions: Vec<_> = (1..=len.div_ceil(protocol::CHUNK_BYTES))
        .map(|n| n.to_string())
        .collect();
    let m = ChunkManifest::new(&bytes, &versions).unwrap();
    fs::create_dir_all(seed.join(protocol::CHUNK_DIR)).unwrap();
    for c in &m.chunks {
        fs::write(
            seed.join(&c.path),
            &bytes[c.index * protocol::CHUNK_BYTES..c.index * protocol::CHUNK_BYTES + c.length],
        )
        .unwrap();
    }
    fs::write(seed.join(protocol::MANIFEST_PATH), m.encode().unwrap()).unwrap();
    fs::write(seed.join("environment.json"), b"{}").unwrap();
    bytes
}
#[test]
fn chunked_boot_reconstructs_full_store_privately_and_supports_legacy_rollback() {
    for len in [65_537, 70_737, 2 * 1024 * 1024 + 31] {
        let seed = tempdir().unwrap();
        let dest = tempdir().unwrap();
        let bytes = staged(seed.path(), len);
        seed_env_store_from_with_transport(seed.path(), dest.path(), Some(protocol::SCHEMA))
            .unwrap();
        let installed = dest.path().join(protocol::STORE_PATH);
        assert_eq!(fs::read(&installed).unwrap(), bytes);
        assert!(!dest.path().join(protocol::MANIFEST_PATH).exists());
        assert!(!dest.path().join(protocol::CHUNK_DIR).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&installed).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        seed_env_store_from(seed.path(), dest.path()).unwrap(); // retry
        let legacy = tempdir().unwrap();
        fs::create_dir_all(legacy.path().join(".greentic/dev")).unwrap();
        let old = vec![7; 65_536];
        fs::write(legacy.path().join(protocol::STORE_PATH), &old).unwrap();
        seed_env_store_from(legacy.path(), dest.path()).unwrap();
        assert_eq!(fs::read(&installed).unwrap(), old);
        seed_env_store_from(seed.path(), dest.path()).unwrap();
        assert_eq!(fs::read(&installed).unwrap(), bytes);
    }
}
#[test]
fn damaged_mount_never_replaces_existing_secret_file_or_environment() {
    for case in 0..7 {
        let seed = tempdir().unwrap();
        let dest = tempdir().unwrap();
        staged(
            seed.path(),
            if case == 2 {
                protocol::CHUNK_BYTES * 2 + 19
            } else {
                70_737
            },
        );
        fs::create_dir_all(dest.path().join(".greentic/dev")).unwrap();
        fs::write(
            dest.path().join(protocol::STORE_PATH),
            b"existing encrypted store",
        )
        .unwrap();
        fs::write(
            dest.path().join("environment.json"),
            b"previous environment",
        )
        .unwrap();
        match case {
            0 => fs::remove_file(seed.path().join(protocol::chunk_path(0))).unwrap(),
            1 => fs::write(
                seed.path().join(protocol::chunk_path(0)),
                b"sensitive-credential-content",
            )
            .unwrap(),
            2 => {
                let a = seed.path().join(protocol::chunk_path(0));
                let b = seed.path().join(protocol::chunk_path(1));
                let x = fs::read(&a).unwrap();
                fs::write(&a, fs::read(&b).unwrap()).unwrap();
                fs::write(&b, x).unwrap();
            }
            3 => fs::write(
                seed.path().join(protocol::CHUNK_DIR).join("duplicate.bin"),
                b"duplicate",
            )
            .unwrap(),
            4 => fs::remove_file(seed.path().join(protocol::MANIFEST_PATH)).unwrap(),
            5 => fs::write(
                seed.path().join(protocol::MANIFEST_PATH),
                b"{\"schema\":\"sensitive-credential-content\"}",
            )
            .unwrap(),
            _ => fs::write(
                seed.path().join(protocol::STORE_PATH),
                b"ambiguous legacy store",
            )
            .unwrap(),
        }
        let err = seed_env_store_from(seed.path(), dest.path()).unwrap_err();
        assert!(!format!("{err:#}").contains("sensitive-credential-content"));
        assert_eq!(
            fs::read(dest.path().join(protocol::STORE_PATH)).unwrap(),
            b"existing encrypted store"
        );
        assert_eq!(
            fs::read(dest.path().join("environment.json")).unwrap(),
            b"previous environment"
        );
    }
}
#[cfg(unix)]
#[test]
fn source_symlink_does_not_escape_seed_root() {
    let seed = tempdir().unwrap();
    let dest = tempdir().unwrap();
    let outside = tempdir().unwrap();
    staged(seed.path(), 70_737);
    let chunk = seed.path().join(protocol::chunk_path(0));
    fs::remove_file(&chunk).unwrap();
    let private = outside.path().join("private");
    fs::write(&private, b"sensitive-credential-content").unwrap();
    std::os::unix::fs::symlink(&private, &chunk).unwrap();
    assert!(seed_env_store_from(seed.path(), dest.path()).is_err());
    assert!(!dest.path().join(protocol::STORE_PATH).exists());
}

#[test]
fn explicit_transport_marker_requires_the_entire_mount_and_rejects_unknown_protocols() {
    let seed = tempdir().unwrap();
    let dest = tempdir().unwrap();
    fs::write(seed.path().join("environment.json"), b"{}").unwrap();
    fs::create_dir_all(dest.path().join(".greentic/dev")).unwrap();
    fs::write(dest.path().join(protocol::STORE_PATH), b"previous store").unwrap();
    for marker in [protocol::SCHEMA, "unknown-sensitive-value"] {
        let error =
            seed_env_store_from_with_transport(seed.path(), dest.path(), Some(marker)).unwrap_err();
        assert!(!format!("{error:#}").contains("unknown-sensitive-value"));
        assert_eq!(
            fs::read(dest.path().join(protocol::STORE_PATH)).unwrap(),
            b"previous store"
        );
        assert!(!dest.path().join("environment.json").exists());
    }
    // Absence of a store remains valid for legacy environments without secrets.
    seed_env_store_from(seed.path(), dest.path()).unwrap();
    assert_eq!(
        fs::read(dest.path().join(protocol::STORE_PATH)).unwrap(),
        b"previous store"
    );
}
