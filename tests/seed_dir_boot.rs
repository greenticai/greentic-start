//! Integration coverage for the `GREENTIC_SEED_DIR` early-boot copy.
//!
//! Exercises the public `seed_env_store_from` across the crate boundary with a
//! realistic Secret-Manager-style seed tree. Per the deployer contract, the seed
//! directory mirrors a SINGLE environment's store directory: `environment.json`
//! plus the nested dev-store secrets file at the seed root (no `<env>/` prefix).

use std::fs;

use tempfile::tempdir;

#[test]
fn seeds_single_environment_tree_from_seed_dir() {
    let seed = tempdir().unwrap();
    let dest = tempdir().unwrap();

    fs::create_dir_all(seed.path().join(".greentic/dev")).unwrap();
    fs::write(seed.path().join("environment.json"), b"{\"id\":\"local\"}").unwrap();
    fs::write(
        seed.path().join(".greentic/dev/.dev.secrets.env"),
        b"TELEGRAM_TOKEN=abc",
    )
    .unwrap();

    let copied = greentic_start::seed_env_store_from(seed.path(), dest.path()).unwrap();
    assert_eq!(copied, 2, "both seed files should be copied");

    assert_eq!(
        fs::read(dest.path().join("environment.json")).unwrap(),
        b"{\"id\":\"local\"}"
    );
    assert_eq!(
        fs::read(dest.path().join(".greentic/dev/.dev.secrets.env")).unwrap(),
        b"TELEGRAM_TOKEN=abc"
    );
    // The copied files must be writable so the dev-store can open them write+flock.
    assert!(
        fs::OpenOptions::new()
            .write(true)
            .open(dest.path().join(".greentic/dev/.dev.secrets.env"))
            .is_ok()
    );
}

#[test]
fn seeding_is_idempotent_and_overwrites() {
    let seed = tempdir().unwrap();
    let dest = tempdir().unwrap();
    fs::write(seed.path().join("environment.json"), b"v2").unwrap();

    // Pre-existing stale content at the destination is overwritten (seed wins),
    // and a second seed run reproduces the same result (cold-start idempotency).
    fs::write(dest.path().join("environment.json"), b"v1-stale").unwrap();

    let first = greentic_start::seed_env_store_from(seed.path(), dest.path()).unwrap();
    let second = greentic_start::seed_env_store_from(seed.path(), dest.path()).unwrap();
    assert_eq!(first, 1);
    assert_eq!(second, 1);
    assert_eq!(
        fs::read(dest.path().join("environment.json")).unwrap(),
        b"v2"
    );
}

#[test]
fn empty_seed_is_rejected() {
    let seed = tempdir().unwrap();
    let dest = tempdir().unwrap();
    let err = greentic_start::seed_env_store_from(seed.path(), dest.path()).unwrap_err();
    assert!(err.to_string().contains("no files to seed"));
}
