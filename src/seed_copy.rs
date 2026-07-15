//! Early-boot environment-store seeding for init-container-less platforms.
//!
//! Cloud Run (and Azure Container Apps / Fargate) have no Kubernetes-style init
//! container, and the runtime image is distroless (no shell, so no `cp`/`rsync`
//! wrapper can run before the binary). They instead mount the env-store seed —
//! `environment.json` and the AES-encrypted `.dev.secrets.env` — as **read-only**
//! Secret Manager volume files. The dev-store, however, opens its file
//! `write(true)` + exclusive `flock` on every read (see `greentic-dev`
//! `Persistence::load`), so a read-only mount cannot be used in place: the seed
//! must be copied into the writable, `$HOME`-rooted store first, with the
//! read-only permission bits stripped.
//!
//! When `GREENTIC_SEED_DIR` is set, [`maybe_seed_env_store`] copies that
//! directory's tree into the store directory of the **resolved** environment
//! (`LocalFsStore::default_root()/<GREENTIC_ENV>`, alias-normalized so it matches
//! what the store itself opens) **before** `bootstrap_local_environment` opens it.
//! Each file is installed atomically (copy to a sibling temp file, force
//! owner-read/write `0600`, then `rename`), so a read-only source lands writable,
//! a pre-existing destination symlink is replaced rather than written through,
//! and a partial copy never leaves a truncated file. The seed is authoritative
//! immutable boot configuration re-materialized identically on every cold start:
//! existing destination files are overwritten (seed wins) and unrelated files are
//! left in place (overlay).
//!
//! Security posture: the copy is scoped to a single resolved environment dir,
//! symlinks are **skipped** (never followed into or out of the store), and the
//! seed and destination must not overlap. An empty seed is rejected as a
//! misconfiguration rather than silently booting a blank environment.
//!
//! Deliberately out of scope for this step (deployer-contract / follow-up work):
//! multi-file transactional publication with a completion marker, a per-file
//! digest manifest that rejects incomplete/extra files, and pruning of stale
//! seed-owned files. On Cloud Run the container filesystem is fresh per instance
//! and the copy completes before any reader starts, so a boot-time abort is
//! fail-closed; cross-instance durability is a separate durable-store follow-up.
//!
//! Contract with the deployer (producer, a later PR): the directory named by
//! `GREENTIC_SEED_DIR` mirrors a **single** environment's store directory, e.g.
//! `<seed>/environment.json` and `<seed>/.greentic/dev/.dev.secrets.env`, and the
//! deployer sets `GREENTIC_ENV` to that environment's id.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::operator_log;

/// Environment variable naming the read-only seed directory to copy into the
/// env-store before boot. Unset on interactive/local runs (the step is a no-op).
pub(crate) const SEED_DIR_ENV: &str = "GREENTIC_SEED_DIR";

/// If `GREENTIC_SEED_DIR` is set, copy its tree into the resolved environment's
/// store directory (writable, `$HOME`-rooted) before the store is opened. No-op
/// when the variable is unset.
///
/// Must be called in the synchronous, single-threaded early-boot section, after
/// `GREENTIC_ENV` is resolved and before the first env-store access.
pub(crate) fn maybe_seed_env_store() -> anyhow::Result<()> {
    let Some(seed) = std::env::var_os(SEED_DIR_ENV) else {
        return Ok(());
    };
    let seed_dir = PathBuf::from(seed);

    // Resolve the env id the SAME way the store does (applies the `dev`->`local`
    // alias), so the seed lands in the directory `bootstrap_local_environment`
    // and the dev-store will actually open — not a divergent raw `$GREENTIC_ENV`.
    let env_id = crate::resolve_env(None);
    greentic_types::EnvId::new(&env_id)
        .with_context(|| format!("cannot seed: invalid environment id `{env_id}`"))?;

    let store_root = greentic_deployer::environment::LocalFsStore::default_root().context(
        "GREENTIC_SEED_DIR is set but no home directory is available to seed the \
         environment store into (set $HOME to a writable path)",
    )?;
    let dest = store_root.join(&env_id);

    // Refuse to copy the seed into (or from) itself: an overlap would let the
    // recursive walk truncate a file onto itself or grow into its own output.
    let seed_canon = fs::canonicalize(&seed_dir).with_context(|| {
        format!(
            "GREENTIC_SEED_DIR points to a path that does not exist or is unreadable: `{}`",
            seed_dir.display()
        )
    })?;
    if dest.starts_with(&seed_canon) || seed_canon.starts_with(&dest) {
        anyhow::bail!(
            "GREENTIC_SEED_DIR `{}` overlaps the environment store destination `{}`; \
             refusing to copy",
            seed_canon.display(),
            dest.display()
        );
    }

    operator_log::info(
        module_path!(),
        format!(
            "seeding environment `{env_id}` from `{}` into `{}`",
            seed_dir.display(),
            dest.display()
        ),
    );
    let copied = seed_env_store_from(&seed_dir, &dest)?;
    operator_log::info(
        module_path!(),
        format!("seeded {copied} file(s) into environment `{env_id}`"),
    );
    Ok(())
}

/// Copy `seed_dir` recursively into `dest_root`, returning the number of files
/// copied. Fails if `seed_dir` does not exist, is not a directory, or contains no
/// files (a zero-file seed is treated as a misconfigured/partial mount).
///
/// Exposed for integration tests; production callers use `maybe_seed_env_store`.
pub fn seed_env_store_from(seed_dir: &Path, dest_root: &Path) -> anyhow::Result<u64> {
    let meta = fs::metadata(seed_dir).with_context(|| {
        format!(
            "GREENTIC_SEED_DIR points to a path that does not exist or is unreadable: `{}`",
            seed_dir.display()
        )
    })?;
    if !meta.is_dir() {
        anyhow::bail!(
            "GREENTIC_SEED_DIR must be a directory, but `{}` is not",
            seed_dir.display()
        );
    }

    let copied = copy_tree_into(seed_dir, dest_root)
        .with_context(|| format!("seeding environment store from `{}`", seed_dir.display()))?;
    if copied == 0 {
        anyhow::bail!(
            "GREENTIC_SEED_DIR `{}` contained no files to seed (empty or partial mount?)",
            seed_dir.display()
        );
    }
    Ok(copied)
}

/// Recursively overlay the regular files of `src` onto `dst`, creating
/// directories as needed. Real directories are recursed; real files are installed
/// atomically and writable via [`install_file`]. Symlinks and special files are
/// **skipped** (never followed) — a read-only Secret Manager mount exposes only
/// regular files, and refusing symlinks keeps the copy from escaping the seed
/// root or writing through a destination link.
fn copy_tree_into(src: &Path, dst: &Path) -> anyhow::Result<u64> {
    fs::create_dir_all(dst)
        .with_context(|| format!("creating seed destination `{}`", dst.display()))?;

    let mut copied = 0u64;
    let entries =
        fs::read_dir(src).with_context(|| format!("reading seed directory `{}`", src.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("reading an entry under `{}`", src.display()))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        // `file_type()` does not follow symlinks: `is_dir`/`is_file` are true only
        // for real directories/files, so links fall through to the skip branch.
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspecting `{}`", from.display()))?;

        if file_type.is_dir() {
            copied += copy_tree_into(&from, &to)?;
        } else if file_type.is_file() {
            install_file(&from, &to)?;
            copied += 1;
        } else {
            operator_log::debug(
                module_path!(),
                format!(
                    "seed: skipping non-regular entry (symlink/special) `{}`",
                    from.display()
                ),
            );
        }
    }
    Ok(copied)
}

/// Install one regular file at `to`, atomically and writable: copy `from` to a
/// sibling temp file, force owner read/write (`0600` on Unix, clear the
/// read-only attribute elsewhere), then `rename` over `to`. The rename replaces a
/// pre-existing destination — including a symlink — with a regular file, and a
/// crash mid-copy leaves only the temp file, never a truncated `to`.
fn install_file(from: &Path, to: &Path) -> anyhow::Result<()> {
    let parent = to
        .parent()
        .with_context(|| format!("destination `{}` has no parent directory", to.display()))?;
    let file_name = to
        .file_name()
        .with_context(|| format!("destination `{}` has no file name", to.display()))?;
    let mut tmp_name = std::ffi::OsString::from(".seedtmp.");
    tmp_name.push(file_name);
    let tmp = parent.join(tmp_name);

    let result = (|| {
        fs::copy(from, &tmp)
            .with_context(|| format!("copying `{}` -> `{}`", from.display(), tmp.display()))?;
        set_writable(&tmp)?;
        fs::rename(&tmp, to)
            .with_context(|| format!("installing `{}` -> `{}`", tmp.display(), to.display()))?;
        Ok(())
    })();

    if result.is_err() {
        // Best-effort cleanup so a failed install does not litter the store.
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Force `path` to be readable and writable by the owning (runtime) user, undoing
/// the read-only bits a Secret Manager mount stamps on the source file.
#[cfg(unix)]
fn set_writable(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("setting writable permissions on `{}`", path.display()))
}

#[cfg(not(unix))]
fn set_writable(path: &Path) -> anyhow::Result<()> {
    let mut perms = fs::metadata(path)
        .with_context(|| format!("reading permissions of `{}`", path.display()))?
        .permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    fs::set_permissions(path, perms)
        .with_context(|| format!("clearing read-only attribute on `{}`", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn copies_nested_tree_and_counts_files() {
        let src = tempdir().unwrap();
        let dst = tempdir().unwrap();
        fs::create_dir_all(src.path().join(".greentic/dev")).unwrap();
        fs::write(src.path().join("environment.json"), b"{\"id\":\"local\"}").unwrap();
        fs::write(
            src.path().join(".greentic/dev/.dev.secrets.env"),
            b"SECRET=1",
        )
        .unwrap();

        let n = copy_tree_into(src.path(), dst.path()).unwrap();
        assert_eq!(n, 2);
        assert_eq!(
            fs::read(dst.path().join("environment.json")).unwrap(),
            b"{\"id\":\"local\"}"
        );
        assert_eq!(
            fs::read(dst.path().join(".greentic/dev/.dev.secrets.env")).unwrap(),
            b"SECRET=1"
        );
    }

    #[test]
    fn overwrites_existing_and_preserves_unrelated() {
        let src = tempdir().unwrap();
        let dst = tempdir().unwrap();
        fs::write(src.path().join("a.txt"), b"new").unwrap();
        fs::write(dst.path().join("a.txt"), b"old").unwrap();
        fs::write(dst.path().join("keep.txt"), b"keep").unwrap();

        let n = copy_tree_into(src.path(), dst.path()).unwrap();
        assert_eq!(n, 1);
        assert_eq!(fs::read(dst.path().join("a.txt")).unwrap(), b"new");
        assert_eq!(fs::read(dst.path().join("keep.txt")).unwrap(), b"keep");
    }

    // The deployment-defining case: a read-only (0444) source — exactly what a
    // Secret Manager mount exposes — must land writable so the dev-store can open
    // it write+flock.
    #[cfg(unix)]
    #[test]
    fn read_only_source_lands_writable() {
        use std::os::unix::fs::PermissionsExt;
        let src = tempdir().unwrap();
        let dst = tempdir().unwrap();
        let ro = src.path().join(".dev.secrets.env");
        fs::write(&ro, b"TOKEN=abc").unwrap();
        fs::set_permissions(&ro, fs::Permissions::from_mode(0o444)).unwrap();

        let n = copy_tree_into(src.path(), dst.path()).unwrap();
        assert_eq!(n, 1);

        let landed = dst.path().join(".dev.secrets.env");
        let mode = fs::metadata(&landed).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "seeded secret must be owner read/write");
        // Prove it is genuinely writable (open for write, as the dev-store does).
        assert!(
            fs::OpenOptions::new().write(true).open(&landed).is_ok(),
            "seeded file must be writable"
        );
    }

    #[cfg(unix)]
    #[test]
    fn skips_symlinks_without_following() {
        use std::os::unix::fs::symlink;
        let src = tempdir().unwrap();
        let dst = tempdir().unwrap();
        let real = src.path().join("real.env");
        fs::write(&real, b"VALUE=42").unwrap();
        symlink(&real, src.path().join("link.env")).unwrap();
        symlink("/etc/hostname", src.path().join("escape.env")).unwrap();

        let n = copy_tree_into(src.path(), dst.path()).unwrap();
        assert_eq!(n, 1, "only the real file is copied; symlinks are skipped");
        assert!(dst.path().join("real.env").is_file());
        assert!(!dst.path().join("link.env").exists());
        assert!(!dst.path().join("escape.env").exists());
    }

    #[cfg(unix)]
    #[test]
    fn replaces_destination_symlink_with_regular_file() {
        use std::os::unix::fs::symlink;
        let src = tempdir().unwrap();
        let dst = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let victim = outside.path().join("victim");
        fs::write(&victim, b"do-not-touch").unwrap();

        fs::write(src.path().join("environment.json"), b"seed").unwrap();
        // A pre-existing destination symlink must NOT be written through.
        symlink(&victim, dst.path().join("environment.json")).unwrap();

        copy_tree_into(src.path(), dst.path()).unwrap();

        assert_eq!(
            fs::read(&victim).unwrap(),
            b"do-not-touch",
            "symlink target untouched"
        );
        let landed = dst.path().join("environment.json");
        assert!(
            !fs::symlink_metadata(&landed)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&landed).unwrap(), b"seed");
    }

    #[test]
    fn empty_source_errors() {
        let src = tempdir().unwrap();
        let dst = tempdir().unwrap();
        let err = seed_env_store_from(src.path(), dst.path()).unwrap_err();
        assert!(err.to_string().contains("no files to seed"));
    }

    #[test]
    fn errors_on_missing_source() {
        let dst = tempdir().unwrap();
        let missing = dst.path().join("nope");
        let err = seed_env_store_from(&missing, dst.path()).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn errors_when_source_is_a_file() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("seed-file");
        fs::write(&file, b"x").unwrap();
        let err = seed_env_store_from(&file, dir.path()).unwrap_err();
        assert!(err.to_string().contains("must be a directory"));
    }

    #[test]
    fn maybe_seed_is_noop_when_env_unset() {
        let _guard = crate::test_env_lock().lock().unwrap();
        // SAFETY: guarded by the process-wide test env lock.
        unsafe {
            std::env::remove_var(SEED_DIR_ENV);
        }
        maybe_seed_env_store().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn maybe_seed_copies_into_resolved_env_dir_writable() {
        let _guard = crate::test_env_lock().lock().unwrap();
        let seed = tempdir().unwrap();
        let home = tempdir().unwrap();
        fs::write(seed.path().join("environment.json"), b"{}").unwrap();

        let prev_home = std::env::var_os("HOME");
        let prev_seed = std::env::var_os(SEED_DIR_ENV);
        let prev_env = std::env::var_os("GREENTIC_ENV");
        // SAFETY: guarded by the process-wide test env lock; restored below.
        unsafe {
            std::env::set_var("HOME", home.path());
            std::env::set_var(SEED_DIR_ENV, seed.path());
            std::env::set_var("GREENTIC_ENV", crate::DEFAULT_ENV_ID);
        }

        let res = maybe_seed_env_store();

        // Restore before asserting so a failing assert never poisons sibling tests.
        // SAFETY: still holding the env lock.
        unsafe {
            restore("HOME", prev_home);
            restore(SEED_DIR_ENV, prev_seed);
            restore("GREENTIC_ENV", prev_env);
        }
        res.unwrap();

        let landed = home
            .path()
            .join(".greentic/environments")
            .join(crate::DEFAULT_ENV_ID)
            .join("environment.json");
        assert!(landed.is_file(), "expected {} to exist", landed.display());
        assert!(fs::OpenOptions::new().write(true).open(&landed).is_ok());
    }

    #[cfg(unix)]
    unsafe fn restore(key: &str, prev: Option<std::ffi::OsString>) {
        match prev {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
    }
}
