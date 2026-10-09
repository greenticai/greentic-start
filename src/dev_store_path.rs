#![allow(dead_code)]

//! Dev-store path resolution for the runtime (reader) side.
//!
//! Mirrors `greentic-setup/src/secrets.rs`'s path helpers verbatim so the
//! `setup` (writer) and `start` (reader) sides resolve the dev store to the
//! *same* shared environment store
//! (`~/.greentic/environments/<env>/.greentic/dev/.dev.secrets.env`). This lets
//! `gtc setup` and `gtc start` rendezvous on one file across invocations,
//! independent of any ephemeral bundle extraction dir, and unifies bundle-path
//! secrets with the env-path (`op secrets` / `provider add`) store.
//!
//! The logic is duplicated (not shared via `greentic_setup`) on purpose: the
//! two crates publish on independent cadences and this crate builds against a
//! *registry* `greentic-setup`, so a call into it would resolve the old
//! bundle-local behavior. Keep the two copies in lock-step.
//!
//! # `--store-root` outranks the `$HOME` rendezvous
//!
//! The `$HOME` preference above is right for the rendezvous it was built for —
//! `gtc setup` and a bare `gtc start` both derive the store from the home
//! directory and so land on one file. It is wrong the moment an operator names
//! a different env home with `--store-root`: the runtime then serves revisions
//! out of `<store-root>/<env>/` while the dev store it reads still resolves to
//! `$HOME/.greentic/environments/<env>/`. Secrets staged with
//! `op --store-root <root> secrets put` are read by nobody, every credentialed
//! read misses, and nothing is red anywhere — the deploy succeeds, the process
//! boots, `/livez` answers, and interop calls return `401`.
//!
//! So [`EnvDirOrigin`] splits the two cases. An env dir an operator named
//! ([`EnvDirOrigin::Explicit`]) puts its own store FIRST; `$HOME` stays the
//! fallback for it, and stays first for everyone else
//! ([`EnvDirOrigin::Default`], which is byte-for-byte the previous order). When
//! both exist and differ, [`DevStoreChoice::shadowed`] carries the one that
//! lost so the caller can say so out loud rather than reading the operator's
//! home store in silence.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;

const STORE_RELATIVE: &str = ".greentic/dev/.dev.secrets.env";
const STORE_STATE_RELATIVE: &str = ".greentic/state/dev/.dev.secrets.env";
const OVERRIDE_ENV: &str = "GREENTIC_DEV_SECRETS_PATH";

/// Returns a path explicitly configured via `$GREENTIC_DEV_SECRETS_PATH`.
pub fn override_path() -> Option<PathBuf> {
    env::var(OVERRIDE_ENV).ok().map(PathBuf::from)
}

/// Dev-store path inside the shared environment store:
///   `~/.greentic/environments/<env>/.greentic/dev/.dev.secrets.env`
///
/// The same file `gtc op secrets` / `provider add` and `gtc setup` write, so the
/// serve loop reads exactly what setup registered. Returns `None` when the
/// environment-store root can't be resolved (no `HOME`/`USERPROFILE`), letting
/// callers fall back to a bundle-local path.
pub fn env_store_dev_secrets_path(env: &str) -> Option<PathBuf> {
    greentic_deployer::environment::LocalFsStore::default_root()
        .map(|root| root.join(env).join(STORE_RELATIVE))
}

/// The explicitly-selected environment, or `None` when `$GREENTIC_ENV` is unset.
/// Bare callers route to the shared env store only when an env is selected;
/// `start` sets `$GREENTIC_ENV` at boot, so production always resolves it, while
/// unit tests (which leave it unset) stay on the hermetic bundle-local store.
fn selected_env() -> Option<String> {
    env::var("GREENTIC_ENV")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|raw| crate::resolve_env(Some(&raw)))
}

/// The path a *write* should target for an explicit env: the shared env store
/// when resolvable, otherwise the legacy bundle-local path.
fn write_path_for_env(bundle_root: &Path, env: &str) -> PathBuf {
    env_store_dev_secrets_path(env).unwrap_or_else(|| bundle_root.join(STORE_RELATIVE))
}

/// Whether the directory a store is being resolved against was named by the
/// operator, or merely derived from the default home-rooted store.
///
/// This is the whole of what `--store-root` contributes to the decision: the
/// caller has already resolved the env dir (`<store-root>/<env>`), so the only
/// fact this module cannot recover for itself is whether an operator chose it.
/// Taking the answer rather than re-deriving it also keeps this resolution on
/// exactly the directory the runtime serves revisions from — `--env` and
/// `$GREENTIC_ENV` can disagree, and the store must follow the revisions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EnvDirOrigin {
    /// No `--store-root`: keep the historical `$HOME`-first order.
    #[default]
    Default,
    /// `--store-root` named this env dir, so its own store wins.
    Explicit,
}

impl EnvDirOrigin {
    /// The origin implied by a `--store-root` value: `Some` means the operator
    /// named the env home, `None` means it was derived from the default store.
    ///
    /// This one-line rule lives here, rather than at each subcommand, because
    /// every command that grows a `--store-root` has to answer it the same way
    /// and a divergent answer is silent in both directions — see
    /// [`crate::cli_args::StartRequest::env_dir_origin`] for what each
    /// direction costs. `start` and `doctor` both call this, which is what
    /// makes doctor's verdict about the store the runtime actually reads.
    pub(crate) fn of_store_root(store_root: Option<&Path>) -> Self {
        match store_root {
            Some(_) => Self::Explicit,
            None => Self::Default,
        }
    }
}

/// The dev store a reader resolved to, plus the one it passed over.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DevStoreChoice {
    /// The store to read, or `None` when none of the candidates exists.
    pub path: Option<PathBuf>,
    /// A `$HOME`-rooted store that exists, differs from [`Self::path`], and
    /// lost only because an explicitly-named env dir had one too. `None`
    /// whenever there is nothing surprising to report.
    pub shadowed: Option<PathBuf>,
}

/// The dev store that lives beside an env directory's revisions.
pub fn env_dir_store_path(env_dir: &Path) -> PathBuf {
    env_dir.join(STORE_RELATIVE)
}

/// Read-preference order for `env_dir`, most-specific first and de-duplicated.
///
/// `Explicit` promotes the env dir's own store ahead of the home-rooted one;
/// `Default` leaves the home store first, which is the order every caller had
/// before `--store-root` existed.
fn read_candidate_paths(
    env_dir: &Path,
    origin: EnvDirOrigin,
    home_store: Option<&Path>,
) -> Vec<PathBuf> {
    let ordered = [
        (origin == EnvDirOrigin::Explicit).then(|| env_dir_store_path(env_dir)),
        home_store.map(Path::to_path_buf),
        Some(env_dir_store_path(env_dir)),
        Some(env_dir.join(STORE_STATE_RELATIVE)),
    ];
    let mut out: Vec<PathBuf> = Vec::new();
    for candidate in ordered.into_iter().flatten() {
        if !out.contains(&candidate) {
            out.push(candidate);
        }
    }
    out
}

/// The home-rooted store for the selected env — the one environment lookup
/// this module's decision needs, isolated so [`choose`] can stay pure.
fn home_store_path() -> Option<PathBuf> {
    selected_env().and_then(|env| env_store_dev_secrets_path(&env))
}

/// The decision itself, with every environment lookup already made by the
/// caller. Pure but for `Path::exists`, which is what lets the ordering be
/// tested without mutating `$HOME` or `$GREENTIC_ENV` — this crate's tests run
/// in parallel and `set_var` is process-wide, so a decision that can only be
/// exercised through the environment is a decision that destabilises its
/// neighbours to test.
fn choose(
    env_dir: &Path,
    origin: EnvDirOrigin,
    home_store: Option<&Path>,
    override_path: Option<&Path>,
) -> DevStoreChoice {
    // The override names one exact file; nothing outranks it, and nothing it
    // beats is worth reporting — the operator already said which store to use.
    if let Some(path) = override_path
        && path.exists()
    {
        return DevStoreChoice {
            path: Some(path.to_path_buf()),
            shadowed: None,
        };
    }

    let path = read_candidate_paths(env_dir, origin, home_store)
        .into_iter()
        .find(|candidate| candidate.exists());

    // Only report the home store when it genuinely lost: it exists, it is not
    // what we chose, and an explicitly-named env dir is why. A home store that
    // simply came first (the `Default` order) beat nothing.
    let shadowed = match (origin, &path) {
        (EnvDirOrigin::Explicit, Some(chosen)) if *chosen == env_dir_store_path(env_dir) => {
            home_store
                .filter(|home| *home != chosen && home.exists())
                .map(Path::to_path_buf)
        }
        _ => None,
    };
    DevStoreChoice { path, shadowed }
}

/// Checks for an existing dev store: override, then env store, then bundle-local.
pub fn find_existing(bundle_root: &Path) -> Option<PathBuf> {
    find_existing_with_override(bundle_root, override_path().as_deref())
}

/// Looks for an existing dev store using an override path before consulting the
/// shared env store and then legacy bundle-local candidates.
pub fn find_existing_with_override(
    bundle_root: &Path,
    override_path: Option<&Path>,
) -> Option<PathBuf> {
    resolve_existing_with_override(bundle_root, EnvDirOrigin::Default, override_path).path
}

/// Resolves the dev store for `env_dir`, honouring `$GREENTIC_DEV_SECRETS_PATH`
/// first and reporting a home-rooted store that an explicit env dir outranked.
pub fn resolve_existing(env_dir: &Path, origin: EnvDirOrigin) -> DevStoreChoice {
    resolve_existing_with_override(env_dir, origin, override_path().as_deref())
}

/// [`resolve_existing`] with the override supplied rather than read from the
/// process environment, so the ordering is testable without mutating it.
pub fn resolve_existing_with_override(
    env_dir: &Path,
    origin: EnvDirOrigin,
    override_path: Option<&Path>,
) -> DevStoreChoice {
    choose(env_dir, origin, home_store_path().as_deref(), override_path)
}

/// [`resolve_existing`], with the home-rooted candidate resolved for `env`
/// rather than for `$GREENTIC_ENV`.
///
/// `start` propagates `--env` INTO `$GREENTIC_ENV` before any store lookup, so
/// for the boot path the two are always the same value and
/// [`resolve_existing`] is correct. A read-only caller cannot do that — and
/// one that skips this ends up with no home candidate at all (the ordinary
/// case: `$GREENTIC_ENV` is unset in an operator's shell) or with the home
/// store of a DIFFERENT environment (when it is set and `--env` disagrees).
/// Either way it answers about a store the runtime would not read, which is
/// the defect this whole module keeps producing in new places.
pub fn resolve_existing_for_env(env_dir: &Path, origin: EnvDirOrigin, env: &str) -> DevStoreChoice {
    choose(
        env_dir,
        origin,
        env_store_dev_secrets_path(env).as_deref(),
        override_path().as_deref(),
    )
}

/// The store a reader would CREATE for `env_dir` when nothing is staged
/// anywhere yet — without creating it.
///
/// This is the other half of [`resolve_existing`]: that one answers "which
/// existing store do I read", this one answers "which store should exist".
/// Doctor needs the second and may not mutate the env dir, so it cannot reach
/// for [`ensure_path`] / [`ensure_env_dir_path`] — but it must name the same
/// file they would, or it sends an operator to seed a store nothing reads.
/// Both writers therefore route through here, so the prediction and the
/// creation cannot drift apart.
pub fn expected_path(env_dir: &Path, origin: EnvDirOrigin) -> PathBuf {
    expected_path_with(env_dir, origin, home_store_path().as_deref())
}

/// [`expected_path`], with the home-rooted candidate resolved for `env` rather
/// than for `$GREENTIC_ENV` — the naming counterpart of
/// [`resolve_existing_for_env`], and it must move with it: a reader that
/// resolves against one home candidate and NAMES another is back to sending
/// an operator to the wrong file.
pub fn expected_path_for_env(env_dir: &Path, origin: EnvDirOrigin, env: &str) -> PathBuf {
    expected_path_with(env_dir, origin, env_store_dev_secrets_path(env).as_deref())
}

/// The decision, with the home lookup already made by the caller — the same
/// split, for the same reason, as [`choose`].
fn expected_path_with(env_dir: &Path, origin: EnvDirOrigin, home_store: Option<&Path>) -> PathBuf {
    // The override names one exact file and outranks both roots, exactly as
    // it does for a read.
    if let Some(path) = override_path() {
        return path;
    }
    match origin {
        // An operator who named this root stages secrets under it with
        // `op --store-root <root> secrets put`; the store belongs beside the
        // revisions, not under `$HOME`.
        EnvDirOrigin::Explicit => env_dir_store_path(env_dir),
        // Byte-for-byte the historical answer: the `$HOME` store that the
        // `gtc setup` ↔ `gtc start` rendezvous is built on, falling back to
        // the bundle-local path when no home store can be resolved.
        EnvDirOrigin::Default => home_store
            .map(Path::to_path_buf)
            .unwrap_or_else(|| env_dir_store_path(env_dir)),
    }
}

/// Ensures the default dev store path exists (creating parent directories).
/// Routes to the shared env store when `$GREENTIC_ENV` is set.
pub fn ensure_path(bundle_root: &Path) -> Result<PathBuf> {
    let path = expected_path(bundle_root, EnvDirOrigin::Default);
    ensure_parent(&path)?;
    Ok(path)
}

/// Like [`ensure_path`], but with an explicit environment — always the shared
/// env store (when resolvable), independent of `$GREENTIC_ENV`.
pub fn ensure_path_for_env(bundle_root: &Path, env: &str) -> Result<PathBuf> {
    if let Some(path) = override_path() {
        ensure_parent(&path)?;
        return Ok(path);
    }
    let path = write_path_for_env(bundle_root, env);
    ensure_parent(&path)?;
    Ok(path)
}

/// Like [`ensure_path`], but rooted at an env directory the operator named
/// with `--store-root` instead of at the home-rooted store.
///
/// Used only when nothing is staged anywhere yet: creating the empty store
/// beside the revisions keeps it where the operator's own
/// `op --store-root <root> secrets put` will write, instead of leaving a stray
/// empty file under `$HOME` that the next boot would then have to report as
/// shadowed.
pub fn ensure_env_dir_path(env_dir: &Path) -> Result<PathBuf> {
    let path = expected_path(env_dir, EnvDirOrigin::Explicit);
    ensure_parent(&path)?;
    Ok(path)
}

fn ensure_parent(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::MutexGuard;
    use tempfile::{TempDir, tempdir};

    const ENV_ID: &str = "local";

    /// Creates an empty dev store at `<root>/<ENV_ID>/.greentic/dev/…` and
    /// returns its path — the shape both a home store and a `--store-root`
    /// store have on disk.
    fn stage_store(root: &Path) -> PathBuf {
        let path = env_dir_store_path(&root.join(ENV_ID));
        fs::create_dir_all(path.parent().expect("store has a parent")).expect("store dir");
        fs::write(&path, b"").expect("store file");
        path
    }

    /// A `--store-root` holding a staged store, and a separate home store.
    /// Returns both roots so each test can decide which stores exist.
    fn roots() -> (TempDir, PathBuf, TempDir, PathBuf) {
        let home_root = tempdir().expect("home root");
        let home_store = env_dir_store_path(&home_root.path().join(ENV_ID));
        let store_root = tempdir().expect("store root");
        let env_dir = store_root.path().join(ENV_ID);
        (home_root, home_store, store_root, env_dir)
    }

    /// The bug: a runtime started with `--store-root` read the operator's
    /// `$HOME` store instead of the one its own deploy staged, so every
    /// credentialed read missed with nothing red anywhere.
    #[test]
    fn an_explicit_env_dir_outranks_an_existing_home_store() {
        let (home_root, home_store, store_root, env_dir) = roots();
        stage_store(home_root.path());
        let explicit_store = stage_store(store_root.path());

        let choice = choose(
            &env_dir,
            EnvDirOrigin::Explicit,
            Some(home_store.as_path()),
            None,
        );

        assert_eq!(
            choice.path.as_deref(),
            Some(explicit_store.as_path()),
            "--store-root names the store to read; {home_store:?} is the operator's own home",
        );
    }

    /// The other half of the ruling, and the reason this is not a plain
    /// inversion: with no `--store-root` the setup↔start rendezvous on the
    /// home store is the whole point of this module.
    #[test]
    fn without_an_explicit_env_dir_the_home_store_still_wins() {
        let (home_root, home_store, store_root, env_dir) = roots();
        stage_store(home_root.path());
        stage_store(store_root.path());

        let choice = choose(
            &env_dir,
            EnvDirOrigin::Default,
            Some(home_store.as_path()),
            None,
        );

        assert_eq!(
            choice.path.as_deref(),
            Some(home_store.as_path()),
            "the default order is byte-for-byte what it was before --store-root",
        );
        assert_eq!(
            choice.shadowed, None,
            "a home store that came first beat nothing worth reporting",
        );
    }

    /// Two stores exist and disagree, so the caller is handed the loser to
    /// name in its warning. Reading past an operator's home store in silence
    /// is what made the original bug invisible.
    #[test]
    fn a_shadowed_home_store_is_reported_so_the_caller_can_warn() {
        let (home_root, home_store, store_root, env_dir) = roots();
        stage_store(home_root.path());
        let explicit_store = stage_store(store_root.path());

        let choice = choose(
            &env_dir,
            EnvDirOrigin::Explicit,
            Some(home_store.as_path()),
            None,
        );

        assert_eq!(choice.path.as_deref(), Some(explicit_store.as_path()));
        assert_eq!(
            choice.shadowed.as_deref(),
            Some(home_store.as_path()),
            "both paths must reach the warning, not just the winner",
        );
    }

    /// `$HOME` stays the fallback: an explicit root with nothing staged under
    /// it reads the home store rather than missing everything.
    #[test]
    fn an_explicit_env_dir_with_no_store_falls_back_to_the_home_store() {
        let (home_root, home_store, _store_root, env_dir) = roots();
        stage_store(home_root.path());

        let choice = choose(
            &env_dir,
            EnvDirOrigin::Explicit,
            Some(home_store.as_path()),
            None,
        );

        assert_eq!(choice.path.as_deref(), Some(home_store.as_path()));
        assert_eq!(
            choice.shadowed, None,
            "nothing was shadowed — the home store is what we chose",
        );
    }

    /// The ruling warns only when two stores genuinely disagree. An explicit
    /// root with no home store beside it must stay quiet, or every ordinary
    /// `--store-root` boot warns about a file that does not exist.
    #[test]
    fn an_explicit_env_dir_alone_shadows_nothing() {
        let (_home_root, home_store, store_root, env_dir) = roots();
        let explicit_store = stage_store(store_root.path());

        let choice = choose(
            &env_dir,
            EnvDirOrigin::Explicit,
            Some(home_store.as_path()),
            None,
        );

        assert_eq!(choice.path.as_deref(), Some(explicit_store.as_path()));
        assert_eq!(
            choice.shadowed, None,
            "there is no home store to have been shadowed",
        );
    }

    /// When `--store-root` points AT the home store there is one file, not
    /// two, so nothing may be reported as shadowed by itself.
    #[test]
    fn an_explicit_env_dir_that_is_the_home_store_shadows_nothing() {
        let home_root = tempdir().expect("home root");
        let store = stage_store(home_root.path());
        let env_dir = home_root.path().join(ENV_ID);

        let choice = choose(
            &env_dir,
            EnvDirOrigin::Explicit,
            Some(store.as_path()),
            None,
        );

        assert_eq!(choice.path.as_deref(), Some(store.as_path()));
        assert_eq!(choice.shadowed, None);
    }

    /// `$GREENTIC_DEV_SECRETS_PATH` still names one exact file and outranks
    /// both roots — the operator has already said which store to use.
    #[test]
    fn the_override_outranks_an_explicit_env_dir() {
        let (home_root, home_store, store_root, env_dir) = roots();
        stage_store(home_root.path());
        stage_store(store_root.path());
        let override_dir = tempdir().expect("override");
        let override_store = override_dir.path().join("override.env");
        fs::write(&override_store, b"").expect("override file");

        let choice = choose(
            &env_dir,
            EnvDirOrigin::Explicit,
            Some(home_store.as_path()),
            Some(override_store.as_path()),
        );

        assert_eq!(choice.path.as_deref(), Some(override_store.as_path()));
        assert_eq!(choice.shadowed, None);
    }

    /// The other half of the ruling, for a reader that has to NAME a store
    /// rather than read one. Doctor reports this path as the remedy when no
    /// store exists yet, so it must be the file the runtime would create —
    /// naming the `$HOME` one under `--store-root` is what sent an operator
    /// to seed a store nothing reads (#620).
    #[test]
    fn the_expected_path_for_an_explicit_env_dir_sits_beside_the_revisions() {
        // `expected_path` consults `$GREENTIC_DEV_SECRETS_PATH`, which other
        // tests set; the crate-wide lock is what keeps this deterministic.
        let _lock = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (_home_root, _home_store, _store_root, env_dir) = roots();

        assert_eq!(
            expected_path(&env_dir, EnvDirOrigin::Explicit),
            env_dir_store_path(&env_dir),
        );
    }

    /// The prediction and the creation are one rule: whatever
    /// [`ensure_env_dir_path`] would make is what [`expected_path`] names.
    /// Two copies of this would drift silently — the prediction is only ever
    /// read by a human, so a wrong one fails nothing.
    #[test]
    fn the_expected_path_is_the_one_the_writer_would_create() {
        let _lock = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (_home_root, _home_store, _store_root, env_dir) = roots();

        let created = ensure_env_dir_path(&env_dir).expect("writer resolves a path");

        assert_eq!(created, expected_path(&env_dir, EnvDirOrigin::Explicit));
        assert!(
            created.parent().is_some_and(Path::exists),
            "the writer creates the parent; the prediction must not",
        );
    }

    /// A read-only caller names the env instead of exporting `$GREENTIC_ENV`,
    /// and gets the same home candidate the boot path would have had.
    ///
    /// `start` propagates `--env` into the process env before it resolves a
    /// store, so its home candidate always matches the env it serves. `doctor`
    /// cannot, and without this its home candidate is simply ABSENT in an
    /// ordinary shell — which silently disables the shadowed-store report, the
    /// half of #620 that exists to say "two stores exist and I read this one".
    #[test]
    fn naming_the_env_gives_the_home_candidate_that_greentic_env_would_have() {
        let _lock = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let home = tempdir().expect("home");
        let home_store = stage_store(&home.path().join(".greentic").join("environments"));
        let store_root = tempdir().expect("store root");
        let env_dir = store_root.path().join(ENV_ID);
        let explicit_store = stage_store(store_root.path());
        // `$HOME` is set but `$GREENTIC_ENV` is NOT — an operator's shell.
        let previous_home = env::var_os("HOME");
        let previous_env = env::var_os("GREENTIC_ENV");
        // SAFETY: serialized by the crate-wide test env lock held above.
        unsafe {
            env::set_var("HOME", home.path());
            env::remove_var("GREENTIC_ENV");
        }

        let ambient = resolve_existing_with_override(&env_dir, EnvDirOrigin::Explicit, None);
        let named = resolve_existing_for_env(&env_dir, EnvDirOrigin::Explicit, ENV_ID);

        // SAFETY: same lock.
        unsafe {
            match previous_home {
                Some(value) => env::set_var("HOME", value),
                None => env::remove_var("HOME"),
            }
            if let Some(value) = previous_env {
                env::set_var("GREENTIC_ENV", value);
            }
        }

        assert_eq!(ambient.path.as_deref(), Some(explicit_store.as_path()));
        assert_eq!(
            ambient.shadowed, None,
            "with no $GREENTIC_ENV there is no home candidate to shadow, so the \
             report an operator needs never fires",
        );
        assert_eq!(named.path.as_deref(), Some(explicit_store.as_path()));
        assert_eq!(
            named.shadowed.as_deref(),
            Some(home_store.as_path()),
            "naming the env recovers the home candidate, and with it the report",
        );
    }

    /// The naming counterpart must follow the resolver. A reader that resolves
    /// against one home candidate and NAMES another is back to pointing an
    /// operator at a file nothing reads.
    #[test]
    fn the_named_env_expected_path_follows_the_named_env_resolver() {
        let _lock = crate::test_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (home_root, _home_store, _store_root, env_dir) = roots();

        let previous_home = env::var_os("HOME");
        // SAFETY: serialized by the crate-wide test env lock held above.
        unsafe { env::set_var("HOME", home_root.path()) };
        let named = expected_path_for_env(&env_dir, EnvDirOrigin::Default, ENV_ID);
        let explicit = expected_path_for_env(&env_dir, EnvDirOrigin::Explicit, ENV_ID);
        // SAFETY: same lock.
        unsafe {
            match previous_home {
                Some(value) => env::set_var("HOME", value),
                None => env::remove_var("HOME"),
            }
        }

        assert_eq!(
            named,
            env_dir_store_path(&home_root.path().join(".greentic/environments").join(ENV_ID)),
            "no --store-root still names the home store, whatever $GREENTIC_ENV says",
        );
        assert_eq!(explicit, env_dir_store_path(&env_dir));
    }

    /// `--store-root` is the only input to the origin, and both commands that
    /// take the flag route through this one rule. A second copy at a new
    /// subcommand is how doctor and start would come to disagree about which
    /// store is authoritative.
    #[test]
    fn the_origin_follows_whether_a_store_root_was_named() {
        assert_eq!(
            EnvDirOrigin::of_store_root(Some(Path::new("/srv/envA"))),
            EnvDirOrigin::Explicit,
        );
        assert_eq!(EnvDirOrigin::of_store_root(None), EnvDirOrigin::Default);
    }

    /// Holds the shared env lock and restores `HOME` / `GREENTIC_ENV` on drop,
    /// including on a failed assertion — `set_var` is process-wide, so a test
    /// that leaves it wrong breaks its neighbours rather than itself.
    struct EnvGuard {
        _lock: MutexGuard<'static, ()>,
        previous: Vec<(&'static str, Option<OsString>)>,
    }

    impl EnvGuard {
        fn new(home: &Path) -> Self {
            let lock = crate::test_env_lock()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = ["HOME", "GREENTIC_ENV"]
                .iter()
                .map(|key| (*key, env::var_os(key)))
                .collect();
            unsafe {
                env::set_var("HOME", home);
                env::set_var("GREENTIC_ENV", ENV_ID);
            }
            Self {
                _lock: lock,
                previous,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.previous.drain(..) {
                unsafe {
                    match value {
                        Some(value) => env::set_var(key, value),
                        None => env::remove_var(key),
                    }
                }
            }
        }
    }

    /// The one test that pays for touching the process environment: it proves
    /// the shell around [`choose`] reads the home store from `$HOME` and
    /// `$GREENTIC_ENV` at all. Without it every ordering test above could pass
    /// while `resolve_existing` handed `choose` the wrong home path.
    #[test]
    fn the_home_candidate_comes_from_home_and_greentic_env() {
        let home = tempdir().expect("home");
        let home_store = stage_store(&home.path().join(".greentic").join("environments"));
        let store_root = tempdir().expect("store root");
        let _guard = EnvGuard::new(home.path());

        let choice = resolve_existing_with_override(
            &store_root.path().join(ENV_ID),
            EnvDirOrigin::Default,
            None,
        );

        assert_eq!(
            choice.path.as_deref(),
            Some(home_store.as_path()),
            "`$HOME/.greentic/environments/$GREENTIC_ENV` is the home candidate",
        );
    }
}
