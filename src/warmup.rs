use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use greentic_runner_host::cache::{
    ArtifactKey, CacheConfig, CacheManager, CpuPolicy, EngineProfile, WarmupItem, WarmupMode,
};
use sha2::{Digest, Sha256};
use wasmtime::Engine;
use zip::ZipArchive;

pub struct WarmupRequest {
    pub bundle: PathBuf,
    pub cache_dir: Option<PathBuf>,
    pub strict: bool,
}

/// If the resolved bundle ships a pre-warmed component cache at `<bundle>/.cache/v1/`,
/// point `GREENTIC_CACHE_DIR` at it so the runner-host loads warm cwasm instead of
/// recompiling on cold start. Skipped when the user has already set the env var,
/// or when no `.cache/v1/` directory is present.
pub(crate) fn adopt_bundle_cache_dir(bundle_root: &Path) {
    if std::env::var_os("GREENTIC_CACHE_DIR").is_some() {
        return;
    }
    let cache_root = bundle_root.join(".cache");
    if !cache_root.join("v1").is_dir() {
        return;
    }
    // SAFETY: called early in single-threaded startup before spawning workers.
    unsafe {
        std::env::set_var("GREENTIC_CACHE_DIR", &cache_root);
    }
    eprintln!(
        "greentic-start: using bundle-shipped component cache at {}",
        cache_root.display()
    );
}

/// Adopt a bundle-shipped component cache from materialized revisions in the
/// env-serve path. Iterates the revision ids, probes
/// `<env_dir>/revisions/<rev_id>/bundle/.cache/v1/`, and delegates to
/// [`adopt_bundle_cache_dir`] (which is a no-op when the dir is absent or
/// `GREENTIC_CACHE_DIR` is already set). First revision with a cache wins.
///
/// Returns the `.cache/v1/` paths that were probed and found absent. Empty when
/// a cache was adopted, when `GREENTIC_CACHE_DIR` was already set, or when there
/// are no revisions. The caller logs the outcome — naming the probed paths is
/// what makes a miss diagnosable, since the whole mechanism rests on the
/// `<env_dir>/revisions/<rev_id>/bundle/` layout being correct.
///
/// Reaches `set_var` via [`adopt_bundle_cache_dir`], so it inherits that
/// function's single-threaded precondition. The env-serve caller in `lib.rs`
/// does NOT satisfy it — `init_trace_log` has already spawned a
/// `tracing_appender` worker thread by then. See the note at that call site;
/// removing the env-var channel is tracked in #430.
pub(crate) fn adopt_env_revision_cache(
    env_dir: &Path,
    revision_ids: &[impl AsRef<str>],
) -> Vec<PathBuf> {
    if std::env::var_os("GREENTIC_CACHE_DIR").is_some() {
        return Vec::new();
    }
    let mut probed = Vec::new();
    for rev_id in revision_ids {
        let bundle_dir = env_dir
            .join("revisions")
            .join(rev_id.as_ref())
            .join("bundle");
        adopt_bundle_cache_dir(&bundle_dir);
        if std::env::var_os("GREENTIC_CACHE_DIR").is_some() {
            return Vec::new();
        }
        probed.push(bundle_dir.join(".cache").join("v1"));
    }
    probed
}

/// Return the runtime engine profile id, computing it at most once per process.
/// `Engine::default()` is constructed only on the first call; subsequent calls
/// return the cached id. The engine argument to `EngineProfile::from_engine` is
/// ignored (the parameter is `_engine`), so this is safe to call at any point.
fn runtime_engine_profile_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        let engine = Engine::default();
        let profile = warmup_engine_profile(&engine);
        profile.id().to_string()
    })
}

/// Result of checking whether a bundle-shipped cache matches the runtime's
/// engine profile.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CacheProfileCheck {
    /// No `v1/` directory under the cache root — nothing to check.
    NoCacheDir,
    /// `v1/` exists but contains no subdirectories (empty or files only).
    EmptyV1,
    /// The runtime's own profile directory exists under `v1/`.
    Match,
    /// `v1/` contains profile directories, but none matches the runtime's.
    /// Fields: `(runtime_profile_id, shipped_profile_dirs)`.
    Mismatch {
        runtime_id: String,
        shipped: Vec<String>,
    },
}

/// Check whether a bundle-shipped cache at `cache_root` contains an engine
/// profile directory that matches the runtime's profile. Pure and
/// side-effect-free — logging is the caller's responsibility.
pub(crate) fn check_cache_profile(cache_root: &Path) -> CacheProfileCheck {
    let v1 = cache_root.join("v1");
    if !v1.is_dir() {
        return CacheProfileCheck::NoCacheDir;
    }

    let runtime_id = runtime_engine_profile_id();
    let config = CacheConfig {
        root: cache_root.to_path_buf(),
        ..CacheConfig::default()
    };
    let expected_dir = config.disk_root(runtime_id);

    if expected_dir.is_dir() {
        return CacheProfileCheck::Match;
    }

    // List actual subdirectory names under v1/.
    let shipped: Vec<String> = std::fs::read_dir(&v1)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();

    if shipped.is_empty() {
        CacheProfileCheck::EmptyV1
    } else {
        CacheProfileCheck::Mismatch {
            runtime_id: runtime_id.to_string(),
            shipped,
        }
    }
}

/// Log the result of a cache profile check using the crate's `operator_log`
/// facility. Shared between the env-serve and demo/bundle adoption paths.
pub(crate) fn log_cache_profile_check(check: &CacheProfileCheck) {
    match check {
        CacheProfileCheck::NoCacheDir | CacheProfileCheck::EmptyV1 => {
            // No cache to match against — nothing to report.
        }
        CacheProfileCheck::Match => {
            crate::operator_log::debug(
                module_path!(),
                "component cache: bundle-shipped profile matches the runtime engine profile",
            );
        }
        CacheProfileCheck::Mismatch {
            runtime_id,
            shipped,
        } => {
            crate::operator_log::warn(
                module_path!(),
                format!(
                    "component cache: engine-profile MISMATCH — the runtime expects profile \
                     `{runtime_id}` but the bundle ships [{}]. Components will be recompiled \
                     from WASM (~20s cold-start penalty). Re-warm the bundle with the same \
                     Wasmtime version, target, and CPU policy as the runtime, or set \
                     GREENTIC_CACHE_DIR to a matching cache.",
                    shipped.join(", "),
                ),
            );
        }
    }
}

struct CollectedWasm {
    bytes: Vec<u8>,
}

pub fn run_warmup_request(request: WarmupRequest) -> Result<()> {
    let bundle = request
        .bundle
        .canonicalize()
        .with_context(|| format!("resolve bundle path {}", request.bundle.display()))?;
    if !bundle.is_dir() {
        anyhow::bail!(
            "bundle path must be an extracted directory: {}",
            bundle.display()
        );
    }

    let collected = collect_component_wasm(&bundle)?;
    if collected.is_empty() {
        eprintln!(
            "warmup: no .wasm components found under {}",
            bundle.display()
        );
        return Ok(());
    }

    let engine = Engine::default();
    let profile = warmup_engine_profile(&engine);
    let cache_config = match request.cache_dir.as_ref() {
        Some(dir) => CacheConfig {
            root: dir.clone(),
            ..CacheConfig::default()
        },
        None => CacheConfig::default(),
    };
    let cache = CacheManager::new(cache_config, profile.clone());

    let mut items = Vec::with_capacity(collected.len());
    for entry in &collected {
        let digest = sha256_hex(&entry.bytes);
        let key = ArtifactKey::new(profile.id().to_string(), format!("sha256:{digest}"));
        items.push(WarmupItem {
            key,
            bytes: entry.bytes.clone(),
        });
    }

    let mode = if request.strict {
        WarmupMode::Strict
    } else {
        WarmupMode::BestEffort
    };
    let runtime = tokio::runtime::Runtime::new().context("build tokio runtime for warmup")?;
    let report = runtime
        .block_on(cache.warmup(&engine, &items, mode))
        .context("cache warmup failed")?;

    println!(
        "warmup: {} components found, warmed={}, skipped={} (cache={})",
        collected.len(),
        report.warmed,
        report.skipped,
        cache.engine_profile_id(),
    );
    Ok(())
}

fn collect_component_wasm(root: &Path) -> Result<Vec<CollectedWasm>> {
    let mut out = Vec::new();
    walk(root, &mut out)?;
    Ok(out)
}

fn walk(dir: &Path, out: &mut Vec<CollectedWasm>) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("read dir {}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("iterate dir {}", dir.display()))?;
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out)?;
            continue;
        }
        let ext = path.extension().and_then(|s| s.to_str());
        match ext {
            Some("wasm") => {
                let bytes = std::fs::read(&path)
                    .with_context(|| format!("read component {}", path.display()))?;
                out.push(CollectedWasm { bytes });
            }
            Some("gtpack") => {
                extract_pack_wasms(&path, out)
                    .with_context(|| format!("read .gtpack archive {}", path.display()))?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn extract_pack_wasms(pack_path: &Path, out: &mut Vec<CollectedWasm>) -> Result<()> {
    let file =
        std::fs::File::open(pack_path).with_context(|| format!("open {}", pack_path.display()))?;
    let mut archive = ZipArchive::new(file)
        .with_context(|| format!("read zip header in {}", pack_path.display()))?;

    let names: Vec<String> = (0..archive.len())
        .filter_map(|i| {
            let entry = archive.by_index(i).ok()?;
            if !entry.is_file() {
                return None;
            }
            let name = entry.name();
            if name.ends_with(".wasm") {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect();

    for name in names {
        let mut entry = archive
            .by_name(&name)
            .with_context(|| format!("open zip entry {name} in {}", pack_path.display()))?;
        let mut bytes = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut bytes)
            .with_context(|| format!("read zip entry {name} in {}", pack_path.display()))?;
        out.push(CollectedWasm { bytes });
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn warmup_engine_profile(engine: &Engine) -> EngineProfile {
    let profile = EngineProfile::from_engine(engine, CpuPolicy::Native, "default".to_string());
    warmup_engine_profile_for_platform(profile, cfg!(windows))
}

fn warmup_engine_profile_for_platform(mut profile: EngineProfile, windows: bool) -> EngineProfile {
    if windows {
        profile.engine_profile_id = windows_safe_cache_segment(profile.id());
    }
    profile
}

fn windows_safe_cache_segment(segment: &str) -> String {
    segment
        .chars()
        .map(|ch| {
            if is_windows_invalid_path_char(ch) {
                '_'
            } else {
                ch
            }
        })
        .collect()
}

fn is_windows_invalid_path_char(ch: char) -> bool {
    matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') || ch.is_control()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_cache_env_lock<F: FnOnce()>(f: F) {
        let lock = crate::test_env_lock();
        let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: tests are serialized via the shared lock.
        unsafe { std::env::remove_var("GREENTIC_CACHE_DIR") };
        f();
        unsafe { std::env::remove_var("GREENTIC_CACHE_DIR") };
        drop(guard);
    }

    #[test]
    fn adopt_bundle_cache_dir_sets_env_when_cache_present() {
        with_cache_env_lock(|| {
            let tmp = tempfile::tempdir().unwrap();
            let bundle_root = tmp.path();
            std::fs::create_dir_all(bundle_root.join(".cache").join("v1")).unwrap();

            adopt_bundle_cache_dir(bundle_root);

            let value = std::env::var("GREENTIC_CACHE_DIR").expect("env var set");
            assert_eq!(PathBuf::from(value), bundle_root.join(".cache"));
        });
    }

    #[test]
    fn adopt_bundle_cache_dir_skips_when_no_cache() {
        with_cache_env_lock(|| {
            let tmp = tempfile::tempdir().unwrap();
            adopt_bundle_cache_dir(tmp.path());
            assert!(std::env::var("GREENTIC_CACHE_DIR").is_err());
        });
    }

    #[test]
    fn adopt_bundle_cache_dir_respects_user_override() {
        with_cache_env_lock(|| {
            let tmp = tempfile::tempdir().unwrap();
            let bundle_root = tmp.path();
            std::fs::create_dir_all(bundle_root.join(".cache").join("v1")).unwrap();
            // SAFETY: protected by the env lock.
            unsafe { std::env::set_var("GREENTIC_CACHE_DIR", "/explicit/from/user") };

            adopt_bundle_cache_dir(bundle_root);

            assert_eq!(
                std::env::var("GREENTIC_CACHE_DIR").unwrap(),
                "/explicit/from/user"
            );
        });
    }

    #[test]
    fn warmup_engine_profile_id_is_windows_path_safe() {
        let engine = Engine::default();
        let profile = EngineProfile::from_engine(&engine, CpuPolicy::Native, "default".to_string());
        assert!(
            profile.id().contains(':'),
            "the upstream profile id currently includes a digest algorithm separator"
        );

        let profile = warmup_engine_profile_for_platform(profile, true);

        assert!(
            !profile.id().chars().any(is_windows_invalid_path_char),
            "warmup cache profile id must be valid as a Windows path segment"
        );
    }

    // --- adopt_env_revision_cache tests (F3 env-serve path) ---

    #[test]
    fn env_revision_cache_adopted_when_present() {
        with_cache_env_lock(|| {
            let tmp = tempfile::tempdir().unwrap();
            let env_dir = tmp.path();
            let rev_id = "rev-abc-123";
            let cache_dir = env_dir
                .join("revisions")
                .join(rev_id)
                .join("bundle")
                .join(".cache")
                .join("v1");
            std::fs::create_dir_all(&cache_dir).unwrap();

            adopt_env_revision_cache(env_dir, &[rev_id]);

            let value = std::env::var("GREENTIC_CACHE_DIR").expect("env var should be set");
            let expected = env_dir
                .join("revisions")
                .join(rev_id)
                .join("bundle")
                .join(".cache");
            assert_eq!(PathBuf::from(value), expected);
        });
    }

    #[test]
    fn env_revision_cache_noop_when_no_cache_dir() {
        with_cache_env_lock(|| {
            let tmp = tempfile::tempdir().unwrap();
            let env_dir = tmp.path();
            // Create the revision's bundle dir but NOT `.cache/v1/`.
            let bundle_dir = env_dir
                .join("revisions")
                .join("rev-no-cache")
                .join("bundle");
            std::fs::create_dir_all(&bundle_dir).unwrap();

            adopt_env_revision_cache(env_dir, &["rev-no-cache"]);

            assert!(
                std::env::var("GREENTIC_CACHE_DIR").is_err(),
                "env var must not be set when bundle has no cache"
            );
        });
    }

    #[test]
    fn env_revision_cache_respects_existing_env_var() {
        with_cache_env_lock(|| {
            let tmp = tempfile::tempdir().unwrap();
            let env_dir = tmp.path();
            let rev_id = "rev-override";
            let cache_dir = env_dir
                .join("revisions")
                .join(rev_id)
                .join("bundle")
                .join(".cache")
                .join("v1");
            std::fs::create_dir_all(&cache_dir).unwrap();

            // SAFETY: protected by the env lock.
            unsafe { std::env::set_var("GREENTIC_CACHE_DIR", "/user/explicit") };

            adopt_env_revision_cache(env_dir, &[rev_id]);

            assert_eq!(
                std::env::var("GREENTIC_CACHE_DIR").unwrap(),
                "/user/explicit",
                "user-set GREENTIC_CACHE_DIR must not be overwritten"
            );
        });
    }

    #[test]
    fn env_revision_cache_first_revision_wins() {
        with_cache_env_lock(|| {
            let tmp = tempfile::tempdir().unwrap();
            let env_dir = tmp.path();
            // Both revisions ship a cache.
            for rev_id in &["rev-first", "rev-second"] {
                let cache_dir = env_dir
                    .join("revisions")
                    .join(rev_id)
                    .join("bundle")
                    .join(".cache")
                    .join("v1");
                std::fs::create_dir_all(&cache_dir).unwrap();
            }

            adopt_env_revision_cache(env_dir, &["rev-first", "rev-second"]);

            let value = std::env::var("GREENTIC_CACHE_DIR").expect("env var should be set");
            let expected = env_dir
                .join("revisions")
                .join("rev-first")
                .join("bundle")
                .join(".cache");
            assert_eq!(
                PathBuf::from(value),
                expected,
                "first revision's cache must win"
            );
        });
    }

    #[test]
    fn env_revision_cache_noop_when_no_revisions() {
        with_cache_env_lock(|| {
            let tmp = tempfile::tempdir().unwrap();
            let empty: &[&str] = &[];
            adopt_env_revision_cache(tmp.path(), empty);

            assert!(
                std::env::var("GREENTIC_CACHE_DIR").is_err(),
                "empty revision list must not set the env var"
            );
        });
    }

    // --- check_cache_profile tests ---

    #[test]
    fn check_cache_profile_no_v1_dir() {
        let tmp = tempfile::tempdir().unwrap();
        // cache_root exists but has no v1/ subdirectory.
        assert_eq!(
            check_cache_profile(tmp.path()),
            CacheProfileCheck::NoCacheDir
        );
    }

    #[test]
    fn check_cache_profile_empty_v1() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("v1")).unwrap();
        assert_eq!(check_cache_profile(tmp.path()), CacheProfileCheck::EmptyV1);
    }

    #[test]
    fn check_cache_profile_v1_with_file_only() {
        let tmp = tempfile::tempdir().unwrap();
        let v1 = tmp.path().join("v1");
        std::fs::create_dir_all(&v1).unwrap();
        std::fs::write(v1.join("not-a-dir"), b"").unwrap();
        assert_eq!(check_cache_profile(tmp.path()), CacheProfileCheck::EmptyV1,);
    }

    #[test]
    fn check_cache_profile_match() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_root = tmp.path();
        // Build the expected directory using CacheConfig::disk_root so the test
        // cannot drift from the implementation's path_safe transformation.
        let runtime_id = runtime_engine_profile_id();
        let config = CacheConfig {
            root: cache_root.to_path_buf(),
            ..CacheConfig::default()
        };
        let expected_dir = config.disk_root(runtime_id);
        std::fs::create_dir_all(&expected_dir).unwrap();

        assert_eq!(check_cache_profile(cache_root), CacheProfileCheck::Match);
    }

    #[test]
    fn check_cache_profile_mismatch_single() {
        let tmp = tempfile::tempdir().unwrap();
        let v1 = tmp.path().join("v1");
        let foreign = "sha256_aaaa";
        std::fs::create_dir_all(v1.join(foreign)).unwrap();

        match check_cache_profile(tmp.path()) {
            CacheProfileCheck::Mismatch {
                runtime_id,
                shipped,
            } => {
                assert_eq!(runtime_id, runtime_engine_profile_id());
                assert_eq!(shipped, vec![foreign.to_string()]);
            }
            other => panic!("expected Mismatch, got {other:?}"),
        }
    }

    #[test]
    fn check_cache_profile_mismatch_multiple() {
        let tmp = tempfile::tempdir().unwrap();
        let v1 = tmp.path().join("v1");
        let foreign_a = "sha256_aaaa";
        let foreign_b = "sha256_bbbb";
        std::fs::create_dir_all(v1.join(foreign_a)).unwrap();
        std::fs::create_dir_all(v1.join(foreign_b)).unwrap();

        match check_cache_profile(tmp.path()) {
            CacheProfileCheck::Mismatch {
                runtime_id,
                shipped,
            } => {
                assert_eq!(runtime_id, runtime_engine_profile_id());
                assert_eq!(shipped.len(), 2);
                let mut sorted = shipped.clone();
                sorted.sort();
                assert_eq!(sorted, vec![foreign_a.to_string(), foreign_b.to_string()]);
            }
            other => panic!("expected Mismatch, got {other:?}"),
        }
    }
}
