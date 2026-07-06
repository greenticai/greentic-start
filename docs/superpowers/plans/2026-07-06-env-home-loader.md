# greentic-start env-home loader — Implementation Plan (Slice 1a)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Teach `greentic-start` to boot from a greentic-deployer environment home (`--store-root <dir> --env <id>`) by reading `runtime-config.json`, digest-verifying the routed revision's packs, and feeding the already-extracted bundle directory to the existing runner load path.

**Architecture:** A new `src/env_home/` module reads `<store-root>/<env>/runtime-config.json`, selects the single routed revision (100%), verifies each `.gtpack` under `<rev>/bundle/packs/` against the sha256 digests pinned in `<rev>/pack-list.lock`, then returns the SAME `(DemoPaths, DemoConfig)` pair that `resolve_demo_paths` + `load_runtime_demo_config` produce for a `--bundle` — pointing `root_dir` at the pre-extracted `<rev>/bundle/` directory. `run_start` branches to this loader when `store_root` is set; everything downstream (`demo_up_services`) is unchanged. A minimal poll-based watcher triggers a clean shutdown on `runtime-config.json` change so a supervisor restarts the process.

**Tech Stack:** Rust 1.95, clap, serde/serde_json, sha2 (all already deps), tokio. No new crate dependencies; the deploy-spec structs are mirrored, not imported.

## Global Constraints

- Rust 1.95.0 (`rust-toolchain.toml`, do not edit). English only in source/tests/comments.
- No `unwrap()`/`panic!()` in production paths — use `anyhow`/`thiserror`. `#![forbid(unsafe_code)]` norm (test env-var mutation uses the existing `crate::test_env_lock()` + `unsafe { set_var }` pattern — allowed in tests only).
- **Do NOT add a `greentic-deploy-spec` dependency** — it pins `greentic-types "<1.2.0-0"`, unsatisfiable here. Mirror the structs in `src/env_home/spec.rs`.
- **Do NOT conflate `--env` with `GREENTIC_ENV`.** `--env` selects the env-home subdirectory (`local`). `GREENTIC_ENV` (default `"dev"`, `src/lib.rs:226`) is the secret-URI tier segment `secrets://{env}/…`. Leave `GREENTIC_ENV` handling exactly as-is; `--env` must never overwrite it.
- **No silent fallback:** if `--store-root` is set and the env-home is malformed/undeployed, error out — never fall back to bundle mode.
- Canonical CI gate: `bash ci/local_check.sh` (fmt + clippy `-D warnings` + test + build + doc + package). Run the FULL check, not `--lib`-scoped, before declaring done.
- Conventional Commits. No Claude co-authorship trailer.

---

### Task 1: CLI flags `--store-root` / `--env` plumbed to `StartRequest`

**Files:**
- Modify: `src/cli_args.rs:91-143` (`StartArgs`), `:197-223` (`StartRequest`), `:233-258` (`start_request_from_args`), `:359-383` (`arg_takes_value` allowlist)
- Modify (fixtures that construct `StartRequest`): `src/bundle_config.rs:501` (`make_test_request`), `src/lib.rs:947`, `:979`, `:1050` (`make_start_request`)
- Test: `src/cli_args.rs` (inline `#[cfg(test)]`)

**Interfaces:**
- Produces: `StartRequest.store_root: Option<PathBuf>`, `StartRequest.env: String` (default `"local"`), consumed by Task 6.

- [ ] **Step 1: Write the failing test** (append to the `#[cfg(test)] mod tests` in `src/cli_args.rs`)

```rust
#[test]
fn store_root_and_env_flow_into_start_request() {
    let args = StartArgs::parse_from([
        "greentic-start", "--store-root", "/tmp/envs", "--env", "local",
    ]);
    let request = start_request_from_args(args, false);
    assert_eq!(request.store_root, Some(std::path::PathBuf::from("/tmp/envs")));
    assert_eq!(request.env, "local");
}

#[test]
fn env_defaults_to_local_when_absent() {
    let args = StartArgs::parse_from(["greentic-start", "--bundle", "x.gtbundle"]);
    let request = start_request_from_args(args, false);
    assert_eq!(request.store_root, None);
    assert_eq!(request.env, "local");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p greentic-start store_root_and_env_flow_into_start_request env_defaults_to_local -- --nocapture`
Expected: FAIL — `no field store_root on StartRequest` (compile error).

- [ ] **Step 3: Add the fields and mapping**

In `StartArgs` (`src/cli_args.rs`, near the `bundle` field ~`:92`):

```rust
    /// Boot from a greentic-deployer environment home instead of a bundle.
    #[arg(long)]
    store_root: Option<PathBuf>,
    /// Environment id within the store root (deployer env, not GREENTIC_ENV).
    #[arg(long, default_value = "local")]
    env: String,
```

In `StartRequest` (`src/cli_args.rs:198`):

```rust
    pub store_root: Option<PathBuf>,
    pub env: String,
```

In `start_request_from_args` (`src/cli_args.rs:234`), add to the constructed `StartRequest`:

```rust
        store_root: args.store_root,
        env: args.env,
```

In the `arg_takes_value` allowlist (`src/cli_args.rs:363`), add:

```rust
        "--store-root" | "--env"
```
(fold into the existing `matches!(flag, ...)` arm so both consume a following value).

Update every `StartRequest { .. }` literal in the fixtures listed under **Files** to include `store_root: None, env: "local".to_string(),` (search: `rg "StartRequest \{" src/` to find all; the report lists `src/bundle_config.rs:501`, `src/lib.rs:947`, `:979`, `:1050`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p greentic-start --lib cli_args`
Expected: PASS (and the crate compiles — all fixtures updated).

- [ ] **Step 5: Commit**

```bash
git add src/cli_args.rs src/bundle_config.rs src/lib.rs
git commit -m "feat(env-home): add --store-root/--env flags to StartArgs/StartRequest"
```

---

### Task 2: Mirror deploy-spec structs + parse `runtime-config.json`

**Files:**
- Create: `src/env_home/mod.rs`, `src/env_home/spec.rs`
- Modify: `src/lib.rs` (add `mod env_home;` near the module list ~`:26`; add `#[doc(hidden)] pub mod env_home;` if integration tests will drive it — use `#[doc(hidden)] pub` to mirror `threshold_watcher`)
- Test: `src/env_home/spec.rs` (inline)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `pub struct RuntimeConfig { pub schema: String, pub env_id: String, pub revisions: Vec<RevisionRuntimeBlock> }`
  - `pub struct RevisionRuntimeBlock { pub deployment_id: String, pub revision_id: String, pub bundle_id: String, pub pack_list_refs: Vec<PathBuf>, pub pack_config_refs: Vec<PathBuf>, pub weight_bps: u32 }`
  - `pub struct PackListLock { pub packs: Vec<LockedPack> }`
  - `pub struct LockedPack { pub pack_id: String, pub path: PathBuf, pub digest: String }`
  - `pub const RUNTIME_CONFIG_SCHEMA: &str = "greentic.runtime-config.v1";`
  - `pub fn parse_runtime_config(bytes: &[u8]) -> Result<RuntimeConfig, EnvHomeError>`

- [ ] **Step 1: Confirm exact serde field names**

Read `/home/bima-pangestu/projects/Works/greentic/greentic-deployer/crates/greentic-deploy-spec/src/runtime_config.rs` and `pack_list_lock.rs` and copy the EXACT serde field names / any `#[serde(rename)]` into the mirror. (The struct shapes above are from verification; confirm casing — they are snake_case in the JSON.) Do not skip this step; a rename mismatch silently drops fields.

- [ ] **Step 2: Write the failing test** (`src/env_home/spec.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "schema": "greentic.runtime-config.v1",
        "env_id": "local",
        "revisions": [{
            "deployment_id": "dep-1",
            "revision_id": "rev-1",
            "bundle_id": "app",
            "pack_list_refs": ["revisions/rev-1/pack-list.lock"],
            "pack_config_refs": [],
            "weight_bps": 10000
        }]
    }"#;

    #[test]
    fn parses_valid_runtime_config() {
        let rc = parse_runtime_config(SAMPLE.as_bytes()).expect("parse");
        assert_eq!(rc.schema, RUNTIME_CONFIG_SCHEMA);
        assert_eq!(rc.revisions.len(), 1);
        assert_eq!(rc.revisions[0].weight_bps, 10000);
        assert_eq!(rc.revisions[0].pack_list_refs[0],
            std::path::PathBuf::from("revisions/rev-1/pack-list.lock"));
    }

    #[test]
    fn rejects_wrong_schema() {
        let bad = SAMPLE.replace("greentic.runtime-config.v1", "greentic.runtime-config.v2");
        let err = parse_runtime_config(bad.as_bytes()).unwrap_err();
        assert!(matches!(err, EnvHomeError::SchemaMismatch { .. }));
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p greentic-start --lib env_home::spec`
Expected: FAIL — module/types not defined.

- [ ] **Step 4: Implement `spec.rs` + `EnvHomeError`**

`src/env_home/mod.rs`:

```rust
//! Boot greentic-start from a greentic-deployer environment home.
mod spec;
pub use spec::{parse_runtime_config, LockedPack, PackListLock, RevisionRuntimeBlock,
    RuntimeConfig, RUNTIME_CONFIG_SCHEMA};

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum EnvHomeError {
    #[error("environment `{env}` is not deployed (no runtime-config.json under {path})")]
    NotDeployed { env: String, path: PathBuf },
    #[error("unexpected runtime-config schema: got `{got}`, expected `{RUNTIME_CONFIG_SCHEMA}`")]
    SchemaMismatch { got: String },
    #[error("invalid traffic split for deployment `{deployment_id}`: weights sum to {sum} bps, expected 10000")]
    InvalidTrafficSplit { deployment_id: String, sum: u32 },
    #[error("partial traffic split for deployment `{deployment_id}` is not supported in slice 1a")]
    UnsupportedSplit { deployment_id: String },
    #[error("pack `{pack_id}` digest mismatch: on-disk {actual} != pinned {expected}")]
    DigestMismatch { pack_id: String, expected: String, actual: String },
    #[error("missing artifact at {0}")]
    MissingArtifact(PathBuf),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("malformed json in {path}: {source}")]
    Json { path: PathBuf, #[source] source: serde_json::Error },
}
```

`src/env_home/spec.rs`:

```rust
use serde::Deserialize;
use std::path::PathBuf;
use super::EnvHomeError;

pub const RUNTIME_CONFIG_SCHEMA: &str = "greentic.runtime-config.v1";

#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeConfig {
    pub schema: String,
    pub env_id: String,
    pub revisions: Vec<RevisionRuntimeBlock>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RevisionRuntimeBlock {
    pub deployment_id: String,
    pub revision_id: String,
    pub bundle_id: String,
    #[serde(default)]
    pub pack_list_refs: Vec<PathBuf>,
    #[serde(default)]
    pub pack_config_refs: Vec<PathBuf>,
    pub weight_bps: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PackListLock {
    pub packs: Vec<LockedPack>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LockedPack {
    pub pack_id: String,
    pub path: PathBuf,
    pub digest: String, // "sha256:<hex>"
}

pub fn parse_runtime_config(bytes: &[u8]) -> Result<RuntimeConfig, EnvHomeError> {
    let rc: RuntimeConfig = serde_json::from_slice(bytes)
        .map_err(|source| EnvHomeError::Json { path: PathBuf::from("runtime-config.json"), source })?;
    if rc.schema != RUNTIME_CONFIG_SCHEMA {
        return Err(EnvHomeError::SchemaMismatch { got: rc.schema });
    }
    Ok(rc)
}
```

Add `mod env_home;` to `src/lib.rs` (near `:26`).

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p greentic-start --lib env_home::spec`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/env_home/ src/lib.rs
git commit -m "feat(env-home): mirror runtime-config/pack-list structs + parser"
```

---

### Task 3: Route selection + traffic-split validation

**Files:**
- Create: `src/env_home/route.rs` (declare `mod route;` + re-export in `mod.rs`)
- Test: `src/env_home/route.rs` (inline)

**Interfaces:**
- Consumes: `RuntimeConfig`, `RevisionRuntimeBlock`, `EnvHomeError` (Task 2).
- Produces: `pub fn select_routed_revisions(rc: &RuntimeConfig) -> Result<Vec<&RevisionRuntimeBlock>, EnvHomeError>` — one block per `deployment_id`, each at 100% (weight_bps == 10000). Validates each deployment's weights sum to exactly 10000 and rejects partial splits.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_home::{RuntimeConfig, RevisionRuntimeBlock, EnvHomeError};

    fn block(dep: &str, rev: &str, w: u32) -> RevisionRuntimeBlock {
        RevisionRuntimeBlock { deployment_id: dep.into(), revision_id: rev.into(),
            bundle_id: "app".into(), pack_list_refs: vec![], pack_config_refs: vec![], weight_bps: w }
    }
    fn rc(revs: Vec<RevisionRuntimeBlock>) -> RuntimeConfig {
        RuntimeConfig { schema: crate::env_home::RUNTIME_CONFIG_SCHEMA.into(), env_id: "local".into(), revisions: revs }
    }

    #[test]
    fn selects_single_full_weight_revision() {
        let cfg = rc(vec![block("dep-1", "rev-1", 10000)]);
        let sel = select_routed_revisions(&cfg).expect("select");
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].revision_id, "rev-1");
    }

    #[test]
    fn rejects_weights_not_summing_to_10000() {
        let cfg = rc(vec![block("dep-1", "rev-1", 9000)]);
        assert!(matches!(select_routed_revisions(&cfg).unwrap_err(),
            EnvHomeError::InvalidTrafficSplit { .. }));
    }

    #[test]
    fn rejects_partial_split() {
        let cfg = rc(vec![block("dep-1", "rev-1", 6000), block("dep-1", "rev-2", 4000)]);
        assert!(matches!(select_routed_revisions(&cfg).unwrap_err(),
            EnvHomeError::UnsupportedSplit { .. }));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p greentic-start --lib env_home::route`
Expected: FAIL — `select_routed_revisions` not defined.

- [ ] **Step 3: Implement `route.rs`**

```rust
use std::collections::BTreeMap;
use super::{EnvHomeError, RevisionRuntimeBlock, RuntimeConfig};

pub fn select_routed_revisions(rc: &RuntimeConfig) -> Result<Vec<&RevisionRuntimeBlock>, EnvHomeError> {
    let mut by_dep: BTreeMap<&str, Vec<&RevisionRuntimeBlock>> = BTreeMap::new();
    for block in &rc.revisions {
        by_dep.entry(block.deployment_id.as_str()).or_default().push(block);
    }
    let mut selected = Vec::new();
    for (dep, blocks) in by_dep {
        let sum: u32 = blocks.iter().map(|b| b.weight_bps).sum();
        if sum != 10000 {
            return Err(EnvHomeError::InvalidTrafficSplit { deployment_id: dep.to_string(), sum });
        }
        let full: Vec<_> = blocks.iter().filter(|b| b.weight_bps == 10000).collect();
        match full.as_slice() {
            [only] => selected.push(**only),
            _ => return Err(EnvHomeError::UnsupportedSplit { deployment_id: dep.to_string() }),
        }
    }
    Ok(selected)
}
```

Add `mod route; pub use route::select_routed_revisions;` to `src/env_home/mod.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p greentic-start --lib env_home::route`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/env_home/
git commit -m "feat(env-home): route selection + traffic-split validation"
```

---

### Task 4: Pack digest verification against `pack-list.lock`

**Files:**
- Create: `src/env_home/verify.rs` (declare `mod verify;` + re-export)
- Test: `src/env_home/verify.rs` (inline, uses `tempfile::tempdir`)

**Interfaces:**
- Consumes: `PackListLock`, `LockedPack`, `EnvHomeError` (Task 2).
- Produces: `pub fn verify_pack_list(env_home: &Path, lock: &PackListLock) -> Result<Vec<PathBuf>, EnvHomeError>` — for each `LockedPack`, joins `env_home/<path>`, recomputes sha256, asserts it equals `digest`, returns the verified absolute pack paths. `MissingArtifact` if a path is absent, `DigestMismatch` on any mismatch.
- Helper: `fn sha256_hex(path: &Path) -> Result<String, EnvHomeError>` returning `"sha256:<hex>"`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_home::{PackListLock, LockedPack, EnvHomeError};
    use std::io::Write;

    fn write_pack(dir: &std::path::Path, rel: &str, bytes: &[u8]) -> String {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::File::create(&p).unwrap().write_all(bytes).unwrap();
        let mut h = <sha2::Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut h, bytes);
        format!("sha256:{:x}", sha2::Digest::finalize(h))
    }

    #[test]
    fn verifies_matching_digest() {
        let dir = tempfile::tempdir().unwrap();
        let digest = write_pack(dir.path(), "revisions/r1/bundle/packs/a.gtpack", b"hello");
        let lock = PackListLock { packs: vec![LockedPack {
            pack_id: "a".into(), path: "revisions/r1/bundle/packs/a.gtpack".into(), digest }] };
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
        let lock = PackListLock { packs: vec![LockedPack {
            pack_id: "a".into(), path: "p/a.gtpack".into(), digest }] };
        assert!(matches!(verify_pack_list(dir.path(), &lock).unwrap_err(),
            EnvHomeError::DigestMismatch { .. }));
    }

    #[test]
    fn rejects_missing_pack() {
        let dir = tempfile::tempdir().unwrap();
        let lock = PackListLock { packs: vec![LockedPack {
            pack_id: "a".into(), path: "nope/a.gtpack".into(), digest: "sha256:00".into() }] };
        assert!(matches!(verify_pack_list(dir.path(), &lock).unwrap_err(),
            EnvHomeError::MissingArtifact(_)));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p greentic-start --lib env_home::verify`
Expected: FAIL — `verify_pack_list` not defined.

- [ ] **Step 3: Implement `verify.rs`**

```rust
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use super::{EnvHomeError, LockedPack, PackListLock};

fn sha256_hex(path: &Path) -> Result<String, EnvHomeError> {
    let mut file = std::fs::File::open(path)
        .map_err(|_| EnvHomeError::MissingArtifact(path.to_path_buf()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

pub fn verify_pack_list(env_home: &Path, lock: &PackListLock) -> Result<Vec<PathBuf>, EnvHomeError> {
    let mut verified = Vec::with_capacity(lock.packs.len());
    for LockedPack { pack_id, path, digest } in &lock.packs {
        let abs = env_home.join(path);
        if !abs.exists() {
            return Err(EnvHomeError::MissingArtifact(abs));
        }
        let actual = sha256_hex(&abs)?;
        if &actual != digest {
            return Err(EnvHomeError::DigestMismatch {
                pack_id: pack_id.clone(), expected: digest.clone(), actual });
        }
        verified.push(abs);
    }
    Ok(verified)
}
```

Add `mod verify; pub use verify::verify_pack_list;` to `mod.rs`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p greentic-start --lib env_home::verify`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/env_home/
git commit -m "feat(env-home): sha256 verify packs against pack-list.lock"
```

---

### Task 5: `load_env_home` → `(DemoPaths, DemoConfig)` by reusing the extracted bundle dir

**Files:**
- Create: `src/env_home/loader.rs` (declare `mod loader;` + re-export)
- Modify: `src/bundle_config.rs` — make `DemoPaths`, `DemoConfigSource`, `load_runtime_demo_config`, and `apply_target_overrides` reachable from `env_home` (they are `pub(crate)` / module-private today; widen to `pub(crate)` where needed).
- Test: `src/env_home/loader.rs` (inline, builds a fixture env-home)

**Interfaces:**
- Consumes: `parse_runtime_config`, `select_routed_revisions`, `verify_pack_list` (Tasks 2–4); `bundle_config::{DemoPaths, DemoConfigSource, load_runtime_demo_config}`; `config::DemoConfig`; `StartRequest`.
- Produces: `pub fn load_env_home(store_root: &Path, env: &str, request: &StartRequest) -> Result<(bundle_config::DemoPaths, crate::config::DemoConfig), anyhow::Error>`.

**Key design:** the routed revision's `<env-home>/revisions/<rev>/bundle/` directory is already a normalized, extracted bundle (`bundle-manifest.json`, `packs/**/*.gtpack`, its own config yaml). So after digest-verifying the packs, we construct a `DemoPaths` with `root_dir = <rev>/bundle`, `config_source = DemoConfigSource::NormalizedBundle`, resolve its config file the same way `resolve_demo_paths` does for a bundle dir, and call the unchanged `load_runtime_demo_config`. No synthetic directory is built and no pack list is materialized — the runner rescans `root_dir` as usual.

- [ ] **Step 1: Confirm the bundle-dir config-file resolution**

Read `src/bundle_config.rs:24-378` (`resolve_demo_paths` + the `NormalizedBundle` inference at `:343-378`) and note exactly how it derives `config_path` from a bundle directory (`bundle.yaml` / `greentic.operator.yaml` / `bundle-manifest.json`). Reuse that same resolution for `<rev>/bundle`. If the private helper that finds the config file is not reachable, expose a `pub(crate) fn resolve_bundle_dir_paths(dir: &Path) -> Result<DemoPaths>` in `bundle_config.rs` that both `resolve_demo_paths` and `load_env_home` call (refactor, no behavior change).

- [ ] **Step 2: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_home::EnvHomeError;

    // Build a minimal env-home: runtime-config.json + revisions/r1/{pack-list.lock, bundle/...}
    fn fixture_env_home() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let env = dir.path().join("local");
        let rev = env.join("revisions/r1");
        let packs = rev.join("bundle/packs");
        std::fs::create_dir_all(&packs).unwrap();
        std::fs::write(packs.join("a.gtpack"), b"pack-bytes").unwrap();
        // a normalized-bundle config the existing loader accepts:
        std::fs::write(rev.join("bundle/bundle.yaml"),
            "tenant: acme\nteam: default\nservices:\n  gateway:\n    listen_addr: 127.0.0.1\n    port: 0\n").unwrap();
        let mut h = <sha2::Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut h, b"pack-bytes");
        let digest = format!("sha256:{:x}", sha2::Digest::finalize(h));
        std::fs::write(rev.join("pack-list.lock"),
            format!(r#"{{"packs":[{{"pack_id":"a","path":"revisions/r1/bundle/packs/a.gtpack","digest":"{digest}"}}]}}"#)).unwrap();
        std::fs::write(env.join("runtime-config.json"),
            r#"{"schema":"greentic.runtime-config.v1","env_id":"local","revisions":[{"deployment_id":"d1","revision_id":"r1","bundle_id":"app","pack_list_refs":["revisions/r1/pack-list.lock"],"pack_config_refs":[],"weight_bps":10000}]}"#).unwrap();
        dir
    }

    #[test]
    fn load_env_home_points_root_at_revision_bundle_dir() {
        let dir = fixture_env_home();
        let req = crate::cli_args::test_request(); // helper returning a default StartRequest
        let (paths, config) = load_env_home(dir.path(), "local", &req).expect("load");
        assert!(paths.root_dir.ends_with("revisions/r1/bundle"));
        assert_eq!(config.tenant.as_deref(), Some("acme"));
    }

    #[test]
    fn not_deployed_when_runtime_config_absent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("local")).unwrap();
        let req = crate::cli_args::test_request();
        let err = load_env_home(dir.path(), "local", &req).unwrap_err();
        assert!(err.downcast_ref::<EnvHomeError>()
            .map(|e| matches!(e, EnvHomeError::NotDeployed { .. })).unwrap_or(false));
    }
}
```

(Adjust `config.tenant` access to the real `DemoConfig` field shape confirmed in Step 1; add a small `pub(crate) fn test_request() -> StartRequest` to `cli_args.rs` if no reusable constructor exists.)

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p greentic-start --lib env_home::loader`
Expected: FAIL — `load_env_home` not defined.

- [ ] **Step 4: Implement `loader.rs`**

```rust
use std::path::{Path, PathBuf};
use anyhow::Context;
use super::{parse_runtime_config, select_routed_revisions, verify_pack_list, EnvHomeError, PackListLock};
use crate::{bundle_config, config, cli_args::StartRequest};

pub fn load_env_home(
    store_root: &Path,
    env: &str,
    request: &StartRequest,
) -> anyhow::Result<(bundle_config::DemoPaths, config::DemoConfig)> {
    let env_home = store_root.join(env);
    let rc_path = env_home.join("runtime-config.json");
    if !rc_path.exists() {
        return Err(EnvHomeError::NotDeployed { env: env.to_string(), path: rc_path }.into());
    }
    let bytes = std::fs::read(&rc_path)
        .map_err(EnvHomeError::from).context("read runtime-config.json")?;
    let rc = parse_runtime_config(&bytes)?;
    let routed = select_routed_revisions(&rc)?;

    // Slice 1a: exactly one deployment/revision.
    let block = routed.first().copied()
        .context("no routed revision in runtime-config.json")?;

    // Verify every pinned pack for this revision.
    for lock_ref in &block.pack_list_refs {
        let lock_bytes = std::fs::read(env_home.join(lock_ref))
            .map_err(|_| EnvHomeError::MissingArtifact(env_home.join(lock_ref)))?;
        let lock: PackListLock = serde_json::from_slice(&lock_bytes)
            .map_err(|source| EnvHomeError::Json { path: env_home.join(lock_ref), source })?;
        verify_pack_list(&env_home, &lock)?;
    }

    // The extracted bundle dir is already runner-loadable; reuse the existing path.
    let bundle_dir: PathBuf = env_home.join("revisions").join(&block.revision_id).join("bundle");
    let paths = bundle_config::resolve_bundle_dir_paths(&bundle_dir)
        .with_context(|| format!("resolve bundle dir {}", bundle_dir.display()))?;
    let config = bundle_config::load_runtime_demo_config(&paths, request)?;
    Ok((paths, config))
}
```

Add `mod loader; pub use loader::load_env_home;` to `mod.rs`. Widen the `bundle_config` items' visibility to `pub(crate)` as needed.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p greentic-start --lib env_home::loader`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/env_home/ src/bundle_config.rs src/cli_args.rs
git commit -m "feat(env-home): load_env_home resolves routed revision + reuses bundle-dir loader"
```

---

### Task 6: Wire env-home mode into `run_start` and `peek_startup_telemetry`

**Files:**
- Modify: `src/lib.rs:309-353` (`run_start` bundle-resolution seam) and `src/lib.rs:603-627` (`peek_startup_telemetry`)
- Test: `tests/env_home_boot.rs` (new integration test, gated) + a focused unit test of the branch

**Interfaces:**
- Consumes: `env_home::load_env_home` (Task 5); existing `demo_up_services` (`src/runtime.rs:485` call site) unchanged.

- [ ] **Step 1: Write the failing test** (`tests/env_home_boot.rs`)

Gate on the presence of the `greentic-deployer` binary; skip-as-pass when absent (mirror `tests/notifier_redis.rs:15-24`). Build a real env-home with `greentic-deployer op env init --store-root <tmp>` + `op deploy --bundle <tests/fixtures/*.gtbundle>`, then drive `greentic_start::run_start_request` in env-home mode on a random gateway port and assert `GET /healthz` → 200.

```rust
// tests/env_home_boot.rs
fn deployer_bin() -> Option<String> { std::env::var("GREENTIC_DEPLOYER_BIN").ok()
    .or_else(|| which::which("greentic-deployer").ok().map(|p| p.display().to_string())) }

#[test]
fn boots_from_env_home_and_serves_healthz() {
    let Some(deployer) = deployer_bin() else { eprintln!("skip: no greentic-deployer"); return; };
    // 1. op env init + op deploy into tmp store-root using a fixture bundle
    // 2. run_start_request with store_root=tmp, env="local", GREENTIC_GATEWAY_PORT=<free>
    // 3. poll http://127.0.0.1:<port>/healthz for 200
    // (full body per repo integration-test conventions; use ws_test_support port helper)
    let _ = deployer;
    todo!("implement per steps once fixture bundle is checked in")
}
```

If no fixture `.gtbundle` can be produced in CI, replace steps 1–2 with a hand-built env-home fixture tree under `tests/fixtures/env-home/` (same shape as Task 5's fixture but with a real minimal `.gtpack`), and assert `run_start` selects the env-home path (unit-level: that `load_env_home` is invoked and returns Ok) rather than a full HTTP boot.

- [ ] **Step 2: Run test to verify it fails / skips**

Run: `cargo test -p greentic-start --test env_home_boot`
Expected: SKIP (prints "skip") when no deployer, else FAIL on the `todo!`.

- [ ] **Step 3: Implement the branch in `run_start`**

At `src/lib.rs:309`, replace the unconditional `resolve_demo_paths` + `load_runtime_demo_config` (`:353`) with a branch:

```rust
let (demo_paths, mut demo_config) = if let Some(store_root) = request.store_root.clone() {
    crate::env_home::load_env_home(&store_root, &request.env, &request)?
} else {
    let demo_paths = bundle_config::resolve_demo_paths(request.config.clone(), request.bundle.as_deref())?;
    let demo_config = bundle_config::load_runtime_demo_config(&demo_paths, &request)?;
    (demo_paths, demo_config)
};
```

Keep the subsequent `config_path`/`config_dir`/`state_dir` extraction (`:322-324`) reading from `demo_paths`. Add a guard early in `run_start` (after arg mapping): if `request.store_root.is_some()` and (`request.bundle.is_some()` || `request.config.is_some()`), `anyhow::bail!("--store-root is mutually exclusive with --bundle/--config")`.

Mirror the branch in `peek_startup_telemetry` (`:606`): when `store_root` is set, resolve the env-home's routed bundle dir for telemetry (or short-circuit telemetry to the env-home path); do not call `resolve_demo_paths` with a `None` bundle there.

- [ ] **Step 4: Run the full check**

Run: `cargo test -p greentic-start` then `cargo clippy -p greentic-start --all-targets -- -D warnings`
Expected: PASS; integration test skips cleanly without a deployer binary.

- [ ] **Step 5: Commit**

```bash
git add src/lib.rs tests/env_home_boot.rs
git commit -m "feat(env-home): branch run_start to env-home loader when --store-root set"
```

---

### Task 7: Reload on `runtime-config.json` change (poll → clean restart signal)

**Files:**
- Modify: `src/lib.rs:829-862` (`ShutdownReason` enum + `wait_for_shutdown`)
- Test: `src/lib.rs` inline (unit test of the change-detection helper)

**Interfaces:**
- Produces: `ShutdownReason::ConfigChanged`; `wait_for_shutdown` gains an optional watched path.

**Scope:** slice 1a implements reload as "detect change → clean shutdown with `ConfigChanged`" so a supervisor (the designer, SP2) restarts the process on the new revision. In-process hot-swap and graceful drain are explicitly out of scope.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn detects_runtime_config_change_by_mtime() {
    use crate::env_home::runtime_config_changed;
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("runtime-config.json");
    std::fs::write(&p, b"{}").unwrap();
    let baseline = std::fs::metadata(&p).unwrap().modified().unwrap();
    // no change yet
    assert!(!runtime_config_changed(&p, baseline));
    // touch with a newer mtime
    std::thread::sleep(std::time::Duration::from_millis(10));
    std::fs::write(&p, b"{ }").unwrap();
    assert!(runtime_config_changed(&p, baseline));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p greentic-start --lib detects_runtime_config_change_by_mtime`
Expected: FAIL — `runtime_config_changed` not defined.

- [ ] **Step 3: Implement the helper + select! arm**

Add to `src/env_home/mod.rs`:

```rust
use std::time::SystemTime;
/// True if `path`'s mtime is strictly newer than `baseline`.
pub fn runtime_config_changed(path: &std::path::Path, baseline: SystemTime) -> bool {
    std::fs::metadata(path).and_then(|m| m.modified())
        .map(|m| m > baseline).unwrap_or(false)
}
```

Add `ConfigChanged` to `ShutdownReason` (`src/lib.rs:829`). In `wait_for_shutdown` (`:848`), when the process is in env-home mode, capture the baseline mtime of `<env-home>/runtime-config.json` and add a third `tokio::select!` arm on the 250ms tick that returns `Ok(ShutdownReason::ConfigChanged)` when `runtime_config_changed(...)`. Thread the watched path into `wait_for_shutdown` (add a `Option<PathBuf>` param; `None` for bundle mode preserves current behavior). In `run_start`'s teardown (`:562`), a `ConfigChanged` reason should exit cleanly (exit code 0) so the supervisor restarts.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p greentic-start --lib env_home`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/lib.rs src/env_home/
git commit -m "feat(env-home): restart-on-change watcher for runtime-config.json"
```

---

### Task 8: Docs + full local CI

**Files:**
- Modify: `CLAUDE.md` / `README` CLI table if it enumerates `greentic-start` flags (add `--store-root`/`--env`).
- Verify only.

- [ ] **Step 1: Document the new mode**

Add a short "Environment-home mode" note to the greentic-start CLI docs: `greentic-start --store-root <dir> --env <id>` boots the routed revision from a greentic-deployer env-home; mutually exclusive with `--bundle`/`--config`; gateway port still via `GREENTIC_GATEWAY_PORT`.

- [ ] **Step 2: Run the canonical CI gate**

Run: `bash ci/local_check.sh`
Expected: PASS (fmt, clippy -D warnings, full test, build, doc, package). Fix anything in-scope; document out-of-scope failures in the PR summary.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "docs(env-home): document --store-root/--env boot mode"
```

---

## Self-Review

- **Spec coverage:** §3.1 flags → Task 1; §3.2 loader (parse/route/verify/load) → Tasks 2–5; §3.1 injection → Task 6; §3.3 watch → Task 7; §3.4 errors → the `EnvHomeError` enum in Task 2 (each variant produced by Tasks 2–5); §5 testing → tests in every task + Task 6 integration + Task 8 CI. Covered.
- **Placeholder scan:** Task 6's integration test intentionally carries a `todo!` guarded behind a binary check with a written fallback — flagged, not hidden; the executor completes it once a fixture bundle exists. All other steps carry real code.
- **Type consistency:** `EnvHomeError`, `RuntimeConfig`, `RevisionRuntimeBlock`, `PackListLock`, `LockedPack`, `select_routed_revisions`, `verify_pack_list`, `load_env_home`, `runtime_config_changed`, `ShutdownReason::ConfigChanged`, `bundle_config::{DemoPaths, resolve_bundle_dir_paths, load_runtime_demo_config}`, `config::DemoConfig` are used consistently across tasks.
- **`--env` vs `GREENTIC_ENV`:** never conflated (Global Constraints + Task 1 comment).

## Execution note

The `bundle.yaml`/`DemoConfig` field names in Task 5's fixture and assertions must be reconciled with the real `config::DemoConfig` shape (`src/config.rs:94-107`) during Step 1 of that task — treat the fixture YAML as illustrative until confirmed.
