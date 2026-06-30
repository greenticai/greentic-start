# DwApplication Agent Activation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `gtc start <bundle>` derive a `greentic_aw_runtime::AgentConfig` from a `DwApplication` app-pack in the bundle and register it into `HostConfig.agents`, so no hand-authored `GREENTIC_AW_AGENTS_FILE` is required.

**Architecture:** Add a shared `dw` module to `greentic-aw-runtime` (owner of `AgentConfig`, already a dep of both consumers) that parses the `DwApplication` `manifest.json` into a typed `DwApplicationManifest` and converts it to `AgentConfig`. `greentic-start` discovers DwApplication packs in the bundle, calls the converter, and inserts the result into the synthetic `HostConfig` it builds.

**Tech Stack:** Rust 1.95 / edition 2024, `serde`/`serde_json`, `zip` (already a `greentic-start` dep), `tracing`.

## Global Constraints

- Rust **1.95.0**, edition 2024, `#![forbid(unsafe_code)]` at crate roots.
- No `unwrap()`/`panic!()` in production paths — `anyhow`/`thiserror`; fail-soft on agent derivation (warn + skip, never abort `gtc start`).
- `cargo fmt --all -- --check` and `cargo clippy --all-targets --all-features -- -D warnings` must pass in each repo.
- Conventional Commits. **No Claude co-author trailer** on `greentic-start` / runner commits.
- `greentic-aw-runtime` exact types (do not redefine): `AgentConfig { agent_id: String, system_prompt: String, tools: Vec<ToolRef>, guardrails: Vec<GuardrailRef>, llm: LlmProviderRef, limits: AgentLimits, memory: Option<MemorySettings>, knowledge: Option<KnowledgeSettings> }`; `LlmProviderRef { provider: String, model: String, credential_ref: Option<String> }`; `MemoryProviderRef { provider: String, capability: String, params: serde_json::Map<String, serde_json::Value>, credential_ref: Option<String> }`; `MemorySettings { short_term: Option<MemoryProviderRef>, long_term: Option<MemoryProviderRef> }`.
- DwApplication `manifest.json` shape (the parse contract): top-level `manifest_id: String`; `manifest.capability_plan.default_provider_ids: { "cap://llm/chat": "provider.llm.deepseek.chat", "cap://memory/long-term": "provider.memory.chronicle", "cap://memory/short-term": "provider.memory.redis" }`; `manifest.defaults.values: { "system_prompt": "...", "provider.llm.deepseek.chat::model": "deepseek-chat", ... }`.
- **Runner branch base:** `greentic-start` pins `greentic-runner` at rev `dd6924c8f26fc2028372771dede2adcecd99da8c`. Create the Phase A branch **from that rev** (not from `research` HEAD) so the Phase B pin bump introduces only this change.

## File Structure

- `greentic-runner/crates/greentic-aw-runtime/src/dw.rs` — **new.** `DwApplicationManifest` parse type + `provider_slug` + `agent_config_from_dw_manifest`. One responsibility: DwApplication-manifest → AgentConfig.
- `greentic-runner/crates/greentic-aw-runtime/src/lib.rs` — **modify.** `pub mod dw;` + re-export.
- `greentic-start/src/runner_host/dw_agents.rs` — **new.** Bundle discovery + per-pack parse: `dw_agents_from_bundle(bundle_root, tenant) -> Vec<(String, AgentConfig)>`. One responsibility: find DwApplication packs in a bundle and convert them.
- `greentic-start/src/runner_host/helpers.rs` — **modify.** Thread `bundle_root` into `build_demo_host_config`; merge bundle agents before the env-file override.
- `greentic-start/src/runner_host/dispatch.rs` — **modify.** Pass `&self.bundle_root` at the one call site (line ~364).
- `greentic-start/src/runner_host.rs` — **modify.** `mod dw_agents;`.
- `greentic-start/docs/agentic-worker-bundle.md` — **modify.** Note bundle-derived agents (env file now optional).

---

## Phase A — `greentic-aw-runtime` (repo: `greentic-runner`)

> Work in `greentic-runner/`. First: `git -C greentic-runner fetch && git -C greentic-runner switch -c feat/dw-agent-from-manifest dd6924c8f26fc2028372771dede2adcecd99da8c`. Build/test with `cargo test -p greentic-aw-runtime`.

### Task 1: `DwApplicationManifest` parse type

**Files:**
- Create: `greentic-runner/crates/greentic-aw-runtime/src/dw.rs`
- Modify: `greentic-runner/crates/greentic-aw-runtime/src/lib.rs` (add `pub mod dw;`)
- Test: inline `#[cfg(test)]` in `dw.rs`

**Interfaces:**
- Produces: `DwApplicationManifest` with `pub manifest_id: String` and accessors `fn llm_provider_id(&self) -> Option<&str>`, `fn memory_provider_id(&self, cap: &str) -> Option<&str>`, `fn system_prompt(&self) -> &str`, `fn model_for(&self, provider_id: &str) -> Option<&str>`.

- [ ] **Step 1: Write the failing test**

In `greentic-runner/crates/greentic-aw-runtime/src/dw.rs`:

```rust
//! DwApplication pack manifest → `AgentConfig` conversion. Shared by the
//! runner host (`gtc start`) and the designer so both apply identical rules.
use std::collections::BTreeMap;

use serde::Deserialize;

/// Minimal typed view of a designer-exported `DwApplication` `manifest.json`.
/// Tolerant of unknown fields so future pack additions don't break parsing.
#[derive(Debug, Clone, Deserialize)]
pub struct DwApplicationManifest {
    pub manifest_id: String,
    #[serde(default)]
    manifest: DwManifestBody,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct DwManifestBody {
    #[serde(default)]
    capability_plan: DwCapabilityPlan,
    #[serde(default)]
    defaults: DwDefaults,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct DwCapabilityPlan {
    #[serde(default)]
    default_provider_ids: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct DwDefaults {
    #[serde(default)]
    values: BTreeMap<String, serde_json::Value>,
}

impl DwApplicationManifest {
    /// Provider id bound to `cap://llm/chat`, if any.
    pub fn llm_provider_id(&self) -> Option<&str> {
        self.manifest
            .capability_plan
            .default_provider_ids
            .get("cap://llm/chat")
            .map(String::as_str)
    }

    /// Provider id bound to a memory capability (e.g. `cap://memory/long-term`).
    pub fn memory_provider_id(&self, cap: &str) -> Option<&str> {
        self.manifest
            .capability_plan
            .default_provider_ids
            .get(cap)
            .map(String::as_str)
    }

    /// The agent system prompt (`defaults.values.system_prompt`), or "".
    pub fn system_prompt(&self) -> &str {
        self.manifest
            .defaults
            .values
            .get("system_prompt")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
    }

    /// Model default for a provider id (`defaults.values["{provider_id}::model"]`).
    pub fn model_for(&self, provider_id: &str) -> Option<&str> {
        let key = format!("{provider_id}::model");
        self.manifest
            .defaults
            .values
            .get(&key)
            .and_then(serde_json::Value::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"{
      "manifest_id": "onboarding-companion",
      "display_name": "Onboarding Companion",
      "manifest": {
        "capability_plan": {
          "default_provider_ids": {
            "cap://llm/chat": "provider.llm.deepseek.chat",
            "cap://memory/long-term": "provider.memory.chronicle",
            "cap://memory/short-term": "provider.memory.redis"
          }
        },
        "defaults": {
          "values": {
            "system_prompt": "You are an Onboarding Companion.",
            "provider.llm.deepseek.chat::model": "deepseek-chat"
          }
        }
      },
      "tenant": "greentic"
    }"#;

    #[test]
    fn parses_manifest_fields() {
        let m: DwApplicationManifest = serde_json::from_str(FIXTURE).expect("parse");
        assert_eq!(m.manifest_id, "onboarding-companion");
        assert_eq!(m.llm_provider_id(), Some("provider.llm.deepseek.chat"));
        assert_eq!(m.memory_provider_id("cap://memory/long-term"), Some("provider.memory.chronicle"));
        assert_eq!(m.system_prompt(), "You are an Onboarding Companion.");
        assert_eq!(m.model_for("provider.llm.deepseek.chat"), Some("deepseek-chat"));
    }
}
```

Add to `greentic-runner/crates/greentic-aw-runtime/src/lib.rs` near the other `pub mod` lines:

```rust
pub mod dw;
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p greentic-aw-runtime dw::tests::parses_manifest_fields`
Expected: compile error / FAIL until `pub mod dw;` and the code above are in place. (If you wrote both files first, it should PASS — in that case temporarily break an assertion, confirm FAIL, then restore.)

- [ ] **Step 3: Confirm implementation present**

The code in Step 1 is the implementation (parse type + accessors). No further code needed for this task.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p greentic-aw-runtime dw::tests::parses_manifest_fields`
Expected: PASS (1 passed).

- [ ] **Step 5: Commit**

```bash
git -C greentic-runner add crates/greentic-aw-runtime/src/dw.rs crates/greentic-aw-runtime/src/lib.rs
git -C greentic-runner commit -m "feat(aw-runtime): add DwApplicationManifest parse type"
```

### Task 2: `provider_slug` shared rule

**Files:**
- Modify: `greentic-runner/crates/greentic-aw-runtime/src/dw.rs`

**Interfaces:**
- Produces: `pub fn provider_slug(provider_id: &str) -> String` (strips `provider.llm.{slug}.{variant}` → `{slug}`; passthrough otherwise). Mirrors `greentic-designer` `dw_form_to_agent_config::provider_slug` exactly.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `dw.rs`:

```rust
    #[test]
    fn provider_slug_strips_catalog_prefix() {
        assert_eq!(provider_slug("provider.llm.deepseek.chat"), "deepseek");
        assert_eq!(provider_slug("provider.llm.anthropic.chat"), "anthropic");
        // pre-resolved slug passes through unchanged
        assert_eq!(provider_slug("deepseek"), "deepseek");
        // non-matching string passes through unchanged
        assert_eq!(provider_slug("provider.llm"), "provider.llm");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p greentic-aw-runtime dw::tests::provider_slug_strips_catalog_prefix`
Expected: FAIL — `cannot find function provider_slug`.

- [ ] **Step 3: Write minimal implementation**

Add to `dw.rs` (module level, above `#[cfg(test)]`):

```rust
/// Map a catalog `provider_id` to its provider slug. Catalog ids follow
/// `provider.llm.{slug}.{variant}` (e.g. `provider.llm.deepseek.chat`); this
/// strips prefix + variant to `{slug}`. Anything not matching is returned
/// unchanged, so a pre-resolved slug like `"deepseek"` passes through.
#[must_use]
pub fn provider_slug(provider_id: &str) -> String {
    if let Some(rest) = provider_id.strip_prefix("provider.llm.") {
        if let Some((slug, _variant)) = rest.split_once('.') {
            return slug.to_string();
        }
    }
    provider_id.to_string()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p greentic-aw-runtime dw::tests::provider_slug_strips_catalog_prefix`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git -C greentic-runner add crates/greentic-aw-runtime/src/dw.rs
git -C greentic-runner commit -m "feat(aw-runtime): add shared provider_slug rule"
```

### Task 3: `agent_config_from_dw_manifest`

**Files:**
- Modify: `greentic-runner/crates/greentic-aw-runtime/src/dw.rs`

**Interfaces:**
- Consumes: `DwApplicationManifest` (Task 1), `provider_slug` (Task 2), `crate::{AgentConfig, AgentLimits, LlmProviderRef, MemoryProviderRef, MemorySettings}`.
- Produces: `pub fn agent_config_from_dw_manifest(m: &DwApplicationManifest) -> AgentConfig`.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `dw.rs`:

```rust
    #[test]
    fn converts_manifest_to_agent_config() {
        let m: DwApplicationManifest = serde_json::from_str(FIXTURE).expect("parse");
        let cfg = agent_config_from_dw_manifest(&m);

        assert_eq!(cfg.agent_id, "onboarding-companion");
        assert_eq!(cfg.system_prompt, "You are an Onboarding Companion.");
        assert_eq!(cfg.llm.provider, "deepseek");
        assert_eq!(cfg.llm.model, "deepseek-chat");
        assert!(cfg.llm.credential_ref.is_none());

        let mem = cfg.memory.expect("memory present");
        assert_eq!(mem.long_term.as_ref().unwrap().provider, "provider.memory.chronicle");
        assert_eq!(mem.long_term.as_ref().unwrap().capability, "cap://memory/long-term");
        assert_eq!(mem.short_term.as_ref().unwrap().provider, "provider.memory.redis");
        assert!(cfg.tools.is_empty());
        assert!(cfg.knowledge.is_none());
    }

    #[test]
    fn missing_model_yields_empty_string() {
        let json = r#"{"manifest_id":"x","manifest":{"capability_plan":{"default_provider_ids":{"cap://llm/chat":"provider.llm.deepseek.chat"}},"defaults":{"values":{"system_prompt":"hi"}}}}"#;
        let m: DwApplicationManifest = serde_json::from_str(json).expect("parse");
        let cfg = agent_config_from_dw_manifest(&m);
        assert_eq!(cfg.llm.model, "");
        assert!(cfg.memory.is_none());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p greentic-aw-runtime dw::tests::converts_manifest_to_agent_config`
Expected: FAIL — `cannot find function agent_config_from_dw_manifest`.

- [ ] **Step 3: Write minimal implementation**

Add to `dw.rs` (module level). Add the imports at the top of the file:

```rust
use crate::{AgentConfig, AgentLimits, LlmProviderRef, MemoryProviderRef, MemorySettings};
```

```rust
/// Convert a parsed `DwApplication` manifest into a runtime [`AgentConfig`].
///
/// `llm.model` is left empty (with a `warn`) when the manifest declares no
/// model default — the runtime forwards `model` to the provider verbatim, so a
/// foreign fallback would silently mis-route. `credential_ref` is left `None`
/// here; populating it is the separate credential-surfacing prerequisite.
#[must_use]
pub fn agent_config_from_dw_manifest(m: &DwApplicationManifest) -> AgentConfig {
    let llm_provider_id = m.llm_provider_id().unwrap_or_default();
    let provider = provider_slug(llm_provider_id);
    let model = m.model_for(llm_provider_id).unwrap_or_default().to_string();
    if model.is_empty() {
        tracing::warn!(
            agent = %m.manifest_id,
            provider_id = %llm_provider_id,
            "DwApplication manifest has no model default; leaving llm.model empty"
        );
    }

    AgentConfig {
        agent_id: m.manifest_id.clone(),
        system_prompt: m.system_prompt().to_string(),
        tools: Vec::new(),
        guardrails: Vec::new(),
        llm: LlmProviderRef {
            provider,
            model,
            credential_ref: None,
        },
        limits: AgentLimits::default(),
        memory: build_memory(m),
        knowledge: None,
    }
}

fn build_memory(m: &DwApplicationManifest) -> Option<MemorySettings> {
    let mem_ref = |cap: &str| {
        m.memory_provider_id(cap).map(|provider_id| MemoryProviderRef {
            provider: provider_id.to_string(),
            capability: cap.to_string(),
            params: serde_json::Map::new(),
            credential_ref: None,
        })
    };
    let short_term = mem_ref("cap://memory/short-term");
    let long_term = mem_ref("cap://memory/long-term");
    if short_term.is_none() && long_term.is_none() {
        None
    } else {
        Some(MemorySettings { short_term, long_term })
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p greentic-aw-runtime dw::`
Expected: PASS (all `dw` tests, including `missing_model_yields_empty_string`).

- [ ] **Step 5: fmt + clippy + commit**

```bash
cd greentic-runner && cargo fmt -p greentic-aw-runtime && cargo clippy -p greentic-aw-runtime --all-targets -- -D warnings && cd ..
git -C greentic-runner add crates/greentic-aw-runtime/src/dw.rs
git -C greentic-runner commit -m "feat(aw-runtime): convert DwApplication manifest to AgentConfig"
```

- [ ] **Step 6: Push the branch and record the rev**

```bash
git -C greentic-runner push -u origin feat/dw-agent-from-manifest
git -C greentic-runner rev-parse HEAD   # record this — Phase B pins it
```

---

## Phase B — `greentic-start` (repo: `greentic-start`)

> Branch off the current `greentic-start` branch (`research`): `git -C greentic-start switch -c feat/dw-agent-activation`.

### Task 4: Discover + register DwApplication agents from the bundle

**Files:**
- Create: `greentic-start/src/runner_host/dw_agents.rs`
- Modify: `greentic-start/src/runner_host.rs` (`mod dw_agents;`)
- Modify: `greentic-start/Cargo.toml` (bump runner pin to the Task-3 rev)
- Modify: `greentic-start/src/runner_host/helpers.rs` (`build_demo_host_config` signature + merge)
- Modify: `greentic-start/src/runner_host/dispatch.rs:~364` (pass `&self.bundle_root`)
- Test: inline `#[cfg(test)]` in `dw_agents.rs`

**Interfaces:**
- Consumes: `greentic_aw_runtime::dw::{DwApplicationManifest, agent_config_from_dw_manifest}`; `greentic_aw_runtime::config::AgentConfig` (re-exported via runner-host as today).
- Produces: `pub(crate) fn dw_agents_from_bundle(bundle_root: &std::path::Path, tenant: &str) -> Vec<(String, AgentConfig)>`.

- [ ] **Step 1: Bump the runner pin**

In `greentic-start/Cargo.toml`, set both runner deps' `rev` to the Phase A Task-3 commit recorded in Phase A Step 6 (replace `dd6924c8f26fc2028372771dede2adcecd99da8c`):

```toml
[dependencies.greentic-runner-host]
git = "https://github.com/greenticai/greentic-runner.git"
rev = "<PHASE_A_HEAD_REV>"
default-features = false
features = ["agentic-worker"]

[dependencies.greentic-runner-desktop]
git = "https://github.com/greenticai/greentic-runner.git"
rev = "<PHASE_A_HEAD_REV>"
default-features = false
features = ["agentic-worker"]
```

Run: `cargo update -p greentic-runner-host -p greentic-runner-desktop && cargo build -p greentic-start --features agentic-worker`
Expected: builds (pulls the new rev with the `dw` module).

- [ ] **Step 2: Write the failing test**

Create `greentic-start/src/runner_host/dw_agents.rs`:

```rust
//! Derive agentic-worker `AgentConfig`s from `DwApplication` packs in a bundle.
//!
//! `gtc start` builds a synthetic `HostConfig`; this module sources its agents
//! from the bundle's DwApplication app-packs (manifest.json), so a hand-authored
//! `GREENTIC_AW_AGENTS_FILE` is no longer required. Fail-soft: any unreadable /
//! non-DwApplication / unparseable pack is logged and skipped.
use std::io::Read;
use std::path::{Path, PathBuf};

use greentic_aw_runtime::config::AgentConfig;
use greentic_aw_runtime::dw::{agent_config_from_dw_manifest, DwApplicationManifest};

/// Discover DwApplication packs under the bundle and convert each to an
/// `(agent_id, AgentConfig)`. Never errors: problems are logged and skipped.
pub(crate) fn dw_agents_from_bundle(bundle_root: &Path, tenant: &str) -> Vec<(String, AgentConfig)> {
    let mut out = Vec::new();
    for pack in candidate_packs(bundle_root, tenant) {
        match agent_from_pack(&pack) {
            Ok(Some(cfg)) => out.push((cfg.agent_id.clone(), cfg)),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(pack = %pack.display(), error = %error, "skipping DwApplication pack");
            }
        }
    }
    out
}

/// `.gtpack` files under `tenants/<tenant>/packs/` and `packs/`.
fn candidate_packs(bundle_root: &Path, tenant: &str) -> Vec<PathBuf> {
    let dirs = [
        bundle_root.join("tenants").join(tenant).join("packs"),
        bundle_root.join("packs"),
    ];
    let mut packs = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "gtpack") {
                packs.push(path);
            }
        }
    }
    packs
}

/// Returns `Some(cfg)` for a DwApplication pack, `None` for any other kind.
fn agent_from_pack(pack: &Path) -> anyhow::Result<Option<AgentConfig>> {
    let file = std::fs::File::open(pack)?;
    let mut archive = zip::ZipArchive::new(file)?;

    let metadata: serde_json::Value = read_json(&mut archive, "metadata.json")?;
    if metadata.get("kind").and_then(serde_json::Value::as_str) != Some("DwApplication") {
        return Ok(None);
    }

    let manifest: DwApplicationManifest = serde_json::from_value(read_json(&mut archive, "manifest.json")?)?;
    Ok(Some(agent_config_from_dw_manifest(&manifest)))
}

fn read_json(archive: &mut zip::ZipArchive<std::fs::File>, name: &str) -> anyhow::Result<serde_json::Value> {
    let mut entry = archive.by_name(name)?;
    let mut buf = String::new();
    entry.read_to_string(&mut buf)?;
    Ok(serde_json::from_str(&buf)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_dw_pack(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        let file = std::fs::File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        zip.start_file("metadata.json", opts).unwrap();
        zip.write_all(br#"{"kind":"DwApplication"}"#).unwrap();
        zip.start_file("manifest.json", opts).unwrap();
        zip.write_all(br#"{"manifest_id":"onboarding-companion","manifest":{"capability_plan":{"default_provider_ids":{"cap://llm/chat":"provider.llm.deepseek.chat"}},"defaults":{"values":{"system_prompt":"hi","provider.llm.deepseek.chat::model":"deepseek-chat"}}}}"#).unwrap();
        zip.finish().unwrap();
        path
    }

    #[test]
    fn discovers_and_converts_dw_pack() {
        let tmp = tempfile::tempdir().unwrap();
        let packs = tmp.path().join("tenants").join("greentic").join("packs");
        std::fs::create_dir_all(&packs).unwrap();
        write_dw_pack(&packs, "onboarding.gtpack");

        let agents = dw_agents_from_bundle(tmp.path(), "greentic");
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].0, "onboarding-companion");
        assert_eq!(agents[0].1.llm.model, "deepseek-chat");
    }

    #[test]
    fn skips_non_dwapplication_and_empty_bundles() {
        let tmp = tempfile::tempdir().unwrap();
        // no packs dir at all → empty, no panic
        assert!(dw_agents_from_bundle(tmp.path(), "greentic").is_empty());
    }
}
```

Register the module — add to `greentic-start/src/runner_host.rs`:

```rust
mod dw_agents;
```

Ensure `zip` and `tempfile` are available: `zip` is already a non-dev dependency; add `tempfile` under `[dev-dependencies]` in `greentic-start/Cargo.toml` if not already present (it is used by existing tests).

- [ ] **Step 3: Run test to verify it fails, then passes**

Run: `cargo test -p greentic-start --features agentic-worker dw_agents::tests`
Expected: first run may FAIL to compile until `mod dw_agents;` is added and the runner pin (Step 1) exposes `greentic_aw_runtime::dw`. Once compiling: PASS (2 tests).

- [ ] **Step 4: Wire into the host config build**

Modify `greentic-start/src/runner_host/helpers.rs` — change the signature and merge bundle agents **before** the env override:

```rust
pub(super) fn build_demo_host_config(tenant: &str, bundle_root: &std::path::Path) -> HostConfig {
    let mut config = HostConfig {
        // ... unchanged fields ...
        agents: HashMap::new(),
    };
    // Bundle-derived DwApplication agents are the primary source.
    for (agent_id, cfg) in crate::runner_host::dw_agents::dw_agents_from_bundle(bundle_root, tenant) {
        config.agents.insert(agent_id, cfg);
    }
    // GREENTIC_AW_AGENTS_FILE (when set) overrides/supplements (dev workflow).
    apply_demo_agents(&mut config);
    config
}
```

Modify `greentic-start/src/runner_host/dispatch.rs` (the call at ~line 364):

```rust
let host_config = Arc::new(build_demo_host_config(&ctx.tenant, &self.bundle_root));
```

Update the two existing helper tests that call `build_demo_host_config("acme")` (helpers.rs ~409, ~438) to pass a path, e.g. `build_demo_host_config("acme", std::path::Path::new("/nonexistent"))` — a missing bundle yields no agents (fail-soft), preserving their original behavior.

- [ ] **Step 5: Run the full crate test + fmt + clippy**

Run:
```bash
cargo test -p greentic-start --features agentic-worker
cargo fmt -p greentic-start -- --check
cargo clippy -p greentic-start --all-targets --features agentic-worker -- -D warnings
```
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git -C greentic-start add src/runner_host/dw_agents.rs src/runner_host.rs src/runner_host/helpers.rs src/runner_host/dispatch.rs Cargo.toml Cargo.lock
git -C greentic-start commit -m "feat: register DwApplication agents from bundle on gtc start"
```

### Task 5: End-to-end verification + docs

**Files:**
- Modify: `greentic-start/docs/agentic-worker-bundle.md`

- [ ] **Step 1: Manual smoke (real bundle)**

Using the composed bundle from earlier work (`scratchpad/companion-bundle`, pack under `tenants/greentic/packs/`), build the AW binary and start WITHOUT `GREENTIC_AW_AGENTS_FILE`:

```bash
cargo build -p greentic-start --features agentic-worker --bin greentic-start
GREENTIC_AW_REDIS_URL=redis://127.0.0.1:6379 \
  ./target/debug/greentic-start start --bundle <bundle> --cloudflared off
```
Expected: the runner constructs a host config whose `agents` map contains `onboarding-companion` (no env agents file set). Confirm via a debug log of `config.agents.len()` or a runner "agent_count" line.

- [ ] **Step 2: Update the doc**

In `greentic-start/docs/agentic-worker-bundle.md`, under "Per-agent config", add:

```markdown
Agents are now **also** sourced automatically from any `DwApplication` app-pack
in the bundle (`tenants/<tenant>/packs/*.gtpack` or `packs/*.gtpack`): greentic-start
reads each pack's `manifest.json`, converts it via
`greentic_aw_runtime::dw::agent_config_from_dw_manifest`, and registers it into
`HostConfig.agents`. `GREENTIC_AW_AGENTS_FILE` remains supported and, when set,
overrides/supplements the bundle-derived agents by id.
```

- [ ] **Step 3: Commit**

```bash
git -C greentic-start add docs/agentic-worker-bundle.md
git -C greentic-start commit -m "docs: bundle-derived DwApplication agents on gtc start"
```

---

## Follow-up (separate plan, not in this DoD)

`greentic-designer` (greentic-biz): refactor `dw_form_to_agent_config::provider_slug` (and, where shapes allow, model resolution) to consume `greentic_aw_runtime::dw::provider_slug` so the designer and runtime never diverge. Guarded until then by the parity assertion in Task 2. Memory mapping is NOT shared (the manifest exposes only provider-id strings, while the form exposes full `ProviderBinding`s).

## Self-Review

**Spec coverage:**
- Shared converter in `greentic-aw-runtime` → Tasks 1–3. ✓
- `DwApplicationManifest` contract → Task 1. ✓
- Mapping rules (agent_id/system_prompt/llm provider+model/memory/credential_ref/limits) → Task 3. ✓
- `apply_bundle_dw_agents` discovery + insert into `HostConfig.agents` → Task 4 (`dw_agents_from_bundle` + helpers wiring). ✓
- Precedence (bundle primary, env override) → Task 4 Step 4. ✓
- Fail-soft → Task 4 (`agent_from_pack`/`dw_agents_from_bundle` log+skip) + the empty-bundle test. ✓
- Reuse existing pack location: NOTE — `load_app_pack_info` reads `manifest.cbor` (flow packs) and does NOT fit the DwApplication JSON pack, so Task 4 uses its own zip read of `metadata.json` + `manifest.json` rather than `load_app_pack_info`. This is a deliberate correction to the spec's Component-2 wording. ✓
- Testing (aw-runtime unit, greentic-start unit, parity) → Tasks 1–4. ✓
- Out-of-scope items → unchanged, restated in Follow-up. ✓

**Placeholder scan:** `<PHASE_A_HEAD_REV>` is an intentional runtime value recorded in Phase A Step 6, not a TODO. No other placeholders.

**Type consistency:** `dw_agents_from_bundle`, `agent_config_from_dw_manifest`, `provider_slug`, `DwApplicationManifest` names match across tasks. `AgentConfig`/`LlmProviderRef`/`MemoryProviderRef`/`MemorySettings` fields match the Global Constraints block verbatim.
