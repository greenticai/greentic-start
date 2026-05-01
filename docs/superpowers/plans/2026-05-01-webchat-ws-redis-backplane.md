# WebChat WebSocket — Redis Backplane (Phase C) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Redis pub/sub backplane to the WebChat WebSocket notifier so activities published on any operator replica are delivered to WS clients connected to any other replica, while keeping single-replica deployments dependency-free.

**Architecture:** A new `RedisNotifier` wraps the existing `InMemoryNotifier` (composition). `publish()` always fires locally first, then mirrors to Redis. A background task subscribes once to a global channel `greentic:webchat:notify`, drops self-echoes via a per-process UUID, and dispatches received events into the wrapped in-memory broadcast. URL is auto-detected from the `state-redis` provider's existing `ConfigEnvelope`. Strict at boot (refuse to start if Redis unreachable), soft at runtime (degrade to local-only on disconnect, reconnect with backoff).

**Tech Stack:**
- Rust 1.95.0, edition 2024 (pinned via `rust-toolchain.toml`)
- `redis = "0.27"` with `tokio-comp` + `connection-manager` features (NEW dep)
- `uuid = { version = "1", features = ["v4"] }` (NEW dep)
- Existing: `tokio`, `serde`, `serde_json`, `serde_yaml_gtc` (imported as `serde_yaml_bw`), `anyhow`, `tracing`, `dashmap`, `async-trait`, `futures-util`
- Tests: `cargo test` for units; integration tests gated behind `GREENTIC_TEST_REDIS_URL` env var (skip silently if unset)

**Spec:** `docs/superpowers/specs/2026-05-01-webchat-ws-redis-backplane-design.md`

**Branch:** `feat/webchat-ws-redis-backplane` (already created off `origin/develop`)

**Repo conventions to follow throughout:**
- `bash ci/local_check.sh` before declaring any task done that touches Rust code (skill says frequent commits — `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all-features`).
- `serde_yaml_gtc` (imported as `serde_yaml_bw`), NOT `serde_yaml`.
- `anyhow::Result<T>` with `.context()` for errors.
- Conventional commits (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`).
- **No Claude co-author trailer** on commits (per `greentic-start/CLAUDE.md` git conventions).
- English only in code, comments, tests, commit messages.
- Pre-commit hook (`.githooks/pre-commit` if `git config core.hooksPath .githooks` is set) runs rustfmt + clippy — do not bypass with `--no-verify`.

---

## File Structure (locked at planning time)

| Path | Action | Responsibility |
|---|---|---|
| `Cargo.toml` | Modify | Add `redis` and `uuid` dependencies |
| `src/notifier/mod.rs` | Modify | Extend `NotifierConfig` enum with `Redis` variant + `serde::Deserialize`; change `build_notifier` to `async fn -> anyhow::Result<Arc<dyn ActivityNotifier>>` |
| `src/notifier/memory.rs` | No change | Stays as-is — `RedisNotifier` composes it |
| `src/notifier/redis.rs` | Create | `RedisNotifier` struct, `Wire` payload type, `process_incoming` dispatch fn (extracted for unit testing), background SUB task with backoff state machine, publish path |
| `src/notifier/config.rs` | Create | `resolve_notifier_config()` — auto-detect Redis URL from state-redis ConfigEnvelope, resolve secret URIs |
| `src/provider_config_envelope.rs` | Modify | Add `read_provider_config_envelope(root, provider_id) -> anyhow::Result<ConfigEnvelope>` (sibling to existing `write_provider_config_envelope`) |
| `src/config.rs` | Modify | Add `webchat: Option<WebchatConfig>` field to `OperatorConfig`; add `WebchatConfig { notifier: NotifierConfig }` struct |
| `src/http_ingress/mod.rs` | Modify | Update 4 call sites of `build_notifier()` (lines 178, 1619, 1974, 2057 on develop HEAD — re-grep at execution time) to `await` the now-async fn; replace `NotifierConfig::default()` with `resolve_notifier_config(...)` at the production call site (line 178) |
| `tests/notifier_redis.rs` | Create | Integration tests gated behind `GREENTIC_TEST_REDIS_URL` |
| `ci/local_check.sh` | Modify | Append conditional integration test invocation when env var is set |
| `docs/coding-agents.md` (or sibling) | Modify | Operator-facing note describing the new YAML section + auto-detect behavior |

**Cross-repo (separate PR in `greentic-setup`):**

| Path | Action | Responsibility |
|---|---|---|
| `greentic-setup/i18n/en.json` (or repo equivalent) | Modify | Add prompt + skip-message strings |
| `greentic-setup/src/cli_helpers/prompts.rs` (or operator-setup section) | Modify | Single Y/N prompt conditional on state-redis being configured |
| `greentic-setup/src/...` (operator yaml writer) | Modify | Patch `webchat.notifier.backend: redis` into `greentic.yaml` when prompt accepted |

The cross-repo work is sequenced last so the `greentic-start` PR can land + be tested first.

---

## Phase A — Pure unit-testable surface (no Redis dep yet)

### Task 1: Stub the new submodule + Wire payload type with JSON roundtrip test

**Files:**
- Create: `src/notifier/redis.rs`
- Modify: `src/notifier/mod.rs`

- [ ] **Step 1: Create `src/notifier/redis.rs` with the failing test**

```rust
//! Redis pub/sub backplane for the WebChat WS notifier.
//!
//! See docs/superpowers/specs/2026-05-01-webchat-ws-redis-backplane-design.md.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Wire payload exchanged over the global pub/sub channel.
///
/// `instance_id` is the per-process UUID used for self-echo suppression.
/// `version` allows future forward-compatible payload changes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Wire {
    pub tenant_id: String,
    pub conversation_id: String,
    pub new_watermark: u64,
    pub version: u8,
    pub instance_id: Uuid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_payload_roundtrip() {
        let original = Wire {
            tenant_id: "tenant-a".into(),
            conversation_id: "conv-1".into(),
            new_watermark: 42,
            version: 1,
            instance_id: Uuid::new_v4(),
        };
        let bytes = serde_json::to_vec(&original).expect("encode");
        let decoded: Wire = serde_json::from_slice(&bytes).expect("decode");
        assert_eq!(original, decoded);
    }
}
```

- [ ] **Step 2: Wire the new module into `src/notifier/mod.rs`**

In `src/notifier/mod.rs`, find the existing `pub mod memory;` line and add directly after:

```rust
pub mod redis;
```

- [ ] **Step 3: Add `uuid` dependency to `Cargo.toml`**

In `Cargo.toml` `[dependencies]` section (alphabetically sorted region), add:

```toml
uuid = { version = "1", features = ["v4", "serde"] }
```

- [ ] **Step 4: Run the test, expect FAIL (uuid not yet pulled / dep resolution)**

Run: `cargo test -p greentic-start --lib notifier::redis::tests::wire_payload_roundtrip -- --nocapture`

Expected: PASS once `cargo` resolves the new dep. If it fails for any other reason, fix before continuing.

- [ ] **Step 5: Run fmt + clippy**

Run:
```
cargo fmt -p greentic-start -- --check
cargo clippy -p greentic-start --all-targets --all-features -- -D warnings
```
Expected: both clean.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/notifier/mod.rs src/notifier/redis.rs
git commit -m "feat(notifier): add Wire payload type for Redis backplane"
```

---

### Task 2: Extract `process_incoming` dispatch fn with loop suppression + version checks

**Files:**
- Modify: `src/notifier/redis.rs`

This is pure dispatch logic — testable without any Redis or async runtime concern.

- [ ] **Step 1: Add the failing tests to `src/notifier/redis.rs`** (under the existing `mod tests` block)

```rust
    use crate::notifier::{ActivityNotifier, NotifierError, NotifyEvent, EventStream};
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// Test double that records every publish call.
    struct RecordingNotifier {
        published: Mutex<Vec<NotifyEvent>>,
    }

    impl RecordingNotifier {
        fn new() -> Self {
            Self { published: Mutex::new(vec![]) }
        }
        fn count(&self) -> usize {
            self.published.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl ActivityNotifier for RecordingNotifier {
        async fn publish(&self, event: NotifyEvent) {
            self.published.lock().unwrap().push(event);
        }
        async fn subscribe(
            &self,
            _tenant: &str,
            _conv: &str,
        ) -> Result<EventStream, NotifierError> {
            unreachable!("not used in dispatch tests")
        }
    }

    fn make_payload(instance_id: Uuid, version: u8) -> Vec<u8> {
        serde_json::to_vec(&Wire {
            tenant_id: "t".into(),
            conversation_id: "c".into(),
            new_watermark: 7,
            version,
            instance_id,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn loop_suppression_drops_self_publish() {
        let inner = RecordingNotifier::new();
        let self_id = Uuid::new_v4();
        let payload = make_payload(self_id, 1);
        process_incoming(&payload, self_id, &inner).await;
        assert_eq!(inner.count(), 0, "self-echo must be dropped");
    }

    #[tokio::test]
    async fn loop_suppression_accepts_other_replica() {
        let inner = RecordingNotifier::new();
        let self_id = Uuid::new_v4();
        let other = Uuid::new_v4();
        let payload = make_payload(other, 1);
        process_incoming(&payload, self_id, &inner).await;
        assert_eq!(inner.count(), 1);
    }

    #[tokio::test]
    async fn dispatch_drops_unknown_version() {
        let inner = RecordingNotifier::new();
        let self_id = Uuid::new_v4();
        let other = Uuid::new_v4();
        let payload = make_payload(other, 99);
        process_incoming(&payload, self_id, &inner).await;
        assert_eq!(inner.count(), 0);
    }

    #[tokio::test]
    async fn dispatch_drops_malformed_payload() {
        let inner = RecordingNotifier::new();
        let self_id = Uuid::new_v4();
        process_incoming(b"not-json{{", self_id, &inner).await;
        assert_eq!(inner.count(), 0);
    }
```

- [ ] **Step 2: Run tests, expect FAIL with "process_incoming not found"**

Run: `cargo test -p greentic-start --lib notifier::redis -- --nocapture`

Expected: compile error referencing `process_incoming`.

- [ ] **Step 3: Implement `process_incoming` in `src/notifier/redis.rs`**

Add directly under the `Wire` struct definition:

```rust
use crate::notifier::{ActivityNotifier, NotifyEvent};

/// Decode a payload received over the Redis SUB stream and dispatch it
/// to the inner notifier, dropping self-echoes and unknown versions.
///
/// Extracted as a free function so unit tests can exercise it without
/// spinning up a Redis connection.
pub(crate) async fn process_incoming(
    payload: &[u8],
    self_id: Uuid,
    inner: &dyn ActivityNotifier,
) {
    let wire: Wire = match serde_json::from_slice(payload) {
        Ok(w) => w,
        Err(err) => {
            tracing::debug!(target: "notifier_redis", ?err, "redis_decode_err");
            return;
        }
    };
    if wire.instance_id == self_id {
        return; // self-echo
    }
    if wire.version != 1 {
        tracing::warn!(
            target: "notifier_redis",
            version = wire.version,
            "redis_unknown_version"
        );
        return;
    }
    inner
        .publish(NotifyEvent {
            tenant_id: wire.tenant_id,
            conversation_id: wire.conversation_id,
            new_watermark: wire.new_watermark,
        })
        .await;
}
```

- [ ] **Step 4: Run tests, expect PASS**

Run: `cargo test -p greentic-start --lib notifier::redis -- --nocapture`

Expected: 5 tests pass (1 from Task 1 + 4 new).

- [ ] **Step 5: Run fmt + clippy**

```
cargo fmt -p greentic-start -- --check
cargo clippy -p greentic-start --all-targets --all-features -- -D warnings
```

- [ ] **Step 6: Commit**

```bash
git add src/notifier/redis.rs
git commit -m "feat(notifier): add process_incoming dispatch with loop suppression"
```

---

### Task 3: `NotifierConfig::Redis` variant with serde Deserialize

**Files:**
- Modify: `src/notifier/mod.rs`

The current enum has no serde derive (it was constructed directly in code). We add `Deserialize` so it can come from `greentic.yaml`, and add the `Redis` variant.

- [ ] **Step 1: Add the failing tests to `src/notifier/mod.rs`** (under the existing `mod build_tests` or in a sibling `mod config_tests`)

```rust
#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn notifier_config_serde_default_yaml_empty() {
        // Empty YAML map should default to Memory { capacity: 64 }.
        let cfg: NotifierConfig = serde_yaml_bw::from_str("backend: memory").expect("parse");
        match cfg {
            NotifierConfig::Memory { capacity } => assert_eq!(capacity, 64),
            _ => panic!("expected Memory variant"),
        }
    }

    #[test]
    fn notifier_config_serde_redis_minimal() {
        let yaml = "backend: redis";
        let cfg: NotifierConfig = serde_yaml_bw::from_str(yaml).expect("parse");
        match cfg {
            NotifierConfig::Redis { url, channel, capacity } => {
                assert!(url.is_none());
                assert!(channel.is_none());
                assert_eq!(capacity, 64);
            }
            _ => panic!("expected Redis variant"),
        }
    }

    #[test]
    fn notifier_config_serde_redis_full() {
        let yaml = "\
backend: redis
url: redis://localhost:6379
channel: greentic:webchat:notify
capacity: 128
";
        let cfg: NotifierConfig = serde_yaml_bw::from_str(yaml).expect("parse");
        match cfg {
            NotifierConfig::Redis { url, channel, capacity } => {
                assert_eq!(url.as_deref(), Some("redis://localhost:6379"));
                assert_eq!(channel.as_deref(), Some("greentic:webchat:notify"));
                assert_eq!(capacity, 128);
            }
            _ => panic!("expected Redis variant"),
        }
    }
}
```

- [ ] **Step 2: Run tests, expect FAIL with "Redis variant not found" / "Deserialize not implemented"**

Run: `cargo test -p greentic-start --lib notifier::config_tests -- --nocapture`

Expected: compile errors.

- [ ] **Step 3: Replace the `NotifierConfig` enum in `src/notifier/mod.rs`**

Find:
```rust
/// Backend selector for `build_notifier`.
#[derive(Debug, Clone)]
pub enum NotifierConfig {
    Memory { capacity: usize },
}

impl Default for NotifierConfig {
    fn default() -> Self {
        NotifierConfig::Memory { capacity: 64 }
    }
}
```

Replace with:
```rust
/// Backend selector for `build_notifier`.
///
/// Deserialized from the `webchat.notifier` section of `greentic.yaml`.
/// Absent or unset → defaults to `Memory { capacity: 64 }`.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "backend", rename_all = "lowercase")]
pub enum NotifierConfig {
    Memory {
        #[serde(default = "default_capacity")]
        capacity: usize,
    },
    Redis {
        /// Optional explicit URL. If `None`, resolved from the state-redis
        /// provider's `ConfigEnvelope` at boot time.
        #[serde(default)]
        url: Option<String>,
        /// Channel name override. Default: `greentic:webchat:notify`.
        #[serde(default)]
        channel: Option<String>,
        /// Local in-memory broadcast capacity (forwarded to the inner
        /// `InMemoryNotifier`).
        #[serde(default = "default_capacity")]
        capacity: usize,
    },
}

fn default_capacity() -> usize {
    64
}

impl Default for NotifierConfig {
    fn default() -> Self {
        NotifierConfig::Memory { capacity: 64 }
    }
}
```

- [ ] **Step 4: Run tests, expect PASS**

Run: `cargo test -p greentic-start --lib notifier::config_tests -- --nocapture`

Expected: 3 tests pass.

- [ ] **Step 5: Confirm existing `notifier::build_tests` still passes**

Run: `cargo test -p greentic-start --lib notifier:: -- --nocapture`

Expected: existing `build_default_returns_memory_backend` still PASSES.

- [ ] **Step 6: Run fmt + clippy**

- [ ] **Step 7: Commit**

```bash
git add src/notifier/mod.rs
git commit -m "feat(notifier): add Redis variant to NotifierConfig"
```

---

### Task 4: `WebchatConfig` field on `OperatorConfig`

**Files:**
- Modify: `src/config.rs`

- [ ] **Step 1: Find the `OperatorConfig` struct in `src/config.rs`** and read its current shape (already known from spec; re-confirm with a quick `grep`).

Run: `grep -n "pub struct OperatorConfig" src/config.rs`

Expected location: line 9-15 area.

- [ ] **Step 2: Add the failing test in `src/config.rs`** (in the existing `#[cfg(test)] mod tests` block, or create one if absent)

```rust
#[cfg(test)]
mod webchat_config_tests {
    use super::*;

    #[test]
    fn operator_config_parses_webchat_notifier_redis() {
        let yaml = "\
binaries:
  some_binary: /usr/bin/foo
webchat:
  notifier:
    backend: redis
";
        let cfg: OperatorConfig = serde_yaml_bw::from_str(yaml).expect("parse");
        let webchat = cfg.webchat.expect("webchat section present");
        match webchat.notifier {
            crate::notifier::NotifierConfig::Redis { url, .. } => assert!(url.is_none()),
            _ => panic!("expected Redis notifier"),
        }
    }

    #[test]
    fn operator_config_webchat_absent_is_none() {
        let yaml = "binaries: {}\n";
        let cfg: OperatorConfig = serde_yaml_bw::from_str(yaml).expect("parse");
        assert!(cfg.webchat.is_none());
    }
}
```

- [ ] **Step 3: Run tests, expect FAIL**

Run: `cargo test -p greentic-start --lib config::webchat_config_tests -- --nocapture`

Expected: compile errors ("no field `webchat`").

- [ ] **Step 4: Modify `OperatorConfig` in `src/config.rs`**

Find:
```rust
#[derive(Clone, Debug, Deserialize, Default)]
pub struct OperatorConfig {
    #[serde(default)]
    pub services: Option<OperatorServicesConfig>,
    #[serde(default)]
    pub binaries: BTreeMap<String, String>,
}
```

Replace with:
```rust
#[derive(Clone, Debug, Deserialize, Default)]
pub struct OperatorConfig {
    #[serde(default)]
    pub services: Option<OperatorServicesConfig>,
    #[serde(default)]
    pub binaries: BTreeMap<String, String>,
    #[serde(default)]
    pub webchat: Option<WebchatConfig>,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct WebchatConfig {
    #[serde(default)]
    pub notifier: crate::notifier::NotifierConfig,
}
```

- [ ] **Step 5: Run tests, expect PASS**

Run: `cargo test -p greentic-start --lib config::webchat_config_tests -- --nocapture`

Expected: 2 tests pass.

- [ ] **Step 6: Run all crate tests to ensure no regression**

Run: `cargo test -p greentic-start --all-features`

Expected: all pass.

- [ ] **Step 7: Run fmt + clippy**

- [ ] **Step 8: Commit**

```bash
git add src/config.rs
git commit -m "feat(config): add webchat.notifier section to OperatorConfig"
```

---

### Task 5: `read_provider_config_envelope` helper

**Files:**
- Modify: `src/provider_config_envelope.rs`

Existing file already contains `write_provider_config_envelope` and `ConfigEnvelope`. Add the read sibling.

- [ ] **Step 1: Add the failing test to `src/provider_config_envelope.rs`** (under the existing `#[cfg(test)] mod tests`, or create one if absent)

```rust
#[cfg(test)]
mod read_envelope_tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn read_envelope_roundtrip() {
        let dir = tempdir().unwrap();
        let providers_root = dir.path().join("providers");
        std::fs::create_dir_all(&providers_root).unwrap();

        // Write a minimal envelope by hand using canonical CBOR.
        let envelope = ConfigEnvelope {
            config: json!({"url": "redis://example:6379"}),
            component_id: "state-redis".into(),
            abi_version: ABI_VERSION.to_string(),
            resolved_digest: "sha256:0".into(),
            describe_hash: "h".into(),
            schema_hash: None,
            operation_id: "configure".into(),
            updated_at: None,
        };
        let bytes = greentic_types::cbor::canonical::to_canonical_cbor(&envelope).unwrap();
        let path = providers_root.join("state-redis").join("config.envelope.cbor");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();

        let read = read_provider_config_envelope(&providers_root, "state-redis").expect("read");
        assert_eq!(read.config.get("url").and_then(|v| v.as_str()), Some("redis://example:6379"));
    }

    #[test]
    fn read_envelope_missing_provider_errors() {
        let dir = tempdir().unwrap();
        let providers_root = dir.path().join("providers");
        std::fs::create_dir_all(&providers_root).unwrap();
        let err = read_provider_config_envelope(&providers_root, "state-redis").unwrap_err();
        assert!(format!("{err:#}").contains("state-redis"));
    }
}
```

- [ ] **Step 2: Run tests, expect FAIL**

Run: `cargo test -p greentic-start --lib provider_config_envelope::read_envelope_tests -- --nocapture`

Expected: compile error "function not found: `read_provider_config_envelope`".

- [ ] **Step 3: First, confirm the on-disk path layout used by `write_provider_config_envelope`**

The plan assumes the envelope file is stored at `<providers_root>/<provider_id>/config.envelope.cbor`. The existing `write_provider_config_envelope` function writes the envelope CBOR — read its body to confirm this path shape and adjust both the new helper AND the test above to match. Run:

```
grep -n "providers_root\|envelope\|config.envelope.cbor" src/provider_config_envelope.rs | head -30
```

Use the actual path scheme (likely involves `atomic_write` from `runtime_state`). If the layout differs from `<root>/<id>/config.envelope.cbor`, update both the test and the helper consistently. **Do not invent a layout — match what `write_provider_config_envelope` produces.**

- [ ] **Step 4: Implement `read_provider_config_envelope`** in `src/provider_config_envelope.rs`, mirroring the write helper:

```rust
/// Read the `ConfigEnvelope` for a single provider, decoding from canonical CBOR.
pub fn read_provider_config_envelope(
    providers_root: &Path,
    provider_id: &str,
) -> anyhow::Result<ConfigEnvelope> {
    // ADJUST path construction to match write_provider_config_envelope's layout.
    let path = providers_root.join(provider_id).join("config.envelope.cbor");
    let mut file = File::open(&path)
        .with_context(|| format!("provider config envelope not found at {}", path.display()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let envelope: ConfigEnvelope = greentic_types::cbor::canonical::from_canonical_cbor(&bytes)
        .map_err(|err| anyhow!("decode envelope at {}: {err}", path.display()))?;
    Ok(envelope)
}
```

- [ ] **Step 5: Run tests, expect PASS**

Run: `cargo test -p greentic-start --lib provider_config_envelope::read_envelope_tests -- --nocapture`

Expected: 2 tests pass. If the path layout was wrong, the first failure will tell you immediately — fix and re-run.

- [ ] **Step 6: Run fmt + clippy**

- [ ] **Step 7: Commit**

```bash
git add src/provider_config_envelope.rs
git commit -m "feat(provider-config): add read_provider_config_envelope helper"
```

---

### Task 6: `resolve_notifier_config` with auto-detect

**Files:**
- Create: `src/notifier/config.rs`
- Modify: `src/notifier/mod.rs`

- [ ] **Step 1: Create `src/notifier/config.rs` with skeleton + failing tests**

```rust
//! Resolve a `NotifierConfig` for boot, including auto-detect of the
//! state-redis URL when `backend: redis` is selected without an explicit URL.

use std::path::Path;

use anyhow::{Context, Result, anyhow};

use crate::config::OperatorConfig;
use crate::notifier::NotifierConfig;
use crate::provider_config_envelope::{ConfigEnvelope, require_provider_config_envelope};

/// Resolve the effective notifier configuration.
///
/// - `Memory` and `Redis { url: Some(_) }` pass through unchanged.
/// - `Redis { url: None }` triggers auto-detect from the state-redis
///   provider's `ConfigEnvelope`, with secret URI resolution if the URL
///   field is a `secret://` reference.
pub async fn resolve_notifier_config(
    operator_root: &Path,
    operator_config: &OperatorConfig,
    secret_resolver: &dyn SecretResolver,
) -> Result<NotifierConfig> {
    let raw = operator_config
        .webchat
        .as_ref()
        .map(|w| w.notifier.clone())
        .unwrap_or_default();

    match raw {
        NotifierConfig::Memory { .. } => Ok(raw),
        NotifierConfig::Redis { url: Some(_), .. } => Ok(raw),
        NotifierConfig::Redis { url: None, channel, capacity } => {
            let providers_root = operator_root.join("providers");
            let envelope: ConfigEnvelope =
                require_provider_config_envelope(&providers_root, "state-redis").with_context(|| {
                    "Redis notifier backend selected but the state-redis provider is not \
                     configured. Run `gtc setup --provider state-redis` first, or set \
                     webchat.notifier.url explicitly in greentic.yaml."
                })?;
            let url_field = envelope
                .config
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    anyhow!("state-redis ConfigEnvelope missing required `url` field")
                })?;
            let resolved_url = secret_resolver
                .resolve(url_field)
                .await
                .context("failed to resolve state-redis url secret reference")?;
            Ok(NotifierConfig::Redis {
                url: Some(resolved_url),
                channel,
                capacity,
            })
        }
    }
}

/// Indirection so unit tests can inject a fake without depending on the full
/// secrets manager construction.
#[async_trait::async_trait]
pub trait SecretResolver: Send + Sync {
    /// If `raw` is a literal URL, return it as-is. If it's a `secret://` URI,
    /// resolve to the underlying value.
    async fn resolve(&self, raw: &str) -> Result<String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WebchatConfig;
    use crate::provider_config_envelope::ConfigEnvelope;
    use serde_json::json;
    use std::sync::Mutex;
    use tempfile::tempdir;

    struct FakeResolver {
        // Maps `secret://...` URIs to literal values; literal `redis://...`
        // is returned as-is.
        map: Mutex<std::collections::HashMap<String, String>>,
    }
    impl FakeResolver {
        fn new() -> Self {
            Self { map: Mutex::new(Default::default()) }
        }
        fn with(secret: &str, literal: &str) -> Self {
            let r = Self::new();
            r.map.lock().unwrap().insert(secret.into(), literal.into());
            r
        }
    }
    #[async_trait::async_trait]
    impl SecretResolver for FakeResolver {
        async fn resolve(&self, raw: &str) -> Result<String> {
            if raw.starts_with("secret://") {
                self.map
                    .lock()
                    .unwrap()
                    .get(raw)
                    .cloned()
                    .ok_or_else(|| anyhow!("no fake mapping for {raw}"))
            } else {
                Ok(raw.to_string())
            }
        }
    }

    fn op_with_redis(url: Option<&str>) -> OperatorConfig {
        OperatorConfig {
            webchat: Some(WebchatConfig {
                notifier: NotifierConfig::Redis {
                    url: url.map(String::from),
                    channel: None,
                    capacity: 64,
                },
            }),
            ..Default::default()
        }
    }

    fn write_state_redis_envelope(operator_root: &std::path::Path, url_field: &str) {
        let providers_root = operator_root.join("providers");
        let path = providers_root.join("state-redis").join("config.envelope.cbor");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let env = ConfigEnvelope {
            config: json!({"url": url_field}),
            component_id: "state-redis".into(),
            abi_version: crate::provider_config_envelope::ABI_VERSION.to_string(),
            resolved_digest: "sha256:0".into(),
            describe_hash: "h".into(),
            schema_hash: None,
            operation_id: "configure".into(),
            updated_at: None,
        };
        let bytes = greentic_types::cbor::canonical::to_canonical_cbor(&env).unwrap();
        std::fs::write(&path, bytes).unwrap();
    }

    #[tokio::test]
    async fn explicit_url_skips_autodetect() {
        let dir = tempdir().unwrap();
        // Note: no envelope written — auto-detect would fail if it ran.
        let op = op_with_redis(Some("redis://override:1"));
        let resolved =
            resolve_notifier_config(dir.path(), &op, &FakeResolver::new()).await.unwrap();
        match resolved {
            NotifierConfig::Redis { url, .. } => assert_eq!(url.as_deref(), Some("redis://override:1")),
            _ => panic!("expected Redis variant"),
        }
    }

    #[tokio::test]
    async fn autodetect_missing_state_redis_errors() {
        let dir = tempdir().unwrap();
        let op = op_with_redis(None);
        let err = resolve_notifier_config(dir.path(), &op, &FakeResolver::new())
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("state-redis"), "error must mention state-redis: {msg}");
    }

    #[tokio::test]
    async fn autodetect_uses_literal_url_from_envelope() {
        let dir = tempdir().unwrap();
        write_state_redis_envelope(dir.path(), "redis://envelope:6379");
        let op = op_with_redis(None);
        let resolved =
            resolve_notifier_config(dir.path(), &op, &FakeResolver::new()).await.unwrap();
        match resolved {
            NotifierConfig::Redis { url, .. } => {
                assert_eq!(url.as_deref(), Some("redis://envelope:6379"))
            }
            _ => panic!("expected Redis variant"),
        }
    }

    #[tokio::test]
    async fn autodetect_resolves_secret_uri() {
        let dir = tempdir().unwrap();
        write_state_redis_envelope(dir.path(), "secret://state-redis/url");
        let op = op_with_redis(None);
        let resolver =
            FakeResolver::with("secret://state-redis/url", "redis://resolved:6379");
        let resolved = resolve_notifier_config(dir.path(), &op, &resolver).await.unwrap();
        match resolved {
            NotifierConfig::Redis { url, .. } => {
                assert_eq!(url.as_deref(), Some("redis://resolved:6379"))
            }
            _ => panic!("expected Redis variant"),
        }
    }

    #[tokio::test]
    async fn memory_backend_passes_through() {
        let dir = tempdir().unwrap();
        let op = OperatorConfig::default();
        let resolved =
            resolve_notifier_config(dir.path(), &op, &FakeResolver::new()).await.unwrap();
        assert!(matches!(resolved, NotifierConfig::Memory { .. }));
    }
}
```

- [ ] **Step 2: Wire the new module in `src/notifier/mod.rs`**

Add after the existing `pub mod redis;` line:

```rust
pub mod config;
```

- [ ] **Step 3: Make `ABI_VERSION` accessible to tests**

`ABI_VERSION` in `src/provider_config_envelope.rs` is currently `const ABI_VERSION: &str = ...`. The test above references it as `crate::provider_config_envelope::ABI_VERSION`. Promote it to `pub(crate) const ABI_VERSION: &str = ...` if not already.

Run: `grep -n "ABI_VERSION" src/provider_config_envelope.rs`

Expected: confirm visibility. If private, change to `pub(crate)`.

- [ ] **Step 4: Run tests, expect PASS**

Run: `cargo test -p greentic-start --lib notifier::config -- --nocapture`

Expected: 5 tests pass.

- [ ] **Step 5: Run fmt + clippy**

- [ ] **Step 6: Commit**

```bash
git add src/notifier/mod.rs src/notifier/config.rs src/provider_config_envelope.rs
git commit -m "feat(notifier): add resolve_notifier_config with state-redis auto-detect"
```

---

## Phase B — Async signature change + InMemoryNotifier-only build_notifier

### Task 7: Change `build_notifier` to `async fn -> anyhow::Result<...>` (still Memory-only)

Goal: ripple the signature change through the 4 existing call sites without yet introducing the Redis branch. This isolates the refactor risk.

**Files:**
- Modify: `src/notifier/mod.rs`
- Modify: `src/http_ingress/mod.rs` (4 call sites)

- [ ] **Step 1: Re-grep call sites at HEAD to confirm current line numbers**

Run: `git grep -n "build_notifier" -- 'src/**/*.rs'`

Expected: 4 hits in `src/http_ingress/mod.rs` plus one definition in `src/notifier/mod.rs` plus one test in `src/notifier/mod.rs`.

- [ ] **Step 2: Update `build_notifier` signature in `src/notifier/mod.rs`**

Find:
```rust
pub fn build_notifier(config: NotifierConfig) -> std::sync::Arc<dyn ActivityNotifier> {
    match config {
        NotifierConfig::Memory { capacity } => std::sync::Arc::new(InMemoryNotifier::new(capacity)),
    }
}
```

Replace with:
```rust
pub async fn build_notifier(
    config: NotifierConfig,
) -> anyhow::Result<std::sync::Arc<dyn ActivityNotifier>> {
    match config {
        NotifierConfig::Memory { capacity } => {
            Ok(std::sync::Arc::new(InMemoryNotifier::new(capacity)))
        }
        NotifierConfig::Redis { .. } => {
            anyhow::bail!(
                "Redis notifier backend not yet implemented in this build (Phase C in progress)"
            )
        }
    }
}
```

- [ ] **Step 3: Update the existing `build_default_returns_memory_backend` test**

Find the test in `src/notifier/mod.rs` and change the call to `build_notifier(...).await.expect("build")`. Verify it still passes.

- [ ] **Step 4: Update each of the 4 call sites in `src/http_ingress/mod.rs`**

For each call site `crate::notifier::build_notifier(crate::notifier::NotifierConfig::default())` change to `crate::notifier::build_notifier(crate::notifier::NotifierConfig::default()).await?`.

The enclosing functions are `async`-context (they construct `HttpIngressState` inside what is generally an async setup path). Verify each enclosing fn signature returns `anyhow::Result<_>` and is `async`. If a particular call site is in a sync context (initialization), use `tokio::task::block_in_place(|| Handle::current().block_on(...))` only as a last resort — prefer making the enclosing fn `async` if that ripple is shallow.

If a call site is in tests where `await` isn't ergonomic, wrap in a small `tokio_test::block_on(...)` or use `#[tokio::test]`.

For each modification:
1. Read the surrounding 30 lines.
2. Decide async vs block_on per the rule above.
3. Apply.
4. Re-run `cargo check -p greentic-start --all-features`.

- [ ] **Step 5: Run all crate tests + clippy**

Run:
```
cargo test -p greentic-start --all-features
cargo clippy -p greentic-start --all-targets --all-features -- -D warnings
cargo fmt -p greentic-start -- --check
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/notifier/mod.rs src/http_ingress/mod.rs
git commit -m "refactor(notifier): make build_notifier async + Result"
```

---

### Task 8: Wire `resolve_notifier_config` into the production boot path

Goal: at the production call site (the one that builds `HttpIngressState` for the running operator, NOT the test-fixture call sites), replace `NotifierConfig::default()` with `resolve_notifier_config(operator_root, &operator_config, &secret_resolver).await?`.

**Files:**
- Modify: `src/http_ingress/mod.rs` (1 call site — the production one, currently line 178)
- Modify: wherever the production call site's caller already has access to `operator_root` + `OperatorConfig` + a secrets manager handle. Likely `src/lib.rs` or `src/runtime.rs`.

- [ ] **Step 1: Identify the production call site**

The 4 call sites of `build_notifier` are:
- Line 178: production (in the main HTTP ingress construction path)
- Line 1619, 1974, 2057: test fixtures (do NOT change these — they should keep `NotifierConfig::default()`)

Read 60 lines around line 178 to confirm what context (operator_root, operator_config, secrets handle) is in scope.

- [ ] **Step 2: Confirm the `DynSecretsManager` trait surface exposes a string-getter for secret URIs**

Run:
```
grep -n "trait SecretsManager\|fn get_text\|fn get_string\|fn get\b" \
    /home/bima-pangestu/Works/greentic/greentic-secrets/greentic-secrets-core/src/embedded.rs \
    /home/bima-pangestu/Works/greentic/greentic-secrets/greentic-secrets-core/src/lib.rs \
    /home/bima-pangestu/Works/greentic/greentic-start/src/secrets_gate.rs | head -30
```

The expected method (from planning-time recon) is `Secrets::get_text(uri: &str) -> Result<String, SecretsError>` on `greentic_secrets_lib::core::embedded::Secrets` (line 423 in `embedded.rs`). The `DynSecretsManager` exposed by `secrets_gate.rs` is `Arc<dyn SecretsManager>` — the trait surface MUST include a string-getter.

If the trait method name differs (`get_string`, `fetch_secret`, etc.), substitute it in Step 3 below. **Do not introduce a new trait method**: if no fitting method exists, write the resolution as a small private function in `src/notifier/config.rs` that calls `manager.get(uri).await` (returns bytes) and `String::from_utf8` over the result.

- [ ] **Step 3: Implement the `SecretsManagerResolver` adapter** in `src/notifier/config.rs`:

```rust
use crate::secrets_gate::DynSecretsManager;

/// Production adapter that wraps `DynSecretsManager` so the notifier
/// auto-detect path can resolve `secret://` URIs without requiring callers
/// to know the full secrets-manager surface.
pub struct SecretsManagerResolver {
    pub manager: DynSecretsManager,
}

#[async_trait::async_trait]
impl SecretResolver for SecretsManagerResolver {
    async fn resolve(&self, raw: &str) -> Result<String> {
        if !raw.starts_with("secret://") {
            return Ok(raw.to_string());
        }
        // PRIMARY: if SecretsManager exposes get_text(uri), use it directly.
        //   self.manager.get_text(raw).await
        //       .with_context(|| format!("resolve secret URI {raw}"))
        //
        // FALLBACK (use only if get_text isn't on the trait): fetch bytes
        // and decode as UTF-8.
        let bytes = self
            .manager
            .get(raw)
            .await
            .with_context(|| format!("resolve secret URI {raw}"))?;
        String::from_utf8(bytes)
            .with_context(|| format!("secret {raw} is not valid UTF-8"))
    }
}
```

Pick whichever branch matches the actual trait. Confirm with `cargo check -p greentic-start --all-features` before moving on.

- [ ] **Step 4: Update the production call site in `src/http_ingress/mod.rs:178`**

Pseudocode (adjust to actual surrounding context):

```rust
let resolver = crate::notifier::config::SecretsManagerResolver {
    manager: secrets_handle.manager(),
};
let notifier_cfg = crate::notifier::config::resolve_notifier_config(
    &operator_root,
    &operator_config,
    &resolver,
).await?;
let notifier = crate::notifier::build_notifier(notifier_cfg).await?;
```

- [ ] **Step 5: Run all crate tests + clippy**

Run: `bash ci/local_check.sh`

Expected: green. If `local_check.sh` fails on something outside this task's scope, document it in the commit message and continue.

- [ ] **Step 6: Commit**

```bash
git add src/notifier/config.rs src/http_ingress/mod.rs
git commit -m "feat(notifier): wire resolve_notifier_config into production boot"
```

---

## Phase C — RedisNotifier struct + connection lifecycle

### Task 9: Add `redis` dep and `RedisNotifier` skeleton

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/notifier/redis.rs`

- [ ] **Step 1: Add dependency to `Cargo.toml`** (alphabetical region in `[dependencies]`):

```toml
redis = { version = "0.27", features = ["tokio-comp", "connection-manager"] }
```

- [ ] **Step 2: Add a minimal `RedisNotifier` stub type** in `src/notifier/redis.rs` (above the `#[cfg(test)]` block)

The stub holds only what the type system needs. Real connection lifecycle lands in Task 10; integration tests against a live Redis land in Tasks 11–12. No new test in this task — the goal is "type compiles + dep added + crate builds".

```rust
use std::sync::Arc;

use crate::notifier::{
    ActivityNotifier, EventStream, InMemoryNotifier, NotifierError,
};

/// Redis pub/sub backplane wrapping an `InMemoryNotifier` for local fan-out.
///
/// `build` (added in Task 10) fails fast if Redis is unreachable. Once running,
/// publish-to-Redis is fire-and-forget and a background SUB task handles
/// reconnect with exponential backoff.
pub struct RedisNotifier {
    inner: Arc<InMemoryNotifier>,
    self_id: Uuid,
    channel: String,
    // pub_conn + background task fields land in Task 10.
}

#[async_trait::async_trait]
impl ActivityNotifier for RedisNotifier {
    async fn publish(&self, event: NotifyEvent) {
        // Real Redis mirror lands in Task 10. For now, local-only.
        self.inner.publish(event).await;
    }

    async fn subscribe(
        &self,
        tenant_id: &str,
        conversation_id: &str,
    ) -> Result<EventStream, NotifierError> {
        // No Redis call per subscribe — delegate to the in-memory broadcast.
        self.inner.subscribe(tenant_id, conversation_id).await
    }
}
```

- [ ] **Step 3: Run `cargo build` to verify dep + skeleton compile**

```
cargo build -p greentic-start --all-features
```

Expected: green.

- [ ] **Step 4: Run fmt + clippy**

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/notifier/redis.rs
git commit -m "feat(notifier): add redis dep and RedisNotifier skeleton"
```

---

### Task 10: `RedisNotifier::build` — open SUB and PUB connections, spawn background task

**Files:**
- Modify: `src/notifier/redis.rs`

This task adds the real connection wiring + the background SUB task. It is the most code-dense task in the plan.

- [ ] **Step 1: Add the connection state machine + background loop in `src/notifier/redis.rs`**

Define the state enum and the connection holder. Pseudocode (concrete code follows the same shape):

```rust
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use redis::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

const DEFAULT_CHANNEL: &str = "greentic:webchat:notify";

enum SubState {
    Connected,
    Reconnecting { attempt: u32 },
}

pub struct RedisNotifier {
    inner: Arc<InMemoryNotifier>,
    self_id: Uuid,
    channel: String,
    pub_conn: ConnectionManager,
    sub_state: Arc<RwLock<SubState>>,
    _sub_task: tokio::task::JoinHandle<()>,
}

impl RedisNotifier {
    pub async fn build(
        url: &str,
        channel: Option<String>,
        capacity: usize,
    ) -> anyhow::Result<Arc<Self>> {
        let channel = channel.unwrap_or_else(|| DEFAULT_CHANNEL.to_string());
        let inner = Arc::new(InMemoryNotifier::new(capacity));
        let self_id = Uuid::new_v4();

        let client = Client::open(url)
            .with_context(|| format!("invalid redis url: {url}"))?;

        // Open and ping the PUB connection (ConnectionManager auto-reconnects).
        let pub_conn = ConnectionManager::new(client.clone())
            .await
            .with_context(|| format!("failed to open redis PUB connection to {url}"))?;

        // Verify SUB connectivity once at boot (strict-startup) by opening +
        // immediately dropping a probe connection. The background loop opens
        // its own SUB on its first iteration.
        {
            let probe = subscribe_once(&client, &channel)
                .await
                .with_context(|| format!("failed to open redis SUB connection to {url}"))?;
            drop(probe);
        }

        let sub_state = Arc::new(RwLock::new(SubState::Connected));

        let notifier = Arc::new_cyclic(|weak: &std::sync::Weak<Self>| {
            let weak_clone = weak.clone();
            let inner_clone = inner.clone();
            let channel_clone = channel.clone();
            let sub_state_clone = sub_state.clone();
            let client_clone = client.clone();
            let self_id_copy = self_id;
            // Supervisor wrapper: catch panics inside the loop and restart.
            // Without this, a panic in `background_sub_loop` would silently
            // kill cross-replica delivery for the lifetime of the process.
            let task = tokio::spawn(async move {
                loop {
                    let inv = std::panic::AssertUnwindSafe(background_sub_loop(
                        weak_clone.clone(),
                        inner_clone.clone(),
                        self_id_copy,
                        client_clone.clone(),
                        channel_clone.clone(),
                        sub_state_clone.clone(),
                    ));
                    match futures_util::FutureExt::catch_unwind(inv).await {
                        Ok(()) => return, // clean exit (parent dropped)
                        Err(_panic) => {
                            tracing::error!(
                                target: "notifier_redis",
                                "background loop panicked; restarting after 500ms"
                            );
                            *sub_state_clone.write().await = SubState::Reconnecting { attempt: 0 };
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            if weak_clone.upgrade().is_none() {
                                return;
                            }
                        }
                    }
                }
            });
            Self {
                inner,
                self_id,
                channel,
                pub_conn,
                sub_state,
                _sub_task: task,
            }
        });

        Ok(notifier)
    }
}

async fn subscribe_once(
    client: &Client,
    channel: &str,
) -> anyhow::Result<redis::aio::PubSub> {
    let mut pubsub = client.get_async_pubsub().await?;
    pubsub.subscribe(channel).await?;
    Ok(pubsub)
}

async fn background_sub_loop(
    notifier_weak: std::sync::Weak<RedisNotifier>,
    inner: Arc<InMemoryNotifier>,
    self_id: Uuid,
    client: Client,
    channel: String,
    sub_state: Arc<RwLock<SubState>>,
) {
    use futures_util::StreamExt;
    loop {
        // 1. (Re)subscribe with bounded backoff. On the first iteration this
        //    opens the long-lived SUB; on later iterations it recovers from
        //    a disconnect.
        let mut sub = loop {
            if notifier_weak.upgrade().is_none() {
                return; // parent dropped
            }
            match subscribe_once(&client, &channel).await {
                Ok(s) => {
                    *sub_state.write().await = SubState::Connected;
                    tracing::info!(target: "notifier_redis", "redis_reconnect_ok");
                    break s;
                }
                Err(err) => {
                    let attempt = match *sub_state.read().await {
                        SubState::Reconnecting { attempt } => attempt,
                        SubState::Connected => 0,
                    };
                    tracing::debug!(
                        target: "notifier_redis",
                        ?err,
                        attempt,
                        "redis_reconnect_fail"
                    );
                    *sub_state.write().await = SubState::Reconnecting { attempt: attempt + 1 };
                    tokio::time::sleep(backoff_with_jitter(attempt)).await;
                }
            }
        };

        // 2. Drain messages until the connection ends.
        while let Some(msg) = sub.on_message().next().await {
            let payload: Vec<u8> = msg.get_payload().unwrap_or_default();
            process_incoming(&payload, self_id, inner.as_ref()).await;
        }

        // 3. Stream ended = disconnect; go back to the (re)subscribe arm.
        *sub_state.write().await = SubState::Reconnecting { attempt: 0 };
        tracing::warn!(target: "notifier_redis", "redis_disconnected");
    }
}

fn backoff_with_jitter(attempt: u32) -> Duration {
    use rand::Rng;
    let base_ms: u64 = match attempt {
        0 => 100,
        1 => 250,
        2 => 500,
        3 => 1000,
        4 => 2000,
        _ => 5000,
    };
    let jitter = rand::thread_rng().gen_range(-20i64..=20i64) as f64 / 100.0;
    let ms = (base_ms as f64) * (1.0 + jitter);
    Duration::from_millis(ms.max(1.0) as u64)
}
```

- [ ] **Step 2: Implement `publish` to mirror to Redis**

Replace the temporary `publish` body with:

```rust
async fn publish(&self, event: NotifyEvent) {
    // Local first — never block on Redis health.
    self.inner.publish(event.clone()).await;

    // Mirror to Redis fire-and-forget.
    let payload = match serde_json::to_vec(&Wire {
        tenant_id: event.tenant_id,
        conversation_id: event.conversation_id,
        new_watermark: event.new_watermark,
        version: 1,
        instance_id: self.self_id,
    }) {
        Ok(p) => p,
        Err(err) => {
            tracing::warn!(target: "notifier_redis", ?err, "redis_encode_err");
            return;
        }
    };
    let mut pub_conn = self.pub_conn.clone();
    let channel = self.channel.clone();
    tokio::spawn(async move {
        if let Err(err) = pub_conn.publish::<_, _, ()>(&channel, payload).await {
            tracing::debug!(target: "notifier_redis", ?err, "redis_publish_dropped");
        }
    });
}
```

- [ ] **Step 3: Verify `NotifyEvent` derives `Clone`**

Run: `grep -n "struct NotifyEvent\|impl Clone for NotifyEvent" src/notifier/mod.rs`

If `Clone` isn't derived, add it. The existing struct already derives `Clone` (verified in spec); confirm.

- [ ] **Step 4: Update `build_notifier` in `src/notifier/mod.rs` to dispatch the Redis branch**

Find the `Redis` branch added in Task 7 (currently `bail!`) and replace with:

```rust
NotifierConfig::Redis { url, channel, capacity } => {
    let url = url.ok_or_else(|| {
        anyhow::anyhow!(
            "Redis notifier built without a URL — call resolve_notifier_config first"
        )
    })?;
    let notifier = crate::notifier::redis::RedisNotifier::build(&url, channel, capacity).await?;
    Ok(notifier as std::sync::Arc<dyn ActivityNotifier>)
}
```

- [ ] **Step 5: Add `rand` dep if not present**

Run: `grep -E "^rand\s*=" Cargo.toml`

`rand = "0.10"` is already in the dependencies (verified during planning). If absent, add `rand = "0.10"`.

- [ ] **Step 6: Run `cargo build` + clippy + lib tests**

```
cargo build -p greentic-start --all-features
cargo clippy -p greentic-start --all-targets --all-features -- -D warnings
cargo test -p greentic-start --lib notifier::redis -- --nocapture
```

Expected: build green; existing unit tests (Wire roundtrip, dispatch) still pass.

- [ ] **Step 7: Commit**

```bash
git add src/notifier/redis.rs src/notifier/mod.rs Cargo.toml Cargo.lock
git commit -m "feat(notifier): implement RedisNotifier connect, publish, reconnect"
```

---

## Phase D — Integration tests behind `GREENTIC_TEST_REDIS_URL`

### Task 11: Integration test scaffold + first three end-to-end tests

**Files:**
- Create: `tests/notifier_redis.rs`

- [ ] **Step 1: Create the file with the env-var skip helper + three first-pass tests**

```rust
//! Integration tests for the Redis notifier backplane.
//!
//! Gated behind GREENTIC_TEST_REDIS_URL — these tests are skipped (treated as
//! pass) when the env var is unset, so default `cargo test` doesn't require
//! a running Redis.
//!
//! Run locally:
//!   docker run --rm -p 6379:6379 redis
//!   GREENTIC_TEST_REDIS_URL=redis://127.0.0.1:6379 cargo test --test notifier_redis -- --nocapture

use std::sync::Arc;
use std::time::Duration;

use greentic_start::notifier::redis::RedisNotifier;
use greentic_start::notifier::{ActivityNotifier, NotifyEvent};

fn redis_url_or_skip() -> Option<String> {
    match std::env::var("GREENTIC_TEST_REDIS_URL") {
        Ok(url) if !url.is_empty() => Some(url),
        _ => {
            eprintln!("skipping: GREENTIC_TEST_REDIS_URL not set");
            None
        }
    }
}

fn unique_channel() -> String {
    format!("greentic:test:{}", uuid::Uuid::new_v4())
}

#[tokio::test]
async fn single_notifier_local_publish_works() {
    let Some(url) = redis_url_or_skip() else { return };
    let notifier = RedisNotifier::build(&url, Some(unique_channel()), 8).await.unwrap();
    let mut stream = notifier.subscribe("t", "c").await.unwrap();
    notifier
        .publish(NotifyEvent {
            tenant_id: "t".into(),
            conversation_id: "c".into(),
            new_watermark: 1,
        })
        .await;
    let evt = tokio::time::timeout(Duration::from_secs(1), futures_util::StreamExt::next(&mut stream))
        .await
        .expect("timeout")
        .expect("no event");
    assert_eq!(evt.new_watermark, 1);
}

#[tokio::test]
async fn two_notifiers_cross_replica_fanout() {
    let Some(url) = redis_url_or_skip() else { return };
    let channel = unique_channel();
    let a = RedisNotifier::build(&url, Some(channel.clone()), 8).await.unwrap();
    let b = RedisNotifier::build(&url, Some(channel.clone()), 8).await.unwrap();

    // Subscribe on B; publish on A.
    let mut stream_b = b.subscribe("t", "c").await.unwrap();

    // Allow SUB to register on Redis side before A publishes.
    tokio::time::sleep(Duration::from_millis(50)).await;

    a.publish(NotifyEvent {
        tenant_id: "t".into(),
        conversation_id: "c".into(),
        new_watermark: 7,
    })
    .await;

    let evt = tokio::time::timeout(Duration::from_secs(2), futures_util::StreamExt::next(&mut stream_b))
        .await
        .expect("timeout waiting for cross-replica fan-out")
        .expect("no event");
    assert_eq!(evt.new_watermark, 7);
}

#[tokio::test]
async fn loop_suppression_no_duplicate_on_self_publish() {
    let Some(url) = redis_url_or_skip() else { return };
    let channel = unique_channel();
    let a = RedisNotifier::build(&url, Some(channel), 8).await.unwrap();
    let mut stream = a.subscribe("t", "c").await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    a.publish(NotifyEvent {
        tenant_id: "t".into(),
        conversation_id: "c".into(),
        new_watermark: 1,
    })
    .await;

    // Should receive exactly one event (the local fan-out).
    let _first = tokio::time::timeout(Duration::from_secs(1), futures_util::StreamExt::next(&mut stream))
        .await
        .expect("timeout")
        .expect("missing first event");

    // No second event — Redis loop was suppressed by instance_id.
    let second = tokio::time::timeout(Duration::from_millis(300), futures_util::StreamExt::next(&mut stream)).await;
    assert!(second.is_err(), "expected timeout (no second event), got {second:?}");
}
```

- [ ] **Step 2: Verify `RedisNotifier` and other types are exposed via `pub use`** in the crate's public surface (crate root or lib.rs)

Run: `grep -n "pub mod notifier\|pub use notifier" src/lib.rs`

If `notifier::redis::RedisNotifier` isn't reachable from outside the crate (i.e., notifier module is not public), expose what the tests need. Minimum required:
- `pub mod notifier;` (likely already public)
- Inside `notifier/mod.rs`: `pub mod redis;` (added in Task 1)
- The `RedisNotifier` type is already `pub`.

If accessibility is a problem at test time, the alternative is to put these as inline tests in `src/notifier/redis.rs` behind `#[cfg(feature = "redis-integration-test")]`. Prefer the `tests/` integration approach.

- [ ] **Step 3: Run the integration tests against a local Redis**

Start Redis:
```
docker run --rm -d -p 6379:6379 --name greentic-test-redis redis:7
```

Run tests:
```
GREENTIC_TEST_REDIS_URL=redis://127.0.0.1:6379 cargo test -p greentic-start --test notifier_redis -- --nocapture
```

Expected: 3 tests pass.

Stop Redis:
```
docker stop greentic-test-redis
```

- [ ] **Step 4: Confirm tests skip when env var absent**

```
unset GREENTIC_TEST_REDIS_URL
cargo test -p greentic-start --test notifier_redis -- --nocapture
```

Expected: tests run but each prints "skipping" and exits PASS.

- [ ] **Step 5: Run fmt + clippy**

- [ ] **Step 6: Commit**

```bash
git add tests/notifier_redis.rs
git commit -m "test(notifier): add Redis integration tests gated by env var"
```

---

### Task 12: Reconnect, boot-fail, and yaml-end-to-end integration tests

**Files:**
- Modify: `tests/notifier_redis.rs`

- [ ] **Step 1: Append three more tests to `tests/notifier_redis.rs`**

```rust
#[tokio::test]
async fn boot_fails_when_redis_unreachable() {
    // Use a port that is overwhelmingly likely to be closed.
    let bogus = "redis://127.0.0.1:1";
    let result = RedisNotifier::build(bogus, Some(unique_channel()), 8).await;
    assert!(result.is_err(), "expected build to fail against unreachable redis");
}

#[tokio::test]
async fn subscribe_after_disconnect_recovers() {
    let Some(url) = redis_url_or_skip() else { return };
    let channel = unique_channel();
    let a = RedisNotifier::build(&url, Some(channel.clone()), 8).await.unwrap();
    let b = RedisNotifier::build(&url, Some(channel.clone()), 8).await.unwrap();

    let mut stream_b = b.subscribe("t", "c").await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Manual disconnect simulation: push a CLIENT KILL via a side connection
    // to force B's SUB connection to drop.
    let client = redis::Client::open(url.clone()).unwrap();
    let mut admin = client.get_multiplexed_async_connection().await.unwrap();
    let _: redis::Value = redis::cmd("CLIENT")
        .arg("KILL")
        .arg("TYPE")
        .arg("pubsub")
        .query_async(&mut admin)
        .await
        .unwrap();

    // Allow B's background loop to detect + reconnect.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Publish from A; B should receive after the reconnect.
    a.publish(NotifyEvent {
        tenant_id: "t".into(),
        conversation_id: "c".into(),
        new_watermark: 99,
    })
    .await;

    let evt = tokio::time::timeout(Duration::from_secs(3), futures_util::StreamExt::next(&mut stream_b))
        .await
        .expect("timeout after reconnect")
        .expect("no event after reconnect");
    assert_eq!(evt.new_watermark, 99);
}

#[tokio::test]
async fn notifier_config_yaml_end_to_end() {
    // No Redis required: this test exercises resolve_notifier_config only.
    // It writes a fake state-redis ConfigEnvelope under <root>/providers/state-redis/config.envelope.cbor
    // and asserts that resolve_notifier_config returns Redis with the literal URL.
    use greentic_start::config::OperatorConfig;
    use greentic_start::notifier::NotifierConfig;
    use greentic_start::notifier::config::{resolve_notifier_config, SecretResolver};
    use greentic_start::provider_config_envelope::{ConfigEnvelope, ABI_VERSION};
    use serde_json::json;

    struct PassthroughResolver;
    #[async_trait::async_trait]
    impl SecretResolver for PassthroughResolver {
        async fn resolve(&self, raw: &str) -> anyhow::Result<String> {
            Ok(raw.to_string())
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let providers_root = dir.path().join("providers");
    std::fs::create_dir_all(providers_root.join("state-redis")).unwrap();
    let env = ConfigEnvelope {
        config: json!({"url": "redis://envelope:6379"}),
        component_id: "state-redis".into(),
        abi_version: ABI_VERSION.to_string(),
        resolved_digest: "sha256:0".into(),
        describe_hash: "h".into(),
        schema_hash: None,
        operation_id: "configure".into(),
        updated_at: None,
    };
    let bytes = greentic_types::cbor::canonical::to_canonical_cbor(&env).unwrap();
    std::fs::write(providers_root.join("state-redis").join("config.envelope.cbor"), bytes).unwrap();

    let yaml = "\
webchat:
  notifier:
    backend: redis
";
    let op: OperatorConfig = serde_yaml_bw::from_str(yaml).unwrap();
    let resolved = resolve_notifier_config(dir.path(), &op, &PassthroughResolver).await.unwrap();
    match resolved {
        NotifierConfig::Redis { url, .. } => {
            assert_eq!(url.as_deref(), Some("redis://envelope:6379"))
        }
        _ => panic!("expected Redis variant"),
    }
}
```

- [ ] **Step 2: Run with Redis present**

```
docker run --rm -d -p 6379:6379 --name greentic-test-redis redis:7
GREENTIC_TEST_REDIS_URL=redis://127.0.0.1:6379 cargo test -p greentic-start --test notifier_redis -- --nocapture
docker stop greentic-test-redis
```

Expected: all 6 integration tests pass. The yaml test passes regardless of the env var (it doesn't need Redis).

- [ ] **Step 3: Run fmt + clippy**

- [ ] **Step 4: Commit**

```bash
git add tests/notifier_redis.rs
git commit -m "test(notifier): add reconnect, boot-fail, yaml-e2e integration tests"
```

---

### Task 13: Wire conditional integration tests into `ci/local_check.sh`

**Files:**
- Modify: `ci/local_check.sh`

- [ ] **Step 1: Read the current `ci/local_check.sh`** to find a sensible insertion point (after the existing `cargo test` block)

Run: `cat ci/local_check.sh`

- [ ] **Step 2: Append the conditional block** at the end of the test section (or after the last `cargo test` invocation):

```bash
# Optional: integration tests that need a real Redis. Skipped silently when
# GREENTIC_TEST_REDIS_URL is not set (the test fns themselves print "skipping").
if [ -n "$GREENTIC_TEST_REDIS_URL" ]; then
    echo "==> Running notifier Redis integration tests against $GREENTIC_TEST_REDIS_URL"
    cargo test -p greentic-start --test notifier_redis -- --nocapture
fi
```

- [ ] **Step 3: Run `bash ci/local_check.sh` (without env var) — verify still green**

Expected: existing checks pass; the new block is no-op since env var unset.

- [ ] **Step 4: Run `GREENTIC_TEST_REDIS_URL=redis://127.0.0.1:6379 bash ci/local_check.sh`** with a local Redis container running

Expected: also green.

- [ ] **Step 5: Commit**

```bash
git add ci/local_check.sh
git commit -m "ci: run notifier Redis integration tests when GREENTIC_TEST_REDIS_URL set"
```

---

## Phase E — Operator-facing docs

### Task 14: Document the new YAML section + auto-detect behavior

**Files:**
- Modify: `docs/coding-agents.md` (or add a new file under `docs/` if `coding-agents.md` is overcrowded — confirm during execution)

- [ ] **Step 1: Read existing `docs/coding-agents.md` to find the right insertion point**

Run: `grep -n -E "^##? " docs/coding-agents.md | head -30`

Look for an existing section about HTTP ingress / WebSocket / configuration. If none fits, add a new top-level section.

- [ ] **Step 2: Add a section** along the lines of:

```markdown
## WebChat WebSocket Notifier

The WebChat DirectLine WebSocket endpoint (`/v3/directline/conversations/{id}/stream`)
delivers activities to connected clients through a notifier. Two backends are
supported, selected via the optional `webchat.notifier` section in
`greentic.yaml`:

```yaml
webchat:
  notifier:
    backend: redis    # "memory" (default) | "redis"
    # url: redis://...           # optional override; defaults to state-redis URL
    # channel: greentic:webchat:notify  # optional override
    # capacity: 64               # optional (local broadcast channel size)
```

**Memory** — process-local broadcast. No external dependency. Suitable for
single-replica deployments and local development. This is the default when
`webchat` is absent.

**Redis** — pub/sub backplane that fans activities out across operator
replicas. URL is auto-detected from the `state-redis` provider's
`ConfigEnvelope` (run `gtc setup --provider state-redis` first to configure
the shared Redis URL). An explicit `url` field overrides auto-detect.

Failure modes:
- Redis configured but unreachable at boot → `gtc start` exits with a clear
  error.
- Redis disconnects after boot → same-replica sessions keep working;
  cross-replica fan-out resumes on reconnect (exponential backoff to 5 s).
- `state-redis` not configured + `backend: redis` selected → boot error
  pointing at the `state-redis` setup command.
```

- [ ] **Step 3: Commit**

```bash
git add docs/coding-agents.md
git commit -m "docs: document webchat.notifier YAML section and Redis backplane"
```

---

## Phase F — Cross-repo wizard (separate PR in `greentic-setup`)

These tasks are sequenced last so that the `greentic-start` PR can ship + be tested independently. Operators that edit `greentic.yaml` by hand can already use Phase C without the wizard.

### Task 15: i18n source-catalog entries for the wizard prompt (greentic-setup)

**Files (in `greentic-setup` repo):**
- Modify: `greentic-setup/i18n/en.json` (or the equivalent source catalog — confirm path)

- [ ] **Step 1: Confirm i18n source catalog path**

Run: `find /home/bima-pangestu/Works/greentic/greentic-setup/i18n -maxdepth 2 -name 'en.json' -o -name 'en.yaml' | head`

Expected: a path like `i18n/en.json`.

- [ ] **Step 2: Add new keys** (alphabetical region):

```json
"webchat.notifier.prompt.enable_redis": "Enable Redis backplane for WebChat WebSocket multi-replica fan-out?",
"webchat.notifier.skip.no_state_redis": "Skipping Redis backplane: state-redis provider is not configured."
```

- [ ] **Step 3: Run the i18n translate script** (if convention requires)

```
bash tools/i18n.sh
```

Per workspace docs: `LANGS=all`, `BATCH_SIZE=200` defaults. If the script is missing in `greentic-setup/`, only `en.json` is updated and translations follow in a later PR.

- [ ] **Step 4: Commit**

```bash
git add greentic-setup/i18n/en.json
# also any translated catalogs the script regenerated
git commit -m "i18n(setup): add webchat notifier prompt strings"
```

---

### Task 16: Add wizard prompt + greentic.yaml writer (greentic-setup)

**Files (in `greentic-setup` repo):**
- Modify: section of `greentic-setup/src/cli_helpers/prompts.rs` or operator-setup engine — confirm during execution
- Modify: greentic.yaml writer helper (locate by grepping for the section that already writes `services` or `binaries`)

- [ ] **Step 1: Locate the existing state-redis prompt** in greentic-setup

Run:
```
grep -rn -i "state-redis\|state_redis" /home/bima-pangestu/Works/greentic/greentic-setup/src/ | head -20
```

The new prompt should run **after** the state-redis prompt has resolved, so it can check whether state-redis is configured.

- [ ] **Step 2: Add the Y/N prompt** (pseudocode, language matches the surrounding helper):

```rust
let enable_redis_backplane = if state_redis_was_configured(&answers) {
    prompt_yes_no(t!("webchat.notifier.prompt.enable_redis"), true /* default Y */)?
} else {
    println!("{}", t!("webchat.notifier.skip.no_state_redis"));
    false
};

if enable_redis_backplane {
    operator_yaml.set_webchat_notifier_backend_redis()?;
}
```

The helper `set_webchat_notifier_backend_redis` writes:
```yaml
webchat:
  notifier:
    backend: redis
```
under the operator's `greentic.yaml`. Add it via the same writer that handles `services` and `binaries` (likely in `tenant_config.rs` or similar — locate via `grep -n "binaries:" /home/bima-pangestu/Works/greentic/greentic-setup/src`).

- [ ] **Step 3: Add a unit test in greentic-setup**

```rust
#[test]
fn webchat_notifier_redis_writer_produces_expected_yaml() {
    let mut yaml = OperatorYaml::default();
    yaml.set_webchat_notifier_backend_redis();
    let rendered = serde_yaml_bw::to_string(&yaml).unwrap();
    assert!(rendered.contains("webchat:"));
    assert!(rendered.contains("notifier:"));
    assert!(rendered.contains("backend: redis"));
}
```

- [ ] **Step 4: Run greentic-setup local CI**

```
cd /home/bima-pangestu/Works/greentic/greentic-setup
bash ci/local_check.sh
```

Expected: green.

- [ ] **Step 5: Commit**

```bash
git add greentic-setup/src/...
git commit -m "feat(setup): add wizard prompt for WebChat Redis backplane"
```

- [ ] **Step 6: Open PRs in dependency order**

1. PR A: `feat/webchat-ws-redis-backplane` in greentic-start (Tasks 1–14).
2. PR B: matching branch in greentic-setup (Tasks 15–16) — references PR A in description so reviewer knows the runtime side is already in place.

---

## Done Criteria

This plan is complete when:

- [ ] All 16 tasks above checked off.
- [ ] `bash ci/local_check.sh` is green in `greentic-start` with `GREENTIC_TEST_REDIS_URL` unset.
- [ ] `bash ci/local_check.sh` is green in `greentic-start` with `GREENTIC_TEST_REDIS_URL=redis://127.0.0.1:6379` against a running Redis container.
- [ ] `bash ci/local_check.sh` is green in `greentic-setup`.
- [ ] Manual two-replica test from spec §7.3 (resilience runbook) passed at least once.
- [ ] `feat/webchat-ws-redis-backplane` opened as PR against `develop` in `greentic-start` and the matching wizard PR opened against `develop` in `greentic-setup`.
