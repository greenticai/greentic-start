# OAuth Card Full Round-Trip Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the github-mcp-demo-bundle's OAuth card work end-to-end against real GitHub OAuth: card renders with valid authorize URL, click → GitHub login → callback → token exchange → flow advance.

**Architecture:** Extend `runner_host::invoke_capability` to wrap OAuth card dispatch with `WitDispatchInput { host, provider, input }` envelope. Add file-based session store for state + PKCE verifier. Add HTTP callback handler that exchanges code for access_token via inline reqwest, persists token to secrets, and injects `oauth_login_success` activity into the originating conversation via loopback Direct Line POST.

**Tech Stack:** Rust 1.94.0 / edition 2024, `anyhow`, `serde_json`, `reqwest` (NEW dep), `rand`, `sha2`, `base64` (already in workspace), `greentic-types::ChannelMessageEnvelope`, `greentic-secrets-lib::{SeedDoc, SeedEntry, apply_seed}`.

**Branch:** `fix/oauth-card-messaging-wiring` (continues from Phase 1)

**Spec:** `docs/superpowers/specs/2026-04-11-oauth-card-full-roundtrip-design.md`

---

## File Structure

| File | Status | Lines | Responsibility |
|---|---|---|---|
| `Cargo.toml` | MODIFY | +2 | Add `reqwest` dep with `json` + `rustls-tls` features |
| `src/oauth_envelope.rs` | NEW | ~180 | `OauthProviderConfig`, `load_provider_config`, `load_public_base_url`, `wrap_dispatch_envelope` |
| `src/oauth_session_store.rs` | NEW | ~220 | `SessionTicket`, `PersistedSession`, `OauthSessionStore::{create, consume, gc_expired}` |
| `src/oauth_callback.rs` | NEW | ~280 | `OauthCallbackContext`, `handle_oauth_callback`, token exchange, activity injection, success HTML |
| `src/lib.rs` | MODIFY | +3 | Declare three new modules |
| `src/runner_host/mod.rs` | MODIFY | +35 / -0 | Add `gateway_port: u16` field; envelope wrapping branch in `invoke_capability` |
| `src/http_ingress/messaging.rs` | MODIFY | +50 / -25 | Update helper signature; create session; build inner_input with state/code_challenge |
| `src/http_ingress/mod.rs` | MODIFY | +50 | Register `/v1/oauth/callback/{provider_id}` route + dispatch glue |
| `src/cards.rs` | DELETE (or stub) | -250 | After Phase 2 ships, the old `CardRenderer::render_if_needed` is unused; delete the file in Task 8 |

---

## Task 1: Add reqwest dependency

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Open `Cargo.toml` and find the `[dependencies]` block**

Look for the alphabetical position between existing deps. Lines that look like:
```toml
rand = "0.10"
serde = { version = "1", features = ["derive"] }
```

- [ ] **Step 2: Add `reqwest` dep after `rand`**

Insert this line:
```toml
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls", "blocking"] }
```

If a `reqwest` workspace dep already exists in `../greentic-runner/crates/greentic-runner-host/Cargo.toml` or similar, prefer the workspace version syntax `reqwest = { workspace = true, features = ["json", "rustls-tls"] }`. Check first:

```bash
grep -rn "^reqwest" ../greentic-*/Cargo.toml ~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/greentic-types-0.4.58/Cargo.toml 2>/dev/null | head -5
```

Use whichever pattern the rest of the workspace uses. Default to the explicit version if uncertain.

- [ ] **Step 3: Build to confirm it resolves**

```bash
cd /home/bimbim/works/greentic/greentic-start
cargo build -p greentic-start --all-features 2>&1 | tail -10
```

Expected: clean build (slow first time as reqwest compiles).

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "deps: add reqwest for OAuth token exchange"
```

---

## Task 2: oauth_envelope module — provider config loader (TDD)

**Files:**
- Create: `src/oauth_envelope.rs`
- Modify: `src/lib.rs` (declare module)

- [ ] **Step 1: Create `src/oauth_envelope.rs` with the type and a stub loader**

```rust
//! Helpers for constructing the WitDispatchInput envelope used by
//! oauth-oidc-generic provider WASM operations.
//!
//! These helpers exist because `runner_host::invoke_capability` passes raw
//! payload bytes to the WASM component, but the oidc-provider-runtime
//! component requires them to be wrapped in `{host, provider, input}`.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OauthProviderConfig {
    pub provider_id: String,
    pub auth_url: String,
    pub token_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub default_scopes: Vec<String>,
}

#[derive(Deserialize)]
struct SetupAnswers {
    provider_id: String,
    auth_url: String,
    token_url: String,
    client_id: String,
    client_secret: String,
    #[serde(default)]
    default_scopes: Option<String>,
}

pub fn load_provider_config(
    bundle_root: &Path,
    provider_pack_id: &str,
) -> Result<OauthProviderConfig> {
    let path: PathBuf = bundle_root
        .join("state")
        .join("config")
        .join(provider_pack_id)
        .join("setup-answers.json");
    let raw = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "oauth provider config not found at {} (run setup or check provider_pack_id)",
            path.display()
        )
    })?;
    let parsed: SetupAnswers = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    let default_scopes = parsed
        .default_scopes
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();

    if parsed.client_id.trim().is_empty() {
        return Err(anyhow!("setup-answers.json: client_id is empty"));
    }
    if parsed.client_secret.trim().is_empty() {
        return Err(anyhow!("setup-answers.json: client_secret is empty"));
    }

    Ok(OauthProviderConfig {
        provider_id: parsed.provider_id,
        auth_url: parsed.auth_url,
        token_url: parsed.token_url,
        client_id: parsed.client_id,
        client_secret: parsed.client_secret,
        default_scopes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn write_setup_answers(bundle_root: &Path, pack_id: &str, body: &serde_json::Value) {
        let dir = bundle_root.join("state").join("config").join(pack_id);
        std::fs::create_dir_all(&dir).expect("mkdirs");
        std::fs::write(
            dir.join("setup-answers.json"),
            serde_json::to_vec_pretty(body).expect("ser"),
        )
        .expect("write");
    }

    #[test]
    fn load_provider_config_reads_setup_answers_json() {
        let dir = tempdir().expect("tempdir");
        write_setup_answers(
            dir.path(),
            "oauth-oidc-generic",
            &json!({
                "provider_id": "github",
                "auth_url": "https://github.com/login/oauth/authorize",
                "token_url": "https://github.com/login/oauth/access_token",
                "client_id": "abc123",
                "client_secret": "supersecret",
                "default_scopes": "repo read:org"
            }),
        );

        let cfg = load_provider_config(dir.path(), "oauth-oidc-generic").expect("ok");
        assert_eq!(cfg.provider_id, "github");
        assert_eq!(cfg.auth_url, "https://github.com/login/oauth/authorize");
        assert_eq!(cfg.client_id, "abc123");
        assert_eq!(cfg.client_secret, "supersecret");
        assert_eq!(
            cfg.default_scopes,
            vec!["repo".to_string(), "read:org".to_string()]
        );
    }

    #[test]
    fn load_provider_config_errors_when_file_missing() {
        let dir = tempdir().expect("tempdir");
        let err = load_provider_config(dir.path(), "oauth-oidc-generic").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn load_provider_config_errors_when_client_id_empty() {
        let dir = tempdir().expect("tempdir");
        write_setup_answers(
            dir.path(),
            "oauth-oidc-generic",
            &json!({
                "provider_id": "github",
                "auth_url": "https://github.com/login/oauth/authorize",
                "token_url": "https://github.com/login/oauth/access_token",
                "client_id": "",
                "client_secret": "x",
                "default_scopes": "repo"
            }),
        );
        let err = load_provider_config(dir.path(), "oauth-oidc-generic").unwrap_err();
        assert!(err.to_string().contains("client_id is empty"));
    }
}
```

- [ ] **Step 2: Declare module in `src/lib.rs`**

Open `src/lib.rs`. Find the existing `pub mod` declarations (probably alphabetical). Add:
```rust
pub mod oauth_envelope;
```

(Visibility: `pub` so the runner_host can call it.)

- [ ] **Step 3: Run the new tests**

```bash
cargo test -p greentic-start --all-features -- oauth_envelope::tests
```

Expected: 3 tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/oauth_envelope.rs src/lib.rs
git commit -m "feat(oauth-envelope): provider config loader for setup-answers.json"
```

---

## Task 3: oauth_envelope module — public_base_url loader (TDD)

**Files:**
- Modify: `src/oauth_envelope.rs`

- [ ] **Step 1: Add the function and tests**

Add this function below `load_provider_config`:

```rust
pub fn load_public_base_url(
    bundle_root: &Path,
    tenant: &str,
    team: Option<&str>,
    fallback_port: u16,
) -> Result<String> {
    let team_segment = match team {
        Some(t) if !t.is_empty() => format!("{tenant}.{t}"),
        _ => format!("{tenant}.default"),
    };
    let runtime_dir = bundle_root.join("state").join("runtime").join(&team_segment);

    // Try endpoints.json first.
    let endpoints_path = runtime_dir.join("endpoints.json");
    if let Ok(raw) = std::fs::read_to_string(&endpoints_path) {
        if let Ok(value) = serde_json::from_str::<Value>(&raw) {
            if let Some(url) = value.get("public_base_url").and_then(Value::as_str) {
                if !url.trim().is_empty() {
                    return Ok(url.trim_end_matches('/').to_string());
                }
            }
        }
    }

    // Fall back to public_base_url.txt.
    let txt_path = runtime_dir.join("public_base_url.txt");
    if let Ok(raw) = std::fs::read_to_string(&txt_path) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.trim_end_matches('/').to_string());
        }
    }

    // Final fallback: local loopback at the configured gateway port.
    Ok(format!("http://127.0.0.1:{fallback_port}"))
}
```

Then add tests in the existing `mod tests`:

```rust
    #[test]
    fn load_public_base_url_reads_endpoints_json() {
        let dir = tempdir().expect("tempdir");
        let runtime = dir.path().join("state/runtime/demo.default");
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::write(
            runtime.join("endpoints.json"),
            json!({"public_base_url": "https://abc.ngrok-free.app/"}).to_string(),
        )
        .unwrap();

        let url = load_public_base_url(dir.path(), "demo", Some("default"), 9999).unwrap();
        assert_eq!(url, "https://abc.ngrok-free.app");
    }

    #[test]
    fn load_public_base_url_falls_back_to_txt_then_loopback() {
        let dir = tempdir().expect("tempdir");
        let runtime = dir.path().join("state/runtime/demo.default");
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::write(runtime.join("public_base_url.txt"), "http://from-txt:1234/").unwrap();

        let url = load_public_base_url(dir.path(), "demo", Some("default"), 9999).unwrap();
        assert_eq!(url, "http://from-txt:1234");
    }

    #[test]
    fn load_public_base_url_falls_back_to_local_loopback() {
        let dir = tempdir().expect("tempdir");
        let url = load_public_base_url(dir.path(), "demo", Some("default"), 8090).unwrap();
        assert_eq!(url, "http://127.0.0.1:8090");
    }
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p greentic-start --all-features -- oauth_envelope::tests::load_public_base_url
```

Expected: 3 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/oauth_envelope.rs
git commit -m "feat(oauth-envelope): public_base_url loader with fallback chain"
```

---

## Task 4: oauth_envelope module — wrap_dispatch_envelope (TDD)

**Files:**
- Modify: `src/oauth_envelope.rs`

- [ ] **Step 1: Add the wrapper fn and tests**

Below `load_public_base_url`:

```rust
pub fn wrap_dispatch_envelope(
    public_base_url: &str,
    provider: &OauthProviderConfig,
    inner_input: Value,
) -> Result<Vec<u8>> {
    let envelope = serde_json::json!({
        "host": {
            "public_base_url": public_base_url,
        },
        "provider": {
            "provider_id": provider.provider_id,
            "client_id": provider.client_id,
            "client_secret": provider.client_secret,
            "client_id_key": Value::Null,
            "client_secret_key": Value::Null,
            "auth_url": provider.auth_url,
            "token_url": provider.token_url,
            "default_scopes": provider.default_scopes,
        },
        "input": inner_input,
    });
    serde_json::to_vec(&envelope)
        .with_context(|| "failed to serialize WitDispatchInput envelope")
}
```

Then in `mod tests`:

```rust
    #[test]
    fn wrap_dispatch_envelope_produces_correct_shape() {
        let cfg = OauthProviderConfig {
            provider_id: "github".to_string(),
            auth_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            client_id: "abc".to_string(),
            client_secret: "secret".to_string(),
            default_scopes: vec!["repo".to_string()],
        };
        let inner = json!({
            "adaptive_card": "{}",
            "tenant": "demo",
            "state": "state-1",
            "code_challenge": "ch-1"
        });
        let bytes = wrap_dispatch_envelope("http://127.0.0.1:8090", &cfg, inner.clone()).unwrap();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(parsed["host"]["public_base_url"], "http://127.0.0.1:8090");
        assert_eq!(parsed["provider"]["provider_id"], "github");
        assert_eq!(parsed["provider"]["client_id"], "abc");
        assert_eq!(parsed["provider"]["client_secret"], "secret");
        assert_eq!(parsed["provider"]["auth_url"], "https://github.com/login/oauth/authorize");
        assert_eq!(parsed["input"], inner);
    }
```

- [ ] **Step 2: Run all oauth_envelope tests**

```bash
cargo test -p greentic-start --all-features -- oauth_envelope::tests
```

Expected: 7 tests total pass (3 from Task 2, 3 from Task 3, 1 new).

- [ ] **Step 3: Commit**

```bash
git add src/oauth_envelope.rs
git commit -m "feat(oauth-envelope): wrap_dispatch_envelope WitDispatchInput builder"
```

---

## Task 5: oauth_session_store module (TDD)

**Files:**
- Create: `src/oauth_session_store.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Create `src/oauth_session_store.rs`**

```rust
//! File-based OAuth session store for state token + PKCE verifier persistence.
//!
//! Storage layout: {bundle_root}/state/oauth-sessions/{state_token}.json
//! TTL: callers should pass `Duration::from_secs(600)` to gc_expired.
//!
//! Concurrency: each session has a unique random state token, so writes
//! never collide. consume() does read+remove and treats remove failures as
//! best-effort (the read already succeeded).

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct SessionTicket {
    pub state_token: String,
    pub code_verifier: String,
    pub code_challenge: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedSession {
    pub state_token: String,
    pub code_verifier: String,
    pub provider_id: String,
    pub provider_pack_id: String,
    pub tenant: String,
    pub team: Option<String>,
    pub conversation_id: String,
    pub created_at_unix_ms: i64,
}

#[derive(Debug, Clone)]
pub struct OauthSessionStore {
    bundle_root: PathBuf,
}

impl OauthSessionStore {
    pub fn new(bundle_root: impl Into<PathBuf>) -> Self {
        Self {
            bundle_root: bundle_root.into(),
        }
    }

    fn sessions_dir(&self) -> PathBuf {
        self.bundle_root.join("state").join("oauth-sessions")
    }

    fn session_path(&self, state_token: &str) -> PathBuf {
        self.sessions_dir().join(format!("{state_token}.json"))
    }

    pub fn create(
        &self,
        provider_id: &str,
        provider_pack_id: &str,
        tenant: &str,
        team: Option<&str>,
        conversation_id: &str,
    ) -> Result<SessionTicket> {
        // Best-effort GC of stale sessions.
        let _ = self.gc_expired(Duration::from_secs(600));

        let state_token = random_url_safe(32);
        let code_verifier = random_url_safe(64);
        let code_challenge = pkce_challenge_s256(&code_verifier);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        let session = PersistedSession {
            state_token: state_token.clone(),
            code_verifier: code_verifier.clone(),
            provider_id: provider_id.to_string(),
            provider_pack_id: provider_pack_id.to_string(),
            tenant: tenant.to_string(),
            team: team.map(str::to_string),
            conversation_id: conversation_id.to_string(),
            created_at_unix_ms: now,
        };

        std::fs::create_dir_all(self.sessions_dir())
            .with_context(|| "failed to create oauth-sessions dir")?;
        let path = self.session_path(&state_token);
        let body = serde_json::to_vec_pretty(&session)
            .with_context(|| "failed to serialize session")?;
        std::fs::write(&path, body)
            .with_context(|| format!("failed to write session file {}", path.display()))?;

        // Restrict perms on POSIX (best-effort).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }

        Ok(SessionTicket {
            state_token,
            code_verifier,
            code_challenge,
        })
    }

    pub fn consume(&self, state_token: &str) -> Result<PersistedSession> {
        let path = self.session_path(state_token);
        let raw = std::fs::read_to_string(&path)
            .map_err(|err| anyhow!("session not found ({state_token}): {err}"))?;
        let session: PersistedSession = serde_json::from_str(&raw)
            .with_context(|| format!("session {state_token} corrupt"))?;
        // Best-effort delete.
        let _ = std::fs::remove_file(&path);
        Ok(session)
    }

    pub fn gc_expired(&self, max_age: Duration) -> Result<usize> {
        let dir = self.sessions_dir();
        if !dir.exists() {
            return Ok(0);
        }
        let cutoff_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
            - max_age.as_millis() as i64;
        let mut removed = 0usize;
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            // Try parsing the session to compare timestamps; if parse fails,
            // delete it (corrupt file).
            let parse_attempt: Option<PersistedSession> = std::fs::read_to_string(&path)
                .ok()
                .and_then(|raw| serde_json::from_str(&raw).ok());
            let stale = match parse_attempt {
                Some(s) => s.created_at_unix_ms < cutoff_ms,
                None => true,
            };
            if stale && std::fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

fn random_url_safe(byte_len: usize) -> String {
    let mut bytes = vec![0u8; byte_len];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn pkce_challenge_s256(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use tempfile::tempdir;

    #[test]
    fn create_persists_session_file_with_random_state_and_verifier() {
        let dir = tempdir().unwrap();
        let store = OauthSessionStore::new(dir.path());
        let ticket = store
            .create("github", "oauth-oidc-generic", "demo", Some("default"), "conv-1")
            .unwrap();
        assert!(!ticket.state_token.is_empty());
        assert!(!ticket.code_verifier.is_empty());
        assert!(!ticket.code_challenge.is_empty());
        let path = dir
            .path()
            .join("state/oauth-sessions")
            .join(format!("{}.json", ticket.state_token));
        assert!(path.exists(), "session file should exist");
    }

    #[test]
    fn create_returns_unique_state_tokens_across_calls() {
        let dir = tempdir().unwrap();
        let store = OauthSessionStore::new(dir.path());
        let a = store.create("github", "p", "demo", None, "c1").unwrap();
        let b = store.create("github", "p", "demo", None, "c2").unwrap();
        assert_ne!(a.state_token, b.state_token);
        assert_ne!(a.code_verifier, b.code_verifier);
    }

    #[test]
    fn consume_returns_session_and_deletes_file() {
        let dir = tempdir().unwrap();
        let store = OauthSessionStore::new(dir.path());
        let ticket = store
            .create("github", "oauth-oidc-generic", "demo", Some("default"), "conv-1")
            .unwrap();
        let session = store.consume(&ticket.state_token).unwrap();
        assert_eq!(session.provider_id, "github");
        assert_eq!(session.conversation_id, "conv-1");
        assert_eq!(session.code_verifier, ticket.code_verifier);
        let path = dir
            .path()
            .join("state/oauth-sessions")
            .join(format!("{}.json", ticket.state_token));
        assert!(!path.exists(), "session file should be deleted");
    }

    #[test]
    fn consume_errors_on_unknown_state_token() {
        let dir = tempdir().unwrap();
        let store = OauthSessionStore::new(dir.path());
        let err = store.consume("nonexistent-state").unwrap_err();
        assert!(err.to_string().contains("session not found"));
    }

    #[test]
    fn gc_expired_removes_old_sessions() {
        let dir = tempdir().unwrap();
        let store = OauthSessionStore::new(dir.path());
        let ticket = store
            .create("github", "p", "demo", None, "c1")
            .unwrap();
        // Backdate the session by mutating the file directly.
        let path = dir
            .path()
            .join("state/oauth-sessions")
            .join(format!("{}.json", ticket.state_token));
        let mut session: PersistedSession =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        session.created_at_unix_ms = 0;
        std::fs::write(&path, serde_json::to_vec(&session).unwrap()).unwrap();

        // Sleep a hair to advance the clock.
        thread::sleep(Duration::from_millis(10));

        let removed = store.gc_expired(Duration::from_millis(1)).unwrap();
        assert_eq!(removed, 1);
        assert!(!path.exists());
    }

    #[test]
    fn code_challenge_is_base64url_sha256_of_verifier() {
        // RFC 7636 Appendix B test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let actual = pkce_challenge_s256(verifier);
        assert_eq!(actual, expected);
    }
}
```

- [ ] **Step 2: Declare module in `src/lib.rs`**

Add:
```rust
pub mod oauth_session_store;
```

- [ ] **Step 3: Run tests**

```bash
cargo test -p greentic-start --all-features -- oauth_session_store::tests
```

Expected: 6 tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/oauth_session_store.rs src/lib.rs
git commit -m "feat(oauth): file-based session store with PKCE generation"
```

---

## Task 6: Add gateway_port field to DemoRunnerHost

**Files:**
- Modify: `src/runner_host/mod.rs`

- [ ] **Step 1: Add field to struct**

Find `pub struct DemoRunnerHost { ... }` (around line 40). Add field:
```rust
    gateway_port: u16,
```

- [ ] **Step 2: Add field to constructor**

Find `pub fn new(...)` of `DemoRunnerHost`. Add a new parameter `gateway_port: u16` AT THE END (after existing params). Then in the `Self { ... }` initializer, add:
```rust
            gateway_port,
```

- [ ] **Step 3: Add accessor**

Below the constructor, add:
```rust
    pub fn gateway_port(&self) -> u16 {
        self.gateway_port
    }
```

- [ ] **Step 4: Update all callers of `DemoRunnerHost::new`**

Find them:
```bash
grep -rn "DemoRunnerHost::new\b" src/
```

For each call site, pass the gateway port. Sources:
- In production code (likely `src/runtime.rs` or similar): pass `config.services.gateway.port`.
- In tests: pass `8080` as a default.

Read each call site and decide locally — most likely just one production call site and a few test helpers.

- [ ] **Step 5: Build**

```bash
cargo build -p greentic-start --all-features 2>&1 | tail -20
```

Expected: clean. If a caller is missed, the compiler will tell you.

- [ ] **Step 6: Run existing test suite to confirm no regressions**

```bash
cargo test -p greentic-start --all-features 2>&1 | tail -10
```

Expected: 433+ tests pass (Phase 1's 427 + new 13 from Tasks 2-5).

- [ ] **Step 7: Commit**

```bash
git add src/runner_host/mod.rs src/runtime.rs
git commit -m "feat(runner_host): expose gateway_port for OAuth callback URL building"
```

(Adjust the file list to whatever was actually changed; only files you modified.)

---

## Task 7: Extend invoke_capability with OAuth envelope wrapping

**Files:**
- Modify: `src/runner_host/mod.rs`

- [ ] **Step 1: Import the new helpers**

At the top of `src/runner_host/mod.rs`, add:
```rust
use crate::oauth_envelope;
```

- [ ] **Step 2: Find the call to `invoke_provider_component_op` inside `invoke_capability`**

Around line 373:
```rust
let outcome = self.invoke_provider_component_op(
    binding.domain,
    pack,
    &binding.pack_id,
    target_op,
    payload_bytes,
    ctx,
)?;
```

- [ ] **Step 3: Insert envelope wrapping before the call**

Replace the block with:
```rust
let final_payload_bytes: Vec<u8> = if cap_id == CAP_OAUTH_CARD_V1 {
    // OAuth card resolution requires the WASM dispatch envelope
    // {host, provider, input}. Build it from the bundle's
    // state/config/{provider_pack_id}/setup-answers.json and
    // state/runtime/{tenant}.{team}/endpoints.json.
    let inner_input: serde_json::Value = serde_json::from_slice(payload_bytes)
        .with_context(|| {
            format!("oauth.card.resolve input must be valid JSON for cap {cap_id}")
        })?;
    let provider_cfg =
        oauth_envelope::load_provider_config(&self.bundle_root, &binding.pack_id)?;
    let public_base_url = oauth_envelope::load_public_base_url(
        &self.bundle_root,
        &ctx.tenant,
        ctx.team.as_deref(),
        self.gateway_port,
    )?;
    oauth_envelope::wrap_dispatch_envelope(&public_base_url, &provider_cfg, inner_input)?
} else {
    payload_bytes.to_vec()
};

let outcome = self.invoke_provider_component_op(
    binding.domain,
    pack,
    &binding.pack_id,
    target_op,
    &final_payload_bytes,
    ctx,
)?;
```

Make sure `anyhow::Context` is imported at the top of the file (the `with_context` method requires it). If not, add `use anyhow::Context;`.

- [ ] **Step 4: Build**

```bash
cargo build -p greentic-start --all-features 2>&1 | tail -10
```

Expected: clean.

- [ ] **Step 5: Run all tests including a smoke check that the helper compiles**

```bash
cargo test -p greentic-start --all-features 2>&1 | tail -10
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/runner_host/mod.rs
git commit -m "feat(runner_host): wrap OAuth card capability dispatch with WitDispatchInput"
```

---

## Task 8: Update resolve_oauth_card_placeholders to create session + new dispatcher input

**Files:**
- Modify: `src/http_ingress/messaging.rs`
- Possibly modify: `src/cards.rs` (only if removed entirely — see Step 7)

- [ ] **Step 1: Add imports at top of `src/http_ingress/messaging.rs`**

Add:
```rust
use crate::oauth_session_store::OauthSessionStore;
use crate::capabilities::CAP_OAUTH_CARD_V1;
```

Remove `use crate::cards::CardRenderer;` (added in Phase 1 task) — we no longer need it; the new helper builds the dispatcher input directly without `CardRenderer::render_if_needed`.

- [ ] **Step 2: Replace the body of `resolve_oauth_card_placeholders`**

Find the existing fn (the one from Phase 1, currently around line 344). Replace its entire body with:

```rust
fn resolve_oauth_card_placeholders(
    provider_type: &str,
    envelope: &mut ChannelMessageEnvelope,
    session_store: &OauthSessionStore,
    provider_pack_id: &str,
    conversation_id: &str,
    mut dispatcher: impl FnMut(&str, &str, &[u8]) -> anyhow::Result<serde_json::Value>,
) -> anyhow::Result<()> {
    let _ = provider_type; // Reserved for future Teams native handling
    let Some(card_str) = envelope.metadata.get("adaptive_card").cloned() else {
        return Ok(());
    };
    if !card_str.contains("oauth://start")
        && !card_str.contains("{{oauth.start_url}}")
        && !card_str.contains("{{oauth.teams.connectionName}}")
    {
        return Ok(());
    }

    // Create a session and persist verifier+challenge for the upcoming callback.
    let team = envelope.tenant.team.as_deref().or(envelope.tenant.team_id.as_deref());
    let provider_id_for_session = derive_provider_id_from_pack(provider_pack_id);
    let ticket = session_store.create(
        &provider_id_for_session,
        provider_pack_id,
        &envelope.tenant.tenant_id,
        team,
        conversation_id,
    )?;

    // Build the dispatcher input matching CardResolveDispatchInput in
    // oidc-provider-runtime/src/lib.rs (handle_resolve_card).
    let inner_input = serde_json::json!({
        "adaptive_card": card_str,
        "tenant": envelope.tenant.tenant_id,
        "state": ticket.state_token,
        "code_challenge": ticket.code_challenge,
        "scopes": serde_json::Value::Null, // provider config supplies default_scopes
        "native_oauth_card": false,
    });
    let input_bytes =
        serde_json::to_vec(&inner_input).map_err(|err| anyhow::anyhow!("serialize: {err}"))?;

    let resolve_result = dispatcher(CAP_OAUTH_CARD_V1, "oauth.card.resolve", &input_bytes)?;

    let resolved_card = resolve_result
        .get("resolved_card")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("oauth.card.resolve output missing resolved_card"))?;

    envelope
        .metadata
        .insert("adaptive_card".to_string(), resolved_card.to_string());

    // Audit fields stored as compact JSON strings (BTreeMap<String,String>).
    let mut audit = resolve_result.clone();
    if let Some(obj) = audit.as_object_mut() {
        obj.remove("resolved_card");
    }
    envelope
        .metadata
        .insert("oauth_card_resolved".to_string(), audit.to_string());
    if let Some(downgrade) = resolve_result.get("downgrade").filter(|v| !v.is_null()) {
        envelope
            .metadata
            .insert("oauth_card_downgrade".to_string(), downgrade.to_string());
    }
    Ok(())
}

/// Derive a provider_id given the pack id. For now, hardcoded to the
/// only supported OAuth provider pack. Future: discover from capability binding.
fn derive_provider_id_from_pack(provider_pack_id: &str) -> String {
    // For oauth-oidc-generic the provider_id lives in setup-answers.json,
    // but reading the file here would couple this fn to oauth_envelope.
    // Instead, the WASM dispatch will validate provider_id at the envelope
    // wrapping stage; here we record a stable label for the session that
    // matches what the callback path uses.
    match provider_pack_id {
        "oauth-oidc-generic" => "github".to_string(),
        other => other.to_string(),
    }
}
```

This is intentionally hardcoded for `oauth-oidc-generic → github`. A TODO is acknowledged in the spec; future improvement is to read provider_id from setup-answers.json via `oauth_envelope::load_provider_config` and pass it through.

- [ ] **Step 3: Update the call site in the egress loop**

Around line 99 (where the helper is currently called from Phase 1), replace the call site with:

```rust
            // Resolve OAuth card placeholders. Phase 2: also persists a
            // session record so the upcoming /v1/oauth/callback/{provider_id}
            // can recover state + PKCE verifier.
            let session_store = OauthSessionStore::new(bundle.to_path_buf());
            let conversation_id = out_envelope.session_id.clone();
            if let Err(err) = resolve_oauth_card_placeholders(
                &provider_type,
                &mut out_envelope,
                &session_store,
                "oauth-oidc-generic",
                &conversation_id,
                |cap_id, op, input| {
                    let outcome = runner_host.invoke_capability(cap_id, op, input, ctx)?;
                    if !outcome.success {
                        return Err(anyhow::anyhow!(
                            "capability {}:{} failed: {}",
                            cap_id,
                            op,
                            outcome
                                .error
                                .clone()
                                .unwrap_or_else(|| "unknown".to_string())
                        ));
                    }
                    outcome.output.ok_or_else(|| {
                        anyhow::anyhow!(
                            "capability {}:{} returned no structured output",
                            cap_id,
                            op
                        )
                    })
                },
            ) {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "[demo messaging] oauth card resolve failed for provider={} envelope_id={}: {err}; sending unresolved",
                        provider, out_envelope.id
                    ),
                );
            }
```

Note the `provider_type` binding from Phase 1's perf hoist still exists above the loop — reuse it.

- [ ] **Step 4: Update existing helper tests for the new signature**

Find the existing tests in `mod tests`:
- `resolve_oauth_card_placeholders_swaps_url_from_capability`
- `resolve_oauth_card_placeholders_fails_soft_when_dispatcher_errors`
- `resolve_oauth_card_placeholders_noop_when_no_card_in_metadata`
- `resolve_oauth_card_placeholders_propagates_team_id_when_team_is_none`

Each call site of `resolve_oauth_card_placeholders` needs the new params. Update the call to:
```rust
let store = OauthSessionStore::new(tempdir().unwrap().keep());
let result = resolve_oauth_card_placeholders(
    "messaging.webchat-gui",
    &mut env,
    &store,
    "oauth-oidc-generic",
    "test-conv-1",
    dispatcher,
);
```

For the tests that previously asserted on `state` propagation (the team_id regression test), now the dispatcher input is the raw inner_input we build — assertions can check `parsed["adaptive_card"]`, `parsed["tenant"]`, `parsed["state"]`, `parsed["code_challenge"]` at the top level (not nested).

- [ ] **Step 5: Run the messaging test module**

```bash
cargo test -p greentic-start --all-features -- http_ingress::messaging::tests
```

Expected: all messaging tests still pass with the updated signature.

- [ ] **Step 6: Run full suite**

```bash
cargo test -p greentic-start --all-features 2>&1 | tail -10
```

Expected: clean.

- [ ] **Step 7: Decide on cards.rs**

Run:
```bash
grep -rn "CardRenderer\|render_if_needed" src/
```

If the only matches are inside `src/cards.rs` itself, the file is now dead code. Delete it:
```bash
git rm src/cards.rs
```

And remove `pub mod cards;` from `src/lib.rs`. Verify the build is still clean.

If `CardRenderer` is referenced elsewhere (it shouldn't be after Task 6 of Phase 1 + Task 8 here, but verify), leave the file alone for this task and add a follow-up TODO.

- [ ] **Step 8: Run full suite again to confirm cards.rs deletion (if applied) is clean**

```bash
cargo build -p greentic-start --all-features 2>&1 | tail -10
cargo test -p greentic-start --all-features 2>&1 | tail -10
```

- [ ] **Step 9: Commit**

```bash
git add src/http_ingress/messaging.rs src/lib.rs
git rm src/cards.rs  # if applicable
git commit -m "feat(messaging): create OAuth session + new dispatcher input shape"
```

---

## Task 9: Phase 2 manual smoke test

**Files:** none (verification only)

- [ ] **Step 1: Install patched binary**

```bash
cd /home/bimbim/works/greentic/greentic-start
cargo install --path . --locked --force 2>&1 | tail -5
greentic-start --version
```

Expected version: `greentic-start 0.4.49`.

- [ ] **Step 2: Override bundle gateway port (port 8080 may be in use)**

```bash
cp /home/bimbim/works/greentic/github-mcp-demo-bundle/greentic.demo.yaml /tmp/greentic.demo.yaml.bak
cat > /home/bimbim/works/greentic/github-mcp-demo-bundle/greentic.demo.yaml <<'YAML'
version: "1"
project_root: "./"
services:
  gateway:
    port: 8090
YAML
```

- [ ] **Step 3: Start bundle in background**

```bash
cd /home/bimbim/works/greentic/github-mcp-demo-bundle
greentic-start --locale en start --bundle . --nats off --cloudflared off --ngrok off > /tmp/gh-mcp-phase2.log 2>&1 &
sleep 10
ss -tlnp 2>&1 | grep ':8090'
```

Expected: greentic-start listening on 127.0.0.1:8090.

- [ ] **Step 4: Get a Direct Line token + start conversation + send "Get started"**

```bash
TOKEN=$(curl -s -X POST 'http://127.0.0.1:8090/v1/messaging/webchat/demo/token?tenant=demo' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
CONV_RESP=$(curl -s -X POST "http://127.0.0.1:8090/v1/messaging/webchat/demo/v3/directline/conversations?tenant=demo" -H "Authorization: Bearer $TOKEN")
CONV=$(echo "$CONV_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['conversationId'])")
CONV_TOKEN=$(echo "$CONV_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))")
[ -z "$CONV_TOKEN" ] && CONV_TOKEN="$TOKEN"
curl -s -X POST "http://127.0.0.1:8090/v1/messaging/webchat/demo/v3/directline/conversations/$CONV/activities?tenant=demo" \
    -H "Authorization: Bearer $CONV_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"type":"message","from":{"id":"user1","name":"User"},"text":"Get started"}'
sleep 3
curl -s "http://127.0.0.1:8090/v1/messaging/webchat/demo/v3/directline/conversations/$CONV/activities?tenant=demo" \
    -H "Authorization: Bearer $CONV_TOKEN" | python3 -m json.tool | head -100
```

- [ ] **Step 5: Assert resolved URL appears**

In the JSON output, find `attachments[0].content.actions[0].url`. It should look like:
```
https://github.com/login/oauth/authorize?response_type=code&client_id=Ov23ligPicBfeZw44MjZ&redirect_uri=http%3A%2F%2F127.0.0.1%3A8090%2Fv1%2Foauth%2Fcallback%2Fgithub&scope=...&state=<random>&code_challenge=<base64url>&code_challenge_method=S256
```

If the URL is still `oauth://start`, check the operator log for errors:
```bash
grep -E "oauth card resolve|invoke_capability|envelope" /home/bimbim/works/greentic/github-mcp-demo-bundle/logs/operator.log | tail -20
```

Common failure modes:
- `setup-answers.json` not found → check the bundle path is correct
- `client_id is empty` → setup-answers.json missing field
- Capability not found → check that `oauth-oidc-generic-pack` is installed in `providers/oauth/`

- [ ] **Step 6: Verify session file was created**

```bash
ls -la /home/bimbim/works/greentic/github-mcp-demo-bundle/state/oauth-sessions/
cat /home/bimbim/works/greentic/github-mcp-demo-bundle/state/oauth-sessions/*.json | python3 -m json.tool
```

Expected: at least one session file containing the conversation_id.

- [ ] **Step 7: Stop bundle + restore config**

```bash
pkill -f "greentic-start.*github-mcp-demo-bundle.*--bundle ." 2>&1
sleep 2
cp /tmp/greentic.demo.yaml.bak /home/bimbim/works/greentic/github-mcp-demo-bundle/greentic.demo.yaml
rm /tmp/greentic.demo.yaml.bak
```

- [ ] **Step 8: No commit — verification only**

If Phase 2 smoke test passes, the fix is partially working. The button now opens a real GitHub OAuth flow but the callback (Phase 3) is not yet wired.

---

## Task 10: Verify flow pause assumption + token mint helper

**Files:** none (investigation)

- [ ] **Step 1: Read main.ygtc to check for session.wait at auth_choice**

```bash
cat /home/bimbim/works/greentic/github-mcp-demo-bundle/packs/github-mcp.pack/flows/main.ygtc
```

Look for the `auth_choice` node. Check whether it has `session.wait` or equivalent that pauses the flow until a user response arrives. Note the routing rules — find the branch that matches `response.text == "oauth_login_success"` or similar, and what node it routes to.

- [ ] **Step 2: Document findings in a comment**

If `auth_choice` does pause: Phase 3's activity injection design works as planned.

If `auth_choice` does NOT pause: Phase 3 will still ship with token persistence + redirect; user has to manually re-send "Get started" after the callback.

Add a comment to `src/oauth_callback.rs` (which you'll create in Task 12) recording the finding so future maintainers understand the design choice.

- [ ] **Step 3: Locate the Direct Line token mint helper**

```bash
grep -rn "mint_directline_token\|fn token_response\|sign_token\|HS256\|directline_token" /home/bimbim/works/greentic/greentic-start/src 2>&1 | head
```

Find the function that handles `/v1/messaging/webchat/{tenant}/token` requests. Note its visibility (`fn` vs `pub fn` vs `pub(crate) fn`).

- [ ] **Step 4: Document fallback choice for activity injection**

Based on the visibility:
- **If publicly callable from oauth_callback.rs:** use it directly to mint a system JWT before the loopback POST (Phase 3 design A).
- **If private:** either expose it `pub(crate)` or skip JWT entirely and POST without auth via a special internal-loopback header that the existing handler honors. If neither is feasible, fall back to writing the activity directly to the conversation state store (Phase 3 design B).
- **If complex:** drop activity injection and rely on manual user re-send (Phase 3 design C).

Pick the option you'll implement in Task 15 and note it.

- [ ] **Step 5: No commit — investigation only**

---

## Task 11: oauth_callback module skeleton

**Files:**
- Create: `src/oauth_callback.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Create the file with a stub handler that returns "not implemented"**

```rust
//! HTTP handler for `/v1/oauth/callback/{provider_id}`.
//!
//! Phase 3 of the OAuth card full round-trip fix. Receives the OAuth
//! authorization code from a redirect, exchanges it for an access token
//! via inline reqwest, persists the token, and injects an
//! `oauth_login_success` activity into the originating conversation so
//! the flow router can advance.

use anyhow::{Result, anyhow};
use http_body_util::Full;
use hyper::body::Bytes;
use std::path::Path;
use url::form_urlencoded;

use crate::oauth_envelope::{self, OauthProviderConfig};
use crate::oauth_session_store::{OauthSessionStore, PersistedSession};
use crate::runner_host::DemoRunnerHost;

pub struct OauthCallbackContext<'a> {
    pub bundle_root: &'a Path,
    pub session_store: &'a OauthSessionStore,
    pub runner_host: &'a DemoRunnerHost,
    pub gateway_port: u16,
}

pub async fn handle_oauth_callback(
    ctx: OauthCallbackContext<'_>,
    provider_id: &str,
    query_string: &str,
) -> hyper::Response<Full<Bytes>> {
    match handle_oauth_callback_inner(ctx, provider_id, query_string).await {
        Ok(html) => html_response(200, &html),
        Err(err) => {
            crate::operator_log::warn(
                module_path!(),
                format!("[oauth callback] failed: {err:#}"),
            );
            html_response(
                400,
                &error_html(&format!("OAuth callback failed: {err}")),
            )
        }
    }
}

async fn handle_oauth_callback_inner(
    _ctx: OauthCallbackContext<'_>,
    _provider_id: &str,
    _query_string: &str,
) -> Result<String> {
    Err(anyhow!("not implemented yet"))
}

fn html_response(status: u16, body: &str) -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(status)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("build hyper response")
}

fn error_html(message: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Greentic OAuth — Error</title>
<style>body {{ font-family: system-ui; padding: 3rem; text-align: center; color: #1f2937; }} h1 {{ color: #dc2626; }}</style>
</head>
<body><h1>Login failed</h1><p>{message}</p><p><a href="/v1/web/webchat/demo/">Return to chat</a></p></body>
</html>"#,
        message = html_escape(message),
    )
}

fn success_html(tenant: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Greentic OAuth — Login Successful</title>
<meta http-equiv="refresh" content="2;url=/v1/web/webchat/{tenant}/">
<style>body {{ font-family: system-ui; padding: 3rem; text-align: center; color: #1f2937; }} h1 {{ color: #16a34a; }}</style>
</head>
<body><h1>Login successful</h1><p>You can close this window and return to the chat.</p>
<p><a href="/v1/web/webchat/{tenant}/">Return to chat</a></p>
<script>setTimeout(() => window.close(), 1500);</script>
</body>
</html>"#,
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_basic() {
        assert_eq!(html_escape("a<b>&c"), "a&lt;b&gt;&amp;c");
    }

    #[test]
    fn success_html_includes_tenant_and_redirect() {
        let h = success_html("demo");
        assert!(h.contains("/v1/web/webchat/demo/"));
        assert!(h.contains("Login successful"));
    }
}
```

- [ ] **Step 2: Declare module in `src/lib.rs`**

Add:
```rust
pub mod oauth_callback;
```

- [ ] **Step 3: Build to confirm imports resolve**

```bash
cargo build -p greentic-start --all-features 2>&1 | tail -10
```

Expected: clean. (`http_body_util`, `hyper`, `url::form_urlencoded` should already be in deps via existing http_ingress code. If not, add them.)

- [ ] **Step 4: Run the new tests**

```bash
cargo test -p greentic-start --all-features -- oauth_callback::tests
```

Expected: 2 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/oauth_callback.rs src/lib.rs
git commit -m "feat(oauth-callback): module skeleton with success/error HTML"
```

---

## Task 12: oauth_callback — query parsing + session consume (TDD)

**Files:**
- Modify: `src/oauth_callback.rs`

- [ ] **Step 1: Add a small parser fn and a test**

Inside `src/oauth_callback.rs`, add this near the top of the implementation block (before `handle_oauth_callback`):

```rust
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

fn parse_callback_query(query_string: &str) -> CallbackParams {
    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut error_description = None;
    for (k, v) in form_urlencoded::parse(query_string.as_bytes()) {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            "error" => error = Some(v.into_owned()),
            "error_description" => error_description = Some(v.into_owned()),
            _ => {}
        }
    }
    CallbackParams {
        code,
        state,
        error,
        error_description,
    }
}
```

- [ ] **Step 2: Add tests**

In `mod tests`:

```rust
    #[test]
    fn parse_callback_query_extracts_code_and_state() {
        let p = parse_callback_query("code=abc&state=xyz&unrelated=1");
        assert_eq!(p.code.as_deref(), Some("abc"));
        assert_eq!(p.state.as_deref(), Some("xyz"));
        assert!(p.error.is_none());
    }

    #[test]
    fn parse_callback_query_extracts_error_fields() {
        let p = parse_callback_query("error=access_denied&error_description=user+canceled");
        assert_eq!(p.error.as_deref(), Some("access_denied"));
        assert_eq!(p.error_description.as_deref(), Some("user canceled"));
        assert!(p.code.is_none());
    }
```

- [ ] **Step 3: Implement initial flow in `handle_oauth_callback_inner` — error param + session consume**

Replace the stub `handle_oauth_callback_inner` body with:

```rust
async fn handle_oauth_callback_inner(
    ctx: OauthCallbackContext<'_>,
    provider_id: &str,
    query_string: &str,
) -> Result<String> {
    let params = parse_callback_query(query_string);

    if let Some(err) = params.error {
        let detail = params
            .error_description
            .unwrap_or_else(|| "OAuth provider returned an error".to_string());
        return Err(anyhow!("provider error: {err} — {detail}"));
    }

    let state = params
        .state
        .ok_or_else(|| anyhow!("callback missing 'state' query param"))?;
    let code = params
        .code
        .ok_or_else(|| anyhow!("callback missing 'code' query param"))?;

    let session: PersistedSession = ctx
        .session_store
        .consume(&state)
        .map_err(|err| anyhow!("session not found or already used: {err}"))?;

    if session.provider_id != provider_id {
        return Err(anyhow!(
            "provider_id mismatch: callback path says {provider_id}, session says {}",
            session.provider_id
        ));
    }

    // Tasks 13-15 will fill in the rest. For now, just acknowledge.
    let _ = code;
    let _ = ctx.runner_host;
    let _ = ctx.bundle_root;
    let _ = ctx.gateway_port;
    Ok(success_html(&session.tenant))
}
```

- [ ] **Step 4: Run new + existing tests**

```bash
cargo test -p greentic-start --all-features -- oauth_callback::tests
```

Expected: 4 tests pass (2 from Task 11 + 2 new).

- [ ] **Step 5: Commit**

```bash
git add src/oauth_callback.rs
git commit -m "feat(oauth-callback): parse callback query and consume session"
```

---

## Task 13: oauth_callback — token exchange via reqwest

**Files:**
- Modify: `src/oauth_callback.rs`

- [ ] **Step 1: Add the token exchange fn**

Add below `parse_callback_query`:

```rust
#[derive(Debug, serde::Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

async fn exchange_code_for_token(
    provider: &OauthProviderConfig,
    redirect_uri: &str,
    code: &str,
    code_verifier: &str,
) -> Result<TokenResponse> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|err| anyhow!("build reqwest client: {err}"))?;

    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", provider.client_id.as_str()),
        ("client_secret", provider.client_secret.as_str()),
        ("code_verifier", code_verifier),
    ];

    let resp = client
        .post(&provider.token_url)
        .header("Accept", "application/json")
        .header("User-Agent", "greentic-start/oauth-callback")
        .form(&form)
        .send()
        .await
        .map_err(|err| anyhow!("token endpoint request failed: {err}"))?;

    let status = resp.status();
    let body_text = resp
        .text()
        .await
        .map_err(|err| anyhow!("read token response body: {err}"))?;

    // GitHub returns either JSON (when Accept: application/json) or form-encoded.
    let parsed: TokenResponse = if body_text.trim_start().starts_with('{') {
        serde_json::from_str(&body_text)
            .map_err(|err| anyhow!("token response not valid JSON: {err} — body: {body_text}"))?
    } else {
        // form-encoded fallback
        let mut access_token = None;
        let mut token_type = None;
        let mut scope = None;
        let mut refresh_token = None;
        let mut error = None;
        let mut error_description = None;
        for (k, v) in form_urlencoded::parse(body_text.as_bytes()) {
            match k.as_ref() {
                "access_token" => access_token = Some(v.into_owned()),
                "token_type" => token_type = Some(v.into_owned()),
                "scope" => scope = Some(v.into_owned()),
                "refresh_token" => refresh_token = Some(v.into_owned()),
                "error" => error = Some(v.into_owned()),
                "error_description" => error_description = Some(v.into_owned()),
                _ => {}
            }
        }
        TokenResponse {
            access_token,
            token_type,
            scope,
            refresh_token,
            error,
            error_description,
        }
    };

    if let Some(err) = parsed.error.as_deref() {
        return Err(anyhow!(
            "token endpoint returned error {err}: {}",
            parsed.error_description.as_deref().unwrap_or("")
        ));
    }
    if !status.is_success() {
        return Err(anyhow!(
            "token endpoint HTTP {status}: {body_text}"
        ));
    }
    if parsed.access_token.is_none() {
        return Err(anyhow!("token response missing access_token"));
    }
    Ok(parsed)
}
```

- [ ] **Step 2: Wire token exchange into `handle_oauth_callback_inner`**

Update the body to call exchange_code_for_token after the session consume. Replace the stub `let _ = code; ...` lines with:

```rust
    let provider_cfg =
        oauth_envelope::load_provider_config(ctx.bundle_root, &session.provider_pack_id)?;
    let redirect_uri = format!(
        "http://127.0.0.1:{}/v1/oauth/callback/{}",
        ctx.gateway_port, provider_id,
    );
    let token_resp =
        exchange_code_for_token(&provider_cfg, &redirect_uri, &code, &session.code_verifier)
            .await?;
    let access_token = token_resp
        .access_token
        .as_ref()
        .ok_or_else(|| anyhow!("access_token missing after exchange"))?
        .clone();

    crate::operator_log::info(
        module_path!(),
        format!(
            "[oauth callback] token exchanged for provider={provider_id} tenant={} conv={}",
            session.tenant, session.conversation_id
        ),
    );

    // Tasks 14-15 will persist + inject. For now, log and return success HTML.
    let _ = access_token;
    Ok(success_html(&session.tenant))
```

- [ ] **Step 3: Build (token exchange fn is hard to unit test without mocking)**

```bash
cargo build -p greentic-start --all-features 2>&1 | tail -10
```

Expected: clean.

- [ ] **Step 4: Run the existing oauth_callback tests**

```bash
cargo test -p greentic-start --all-features -- oauth_callback::tests
```

Expected: 4 tests still pass (no new tests added in this task because mocking reqwest is complex; manual E2E in Task 19 covers the happy path).

- [ ] **Step 5: Commit**

```bash
git add src/oauth_callback.rs
git commit -m "feat(oauth-callback): inline reqwest token exchange against provider token endpoint"
```

---

## Task 14: oauth_callback — persist access token to secrets

**Files:**
- Modify: `src/oauth_callback.rs`

- [ ] **Step 1: Add the secrets persistence helper**

At the bottom of the file:

```rust
async fn persist_access_token(
    runner_host: &DemoRunnerHost,
    session: &PersistedSession,
    access_token: &str,
) -> Result<String> {
    use greentic_secrets_lib::{ApplyOptions, SecretFormat, SeedDoc, SeedEntry, SeedValue, apply_seed};

    let env = std::env::var("GREENTIC_ENV").unwrap_or_else(|_| "dev".to_string());
    let team = session.team.as_deref().unwrap_or("_");
    let uri = format!(
        "secrets://{env}/{}/{}/{}/access_token",
        session.tenant, team, session.provider_pack_id,
    );

    let entry = SeedEntry {
        uri: uri.clone(),
        format: SecretFormat::Text,
        value: SeedValue::Text {
            text: access_token.to_string(),
        },
        description: Some(format!(
            "OAuth access_token for {} (callback)",
            session.provider_id
        )),
    };

    let manager = runner_host.secrets_handle();
    let store = manager.manager();
    let report = apply_seed(
        store.as_ref(),
        &SeedDoc {
            entries: vec![entry],
        },
        ApplyOptions::default(),
    )
    .await;

    if !report.failed.is_empty() {
        return Err(anyhow!(
            "failed to persist access_token: {:?}",
            report.failed
        ));
    }
    Ok(uri)
}
```

Note: this is the same `apply_seed` pattern used in `src/qa_persist.rs`. Verify the imports work — if `greentic_secrets_lib::SeedEntry` etc. aren't exposed at that path, look at how `qa_persist.rs` imports them and copy that pattern.

- [ ] **Step 2: Call it from `handle_oauth_callback_inner`**

After the `let access_token = ...` block in handle_oauth_callback_inner, add:

```rust
    let secret_uri = persist_access_token(ctx.runner_host, &session, &access_token).await?;
    crate::operator_log::info(
        module_path!(),
        format!("[oauth callback] persisted access_token to {secret_uri}"),
    );
```

- [ ] **Step 3: Build**

```bash
cargo build -p greentic-start --all-features 2>&1 | tail -15
```

Expected: clean. If imports fail, look at `src/qa_persist.rs:14` for the canonical import path.

- [ ] **Step 4: Run tests (no new tests; secrets persistence is integration-tested manually in Task 19)**

```bash
cargo test -p greentic-start --all-features -- oauth_callback::tests
```

Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/oauth_callback.rs
git commit -m "feat(oauth-callback): persist access_token via secrets seed API"
```

---

## Task 15: oauth_callback — inject oauth_login_success activity

**Files:**
- Modify: `src/oauth_callback.rs`

- [ ] **Step 1: Add the injection helper based on Task 10's findings**

Two paths depending on Task 10's investigation:

**Path A — JWT mint helper is callable:**

```rust
async fn inject_oauth_login_success_activity(
    runner_host: &DemoRunnerHost,
    gateway_port: u16,
    tenant: &str,
    conversation_id: &str,
) -> Result<()> {
    let token = mint_directline_system_token(runner_host, tenant, conversation_id)?;
    let url = format!(
        "http://127.0.0.1:{gateway_port}/v1/messaging/webchat/{tenant}/v3/directline/conversations/{conversation_id}/activities?tenant={tenant}",
    );
    let body = serde_json::json!({
        "type": "message",
        "from": {"id": "system", "name": "OAuth Callback"},
        "text": "oauth_login_success"
    });
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|err| anyhow!("inject loopback POST failed: {err}"))?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "inject loopback POST returned {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    Ok(())
}

fn mint_directline_system_token(
    _runner_host: &DemoRunnerHost,
    _tenant: &str,
    _conversation_id: &str,
) -> Result<String> {
    // Look up the actual mint helper located in Task 10. Replace this body
    // with the actual call. If the helper is in src/http_ingress/mod.rs and
    // private, expose it as `pub(crate) fn`.
    Err(anyhow!("mint_directline_system_token: integrate with existing token endpoint helper"))
}
```

**Path B — JWT mint not callable, write to state store directly OR skip:**

```rust
async fn inject_oauth_login_success_activity(
    _runner_host: &DemoRunnerHost,
    _gateway_port: u16,
    _tenant: &str,
    _conversation_id: &str,
) -> Result<()> {
    // No automated injection. The user must re-send "Get started" in the
    // chat after the callback completes. The flow's auth_choice node will
    // then see the access_token in secrets and skip to the next state.
    crate::operator_log::info(
        module_path!(),
        "[oauth callback] activity injection skipped (manual re-send required)",
    );
    Ok(())
}
```

Pick Path A if the JWT mint helper is accessible. Pick Path B otherwise. Document the choice with a comment block above the fn explaining which fallback was selected and why.

- [ ] **Step 2: Call it from `handle_oauth_callback_inner` (best-effort)**

Below the secrets persistence call:

```rust
    if let Err(err) = inject_oauth_login_success_activity(
        ctx.runner_host,
        ctx.gateway_port,
        &session.tenant,
        &session.conversation_id,
    )
    .await
    {
        crate::operator_log::warn(
            module_path!(),
            format!("[oauth callback] activity injection failed (non-fatal): {err}"),
        );
    }
```

Activity injection is best-effort: if it fails, the user still sees the success HTML and the token is persisted. Worst case is they need to manually re-send "Get started".

- [ ] **Step 3: Build**

```bash
cargo build -p greentic-start --all-features 2>&1 | tail -10
```

Expected: clean. If Path A and the mint helper isn't found, fall back to Path B before this build.

- [ ] **Step 4: Run tests**

```bash
cargo test -p greentic-start --all-features 2>&1 | tail -10
```

Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/oauth_callback.rs
git commit -m "feat(oauth-callback): inject oauth_login_success activity (best-effort)"
```

---

## Task 16: Register /v1/oauth/callback route in http_ingress

**Files:**
- Modify: `src/http_ingress/mod.rs`

- [ ] **Step 1: Locate the route dispatch**

```bash
grep -n "fn handle_request\|match path\|/v1/messaging\|/v1/web\|fn route" src/http_ingress/mod.rs | head -20
```

Find the function that pattern-matches request paths to handlers. It probably has a series of `if path.starts_with(...)` or similar.

- [ ] **Step 2: Add an OAuth callback branch ahead of the messaging branches**

Insert near the top of the path matching (so it takes precedence over generic patterns):

```rust
    // OAuth callback: /v1/oauth/callback/{provider_id}
    if let Some(provider_id) = path.strip_prefix("/v1/oauth/callback/") {
        if !provider_id.is_empty() && !provider_id.contains('/') {
            let bundle_root: PathBuf = bundle_path.to_path_buf();
            let session_store = OauthSessionStore::new(bundle_root.clone());
            let ctx = crate::oauth_callback::OauthCallbackContext {
                bundle_root: &bundle_root,
                session_store: &session_store,
                runner_host,
                gateway_port: runner_host.gateway_port(),
            };
            let resp =
                crate::oauth_callback::handle_oauth_callback(ctx, provider_id, query_string)
                    .await;
            return Ok(resp);
        }
    }
```

The exact local variable names (`bundle_path`, `runner_host`, `query_string`) depend on the existing handler signature. Read the surrounding context and adapt names accordingly.

Add the necessary imports at the top of the file:
```rust
use crate::oauth_session_store::OauthSessionStore;
use std::path::PathBuf;
```

- [ ] **Step 3: Build**

```bash
cargo build -p greentic-start --all-features 2>&1 | tail -15
```

Expected: clean. If the existing route dispatch is structured differently from what I assumed (e.g., uses a router crate, or has middleware layers), read the code carefully and add the new route in the existing pattern.

- [ ] **Step 4: Run all tests**

```bash
cargo test -p greentic-start --all-features 2>&1 | tail -10
```

Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/http_ingress/mod.rs
git commit -m "feat(http-ingress): register /v1/oauth/callback/{provider_id} route"
```

---

## Task 17: Full CI sweep

**Files:** none

- [ ] **Step 1: Format**

```bash
cargo fmt --all
git diff --stat
```

If any files changed, commit:
```bash
git add -u
git commit -m "chore: cargo fmt"
```

- [ ] **Step 2: Clippy with warnings as errors**

```bash
cargo clippy -p greentic-start --all-targets --all-features -- -D warnings 2>&1 | tail -20
```

Expected: clean. Fix any issues inline.

- [ ] **Step 3: Full test suite**

```bash
cargo test -p greentic-start --all-features 2>&1 | grep -E "test result:|FAILED" | head
```

Expected: all `ok`, no `FAILED`. Total test count should be ~440+ (Phase 1's 427 + new ~17 from Phase 2/3).

- [ ] **Step 4: Local CI script**

```bash
bash ci/local_check.sh 2>&1 | tail -10
```

Expected: exit 0.

- [ ] **Step 5: No commit unless fmt changed something**

---

## Task 18: Manual E2E end-to-end against github-mcp-demo-bundle

**Files:** none

This is the moment of truth. The Phase 9 of the original plan plus full round-trip.

- [ ] **Step 1: Install patched binary**

```bash
cd /home/bimbim/works/greentic/greentic-start
cargo install --path . --locked --force 2>&1 | tail -5
greentic-start --version
```

- [ ] **Step 2: Override bundle gateway port if needed**

Same as Task 9 Step 2. Skip if 8080 is already free.

- [ ] **Step 3: Update setup-answers.json public_base_url to match the gateway**

The OAuth provider needs to know its own public-facing URL so that the redirect_uri matches. Edit `state/config/oauth-oidc-generic/setup-answers.json` and ensure `public_base_url` is `http://127.0.0.1:8090` (or whichever port the gateway listens on). Back up first.

```bash
cp /home/bimbim/works/greentic/github-mcp-demo-bundle/state/config/oauth-oidc-generic/setup-answers.json /tmp/setup-answers.json.bak
python3 -c "
import json
p = '/home/bimbim/works/greentic/github-mcp-demo-bundle/state/config/oauth-oidc-generic/setup-answers.json'
d = json.load(open(p))
d['public_base_url'] = 'http://127.0.0.1:8090'
json.dump(d, open(p, 'w'), indent=2)
print('public_base_url:', d['public_base_url'])
"
```

- [ ] **Step 4: Verify the GitHub OAuth app's callback URL allowlist matches**

Open the GitHub OAuth app settings (the one with `client_id=Ov23ligPicBfeZw44MjZ`) and confirm `http://127.0.0.1:8090/v1/oauth/callback/github` is in the Authorization callback URL list. If not, add it.

If you can't access the GitHub app settings, use a tunnel like cloudflared or ngrok and update both `setup-answers.json#public_base_url` AND the GitHub app callback list to match the tunnel URL.

- [ ] **Step 5: Start bundle**

```bash
cd /home/bimbim/works/greentic/github-mcp-demo-bundle
greentic-start --locale en start --bundle . --nats off --cloudflared off --ngrok off > /tmp/gh-mcp-e2e.log 2>&1 &
sleep 10
ss -tlnp 2>&1 | grep ':8090'
```

- [ ] **Step 6: Open webchat in browser**

```bash
xdg-open "http://127.0.0.1:8090/v1/web/webchat/demo/" || echo "open manually: http://127.0.0.1:8090/v1/web/webchat/demo/"
```

- [ ] **Step 7: In the webchat UI, type "Get started" and send**

Verify the bot reply card has a "Login with OAuth" button. Right-click the button → Inspect → confirm the URL is `https://github.com/login/oauth/authorize?...&state=...&code_challenge=...`.

- [ ] **Step 8: Click the button**

A new browser tab opens with the GitHub OAuth consent screen. Authorize the app.

- [ ] **Step 9: Verify callback success**

After authorize, GitHub redirects to `http://127.0.0.1:8090/v1/oauth/callback/github?code=...&state=...`. You should see the success HTML page ("Login successful, You can close this window…"). The page should auto-close after 1.5s or you can click "Return to chat".

If you see an error page, check the operator log:
```bash
grep -E "oauth callback|exchange_code|persist_access_token|inject" /home/bimbim/works/greentic/github-mcp-demo-bundle/logs/operator.log | tail -30
```

- [ ] **Step 10: Verify access token persisted**

```bash
ls /home/bimbim/works/greentic/github-mcp-demo-bundle/.greentic/dev/ 2>&1
grep -r "access_token" /home/bimbim/works/greentic/github-mcp-demo-bundle/.greentic/ 2>&1 | head
```

Expected: a secret file containing the access_token.

- [ ] **Step 11: Verify webchat advances (or fall back to manual re-send)**

Return to the webchat tab. Two possible outcomes:
- **Outcome A — flow advances automatically:** A new bot message appears (e.g., "MCP ready" or whatever `mcp_ready` node renders). Activity injection worked. ✅
- **Outcome B — webchat is silent:** Activity injection failed or flow didn't pause. Type "Get started" again in the webchat. The flow should now see the access_token in secrets and advance to the next state without showing the OAuth card again. Document this as a known UX limitation.

- [ ] **Step 12: Stop bundle + restore configs**

```bash
pkill -f "greentic-start.*--bundle ." 2>&1
sleep 2
cp /tmp/setup-answers.json.bak /home/bimbim/works/greentic/github-mcp-demo-bundle/state/config/oauth-oidc-generic/setup-answers.json
rm /tmp/setup-answers.json.bak
[ -f /tmp/greentic.demo.yaml.bak ] && cp /tmp/greentic.demo.yaml.bak /home/bimbim/works/greentic/github-mcp-demo-bundle/greentic.demo.yaml
[ -f /tmp/greentic.demo.yaml.bak ] && rm /tmp/greentic.demo.yaml.bak
```

- [ ] **Step 13: No commit — verification only**

Record the outcome (A or B) in your notes for the changelog (Task 19).

---

## Task 19: Changelog + push branch

**Files:**
- Create: `/home/bimbim/works/greentic/updates/2026-04-11/greentic-start.md`

- [ ] **Step 1: Create changelog directory if needed**

```bash
mkdir -p /home/bimbim/works/greentic/updates/2026-04-11
```

- [ ] **Step 2: Write the changelog**

Create `/home/bimbim/works/greentic/updates/2026-04-11/greentic-start.md` with this content (adjust the "Verification result" line based on Task 18 outcome A or B):

```markdown
# greentic-start — 2026-04-11

## Fix: OAuth card full round-trip in messaging egress

**Branch:** `fix/oauth-card-messaging-wiring`

**Problem:** Outbound Adaptive Cards with `oauth://start` placeholders were sent to the webchat client unresolved. The "Login with OAuth" button in the github-mcp demo bundle did nothing because (a) the host-side wiring of `CardRenderer::render_if_needed` was only on the entry_flows dispatch path which messaging egress never hits, and (b) the capability dispatch to `oidc-provider-runtime` failed at the WASM boundary because the host side did not wrap the payload in the required `WitDispatchInput { host, provider, input }` envelope.

**Fix (3 phases on the same branch):**

**Phase 1 — Wiring** (commits `3b43f53` … `5bd729f`):
- Added private helper `resolve_oauth_card_placeholders` in `src/http_ingress/messaging.rs`.
- Called it in the existing outputs loop right after `ensure_card_i18n_resolved` and before `egress::render_plan`.
- Removed the dead `render_if_needed` call in `src/runner_host/dispatch.rs` and the unused `card_renderer` field on `DemoRunnerHost`.
- 4 unit tests (happy path, error path, no-op, team_id regression) covering helper behavior.

**Phase 2 — Envelope wrapping + session store** (commits from this batch):
- New module `src/oauth_envelope.rs`: provider config loader (reads `state/config/{pack_id}/setup-answers.json`), public base URL loader, `wrap_dispatch_envelope` builder.
- New module `src/oauth_session_store.rs`: file-based session store at `state/oauth-sessions/{state}.json` with state token + PKCE verifier + 10-minute TTL GC.
- Extended `runner_host::invoke_capability` to wrap payloads as `WitDispatchInput { host, provider, input }` when `cap_id == CAP_OAUTH_CARD_V1`.
- Added `gateway_port` field to `DemoRunnerHost` so the OAuth callback URL can be built.
- Updated `resolve_oauth_card_placeholders` to create a session and pass `state + code_challenge + tenant + scopes` to the capability dispatcher.
- Removed obsolete `src/cards.rs` (`CardRenderer` no longer used).

**Phase 3 — Callback + token exchange + flow resume**:
- New module `src/oauth_callback.rs`: HTTP handler for `/v1/oauth/callback/{provider_id}`.
- Inline `reqwest` token exchange against the provider's `token_url` (no broker dependency).
- Persist `access_token` to the bundle's dev secrets store via the existing `apply_seed` API.
- Best-effort injection of an `oauth_login_success` activity into the originating conversation via loopback Direct Line POST.
- Success / error HTML response with auto-close and meta-refresh fallback.
- New static route `/v1/oauth/callback/{provider_id}` registered in `src/http_ingress/mod.rs`.

**Verification result:** [FILL: outcome A or B from Task 18]

- Phase 1: 4 unit tests, all green
- Phase 2: ~10 unit tests across `oauth_envelope` and `oauth_session_store`, all green
- Phase 3: 4 unit tests in `oauth_callback`, all green
- `cargo fmt --all -- --check`, `cargo clippy -- -D warnings`, `cargo test --all-features` all clean
- Manual E2E against `github-mcp-demo-bundle` confirmed: card renders with valid GitHub OAuth URL, click → real GitHub OAuth → callback completes → access_token persisted

**New dependency:** `reqwest = { version = "0.12", features = ["json", "rustls-tls", "blocking"] }` (or workspace-aligned version)

**Spec:** `greentic-start/docs/superpowers/specs/2026-04-11-oauth-card-full-roundtrip-design.md` (Phase 2 + 3) and `2026-04-11-oauth-card-messaging-wiring-design.md` (Phase 1)
**Plan:** `greentic-start/docs/superpowers/plans/2026-04-11-oauth-card-full-roundtrip.md` (this plan)
```

- [ ] **Step 3: This file is OUTSIDE the greentic-start repo**

The `updates/` directory lives in the parent workspace, not in greentic-start. Don't try to commit it from inside greentic-start. Just leave the file in place; it'll be picked up by whatever changelog aggregation lives at the workspace level.

- [ ] **Step 4: Run final CI sweep one more time**

```bash
cd /home/bimbim/works/greentic/greentic-start
cargo fmt --all -- --check && \
cargo clippy -p greentic-start --all-targets --all-features -- -D warnings && \
cargo test -p greentic-start --all-features 2>&1 | tail -5
```

Expected: all green.

- [ ] **Step 5: Push the branch**

```bash
git push -u origin fix/oauth-card-messaging-wiring
```

Expected: branch pushed; the URL in the output is the page where you'd open the PR. Do NOT auto-create the PR — the user will do it manually after reviewing.

- [ ] **Step 6: Stop. Hand off to user with the push URL.**

Print the count of commits on the branch (`git log --oneline fix/oauth-card-messaging-wiring ^origin/main | wc -l`) and the latest commit SHA so the user can verify what's about to be merged.
