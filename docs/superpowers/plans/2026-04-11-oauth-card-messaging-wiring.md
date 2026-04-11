# OAuth Card Messaging Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `CardRenderer::render_if_needed` into the messaging egress pipeline so outbound Adaptive Cards carrying `oauth://start` are resolved into real OAuth authorize URLs before reaching the webchat client.

**Architecture:** Add a private helper `resolve_oauth_card_placeholders` in `src/http_ingress/messaging.rs` that wraps `CardRenderer::render_if_needed`. Call it in the existing outputs loop right after `ensure_card_i18n_resolved` and before `egress::render_plan`. Remove the dead call to `render_if_needed` inside `src/runner_host/dispatch.rs` (the entry_flows branch is never reached by messaging egress ops). Fail-soft on any error: log warn, keep the envelope unchanged, continue.

**Tech Stack:** Rust 1.94.0 / edition 2024, `anyhow`, `serde_json`, `greentic-types` (`ChannelMessageEnvelope`), the local `CardRenderer` in `src/cards.rs`.

**Branch:** `fix/oauth-card-messaging-wiring` (already created from `origin/main`)

**Spec:** `docs/superpowers/specs/2026-04-11-oauth-card-messaging-wiring-design.md`

---

## File Structure

Files this plan will touch, with responsibilities:

| File | Role after fix |
|---|---|
| `src/http_ingress/messaging.rs` | Adds private fn `resolve_oauth_card_placeholders` (helper) + invokes it in the outputs loop. New unit tests live in the existing `#[cfg(test)] mod tests`. |
| `src/runner_host/dispatch.rs` | Loses the dead `self.card_renderer.render_if_needed(...)` call in the `entry_flows` branch. All other dispatch logic stays. |
| `src/runner_host/mod.rs` | Loses the `card_renderer: CardRenderer` struct field and its initialization. `CardRenderer::new()` still exists in `src/cards.rs` and is instantiated locally by the helper. |
| `src/cards.rs` | **Unchanged.** `CardRenderer::render_if_needed` and its two existing unit tests remain exactly as-is. |
| `updates/2026-04-11/greentic-start.md` | New changelog entry describing the fix. |

Key data contracts:
- `ChannelMessageEnvelope.metadata: BTreeMap<String, String>` — values are strings only. The helper must serialize audit fields as JSON-encoded strings (not nested JSON objects) before inserting.
- `CardRenderer::render_if_needed` works on `serde_json::Value` with shape `{ "metadata": { "adaptive_card": "<stringified card JSON>" }, ... }`. The helper must build this minimal payload from the envelope, call the renderer, and extract the resolved adaptive_card back out — it must NOT round-trip through `ChannelMessageEnvelope` because the type system rejects non-string metadata values.

---

## Task 1: Add the helper skeleton and failing happy-path test

**Files:**
- Modify: `src/http_ingress/messaging.rs` — append helper stub at end of file, add test in existing `mod tests`

- [ ] **Step 1: Add the helper function as a stub that always returns `Ok(())` without mutating the envelope**

Open `src/http_ingress/messaging.rs`. Add the following helper at the end of the file, right before `#[cfg(test)]` (around the current line 335):

```rust
/// Resolve OAuth card placeholders in an outbound envelope by delegating to
/// `greentic.cap.oauth.card.v1`. Operates on a minimal JSON payload to avoid
/// round-tripping the envelope through serde (metadata is a string map,
/// incompatible with the nested JSON values the capability produces).
///
/// Fail-soft: any internal error is returned to the caller, which is expected
/// to log and continue with the unresolved envelope.
fn resolve_oauth_card_placeholders(
    provider_type: &str,
    envelope: &mut ChannelMessageEnvelope,
    dispatcher: impl FnMut(&str, &str, &[u8]) -> anyhow::Result<serde_json::Value>,
) -> anyhow::Result<()> {
    let _ = (provider_type, envelope, dispatcher);
    Ok(())
}
```

- [ ] **Step 2: Add the happy-path unit test inside `mod tests`**

Inside `src/http_ingress/messaging.rs`, inside `#[cfg(test)] mod tests { ... }`, add this test **after** the existing `envelope()` helper (so it can use it):

```rust
    fn envelope_with_oauth_card() -> ChannelMessageEnvelope {
        let mut env = envelope();
        let card = serde_json::json!({
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.5",
            "body": [{"type": "TextBlock", "text": "Sign in", "wrap": true}],
            "actions": [{
                "type": "Action.OpenUrl",
                "title": "Login with OAuth",
                "url": "oauth://start"
            }]
        });
        env.metadata
            .insert("adaptive_card".to_string(), card.to_string());
        env
    }

    #[test]
    fn resolve_oauth_card_placeholders_swaps_url_from_capability() {
        let mut env = envelope_with_oauth_card();
        let resolved_url =
            "https://github.com/login/oauth/authorize?client_id=abc&state=xyz".to_string();
        let resolved_url_for_closure = resolved_url.clone();

        let dispatcher = move |cap_id: &str,
                               op: &str,
                               _input: &[u8]|
              -> anyhow::Result<serde_json::Value> {
            assert_eq!(cap_id, "greentic.cap.oauth.card.v1");
            assert_eq!(op, "oauth.card.resolve");
            let resolved_card = serde_json::json!({
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.5",
                "body": [{"type": "TextBlock", "text": "Sign in", "wrap": true}],
                "actions": [{
                    "type": "Action.OpenUrl",
                    "title": "Login with OAuth",
                    "url": resolved_url_for_closure.clone()
                }]
            });
            Ok(serde_json::json!({
                "resolved_card": resolved_card.to_string(),
                "start_url": resolved_url_for_closure.clone(),
            }))
        };

        let result =
            resolve_oauth_card_placeholders("messaging.webchat-gui", &mut env, dispatcher);
        assert!(result.is_ok(), "helper should succeed: {result:?}");

        let card = env
            .metadata
            .get("adaptive_card")
            .expect("adaptive_card present");
        assert!(
            card.contains(&resolved_url),
            "resolved URL missing from card: {card}"
        );
        assert!(
            !card.contains("oauth://start"),
            "oauth://start marker still present in card: {card}"
        );
        assert!(
            env.metadata.contains_key("oauth_card_resolved"),
            "audit metadata missing"
        );
    }
```

- [ ] **Step 3: Run the new test and confirm it fails**

```bash
cd /home/bimbim/works/greentic/greentic-start
cargo test -p greentic-start --all-features -- tests::resolve_oauth_card_placeholders_swaps_url_from_capability --exact
```

Expected output: FAIL with `assertion failed: card.contains(&resolved_url)` or similar — the stub helper returned `Ok(())` without touching the envelope, so the card still contains `oauth://start`.

- [ ] **Step 4: Commit the failing test and stub**

```bash
git add src/http_ingress/messaging.rs
git commit -m "test(messaging): add failing test for oauth card placeholder resolution"
```

---

## Task 2: Implement the helper body to make the happy-path test pass

**Files:**
- Modify: `src/http_ingress/messaging.rs` — replace stub body

- [ ] **Step 1: Add `use crate::cards::CardRenderer;` to the imports at the top of the file**

Open `src/http_ingress/messaging.rs`. Just under the existing `use crate::runner_host::{DemoRunnerHost, OperatorContext};` line (around line 12), add:

```rust
use crate::cards::CardRenderer;
```

- [ ] **Step 2: Replace the stub body of `resolve_oauth_card_placeholders`**

Replace the entire function body (the `let _ = (...); Ok(())` stub) with this implementation:

```rust
fn resolve_oauth_card_placeholders(
    provider_type: &str,
    envelope: &mut ChannelMessageEnvelope,
    dispatcher: impl FnMut(&str, &str, &[u8]) -> anyhow::Result<serde_json::Value>,
) -> anyhow::Result<()> {
    let Some(card_str) = envelope.metadata.get("adaptive_card").cloned() else {
        return Ok(());
    };

    // Minimal payload matching the shape CardRenderer::render_if_needed expects.
    // We cannot round-trip the full ChannelMessageEnvelope because `metadata`
    // is `BTreeMap<String, String>` and the renderer inserts nested JSON
    // values under /metadata/oauth_card_resolved.
    let tenant_value = serde_json::json!({
        "tenant_id": envelope.tenant.tenant_id,
        "team": envelope.tenant.team,
    });
    let payload = serde_json::json!({
        "metadata": { "adaptive_card": card_str },
        "tenant": tenant_value,
    });
    let payload_bytes =
        serde_json::to_vec(&payload).map_err(|err| anyhow::anyhow!("serialize payload: {err}"))?;

    let renderer = CardRenderer::new();
    let outcome = renderer.render_if_needed(provider_type, &payload_bytes, dispatcher)?;

    // Fast path: nothing changed (no placeholder, or renderer returned the
    // original bytes unchanged).
    if outcome.bytes == payload_bytes {
        return Ok(());
    }

    let rewritten: serde_json::Value = serde_json::from_slice(&outcome.bytes)
        .map_err(|err| anyhow::anyhow!("parse rewritten payload: {err}"))?;

    if let Some(new_card) = rewritten
        .pointer("/metadata/adaptive_card")
        .and_then(serde_json::Value::as_str)
    {
        envelope
            .metadata
            .insert("adaptive_card".to_string(), new_card.to_string());
    }
    if let Some(audit) = rewritten.pointer("/metadata/oauth_card_resolved") {
        envelope
            .metadata
            .insert("oauth_card_resolved".to_string(), audit.to_string());
    }
    if let Some(downgrade) = rewritten
        .pointer("/metadata/oauth_card_downgrade")
        .filter(|v| !v.is_null())
    {
        envelope
            .metadata
            .insert("oauth_card_downgrade".to_string(), downgrade.to_string());
    }

    Ok(())
}
```

- [ ] **Step 3: Run the happy-path test again and confirm it passes**

```bash
cargo test -p greentic-start --all-features -- tests::resolve_oauth_card_placeholders_swaps_url_from_capability --exact
```

Expected output: `test result: ok. 1 passed; 0 failed`.

- [ ] **Step 4: Commit the implementation**

```bash
git add src/http_ingress/messaging.rs
git commit -m "feat(messaging): implement resolve_oauth_card_placeholders helper"
```

---

## Task 3: Add fail-soft error-path test

**Files:**
- Modify: `src/http_ingress/messaging.rs` — add second test

- [ ] **Step 1: Add the error-path test in `mod tests`**

Inside `mod tests` in `src/http_ingress/messaging.rs`, below the happy-path test you added in Task 1, add:

```rust
    #[test]
    fn resolve_oauth_card_placeholders_fails_soft_when_dispatcher_errors() {
        let mut env = envelope_with_oauth_card();
        let original_card = env
            .metadata
            .get("adaptive_card")
            .cloned()
            .expect("seed card");

        let dispatcher = |_cap_id: &str,
                          _op: &str,
                          _input: &[u8]|
         -> anyhow::Result<serde_json::Value> {
            Err(anyhow::anyhow!("capability not installed"))
        };

        let result =
            resolve_oauth_card_placeholders("messaging.webchat-gui", &mut env, dispatcher);

        // The helper propagates the error so the caller can log it. The
        // envelope must be left untouched so the caller can still send the
        // card unresolved as a fail-soft fallback.
        assert!(result.is_err(), "dispatcher error should be propagated");
        assert_eq!(
            env.metadata.get("adaptive_card"),
            Some(&original_card),
            "envelope card should be unchanged on dispatcher error"
        );
        assert!(
            !env.metadata.contains_key("oauth_card_resolved"),
            "no audit should be stored on error"
        );
    }

    #[test]
    fn resolve_oauth_card_placeholders_noop_when_no_card_in_metadata() {
        let mut env = envelope(); // no adaptive_card in metadata
        let called = std::cell::Cell::new(false);
        let dispatcher = |_cap_id: &str,
                          _op: &str,
                          _input: &[u8]|
         -> anyhow::Result<serde_json::Value> {
            called.set(true);
            Ok(serde_json::json!({}))
        };

        resolve_oauth_card_placeholders("messaging.webchat-gui", &mut env, dispatcher)
            .expect("no-op succeeds");
        assert!(!called.get(), "dispatcher should not be invoked when no card");
    }
```

- [ ] **Step 2: Run both new tests and confirm they pass**

```bash
cargo test -p greentic-start --all-features -- tests::resolve_oauth_card_placeholders
```

Expected: 3 tests run (swap_url + fails_soft + noop), all pass. If `fails_soft` fails because the helper doesn't propagate errors (e.g. because `render_if_needed`'s closure failure is swallowed), check the error path in `cards.rs:77-81` — the closure's `Err` is supposed to propagate out via `?`.

- [ ] **Step 3: Commit**

```bash
git add src/http_ingress/messaging.rs
git commit -m "test(messaging): add fail-soft and no-op tests for oauth card helper"
```

---

## Task 4: Wire the helper into the egress loop

**Files:**
- Modify: `src/http_ingress/messaging.rs` (line ~86 loop)

- [ ] **Step 1: Insert the helper call right after `ensure_card_i18n_resolved`**

Open `src/http_ingress/messaging.rs`. Find the block around line 86-100 that looks like this:

```rust
        for mut out_envelope in outputs {
            // Ensure i18n tokens are resolved in any adaptive card.  The WASM
            // component *should* resolve them, but when running through
            // greentic-runner-desktop the host resolver is not registered so the
            // component falls back to Handlebars which silently eats unresolved
            // `{{i18n:KEY}}` tokens.  Re-read the card from the pack and apply
            // i18n as a safety net.
            ensure_card_i18n_resolved(&mut out_envelope, &app_pack_path);

            // Standard egress pipeline: render → encode → send_payload.
```

Insert the OAuth card resolution step between `ensure_card_i18n_resolved(...)` and the `// Standard egress pipeline` comment:

```rust
        for mut out_envelope in outputs {
            // Ensure i18n tokens are resolved in any adaptive card.  The WASM
            // component *should* resolve them, but when running through
            // greentic-runner-desktop the host resolver is not registered so the
            // component falls back to Handlebars which silently eats unresolved
            // `{{i18n:KEY}}` tokens.  Re-read the card from the pack and apply
            // i18n as a safety net.
            ensure_card_i18n_resolved(&mut out_envelope, &app_pack_path);

            // Resolve OAuth card placeholders (oauth://start, {{oauth.start_url}},
            // {{oauth.teams.connectionName}}) by delegating to the
            // `greentic.cap.oauth.card.v1` capability. Fail-soft: on any error
            // we log and continue with the unresolved envelope so the rest of
            // the pipeline still runs.
            let provider_type =
                runner_host.canonical_provider_type(Domain::Messaging, provider);
            if let Err(err) = resolve_oauth_card_placeholders(
                &provider_type,
                &mut out_envelope,
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

            // Standard egress pipeline: render → encode → send_payload.
```

Note: the existing call to `runner_host.canonical_provider_type(...)` that appears later in the loop (around current line 136, before `build_send_payload`) can be kept as-is. Having it twice is a minor duplication but keeps the diff local to our insertion. If clippy complains about the shadow/rebind, remove the second call and reuse the `provider_type` binding from above.

- [ ] **Step 2: Build to catch compile errors**

```bash
cargo build -p greentic-start --all-features 2>&1 | tail -30
```

Expected: clean build. If it fails:
- `error[E0425]: cannot find value ctx in this scope` → the closure captures `ctx`; confirm `ctx: &OperatorContext` is the parameter name in `route_messaging_envelopes`.
- `error[E0599]: no method named invoke_capability` → verify `runner_host.invoke_capability` is `pub`. (Confirmed at `src/runner_host/mod.rs:270`.)
- `error: use of moved value` on `provider_type` → if kept the later `let provider_type = ...` at line ~136, rename our earlier binding to `oauth_provider_type` or remove the later one.

- [ ] **Step 3: Run the full messaging test subset**

```bash
cargo test -p greentic-start --all-features -- http_ingress::messaging::tests
```

Expected: all tests in the module pass, including the 3 new OAuth helper tests.

- [ ] **Step 4: Commit**

```bash
git add src/http_ingress/messaging.rs
git commit -m "fix(messaging): call resolve_oauth_card_placeholders in egress loop"
```

---

## Task 5: Remove the dead `render_if_needed` call from dispatch.rs

**Files:**
- Modify: `src/runner_host/dispatch.rs`

- [ ] **Step 1: Open `src/runner_host/dispatch.rs` and find lines 146-177**

The block starts with `let render_outcome = self.card_renderer.render_if_needed(...)` and ends right before `let payload = serde_json::from_slice(&render_outcome.bytes).unwrap_or_else(|_| {`. The exact block to remove:

```rust
            let render_outcome = self.card_renderer.render_if_needed(
                provider_type,
                payload_bytes,
                |cap_id, op, input| {
                    let outcome = self.invoke_capability(cap_id, op, input, ctx)?;
                    if !outcome.success {
                        let reason = outcome
                            .error
                            .clone()
                            .or(outcome.raw.clone())
                            .unwrap_or_else(|| "capability invocation failed".to_string());
                        return Err(anyhow!(
                            "card capability {}:{} failed: {}",
                            cap_id,
                            op,
                            reason
                        ));
                    }
                    outcome.output.ok_or_else(|| {
                        anyhow!(
                            "card capability {}:{} returned no structured output",
                            cap_id,
                            op
                        )
                    })
                },
            )?;
            let payload = serde_json::from_slice(&render_outcome.bytes).unwrap_or_else(|_| {
                json!({
                    "payload": general_purpose::STANDARD.encode(&render_outcome.bytes)
                })
            });
```

- [ ] **Step 2: Replace it with a direct parse of `payload_bytes`**

Replace the entire block above with:

```rust
            let payload = serde_json::from_slice(payload_bytes).unwrap_or_else(|_| {
                json!({
                    "payload": general_purpose::STANDARD.encode(payload_bytes)
                })
            });
```

This preserves the fallback behavior (base64-encode non-JSON payloads) while dropping the unused `render_if_needed` indirection.

- [ ] **Step 3: Remove the now-unused `anyhow` macro import if it was only used by the removed block**

```bash
cargo build -p greentic-start --all-features 2>&1 | grep -E "unused import|anyhow" | head -10
```

If clippy/compiler warns `unused import: anyhow`, open `src/runner_host/dispatch.rs` and remove `anyhow` from `use anyhow::{..., anyhow};` (keep any other items). Otherwise leave it — other code in the file may still use it.

- [ ] **Step 4: Build and verify**

```bash
cargo build -p greentic-start --all-features 2>&1 | tail -20
```

Expected: clean build.

- [ ] **Step 5: Run the dispatch tests**

```bash
cargo test -p greentic-start --all-features -- runner_host::dispatch::tests
```

Expected: all existing tests still pass. None of them assert on `render_if_needed`, so they should be unaffected.

- [ ] **Step 6: Commit**

```bash
git add src/runner_host/dispatch.rs
git commit -m "refactor(dispatch): drop dead render_if_needed call in entry_flows branch"
```

---

## Task 6: Remove the `card_renderer` field from `DemoRunnerHost`

**Files:**
- Modify: `src/runner_host/mod.rs`

- [ ] **Step 1: Remove the field declaration**

Open `src/runner_host/mod.rs`. Find and remove the `card_renderer: CardRenderer,` field from the `DemoRunnerHost` struct (currently at line 48).

Before (approx):
```rust
pub struct DemoRunnerHost {
    // ...other fields...
    card_renderer: CardRenderer,
    // ...
}
```

After: the line `card_renderer: CardRenderer,` is deleted.

- [ ] **Step 2: Remove the initialization in `DemoRunnerHost::new`**

Still in `src/runner_host/mod.rs`, find and remove the `card_renderer: CardRenderer::new(),` line inside the `Self { ... }` constructor (currently at line 180).

- [ ] **Step 3: Remove the now-unused import**

At the top of `src/runner_host/mod.rs` (line 26), remove:
```rust
use crate::cards::CardRenderer;
```

- [ ] **Step 4: Build to confirm everything is consistent**

```bash
cargo build -p greentic-start --all-features 2>&1 | tail -20
```

Expected: clean build. If clippy flags `card_renderer` as unused somewhere else, grep for it and remove remaining references (there should be none after Tasks 4 and 5).

```bash
grep -rn "card_renderer" src/ 2>&1
```

Expected: no matches.

- [ ] **Step 5: Commit**

```bash
git add src/runner_host/mod.rs
git commit -m "refactor(runner_host): drop card_renderer field (moved to messaging.rs)"
```

---

## Task 7: Run the full CI sweep locally

**Files:** none

- [ ] **Step 1: Format check**

```bash
cargo fmt --all -- --check
```

Expected: exit code 0 (no output). If it fails, run `cargo fmt --all` and commit the reformatting separately:

```bash
cargo fmt --all
git add -u
git commit -m "chore: cargo fmt"
```

- [ ] **Step 2: Clippy with the project's strict flags**

```bash
cargo clippy -p greentic-start --all-targets --all-features -- -D warnings 2>&1 | tail -40
```

Expected: exit code 0. Fix any warnings inline and recommit (`git commit -am "chore: clippy"`). Common expected issues:
- Unused imports (`anyhow::anyhow`, `CardRenderer`) → remove them.
- Dead code from removed fields → covered by Task 6.

- [ ] **Step 3: Full test suite**

```bash
cargo test -p greentic-start --all-features 2>&1 | tail -40
```

Expected: all tests pass. The 3 new tests from Tasks 1 and 3 should be visible in the output. The 2 existing tests in `src/cards.rs::tests` (`oauth_card_resolve_swaps_resolved_card`, `oauth_card_downgrade_propagated_from_capability`) should still pass unchanged.

- [ ] **Step 4: Run the project's local CI script if present**

```bash
ls ci/local_check.sh 2>&1 && bash ci/local_check.sh 2>&1 | tail -40 || echo "no local_check.sh; skipping"
```

Expected: script runs fmt + clippy + test + build + doc + package and reports success. If any step fails, fix and commit separately before continuing.

- [ ] **Step 5: No commit — this task is verification only**

---

## Task 8: Manual end-to-end verification against github-mcp-demo-bundle

**Files:** none — this task re-runs the Phase B3 verification from the spec using the newly built binary.

- [ ] **Step 1: Install the patched binary**

```bash
cargo install --path /home/bimbim/works/greentic/greentic-start --locked --force 2>&1 | tail -20
```

Expected: `Replacing /home/bimbim/.cargo/bin/greentic-start` and a clean install. Confirm version:

```bash
greentic-start --version
```

Expected: still `0.4.48` (or whatever the `Cargo.toml` says) — no version bump in this fix.

- [ ] **Step 2: Ensure port 8090 is free and the github-mcp bundle's `greentic.demo.yaml` overrides the gateway port**

If port 8080 is still held by another bundle (check with `ss -tlnp | grep 8080`), temporarily edit `/home/bimbim/works/greentic/github-mcp-demo-bundle/greentic.demo.yaml` to add a gateway port override (back up the file first):

```bash
cp /home/bimbim/works/greentic/github-mcp-demo-bundle/greentic.demo.yaml /tmp/greentic.demo.yaml.bak
cat > /home/bimbim/works/greentic/github-mcp-demo-bundle/greentic.demo.yaml <<'EOF'
version: "1"
project_root: "./"
services:
  gateway:
    port: 8090
EOF
```

Remember to restore it at the end of this task (Step 7).

If port 8080 is free, you can skip this step and run the bundle on 8080.

- [ ] **Step 3: Start the bundle in the background**

```bash
cd /home/bimbim/works/greentic/github-mcp-demo-bundle
greentic-start --locale en start --bundle . --nats off --cloudflared off --ngrok off > /tmp/gh-mcp-verify.log 2>&1 &
sleep 10
ss -tlnp | grep -E ':(8080|8090)' | grep greentic-start
```

Expected: `greentic-start` listening on the configured port. If not, check `/tmp/gh-mcp-verify.log` for errors.

- [ ] **Step 4: Request a Direct Line token, start a conversation, send "Get started"**

Replace `PORT` below with `8090` or `8080` depending on the setup:

```bash
PORT=8090
TOKEN=$(curl -s -X POST "http://127.0.0.1:$PORT/v1/messaging/webchat/demo/token?tenant=demo" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
CONV=$(curl -s -X POST "http://127.0.0.1:$PORT/v1/messaging/webchat/demo/v3/directline/conversations?tenant=demo" -H "Authorization: Bearer $TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)['conversationId'])")
curl -s -X POST "http://127.0.0.1:$PORT/v1/messaging/webchat/demo/v3/directline/conversations/$CONV/activities?tenant=demo" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"type":"message","from":{"id":"user1","name":"User"},"text":"Get started"}'
sleep 3
curl -s "http://127.0.0.1:$PORT/v1/messaging/webchat/demo/v3/directline/conversations/$CONV/activities?tenant=demo" \
    -H "Authorization: Bearer $TOKEN" \
  | python3 -m json.tool | head -60
```

- [ ] **Step 5: Assert the bot reply contains a resolved GitHub OAuth URL**

In the JSON output from Step 4, find the bot reply (`"role":"bot"`) and its `attachments[0].content.actions`. You should see:

```json
{
    "type": "Action.OpenUrl",
    "title": "Login with OAuth",
    "url": "https://github.com/login/oauth/authorize?response_type=code&client_id=Ov23ligPicBfeZw44MjZ&redirect_uri=...&scope=repo%20security_events%20read%3Aorg&state=<uuid>"
}
```

**If the URL is still `oauth://start`**, the fix did not take effect. Re-check the verification log:

```bash
grep -E "oauth card resolve|oauth.card|oauth_card_resolved" /home/bimbim/works/greentic/github-mcp-demo-bundle/logs/operator.log | tail -20
```

Expected (on success): entries showing the helper invoked, or at minimum the `render_plan` op receiving the resolved URL. If you see `[demo messaging] oauth card resolve failed`, investigate the capability dispatch error in the log and fix before merging.

- [ ] **Step 6: Stop the bundle**

```bash
pkill -f "greentic-start.*github-mcp-demo-bundle" || pkill -f "greentic-start.*--bundle \\." 
sleep 2
ss -tlnp | grep -E ':(8080|8090)' | grep greentic-start || echo "stopped"
```

- [ ] **Step 7: Restore the bundle config if you modified it in Step 2**

```bash
if [ -f /tmp/greentic.demo.yaml.bak ]; then
  cp /tmp/greentic.demo.yaml.bak /home/bimbim/works/greentic/github-mcp-demo-bundle/greentic.demo.yaml
  rm /tmp/greentic.demo.yaml.bak
fi
cat /home/bimbim/works/greentic/github-mcp-demo-bundle/greentic.demo.yaml
```

Expected: the file is back to its committed state.

- [ ] **Step 8: No commit — verification task only. Record the outcome in the PR description when opened.**

---

## Task 9: Add changelog entry and final summary commit

**Files:**
- Create: `/home/bimbim/works/greentic/updates/2026-04-11/greentic-start.md`

- [ ] **Step 1: Create the daily changelog directory if missing**

```bash
mkdir -p /home/bimbim/works/greentic/updates/2026-04-11
```

- [ ] **Step 2: Write the changelog entry**

Create `/home/bimbim/works/greentic/updates/2026-04-11/greentic-start.md` with the following content:

```markdown
# greentic-start — 2026-04-11

## Fix: OAuth card resolution in messaging egress

**Branch:** `fix/oauth-card-messaging-wiring`

**Problem:** Outbound Adaptive Cards with `oauth://start` placeholders were being sent to the webchat client unresolved. The "Login with OAuth" button in the github-mcp demo bundle did nothing because the URL was literal `oauth://start` instead of a real GitHub OAuth authorize URL.

**Root cause:** `CardRenderer::render_if_needed` was only wired into `src/runner_host/dispatch.rs:146`, inside the `entry_flows` branch of `run_provider_op_with_payload`. Messaging egress ops (`render_plan`, `encode`, `send_payload`) do not match any entry flow for the `messaging-webchat-gui` pack, so they fall through to `invoke_provider_component_op` and bypass the hook entirely.

**Fix:** Added a private helper `resolve_oauth_card_placeholders` in `src/http_ingress/messaging.rs` that wraps `CardRenderer::render_if_needed` and is called in the existing outputs loop right after `ensure_card_i18n_resolved` and before `egress::render_plan`. The dead `render_if_needed` call in `src/runner_host/dispatch.rs` and the unused `card_renderer` field on `DemoRunnerHost` were removed. Failures fail-soft: log warn, keep the envelope unchanged, continue.

**Verification:** 3 new unit tests (happy path, dispatcher error, no-op when no card). Full `cargo test -p greentic-start --all-features` + `cargo clippy -- -D warnings` + `cargo fmt --check` green. Manual end-to-end run against `github-mcp-demo-bundle` confirmed the bot reply now contains `https://github.com/login/oauth/authorize?...` instead of `oauth://start`.

**Spec:** `greentic-start/docs/superpowers/specs/2026-04-11-oauth-card-messaging-wiring-design.md`
**Plan:** `greentic-start/docs/superpowers/plans/2026-04-11-oauth-card-messaging-wiring.md`
```

- [ ] **Step 3: Commit the changelog**

The changelog lives outside the `greentic-start` repo (it's in the parent workspace's `updates/` dir). Commit it separately using the parent workspace's git (if any) or leave it uncommitted and mention in the PR. For now, do not commit from inside the greentic-start repo — the `updates/` path is outside the repo root.

```bash
cd /home/bimbim/works/greentic/greentic-start
git log --oneline fix/oauth-card-messaging-wiring ^origin/main
```

Expected output: the 5 commits from Tasks 1-6 (test, impl, error tests, wiring, dispatch cleanup, mod cleanup).

- [ ] **Step 4: Re-run the final CI sweep one more time to make sure nothing broke in later tasks**

```bash
cargo fmt --all -- --check && cargo clippy -p greentic-start --all-targets --all-features -- -D warnings && cargo test -p greentic-start --all-features
```

Expected: exit code 0 for all three commands.

- [ ] **Step 5: Push the branch (do NOT push to main)**

```bash
git push -u origin fix/oauth-card-messaging-wiring
```

Expected: branch created on origin, ready for PR.

- [ ] **Step 6: Stop and hand off. Open PR creation is a separate user-driven step — do not auto-create.**

---

## Self-review notes (for the implementer)

- **Type mismatch trap:** `ChannelMessageEnvelope.metadata` is `BTreeMap<String, String>`. The helper intentionally does NOT deserialize the renderer's output back into a `ChannelMessageEnvelope` because `cards.rs` inserts `oauth_card_resolved` as a nested JSON object under `/metadata/`, which is not a string. Instead, the helper extracts specific fields from the `Value` and inserts stringified JSON into the envelope's metadata map.
- **Shadowing `provider_type`:** the existing loop computes `provider_type` later (around line 136) for `build_send_payload`. Our Task 4 insertion computes it earlier. If clippy flags the shadow, remove the later binding and reuse the earlier one — the value does not change within the loop iteration.
- **Why the helper short-circuits on `outcome.bytes == payload_bytes`:** `CardRenderer::render_if_needed` returns the input bytes unchanged when there is no placeholder. Skipping the `from_slice` round-trip on that fast path avoids an unnecessary allocation.
- **`runner_host.invoke_capability` is already `pub`** (`src/runner_host/mod.rs:270`) — no visibility change needed.
- **Existing `cards.rs` tests are unaffected** because they construct synthetic `serde_json::Value` payloads, not `ChannelMessageEnvelope` instances.
