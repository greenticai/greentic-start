# OAuth Card Messaging Wiring — Design

**Status:** Draft
**Date:** 2026-04-11
**Author:** Bima Pangestu (pairing with Claude Code)
**Repo:** greentic-start
**Target branch:** `fix/oauth-card-messaging-wiring`

## Context

The `greentic.cap.oauth.card.v1` capability resolves `oauth://start` placeholders in Adaptive Cards into real OAuth authorize URLs (with `client_id`, `redirect_uri`, `state`, etc.). The library (`greentic-oauth/components/oauth-card`) and its capability dispatcher (`oidc-provider-runtime`) are implemented, tested, and working.

However, a verification session on 2026-04-11 with `greentic-start 0.4.48` and the `github-mcp-demo-bundle` confirmed a regression: the **messaging egress pipeline** does not invoke the OAuth card resolution hook. Outbound Adaptive Cards reach the webchat client with `"url":"oauth://start"` unresolved, so the "Login with OAuth" button does nothing.

### Evidence

1. Unit tests green: 16/16 in `oauth-card`, 9/9 in `oidc-provider-runtime` (4 `resolve-card` tests), 2/2 in `greentic-start/src/cards.rs`.
2. Smoke test: loading `packs/github-mcp.pack/assets/cards/auth_choice.json` and calling `oauth_card::resolve_card()` directly produces the correct resolved URL.
3. Fresh Direct Line run (Phase B3 of the verification):
   - `POST /v1/messaging/webchat/demo/v3/directline/conversations/<id>/activities` with `text:"Get started"`
   - `GET /v1/messaging/webchat/demo/v3/directline/conversations/<id>/activities`
   - Bot reply attachment content: `"actions":[{"type":"Action.OpenUrl","url":"oauth://start",...}]` — unresolved.
4. `logs/operator.log` for the fresh run shows `op=render_plan` WASM input containing `\"url\":\"oauth://start\"` — no capability dispatch for `oauth.card.resolve` is logged.
5. Historical log from 2026-04-08/09 (older `greentic-start` binary) shows `render_plan` receiving the resolved GitHub OAuth URL — confirming the feature worked before and regressed.

### Root cause

`CardRenderer::render_if_needed` at `src/cards.rs:24` is only invoked from `src/runner_host/dispatch.rs:146`, inside the branch `if pack.entry_flows.iter().any(|flow| flow == op_id)` (line 117). For the `messaging-webchat-gui` provider pack:

- `greentic-pack doctor` reports `Flows: 0`; the entry_flows fallback in `src/domains.rs:658-670` sets `entry_flows` to the pack id (`"messaging-webchat-gui"`).
- Messaging egress ops (`render_plan`, `encode`, `send_payload`) do not match any entry_flow and fall through `dispatch.rs:230` to `invoke_provider_component_op`, bypassing `render_if_needed`.

The hook logic is correct, tested, and well-specified; it is simply wired to the wrong code path for the messaging egress pipeline used by `http_ingress/messaging.rs`.

## Goal

Wire `CardRenderer::render_if_needed` into the messaging egress pipeline so that every outbound envelope carrying `metadata.adaptive_card` with an OAuth placeholder has the placeholder resolved before reaching the provider's `render_plan` op.

Non-goals:
- Fixing OAuth card resolution in onboard/admin flows (scope limitation — see "Known scope gaps").
- Changing the `oauth-card` library API or the `greentic.cap.oauth.card.v1` capability contract.
- Changing the `component-adaptive-card` WASM component (it correctly emits `oauth://start` by design — host-side resolution is intentional).

## Architecture

### Call site

The new hook runs in `src/http_ingress/messaging.rs` inside the existing `for mut out_envelope in outputs` loop (currently at line 86), immediately after `ensure_card_i18n_resolved(&mut out_envelope, &app_pack_path)` and before `egress::render_plan(...)`:

```
http_ingress/messaging.rs outputs loop
├─ ensure_card_i18n_resolved(&mut envelope, pack_path)   // existing safety net
├─ resolve_oauth_card_placeholders(provider_type, &mut envelope, dispatcher)   // NEW
├─ egress::render_plan(runner_host, ctx, provider, message_value)
├─ egress::encode_payload(runner_host, ctx, provider, message_value, plan)
└─ runner_host.invoke_provider_op(Messaging, provider, "send_payload", ...)
```

Why this location:
1. `runner_host` is already in scope (used by `egress::render_plan` on line 101), so the hook can dispatch the capability without plumbing through lower layers.
2. There is precedent: `ensure_card_i18n_resolved` sits in the same spot as a parallel host-side card preprocessor.
3. By the time the envelope reaches this loop, `parse_envelopes` (`src/messaging_app.rs:559`) has already populated `metadata.adaptive_card` as a stringified JSON — matching the payload shape `CardRenderer::render_if_needed` expects (`/metadata/adaptive_card` as a string).
4. Placing the hook inside `parse_envelopes` would require plumbing `runner_host` through `run_app_flow_safe` → `run_app_flow` → `parse_envelopes` (three layers), which is more invasive.

### Helper signature

```rust
fn resolve_oauth_card_placeholders(
    provider_type: &str,
    envelope: &mut ChannelMessageEnvelope,
    mut dispatcher: impl FnMut(&str, &str, &[u8]) -> anyhow::Result<serde_json::Value>,
) -> anyhow::Result<()>;
```

The helper is testable without a real `runner_host`: the caller (the egress loop) supplies a closure that delegates to `runner_host.invoke_capability(cap_id, op, input, ctx)`; the tests supply a stub closure.

The helper:
1. Serializes `envelope` to JSON bytes.
2. Constructs a `CardRenderer` locally and calls `render_if_needed(provider_type, &bytes, dispatcher)`.
3. Parses `render_outcome.bytes` back into a `ChannelMessageEnvelope` and replaces `*envelope` in place.
4. On any error, logs a warning and leaves `*envelope` unchanged.

### Dispatcher closure at the call site

```rust
resolve_oauth_card_placeholders(
    &provider_type,
    &mut out_envelope,
    |cap_id, op, input| {
        let outcome = runner_host.invoke_capability(cap_id, op, input, ctx)?;
        if !outcome.success {
            return Err(anyhow!(
                "capability {}:{} failed: {}",
                cap_id,
                op,
                outcome.error.clone().unwrap_or_else(|| "unknown".into())
            ));
        }
        outcome
            .output
            .ok_or_else(|| anyhow!("capability {}:{} returned no structured output", cap_id, op))
    },
)?;
```

`runner_host.invoke_capability(...)` already exists and is used by `dispatch.rs:150`. It must remain `pub` (or `pub(crate)`) — verify during implementation.

## Data flow

1. `out_envelope` enters the loop with `metadata.adaptive_card` already populated by `parse_envelopes`.
2. `ensure_card_i18n_resolved` rewrites `{{i18n:KEY}}` tokens (existing behavior).
3. `resolve_oauth_card_placeholders`:
   - Serializes `out_envelope` to JSON bytes via `serde_json::to_vec`.
   - `CardRenderer::render_if_needed(provider_type, &bytes, dispatcher)`:
     - Parses bytes, reads `/metadata/adaptive_card`.
     - Pre-flight: if no `oauth://start`, `{{oauth.start_url}}`, or `{{oauth.teams.connectionName}}` placeholder, short-circuits and returns bytes unchanged.
     - Otherwise, builds the `CardResolveInput`, invokes dispatcher with `(CAP_OAUTH_CARD_V1, "oauth.card.resolve", request_bytes)`.
     - Capability returns `{resolved_card, start_url?, downgrade?, ...}`; `CardRenderer` swaps `metadata.adaptive_card` with `resolved_card`, inserts `metadata.oauth_card_resolved` audit, and optionally `metadata.oauth_card_downgrade`.
     - Returns the rewritten payload bytes.
   - Helper parses the rewritten bytes back into `ChannelMessageEnvelope` and replaces `*envelope`.
4. `egress::render_plan(runner_host, ctx, provider, message_value)` — now receives an envelope where `metadata.adaptive_card` contains the real OAuth URL.
5. `egress::encode_payload(...)` and `invoke_provider_op("send_payload")` complete as before.

## Error handling

All failure modes are fail-soft: log warn, keep the envelope unchanged, continue egress. This mirrors `ensure_card_i18n_resolved`'s silent safety-net behavior.

| Condition | Behavior |
|---|---|
| `metadata.adaptive_card` absent or empty | no-op, no log (normal for non-card messages) |
| Card present but no OAuth placeholder | short-circuit inside `has_oauth_placeholders`; no capability call |
| `serde_json::to_vec(envelope)` fails | warn `"serialize envelope for oauth resolve failed: {err}"`, continue with original |
| Dispatcher closure returns `Err` (capability missing, invocation failed, unstructured output) | warn `"[demo messaging] oauth card resolve failed for provider={} envelope_id={}: {err}; sending unresolved"`, continue with original |
| `CardRenderer::render_if_needed` returns `Err` (invalid JSON, malformed capability output) | warn with same format, continue with original |
| `serde_json::from_slice(rewritten_bytes)` fails (shouldn't happen — we just serialized) | warn, continue with original |
| Capability returns `downgrade` metadata | normal success; `metadata.oauth_card_downgrade` is preserved for audit; egress continues |

No retries, no custom timeout — `runner_host.invoke_capability` already enforces its own timeouts.

## Testing

Two new unit tests in `src/http_ingress/messaging.rs` (inside `#[cfg(test)] mod tests`):

### Test 1: happy path wires placeholder to resolved URL
```rust
#[test]
fn oauth_card_placeholder_resolved_before_render_plan() {
    // Given: an envelope with metadata.adaptive_card containing oauth://start
    let mut envelope = envelope_with_oauth_card("oauth://start");
    let resolved_url = "https://github.com/login/oauth/authorize?state=abc123";
    let dispatcher = |_cap: &str, _op: &str, _input: &[u8]| -> anyhow::Result<Value> {
        Ok(json!({
            "resolved_card": {/* adaptive card JSON with url replaced by resolved_url */}.to_string(),
            "start_url": resolved_url,
        }))
    };

    // When
    resolve_oauth_card_placeholders("messaging.webchat-gui", &mut envelope, dispatcher).unwrap();

    // Then
    assert!(envelope.metadata.get("adaptive_card").unwrap().contains(resolved_url));
    assert!(!envelope.metadata.get("adaptive_card").unwrap().contains("oauth://start"));
    assert!(envelope.metadata.contains_key("oauth_card_resolved"));
}
```

### Test 2: dispatcher failure leaves envelope unchanged
```rust
#[test]
fn oauth_card_resolve_failure_passes_envelope_through_unchanged() {
    // Given
    let mut envelope = envelope_with_oauth_card("oauth://start");
    let original_card = envelope.metadata.get("adaptive_card").unwrap().clone();
    let dispatcher = |_cap: &str, _op: &str, _input: &[u8]| -> anyhow::Result<Value> {
        Err(anyhow::anyhow!("capability not installed"))
    };

    // When
    let result = resolve_oauth_card_placeholders("messaging.webchat-gui", &mut envelope, dispatcher);

    // Then
    assert!(result.is_ok(), "fail-soft: helper should return Ok even on dispatcher error");
    assert_eq!(envelope.metadata.get("adaptive_card").unwrap(), &original_card);
    assert!(!envelope.metadata.contains_key("oauth_card_resolved"));
}
```

### Existing tests that must stay green
- `src/cards.rs::tests::oauth_card_resolve_swaps_resolved_card` — tests `CardRenderer::render_if_needed` directly with a mock dispatcher closure. Unaffected.
- `src/cards.rs::tests::oauth_card_downgrade_propagated_from_capability` — tests downgrade propagation. Unaffected.
- `src/runner_host/dispatch.rs::tests::*` — integration runner tests. The removal of `render_if_needed` from the `entry_flows` branch must not break these; from a prior grep none of the dispatch tests assert on `render_if_needed` behavior.

### Manual verification (after implementation)
1. `cargo fmt --all -- --check`
2. `cargo clippy -p greentic-start --all-targets --all-features -- -D warnings`
3. `cargo test -p greentic-start --all-features`
4. Install: `cargo install --path . --locked`
5. Re-run Phase B3 of the verification session against `github-mcp-demo-bundle`:
   - Start bundle with `greentic-start --locale en start --bundle . --nats off --cloudflared off --ngrok off` (override port in `greentic.demo.yaml` if 8080 is occupied).
   - Obtain Direct Line token, start conversation, send `"Get started"`.
   - `GET .../activities` and assert the bot reply attachment action URL matches `https://github.com/login/oauth/authorize?...` (not `oauth://start`).

## File changes

| File | Change | LOC estimate |
|---|---|---|
| `src/http_ingress/messaging.rs` | Add private helper `resolve_oauth_card_placeholders()`; invoke it in the outputs loop right after `ensure_card_i18n_resolved`. Add 2 unit tests in `#[cfg(test)] mod tests`. | +60 src, +80 test |
| `src/runner_host/dispatch.rs` | Remove the call `self.card_renderer.render_if_needed(...)` at line 146–172 inside the `entry_flows` branch (dead code for messaging egress; all other provider dispatch logic stays). | −27 |
| `src/runner_host/mod.rs` | Remove `card_renderer: CardRenderer` field (line 48) and its initialization at line 180. `CardRenderer` becomes a zero-cost struct instantiated locally in the helper. | −3 |
| `src/cards.rs` | No changes. `CardRenderer::render_if_needed` and its two tests remain. | 0 |

Files explicitly not touched: `greentic-oauth/*`, `greentic-messaging-providers/*`, `component-adaptive-card/*`, `github-mcp-demo-bundle/*`, project-level `CLAUDE.md`. This is an internal implementation fix with no contract change.

## Migration and backward compatibility

- Zero breaking changes in public API.
- Packs that don't use `oauth://start` short-circuit in `has_oauth_placeholders` and pay no extra cost.
- After upgrading `greentic-start`, existing installed bundles work without re-setup.

## Known scope gaps

- **Onboard and admin flows:** if any code path outside `http_ingress/messaging.rs` ever sets `metadata.adaptive_card` with an OAuth placeholder (e.g. a future wizard reply or admin-triggered card), this fix does not cover it. Resolution for those paths can be added separately by invoking the same helper. This spec documents messaging egress only.
- **Non-messaging domains:** event domains currently don't emit Adaptive Cards; no wiring needed.

## Risks

1. **`runner_host.invoke_capability` visibility:** the method must be callable from `http_ingress/messaging.rs`. If it's currently `pub(super)` or private, the fix needs a visibility bump. *Mitigation:* verify during implementation; promote to `pub(crate)` if needed.
2. **Envelope round-trip cost:** serializing to JSON and deserializing back adds allocation per envelope with a card. Acceptable given cards are rare and this mirrors existing `ensure_card_i18n_resolved` cost. If profiling later shows an issue, the helper can operate on `serde_json::Value` instead of bytes to skip the final deserialize.
3. **Removing the `dispatch.rs` hook:** if any non-messaging entry flow was actually relying on `render_if_needed` being called (unverified — no known user), that pathway loses OAuth resolution. *Mitigation:* grep the codebase for entry flows that emit adaptive cards before removing; if any exist, fall back to keeping `dispatch.rs` hook in addition to the new messaging-side call.

## Verification checklist

- [ ] `cargo fmt --all -- --check` clean
- [ ] `cargo clippy -p greentic-start --all-targets --all-features -- -D warnings` clean
- [ ] `cargo test -p greentic-start --all-features` all green (new + existing)
- [ ] Manual Direct Line run against `github-mcp-demo-bundle` returns resolved OAuth URL in activities response
- [ ] `updates/2026-04-11/greentic-start.md` changelog entry added
