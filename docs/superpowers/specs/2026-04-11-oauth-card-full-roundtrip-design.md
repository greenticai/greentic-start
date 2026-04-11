# OAuth Card Full Round-Trip — Design

**Status:** Draft
**Date:** 2026-04-11
**Author:** Bima Pangestu (pairing with Claude Code)
**Repo:** greentic-start
**Target branch:** `fix/oauth-card-messaging-wiring` (continues from Phase 1)
**Prerequisite spec:** `2026-04-11-oauth-card-messaging-wiring-design.md`

## Context

Phase 1 of the OAuth card fix (committed as `3b43f53` … `5bd729f` on the same branch) restored the wiring of `CardRenderer::render_if_needed` into the messaging egress pipeline. End-to-end verification on 2026-04-11 confirmed the helper is now invoked per envelope and the capability dispatch reaches the `oidc-provider-runtime` WASM component. However, the dispatch fails inside the WASM with `"invalid input: runtime envelope required for this operation"` because the WASM's `invoke()` entry point expects a `WitDispatchInput { host, provider, input }` envelope and the host side passes only the inner input bytes.

Code search confirmed there is **no host-side code** in greentic-start that constructs `WitDispatchInput`. The capability-based OAuth card resolution path has never been wired end-to-end on the host. This spec defines that wiring plus the missing pieces required to complete the OAuth round-trip.

User requirement (decided in brainstorming on 2026-04-11):
- Full OAuth round-trip: tombol "Login with OAuth" → GitHub authorize → callback → flow continues
- Token exchange via inline `reqwest` from greentic-start (no external broker subprocess)
- File-based session store at `state/oauth-sessions/` for state token + PKCE verifier
- Session TTL 10 minutes
- Callback path `/v1/oauth/callback/{provider_id}`
- Scope: only `oauth-oidc-generic` provider pack and the github-mcp-demo-bundle for now

## Goal

Make the github-mcp demo bundle's OAuth card work end-to-end:
1. User sends "Get started" in webchat → bot reply contains an Adaptive Card whose "Login with OAuth" button URL is a fully-formed GitHub `https://github.com/login/oauth/authorize?…` URL with valid `client_id`, `redirect_uri`, `state`, `code_challenge`, `code_challenge_method=S256`, and `scope`.
2. User clicks the button → browser opens GitHub OAuth consent → user authorizes.
3. GitHub redirects to greentic-start callback `/v1/oauth/callback/github` with `code` and `state`.
4. greentic-start exchanges the code for an access token via direct HTTP POST to `token_url`, persists the token to the bundle's secrets store, injects an `oauth_login_success` activity into the originating conversation, and returns an HTML success page that closes/redirects the browser back to the webchat UI.
5. The webchat client polls the conversation, sees the new activity, and the flow router advances `auth_choice` → `mcp_ready` (or whatever the `response.text == "oauth_login_success"` branch leads to).

Non-goals:
- Multi-tenant production session storage (Redis/Postgres) — file-based is bundle-local dev only
- Refresh token handling — only initial token exchange; refresh is a follow-up
- OAuth scope upgrade flow — assume default scopes from `setup-answers.json`
- Provider extension discovery via capability binding for `provider_pack_id` (hardcoded `oauth-oidc-generic` for now)
- Callback handling for non-OAuth providers (Teams native sign-in, Slack OAuth, etc.) — only `oauth-oidc-generic`
- `CAP_OAUTH_BROKER_V1` envelope wrapping — the design leaves room for future extension but only `CAP_OAUTH_CARD_V1` is wired here
- Refactoring `runner_host/mod.rs` or `messaging.rs` beyond what this fix needs

## Architecture

The fix is split into two phases that build on Phase 1 (already committed):

| Phase | Status | Scope |
|---|---|---|
| **Phase 1: Wiring** | ✅ Committed (T1–T7) | `resolve_oauth_card_placeholders` helper called in egress loop, fail-soft logging in place. Capability dispatch reaches WASM but fails at envelope check. |
| **Phase 2: Envelope + Card Render** | This spec | Wrap dispatch payload as `WitDispatchInput { host, provider, input }`. Generate state + PKCE + persist verifier. Card returned to client contains a fully-formed GitHub OAuth URL. |
| **Phase 3: Callback + Token Exchange + Flow Resume** | This spec | HTTP route `/v1/oauth/callback/{provider_id}`. Inline `reqwest` token exchange. Persist access_token. Inject `oauth_login_success` activity into the originating conversation so the flow advances. |

### End-to-end data flow after Phase 3

```
Browser (webchat)                  greentic-start                                  GitHub
─────────────────                  ──────────────                                  ──────
1. User: "Get started" ─► Direct Line ─► messaging.rs egress loop
                                          ├─ resolve_oauth_card_placeholders
                                          │   ├─ OauthSessionStore::create()
                                          │   │   → SessionTicket{state, verifier, code_challenge}
                                          │   │   persisted at state/oauth-sessions/{state}.json
                                          │   └─ invoke_capability(CAP_OAUTH_CARD_V1, "oauth.card.resolve")
                                          │       └─ runner_host wraps payload via oauth_envelope::wrap()
                                          │           → WitDispatchInput{host, provider, input}
                                          │           → oidc-provider-runtime WASM
                                          │              → builds authorize_url from
                                          │                 client_id+redirect_uri+state+code_challenge+scopes
                                          │              → oauth_card::resolve_card rewrites
                                          │                 oauth://start with the URL
                                          │           → returns resolved_card to host
                                          └─ envelope sent through standard egress (render_plan → encode → send_payload)
2. User sees resolved card ◄── Direct Line activities
3. User clicks Login ──────────────────────────────────────────────────────► GitHub auth
4. GitHub redirect ◄────────────────────────────────────────────────────────  code + state
   to /v1/oauth/callback/github
                       ─► http_ingress dispatch ─► oauth_callback::handle
                          ├─ parse code + state from query string
                          ├─ session_store.consume(state) → PersistedSession{verifier, conv_id, …}
                          ├─ load_provider_config(setup-answers.json)
                          ├─ reqwest::post(provider.token_url, {grant_type=authorization_code, code, code_verifier=session.verifier, client_id, client_secret, redirect_uri})
                          │     ──────────────────────────────────────────► GitHub token endpoint
                          │                                                  ↓
                          │                                              {access_token, …}
                          ├─ secrets_manager.write(access_token URI)
                          ├─ inject_oauth_login_success_activity(conv_id, tenant)
                          │   └─ POST to local /v1/messaging/webchat/{tenant}/v3/directline/conversations/{conv_id}/activities
                          │      with system-minted JWT + body {type:"message", text:"oauth_login_success"}
                          └─ render success HTML (auto-close + meta refresh fallback)
5. Webchat client polls ◄── sees "oauth_login_success" activity
6. Flow router matches response.text == "oauth_login_success" ─► next node
7. User sees next bot reply ◄── Direct Line
```

## Phase 2 — Envelope wrapper + card render

### New module `src/oauth_envelope.rs` (~150 LOC)

Pure helpers, no async, no I/O on hot path.

```rust
pub struct OauthProviderConfig {
    pub provider_id: String,        // e.g., "github"
    pub auth_url: String,
    pub token_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub default_scopes: Vec<String>,
}

/// Read setup-answers.json for an OAuth provider pack and parse to provider config.
/// Path: {bundle_root}/state/config/{provider_pack_id}/setup-answers.json
/// Errors:
/// - File not found → AnyhowError("oauth provider config not found at <path>")
/// - Missing required field (client_id, client_secret, auth_url, token_url, provider_id)
/// - default_scopes parsed from space-separated string (matches existing setup-answers.json shape)
pub fn load_provider_config(
    bundle_root: &Path,
    provider_pack_id: &str,
) -> anyhow::Result<OauthProviderConfig>;

/// Resolve the public base URL the host should advertise to OAuth providers.
/// Lookup order:
///   1. {bundle_root}/state/runtime/{tenant}.{team_or_default}/endpoints.json#public_base_url
///   2. {bundle_root}/state/runtime/{tenant}.{team_or_default}/public_base_url.txt
///   3. fallback "http://127.0.0.1:{gateway_port}"
pub fn load_public_base_url(
    bundle_root: &Path,
    tenant: &str,
    team: Option<&str>,
    gateway_port: u16,
) -> anyhow::Result<String>;

/// Wrap an OAuth dispatch input as `WitDispatchInput { host, provider, input }` bytes.
/// `inner_input` is the per-op payload (e.g., {adaptive_card, tenant, state, code_challenge, scopes}).
pub fn wrap_dispatch_envelope(
    public_base_url: &str,
    provider: &OauthProviderConfig,
    inner_input: serde_json::Value,
) -> anyhow::Result<Vec<u8>>;
```

### New module `src/oauth_session_store.rs` (~180 LOC)

File-based session lifecycle. One file per session.

```rust
pub struct SessionTicket {
    pub state_token: String,    // 32 bytes url-safe random
    pub code_verifier: String,  // 64 bytes url-safe random (RFC 7636)
    pub code_challenge: String, // base64url(SHA256(verifier))
}

#[derive(Serialize, Deserialize)]
pub struct PersistedSession {
    pub state_token: String,
    pub code_verifier: String,
    pub provider_id: String,        // e.g., "github" — matches setup-answers.json
    pub provider_pack_id: String,   // e.g., "oauth-oidc-generic"
    pub tenant: String,
    pub team: Option<String>,
    pub conversation_id: String,    // webchat conversation id, used by callback to resume the right conversation
    pub created_at_unix_ms: i64,
}

pub struct OauthSessionStore {
    bundle_root: PathBuf,
}

impl OauthSessionStore {
    pub fn new(bundle_root: impl Into<PathBuf>) -> Self;

    /// Generate state + verifier + challenge, persist a session file, return the ticket.
    /// Calls `gc_expired(Duration::from_secs(600))` first to clean up stale sessions.
    pub fn create(
        &self,
        provider_id: &str,
        provider_pack_id: &str,
        tenant: &str,
        team: Option<&str>,
        conversation_id: &str,
    ) -> anyhow::Result<SessionTicket>;

    /// Atomically read + delete the session file matching `state_token`.
    /// Returns the persisted session for downstream callback use.
    pub fn consume(&self, state_token: &str) -> anyhow::Result<PersistedSession>;

    /// Remove session files older than `max_age`. Returns count of removed files.
    pub fn gc_expired(&self, max_age: Duration) -> anyhow::Result<usize>;
}
```

Storage layout: `{bundle_root}/state/oauth-sessions/{state_token}.json`. Files are world-readable to the bundle owner only (mode 0600 on POSIX). `consume()` does `read → remove`; if `remove` fails after read, the operation is still considered consumed (file lifetime is "best-effort delete").

### Extension to `runner_host::invoke_capability`

Add envelope wrapping inside `invoke_capability` (`src/runner_host/mod.rs:267`). After resolving `binding`, before calling `invoke_provider_component_op`:

```rust
let final_payload_bytes: Vec<u8> = if cap_id == CAP_OAUTH_CARD_V1 {
    // OAuth card resolution requires the WASM dispatch envelope
    // {host, provider, input}. Build it from the bundle's setup-answers.json
    // and runtime state.
    let inner_input: serde_json::Value =
        serde_json::from_slice(payload_bytes)
            .with_context(|| "oauth.card.resolve input must be valid JSON")?;
    let provider_pack_id = &binding.pack_id;
    let provider_cfg =
        oauth_envelope::load_provider_config(&self.bundle_root, provider_pack_id)?;
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

This requires `DemoRunnerHost` to know `gateway_port: u16`. Add a field populated at construction from `DemoConfig.services.gateway.port`.

### Updated helper signature

`resolve_oauth_card_placeholders` (in `src/http_ingress/messaging.rs`) gains three parameters:

```rust
fn resolve_oauth_card_placeholders(
    provider_type: &str,
    envelope: &mut ChannelMessageEnvelope,
    session_store: &OauthSessionStore,
    provider_pack_id: &str,
    conversation_id: &str,
    dispatcher: impl FnMut(&str, &str, &[u8]) -> anyhow::Result<serde_json::Value>,
) -> anyhow::Result<()>;
```

Inside (additions over Phase 1 logic):
1. After detecting an OAuth placeholder, call `session_store.create(...)` with the envelope's tenant/team and the provided `conversation_id`. The store returns a `SessionTicket{state_token, code_verifier, code_challenge}`.
2. Determine the `provider_id` from setup-answers.json via `oauth_envelope::load_provider_config(bundle_root, provider_pack_id).provider_id`. Hardcoded `provider_pack_id = "oauth-oidc-generic"` is acceptable for this spec; pass it through from the call site.
3. Build the inner input that `oidc-provider-runtime::handle_resolve_card` expects:
   ```json
   {
     "adaptive_card": "<stringified card>",
     "tenant": "<envelope tenant>",
     "state": "<ticket.state_token>",
     "code_challenge": "<ticket.code_challenge>",
     "scopes": ["repo", "security_events", "read:org"],
     "native_oauth_card": false
   }
   ```
4. Call `dispatcher(CAP_OAUTH_CARD_V1, "oauth.card.resolve", &serde_json::to_vec(&inner_input)?)`. The dispatcher (provided by the call site at messaging.rs) goes through `runner_host.invoke_capability` which wraps with the envelope.
5. Receive `resolved_card` from dispatcher response (existing logic) and swap into envelope metadata as a stringified JSON.
6. Audit metadata (`oauth_card_resolved`, `oauth_card_downgrade`) is preserved as in Phase 1.

Note: the helper no longer goes through `CardRenderer::render_if_needed` because that helper builds `build_card_resolve_request`'s flat output, which doesn't carry `state`/`code_challenge`. The new design constructs the dispatcher input directly. This means `CardRenderer` becomes unused after Phase 2 — clean up by removing it from `cards.rs` (or keeping the file for the placeholder pre-flight check, deciding during implementation).

### Phase 2 deliverable

After Phase 2, manual run against github-mcp-demo-bundle should produce a card whose "Login with OAuth" button has a URL like:
```
https://github.com/login/oauth/authorize
  ?response_type=code
  &client_id=Ov23ligPicBfeZw44MjZ
  &redirect_uri=http%3A%2F%2F127.0.0.1%3A8090%2Fv1%2Foauth%2Fcallback%2Fgithub
  &scope=repo+security_events+read%3Aorg
  &state=<32-byte-random>
  &code_challenge=<base64url-sha256>
  &code_challenge_method=S256
```

`state/oauth-sessions/<state>.json` is written. Clicking the button opens GitHub OAuth and the user can authorize. The callback URL 404s because Phase 3 hasn't shipped yet — that's expected.

## Phase 3 — Callback + token exchange + flow resume

### New module `src/oauth_callback.rs` (~250 LOC)

```rust
pub struct OauthCallbackContext<'a> {
    pub bundle_root: &'a Path,
    pub session_store: &'a OauthSessionStore,
    pub secrets: &'a SecretsHandle,
    pub runner_host: &'a DemoRunnerHost,
    pub gateway_port: u16,
}

/// HTTP handler for `/v1/oauth/callback/{provider_id}`.
/// Returns hyper::Response with HTML body redirecting browser back to webchat UI.
pub async fn handle_oauth_callback(
    ctx: OauthCallbackContext<'_>,
    provider_id: &str,
    query_string: &str,
) -> hyper::Response<Full<Bytes>>;
```

### Callback handler logic

1. **Parse query** via `url::form_urlencoded::parse`: extract `code`, `state`, `error`, `error_description`. If `error` is present, render error HTML, log a warning, do NOT consume the session (let GC clean it up). Return early.
2. **Consume session**: `session_store.consume(&state)?`. If not found, render "session expired or already used" error HTML.
3. **Validate provider_id**: confirm `session.provider_id == provider_id` (path param matches stored). Reject mismatch.
4. **Load provider config**: `oauth_envelope::load_provider_config(bundle_root, &session.provider_pack_id)?`.
5. **Build redirect_uri** (must match exactly what was sent in step 1 of the OAuth flow):
   ```rust
   let redirect_uri = format!(
       "http://127.0.0.1:{}/v1/oauth/callback/{}",
       ctx.gateway_port, provider_id,
   );
   ```
   (For production deployments behind a tunnel, this would use `public_base_url`. For dev demo we use the loopback so the browser can reach it.)
6. **Token exchange**: HTTP POST to `provider_cfg.token_url` with form body:
   ```
   grant_type=authorization_code
   code=<code>
   redirect_uri=<redirect_uri>
   client_id=<provider_cfg.client_id>
   client_secret=<provider_cfg.client_secret>
   code_verifier=<session.code_verifier>
   ```
   Use `reqwest::Client::new().post(token_url).form(&body).timeout(Duration::from_secs(10)).send().await`. Parse response as JSON or `application/x-www-form-urlencoded` (GitHub returns the latter by default unless `Accept: application/json` is set — set the Accept header). Extract `access_token`, `token_type`, `scope`, optional `refresh_token`.
7. **Persist token**: write to secrets via `ctx.secrets.runtime_manager(Some(&session.provider_pack_id)).put(secret_uri, token_value)?`. URI format: `secrets://{env}/{tenant}/{team_or_underscore}/{provider_pack_id}/access_token`. Reuse existing `resolve_env(None)` helper for env consistency (per memory note — use `dev` not `demo`).
8. **Inject `oauth_login_success` activity** into the originating conversation (see "Activity injection" below).
9. **Render success HTML** and return.

### Activity injection mechanism

To resume the flow without modifying the flow engine, the callback POSTs a synthetic Direct Line activity to the local webchat ingress endpoint via loopback HTTP. This reuses the entire existing pipeline (route resolution, JWT validation, ingest_http, run_app_flow, flow router) without a new code path.

```rust
async fn inject_oauth_login_success_activity(
    runner_host: &DemoRunnerHost,
    gateway_port: u16,
    tenant: &str,
    conversation_id: &str,
) -> anyhow::Result<()>;
```

Steps inside:
1. Mint a system-level Direct Line JWT for the conversation. The webchat-gui pack's `/v1/messaging/webchat/{tenant}/token` endpoint already mints these via an internal helper. **Implementation step: locate the helper, ensure it's `pub(crate)` or extract a small public fn that takes `(tenant, conversation_id) -> String`.** If the helper is private and complex, fallback: write the activity directly to the conversation state store (skip JWT entirely — see Risk R2).
2. POST to `http://127.0.0.1:{gateway_port}/v1/messaging/webchat/{tenant}/v3/directline/conversations/{conversation_id}/activities?tenant={tenant}` with `Authorization: Bearer <jwt>` and body:
   ```json
   {
     "type": "message",
     "from": {"id": "system", "name": "OAuth Callback"},
     "text": "oauth_login_success"
   }
   ```
3. Use `reqwest::Client::new().post(...)`. Don't await the response result for resume — log on failure but don't fail the callback (the user will still see the success HTML even if injection fails).

### Risk: flow does not pause at `auth_choice`

Whether the flow router actually advances after seeing `oauth_login_success` depends on whether the `auth_choice` node uses `session.wait` (or YGTc equivalent) to pause execution. Verification step at start of Phase 3 implementation: read `packs/github-mcp.pack/flows/main.ygtc` and check the routing of `auth_choice`.

If the flow does not pause, the synthetic activity will arrive but not trigger anything until the user sends another message. Fallback design (acceptable): the callback still persists the token and renders a success page; user manually returns to chat and sends "Get started" again. The flow on the second run will see secrets present and skip auth_choice. UX is less seamless but functionally complete.

### Callback HTTP route registration

In `src/http_ingress/mod.rs` (or wherever route dispatch lives — confirmed during implementation), add a new route match for `/v1/oauth/callback/{provider_id}`:
- Method: GET
- Handler: extract `provider_id` from path, build `OauthCallbackContext` from runtime state, call `oauth_callback::handle_oauth_callback`.
- Routing precedence: this is a static route, registered ahead of generic provider/messaging routes.

### Success HTML response

Returned with `Content-Type: text/html; charset=utf-8`:

```html
<!DOCTYPE html>
<html>
  <head>
    <title>Greentic OAuth — Login Successful</title>
    <meta http-equiv="refresh" content="2;url=/v1/web/webchat/{tenant}/">
    <style>
      body { font-family: system-ui, sans-serif; text-align: center; padding: 3rem; color: #1f2937; }
      h1 { color: #16a34a; }
      a { color: #0ea5e9; }
    </style>
  </head>
  <body>
    <h1>Login successful</h1>
    <p>You can close this window and return to the chat.</p>
    <p><a href="/v1/web/webchat/{tenant}/">Return to chat</a></p>
    <script>setTimeout(() => window.close(), 1500);</script>
  </body>
</html>
```

`{tenant}` is interpolated server-side from the consumed session.

### Phase 3 deliverable

After Phase 3, the full round-trip works against real GitHub OAuth from the github-mcp-demo-bundle:
- Click "Login with OAuth" → GitHub authorize → user clicks Authorize
- Callback consumes session, exchanges code for token, persists to secrets
- Synthetic activity injected, flow router advances (if flow pauses)
- User returns to webchat and sees the next bot reply (e.g., `mcp_ready` confirmation)

## File changes summary

| File | Status | Lines (approx) | Responsibility |
|---|---|---|---|
| `src/oauth_envelope.rs` | NEW | ~150 | Provider config loader, public base URL loader, dispatch envelope wrapper |
| `src/oauth_session_store.rs` | NEW | ~180 | File-based session lifecycle (create/consume/gc), state + PKCE generation |
| `src/oauth_callback.rs` | NEW | ~250 | HTTP callback handler, token exchange via reqwest, activity injection, success HTML |
| `src/runner_host/mod.rs` | MODIFY | +30 / -0 | Add `gateway_port: u16` field; extend `invoke_capability` with envelope wrapping for `CAP_OAUTH_CARD_V1` |
| `src/http_ingress/messaging.rs` | MODIFY | +60 / -30 | Update `resolve_oauth_card_placeholders` signature; create session before dispatch; build inner_input with state/challenge |
| `src/http_ingress/mod.rs` (or routes file) | MODIFY | +30 | Register `/v1/oauth/callback/{provider_id}` route, wire to `oauth_callback::handle_oauth_callback` |
| `src/lib.rs` | MODIFY | +3 | `mod oauth_envelope; mod oauth_session_store; mod oauth_callback;` |
| `src/cards.rs` | MODIFY (or DELETE) | -100 (remove if obsolete) | Decide during impl: remove `CardRenderer::render_if_needed` if no longer used; keep file for placeholder pre-flight if reused |
| `Cargo.toml` | MODIFY | +3 | Add `rand`, `sha2`, `base64` if not already in workspace; verify `reqwest` features |

## Testing

### Unit tests

**`oauth_envelope.rs`** — 5 tests, tempdir-based, no external I/O:
- `load_provider_config_reads_setup_answers_json` — happy path with valid file
- `load_provider_config_errors_when_missing_required_fields`
- `load_public_base_url_reads_endpoints_json` — endpoints.json takes precedence
- `load_public_base_url_falls_back_to_local_loopback` — no state files → returns `http://127.0.0.1:{port}`
- `wrap_dispatch_envelope_produces_correct_shape` — assert serialized JSON has top-level `host`, `provider`, `input`

**`oauth_session_store.rs`** — 6 tests, tempdir:
- `create_persists_session_file_with_random_state_and_verifier`
- `create_returns_unique_state_tokens_across_calls`
- `consume_returns_session_and_deletes_file`
- `consume_errors_on_unknown_state_token`
- `gc_expired_removes_old_sessions` — write file with backdated mtime, GC removes
- `code_challenge_is_base64url_sha256_of_verifier` — known fixture vector (RFC 7636 Appendix B)

**`oauth_callback.rs`** — 4 tests with mocked HTTP via `httpmock` (or hand-rolled hyper test server):
- `handle_callback_consumes_session_and_extracts_code_state` — pre-seeded session, mocked token endpoint, assert secrets write was called
- `handle_callback_renders_error_html_on_oauth_error_param` — query has `error=access_denied` → response is error HTML, session NOT consumed
- `handle_callback_renders_error_html_on_unknown_state` — state not in store → error HTML, no token call attempted
- `handle_callback_persists_token_to_secrets_after_exchange` — verify secrets manager write was called with the correct URI and value

**`runner_host::invoke_capability` extension** — 1 new test in existing `runner_host/mod.rs::tests`:
- `invoke_capability_wraps_oauth_card_payload_with_envelope` — synthetic binding pointing at oauth-oidc pack, write fake `setup-answers.json` + `endpoints.json` in tempdir bundle root, intercept the bytes passed to `invoke_provider_component_op` via a test seam, verify the bytes shape includes `host`, `provider`, `input`. Use a thin extracted helper (`oauth_envelope::wrap_for_capability`) to make this testable in isolation.

**`http_ingress::messaging::resolve_oauth_card_placeholders`** — update existing tests for the new signature, add 1 new test:
- `resolve_creates_session_and_passes_state_to_dispatcher` — verify dispatcher receives input with `state`, `code_challenge`, `tenant`, `scopes` populated and a session file is created

### Existing tests

All 427 tests from Phase 1 must remain green. The signature change to `resolve_oauth_card_placeholders` requires updating 3 existing tests (mostly mechanical: pass new params).

### Manual end-to-end verification (Phase 8 of plan)

1. Install patched binary: `cargo install --path . --locked --force`
2. Start github-mcp bundle on port 8090 (port override via greentic.demo.yaml)
3. Open browser to `http://127.0.0.1:8090/v1/web/webchat/demo/`
4. In webchat, send "Get started"
5. Verify card has resolved GitHub URL (right-click button → inspect href)
6. Click "Login with OAuth" → authorize on GitHub
7. Verify callback redirects back, success HTML displayed
8. Verify webchat shows next bot reply (or, if flow doesn't pause, send "Get started" again and verify it skips auth_choice)
9. Restore bundle config, stop bundle, clean up

## Error handling summary

| Failure point | Behavior |
|---|---|
| `setup-answers.json` missing or malformed | Phase 2 helper logs warn, fail-soft (Phase 1 path), card sent unresolved |
| `public_base_url` lookup fails | Falls back to `http://127.0.0.1:{gateway_port}` automatically |
| `wrap_dispatch_envelope` fails | Helper returns Err, logged at call site, fail-soft |
| `session_store.create` fails (disk full, permission denied) | Helper returns Err, logged, fail-soft |
| `dispatcher` returns Err (capability or wrapping problem) | Existing fail-soft path from Phase 1 |
| Callback received with no matching session | Render "session expired or already used" error HTML, return 400 |
| Token exchange HTTP fails (network, GitHub 4xx/5xx) | Render "token exchange failed: {detail}" error HTML, return 502, log full error |
| `secrets_manager.put` fails | Render error HTML, return 500, log |
| Activity injection fails | Log warn, return success HTML anyway (token was persisted) |
| Synthetic activity arrives but flow doesn't advance | User re-sends "Get started" manually; flow sees secrets present and skips auth |

## Risks

**R1 — Flow does not pause at `auth_choice`** (medium likelihood)
- Detection: read `main.ygtc` at start of Phase 3 implementation
- Fallback: ship Phase 3 with token persistence + redirect; user manually re-sends "Get started"

**R2 — JWT mint helper not callable from callback context** (medium likelihood)
- Detection: locate `/v1/messaging/webchat/{tenant}/token` handler, check visibility
- Fallback 1: extract small `pub(crate) fn` for token mint
- Fallback 2: write activity directly to conversation state store, bypassing JWT
- Fallback 3: drop activity injection, rely on user manual re-send

**R3 — `runner_host.invoke_capability` test seam** (low likelihood)
- Mitigation: extract envelope wrapping into a small testable helper that doesn't require WASM

**R4 — File ordering / atomicity in session store** (low likelihood)
- Two concurrent OAuth attempts in same bundle write different files (state token is unique). Two callbacks for the same state → second `consume()` returns "not found" — handled as session expired error.

**R5 — `reqwest` dep not in greentic-start `Cargo.toml`** (low likelihood)
- Detection: grep `Cargo.toml`. If missing, add at workspace version. `reqwest` is widely used elsewhere in greentic.

## Verification checklist

- [ ] `cargo fmt --all -- --check` clean
- [ ] `cargo clippy -p greentic-start --all-targets --all-features -- -D warnings` clean
- [ ] `cargo test -p greentic-start --all-features` all green (existing 427 + new ~17)
- [ ] Manual E2E against github-mcp-demo-bundle: card has resolved URL
- [ ] Manual E2E: clicking button opens real GitHub OAuth
- [ ] Manual E2E: callback completes, token persisted to secrets
- [ ] Manual E2E: webchat advances to next bot state (or manual re-send if flow doesn't pause)
- [ ] `updates/2026-04-11/greentic-start.md` changelog updated to cover Phase 1 + 2 + 3
