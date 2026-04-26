# WebChat Gateway Hardening — Proposal

**Status:** Draft for alignment (pre-implementation)
**Author:** Bima
**Date:** 2026-04-23
**Audience:** Maarten (approval), team (reference)
**Companion:** Plan B to `greentic-designer/docs/proposals/2026-04-23-ai-assistant-template.md` (PR #82). Both ship independently.

## Summary

Add two middleware layers to the `greentic-start` HTTP ingress to make the `messaging-webchat-gui` pack's public endpoints safe for production embed usage:

1. **Per-IP rate limit** on `/v1/messaging/webchat/{tenant}/token` — currently unthrottled, directly backed by the WASM pack's `ingest_http` which mints short-lived Direct Line JWTs.
2. **Tenant allowlist validation** — the `{tenant}` path segment currently accepts any non-empty value and is passed straight to the WASM component; malicious tenants could probe bucket/namespace collisions or generate noise.

Both are prerequisites for exposing the Web embed widget on public marketing pages (the use case Maarten confirmed 2026-04-23).

## Context

Gateway architecture (confirmed via recon 2026-04-23):

- **Binary:** `greentic-start`
- **Ingress entry:** `src/http_ingress/mod.rs:350–516` (`handle_request_inner`)
- **Stack:** raw `hyper` (not axum) + `tokio-rustls`
- **Routes in scope:**
  - `GET|POST /v1/messaging/webchat/{tenant}/token` — Direct Line token mint
  - `* /v1/messaging/webchat/{tenant}/v3/directline/{path*}` — Direct Line proxy (send message, receive activities, WebSocket upgrade)
  - `GET /v1/web/webchat/{tenant}/*` — static assets (embed.js, skin.json, index.html) served directly from pack ZIP
- **Dispatch:** `ingress_dispatch.rs:64` — `runner_host.invoke_provider_op(domain, &request.provider, "ingest_http", ...)`
- **Tenant extraction:** `http_routes.rs:131–139` — path segment parsed, empty-check only, no validation

## Goals

1. `/token` per-IP rate limit prevents abuse of the public JWT mint surface.
2. Unknown-tenant requests rejected **before** they reach the WASM component (don't trust input, don't pay WASM dispatch cost for noise).
3. Operator can configure both via environment variables without recompiling.
4. Zero breaking changes for existing internal/private deployments that don't set the new env vars.

## Non-Goals

- Rate limiting beyond `/token` — Direct Line activity endpoints (`/v3/directline/*`) have their own DoS characteristics (websocket, authenticated via minted JWT) and are out of scope for this round.
- User-level rate limiting — per-IP is sufficient for Phase 1 public embed. Per-tenant or per-JWT limits can come later if abuse patterns emerge.
- Authentication for static assets (`/v1/web/webchat/{tenant}/*`) — these are intentionally public (the embed HTML/JS/CSS). No change.
- A full WAF or DDoS layer — Cloudflare/CloudFront/nginx in front of `greentic-start` remains the right place for that. Our middleware is an always-on fallback.
- Metrics / telemetry for the new middleware — can plug into existing `tracing` spans, but no new metrics endpoint.

## Architecture

### Middleware placement

```
hyper::service_fn
  └─ handle_request (src/http_ingress/mod.rs)
       └─ [NEW] rate_limit_guard (per-IP token bucket, only for /token)
       └─ [NEW] tenant_allowlist_guard (after route match, before dispatch)
       └─ handle_request_inner
            └─ match route → static_handler | dispatch_http_ingress → WASM
```

Both guards live as small functions in a new `src/http_ingress/guards.rs` module (~150 lines) and are called inline from `handle_request` before existing dispatch logic. This avoids adding a middleware framework on top of raw hyper.

### Rate limiter design

- Use the `governor` crate (`^0.6`) — well-maintained, no_std-friendly token bucket
- Key by remote IP address (extracted from `SocketAddr` that hyper gives the service fn; respect `X-Forwarded-For` only when `GREENTIC_GATEWAY_TRUST_XFF=1` to prevent header-spoof bypass)
- Bucket: default 60 requests/minute per IP, burst 10
- Configuration via env: `GREENTIC_GATEWAY_TOKEN_RATE_PER_MIN` (default 60), `GREENTIC_GATEWAY_TOKEN_BURST` (default 10), `GREENTIC_GATEWAY_TRUST_XFF` (default unset = off)
- On exceed: HTTP 429 with `Retry-After` header
- Scope: **only** `/v1/messaging/webchat/{tenant}/token` — the guard short-circuits if path doesn't match
- Storage: in-memory `governor::RateLimiter` with `DashMap`-backed keyed store (bounded LRU of ~10k IPs to cap memory)

### Tenant allowlist design

- Configuration via env: `GREENTIC_GATEWAY_TENANT_ALLOWLIST` — comma-separated list of tenant IDs (e.g. `demo,acme,cisco`)
- **Default when unset: allow all** (back-compat — private/internal deployments keep current behavior)
- When set: requests whose path `{tenant}` segment is not in the list get HTTP 404 (opaque to hide existence of valid tenants)
- Applied to both `/v1/messaging/webchat/{tenant}/*` and `/v1/web/webchat/{tenant}/*` so `embed.js` also 404s for unknown tenants (prevents enumeration via static asset availability)
- Optional mode via `GREENTIC_GATEWAY_TENANT_ALLOWLIST_MODE=strict` — when `strict`, even unset allowlist is treated as "empty = deny all" so operators can't forget to configure it in production

### Response shape

Both guards return minimal JSON errors to match the rest of the gateway's error convention (see `helpers::error_response`):

- 429: `{"error": "rate_limit_exceeded", "retry_after_seconds": 30}` + `Retry-After: 30` header
- 404 (unknown tenant): existing opaque 404 response (no body) — indistinguishable from "route not found"

## Configuration surface (new env vars)

| Env var | Default | Purpose |
|---------|---------|---------|
| `GREENTIC_GATEWAY_TOKEN_RATE_PER_MIN` | `60` | Per-IP requests/min to `/token` |
| `GREENTIC_GATEWAY_TOKEN_BURST` | `10` | Burst capacity |
| `GREENTIC_GATEWAY_TRUST_XFF` | unset (off) | Extract IP from `X-Forwarded-For` when behind trusted proxy |
| `GREENTIC_GATEWAY_TENANT_ALLOWLIST` | unset (allow all) | Comma-separated tenant allowlist |
| `GREENTIC_GATEWAY_TENANT_ALLOWLIST_MODE` | `permissive` | `permissive` (unset = allow all) or `strict` (unset = deny all) |

All documented in README + `docs/coding-agents.md`.

## Phases

**Phase 1 (this plan) — ~3-4 dev days:**
- Rate limit middleware + per-IP token bucket + env config
- Tenant allowlist guard + env config
- Unit tests (IP parsing, bucket semantics, allowlist match)
- Integration tests (loopback hyper server, verify 429 + 404 + success paths)
- README + `coding-agents.md` update

**Phase 2 (future, not in this plan):**
- Per-tenant rate limits (e.g. enterprise tier gets higher budget)
- Redis-backed rate limiter for multi-instance deployments (current in-memory store is per-process)
- Integration with telemetry capability (metrics + spans)

## Open questions

1. **Default allowlist mode** — recommended `permissive` (unset = allow all) for back-compat, but is `strict` the right prod default? Breaking change for existing deployments if we flip.
2. **XFF trust** — should trust-XFF be on-by-default when a Cloudflare/ngrok front is detected via request path/headers? Or keep it strict opt-in?
3. **Burst size** — 10 for embedded chat token refreshes feels reasonable; confirm against observed patterns if any telemetry exists from current deployments.
4. **`RateLimiter` eviction** — 10k IP LRU cap is arbitrary; do we expect wider IP diversity that warrants a larger bound?
5. **Integration with existing admin API** — should the new rate-limit hits count toward an admin-visible metric at `/admin/metrics` or similar (future endpoint)?

## Risks

- **Hyper-level middleware ≠ tower layers** — implementation is hand-rolled, so tests must cover race conditions + middleware ordering that a framework would handle. Mitigation: targeted integration tests that spin up a hyper server and hammer `/token`.
- **`governor` DashMap-keyed store unbounded growth** — IP diversity in abuse scenarios could OOM. Mitigation: bounded LRU with `lru` crate or size-capped `DashMap` + eviction task.
- **Back-compat surface** — existing `:demo` deployments may break if `ALLOWLIST_MODE=strict` is set without listing `demo`. Mitigation: default `permissive` + loud startup log when allowlist is configured but empty.
- **`GREENTIC_GATEWAY_TRUST_XFF` misuse** — enabling XFF trust without a real proxy in front lets attackers spoof `X-Forwarded-For` and bypass the rate limit per-IP. Mitigation: doc warning + no-trust default.

## Dependencies

- `governor = "0.6"` (new) — rate limiter
- `dashmap` (already in workspace elsewhere; may need to add to `greentic-start`)
- `lru = "0.12"` (new, for IP LRU cap)
- No breaking change to existing deps

## Next Steps

1. Maarten reviews this proposal + answers open Q1-5
2. Executable implementation plan via `writing-plans` skill (TDD-style, companion at `docs/superpowers/plans/2026-04-23-webchat-gateway-hardening.md`)
3. Execute via subagent-driven development on `feat/webchat-gateway-hardening` branch (targeting `develop`)
4. Review checkpoint after rate-limit lands, then after allowlist, then integration test round
