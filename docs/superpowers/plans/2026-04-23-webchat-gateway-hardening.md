# WebChat Gateway Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-IP rate limiting on `/v1/messaging/webchat/{tenant}/token` and tenant allowlist validation on `/v1/{messaging,web}/webchat/{tenant}/*` in the `greentic-start` HTTP ingress, making the `messaging-webchat-gui` pack safe for public embed usage.

**Architecture:** Two small guard functions in a new `src/http_ingress/guards.rs` module are called inline from `handle_request` before existing route dispatch. Rate limiter uses the `governor` crate with a bounded in-memory per-IP token bucket; tenant allowlist is an env-configured `HashSet<String>` membership check. Both are env-configurable with safe defaults.

**Tech Stack:** Rust 1.95 (edition 2024) / raw `hyper` (not axum) / `governor 0.6` / `dashmap` / `lru 0.12` / `tokio-rustls`.

**Scope:** `greentic-start` only. The `messaging-webchat-gui` pack, `greentic-runner`, and `greentic-designer` are unchanged.

**Branch:** `feat/webchat-gateway-hardening` off `develop`.

**Proposal reference:** `docs/proposals/2026-04-23-webchat-gateway-hardening.md` (the Plan B companion to the PR #82 AI Assistant template).

---

## File Structure

### New files

| Path | Responsibility | Approx. LoC |
|------|---------------|-------------|
| `src/http_ingress/guards.rs` | Rate limit + tenant allowlist guard functions + config parser + tests | ~280 |
| `tests/gateway_hardening.rs` | Hyper loopback integration tests (429 + allowlist 404 + happy path) | ~200 |

### Modified files

| Path | Change |
|------|--------|
| `Cargo.toml` | Add `governor = "0.6"`, `dashmap = "6"`, `lru = "0.12"` |
| `src/http_ingress/mod.rs` | Declare `mod guards;`; call `guards::rate_limit_guard` + `guards::tenant_allowlist_guard` from `handle_request` before route dispatch; thread `GatewayGuards` state through the service fn |
| `src/lib.rs` (or wherever the ingress is started) | Construct `GatewayGuards` from env at server boot, wire into the hyper service factory |
| `README.md` | Document the 5 new env vars |
| `docs/coding-agents.md` | Document gateway middleware behavior |

### Unchanged

- `src/http_ingress/{admin_relay,helpers,messaging,static_handler}.rs`
- `ingress_dispatch.rs` — guards run *before* dispatch
- Pack manifest / WIT contracts — purely server-side change

---

## Track G1 — Config + types

### Task G1.1: Define `GatewayGuards` config struct + env parser

**Files:**
- Create: `src/http_ingress/guards.rs`
- Modify: `src/http_ingress/mod.rs` (add `mod guards;`)

- [ ] **Step 1: Write failing tests (top of guards.rs)**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_env_defaults() {
        let cfg = GatewayGuardConfig::from_env_with(|_| None);
        assert_eq!(cfg.token_rate_per_min, 60);
        assert_eq!(cfg.token_burst, 10);
        assert!(!cfg.trust_xff);
        assert!(cfg.tenant_allowlist.is_none());
        assert_eq!(cfg.allowlist_mode, AllowlistMode::Permissive);
    }

    #[test]
    fn from_env_parses_overrides() {
        let map: std::collections::HashMap<&str, &str> = [
            ("GREENTIC_GATEWAY_TOKEN_RATE_PER_MIN", "120"),
            ("GREENTIC_GATEWAY_TOKEN_BURST", "20"),
            ("GREENTIC_GATEWAY_TRUST_XFF", "1"),
            ("GREENTIC_GATEWAY_TENANT_ALLOWLIST", "demo,acme, cisco "),
            ("GREENTIC_GATEWAY_TENANT_ALLOWLIST_MODE", "strict"),
        ]
        .into_iter()
        .collect();
        let cfg = GatewayGuardConfig::from_env_with(|k| map.get(k).map(|v| v.to_string()));
        assert_eq!(cfg.token_rate_per_min, 120);
        assert_eq!(cfg.token_burst, 20);
        assert!(cfg.trust_xff);
        let allowlist = cfg.tenant_allowlist.as_ref().unwrap();
        assert!(allowlist.contains("demo"));
        assert!(allowlist.contains("acme"));
        assert!(allowlist.contains("cisco")); // whitespace trimmed
        assert_eq!(cfg.allowlist_mode, AllowlistMode::Strict);
    }

    #[test]
    fn strict_mode_without_allowlist_denies_all() {
        let map: std::collections::HashMap<&str, &str> = [
            ("GREENTIC_GATEWAY_TENANT_ALLOWLIST_MODE", "strict"),
        ]
        .into_iter()
        .collect();
        let cfg = GatewayGuardConfig::from_env_with(|k| map.get(k).map(|v| v.to_string()));
        assert!(cfg.tenant_allowlist.is_none());
        assert!(cfg.is_tenant_allowed("demo") == false);
    }

    #[test]
    fn permissive_mode_without_allowlist_allows_all() {
        let cfg = GatewayGuardConfig::from_env_with(|_| None);
        assert!(cfg.is_tenant_allowed("demo"));
        assert!(cfg.is_tenant_allowed("anything"));
    }

    #[test]
    fn allowlist_respects_membership() {
        let map: std::collections::HashMap<&str, &str> = [
            ("GREENTIC_GATEWAY_TENANT_ALLOWLIST", "demo,acme"),
        ]
        .into_iter()
        .collect();
        let cfg = GatewayGuardConfig::from_env_with(|k| map.get(k).map(|v| v.to_string()));
        assert!(cfg.is_tenant_allowed("demo"));
        assert!(cfg.is_tenant_allowed("acme"));
        assert!(!cfg.is_tenant_allowed("unknown"));
    }
}
```

- [ ] **Step 2: Run to verify fails**

Run: `cargo test -p greentic-start http_ingress::guards::tests`
Expected: types/functions undefined.

- [ ] **Step 3: Implement config**

Prepend to `src/http_ingress/guards.rs`:

```rust
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowlistMode {
    Permissive,
    Strict,
}

#[derive(Debug, Clone)]
pub struct GatewayGuardConfig {
    pub token_rate_per_min: u32,
    pub token_burst: u32,
    pub trust_xff: bool,
    pub tenant_allowlist: Option<HashSet<String>>,
    pub allowlist_mode: AllowlistMode,
}

impl GatewayGuardConfig {
    pub fn from_env() -> Self {
        Self::from_env_with(|k| std::env::var(k).ok())
    }

    pub fn from_env_with<F: Fn(&str) -> Option<String>>(get: F) -> Self {
        let token_rate_per_min = get("GREENTIC_GATEWAY_TOKEN_RATE_PER_MIN")
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        let token_burst = get("GREENTIC_GATEWAY_TOKEN_BURST")
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);
        let trust_xff = matches!(
            get("GREENTIC_GATEWAY_TRUST_XFF").as_deref(),
            Some("1") | Some("true") | Some("yes")
        );
        let tenant_allowlist = get("GREENTIC_GATEWAY_TENANT_ALLOWLIST").map(|raw| {
            raw.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<HashSet<String>>()
        });
        let allowlist_mode = match get("GREENTIC_GATEWAY_TENANT_ALLOWLIST_MODE").as_deref() {
            Some("strict") => AllowlistMode::Strict,
            _ => AllowlistMode::Permissive,
        };
        Self {
            token_rate_per_min,
            token_burst,
            trust_xff,
            tenant_allowlist,
            allowlist_mode,
        }
    }

    pub fn is_tenant_allowed(&self, tenant: &str) -> bool {
        match (&self.tenant_allowlist, &self.allowlist_mode) {
            (Some(set), _) => set.contains(tenant),
            (None, AllowlistMode::Permissive) => true,
            (None, AllowlistMode::Strict) => false,
        }
    }
}
```

Declare module in `src/http_ingress/mod.rs`:

```rust
mod guards;
```

- [ ] **Step 4: Run**

Run: `cargo test -p greentic-start http_ingress::guards::tests`
Expected: 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/http_ingress/guards.rs src/http_ingress/mod.rs
git commit -m "feat(gateway): add GatewayGuardConfig env parser + allowlist logic"
```

---

## Track G2 — Rate limiter

### Task G2.1: Add deps + implement rate_limit_guard

**Files:**
- Modify: `Cargo.toml` (add `governor`, `dashmap`, `lru`)
- Modify: `src/http_ingress/guards.rs` (extend with rate limiter)

**Depends on:** G1.1

- [ ] **Step 1: Add deps**

Add to `[dependencies]` in `Cargo.toml`:

```toml
governor = "0.6"
dashmap = "6"
lru = "0.12"
```

Run `cargo check -p greentic-start` to verify resolution.

- [ ] **Step 2: Write failing tests**

Append to `src/http_ingress/guards.rs` test module:

```rust
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn rate_limiter_allows_under_budget() {
        let cfg = GatewayGuardConfig {
            token_rate_per_min: 6,  // 6/min = 0.1/sec, burst 2
            token_burst: 2,
            trust_xff: false,
            tenant_allowlist: None,
            allowlist_mode: AllowlistMode::Permissive,
        };
        let limiter = TokenRateLimiter::new(&cfg);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // 2 burst capacity: first 2 should pass
        assert!(limiter.check(ip).is_ok());
        assert!(limiter.check(ip).is_ok());
        // 3rd immediately after burst should 429
        assert!(limiter.check(ip).is_err());
    }

    #[test]
    fn rate_limiter_is_per_ip() {
        let cfg = GatewayGuardConfig {
            token_rate_per_min: 6,
            token_burst: 1, // tight
            trust_xff: false,
            tenant_allowlist: None,
            allowlist_mode: AllowlistMode::Permissive,
        };
        let limiter = TokenRateLimiter::new(&cfg);
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        assert!(limiter.check(ip_a).is_ok());
        assert!(limiter.check(ip_a).is_err()); // ip_a exhausted
        assert!(limiter.check(ip_b).is_ok()); // ip_b has its own bucket
    }
```

- [ ] **Step 3: Implement `TokenRateLimiter`**

Append to `src/http_ingress/guards.rs`:

```rust
use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    state::keyed::DashMapStateStore,
};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

pub struct TokenRateLimiter {
    limiter: Arc<RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>>,
}

impl TokenRateLimiter {
    pub fn new(cfg: &GatewayGuardConfig) -> Self {
        let per_min = NonZeroU32::new(cfg.token_rate_per_min.max(1)).unwrap();
        let burst = NonZeroU32::new(cfg.token_burst.max(1)).unwrap();
        let quota = Quota::per_minute(per_min).allow_burst(burst);
        let limiter = RateLimiter::dashmap(quota);
        Self {
            limiter: Arc::new(limiter),
        }
    }

    pub fn check(&self, ip: IpAddr) -> Result<(), governor::NotUntil<governor::clock::QuantaInstant>> {
        self.limiter.check_key(&ip)
    }
}

impl Clone for TokenRateLimiter {
    fn clone(&self) -> Self {
        Self {
            limiter: Arc::clone(&self.limiter),
        }
    }
}
```

- [ ] **Step 4: Run**

Run: `cargo test -p greentic-start http_ingress::guards::tests`
Expected: 7 tests pass (5 config + 2 rate limiter).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/http_ingress/guards.rs
git commit -m "feat(gateway): add per-IP token rate limiter (governor)"
```

### Task G2.2: Implement `rate_limit_guard` for `/token` path

**Files:**
- Modify: `src/http_ingress/guards.rs`

**Depends on:** G2.1

- [ ] **Step 1: Write failing tests**

Append:

```rust
    use hyper::{Request, Method};

    fn req(method: Method, path: &str) -> Request<()> {
        Request::builder().method(method).uri(path).body(()).unwrap()
    }

    #[test]
    fn guard_passes_non_token_paths() {
        let cfg = GatewayGuardConfig {
            token_rate_per_min: 1,
            token_burst: 1,
            trust_xff: false,
            tenant_allowlist: None,
            allowlist_mode: AllowlistMode::Permissive,
        };
        let limiter = TokenRateLimiter::new(&cfg);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        // Exhaust the (hypothetical) bucket
        let _ = limiter.check(ip);
        // Non-token path should not be rate-limited
        assert!(
            rate_limit_guard(&limiter, &cfg, &req(Method::GET, "/healthz"), ip)
                .is_none()
        );
        assert!(
            rate_limit_guard(
                &limiter,
                &cfg,
                &req(Method::POST, "/v1/messaging/webchat/demo/v3/directline/conversations"),
                ip
            )
            .is_none()
        );
    }

    #[test]
    fn guard_blocks_token_path_when_over_budget() {
        let cfg = GatewayGuardConfig {
            token_rate_per_min: 60,
            token_burst: 1,
            trust_xff: false,
            tenant_allowlist: None,
            allowlist_mode: AllowlistMode::Permissive,
        };
        let limiter = TokenRateLimiter::new(&cfg);
        let ip = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        // First call in budget
        assert!(
            rate_limit_guard(&limiter, &cfg, &req(Method::POST, "/v1/messaging/webchat/demo/token"), ip)
                .is_none()
        );
        // Second call over burst of 1 → should return Some(response)
        let resp = rate_limit_guard(
            &limiter,
            &cfg,
            &req(Method::POST, "/v1/messaging/webchat/demo/token"),
            ip,
        );
        assert!(resp.is_some());
    }
```

- [ ] **Step 2: Run to verify fails**

Run: `cargo test -p greentic-start http_ingress::guards::tests`
Expected: compile error — `rate_limit_guard` not defined.

- [ ] **Step 3: Implement guard**

Append:

```rust
use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode, body::Bytes};

const TOKEN_PATH_PREFIX: &str = "/v1/messaging/webchat/";
const TOKEN_PATH_SUFFIX: &str = "/token";

fn is_token_path(path: &str) -> bool {
    path.starts_with(TOKEN_PATH_PREFIX) && path.ends_with(TOKEN_PATH_SUFFIX)
}

pub fn rate_limit_guard<B>(
    limiter: &TokenRateLimiter,
    _cfg: &GatewayGuardConfig,
    req: &Request<B>,
    ip: IpAddr,
) -> Option<Response<Full<Bytes>>> {
    let path = req.uri().path();
    let method = req.method();
    if !is_token_path(path) || !matches!(method, &Method::GET | &Method::POST) {
        return None;
    }
    match limiter.check(ip) {
        Ok(_) => None,
        Err(not_until) => {
            let retry_after = not_until
                .wait_time_from(std::time::Instant::now().into())
                .as_secs()
                .max(1);
            let body = format!(
                r#"{{"error":"rate_limit_exceeded","retry_after_seconds":{retry_after}}}"#
            );
            let resp = Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("content-type", "application/json")
                .header("retry-after", retry_after.to_string())
                .body(Full::new(Bytes::from(body)))
                .unwrap();
            Some(resp)
        }
    }
}
```

Note: the `Request<B>` generic lets callers pass the hyper body type without the guard caring about body details.

- [ ] **Step 4: Run**

Run: `cargo test -p greentic-start http_ingress::guards::tests`
Expected: 9 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/http_ingress/guards.rs
git commit -m "feat(gateway): add rate_limit_guard for /token path"
```

---

## Track G3 — Tenant allowlist guard

### Task G3.1: Implement `tenant_allowlist_guard`

**Files:**
- Modify: `src/http_ingress/guards.rs`

**Depends on:** G1.1

- [ ] **Step 1: Write failing tests**

Append:

```rust
    #[test]
    fn allowlist_guard_passes_non_tenant_paths() {
        let cfg = GatewayGuardConfig {
            token_rate_per_min: 60,
            token_burst: 10,
            trust_xff: false,
            tenant_allowlist: Some(["demo"].iter().map(|s| s.to_string()).collect()),
            allowlist_mode: AllowlistMode::Permissive,
        };
        // Not a webchat path — passes through
        assert!(
            tenant_allowlist_guard(&cfg, &req(Method::GET, "/healthz")).is_none()
        );
        assert!(
            tenant_allowlist_guard(&cfg, &req(Method::GET, "/operator/op/invoke")).is_none()
        );
    }

    #[test]
    fn allowlist_guard_allows_listed_tenant() {
        let cfg = GatewayGuardConfig {
            token_rate_per_min: 60,
            token_burst: 10,
            trust_xff: false,
            tenant_allowlist: Some(["demo", "acme"].iter().map(|s| s.to_string()).collect()),
            allowlist_mode: AllowlistMode::Permissive,
        };
        assert!(
            tenant_allowlist_guard(
                &cfg,
                &req(Method::POST, "/v1/messaging/webchat/demo/token")
            )
            .is_none()
        );
        assert!(
            tenant_allowlist_guard(
                &cfg,
                &req(Method::GET, "/v1/web/webchat/acme/embed.js")
            )
            .is_none()
        );
    }

    #[test]
    fn allowlist_guard_rejects_unlisted_tenant() {
        let cfg = GatewayGuardConfig {
            token_rate_per_min: 60,
            token_burst: 10,
            trust_xff: false,
            tenant_allowlist: Some(["demo"].iter().map(|s| s.to_string()).collect()),
            allowlist_mode: AllowlistMode::Permissive,
        };
        let resp = tenant_allowlist_guard(
            &cfg,
            &req(Method::POST, "/v1/messaging/webchat/rogue/token"),
        );
        assert!(resp.is_some());
        assert_eq!(resp.unwrap().status(), StatusCode::NOT_FOUND);
    }
```

- [ ] **Step 2: Run to verify fails**

Run: `cargo test -p greentic-start http_ingress::guards::tests`
Expected: `tenant_allowlist_guard` undefined.

- [ ] **Step 3: Implement**

Append:

```rust
const TENANT_PATH_PREFIXES: &[&str] = &[
    "/v1/messaging/webchat/",
    "/v1/web/webchat/",
];

fn extract_tenant_from_path(path: &str) -> Option<&str> {
    for prefix in TENANT_PATH_PREFIXES {
        if let Some(rest) = path.strip_prefix(prefix) {
            let tenant = rest.split('/').next().unwrap_or("");
            if !tenant.is_empty() {
                return Some(tenant);
            }
        }
    }
    None
}

pub fn tenant_allowlist_guard<B>(
    cfg: &GatewayGuardConfig,
    req: &Request<B>,
) -> Option<Response<Full<Bytes>>> {
    let path = req.uri().path();
    let Some(tenant) = extract_tenant_from_path(path) else {
        return None;
    };
    if cfg.is_tenant_allowed(tenant) {
        return None;
    }
    let resp = Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::new()))
        .unwrap();
    Some(resp)
}
```

- [ ] **Step 4: Run**

Run: `cargo test -p greentic-start http_ingress::guards::tests`
Expected: 12 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/http_ingress/guards.rs
git commit -m "feat(gateway): add tenant_allowlist_guard with opaque 404"
```

---

## Track G4 — Wire into ingress + IP extraction

### Task G4.1: Thread guards through `handle_request` with XFF-aware IP extraction

**Files:**
- Modify: `src/http_ingress/mod.rs`
- Modify: `src/http_ingress/guards.rs` — add `resolve_client_ip(req, socket_ip, cfg)` helper

**Depends on:** G2.2, G3.1

This is the integration step. Provide the implementer with exact file:line refs to the existing `handle_request` + service fn so they know where to inject.

- [ ] **Step 1: Read context**

Read `src/http_ingress/mod.rs` around line 350-516 (`handle_request_inner` entry) and the service_fn wiring around line 50-200 (where the `SocketAddr` comes in from hyper's `conn` API). Note the existing state-threading pattern.

- [ ] **Step 2: Add IP resolver + test**

In `guards.rs`:

```rust
pub fn resolve_client_ip<B>(req: &Request<B>, socket_ip: IpAddr, cfg: &GatewayGuardConfig) -> IpAddr {
    if cfg.trust_xff {
        if let Some(xff) = req.headers().get("x-forwarded-for") {
            if let Ok(s) = xff.to_str() {
                if let Some(first) = s.split(',').next() {
                    if let Ok(parsed) = first.trim().parse::<IpAddr>() {
                        return parsed;
                    }
                }
            }
        }
    }
    socket_ip
}

#[cfg(test)]
mod ip_tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn req_with_xff(xff: &str) -> Request<()> {
        Request::builder()
            .header("x-forwarded-for", xff)
            .uri("/anything")
            .body(())
            .unwrap()
    }

    #[test]
    fn no_trust_returns_socket_ip() {
        let cfg = GatewayGuardConfig::from_env_with(|_| None);
        let socket_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let req = req_with_xff("203.0.113.1");
        assert_eq!(resolve_client_ip(&req, socket_ip, &cfg), socket_ip);
    }

    #[test]
    fn trust_returns_first_xff_hop() {
        let map: std::collections::HashMap<&str, &str> =
            [("GREENTIC_GATEWAY_TRUST_XFF", "1")].into_iter().collect();
        let cfg = GatewayGuardConfig::from_env_with(|k| map.get(k).map(|v| v.to_string()));
        let socket_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let req = req_with_xff("203.0.113.1, 198.51.100.2");
        assert_eq!(
            resolve_client_ip(&req, socket_ip, &cfg),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))
        );
    }

    #[test]
    fn trust_falls_back_on_malformed_xff() {
        let map: std::collections::HashMap<&str, &str> =
            [("GREENTIC_GATEWAY_TRUST_XFF", "1")].into_iter().collect();
        let cfg = GatewayGuardConfig::from_env_with(|k| map.get(k).map(|v| v.to_string()));
        let socket_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let req = req_with_xff("not-an-ip");
        assert_eq!(resolve_client_ip(&req, socket_ip, &cfg), socket_ip);
    }
}
```

Run: `cargo test -p greentic-start http_ingress::guards::ip_tests` — expect 3 pass.

- [ ] **Step 3: Wire into `handle_request`**

In `src/http_ingress/mod.rs`, the service fn should construct or accept a shared `GatewayGuards { cfg: Arc<GatewayGuardConfig>, limiter: TokenRateLimiter }` and pass it into `handle_request`. The hyper conn API exposes `SocketAddr`; extract it once and pass.

Before `handle_request_inner` is called:

```rust
let client_ip = guards::resolve_client_ip(&req, socket_addr.ip(), &guards.cfg);

// Allowlist first (cheaper than rate limit, and fails earlier)
if let Some(resp) = guards::tenant_allowlist_guard(&guards.cfg, &req) {
    return Ok(resp);
}

// Rate limit for /token
if let Some(resp) = guards::rate_limit_guard(&guards.limiter, &guards.cfg, &req, client_ip) {
    return Ok(resp);
}

// ... existing handle_request_inner call ...
```

Add a `GatewayGuards` struct in `guards.rs`:

```rust
#[derive(Clone)]
pub struct GatewayGuards {
    pub cfg: Arc<GatewayGuardConfig>,
    pub limiter: TokenRateLimiter,
}

impl GatewayGuards {
    pub fn from_env() -> Self {
        let cfg = GatewayGuardConfig::from_env();
        let limiter = TokenRateLimiter::new(&cfg);
        Self {
            cfg: Arc::new(cfg),
            limiter,
        }
    }
}
```

- [ ] **Step 4: Construct at startup**

Find the ingress server bootstrap (likely in `src/lib.rs` or `src/http_ingress/mod.rs::start`). Call `GatewayGuards::from_env()` once at startup, clone it into each accepted connection's service fn.

Log the config at startup (eprintln! to match existing style):

```rust
eprintln!(
    "Gateway guards: token_rate_per_min={}, burst={}, trust_xff={}, allowlist_mode={:?}, allowlist_size={}",
    guards.cfg.token_rate_per_min,
    guards.cfg.token_burst,
    guards.cfg.trust_xff,
    guards.cfg.allowlist_mode,
    guards.cfg.tenant_allowlist.as_ref().map(|s| s.len()).unwrap_or(0)
);
```

- [ ] **Step 5: Compile + regression test**

Run: `cargo test -p greentic-start --all-features`
Expected: no regression in existing tests.

- [ ] **Step 6: Commit**

```bash
git add src/http_ingress/guards.rs src/http_ingress/mod.rs src/lib.rs
git commit -m "feat(gateway): wire rate-limit + allowlist guards into hyper ingress"
```

---

## Track G5 — Integration tests

### Task G5.1: Hyper loopback test: 429 + allowlist 404 + happy path

**Files:**
- Create: `tests/gateway_hardening.rs`

**Depends on:** G4.1

- [ ] **Step 1: Write integration test**

This test spins up a minimal hyper server bound to loopback, dispatches mock handlers for `/token` and friends, and verifies guard behavior end-to-end.

```rust
//! Integration tests for gateway hardening guards.
//! These spin up a minimal hyper server on 127.0.0.1:0 and verify 429 + 404 + 200 paths.

use greentic_start::http_ingress::guards::{GatewayGuardConfig, GatewayGuards};
// ... hyper + tokio setup ...

#[tokio::test]
async fn over_budget_returns_429_with_retry_after() {
    // Create guards with burst=1 so the 2nd request 429s
    // Spin up a test server that invokes the guards + a stub backend
    // Hammer /v1/messaging/webchat/demo/token twice
    // Assert first = 200, second = 429 with Retry-After header
    todo!("see G5.1 step 3 for reference implementation below")
}

#[tokio::test]
async fn unlisted_tenant_returns_opaque_404() {
    // Create guards with allowlist=["demo"]
    // Hit /v1/messaging/webchat/rogue/token
    // Assert 404 with empty body
    todo!("see G5.1 step 3")
}

#[tokio::test]
async fn listed_tenant_passes_allowlist() {
    // allowlist=["demo"]
    // Hit /v1/web/webchat/demo/embed.js via the guards (bypasses actual static handler; test only verifies guard pass-through)
    todo!("see G5.1 step 3")
}
```

- [ ] **Step 2: Run to verify fails**

Run: `cargo test -p greentic-start --test gateway_hardening`
Expected: `todo!()` panics.

- [ ] **Step 3: Implement the hyper loopback harness + tests**

Use `hyper::server::conn::http1::Builder` + `tokio::net::TcpListener` + `hyper-util`. A minimal reference:

```rust
use bytes::Bytes;
use greentic_start::http_ingress::guards::{
    GatewayGuardConfig, GatewayGuards, TokenRateLimiter,
    rate_limit_guard, tenant_allowlist_guard, resolve_client_ip,
};
use http_body_util::{BodyExt, Empty, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

async fn spawn_test_server(guards: GatewayGuards) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, peer_addr) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let guards = guards.clone();
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req: Request<hyper::body::Incoming>| {
                            let guards = guards.clone();
                            async move {
                                let ip = resolve_client_ip(&req, peer_addr.ip(), &guards.cfg);
                                if let Some(resp) = tenant_allowlist_guard(&guards.cfg, &req) {
                                    return Ok::<_, std::convert::Infallible>(resp);
                                }
                                if let Some(resp) =
                                    rate_limit_guard(&guards.limiter, &guards.cfg, &req, ip)
                                {
                                    return Ok(resp);
                                }
                                // stub happy-path backend
                                Ok(Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::new(Bytes::from("ok")))
                                    .unwrap())
                            }
                        }),
                    )
                    .await;
            });
        }
    });

    addr
}

async fn send(addr: SocketAddr, method: Method, path: &str) -> (StatusCode, String) {
    let url = format!("http://{addr}{path}");
    let client = reqwest::Client::new();
    let resp = client.request(method, url).send().await.unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    (status.as_u16().into(), body)
}

#[tokio::test]
async fn over_budget_returns_429_with_retry_after() {
    let cfg = GatewayGuardConfig::from_env_with(|k| match k {
        "GREENTIC_GATEWAY_TOKEN_RATE_PER_MIN" => Some("60".into()),
        "GREENTIC_GATEWAY_TOKEN_BURST" => Some("1".into()),
        _ => None,
    });
    let limiter = TokenRateLimiter::new(&cfg);
    let guards = GatewayGuards {
        cfg: Arc::new(cfg),
        limiter,
    };
    let addr = spawn_test_server(guards).await;
    let (s1, _) = send(addr, Method::POST, "/v1/messaging/webchat/demo/token").await;
    let (s2, body2) = send(addr, Method::POST, "/v1/messaging/webchat/demo/token").await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::TOO_MANY_REQUESTS);
    assert!(body2.contains("rate_limit_exceeded"));
}

#[tokio::test]
async fn unlisted_tenant_returns_opaque_404() {
    let cfg = GatewayGuardConfig::from_env_with(|k| match k {
        "GREENTIC_GATEWAY_TENANT_ALLOWLIST" => Some("demo".into()),
        _ => None,
    });
    let limiter = TokenRateLimiter::new(&cfg);
    let guards = GatewayGuards {
        cfg: Arc::new(cfg),
        limiter,
    };
    let addr = spawn_test_server(guards).await;
    let (s, body) = send(addr, Method::POST, "/v1/messaging/webchat/rogue/token").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(body.is_empty(), "404 should have empty body");
}

#[tokio::test]
async fn listed_tenant_passes_allowlist() {
    let cfg = GatewayGuardConfig::from_env_with(|k| match k {
        "GREENTIC_GATEWAY_TENANT_ALLOWLIST" => Some("demo".into()),
        _ => None,
    });
    let limiter = TokenRateLimiter::new(&cfg);
    let guards = GatewayGuards {
        cfg: Arc::new(cfg),
        limiter,
    };
    let addr = spawn_test_server(guards).await;
    let (s, _) = send(addr, Method::GET, "/v1/web/webchat/demo/embed.js").await;
    assert_eq!(s, StatusCode::OK);
}
```

Add `reqwest = { version = "0.12", features = ["json"] }` + `hyper-util = { version = "0.1", features = ["tokio"] }` to `[dev-dependencies]` in `Cargo.toml` if not already present.

- [ ] **Step 4: Run**

Run: `cargo test -p greentic-start --test gateway_hardening`
Expected: 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add tests/gateway_hardening.rs Cargo.toml Cargo.lock
git commit -m "test(gateway): add hyper loopback integration tests for guards"
```

---

## Track G6 — Docs + PR

### Task G6.1: Document new env vars in README + coding-agents.md

**Files:**
- Modify: `README.md`
- Modify: `docs/coding-agents.md`

- [ ] **Step 1: Add README section**

After the existing configuration section, add:

```markdown
### Gateway hardening (webchat public surface)

When the `messaging-webchat-gui` pack is loaded and the embed widget is
exposed to public traffic, enable these guards:

| Env var | Default | Purpose |
|---------|---------|---------|
| `GREENTIC_GATEWAY_TOKEN_RATE_PER_MIN` | `60` | Per-IP requests/min to `/v1/messaging/webchat/{tenant}/token` |
| `GREENTIC_GATEWAY_TOKEN_BURST` | `10` | Token-bucket burst capacity |
| `GREENTIC_GATEWAY_TRUST_XFF` | unset | Set to `1` when behind a trusted reverse proxy to use `X-Forwarded-For` as client IP. **Do not enable without a proxy** — attackers can spoof the header and bypass rate limiting. |
| `GREENTIC_GATEWAY_TENANT_ALLOWLIST` | unset | Comma-separated tenant IDs allowed to match `{tenant}` in webchat routes. Unknown tenants return 404. |
| `GREENTIC_GATEWAY_TENANT_ALLOWLIST_MODE` | `permissive` | `strict` makes an unset allowlist reject all tenants (safer prod default); `permissive` (default) allows all when unset (back-compat). |

Rate-limit exceed → HTTP 429 with `Retry-After` header + JSON error body.
Allowlist miss → opaque HTTP 404 (indistinguishable from unknown route).
```

- [ ] **Step 2: Add coding-agents.md entry**

Document the module layout + testing expectations.

- [ ] **Step 3: Commit**

```bash
git add README.md docs/coding-agents.md
git commit -m "docs(gateway): document hardening env vars + behavior"
```

### Task G6.2: Final CI + push + open PR

- [ ] `bash ci/local_check.sh`
- [ ] `git push -u origin feat/webchat-gateway-hardening`
- [ ] `gh pr create --base develop --title "feat: webchat gateway hardening (rate limit + tenant allowlist)"` with the body below

PR body:

```
## Summary

Plan B companion to greentic-designer PR #82 (AI Assistant template).
Adds rate limiting + tenant allowlist to greentic-start's HTTP ingress
so the messaging-webchat-gui embed is safe for public use.

- Per-IP rate limit on /v1/messaging/webchat/{tenant}/token (default 60/min, burst 10)
- Tenant allowlist on /v1/{messaging,web}/webchat/{tenant}/* (opaque 404 on miss)
- 5 new env vars, all with back-compat defaults
- X-Forwarded-For support gated behind explicit opt-in
- Hyper-level guards (no axum dep added); +governor, +dashmap, +lru

## Test plan

- [x] cargo test -p greentic-start --all-features
- [x] bash ci/local_check.sh
- [x] 3 new integration tests (429, allowlist 404, happy path) via hyper loopback
- [ ] Manual smoke: curl hammer /token with GREENTIC_GATEWAY_TOKEN_BURST=1 → verify 429
- [ ] Manual smoke: GREENTIC_GATEWAY_TENANT_ALLOWLIST=demo → verify /v1/web/webchat/rogue/embed.js returns 404

## Out of scope (future)

- Direct Line activity endpoint rate limits (/v3/directline/*)
- Per-tenant rate limits
- Redis-backed distributed limiter
- Telemetry metrics
```

---

## Self-Review

**Spec coverage check:**
- ✅ Per-IP rate limit → Track G2
- ✅ Tenant allowlist → Track G3
- ✅ 5 env vars → Track G1 + G4
- ✅ XFF handling → Task G4.1
- ✅ Integration tests → Track G5
- ✅ Docs → Track G6
- ❌ Bounded IP LRU — deferred. Governor's `dashmap` store has no built-in eviction. If ops pressure, add `lru` wrap in a follow-up. Documented in proposal risks.

**Placeholder scan:** All "see G5.1 step 3" references resolve to actual code in the same task. No TODO / TBD.

**Type consistency:**
- `TokenRateLimiter::check` returns `Result<(), NotUntil<...>>` (G2.1) — consumed by `rate_limit_guard` (G2.2) — consistent
- `GatewayGuards { cfg, limiter }` (G4.1) — consumed by integration tests (G5.1) — consistent
- `is_tenant_allowed` (G1.1) — consumed by `tenant_allowlist_guard` (G3.1) — consistent

---

## Execution Handoff

**Plan complete. Two execution options:**

**1. Subagent-Driven** — controller dispatches fresh subagent per task with two-stage review. Recommended if you want review checkpoints between tasks.

**2. Inline Execution** — all tasks in one session with checkpoints at track boundaries.

**Which approach?**
