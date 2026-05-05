# WebChat WebSocket — Redis Backplane (Phase C) Design

| Field | Value |
|---|---|
| Date | 2026-05-01 |
| Status | Draft (pending implementation plan) |
| Owner | Bima Pangestu |
| Repo | `greentic-start` (cross-repo touch-points: `greentic-setup`) |
| Branch | `feat/webchat-ws-redis-backplane` (off `develop`) |
| Phase | C of the WebChat DirectLine WebSocket roadmap |
| Related | Phase B (`feature/webchat-websocket-mvp`, PR #111, merged 2026-04-26 into `develop`) |
| Driving incident | 3Point demo P0 (`/home/bima-pangestu/.claude/.../project_3point_escalation.md`); quality > features |

## 1. Context

Phase B delivered a working Direct Line WebSocket implementation in `greentic-start` on `origin/develop`:

- `src/http_ingress/websocket/{mod,upgrade,session,pump,protocol}.rs` — handshake, JWT auth, session limits (`WsLimits`: 1000/tenant, 5/conv, 300s idle, 1000-replay, 1 MiB frame), replay-then-live pump.
- `src/notifier/{mod.rs,memory.rs}` — `ActivityNotifier` trait + `NotifyEvent { tenant_id, conversation_id, new_watermark }` + `InMemoryNotifier` using tokio `broadcast` channels keyed by `(tenant, conv)`.
- Publish hook (`b7717c4`) wired into `src/http_ingress/mod.rs` + `src/runner_host/dispatch.rs`: every time the WASM webchat provider writes an activity, `notifier.publish(NotifyEvent { ... })` fires.

**Phase B is single-replica.** The notifier's broadcast channel is in-process, so a WebSocket session connected to replica A does not receive activities published on replica B. Phase C closes that gap with a Redis pub/sub backplane.

This spec covers **only the Redis backplane**. Other Phase B/C hardening items (per-IP caps, origin allowlist, token TTL auto-close, slow-consumer drop, full Prometheus metrics, token refresh endpoint) are out of scope and tracked separately (see §9).

## 2. Goal / Non-Goals

### Goal

Activities published on any replica are delivered to WebSocket clients connected to **any** replica of the same operator, while preserving:

- Existing single-replica behavior when Redis is not configured (zero-config local dev).
- Strict configuration validation at boot — a misconfigured operator fails fast.
- Soft runtime degradation — transient Redis unavailability does not break sessions on the same replica.
- The existing `ActivityNotifier` trait surface — no call-site changes outside `src/notifier/`.

### Non-goals

- Persistence of activities at the notifier layer (the WASM webchat provider is the source of truth; notifier is a wake-up signal).
- Replacing the in-memory notifier (it remains the default for local dev and single-replica deployments).
- Multi-tenant isolation at the Redis ACL/network layer (operator concern; addressable via Redis ACL configured outside greentic-start).
- Redis Cluster topology (single-node + sentinel are supported; cluster has known PUBSUB caveats and is deferred).
- A `/metrics` Prometheus endpoint (Phase C ships internal `tracing`-based counters only).

## 3. Decisions

| # | Topic | Decision |
|---|---|---|
| D1 | Backend | Redis pub/sub |
| D2 | Mode selection | Config-driven via `greentic.yaml`. **No `--production` runtime flag.** Default `Memory`, opt-in `Redis`. |
| D3 | Redis URL source | Auto-share with the `state-redis` provider. Explicit `url` override allowed. |
| D4 | Failover semantics | Strict at boot (refuse to start if Redis unreachable); soft at runtime (degrade to local-only fan-out, reconnect with exponential backoff). |
| D5 | Channel topology | Single global channel `greentic:webchat:notify` + replica-side filter via the existing per-conv `InMemoryNotifier`. |
| D6 | URL discovery | Implicit auto-detect from the `state-redis` `ConfigEnvelope` (same secret URI resolution as `qa_persist.rs`). |

### Technical defaults (locked, not user-blocking)

| Item | Value | Why |
|---|---|---|
| Crate | `redis = "0.27"` with features `["tokio-comp", "connection-manager"]` | Mainstream, well-maintained, sentinel discovery via URL, `ConnectionManager` provides automatic reconnect for the publish path. |
| Topology | Single-node + sentinel-via-URL | MVP fit; cluster deferred (see §9). |
| Channel name | `greentic:webchat:notify` | Prefixed to avoid collision with state-redis keyspace; configurable via `webchat.notifier.channel`. |
| Wire payload | JSON `{ tenant_id, conversation_id, new_watermark, version, instance_id }` | `version` for forward-compat; `instance_id` for loop suppression. |
| Loop-suppression key | UUIDv4 generated per process | Effectively zero collision risk; cheap. |
| Counter surface | `tracing` events with `target = "notifier_redis"` | Defers full Prometheus surface to a follow-up. Searchable via existing log pipeline. |

## 4. Architecture

`RedisNotifier` is a **wrapper** around `InMemoryNotifier`. Composition, not replacement.

```
                                  greentic-start (replica A)
  +-------------------------------------------------------------+
  |  publish(event)              subscribe(tenant, conv)        |
  |       |                              |                      |
  |       v                              v                      |
  |  +----------------------------------------+                 |
  |  |           RedisNotifier                |                 |
  |  |                                        |                 |
  |  |  pub: PUBLISH greentic:webchat:notify  |                 |
  |  |  sub: SUBSCRIBE greentic:webchat:notify|                 |
  |  |                                        |                 |
  |  |  inner: Arc<InMemoryNotifier>          |                 |
  |  |   |-- publish() always called locally  |                 |
  |  |   `-- subscribe() delegated as-is      |                 |
  |  |                                        |                 |
  |  |  background_task: read SUB stream ->   |                 |
  |  |    skip if instance_id == self.id ->   |                 |
  |  |    inner.publish(event)                |                 |
  |  +----------------------------------------+                 |
  +-------------------------------------------------------------+
                            ^          |
                            |SUB       |PUB
                            |          v
                       +----------------------+
                       |   Redis (shared)     |
                       |   chan: greentic:    |
                       |   webchat:notify     |
                       +----------------------+
                            ^          |
                            |PUB       |SUB
                            |          v
  +-------------------------------------------------------------+
  |              greentic-start (replica B)                     |
  |              (mirror of A)                                  |
  +-------------------------------------------------------------+
```

### Properties

- `subscribe()` from WS sessions stays in-process; no Redis call per session open.
- `publish()` from the existing post-op hook fires the local broadcast **first** (instant fan-out for same-replica sessions), **then** mirrors to Redis fire-and-forget.
- Background SUB task drops messages where `instance_id == self.id` (loop-back suppression).
- Cross-replica delivery: replica B's background task receives the published wire payload, `inner.publish(event)` fans out to local subscribers, the existing `Pump` re-fetches via `ActivitySource` and emits the new activity to the WS sink.
- When Redis is disconnected: same-replica sessions keep working; cross-replica is frozen until reconnect; backoff retries; nothing in the call graph blocks on Redis.
- `InMemoryNotifier` itself is unchanged.

### Module layout

```
src/notifier/
  mod.rs        # trait ActivityNotifier (signature unchanged)
                # NotifierConfig: add Redis { url, channel, capacity }
                # build_notifier() factory: handle Redis branch (becomes async + Result<>)
  memory.rs     # InMemoryNotifier — no change
  redis.rs      # NEW: RedisNotifier { inner, pub_conn, self_id, ... }
  config.rs     # NEW: resolve_notifier_config() — auto-detect from state-redis envelope
```

## 5. Data Flow

### 5.1 Publish path (event happens on replica A)

```
post-op hook in src/http_ingress/mod.rs
    +-> notifier.publish(event)
        +-> RedisNotifier::publish(event)
            +-> inner.publish(event.clone())                   // ALWAYS, instant local
            `-> match self.state.read():
                  Connected(pub_conn) =>
                      let payload = serde_json::to_vec(&Wire {
                          tenant_id, conversation_id, new_watermark,
                          version: 1,
                          instance_id: self.self_id,
                      });
                      tokio::spawn(async move {
                          let _ = pub_conn.publish::<_,_,()>(channel, payload).await;
                          // failures: tracing::debug!, increment counter, do NOT propagate
                      });
                  Reconnecting | Failed =>
                      counter "redis_publish_dropped" += 1
                      // local already done above; same-replica sessions still get it
```

**Invariant:** `inner.publish` always runs first. Same-replica sessions never depend on Redis health.

### 5.2 Subscribe path (WS session opens on replica A)

```
http_ingress upgrade handler
    +-> notifier.subscribe(tenant_id, conversation_id)
        +-> RedisNotifier::subscribe(tenant, conv)
            `-> delegate to inner.subscribe(tenant, conv)
                (returns local broadcast stream; no Redis call)
```

### 5.3 Background SUB task (one per process, lifetime = process)

Spawned at notifier construction time:

```
loop {
    match self.state.write() {
        Connected(sub_stream) => {
            while let Some(msg) = sub_stream.next().await {
                let wire: Wire = match serde_json::from_slice(&msg.payload) {
                    Ok(w) => w,
                    Err(err) => {
                        tracing::debug!(target: "notifier_redis", ?err, "decode_err");
                        counter "redis_decode_err" += 1;
                        continue;
                    }
                };
                if wire.instance_id == self.self_id { continue; }   // loop suppression
                if wire.version != 1 {
                    tracing::warn!(target: "notifier_redis", v = wire.version, "unknown_version");
                    counter "redis_unknown_version" += 1;
                    continue;
                }
                inner.publish(NotifyEvent {
                    tenant_id: wire.tenant_id,
                    conversation_id: wire.conversation_id,
                    new_watermark: wire.new_watermark,
                }).await;
            }
            // stream ended = disconnect
            self.state = Reconnecting { attempt: 0 };
            counter "redis_disconnected" += 1;
        }
        Reconnecting { attempt } => {
            let delay = backoff_with_jitter(attempt);
            tokio::time::sleep(delay).await;
            match try_subscribe(&url, &channel).await {
                Ok(stream) => {
                    self.state = Connected(stream);
                    counter "redis_reconnect_ok" += 1;
                    tracing::info!(target: "notifier_redis", "reconnected");
                }
                Err(err) => {
                    counter "redis_reconnect_fail" += 1;
                    self.state = Reconnecting { attempt: attempt + 1 };
                }
            }
        }
    }
}
```

### 5.4 Backoff schedule

Exponential with jitter, capped:

| Attempt | Base delay | With ±20% jitter |
|---|---|---|
| 0 | 100 ms | 80–120 ms |
| 1 | 250 ms | 200–300 ms |
| 2 | 500 ms | 400–600 ms |
| 3 | 1 s | 800ms–1.2s |
| 4 | 2 s | 1.6–2.4 s |
| 5+ | 5 s | 4–6 s |

### 5.5 Connection model — separate PUB and SUB

A Redis connection in `SUBSCRIBE` mode can only receive pub/sub messages until `UNSUBSCRIBE`. Therefore:

- **SUB connection**: dedicated, owned by background task. Reconnect logic above.
- **PUB connection**: shared, managed by `redis::aio::ConnectionManager` (its built-in reconnect handles transient failures transparently). Each `publish()` call spawns a short task using a cloned manager handle.

### 5.6 Startup sequence (strict)

```rust
// in src/lib.rs (or boot path that already builds InMemoryNotifier today)
let notifier_cfg = resolve_notifier_config(
    &operator_root,
    &operator_config,
    &secrets_store,
    env,
    tenant,
).await?;
// ^ for backend=redis with url=None, reads state-redis ConfigEnvelope and resolves secret URI

let notifier: Arc<dyn ActivityNotifier> = build_notifier(notifier_cfg).await?;
// ^ async + Result<>: pings Redis (open SUB, open PUB), fails boot if either errors
```

`build_notifier` for `Redis`:

1. Open SUB connection. `SUBSCRIBE channel`. Return `Err` on failure.
2. Build PUB `ConnectionManager`. Return `Err` on failure.
3. Spawn background SUB task.
4. Return `Arc<RedisNotifier>`.

### 5.7 Failure modes

| Scenario | Behavior |
|---|---|
| Redis unreachable at boot | `gtc start` exits non-zero. Error message identifies the resolved Redis URL. |
| `backend: redis` but `state-redis` provider not configured | Boot error: "Redis backplane requires the `state-redis` provider — run `gtc setup --provider state-redis` first, or set `webchat.notifier.url` explicitly in `greentic.yaml`." |
| Redis disconnects after boot | Local fan-out keeps working; cross-replica frozen; reconnect with backoff; `redis_disconnected`/`redis_reconnect_*` counters visible in tracing logs. |
| Reconnect succeeds | Subscribe resumes. **No replay** — the existing Pump re-fetches from `ActivitySource` on the next event, so missed events surface on the next user activity. |
| Replica receives its own publish | Dropped via `instance_id` suppression. |
| Malformed payload from Redis | Dropped, `redis_decode_err` counter increments, loop continues. |
| Wire version mismatch | Dropped, `redis_unknown_version` counter increments, loop continues. |
| Slow local consumer (broadcast channel full) | Inherits existing `InMemoryNotifier` behavior — broadcast channel drops oldest. |
| Background task panics | Wrapped with explicit panic handler that logs + transitions to `Reconnecting { attempt: 0 }`. |

## 6. Configuration & Auto-Detect

### 6.1 `NotifierConfig` enum

Extend `src/notifier/mod.rs`:

```rust
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "backend", rename_all = "lowercase")]
pub enum NotifierConfig {
    Memory {
        #[serde(default = "default_capacity")]
        capacity: usize,
    },
    Redis {
        /// Optional explicit URL. If absent, resolved from state-redis ConfigEnvelope.
        #[serde(default)]
        url: Option<String>,
        /// Channel name override. Default: "greentic:webchat:notify".
        #[serde(default)]
        channel: Option<String>,
        /// Local in-memory broadcast capacity (passed through to inner InMemoryNotifier).
        #[serde(default = "default_capacity")]
        capacity: usize,
    },
}

fn default_capacity() -> usize { 64 }

impl Default for NotifierConfig {
    fn default() -> Self { NotifierConfig::Memory { capacity: 64 } }
}
```

### 6.2 `greentic.yaml` schema addition

New optional top-level section. Absent or unset → default `Memory`.

```yaml
# greentic.yaml — new section, all fields optional under webchat.notifier
webchat:
  notifier:
    backend: redis        # "memory" (default) | "redis"
    # url:     redis://...           # optional override; defaults to state-redis URL
    # channel: greentic:webchat:notify   # optional override
    # capacity: 64                   # optional override (local broadcast channel size)
```

For 95% of operators with state-redis already configured, the two non-comment lines above are the only edit needed. The wizard (see §6.4) writes them.

`OperatorConfig` extension in `src/config.rs`:

```rust
#[derive(Clone, Debug, Deserialize, Default)]
pub struct OperatorConfig {
    #[serde(default)]
    pub services: Option<OperatorServicesConfig>,
    #[serde(default)]
    pub binaries: BTreeMap<String, String>,
    #[serde(default)]                          // NEW
    pub webchat: Option<WebchatConfig>,        // NEW
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct WebchatConfig {
    #[serde(default)]
    pub notifier: NotifierConfig,
}
```

YAML parsing uses `serde_yaml_gtc` (imported as `serde_yaml_bw`) per the repo convention — same path as existing `OperatorConfig` deserialization in `load_operator_config`.

### 6.3 Auto-detect — `resolve_notifier_config()`

New function in `src/notifier/config.rs`:

```rust
pub async fn resolve_notifier_config(
    operator_root: &Path,
    operator_config: &OperatorConfig,
    secrets_store: &DevStore,
    env: &str,
    tenant: &str,
) -> anyhow::Result<NotifierConfig> {
    let raw = operator_config
        .webchat
        .as_ref()
        .map(|w| w.notifier.clone())
        .unwrap_or_default();

    match raw {
        NotifierConfig::Memory { .. } => Ok(raw),
        NotifierConfig::Redis { url: Some(_), .. } => Ok(raw),  // explicit override wins
        NotifierConfig::Redis { url: None, channel, capacity } => {
            let envelope = read_provider_config_envelope(operator_root, "state-redis")
                .with_context(|| {
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

            let resolved_url = resolve_secret_uri(secrets_store, env, tenant, url_field)
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
```

### 6.4 Wizard step (`greentic-setup` repo)

A single Y/N prompt added to the operator setup wizard, conditional on whether state-redis is in the current setup answers:

```
? Enable Redis backplane for WebChat WebSocket multi-replica fan-out? (Y/n)
  -> if state-redis is configured: writes webchat.notifier.backend=redis (auto URL)
  -> if not configured: prints "skipping (state-redis not configured)" and writes nothing
```

Implementation lives alongside the existing state-redis prompt in `greentic-setup` (exact module identified during planning). The prompt string and the "skipping" message MUST be added to `greentic-setup/i18n/en.json` (or the equivalent source catalog for that repo) — per the workspace convention "Never hardcode user-facing strings" — and translated via the existing `tools/i18n.sh` flow.

The yaml-write side patches `greentic.yaml` via whichever operator-config write helper greentic-setup already uses for `services` and `binaries` sections. If no shared helper covers the `webchat` section yet, the plan adds a focused helper rather than performing in-place line edits.

### 6.5 New helpers

| Helper | Location | Notes |
|---|---|---|
| `read_provider_config_envelope(root, provider_id)` | `src/provider_config_envelope.rs` (existing file) | New sibling to `write_provider_config_envelope`; CBOR read using `greentic_types::cbor::canonical`. |
| `resolve_secret_uri(store, env, tenant, raw)` | Reuse from `secrets_client.rs` if present; otherwise extract the same logic used in `qa_persist.rs::persist_qa_secrets`. | Per reuse-first policy, prefer the existing helper. Confirm during planning. |

## 7. Testing Strategy

### 7.1 Unit tests (no external dependency, run on `cargo test` default)

Located in `src/notifier/redis.rs` (`#[cfg(test)] mod tests`).

| Test | Verifies |
|---|---|
| `wire_payload_roundtrip` | JSON encode/decode of `Wire`. |
| `loop_suppression_drops_self_publish` | Synthesize a `Wire` with `instance_id == self.id`, feed into the dispatch fn directly, assert `inner.publish` NOT called. |
| `loop_suppression_accepts_other_replica` | Same but with a different `instance_id`, assert `inner.publish` IS called. |
| `dispatch_drops_unknown_version` | Wire with `version: 99` dropped without panic. |
| `dispatch_drops_malformed_payload` | Non-JSON bytes dropped without panic. |
| `notifier_config_serde_default` | `serde_yaml_bw::from_str("")` → `Memory { capacity: 64 }`. |
| `notifier_config_serde_redis_minimal` | `backend: redis` only → `Redis { url: None, channel: None, capacity: 64 }`. |
| `notifier_config_serde_redis_full` | All fields populated parse correctly. |
| `resolve_notifier_config_explicit_url_skips_autodetect` | Mocked `read_provider_config_envelope` panics; `Redis { url: Some(_) }` should never call it. |
| `resolve_notifier_config_autodetect_missing_state_redis_errors` | Mock returns `Err` → propagates with helpful context. |
| `resolve_notifier_config_autodetect_resolves_secret_uri` | URL = `secret://state-redis/url` → reads from mock secrets store, returns resolved literal. |

For testability the dispatch body of the background SUB task is extracted into a free function:

```rust
fn process_incoming(
    payload: &[u8],
    self_id: Uuid,
    inner: &dyn ActivityNotifier,
);
```

This lets unit tests exercise loop suppression and decode paths without spinning up Redis.

### 7.2 Integration tests (gated, opt-in)

Located in `tests/notifier_redis.rs` (NEW). Gate via env var:

```rust
fn redis_url_or_skip() -> String {
    match std::env::var("GREENTIC_TEST_REDIS_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("skipping: GREENTIC_TEST_REDIS_URL not set");
            std::process::exit(0);  // pass, not fail
        }
    }
}
```

Run locally via `docker run -p 6379:6379 redis` and:
```
GREENTIC_TEST_REDIS_URL=redis://127.0.0.1:6379 cargo test --test notifier_redis
```

| Test | Verifies |
|---|---|
| `single_notifier_local_publish_works` | One `RedisNotifier`, subscribe locally, publish → received locally (Redis path doesn't break local fan-out). |
| `two_notifiers_cross_replica_fanout` | Two `RedisNotifier` (simulating 2 replicas) sharing same Redis. Subscribe on B, publish on A → received on B. |
| `two_notifiers_loop_suppression` | Subscribe on A, publish on A → received exactly once (not twice from local + Redis echo). |
| `subscribe_after_disconnect_recovers` | Subscribe; drop SUB connection; reconnect succeeds; new publish from another replica delivered. |
| `boot_fails_when_redis_unreachable` | `build_notifier(Redis { url: "redis://127.0.0.1:1" })` returns `Err`. |
| `notifier_config_yaml_end_to_end` | Write `greentic.yaml` with `webchat.notifier.backend: redis`, write fake state-redis ConfigEnvelope CBOR under `operator_root/providers/state-redis/`, call `resolve_notifier_config` → `Redis { url: Some(literal_redis_url) }`. |

### 7.3 Resilience runbook (manual, for QA)

Not automated. Documented in this spec; consider migrating to `greentic-e2e/` later.

1. Boot two operator replicas with Redis backplane enabled, fronted by a non-sticky load balancer.
2. WS client connects to replica A, sends a message that the gateway routes to replica B.
3. Verify the message is delivered to the WS client (i.e., A received the activity push).
4. Stop the Redis container; observe `redis_publish_dropped` increases on subsequent activities.
5. Restart Redis; observe `redis_reconnect_ok` event in tracing log; verify cross-replica fan-out resumes.

### 7.4 Existing test impact

`tests/webchat_websocket.rs` already exercises the WS handler against `InMemoryNotifier`. **No changes required** — `RedisNotifier` exposes the same trait and the default remains `Memory`. Existing tests prove the single-replica baseline stays intact.

### 7.5 CI integration

`bash ci/local_check.sh`: append a conditional block:

```bash
if [ -n "$GREENTIC_TEST_REDIS_URL" ]; then
    cargo test --test notifier_redis -- --nocapture
fi
```

Default behavior (no env var): tests skip silently, `local_check.sh` stays green. Nightly CI can spin up a Redis container to gain coverage; PR CI does not require Redis.

## 8. Cross-Repo Impact

| Repo | Change | Owner |
|---|---|---|
| `greentic-start` | Notifier module additions (`redis.rs`, `config.rs`), `OperatorConfig` extension, `build_notifier` becomes `async` + `Result`, `resolve_notifier_config` boot-path call, integration tests. | This spec. |
| `greentic-setup` | New wizard prompt (single Y/N) under the existing operator setup flow. Writes `webchat.notifier.backend: redis` to `greentic.yaml` when accepted and state-redis is configured. | Phase C scope (cross-repo PR coordinated with greentic-start PR). |
| `greentic-runner` | None directly. Phase C is internal to greentic-start. | n/a |
| `greentic-pack` / `state-redis` provider | None. Auto-detect reads state-redis's existing config envelope shape. | n/a |

## 9. Out of Scope (tracked separately)

| Item | Why deferred |
|---|---|
| Per-IP connection cap, per-IP upgrade rate limit | Hardening — orthogonal to backplane. |
| Origin allowlist beyond JWT | Hardening — orthogonal. |
| Token-TTL auto-close at expiry-3min with `1008 token_expiring` | Hardening — separate task. |
| Slow-consumer detection + drop on WS sink | Hardening — separate task. |
| Full Prometheus `/metrics` endpoint per spec §10.1 | Phase C ships internal `tracing`-based counters only; proper metrics surface is a separate task. |
| Token refresh endpoint `POST /v3/directline/tokens/refresh` (still 404 in WASM) | Different layer — token issuance, not push fan-out. |
| Redis Cluster topology | PUBSUB on cluster broadcasts to all nodes; works but with caveats. Single-node + sentinel cover MVP; cluster can be added once a use case warrants it. |
| Redis ACL / TLS-to-Redis configuration | Transparent — `rediss://` URL parses; ACL is part of state-redis URL (operator concern). |
| Hot reload of `webchat.notifier.url` | Operator restart matches state-redis itself; reload-on-edit is a larger lift. |
| Migration to NATS (the original `notifier/mod.rs` comment mentioned NATS as a follow-up) | Not on the roadmap; the trait abstraction makes a future swap straightforward if requirements change. |

## 10. Risks & Mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| Background SUB task panic kills the loop silently | Low | Wrap loop body in a `tokio::spawn` with explicit panic handler; on panic, log + transition to `Reconnecting`, restart. |
| Redis SUBSCRIBE delivers messages out of order across replicas | n/a | Pump's `ActivitySource` is the source of truth for ordering; notifier event is a "wake up and re-fetch" trigger. Out-of-order events cause harmless extra fetches that converge. |
| Two replicas publish for the same conversation simultaneously | High at scale | `pump.rs` already filters via `event.new_watermark < cursor` continue; idempotent. |
| `instance_id` collision (two replicas same UUID) | Effectively zero (UUIDv4) | None — UUIDv4. |
| Operator boots with stale state-redis URL secret | Low | Boot-time SUB ping fails fast with a clear error. |
| Connection storm if many replicas restart together | Low at MVP scale | Backoff caps at 5 s; ±20% jitter added. |
| Redis pub/sub message loss during disconnect window | Medium | Pump replays from `ActivitySource` on next event, so loss = delayed delivery, not silent drop. Worst case: a user message visibly arrives only after the next activity from the other side. Acceptable for chat. |
| Operator runs Redis-backed backplane against a single replica (overkill, no benefit) | Low | Documented as supported; works correctly, just no functional difference vs Memory backend. |
| The new `async` signature on `build_notifier` ripples to call sites | Bounded | One call site exists today (boot path); ripple is a single `await`. |

## 11. Implementation Roadmap (high-level)

The detailed plan with task breakdown will be produced by the writing-plans skill after this spec is approved. High-level phases:

1. **Skeleton** — `RedisNotifier` struct with stub publish/subscribe/dispatch fn; `Wire` payload type; UUIDv4 `self_id`; unit tests for wire roundtrip + loop suppression.
2. **Connection lifecycle** — open SUB conn, open PUB `ConnectionManager`, background task with backoff state machine; unit tests with extracted `process_incoming` fn; `tracing`-based counters.
3. **Config plumbing** — `NotifierConfig::Redis` variant + serde; `OperatorConfig.webchat` field; `read_provider_config_envelope` helper; `resolve_notifier_config` with secret URI resolution.
4. **Boot wiring** — `build_notifier` becomes `async` + `Result<>`; call sites updated; integration tests behind `GREENTIC_TEST_REDIS_URL`.
5. **CI hook** — conditional integration-test invocation in `ci/local_check.sh`.
6. **Wizard step** (greentic-setup) — single Y/N prompt with i18n source-catalog entry; `greentic.yaml` writer extension for the `webchat` section.
7. **Docs** — operator-facing note in `greentic-start/docs/coding-agents.md` (or sibling) describing the new YAML section + auto-detect behavior.

## 12. References

- Phase B PR: `feature/webchat-websocket-mvp` (PR #111, merged 2026-04-26 into `develop`).
- Existing notifier code: `src/notifier/mod.rs`, `src/notifier/memory.rs` (on `origin/develop`).
- Existing WS code: `src/http_ingress/websocket/{mod,upgrade,session,pump,protocol}.rs` (on `origin/develop`).
- Publish hook: commit `b7717c4` (`feat(ws): wire post-op publish hook for webchat watermark events`).
- Provider config envelope schema: `src/provider_config_envelope.rs::ConfigEnvelope`.
- Reuse-first / source-of-truth conventions: `/home/bima-pangestu/Works/greentic/CLAUDE.md`.
- Repo conventions: `greentic-start/CLAUDE.md` (no Claude co-author, `serde_yaml_gtc`, anyhow + context).
