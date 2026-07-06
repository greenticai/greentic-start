# EPIC-C Business-Event Listener Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** greentic-start subscribes to the SoRX business-event bus (NATS `greentic.events.>`), decodes each `EventEnvelope`, and routes it to flows via the existing `event_router::route_events` (matching `subscribes_to`). "Fire a flow when a business event happens." Off by default (`GREENTIC_EVENTS_NATS_URL`); the EPIC-C event half.

**Architecture:** A new `src/business_event_listener.rs` (sibling of `src/threshold_watcher.rs`): on boot, when `GREENTIC_EVENTS_NATS_URL` is set, connect `async-nats` + `subscribe("greentic.events.>")` in a spawned task; per message, parse the subject + decode the `greentic_types::EventEnvelope`, convert to a `crate::ingress_types::EventEnvelopeV1` (with `event_type` = the routing topic so `subscribes_to` matches), derive the `OperatorContext`, and call `route_events`. Best-effort, drop-on-error, never affects the server.

**Tech Stack:** Rust (edition 2024), `async-nats` (NEW dep), `tokio`, `serde_json`, `greentic_types::EventEnvelope`, `crate::ingress_types::EventEnvelopeV1`, `crate::event_router::route_events`.

## Global Constraints

- **Crate:** greentic-start only. Reuse `event_router::route_events(bundle, ctx: &OperatorContext, &[EventEnvelopeV1])` + the `EventEnvelopeV1`/`EventScopeV1`/`EventSourceV1` construction pattern from `src/threshold_watcher/watcher.rs::build_crossing_event` (which already builds an `EventEnvelopeV1` with `event_type` = a topic string). Do NOT modify `route_events`/`event_router`.
- **Routing key:** `route_events`/`select_target_flows` match a flow's `subscribes_to` patterns against `EventEnvelopeV1.event_type`. The NATS subject is `greentic.events.<tenant>.<topic>` (e.g. `greentic.events.t1.sorla.<pack>.<entity>.created`). Set `EventEnvelopeV1.event_type = <topic>` (the subject portion AFTER `greentic.events.<tenant>.`), so a flow with `subscribes_to: ["sorla.*"]` / `["sorla.<pack>.<entity>.created"]` fires. (Fall back to the decoded envelope's `topic`/`type` if the subject can't be parsed.) Document this in a comment.
- **Tenant/team:** derive the `OperatorContext` (tenant, team) from the decoded `EventEnvelope.tenant` (`TenantCtx`) — and cross-check against the subject's `<tenant>` segment (prefer the envelope's).
- **Off by default:** no `GREENTIC_EVENTS_NATS_URL` → the listener does not start (mirror how `threshold_watcher`/timer are gated). Zero default-path change.
- **Best-effort / never panic:** a decode failure / malformed subject → warn + skip (drop the message); a `route_events` error → warn + continue; a NATS disconnect → warn (do not crash the server). The listener task must never bring down the process.
- **No new deps beyond `async-nats`** (add it to `Cargo.toml`; pick the version already used elsewhere in the workspace — check greentic-runner's `async-nats` version to match, e.g. 0.46).
- **Conventional commits, NO Claude co-author.** Target `research`.
- **Build discipline (SHARED CONTENDED MACHINE — ~8 concurrent builds, OOM risk):** all cargo with `-j2` + `CARGO_BUILD_JOBS=2`; FOREGROUND, block+wait; NEVER pkill/kill or delete another worktree's `target/`.

---

### Task 1: parse + convert (NATS message → ctx + EventEnvelopeV1)

**Files:**
- Create: `src/business_event_listener.rs` (the pure parse/convert fns + `mod business_event_listener;` in `src/lib.rs`)
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Consumes: `greentic_types::EventEnvelope`, `crate::ingress_types::{EventEnvelopeV1, EventScopeV1, EventSourceV1}` (read `build_crossing_event` in `threshold_watcher/watcher.rs` for the exact field construction), `crate::...OperatorContext` (read `route_events`'s `OperatorContext` — tenant/team fields).
- Produces:
  - `fn topic_from_subject(subject: &str) -> Option<String>` — strip the `greentic.events.<tenant>.` prefix, returning `<topic>` (everything after the tenant segment); `None` if the subject isn't `greentic.events.<tenant>.<...>`.
  - `fn tenant_from_subject(subject: &str) -> Option<String>` — the `<tenant>` segment.
  - `fn convert(subject: &str, body: &[u8]) -> Option<(OperatorContext, EventEnvelopeV1)>` — decode `body` → `greentic_types::EventEnvelope`; `event_type` = `topic_from_subject(subject)` (fall back to `envelope.topic` then `envelope.r#type`); build `EventEnvelopeV1` (mirror `build_crossing_event`: id, event_type, scope from tenant/team, source, payload from the envelope); build `OperatorContext` (tenant/team from `envelope.tenant`). `None` on decode failure.

- [ ] **Step 1: Read the references** — `threshold_watcher/watcher.rs::build_crossing_event` (the `EventEnvelopeV1`/`EventScopeV1`/`EventSourceV1` field construction) + `event_router.rs` (the `OperatorContext` shape: `tenant`, `team: Option<String>`) + `greentic-types` `EventEnvelope` fields (`topic`, `r#type`, `tenant: TenantCtx`, `subject`, `payload`, `time`, `correlation_id`).
- [ ] **Step 2: Write failing tests.**
```rust
#[test]
fn topic_and_tenant_parsed_from_subject() {
    assert_eq!(topic_from_subject("greentic.events.t1.sorla.pack.order.created").as_deref(), Some("sorla.pack.order.created"));
    assert_eq!(tenant_from_subject("greentic.events.t1.sorla.pack.order.created").as_deref(), Some("t1"));
    assert!(topic_from_subject("not.events").is_none());
}
#[test]
fn convert_maps_business_event_to_routable_envelope() {
    // a serialized greentic_types::EventEnvelope for tenant t1
    let env = /* build greentic_types::EventEnvelope (tenant t1, topic "sorla.pack.order.created", payload {...}) — read the ctor */;
    let body = serde_json::to_vec(&env).unwrap();
    let (ctx, ev) = convert("greentic.events.t1.sorla.pack.order.created", &body).unwrap();
    assert_eq!(ctx.tenant, "t1");
    assert_eq!(ev.event_type, "sorla.pack.order.created"); // the subject topic → drives subscribes_to matching
    let bad = convert("greentic.events.t1.x", b"{ not json");
    assert!(bad.is_none());
}
```
- [ ] **Step 3: Run — expect FAIL** (`CARGO_BUILD_JOBS=2 cargo test -p greentic-start -j2 business_event_listener`).
- [ ] **Step 4: Implement** `topic_from_subject`/`tenant_from_subject`/`convert`. `convert` must never panic (all `?`/`.ok()?`).
- [ ] **Step 5: Run — PASS + commit** (`feat(events): parse+convert business-event NATS message to routable envelope`).

---

### Task 2: NATS subscribe loop + boot wiring

**Files:**
- Modify: `Cargo.toml` (add `async-nats`), `src/business_event_listener.rs` (the subscribe loop + `start`), `src/runtime.rs` (boot wiring — mirror `threshold_watcher` start/stop)
- Test: an integration-style test driving the per-message handler with a stubbed `route_events` (mirror `threshold_watcher`'s `poll_once`-style injectable seam)

**Interfaces:**
- Consumes: Task 1's `convert`; `event_router::route_events`; `async_nats::Client`.
- Produces: `struct BusinessEventListener { ... }` with `fn start(cfg) -> Self` (spawns the subscribe task) + `fn stop(self)`; a testable `fn handle_message<R>(subject, body, bundle_root, route: R)` where `R: FnOnce(&Path, &OperatorContext, &[EventEnvelopeV1]) -> anyhow::Result<usize>` (mirror `threshold_watcher`'s injectable route seam so the message→route path is unit-tested without live NATS).

- [ ] **Step 1: Write the failing test** — `handle_message` with a valid business-event subject+body drives the injected route fn with the converted `(ctx, [EventEnvelopeV1])` (assert the route closure received `event_type == "sorla.pack.order.created"` + tenant `t1`); a malformed body → the route fn is NOT called (dropped, no error). Mirror `threshold_watcher`'s test seam.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** the subscribe loop (`client.subscribe("greentic.events.>")`; `while let Some(msg) = sub.next().await { handle_message(msg.subject, &msg.payload, bundle_root, |b,c,e| route_events(b,c,e)) }`; best-effort warn+continue) + `handle_message` (calls `convert` → `route_events`; drop+warn on `None`/`Err`) + `start`/`stop`. Add `async-nats` to `Cargo.toml` (match the workspace version).
- [ ] **Step 4: Wire into `runtime.rs`** — mirror `threshold_watcher`: read `GREENTIC_EVENTS_NATS_URL`; if set, `async_nats::connect(url).await` → `BusinessEventListener::start(...)`; store `Option<BusinessEventListener>` on the runtime struct; `stop()` on shutdown. If NOT set, don't start (zero default-path change). Handle connect failure with a warn (don't crash boot — mirror the runner's `runtime.rs:322` pattern).
- [ ] **Step 5: Gate + commit.** `cargo fmt --all`; `CARGO_BUILD_JOBS=2 cargo clippy -p greentic-start -j2 --all-targets -- -D warnings`; `CARGO_BUILD_JOBS=2 cargo test -p greentic-start -j2`. Commit (`feat(events): NATS greentic.events.> listener routes business events to flows`). Then finishing-a-development-branch → PR to `research`, noting live SoRX-publishing verification is a pre-enablement item (the convert+route logic is unit-tested; the live NATS subscription needs a running SoRX to fully exercise).

---

## Self-Review

- **Spec coverage** (against the architecture doc §5): §5.1 subscribe/gate → Task 2 (loop + boot wiring, off-by-default); §5.2 decode+ctx+route → Task 1 (`convert`) + Task 2 (`handle_message`→`route_events`); §5.3 best-effort → Task 1/2 (never-panic, drop+warn); §5.4 tests → per-task (decode+route, off-when-no-NATS). The event_type routing-key mapping (subject topic → `event_type`) is the crux, documented + tested in Task 1.
- **Placeholder scan:** "read build_crossing_event / OperatorContext / EventEnvelope ctor / the workspace async-nats version" are deliberate — the exact `EventEnvelopeV1`/`OperatorContext` fields + the greentic_types ctor + the dep version must be read from the repo. The routing-key decision is explicit. No TBD as work-defining. Live NATS intentionally not unit-tested (pre-enablement).
- **Type consistency:** `convert` (Task 1) → `(OperatorContext, EventEnvelopeV1)` consumed by `handle_message` (Task 2) → `route_events`. `topic_from_subject`/`tenant_from_subject` (Task 1) used by `convert`. The injectable `R` route seam (Task 2) matches `route_events`'s signature exactly (mirrors `threshold_watcher`).
- **Scope:** 1 new module + `Cargo.toml` (async-nats) + `runtime.rs` wiring; reuses `route_events` + the threshold_watcher patterns; one plan; off by default.
