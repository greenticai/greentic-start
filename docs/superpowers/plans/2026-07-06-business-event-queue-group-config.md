# Business-Event Listener Queue-Group Config Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make the business-event listener's NATS queue-group name configurable via `GREENTIC_BE_QUEUE_GROUP` (default = the current literal `"greentic-start-be-listener"`), removing a latent multi-deployment footgun without deciding the deployment model. Plus document the SoRX subject contract + queue-group semantics.

**Background / why:** The listener subscribes to `greentic.events.>` under a **fixed** queue group. Same-bundle replicas sharing that group is correct (HA dedup). But two *different* greentic-start deployments on the same NATS would also share the group, so NATS could deliver tenant A's event to a deployment that can't route it → lost event. The code cannot know the operator's topology; making the group configurable (safe default preserved) lets the operator scope it per deployment. This is the non-guessing fix.

**Architecture:** Thread a `queue_group: String` through `BusinessEventListenerConfig`, resolved once in `runtime.rs` from `GREENTIC_BE_QUEUE_GROUP` (or the default literal). `business_event_listener.rs` uses `config.queue_group` instead of the const.

**Tech Stack:** Rust (edition 2024), the existing listener + `std::env::var`.

## Global Constraints
- **Crate:** greentic-start only. Files: `src/business_event_listener.rs`, `src/runtime.rs`.
- **Default preserved:** unset env → queue group is EXACTLY `"greentic-start-be-listener"` (current behavior, zero change for existing deployments).
- **Conventional commits, NO Claude co-author.** Target `research`.
- **Build discipline (shared machine, disk ample ~103GB):** cargo `-j2` + `CARGO_BUILD_JOBS=2`, FOREGROUND; never pkill/kill or delete another worktree's target/.

---

### Task 1: configurable queue group + doc

**Files:**
- Modify: `src/business_event_listener.rs` (add `queue_group` to `BusinessEventListenerConfig`; use it at the `queue_subscribe` call ~:335-337 + the log ~:356; add a resolver `fn resolve_queue_group() -> String` or resolve in runtime.rs), `src/runtime.rs` (set `queue_group` when building the config ~:946-965)
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Produces: `BusinessEventListenerConfig` gains `pub queue_group: String`; a resolver reading `GREENTIC_BE_QUEUE_GROUP` with the default `DEFAULT_BUSINESS_EVENTS_QUEUE_GROUP = "greentic-start-be-listener"`.

- [ ] **Step 1: Read** `business_event_listener.rs` — the `BUSINESS_EVENTS_QUEUE_GROUP` const (:49), the `BusinessEventListenerConfig` struct, the `queue_subscribe` call (:335-337), the log (:356); and `runtime.rs:946-965` where the config is built + `BusinessEventListener::start` is called.
- [ ] **Step 2: Write the failing test** — a pure resolver `fn resolve_queue_group(env_value: Option<String>) -> String` (or test via a helper): `resolve_queue_group(Some("acme-prod".into())) == "acme-prod"`; `resolve_queue_group(None) == DEFAULT_BUSINESS_EVENTS_QUEUE_GROUP` (== `"greentic-start-be-listener"`); an empty/whitespace env value falls back to the default (`resolve_queue_group(Some("  ".into()))` == default). Take the env value as a parameter so the test is deterministic (do NOT read the process env inside the tested fn).
- [ ] **Step 3: Run — expect FAIL** (`CARGO_BUILD_JOBS=2 cargo test -p greentic-start -j2 business_event_listener`).
- [ ] **Step 4: Implement.** Rename the const to `DEFAULT_BUSINESS_EVENTS_QUEUE_GROUP`; add `pub queue_group: String` to `BusinessEventListenerConfig`; add `fn resolve_queue_group(env_value: Option<String>) -> String` (trim; empty → default); use `config.queue_group` at the `queue_subscribe` call + the log. In `runtime.rs`, set `queue_group: resolve_queue_group(std::env::var("GREENTIC_BE_QUEUE_GROUP").ok())` when building the config. Keep everything else (off-by-default gating, dedicated-thread runtime) unchanged.
- [ ] **Step 5: Doc.** In the business-event-listener spec (`docs/superpowers/specs/2026-07-06-business-event-listener-architecture.md`) add a short "Queue group & SoRX subject contract" note: the subject is `greentic.events.<tenant>.<topic>` (SoRX publishes; `<topic>` = the routing key matched against `subscribes_to`); the queue group defaults to `greentic-start-be-listener` and is overridable via `GREENTIC_BE_QUEUE_GROUP` — set it per deployment when multiple distinct greentic-start deployments share one NATS, so events aren't cross-delivered; leave it default for HA replicas of the same bundle. Also add `GREENTIC_BE_QUEUE_GROUP` to the env-var table in `docs/coding-agents.md` if such a table exists (grep for `GREENTIC_EVENTS_NATS_URL`).
- [ ] **Step 6: Gate + commit.** `cargo fmt --all`; `CARGO_BUILD_JOBS=2 cargo clippy -p greentic-start -j2 --all-targets -- -D warnings`; `CARGO_BUILD_JOBS=2 cargo test -p greentic-start -j2`. Commit (`feat(events): configurable business-event queue group (GREENTIC_BE_QUEUE_GROUP)`). Then finishing-a-development-branch → PR to `research`.

## Self-Review
- **Coverage:** configurable queue group (Steps 4) + default preserved (Step 2 test) + SoRX-subject/queue-group doc (Step 5).
- **Placeholder scan:** the doc note content is specified inline. No TBD.
- **Scope:** 2 code files + 1-2 doc files; additive; default behavior byte-identical when the env is unset.
