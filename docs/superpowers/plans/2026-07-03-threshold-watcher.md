# Host `threshold_watcher` (EPIC-C v1 thin slice) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A host module `greentic-start/src/threshold_watcher.rs` that polls an HTTP numeric metric on an interval, detects a threshold edge-cross (fires **once** per crossing, durably), and emits an `EventEnvelope` that the existing `event_router::route_events` delivers to any flow subscribed to the metric topic.

**Architecture:** Sibling of `src/timer_scheduler.rs`. Pure eval + edge-detect fns, a validated config model, a durable per-watch state file under `state_dir`, an `ureq` metric fetch, and a background loop wired in `src/runtime.rs` the same way `timer_scheduler` is. No flow-schema change, no new WASM component, no runner change.

**Tech Stack:** Rust (edition 2024), `ureq` (already a greentic-start dep) for the poll, `serde`/`serde_json` + `serde_yaml_bw` for config/state, `greentic_types::EventEnvelope`, the existing `event_router::route_events`.

## Global Constraints

- **Reference module (mirror its idioms):** `src/timer_scheduler.rs` — the background-thread loop (`run_scheduler_loop`), `next_tick`/interval scheduling, `ScheduledTimer` shape, `discover_timer_handlers`, the `route_events` call after building events, and the `runtime.rs` wiring (`discover_* → ::start(cfg) → stored on runtime → stop() on shutdown`, see `src/runtime.rs:844-852,1436` + the `stop` at `:48`). Reproduce that structure; do not invent a new scheduling pattern.
- **Delivery reuse:** emit via `crate::event_router::route_events(bundle_root, &ctx, &events)` — do NOT write a new delivery path.
- **EventEnvelope:** use `greentic_types::EventEnvelope`; shape it like `provider-timer`/`timer_scheduler` do (topic, `source.producer`, `scope.tenant/team`, payload). Read the real struct in `greentic-types/src/events.rs` before constructing.
- **HTTP client:** use `ureq` (already in `Cargo.toml`), with a short timeout. Do NOT add reqwest/hyper for the poll.
- **Durable state path:** `{state_dir}/threshold/{tenant}/{name}.json`; atomic write (temp + rename); absent/corrupt → `unknown` (fail-safe, never a spurious fire).
- **Fire-once semantics:** a watch fires ONLY on a genuine side transition where the prior side is not `unknown`; the first-ever poll records the side without firing.
- **Fail-safe on error:** any fetch/parse/state error → log `warn`, skip the tick WITHOUT changing `last_side` (a transient error must never fabricate a crossing). Never panic; one poisoned watch must not stop the others.
- **Zero default-path change:** the watcher starts only when watches are configured (mirror timer_scheduler's no-handlers → don't start).
- **No new deps** beyond what greentic-start already has, unless a step explicitly justifies one.
- **Conventional commits, NO Claude co-author.** Target branch `research`.
- **Build discipline (shared disk-constrained machine):** run cargo in the worktree only; FOREGROUND; never `pkill`/`kill` or delete another worktree's `target/`. Prefer `cargo test -p greentic-start <name>` for targeted runs.

---

### Task 1: threshold eval + edge-detect (pure)

**Files:**
- Create: `src/threshold_watcher/eval.rs` (+ `src/threshold_watcher/mod.rs` with `pub mod eval;`)
- Modify: `src/lib.rs` (`mod threshold_watcher;`)
- Test: inline `#[cfg(test)]` in `eval.rs`

**Interfaces:**
- Produces:
  - `enum Comparator { Gt, Lt, Gte, Lte }`, `enum EdgeDirection { Rising, Falling, Both }`, `enum Side { Above, Below, Unknown }` (all `#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]`, serde `rename_all="snake_case"`).
  - `fn side(value: f64, threshold: f64, cmp: Comparator) -> Side` (Above when the comparison holds, else Below).
  - `fn crossing(prev: Side, curr: Side, dir: EdgeDirection) -> Option<&'static str>` → `Some("rising")` on Below→Above, `Some("falling")` on Above→Below, filtered by `dir`; `None` if `prev == Unknown`, `prev == curr`, or the direction doesn't match.

- [ ] **Step 1: Write the failing tests.**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn side_respects_comparator() {
        assert_eq!(side(10.0, 5.0, Comparator::Gt), Side::Above);
        assert_eq!(side(3.0, 5.0, Comparator::Gt), Side::Below);
        assert_eq!(side(5.0, 5.0, Comparator::Gte), Side::Above);
        assert_eq!(side(5.0, 5.0, Comparator::Gt), Side::Below);
        assert_eq!(side(3.0, 5.0, Comparator::Lt), Side::Above); // "below threshold" IS the trigger side for Lt
    }
    #[test]
    fn crossing_fires_once_on_matching_edge() {
        assert_eq!(crossing(Side::Below, Side::Above, EdgeDirection::Rising), Some("rising"));
        assert_eq!(crossing(Side::Above, Side::Below, EdgeDirection::Rising), None);
        assert_eq!(crossing(Side::Above, Side::Below, EdgeDirection::Falling), Some("falling"));
        assert_eq!(crossing(Side::Below, Side::Above, EdgeDirection::Both), Some("rising"));
        assert_eq!(crossing(Side::Above, Side::Above, EdgeDirection::Both), None); // no transition
        assert_eq!(crossing(Side::Unknown, Side::Above, EdgeDirection::Both), None); // first poll never fires
    }
}
```
Note the `Lt` subtlety: `side` returns `Above` when the comparator condition holds, so for `Lt` a value BELOW the threshold yields `Side::Above` ("in the trigger region"). Document this in a comment: `Side::Above` means "the comparator condition is satisfied," not "numerically greater."

- [ ] **Step 2: Run — expect FAIL** (`cargo test -p greentic-start threshold_watcher::eval`).
- [ ] **Step 3: Implement** the enums + `side` + `crossing`.
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Commit** (`feat(threshold): threshold side + edge-crossing eval`).

---

### Task 2: config model + validate

**Files:**
- Create: `src/threshold_watcher/config.rs` (`pub mod config;` in mod.rs)
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Consumes: `eval::{Comparator, EdgeDirection}`.
- Produces:
  - `struct MetricSource { url: String, json_path: String, #[serde(default)] headers: Vec<(String,String)> }`
  - `struct ThresholdWatchConfig { name, tenant, #[serde(default)] team: Option<String>, source: MetricSource, comparator: Comparator, threshold: f64, direction: EdgeDirection, interval_seconds: u64, topic: String }` (`#[derive(Debug, Clone, Deserialize)]`).
  - `fn load_watches(bundle_root: &Path) -> Vec<ThresholdWatchConfig>` — reads `{bundle_root}/threshold-watchers.yaml` (a top-level `watches: [...]` list) via `serde_yaml_bw`; missing file → empty vec; parse error → log `warn` + empty vec (never panic).
  - `fn validate(&self) -> Result<(), String>` — non-empty name/tenant/url/json_path/topic; `interval_seconds >= 1`; `threshold` finite.

- [ ] **Step 1: Write failing tests** — a valid YAML string parses to the expected config; a missing file → `[]`; `validate` rejects empty url + `interval_seconds = 0`. (Use a `tempfile` dir — check how `timer_scheduler`/other tests build a temp bundle; mirror that.)
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** the structs + `load_watches` + `validate`. Skip (with a `warn`) any watch that fails `validate` in `load_watches` so one bad entry doesn't drop the rest.
- [ ] **Step 4: Run — expect PASS + commit** (`feat(threshold): watch config model + bundle loader`).

---

### Task 3: durable edge-state store

**Files:**
- Create: `src/threshold_watcher/state.rs` (`pub mod state;`)
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Consumes: `eval::Side`.
- Produces:
  - `struct WatchState { last_side: Side, last_value: Option<f64>, last_checked: Option<String> }` (`Serialize/Deserialize`).
  - `fn load_state(state_dir: &Path, tenant: &str, name: &str) -> WatchState` — reads `{state_dir}/threshold/{tenant}/{name}.json`; absent/corrupt → `WatchState { last_side: Side::Unknown, .. }`.
  - `fn save_state(state_dir: &Path, tenant: &str, name: &str, st: &WatchState) -> std::io::Result<()>` — creates dirs, writes atomically (write to `{name}.json.tmp` then `rename`).

- [ ] **Step 1: Write failing tests** (tempdir): save→load round-trip preserves `last_side`/`last_value`; loading a missing file → `Unknown`; loading a corrupt file (write `"{ not json"`) → `Unknown` (no panic); after `save`, no `.tmp` file remains.
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** with `serde_json` + create_dir_all + temp-write + `fs::rename`.
- [ ] **Step 4: Run — expect PASS + commit** (`feat(threshold): durable per-watch edge state`).

---

### Task 4: metric fetch + numeric extract

**Files:**
- Create: `src/threshold_watcher/fetch.rs` (`pub mod fetch;`)
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Produces:
  - `fn extract_number(body: &serde_json::Value, json_path: &str) -> Option<f64>` — dotted path (`"data.available"`), returns the numeric leaf (accept JSON number, or a string that parses as f64); `None` if missing/non-numeric.
  - `fn fetch_metric(source: &MetricSource) -> Result<f64, String>` — `ureq` GET with a short timeout (e.g. 10s), non-2xx/transport error → `Err`, parse body as JSON, `extract_number` → `Ok(value)` or `Err`.

- [ ] **Step 1: Write failing tests** — `extract_number` on `{"data":{"available":12}}` with `"data.available"` → `Some(12.0)`; on a string `"12.5"` → `Some(12.5)`; missing path → `None`; non-numeric → `None`. (`extract_number` is pure and fully testable without network. `fetch_metric`'s HTTP is covered by the Task-5 integration test against a local stub server, or a `#[ignore]` live test — do NOT hit a real network in unit tests.)
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** `extract_number` (split path on `.`, walk the `Value`) + `fetch_metric` (ureq). Keep the HTTP thin; the testable logic is `extract_number`.
- [ ] **Step 4: Run — expect PASS + commit** (`feat(threshold): HTTP metric fetch + json-path numeric extract`).

---

### Task 5: watcher loop + emit + runtime wiring

**Files:**
- Create: `src/threshold_watcher/watcher.rs` (the loop + emit); re-export `ThresholdWatcher`/`ThresholdWatcherConfig` from `mod.rs`
- Modify: `src/runtime.rs` (discover + start + store + stop, mirroring `timer_scheduler`)
- Test: `tests/threshold_watcher.rs` (integration) + inline emit-shape test

**Interfaces:**
- Consumes: `eval::{side, crossing}`, `config::{ThresholdWatchConfig, load_watches}`, `state::{load_state, save_state, WatchState}`, `fetch::fetch_metric`, `crate::event_router::route_events`.
- Produces: `ThresholdWatcher { ... }` with `fn start(cfg: ThresholdWatcherConfig) -> Self` + `fn stop(self)`; `ThresholdWatcherConfig { bundle_root, state_dir, tenant, team, watches: Vec<ThresholdWatchConfig>, runner_host/ctx as timer_scheduler needs }`.
- Produces: `fn build_crossing_event(w: &ThresholdWatchConfig, value: f64, crossed: &str, checked_at: &str) -> EventEnvelope` (pure, unit-tested).
- Produces: `fn poll_once(...)` — the per-watch cycle (fetch → side → load_state → crossing → maybe emit → save_state), factored so the integration test can drive one cycle with a stubbed fetch/metric value.

- [ ] **Step 1: Write the failing tests.**
  - Emit-shape (pure): `build_crossing_event` sets `topic == w.topic`, producer `"threshold:<name>"`, payload carries `value`/`threshold`/`crossed`.
  - Integration (mirror the timer/event_router integration test): construct a bundle with a flow subscribing to `metric.test.crossed`; drive `poll_once` with a stub that returns a value ABOVE T after a prior `below` state; assert an event was routed to the flow. Then a second `poll_once` still above T asserts NO second event (fire-once). A `poll_once` whose fetch errors asserts `last_side` unchanged + no event.
  (Factor `poll_once` to take the fetched value (or a fetch closure) so the test injects it without a network.)
- [ ] **Step 2: Run — expect FAIL.**
- [ ] **Step 3: Implement** `build_crossing_event`, `poll_once`, and the loop (mirror `timer_scheduler::run_scheduler_loop` — background thread, per-watch `next_tick`, sleep to soonest). Wire `route_events` on a firing crossing. `poll_once` persists `current_side` every call; only emits when `crossing(..)` is `Some` matching `direction`.
- [ ] **Step 4: Wire into `runtime.rs`** — mirror `timer_scheduler`: `let watches = load_watches(&bundle_root);` then `if !watches.is_empty() { ThresholdWatcher::start(ThresholdWatcherConfig{..}) }`, store `Option<ThresholdWatcher>` on the runtime struct, call `stop()` in the shutdown path next to `timer_scheduler`. Do NOT start it when `watches` is empty.
- [ ] **Step 5: Run — expect PASS** (`cargo test -p greentic-start threshold` + the integration test).
- [ ] **Step 6: Gate + commit.** `cargo fmt --all`, `cargo clippy -p greentic-start --all-targets -- -D warnings`, `cargo test -p greentic-start`. Commit (`feat(threshold): watcher loop, crossing event emit, runtime wiring`).

---

## Self-Review

- **Spec coverage:** §3.1 config → Task 2; §3.2 state → Task 3; §3.3 edge-detect → Task 1; §4 delivery/emit → Task 5; §5 discovery → Task 2 (`load_watches`) + Task 5 (wiring); §6 loop → Task 5; §7 error handling → fail-safe rules in Tasks 3/4/5 (skip-without-state-change); §9 testing → per-task tests incl. fire-once + transient-error integration cases. §2 host-not-wasm rationale → Global Constraints (host module, reuse route_events).
- **Placeholder scan:** "mirror timer_scheduler" / "read the real EventEnvelope struct" are deliberate — the exact host loop idioms, the `route_events`/`runtime.rs` signatures, and the `EventEnvelope` field names must be read from the repo (not invented). Every task names its reference. No TBD left as work-defining.
- **Type consistency:** `Side`/`Comparator`/`EdgeDirection` defined in Task 1, consumed by Tasks 2/3/5; `ThresholdWatchConfig`/`MetricSource` defined Task 2, consumed Task 5; `WatchState` Task 3 ↔ Task 5; `crossing` return `Option<&str>` ("rising"/"falling") consistent Task 1 ↔ Task 5 `build_crossing_event`. `fetch_metric`/`extract_number` Task 4 ↔ Task 5 `poll_once`.
- **Scope:** single host module (5 focused files under `src/threshold_watcher/`) + one `runtime.rs` wiring; one plan; no wasm build.
