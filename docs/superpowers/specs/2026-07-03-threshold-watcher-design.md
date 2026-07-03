# EPIC-C v1 (thin slice) — Host `threshold_watcher` — Design Spec

**Status:** Draft for review — 2026-07-03
**Initiative:** Agentic platform coverage (PRD `greentic-designer:docs/superpowers/specs/2026-07-02-agentic-platform-coverage-prd.md`), EPIC-C "Event/Threshold Triggers".
**Scope of THIS slice:** the **poll-based threshold half** — "fire a flow when a polled numeric metric crosses a threshold." The "business event happens" half (subscribe to sorx business events) is deferred (§8).

## 1. Problem & goal

The PRD wants flows triggered by business events/thresholds, not just cron/webhook. A read-only audit found:

- **No trigger model exists** (`greentic-triggers`/`TriggerDef` absent); triggering is ad-hoc per ingress.
- **The working "run flow X when event Y" seam** is: a flow declares `subscribes_to: ["topic"]` in its pack manifest, some events-domain producer emits an `EventEnvelope` with that topic, and `greentic-start/src/event_router.rs::route_events` matches the topic and invokes the flow.
- **The host already turns periodic work into routed flow invocations** via `greentic-start/src/timer_scheduler.rs` (an interval loop that calls providers and routes their emitted events) — but its per-handler state is **in-memory only** (`last_run_rfc3339`), so it cannot edge-detect or survive restart.
- **Threshold/condition evaluation is 100% net-new** — nothing anywhere compares a value against a target or detects an edge-cross.

**Goal:** a host module that polls a numeric metric on an interval, detects when it **crosses** a configured threshold (rising/falling edge, fired **once** per crossing), and emits an `EventEnvelope` that the existing `route_events` chain delivers to any flow subscribed to the metric's topic — with **durable** per-watch state so it fires once (not every poll) and survives restart.

## 2. Why a host module (not a WASM events-provider)

The Explore recommendation was a threshold-poll events-provider, but a WASM events-provider cannot own the durable edge-state: events-provider components have **no state-store host import** (only `secrets-store`), and `timer_scheduler` does not persist arbitrary provider state. Putting the watcher in the host is strictly thinner and better-isolated:

| | Host module (`threshold_watcher.rs`) | New WASM events-provider |
|---|---|---|
| Durable edge-state | Trivial — a JSON file under the host `state_dir` | Needs a new WASM state import that doesn't exist, OR a state round-trip through `timer_scheduler` (larger blast radius) |
| Metric poll (HTTP GET) | `ureq` (already a greentic-start dep) | Needs the WASM `http-client` import + a component build |
| Build cost | Host crate only (no `wasm32-wasip2` build) | Full component scaffold + wasm build |
| Testability | Threshold-eval + edge-detect + config parse are pure host fns | Split across wasm boundary |
| Consistency | `timer_scheduler` is already a host-core generic scheduling capability; this is its sibling | — |

A generic "poll a URL and compare a number" is a core scheduling capability (like the timer scheduler), not provider-specific business logic, so it belongs in the host — consistent with the "core provides basic capabilities" principle.

## 3. Architecture

New module `greentic-start/src/threshold_watcher.rs`, a sibling of `timer_scheduler.rs`, wired the same way in `src/runtime.rs` (discover → `ThresholdWatcher::start(...)` → stored on the runtime → stopped on shutdown).

**Data flow:**
```
interval tick → for each watch:
  GET source.url (ureq) → extract numeric field by json_path
    → load durable last_side for (tenant, watch.name)
    → compare value vs threshold (comparator) → current_side (above|below)
    → if edge-crossed in the configured direction → build EventEnvelope(topic)
       → route_events(bundle_root, ctx, [event])   [existing]
    → persist { last_side: current_side, last_value, last_checked }
```
The flow that reacts declares `subscribes_to: ["metric.<name>.crossed"]` in its pack manifest (existing mechanism) — **no flow-schema change, no new node type**.

### 3.1 Config model

```rust
struct ThresholdWatchConfig {
    name: String,              // unique per tenant; used in the state-file path + default topic
    tenant: String,
    team: Option<String>,
    source: MetricSource,      // where to read the number
    comparator: Comparator,    // Gt | Lt | Gte | Lte
    threshold: f64,
    direction: EdgeDirection,  // Rising | Falling | Both  (which crossing fires)
    interval_seconds: u64,
    topic: String,             // emitted EventEnvelope topic (e.g. "metric.inventory_low.crossed")
}
struct MetricSource {
    url: String,               // HTTP GET
    json_path: String,         // dotted path to a numeric field, e.g. "data.available"
    headers: Vec<(String,String)>, // optional (e.g. an auth header; values may be secret-refs — see §7)
}
enum Comparator { Gt, Lt, Gte, Lte }
enum EdgeDirection { Rising, Falling, Both }
```

### 3.2 Durable state

`{state_dir}/threshold/{tenant}/{name}.json`:
```json
{ "last_side": "below", "last_value": 12.0, "last_checked": "2026-07-03T10:00:00Z" }
```
- `last_side ∈ {above, below, unknown}`; first-ever poll sets the side **without firing** (`unknown → side` is not a crossing) — a watch fires only on a genuine transition, so enabling a watch while the metric is already above T does not immediately fire.
- Written atomically (temp file + rename) so a crash mid-write can't corrupt state.
- Absent/corrupt file → treated as `unknown` (fail-safe: no spurious fire).

### 3.3 Edge detection (fire once)

`side(value) = above if compares(value, threshold, comparator) else below`. A crossing occurs when `last_side != current_side` AND `last_side != unknown`. Fire when the crossing matches `direction`:
- `Rising` fires on `below → above`.
- `Falling` fires on `above → below`.
- `Both` fires on either.
Persist `current_side` every poll regardless of firing.

## 4. Delivery — reuse `route_events`

On a firing crossing, build a canonical `greentic_types::EventEnvelope` (mirror how `timer_scheduler`/`provider-timer` shape theirs): `type` = a `cap://greentic/events/threshold/crossed`-style id, `topic` = `config.topic`, `source.producer` = `"threshold:<name>"`, `scope.tenant`/`team`, `payload` = `{ name, value, threshold, comparator, direction, crossed: "rising"|"falling", checked_at }`. Call `event_router::route_events(bundle_root, &ctx, &[envelope])` — the same delivery the timer scheduler uses; any flow with a matching `subscribes_to` runs, falling back to the default app flow if none subscribes (existing behavior).

## 5. Registration / discovery

Mirror `discover_timer_handlers` (`timer_scheduler.rs:223`): scan the bundle for a declarative `threshold_watchers` array. Two options; **v1 = bundle config** (simpler, no manifest schema change):
- Read `{bundle_root}/threshold-watchers.yaml` (or a `greentic.demo.yaml` section) → `Vec<ThresholdWatchConfig>`.
- (Deferred: a `greentic.threshold-watchers.v1` pack manifest extension so a pack can ship watches, mirroring `timer_handlers`.)

If no config is present, the watcher does not start (zero overhead, no behavior change) — exactly like the timer scheduler when no timer handlers are discovered.

## 6. Scheduler loop

Mirror `timer_scheduler.rs`: a background thread with a per-watch `next_tick = now + interval_seconds`, sleeping until the soonest tick. On tick, run the §3 poll→compare→emit→persist cycle for that watch, reschedule. `ThresholdWatcher::start(cfg) -> Self` + `stop()` for graceful shutdown, held on the runtime struct next to `timer_scheduler`.

## 7. Error handling

- HTTP GET failure / non-2xx / timeout → log `warn`, skip this tick (do NOT change `last_side` — a transient fetch error must not fabricate a crossing). A short `ureq` timeout is set so a slow endpoint can't stall the loop.
- `json_path` missing / value non-numeric → log `warn`, skip tick (no state change).
- State-file read error → treat as `unknown` (fail-safe). Write error → log `warn`, continue (next tick retries).
- A secret-ref in a `headers` value (e.g. `{{secret:MY_API_TOKEN}}`) is resolved via the host's existing tenant-scoped secret mechanism before the GET; an unresolved ref → skip tick + warn (never send the literal placeholder). (If wiring the secret resolver is non-trivial, v1 supports only non-secret headers and documents that; secret headers become a fast follow.)
- The watcher never panics; a poisoned single watch logs and continues; other watches are unaffected.

## 8. Scope boundaries (YAGNI)

**In v1:** poll an HTTP JSON metric, numeric comparator, rising/falling/both edge-detection, durable fire-once state, emit `EventEnvelope` → `route_events`, bundle-config registration, unit tests for compare/edge/state/config + an integration test that a crossing routes to a subscribed flow.

**Deferred (follow-on slices):**
- **Business-event trigger half** — subscribe to sorx `greentic.events.<tenant>.<topic>` business events and evaluate a condition (the vision's "Operala event listeners" item). Blocked on a listener/subscriber seam that does not exist yet (sorx events are publish-only) — a larger slice.
- Pack-manifest `threshold-watchers.v1` extension (v1 uses bundle config).
- Non-HTTP metric sources (a component output, a DB query, a sorx entity field).
- Hysteresis / debounce (a re-arm band around T), multi-condition (AND/OR) watches, and a designer UI to author watches.
- Durable state in Redis/greentic-state (v1 uses a state-dir file; fine for a single host).

## 9. Testing

- **Pure fns (no I/O):** `side(value, threshold, comparator)`; `crossing(last_side, current_side, direction) -> Option<"rising"|"falling">` incl. the `unknown` first-poll no-fire; config parse/validate (bad comparator, missing url).
- **State store:** write → read round-trip; atomic-rename; corrupt/absent → `unknown`.
- **Emit shape:** a crossing builds the expected `EventEnvelope` (topic, producer, payload fields).
- **Integration:** a stubbed metric source crossing T routes an event to a flow with `subscribes_to` (mirror the timer/event_router integration tests); a transient fetch error does not change `last_side` and does not fire.
- **Fire-once:** two consecutive polls both above T fire exactly once (the second is not a crossing).

## 10. Rollout

- Additive host module; the watcher only starts when watches are configured → zero default-path change. No flow-schema change, no new WASM component, no runner change.
- Target branch `research`.
- Follow-ups: the business-event trigger half (once a sorx listener seam lands), the pack-manifest extension, and a designer UI to author watches.
