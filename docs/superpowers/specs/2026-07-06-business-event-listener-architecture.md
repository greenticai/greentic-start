# EPIC-C — Business-Event Trigger Listener — Architecture Decision (design only)

**Status:** Decision-needed (NO implementation) — 2026-07-06
**Initiative:** Agentic platform coverage PRD, EPIC-C "Event/Threshold Triggers". EPIC-C v1 (threshold_watcher, `#336`) delivered the **poll** half ("fire a flow when a metric crosses X"). This doc scopes the **event** half ("fire a flow when a business event happens") and surfaces the one architecture decision that gates it. It is deliberately design-only — the recommended slice cannot start until the decision below is made.

## 1. The gap

- **Publisher exists.** SoRX publishes business events to NATS `greentic.events.<tenant>.<topic>` (sorx business-events design, Phase 1 / `sorx#32`), where `topic` = `sorla.<pack>.<entity>.created|updated|deleted` or `sorla.<pack>.<event_name>`; the payload is a canonical `greentic_types::EventEnvelope`. The **consumer / listener side was explicitly out of scope** in that design.
- **Routing exists.** `greentic-start/src/event_router.rs::route_events(bundle_root, ctx, &[EventEnvelopeV1])` already delivers events to flows whose pack manifest declares `subscribes_to: ["<topic-pattern>"]` (used today by `timer_scheduler` + the EPIC-C v1 `threshold_watcher`).
- **The missing piece** is the wire between them: something that **subscribes to NATS `greentic.events.>`, decodes the `EventEnvelope`, and calls `route_events`** so a flow fires when a business event lands. That is the whole EPIC-C event half.

## 2. The blocking fact (why this isn't a thin slice)

`route_events` lives in **greentic-start**, but **greentic-start has no NATS client** — verified: no `async-nats` dependency in its `Cargo.toml`, no `async_nats::connect` anywhere in `src/`. Its only "subscribe" is the in-memory `notifier` + the websocket pump. Meanwhile **greentic-runner** *has* a NATS client (`NatsDispatcher` / `remote_dispatch.rs`, gated on `GREENTIC_EVENTS_NATS_URL`) but does **not** own the `route_events → app-flow` path.

So the listener needs a NATS subscription in a process that can reach `route_events`. Neither existing process has both. That is the decision.

## 3. Options

### Option A — Add a NATS subscriber to greentic-start (recommended)
Add `async-nats` to greentic-start and a `business_event_listener` module (sibling of `timer_scheduler`/`threshold_watcher`): on boot, when `GREENTIC_EVENTS_NATS_URL` is set, `subscribe("greentic.events.>")`; per message decode `EventEnvelope` → build the `ctx` (tenant/team from the envelope scope) → `route_events(bundle_root, &ctx, &[envelope])`. Best-effort, drop-on-decode-error, off when no NATS URL.
- **Pros:** the listener sits exactly where `route_events` + the bundle live; mirrors the `timer_scheduler`/`threshold_watcher`/admin-`audit.>`-subscriber patterns already in the codebase; one process; no cross-repo hop; testable offline (decode + route with a stub).
- **Cons:** greentic-start takes on a NATS client dependency + a long-lived subscription task (a new responsibility for the bundle server). It becomes an event-bus consumer, not just an HTTP front door.
- **Blast radius:** additive; off unless `GREENTIC_EVENTS_NATS_URL` is set (same gate the runner uses). No default-path change.

### Option B — Runner-side subscriber that bridges to greentic-start's route
greentic-runner (which already has NATS) subscribes to `greentic.events.>` and forwards each event to greentic-start over an internal HTTP hop (`/v1/events/ingress/...`, which already exists) so `route_events` runs in start.
- **Pros:** reuses the runner's existing NATS client; keeps greentic-start NATS-free.
- **Cons:** a network hop per event; the runner must know start's ingress URL + auth; more moving parts; the runner isn't obviously the owner of "business-event → app-flow" either. Higher latency + failure surface than A.

### Option C — A small standalone bridge service
A new tiny process that subscribes to `greentic.events.>` and POSTs to start's `/v1/events/ingress`.
- **Pros:** neither existing process changes.
- **Cons:** a whole new deployable unit for a thin bridge — the most operational overhead. Only justified if a dedicated event-router service is wanted long-term.

## 4. Recommendation

**Option A.** It is the smallest, most consistent change: greentic-start already owns `route_events`, the bundle, and the `subscribes_to` mechanism, and already runs long-lived host tasks (`timer_scheduler`, and the EPIC-C v1 `threshold_watcher`). Adding a `business_event_listener` that subscribes to `greentic.events.>` and feeds `route_events` mirrors those patterns and the admin `audit.>` subscriber, with the same off-by-default `GREENTIC_EVENTS_NATS_URL` gate. The only real objection — "should the bundle server consume an event bus?" — is the decision to make; if yes, A is clearly right.

**If the answer is "greentic-start must stay NATS-free,"** then Option B (runner bridge) is the fallback, at the cost of a per-event HTTP hop.

## 5. Thin first slice (once Option A is chosen)

`greentic-start/src/business_event_listener.rs` (mirror `threshold_watcher.rs` + the admin `audit_ingest.rs` subscriber):
1. Add `async-nats` dep; on boot, if `GREENTIC_EVENTS_NATS_URL` is set, connect + `subscribe("greentic.events.>")` in a spawned task; else don't start (zero default-path change).
2. Per message: `serde_json::from_slice::<EventEnvelope>` (best-effort, drop+warn on failure) → derive `ctx` (tenant/team from the envelope's scope) + the event topic → `route_events(bundle_root, &ctx, &[envelope])`.
3. Best-effort, never blocks/panics; a NATS outage or a malformed event never affects the server.
4. Tests: a decode+route unit test (a sample `greentic.events.<tenant>.sorla.<pack>.<entity>.created` envelope routes to a flow subscribed to `sorla.*` via the real `select_target_flows`); off-when-no-NATS.
**Scope caveat:** end-to-end verification needs a live SoRX publishing to NATS (a pre-enablement item, like the threshold_watcher's live source) — the decode+route logic is unit-testable offline.

## 6. Decision required

**Should greentic-start take on a NATS client + subscribe to the business-event bus (Option A)?** Yes → the §5 slice is ready to build (no other blocker; it reuses `route_events` + `subscribes_to`, off by default). No → fall back to Option B (runner bridge) and confirm start's `/v1/events/ingress` contract for runner-forwarded events.

This doc is the decision artifact; no code is written until the answer is given.

## 7. Queue group & SoRX subject contract (implemented — Option A shipped in #345)

**Subject contract.** SoRX publishes business events on `greentic.events.<tenant>.<topic>`, where `<topic>` (e.g. `sorla.<pack>.<entity>.created`) is the routing key. The listener sets `EventEnvelopeV1.event_type` to that subject-derived `<topic>`, which `route_events`/`select_target_flows` match against each flow's `subscribes_to` patterns (so `subscribes_to: ["sorla.*"]` fires on `sorla.pack.order.created`). The decoded envelope's `tenant` is authoritative; the subject's `<tenant>` segment is only cross-checked (mismatch → warn, envelope wins).

**Queue group.** The listener uses `queue_subscribe` under a queue group (not a fan-out `subscribe`), so multiple `greentic-start` instances form a NATS queue group and each event is delivered to exactly one instance — same-bundle HA replicas dedup instead of every replica double-firing the flow.

The group defaults to `greentic-start-be-listener` and is overridable via the **`GREENTIC_BE_QUEUE_GROUP`** environment variable (`resolve_queue_group`; an empty/whitespace value falls back to the default). **Set it per deployment when two *distinct* greentic-start deployments share one NATS server** — otherwise they share the default group and NATS may deliver one deployment's event to the other (which can't route it against its own bundle), silently losing it. Leave it at the default for HA replicas of the *same* bundle. The code cannot know the operator's topology, so this is a deployment-time choice.
