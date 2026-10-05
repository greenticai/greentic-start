# Fast2Flow: routing misses and the route signal

Applies to BOTH messaging ingresses: the legacy one (`src/http_ingress/messaging.rs`,
turn body in `messaging_turn.rs`, used when started WITH `--bundle`) and the
revision-serve one (`src/revision_serve/fast2flow_hook.rs`, used without
`--bundle`). Both decide a turn through `src/fast2flow/probe.rs`
(`plan_turn` / `plan_from`); pure decisions live in `src/fast2flow/turn.rs`.

### Revision-serve specifics

* The app pack is the one of the revision serving the turn
  (`RevisionIngressRouting::app_packs`), and the intent index lives in a
  per-revision scope (`revision_index_scope`, `<tenant>:<team>--<hex>`).
* Precedence. A target that names a flow OTHER than the default flow (a
  URL/header-named flow, or a valid envelope `flow_hint`) is a deliberate
  selection: it always wins and is never probed
  (`[fast2flow:gate] skip path=revision reason=explicit_target`, info once per
  revision). A target that names the DEFAULT flow — the bundle's registered
  default, or the app pack's own (`default` > `main` > sole messaging flow) —
  is treated exactly like no target: Fast2Flow may replace it, and nothing
  extra is logged. This matters because the webchat provider stores the
  `X-Greentic-Flow` header a conversation was opened with and copies it into
  `flow_hint` on every activity of that conversation; a conversation opened
  against the default flow would otherwise never be routed. Mechanism:
  `fast2flow_hook::is_default_target` / `demote_default_target`. A
  conversation parked in any flow still resumes it (next bullet), because the
  parked-flow check runs before the probe.
* A conversation parked in a flow resumes that flow and is not probed. On this
  path the runner keys a parked snapshot by the flow the turn was pinned to,
  so the hook checks each messaging flow of the app pack in the revision's
  session store before probing.
* No LLM fallback: revision mode has no `bundle.yaml` `llm:` block.
* A card submit (`routeToCardId` / `toCardId` / `nextCardId`) navigates; it is
  never probed nor answered with the fixed reply (same rule as legacy).
* **Failure modes diverge from legacy here.** When the router could not be
  asked or failed — routing host binary missing, crashing, or still running
  at `GREENTIC_FAST2FLOW_TIME_BUDGET_MS` + 500 ms (greentic-start then kills
  the host's process group; `router FAILED: host timed out after … ms`), or the pack ships no `assets/intent-index.json`
  (`router not configured (no_index)`) — the revision path runs the default
  flow (fail open, logged at warn), so a turn that worked before Fast2Flow
  keeps working when the host is absent. Only a genuine no-match (the router
  ran and answered `Continue`) gets the miss policy below. The legacy path is
  unchanged: there every unrouted cause is a miss. Mechanism:
  `fast2flow::probe::OnRouterFailure`.
* `[fast2flow:gate] enter path=revision ...` is logged at INFO.
* **Behaviour change for existing revision deployments:** a pack that declares
  `greentic.cap.fast2flow.v1` now gets the fixed miss reply for free text that
  routes nowhere (before, the default flow ran). Declare
  `greentic.cap.fast2flow.on_miss.default_flow.v1` to keep running the default
  flow. This is the same behaviour the legacy path has always had.

## What a routing miss does

A turn is a **miss** when the app pack declares `greentic.cap.fast2flow.v1`,
the user sent non-blank text, the conversation is not owned by a flow, and
neither Fast2Flow (BM25 host) nor the LLM fallback produced a usable dispatch.
The router's answer is one of: dispatched, no match, not configured (gate
closed, no index path or no index — logged at debug), or **failed** (spawn
error, non-zero exit, unparseable output, or a host killed for running past
its time budget plus a 500 ms grace — logged at `warn` with the reason).
A failure behaves like a miss below, but the log names it as a failure.

A Fast2Flow `Deny` or `Respond` is not handled on this path yet: it stops
routing for the turn (the LLM fallback is NOT asked), logs a `warn`, and sends
the fixed reply — with or without the opt-in. Before this change the LLM
fallback was consulted after a `Deny`.

| pack declares | on a miss |
|---|---|
| `greentic.cap.fast2flow.v1` only (default) | fixed reply: "I'm not sure what you meant. Tap one of the menu options or rephrase your request." |
| also `greentic.cap.fast2flow.on_miss.default_flow.v1` | the pack's default flow runs with the **original** message, unchanged |

The default is unchanged on purpose: card-menu packs rely on the fixed reply so
the default flow does not re-echo their welcome menu. The opt-in is for packs
whose default flow can answer free text itself (e.g. an agentic worker).

Declare it next to the Fast2Flow capability in `pack.yaml`:

```yaml
capabilities:
  - name: greentic.cap.fast2flow.v1
  - name: greentic.cap.fast2flow.on_miss.default_flow.v1
```

It has no effect without `greentic.cap.fast2flow.v1`. A turn in a conversation
owned by a flow (a parked, dispatched flow) is never routed, so it can never
miss: it resumes its flow either way.

## The route signal on replies

When Fast2Flow or the LLM fallback routed a turn, every reply of that turn
carries key `fast2flow`:

- in `metadata["fast2flow"]` as a JSON **string**;
- in `extensions["channel_data"]["fast2flow"]` as a JSON **object** — merged
  into an existing object, left alone when `channel_data` is not an object.

```json
{"flow": "refund", "confidence": 0.92, "source": "bm25"}
{"flow": "default", "node": "refund_card", "confidence": 0.81, "source": "llm"}
```

| field | meaning |
|---|---|
| `flow` | the flow that ran the turn: the dispatched flow for a flow route, the default flow for a node route. When a node route is rendered straight from a card asset, no flow runs and `flow` still names the default flow |
| `node` | present only for a node route (`routeToCardId`): the card node targeted |
| `confidence` | the router's confidence as its shortest decimal (`0.92`, never `0.9200000166893005`); `null` when none was reported, or when it is non-finite or outside `[0, 1]` |
| `source` | `"bm25"` (Fast2Flow host) or `"llm"` (LLM fallback) |

Default-flow turns, sticky resumes, the fixed miss reply, and a routed turn
whose flow FAILED (its reply is the error-fallback echo) carry **no** signal:
the key is removed from both places, so an inbound message cloned into a reply
cannot forge one. The removal also drops a `fast2flow` key a flow emitted
itself — intentionally: the key is reserved for the router.

The `channel_data` copy is the one a Direct Line (webchat) client sees: the
webchat provider forwards `extensions["channel_data"]` as the activity's
`channelData`, while its encoder copies no arbitrary `metadata` key into the
activity.
