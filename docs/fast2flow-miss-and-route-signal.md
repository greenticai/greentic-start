# Fast2Flow: routing misses and the route signal

Applies ONLY to the legacy messaging ingress (`src/http_ingress/messaging.rs`,
turn body in `messaging_turn.rs`). The revision-serve path does not run this
code: there, neither the opt-in nor the route signal exists. Pure decisions
live in `src/http_ingress/fast2flow_turn.rs`.

## What a routing miss does

A turn is a **miss** when the app pack declares `greentic.cap.fast2flow.v1`,
the user sent non-blank text, the conversation is not owned by a flow, and
neither Fast2Flow (BM25 host) nor the LLM fallback produced a usable dispatch.
The router's answer is one of: dispatched, no match, not configured (gate
closed, no index path or no index — logged at debug), or **failed** (spawn
error, non-zero exit, unparseable output — logged at `warn` with the reason).
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
