# Fast2Flow: routing misses and the route signal

Applies to the legacy messaging ingress (`src/http_ingress/messaging.rs`).
Decisions live in `src/http_ingress/fast2flow_turn.rs`.

## What a routing miss does

A turn is a **miss** when the app pack declares `greentic.cap.fast2flow.v1`,
the user sent non-blank text, the conversation is not owned by a flow, and
neither Fast2Flow (BM25 host) nor the LLM fallback produced a usable dispatch.

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
| `flow` | the flow that ran the turn: the dispatched flow for a flow route, the default flow for a node route |
| `node` | present only for a node route (`routeToCardId`): the card node targeted |
| `confidence` | the router's confidence, `null` when none (or non-finite) was reported |
| `source` | `"bm25"` (Fast2Flow host) or `"llm"` (LLM fallback) |

Default-flow turns, sticky resumes and the fixed miss reply carry **no**
signal: the key is removed from both places, so an inbound message cloned into
a reply cannot forge one.

The `channel_data` copy is the one a Direct Line (webchat) client sees: the
webchat provider forwards `extensions["channel_data"]` as the activity's
`channelData`, while its encoder copies no arbitrary `metadata` key into the
activity.
