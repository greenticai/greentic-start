# The approval-rail bridge

greentic-designer publishes human-in-the-loop approval requests on the NATS
subject `greentic.approval.request.v1` and reads the human's answer off
`greentic.approval.response.v1`. `greentic-messaging-providers` renders the
approve/reject affordance for a channel and parses that channel's click back
into a response body.

Neither of them can touch NATS. A provider component's only host imports are
`http-client` and `secrets-store`, and the designer's listener is on the other
side of the wire. **This repo is the middle**, and until this change nothing
subscribed to that subject: the designer shouted into the rail and nobody
listened.

The authoritative contract is
`greentic-designer/docs/approval-rail-contract-v2.md`. Its two conformance
fixtures are vendored here at `tests/fixtures/approval_rail/` and asserted
against directly, so a drift in the designer's payload fails a test here rather
than in production. `docs/approval-rail-ingress.md` (a sibling change) records
why the interactivity ingress needed no schema change; this document is about
what was built on top of it.

## What it does

| Step | Where |
|---|---|
| Subscribe to `greentic.approval.request.v1` under a queue group | `src/approval_rail/listener.rs` |
| Parse the request, defensively and additively | `src/approval_rail/request.rs` |
| Pick a provider and call its `approval_request` op, then `send_payload` | `src/approval_rail/delivery.rs` |
| Hold `correlation_id -> message_ts` so a republish updates one message | `src/approval_rail/ledger.rs` |
| Lift the answer off the click's envelope and drop the marker envelope | `src/approval_rail/response.rs` |
| Publish the answer, echoing `Greentic-Correlation-Id` | `src/approval_rail/listener.rs` |

Two ingress paths call `approval_rail::intercept_inbound` — `ingress_dispatch.rs`
(legacy, on **both** its return paths, because the
`messaging.provider_ingress.v1` shortcut returns early and skips the
post-ingress hooks) and `revision_serve.rs::dispatch_provider_route` (the
deployed path). It is a no-op unless the bridge is running.

## Configuration

Both are required and neither has a default. A half-configured bridge is
reported and not started.

| Variable | Purpose |
|---|---|
| `GREENTIC_APPROVAL_NATS_URL` | Broker carrying the rail |
| `GREENTIC_APPROVAL_DESTINATION` | Conversation approval requests are delivered to |

`GREENTIC_APPROVAL_NATS_URL` is deliberately **not** `GREENTIC_EVENTS_NATS_URL`.
Contract §6 makes per-tenant subject-level read authorization on the approval
subjects mandatory, which in practice means a different NATS account or
credential from the general business-event bus; one variable could not express
that separation.

## Two questions the contract does not answer, and what was done

### Which conversation does a request go to?

**The rail does not carry a destination and cannot be made to.**
`routing.channels` is advisory and names a channel *kind*;
`routing.approvers.emails` are emails, and §7 states plainly that "the request
carries no channel handles, only emails. An email -> channel-handle mapping is
greentic-designer-admin's to supply."

This deployment has no answer of its own either. Every `send_payload` in this
crate is downstream of an inbound message and reuses its `to`
(`preserve_ingress_reply_route`); `grep -rn "Destination" src/` finds nothing
that constructs one. An approval request is unsolicited — there is no inbound
conversation to reply to. The one remaining mechanism is the Slack provider's
own `default_channel` setup answer, resolved inside the component.

Falling through to `default_channel` is exactly what must not happen. §4 is
explicit that the button state carrying the `decision_token` "is readable by any
member of the conversation" via `conversations.history`, so delivery belongs in
a DM or a private approver channel. Inheriting the deployment's general chat
channel would put a bearer credential in front of everyone in it, silently.

So the destination is explicit and the bridge **fails closed** without one. That
is the smallest mechanism that does not guess. `routing.channels` is still read
— it orders which installed provider delivers, and never filters, because an
advisory field that can drop a gate is not advisory.

### Which tenant does a request belong to?

**It cannot be determined from the message.** The body carries no tenant, and
`Greentic-Tenant` is explicitly unusable for it (§1): it is the executor's
checkpoint-partition tenant on the first publish and the approval row's real
tenant on a sweeper republish, so the same gate arrives under two different
values.

The bridge therefore stamps the tenant and team the **process** was started for
(`gtc start --tenant <t> --team <team>`), the same pair everything else in the
process scopes to. A `greentic-start` instance serves one tenant, so this is
exact rather than a guess.

What it costs, stated rather than implied: a single instance cannot fan a shared
subject out to several tenants. That is not a limitation this repo can lift, and
it is not one that wants lifting here — §6 already requires that a tenant's
delivery integration hold its own NATS credential and be unable to read another
tenant's requests. One process, one tenant, one credential is the shape that
requirement asks for. A multi-tenant deployment runs one bridge per tenant.

**Feedback for the contract:** if a single shared subscriber should ever serve
several tenants, the request needs a routable tenant field.
`Greentic-Tenant` cannot become one without breaking the republish case it was
documented around.

## Token handling

The `decision_token` is a bearer credential and this repo sits in the middle of
its path, which makes it the easiest place to leak one. Concretely:

- **It is never read.** A request body is handed to the delivery component
  verbatim and a response body is published verbatim.
- **It is never logged**, at any level, truncated or hashed. Every rail body
  held here is a `RailBody` (`src/approval_rail/body.rs`) whose `Debug` and
  `Display` are redacted and whose only reader is the greppable `expose()`, so
  a body reaching a log line as a field of some other struct still cannot leak
  one. Failure paths name the correlation id and a stable reason token instead.
- **It is never put in a URL.** Nothing here constructs an approval link.
- **It is never stored at rest.** The delivery ledger holds correlation ids and
  Slack message ids only.
- **The click reader never touches `actions[].value`**, which is where the token
  rides. Everything it needs — the correlation id and the clicked message's id
  — is in the message metadata Slack echoes back, so it takes the route that
  cannot leak. Pinned by
  `the_click_reader_never_touches_the_button_value`.
- **A provider may not name its own publish subject.** A component is a third
  party's WASM running in this process; the `subject` on its response extension
  is validated against `greentic.approval.response.v1` rather than trusted.
- **The generic provider dispatcher's log previews are suppressed for
  `approval_request`.** This one was a real leak, found by auditing rather than
  by a failing test. `runner_host/dispatch.rs` logs a truncated preview of every
  op's payload and of every component op's result; the `approval_request`
  **input** carries the token in cleartext at `request.routing.decision_token`,
  and its **output** carries the same token base64'd inside the rendered Slack
  message at `payload.body_b64`. Truncation is not redaction — where a secret
  falls relative to a 256- or 500-character cut is an accident of how long the
  fields before it happened to be. `op_payload_is_credential_bearing`
  (`runner_host/helpers.rs`) suppresses both, keyed on the **op** rather than
  the provider, so a channel that grows an approval affordance later gets the
  same suppression without anyone remembering to add it. Pinned by
  `the_approval_request_op_is_never_previewed_into_a_log_line`.

  **Residual, stated rather than implied:** the `send_payload` *input* for an
  approval message also carries the token (it is the same rendered body). It
  cannot be suppressed by op id without blinding every ordinary outbound
  message, and the dispatcher cannot see that a given payload came from
  `approval_request`. In practice it is not reachable today: that input is
  previewed only on the entry-**flow** branch, and only when `debug_enabled` is
  set, and no shipped messaging pack registers `send_payload` as an entry flow
  (Slack exposes it as a component op). A pack that did would reopen it.
  Closing it properly means marking the payload rather than the op.

And what the token does **not** do (§5): it authenticates the **sender**, not
the person named in `resolved_by`. Nothing built here claims otherwise —
`resolved_by` is carried through as the component produced it, and if Slack
gave no email (the app lacks `users:read.email`) it stays `null` and a
policy-governed gate correctly refuses the vote as `no_claimed_identity`. That
is a better outcome than a guessed identity, and it is the component's decision,
not this bridge's.

## Operator requirement

From §6, and this repo cannot enforce it: **per-tenant subject-level read
authorization on `greentic.approval.request.v1` is mandatory** wherever this
rail is live, and publish permission on the response subject should be scoped
the same way. Anyone who can subscribe to the request subject can read a token
out of it and approve the gates they can see, and `routing.approvers.emails`
puts tenant member addresses on the same subject. Do not fan either subject out
to a general-purpose bus tap, an archive, or a debug consumer that logs
payloads.

Delivery must go to a DM or a private approver channel, for the same reason. The
bridge cannot enforce that either — it is what `GREENTIC_APPROVAL_DESTINATION`
names.

## Known gap — `send_payload` discards the provider's message id

**The ledger is filled from the human's click, not from the send, because the
send cannot report it.**

`send_payload` returns `SendPayloadResultV1 { ok, message, retryable }`
(greentic-types). The provider's message id is not on that type, and a component
cannot add a field to a typed DTO it does not own — Slack's own `send_payload`
computes the `ts` and then drops it (`components/messaging-provider-slack/src/ops/send.rs`).
The click envelope does not carry it either: `build_slack_envelope` never sets a
`ts`.

So the bridge learns the outstanding message's id from the click instead
(`slack_click_delivery`), which covers the case the contract actually calls out:
a quorum republish is always *caused by* a vote, and a vote is a click, so by
the time a republish arrives the ledger already knows where the message is. This
is proved end-to-end in `tests/approval_rail_live_broker.rs`.

What it does **not** cover: an escalation republish for a gate **nobody has
clicked yet** posts a second message, because nothing ever told this process
where the first one went. That is one extra message per un-clicked escalation,
and it is logged.

Two one-line fixes, either of which closes it, both in
greentic-messaging-providers:

1. `handle_approval_interaction` stamps `container.message_ts` into the emitted
   envelope's metadata — which also lets this repo stop parsing the raw Slack
   body at all, and generalises to any channel.
2. Or `SendPayloadResultV1` grows an optional `message_id`, in greentic-types.

(1) is the better one: it is channel-agnostic and needs no change to a shared
DTO.

## What happens on restart

The ledger is in-memory and deliberately not persisted. A restart loses it, and
the next republish for a gate delivered before the restart posts a new message;
every republish after that updates *that* message, because the new delivery
re-enters the ledger. The degradation is bounded — at most one extra message per
outstanding gate per restart — and it is logged, never silent.

Persisting it to `state/runtime/` would not fix the general case and would read
as if it had: the rail is consumed under a NATS **queue group**, so in a
multi-instance deployment a republish is delivered to exactly one instance and
not necessarily the one that made the first delivery. A map local to a process
is already incomplete before any restart happens. Closing that needs shared
state or a channel-side lookup of the outstanding message (Slack stamps
`event_payload.correlation_id` into the delivered message precisely so such a
lookup is possible), and both are larger than this bridge.

## Testing

Unit tests live beside each module. The live-broker proof is
`tests/approval_rail_live_broker.rs`, skipped when
`GREENTIC_APPROVAL_NATS_URL` is unset (CI has no broker, and a test that goes
red there gets turned off within a week):

```bash
docker run -d --name greentic-nats-bridge -p 4223:4222 nats:latest -js
GREENTIC_APPROVAL_NATS_URL=nats://127.0.0.1:4223 \
  cargo test -p greentic-start --test approval_rail_live_broker -- --nocapture
```

Real in that test: the broker, the subscribe, the queue group, the request
parse, the ledger, the response publish and its header, and the
`approval_request` op input production code builds. Stubbed: the WASM component
and the Slack HTTP call (an `ApprovalDelivery` that records what it was handed),
and the click body (the shape Slack posts, not one Slack sent).
