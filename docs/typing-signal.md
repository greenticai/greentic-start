# Typing signal (host half)

While a turn runs, greentic-start raises the channel's native "is typing"
indicator through the OPTIONAL provider op `send_typing`. It is cosmetic: it sends
once, refreshes until the turn finishes (hard cap 120 s), and never fails, alters
or meaningfully delays a turn or its replies.

The cross-repo contract is `docs/typing-signal-contract-v1.md` in
greentic-designer (spec: `docs/superpowers/specs/2026-09-29-thinking-and-typing-indicators-design.md`
there, §5). Code: `src/typing/`.

## The op

A provider opts in by listing `send_typing` in its
`greentic.provider-extension.v1` `inline.providers[].ops`. The host never calls it
otherwise.

Input `SendTypingInV1` (JSON):

```json
{
  "v": 1,
  "provider_type": "messaging.telegram.bot",
  "tenant_id": "acme",
  "tenant": { "tenant": "acme", "team": "ops" },
  "message": { "...": "the INBOUND ChannelMessageEnvelope the turn answers" },
  "config": { "...": "optional; the same config the host hands send_payload on this path" }
}
```

`message` is the inbound envelope; the provider derives its target from it exactly
as it does for a reply. `tenant_id` and `tenant.tenant` are the same slug.
`config` and `tenant.team` are omitted when absent, and mirror each path's
`send_payload`:

| path | `tenant.team` | `config` |
|---|---|---|
| deployed (revision-serve) | absent | the deployment's per-pack config overrides |
| legacy (demo / single bundle) | `ctx.team` | `build_injected_config`, `_b64` keys decoded |

Output `SendTypingOutV1`:

```json
{ "v": 1, "ok": true, "refresh_after_ms": 4000 }
```

- `ok: false` (+ optional `error`) is a failed attempt, never a failed turn.
- `refresh_after_ms` is how long the indicator stays visible. Absent or `0` means
  "do not refresh".
- There is no stop call; platforms clear the indicator on the next bot message.
- The op must never produce a visible message.

## Capability: read once, never probed

- **Deployed:** `HttpRouteDescriptor::supports_typing` is stamped at revision
  activation (`http_routes::discover_revision_routes`) from the same
  `provider-extension.v1` `ops` array the runner's `declared_ops` allowlist reads.
  A declared `http-routes.v1` route inherits it with its `provider_type`.
- **Legacy:** `DemoRunnerHost::supports_op(Messaging, provider, "send_typing")`,
  once per `route_messaging_envelopes` batch (a manifest read, never an invoke).

A provider that does not declare the op is never invoked for it. Nothing catches
the runner's "op is not declared" refusal per turn.

## Schedule

| `refresh_after_ms` | behaviour |
|---|---|
| absent / `0` | send once, never refresh |
| `n` | refresh every `clamp(n − 500 ms, 1 s, 30 s)` |

No refresh is scheduled whose start falls at or past 120 s from the FIRST send.
The first failure (`Err`, `ok: false`, undecodable output) stops refreshing for
that turn. Bot self-messages (`metadata.is_bot_message == "true"`) raise nothing.

## Stop rule

When the turn completes no new send starts, and an in-flight `send_typing` is
awaited for at most `STOP_GRACE` (2 s) before egress (`render_plan` → `encode` →
`send_payload`) begins. So a refresh never lands after the reply unless the
provider call outlives the grace, in which case it is abandoned and logged.

- Deployed: the loop runs in the turn's own task (`tokio::select!`), then
  `tokio::time::timeout(STOP_GRACE, …)`.
- Legacy: the loop runs on a detached thread; the turn's thread waits on a done
  channel with `recv_timeout(STOP_GRACE)`. An abandoned thread sends nothing more
  and exits when the hung call returns.

## Webchat WS notify

A webchat `send_typing` output carries the same `_greentic`
`{tenant, conversation_id, watermark_bumped}` block as `send_payload`, and the host
publishes a `NotifyEvent` for it on both paths (deployed:
`try_notify_webchat_activity`; legacy: the post-op callback, whose op filter
includes `send_typing`). The WS pump acts on an event whose watermark is `>=` its
cursor, so reporting the conversation's CURRENT next watermark (not a consumed
one) is enough to wake it.

## No metering

Typing goes through the provider-invoke seams only
(`RunnerHost::invoke_provider_for_revision`, `DemoRunnerHost::invoke_provider_op`),
never through `handle_activity_for_revision`. It is not a turn, creates no run
outcome and is not metered.

## Kill switch

`GREENTIC_TYPING_SIGNAL` — default on. `0`, `false`, `no`, `off` (trimmed,
case-insensitive) stop every `send_typing` call.

## Known limits

- The deployed capability mirrors the runner's `declared_ops` rather than asking
  it (the runner exposes no query). If the two ever diverge, the cost is one
  logged refusal per turn; no turn is affected.
- An abandoned in-flight call (past the grace) can still reach the platform after
  the reply; the platform clears it on its own timeout.
- `messaging-3aigent-gui` is not in the legacy post-op notifier's provider filter
  (for any op, not only typing).
