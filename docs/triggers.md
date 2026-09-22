# Flow triggers (`greentic.triggers.v1`)

A flow can be started from outside a conversation: on a **cron schedule**, or
when a **verified webhook** arrives. The pack declares its triggers in
`assets/triggers.json`; greentic-designer writes that file, and this host
reads it on every revision activation.

The contract is `docs/trigger-contract-v1.md` in greentic-designer. This page
covers what an operator needs to know about the host side.

## What the host does

| | Cron | Webhook |
|---|---|---|
| Declared by | `kind: "cron"`, `cron.expr` + `cron.timezone` | `kind: "webhook"`, `webhook.verify` (+ `challenge`) |
| Fired by | one server-lifetime loop, ticking every second against the live activation | `POST <deployment-prefix>/trigger/<trigger_id>` |
| Revision | the one the traffic split picks at that moment | same |
| Session | `per_run` (default): each firing gets its own session; `per_key`: firings sharing a key share a session | same |
| Flow entry | `entry_node` of `flow_id`, with the §9 payload under `{{entry.*}}` | same |

Code: `src/triggers/` (`schema`, `table`, `scheduler`, `webhook`, `verify`,
`dispatch`, `store`, `limits`, `telemetry`).

## Replicas: set a shared store

`GREENTIC_TRIGGER_REDIS_URL` (falling back to
`GREENTIC_REVISION_PIN_REDIS_URL`) holds three things that must be shared
across replicas:

- the per-tick claim, so each cron tick fires on **one** replica;
- the webhook idempotency set;
- the hourly firing budget.

Without Redis the in-memory store is used. It is correct for a single
replica. With two or more, every replica fires every cron tick, and
deduplication only works per replica. Boot logs which store is active.

## Webhook responses

| Status | Meaning |
|---|---|
| 200 | accepted and queued (the flow runs after the response), or a duplicate suppressed by idempotency, or a Meta challenge echo |
| 401 | verification failed (bad or missing signature/token); the flow never runs |
| 403 | wrong Meta verify token |
| 404 | no such trigger on the revision the split picked, or `enabled: false` |
| 405 | method not declared, or a `GET` that is not a subscription handshake |
| 413 | body over `max_body_bytes` (checked before verification) |
| 429 | concurrency limit or hourly budget reached (`Retry-After: 5`) |
| 503 | a verification secret cannot be read, or the trigger asks for a check this host cannot enforce yet |

Refusals carry no body. The route is public, and error detail would reveal
the configuration to anyone probing it.

## Secrets

`secret_ref` / `verify_token_ref` are `<provider>/<key>` names. They are
resolved at exactly the address a component in the same pack reads them:
the runner's `tenant_ctx()` for the revision plus
`scoped_secret_path_for_pack(pack_id, ref)`. An unreadable secret answers
503. It never falls back to accepting unverified requests.

## Not supported yet

- `webhook.allowed_sources`: the revision path has no trusted client-address
  header yet. A trigger that declares it is **not served** (503 and a boot
  warning), because serving it would skip the restriction the author asked
  for.
- Concurrency limits are per replica. The budget is shared only when Redis
  is configured.

## Observability

- Counter `greentic.trigger.outcomes{trigger_id,kind,outcome,reason,deployment_id}`
  with outcomes `fired`, `rejected`, `deduplicated`, `skipped`, `failed`.
- One `greentic.trigger` log line per outcome. Rejections are also logged on
  `greentic.trigger.audit` with the trigger and reason, never the body or a
  header value.
- `/status` lists every loaded trigger with its revision, whether it is
  served, and its webhook routes or cron schedule.
