# Shared state backend (running more than one instance)

A worker is one instance by default. Flow state, the trigger store and the
dev store all assume a single process. This document says which of them must be
shared for N > 1, how a deployed workload is told where the shared backend is,
and what happens when it is down.

## Which stores must be shared

| Store | Holds | N > 1 | Why |
|-------|-------|-------|-----|
| **Session store** (parked conversations) | A card awaiting its submit, a `session.wait` | **Must be shared** | The next message of a conversation can land on any instance. Per-revision keyspace, see `docs/durable-conversation-state.md` |
| **Flow state** (per-session key/value) | `state` operations of a flow | **Must be shared** | Same reason. NOT revision-scoped; the boot warns |
| **Trigger store** | Cron tick claim, webhook idempotency, hourly firing budget | **Must be shared** | Otherwise every instance fires each cron tick, deduplicates webhooks per instance, and each has its own budget. `docs/triggers.md` |
| **Session-pin store** | Revision affinity for callers with no cookie | **Should be shared** | Without it a resumed turn can be routed to a different revision than it parked on |
| **Dev store** (`.dev.secrets.env`) | Credentials staged by `op secrets put` | **May stay per-instance, read-only** | Each instance boots from the same staged copy. It must not be a runtime write target: an instance that writes to its own copy diverges from the others. Anything that has to be written at run time belongs in one of the shared stores above |

The dev store is deliberately NOT moved to Redis by this feature. It is seeded
per revision from the same staged secrets on every instance, so identical
read-only copies are correct; the hazard is only a second WRITER.

## Telling a deployed workload where the backend is

A deployed workload receives no arbitrary environment variables from the
Greentic Designer; credentials travel through the staged `op` secret store. So
the backend is configured by ONE secret:

```
secrets://{env}/{tenant}/_/shared_state/redis_url     UTF-8 Redis URL
```

```bash
op secrets put --store-root <env_home> shared_state redis_url   # value: redis://...
```

The served tenant is tried first, then `default` (what a remote lane carries).
Use `rediss://` for TLS. When the secret is present it
fills in every setting the environment does not set:

* trigger store -> that Redis;
* session-pin store -> that Redis;
* session store AND flow state -> `redis`, against that Redis.

### Environment variables override

Setting any of these explicitly wins, per setting, over the shared secret:
`GREENTIC_TRIGGER_REDIS_URL`, `GREENTIC_REVISION_PIN_REDIS_URL`,
`GREENTIC_RUNNER_SESSION_BACKEND`, `GREENTIC_RUNNER_STATE_BACKEND`,
`GREENTIC_RUNNER_REDIS_URL`. That lets an operator split backends or opt one
store back to memory (`GREENTIC_RUNNER_STATE_BACKEND=memory`). With no shared
secret, behaviour is exactly what it was before.

## Failure behaviour: loud

A shared backend that was asked for and cannot be used stops the **boot**:

* the secret exists but the secret store cannot be read -> boot fails (a failed
  store has not shown sharing is unconfigured);
* the trigger store Redis (from `GREENTIC_TRIGGER_REDIS_URL` or the secret) is
  unreachable -> boot fails; there is no in-memory fallback;
* the session-pin Redis from the secret is unreachable -> boot fails;
* the session/flow-state Redis is unreachable -> boot fails (unchanged).

The one fail-open case left: `GREENTIC_REVISION_PIN_REDIS_URL` used as a
FALLBACK for the trigger store (it was never a request for a shared trigger
store) still warns and continues in memory.

Rationale: a second instance on in-memory state double-fires cron ticks and
loses parked conversations while every probe stays green.

Redis outages AFTER boot are unchanged: a trigger-store error skips the tick
(never fires unclaimed).

## Capability flag

```
$ greentic-start capabilities
{"schema":"greentic.start.capabilities.v1","version":"...","capabilities":["shared-state-backend"]}
```

`shared-state-backend` means this build reads `shared_state/redis_url` and
applies the rules above. A deployer (greentic-deployer#661) should gate
`replicas` / `max_instances` > 1 on this flag being present. An older binary
has no `capabilities` subcommand at all: treat a failing call as "not
supported".

## Tests and what is not verified

Unit tests cover: precedence and merge (`shared_backend::tests`), reading the
staged secret, the fail-loud rule with an injected connector, and a
two-instance cron claim over one shared store (`triggers::scheduler_tests`).
The real Redis tests in `triggers::store` still run only with
`GREENTIC_TEST_REDIS_URL`. Not verified: a real multi-instance run on Cloud Run
or Kubernetes, and the designer/deployer side staging the secret.
