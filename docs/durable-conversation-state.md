# Durable conversation state

A conversation that is waiting on the person — a card awaiting its submit, a
`session.wait` — is a snapshot in the runner host's **session store**. By
default that store is in memory, so it dies with the process.

For a desktop run that is right. For a deployed worker it is not: a revision
rollout, a pod restart or a Cloud Run cold start throws every parked
conversation away, and **nothing reports it**. The deploy succeeds, `/livez`
answers, and the person's next message lands on the entry card as though they
had never typed anything. The only party who sees the failure is the user.

This page is how an operator turns that off.

## What an operator sets

| Variable | Values | Default | What it does |
|---|---|---|---|
| `GREENTIC_RUNNER_SESSION_BACKEND` | `memory` \| `redis` | `memory` | Where parked conversations live. **This is the one that matters.** |
| `GREENTIC_RUNNER_STATE_BACKEND` | `memory` \| `redis` | `memory` | Where per-session flow state lives. Optional; read the caveat below. |
| `GREENTIC_RUNNER_REDIS_URL` | `redis://…` / `rediss://…` | — | The connection URL for both stores. Required once either backend is `redis`. |
| `GREENTIC_RUNNER_SESSION_NAMESPACE` | a keyspace prefix | `greentic:session:<env>` | The prefix every session key of this deployment is written under. |
| `GREENTIC_RUNNER_SESSION_WAIT_TTL_SECS` | seconds, or `0` | `86400` (24 h) | How long a parked conversation survives before Redis expires it. `0` disables expiry. |
| `GREENTIC_REVISION_PIN_REDIS_URL` | `redis://…` | — | Revision affinity. **Set this too** — see "Affinity" below. |

The minimum for a Cloud Run deployment:

```bash
GREENTIC_RUNNER_SESSION_BACKEND=redis
GREENTIC_RUNNER_REDIS_URL=rediss://default:<password>@<host>:<port>
GREENTIC_REVISION_PIN_REDIS_URL=rediss://default:<password>@<host>:<port>
GREENTIC_ENV=<your environment id>        # or --env; it derives the keyspace
```

Naming neither backend leaves the binary byte-for-byte on the behaviour it had
before this feature existed. A Redis URL **alone** switches nothing on: the
backend has to be named, so a URL that is in the environment for some other
reason (the pin store's, say) cannot silently move a deployment's conversations.

## What is stored, and for how long

Only the parked snapshot: which flow, which node it stopped at, and the
execution state that node needs to continue. No message history, no rendered
card, no credential.

Each parked conversation carries a 24-hour TTL by default. The number is a
judgement between two bounds:

- **Long enough that the feature works.** The conversation this exists to
  preserve is one a human parked. Someone who answers the next morning has to
  still resume.
- **Short enough that abandonment is bounded.** Without expiry, every
  parked-and-never-resumed conversation is a permanent key, accumulating for as
  long as the deployment runs, with nothing reporting the growth.

Raise or lower it with `GREENTIC_RUNNER_SESSION_WAIT_TTL_SECS`. `0` means no
expiry, which is a real choice for a deployment that archives its own keys — but
it is not the default, because the failure it produces is invisible.

## A shared Redis is a shared blast radius

Every key this writes is under one prefix, and **choosing that prefix is the
operator's job.** Two environments pointed at one Redis with one namespace do
not merely see each other's keys: a greentic-session entry key carries the
tenant, provider, channel, conversation and user but **not the environment**, so
a lookup that finds the other environment's context drops the entry and returns
nothing. Two environments sharing a keyspace *evict each other's parked
conversations* — intermittently, under load, with nothing red anywhere.

So:

- give every environment its own `GREENTIC_RUNNER_SESSION_NAMESPACE`, or
- give every environment its own `GREENTIC_ENV` (the default keyspace is
  `greentic:session:<env>`), or
- give every environment its own Redis database or instance.

Within one environment, greentic-start folds each pack **revision**'s identity
into the keyspace automatically — see below. That is the one piece of scoping
the binary does for you; the environment boundary is yours.

The same Redis may be shared with `GREENTIC_REVISION_PIN_REDIS_URL` and with
`GREENTIC_AW_REDIS_URL`; those use their own prefixes.

## Affinity: durable sessions alone are half a configuration

greentic-start gives every pack revision its **own** session keyspace, on
purpose. Two revisions serving the same tenant/user/conversation must not resume
each other's snapshot against a different flow graph.

That isolation and durability are not in tension — a per-revision keyspace still
survives a restart, which is the whole point — but it does mean a resumed turn
has to reach the revision it parked on. Interop callers (`/a2a`, `/mcp`) carry
no stickiness cookie at all, so `GREENTIC_REVISION_PIN_REDIS_URL` is the only
affinity mechanism on that path. Configured without it, a resumed turn can be
weighted onto another revision, find nothing under that revision's keyspace, and
restart the conversation: the same symptom the operator just configured Redis to
remove, now intermittent instead of certain.

The binary **warns loudly at boot** when durable sessions are configured and the
pin URL is not, naming both variables. It does not refuse, because a
single-replica, single-revision deployment is a legitimate configuration in
which pinning buys nothing.

## Flow state is a separate switch, and it is not revision-scoped

`GREENTIC_RUNNER_STATE_BACKEND=redis` makes the per-session flow state (what a
flow's `state` operations read and write) durable too. One caveat, which
greentic-start warns about at boot rather than leaving you to find:

`greentic-state` composes its own key
(`greentic:state:<env>:<tenant>[:<team>][:<user>]:runner:pack/<pack>/flow/<flow>/session/<hint>`)
and its Redis store takes no namespace, so there is nowhere to fold a revision
in. A durable flow-state store is therefore **shared between two live revisions
of one pack**. That is a smaller hazard than a shared resume snapshot — the two
revisions are the same flow, and the key carries pack, flow and session — but it
is a real difference from the in-memory default.

Parked **sessions** stay isolated per revision either way.

## Failure behaviour

Two rules, and they differ deliberately:

- **A backend that was named and cannot be reached is a boot failure.** The
  store is probed at construction (`redis::Client::open` parses the URL and
  opens no socket, so construction alone proves nothing), and an unreachable
  Redis aborts the boot with a message naming which store failed. It never
  degrades to memory. An operator who configured durability and silently got
  memory would have a worker that boots, serves, passes every probe, and
  restarts every parked conversation — the exact failure this feature removes.
- **A store that degrades later keeps serving.** A Redis that goes away
  mid-flight surfaces as a turn-level error, not a crash.

This is the opposite of `GREENTIC_REVISION_PIN_REDIS_URL`, which fails **open**:
a pin is a routing hint, and losing one re-picks a revision for a conversation
that still works. Losing conversation state is not a hint — it is the
conversation.

## Verifying it

```bash
# 1. The boot line names the backend (and never the URL):
#    conversation state: sessions redis (namespace 'greentic:session:prod',
#    wait ttl 86400s), flow state in-memory (parked conversations survive a restart)

# 2. Park a conversation, then look for its key:
redis-cli --scan --pattern 'greentic:session:prod:*' | head

# 3. Restart the process and send the next turn on the same conversation id.
#    It must continue, not greet.
```

The automated version of step 3 is
`durable_state::tests::a_parked_conversation_survives_a_restart`, which is
`#[ignore]`d because it needs a real Redis:

```bash
docker run -d --name start-durable-redis -p 127.0.0.1:6398:6379 redis:7-alpine
GREENTIC_DURABLE_TEST_REDIS_URL=redis://127.0.0.1:6398 \
  cargo test -p greentic-start --lib durable_state::tests -- --ignored --nocapture
```

## Requirements

`greentic-runner-host` must be built with its `session-redis` feature, which is
on by its default feature set and therefore on in this binary. A build without
it **refuses** a Redis session backend rather than falling back to memory.
