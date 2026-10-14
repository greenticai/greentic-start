# Interop access policy (private and public units)

The designer stages an optional `access` block, and an optional `a2a_resource`,
in a unit's ingress document (document `v` stays `1`). `/a2a` and `/mcp` enforce
them. Contract: designer repo
`docs/superpowers/specs/2026-10-12-mcp-a2a-access-policy-design.md`.

```json
"access": { "visibility": "private|public", "mechanisms": ["api_key","oauth"],
            "public": { "rate_per_min": 60, "burst": 20, "daily_turn_cap": null },
            "generation": 7 },
"a2a_resource": "https://<service>/a2a"
```

## Reading the block never opens a unit

Any problem in the block forces the unit **private**; never public. The
`mechanisms` list is read first and on its own, so a problem elsewhere never
widens it:

- readable list: its known entries are kept (an unknown name is dropped alone);
- an empty list, one with no known entry, or one that is not a list invalidates
  the whole block: private with both mechanisms, logged at **error** level
  naming the value;
- an unknown `visibility`, malformed or non-positive public limits (a `daily_turn_cap` of 0 included; an absent or null cap means no cap), or a
  malformed `daily_turn_cap` force private but KEEP the readable list, so an
  `["oauth"]` unit stays OAuth-only;
- a non-object `access` or an absent block: private with both mechanisms.
`public` limits are read only when `visibility` is `public`. `a2a_resource` is
kept only when it is `https://` (or loopback `http://`).

## Who is let in

| unit | credential presented | result |
|---|---|---|
| private | none | 401 |
| private | valid, mechanism listed | served as that caller |
| any | presented and invalid, or valid but its mechanism is not listed | **401**, never anonymous |
| public | none | served as anonymous, within the limits |
| any | a Direct Line (HS256) token | never an identity: 401 on private, anonymous on public |

- `mechanisms` is a strict filter. A mechanism the policy does not list is never
  accepted. If the policy is OAuth-only and OAuth cannot be verified on the
  surface (no issuer, tenant or audience: `a2a_resource` for `/a2a`,
  `mcp_resource` or the public base URL for `/mcp`) every credential is refused
  (401) and the reason is logged once at error level; the staged bearer is NOT
  accepted instead. The designer stages an OAuth-only policy only together with
  what OAuth needs. The default policy (no `access` block) lists both mechanisms,
  so its bearer works whether or not OAuth is available, as before.
- An OAuth token's `aud` must equal the surface's own resource URL, so an MCP
  token cannot call `/a2a` and the reverse. Service-client tokens
  (`sub = svc:<client_id>@<tenant>`) are namespaced as `svc~<client_id>~<tenant>`:
  the key carries no colon (a colon in a caller key breaks the session-hint
  namespace) and `~` is outside every other caller key's alphabet.
- An old greentic-start ignores `access`, so a unit staged `public` there still
  demands a bearer. Closed, not open.

## Anonymous limits

1. `anon:<deployment>`: a per-unit bucket holding `burst` turns, refilled at
   `rate_per_min`. Always applies. This is the guarantee.
2. `daily_turn_cap`: anonymous turns per UTC day, per unit, per process (a cold
   start resets it). 429 with `Retry-After` to the next UTC midnight.
3. `anon:<deployment>:<client>`: a per-client bucket (half the burst and rate,
   never below one turn), fairness only. The table holds at most 1024 buckets;
   when full of active clients a new client gets none and only (1) applies.

The client is the N-th `X-Forwarded-For` entry from the right when
`GREENTIC_TRUSTED_PROXY_HOPS=N` (default 1 on Cloud Run, else 0), else the TCP
peer **only if it is a public address**. A private or loopback peer is a load
balancer hiding every caller (an ALB, ECS or Cloudflare tunnel with no hops set),
so the client is then **unknown**. The header is client-writable, which is why
only (1) is a guarantee. A refused request spends none of the daily cap, and a
client turned away by the unit bucket gets its own tokens back.

Conversations are never namespaced by the client label alone, because the
context id is the caller's own choice:

- identifiable client: namespace `anon_` + `hash(client, context id)`, so two
  clients using the same context id never share state and one client continues
  its own conversation;
- unknown client: no per-client bucket (the unit bucket alone governs), and every
  request gets a fresh random namespace, so nothing can be continued or read
  across callers. A public unit read with hops 0 logs this once.

The `anon_` prefix is reserved: a staged credential id starting with it is dropped
at parse time (error log), and an OAuth token whose `sub` starts with it is
refused. An `Authorization` header that is present but unreadable (non-ASCII) is
a presented, invalid credential (401), not an absent one.

The daily cap is counted per process. For a unit that stages `access.door`
(below) the admin's count of today's anonymous turns raises the local counter
on every fetch, so a scale-to-zero or restart no longer hands the budget back;
for a unit without the door a cold start still resets it.

Anonymous usage events carry no `credential_id` and `caller_kind: "anonymous"`;
every other event is byte-identical to before. `caller_kind` is advisory for the
admin until the admin persists it. The agent card of a public unit
advertises no security scheme.

Anonymous turns also share the unit's concurrent-turn gate without being able to
fill it: they hold at most half of the permits (at least one), so a credentialed
caller always has the other half.

## The runtime access-policy door (phase 3)

A unit whose `access` block carries `"door": true` asks the admin, while it
runs, to NARROW the staged policy. Without the flag nothing is fetched and the
unit is served exactly as before. The flag is read on its own, so an `access`
block that is otherwise thrown away does not stop a unit from being narrowed.

```json
"access": { "...": "...", "door": true }
```

`GET <metering.endpoint with its last segment swapped for access-policy>` with
the unit's metering token (the token needs the purpose `access`), `If-None-Match`
when it holds an ETag. Answer:

```json
{ "generation": 7,
  "policy": { "private_mechanisms": ["api_key","oauth"], "public_allowed": true,
              "public_rate_per_min": 60, "public_burst": 20,
              "public_daily_turn_cap": null },
  "revoked_credential_ids": ["c_01J"], "revoked_client_ids": ["mcpc_01J"],
  "public": { "daily_turns_used": 12 } }
```

Timing: an answer is served for 60 s, then revalidated; a failed attempt is not
repeated for 30 s (the refresh floor); concurrent requests share one fetch; one
attempt waits at most 3 s; no redirects; the body is capped at 1 MiB.

**The door only tightens** (spec D17). The effective policy is the staged one
with:

| staged | door | effective |
|---|---|---|
| mechanisms | `private_mechanisms` | the intersection. Empty = every credential refused (error log), never a fallback |
| public | `public_allowed: false` | private. A private unit is never made public |
| rate / burst | `public_rate_per_min` / `public_burst` | the minimum |
| daily cap | `public_daily_turn_cap` | the minimum; a cap can appear, never be lifted |
| credentials | `revoked_credential_ids` | those credentials removed (a presented one is a `401`, also on a public unit) |
| OAuth tokens | `revoked_client_ids` | a token whose subject is `svc:<client_id>@<tenant>` for a revoked client is refused **before the issuer is asked anything**, a token minted before the revocation included |

The anonymous daily count becomes `max(local count, daily_turns_used)` each
time a new answer arrives and grows by every turn served here after that, so
the remaining budget is `min(staged, door) - daily_turns_used - turns served
since the fetch`. (`max` rather than a plain assignment so a turn this process
served that the admin has not yet been told about is never forgotten.)

**A door that cannot answer opens nothing and denies nothing new.** A timeout,
a 5xx, a 401/403/404 or a body this build cannot read keeps the last good
answer; with none, the staged policy stands. Each distinct failure is logged
once, never with the token or the body. A door answer is not trusted beyond
what the table above says: a wider mechanism list, `public_allowed: true` on a
private unit or a higher limit changes nothing.

Not covered: the door cannot revoke a named bearer the designer never reported
to the admin, and a revocation reaches a running unit within one 60 s window,
not instantly.

### Known limits of the door

- **Revocation needs a first answer.** A revoked credential or service client is
  refused only after the door has answered once. A process that cold-starts while
  the admin is unreachable serves the staged policy, so a credential revoked since
  the last deploy is still accepted until the first successful fetch. The next
  deploy closes the gap for good, because it stages the document without that
  credential's hash.
- **The last good answer never expires.** While the admin stays unreachable, the
  most recent answer keeps applying, revocations included. It is dropped only
  when the process restarts.
- **The door can only tighten.** An answer that would widen the staged policy is
  intersected with it, so a compromised or misconfigured admin cannot open a unit.
