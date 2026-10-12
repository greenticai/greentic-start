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

Absent, unparseable, an unknown `visibility`, non-positive public limits or a
non-object `access` all read as **private with both mechanisms**. Never public.
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

- `mechanisms` is a filter. If OAuth cannot be verified on a surface (no issuer,
  tenant, or audience: `a2a_resource` for `/a2a`, `mcp_resource` or the public
  base URL for `/mcp`) the staged bearer is accepted whatever the list says, so a
  policy cannot lock an owner out of a surface that cannot run it.
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

The client is the TCP peer, or with `GREENTIC_TRUSTED_PROXY_HOPS=N` (default 1 on
Cloud Run, else 0) the N-th `X-Forwarded-For` entry from the right. The header is
client-writable, which is why only (1) is a guarantee. A refused request spends
none of the daily cap, and a client turned away by the unit bucket gets its own
tokens back.

Anonymous usage events carry no `credential_id` and `caller_kind: "anonymous"`;
every other event is byte-identical to before. The agent card of a public unit
advertises no security scheme.
