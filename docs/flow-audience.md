# Flow audience

Runtime half of the designer's "who can use this" flow setting
(designer spec: `docs/superpowers/specs/2026-10-10-flow-audience-design.md`).

The designer writes `assets/flow-meta.json` into an app pack:

```json
{"version":1,"audience":["sales"],"example_requests":["..."]}
```

## What this host does

* **Reads** the sidecar when the app pack is loaded (`messaging_app::load_app_pack_info`,
  `AppPackInfo::flow_meta`). Absent, oversized, malformed or of an unknown
  `version` means "no audience" (fail open, one warning).
* **Fills `team_hint`** in the inbound envelope's `metadata` from the caller's teams.
  A user may belong to several teams. The teams come from
  `extensions.caller.team` (one slug, backward compatible) and
  `extensions.caller.teams` (array of slugs, at most 50 read), the block only a
  messaging provider may author on the revision-serve route (`client_caller`),
  and only when `extensions.caller.user_verified` is `true`. Each slug is
  trimmed, lowercased and must be a DNS label of at most 50 characters
  (`[a-z0-9-]`, no leading or trailing `-`); invalid entries are ignored and
  duplicates removed. `team_hint` stays a single value: the first caller team
  that is in the flow's audience (so the router uses the relevant team), else
  the first caller team. The key is always overwritten, or removed when no team
  is known: card submits flatten user-controlled data into `metadata`, so an
  inbound `team_hint` is never trusted.
* **Enforces** the audience (`flow_audience::decide`):
  empty audience = everyone; ANY caller team in the audience = allowed;
  known teams and none in the audience = refused with a plain reply
  ("Sorry, this assistant is not available to your team.") and no flow runs;
  no known team (absent, unverified, empty or all-invalid) = NOT refused (fail
  open, logged at info), or every anonymous chat would break.

## Router packs (Fast2Flow): `node_audience`

A channel served by a generated Fast2Flow router forwards the message to a
target unit over agent-to-agent, so the target's own flow gate never sees the
caller's teams. The router enforces the target's audience instead, on the
message it received through the messaging path (verified caller block):

* the designer writes `node_audience` into the router pack's
  `assets/flow-meta.json`: `{"version":1,"audience":[],"node_audience":{"ask_hr":["hr"]}}`
  (node id of the `a2a` node to the teams allowed to be routed to it; a node
  absent or mapped to no team is open);
* `fast2flow_hook` applies `flow_audience::decide_node`, the same policy as the
  flow gate (open = allow; no verified team = allow, logged; any caller team
  listed = allow; known teams none listed = the plain refusal reply, no target
  is called), to (a) a node the router dispatches to, (b) a node dispatched
  while re-routing a parked conversation, and (c) a card-navigation key
  (`routeToCardId`, `toCardId`, `nextCardId`) in the inbound metadata, so a
  client cannot name a restricted node itself;
* nothing is trusted from an unflagged hop: teams are read from this message's
  caller block, never from a forwarded header (see the next section for the one
  hop that may forward a caller).

Not covered: the router's assistant (the on-miss default flow), and a
conversation already parked inside a target resumes without a new check.

## Scope and limits

* Revision-serve messaging path only (start without `--bundle`). The legacy
  `--bundle` ingress, the generic JSON ingress, agent-to-agent and MCP doors are not covered.
* The gate checks the revision's app pack (the one that resolves the default flow).
  Other packs in a bundle are not gated.
* The check runs per inbound message, including card submits and parked
  conversations. It runs after inbound attachment handling, so a refused
  caller's files were already fetched and stored.
* Until a provider puts `team` / `teams` in the caller block, every caller has
  an unknown team and nothing is refused.

## Open questions

1. Router hint vs flow gate: this change makes the flow gate authoritative and
   `team_hint` advisory input for routing; the router does not read it yet.
2. Source of the caller's team: `extensions.caller.team` (provider-verified).
   Confirm the providers (webchat OIDC, Teams, Slack) will fill it.

## A router may forward the verified caller (`forwards_caller`)

"The target never sees the caller's teams" holds for every hop EXCEPT a router
whose credential is flagged `forwards_caller`. For that hop the target receives
the identity the router's provider verified, and its own flow audience can be
enforced against it.

**Wire (sender: the `a2a` flow node with `forward_caller`).** In the A2A
`SendMessage`, on both bindings (JSON-RPC `/a2a` and REST `/a2a/message:send`):

```json
"message": {"metadata": {"caller": {
  "sub": "u-1", "iss": "https://idp", "teams": ["sales"], "groups": ["g"],
  "role": "member", "user_verified": true }}}
```

**Opt-in (ingress document).** Each entry of `credentials[]` takes an optional
`forwards_caller: bool` (default `false`; a document without the key behaves
exactly as before). The flag is read from the entry of the credential the
request AUTHENTICATED with, never from the request. If a credential id appears
twice (rotation), every entry must carry the flag.

**Acceptance (all required, else the block is silently dropped, a `warn` without
the block's content is logged, and the turn runs as it always did):**

1. the authenticated credential is a staged bearer flagged `forwards_caller`
   (OAuth and anonymous callers never forward);
2. the block has exactly the fields above (`iss`, `role`, `teams`, `groups`
   optional), `user_verified` is the boolean `true`, `sub` is non-blank, it is at
   most 4096 bytes of JSON, `teams`/`groups` at most 64 entries, every string at
   most 256 characters with no control characters;
3. the binding is A2A. MCP, `/workers/invoke` and the generic ingress never
   accept one (and still strip any `extensions.caller` a body carries).

`metadata.caller` is removed from the request unconditionally; an accepted block
is REBUILT from the validated fields, gets `via: "router:<credential id>"`, and
is written to the turn's `extensions.caller` — the key the runner's
`caller_identity` reads. The session hint and the `a2a:<credential id>` user
stay per credential, not per forwarded user. The request telemetry span carries
`interop.forwarded_via` (the usage event already names the router credential in
`credential_id`; its wire format is unchanged).

**Not covered:** the A2A path itself runs no flow-audience gate (the gate lives
on the provider route and in the router), so a forwarded `teams` list is made
available to the runner and flows, not enforced by this host on this hop. Teams
are forwarded as `teams`; this host does not also set the single `team` key.
