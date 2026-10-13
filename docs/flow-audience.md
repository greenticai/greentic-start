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
