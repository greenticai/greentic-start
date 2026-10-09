# Approval-rail interactivity ingress

**Status: no schema change is needed, and none was made.**

The approval rail contract v2 (owned by greentic-designer,
`docs/approval-rail-contract-v2.md`) assigns this repo one line of work in §8:

> `greentic-start` — Route the interactivity ingress. **Slack needs a SECOND
> ingress path, distinct from `/slack/events`, which today's config schema
> cannot express** — that schema needs a new field. This is a schema change,
> not a routing tweak.

Both halves of that claim are wrong for this codebase, and this document is the
record of why, so the schema change is not built later by someone reading the
contract on its own.

## 1. Slack does not use a second path here — one URL serves both surfaces

The Slack pack registers the SAME URL for events and for interactivity. In
greentic-messaging-providers,
`components/messaging-provider-slack/src/ops/webhook.rs` builds one
`ingress_url` and submits it under both keys of the Slack app manifest:

```rust
"event_subscriptions": { "request_url": ingress_url, "bot_events": [...] },
"interactivity":       { "is_enabled": true, "request_url": ingress_url },
```

`update_manifest_urls` in the same file rewrites both to the same value. Slack
permits this: the Interactivity Request URL is configured independently of the
Events Request URL, but nothing requires the two to differ.

The component demultiplexes on **body shape, never on path**. Its `ingest_http`
(`components/messaging-provider-slack/src/ops/ingest.rs`) tests, in order,
`url_verification`, `block_actions` (as raw JSON *or* as the form-urlencoded
`payload=<json>` shape Slack posts for interactivity), `view_submission`, and
finally the Events API envelope. `request.path` is read nowhere outside its test
fixtures.

Signature verification cannot depend on the path even in principle: it lives in
`components/messaging-ingress-slack`, whose `handle-webhook` export receives
`(headers_json, body_json)` and is never given a path at all.

This repo already assumes the same thing. `src/session_hint_extractor.rs`
demultiplexes all four Slack body shapes — Events API JSON, interactive JSON,
form-urlencoded slash commands, and form-urlencoded `payload=` interactivity —
off a single inbound body on a single route, and it is only reachable from
`dispatch_provider_route`, i.e. after a `/webhook/<provider>` match.

So an approval button click already arrives, is already parsed, and its button
`value` is already splatted key-by-key into the outbound envelope's `metadata`
(`ingest.rs`), which is how a `decision_token` carried in Slack's opaque
per-message state reaches a flow without ever touching a URL. Nothing in this
repo has to change for that to work.

## 2. Even if a second path were wanted, the schema already expresses it

A pack declares extra inbound paths with the existing
`greentic.http-routes.v1` extension (`src/http_routes.rs`), which carries
`pattern`, `methods`, `provider_op` and `domain` per route. `webchat` already
uses it for three paths.

The rule that makes such a route reach a provider is in
`discover_revision_routes` (`src/http_routes.rs`): when a pack declares BOTH
`http-routes.v1` routes AND a `provider-extension.v1` provider exposing
`ingest_http`, each declared route inherits that provider's `provider_type`.
Without the stamp, `dispatch_provider_route` (`src/revision_serve.rs`) returns
**501** and the path is dead. The stamp is applied only when the pack has
exactly one `ingest_http` provider; with two there is no right answer, so the
route is deliberately left to 501 rather than wired to whichever was listed
first.

`descriptor.provider_op` is invoked verbatim, so a declared route can also name
a dedicated op instead of being demultiplexed inside `ingest_http`.

That whole mechanism had **no test coverage**. It does now — see
`a_declared_second_path_inherits_the_packs_sole_ingest_http_provider_type` and
its three siblings in `src/http_routes.rs`.

### The one caveat a pack author must know

Deployment `path_prefixes` are applied to **synthesized** webhooks only
(`build_webhook_pattern`). A declared pattern is mounted verbatim. Under a
deployment bound to `/acme`, the event webhook moves to
`/acme/webhook/<provider>` while a declared `/webhook/<provider>/interactivity`
does not — the pack author would have to declare the prefix themselves, which
they cannot know at pack-build time. Pinned by
`a_declared_second_path_does_not_inherit_the_deployment_path_prefix`.

This is a reason to prefer the single shared path of §1, not a reason to add a
schema field: a new field would inherit exactly the same problem.

## 3. Contract obligations that do NOT fall to this repo

From the contract's §4 token rules, checked against what this repo does:

- **Never put the token in a URL.** Nothing here constructs an approval link.
  The token rides in Slack's `private_metadata` / action `value`, is decoded
  inside the WASM component, and reaches a flow through envelope metadata.
- **Never log the token.** This repo has no approval-aware code and logs no
  request bodies on the provider path; `dispatch_provider_route` logs
  `provider_type`, `provider_op`, deployment and revision ids only. Any future
  change that starts logging provider bodies would break this — the request
  subject carries a bearer credential and approver emails (contract §6).
- **Subject-level NATS read authorization** is an operator requirement neither
  repo can enforce. `src/business_event_listener.rs` subscribes to
  `greentic.events.>` with no approval-specific handling; it is not on the
  approval rail.

## 4. Known gap, reported not fixed

On the **revision-serve** path, the `messaging.provider_ingress.v1` extension
is never invoked — `invoke_provider_ingress_extension` has exactly one caller,
`src/ingress_dispatch.rs`, which is reached only from the legacy
`src/http_ingress/` server. Since Slack's signature verification lives in that
ingress extension (`messaging-ingress-slack`) and NOT in
`messaging-provider-slack::ingest_http`, a Slack webhook served by the revision
path is not signature-verified at the transport layer. The comment in
`dispatch_provider_route` about a provider that "verifies inside its own
component (e.g. Slack signature)" does not hold for the Slack pack as shipped.

For approvals specifically this is mitigated but not removed: the
`decision_token` is the credential the designer verifies (contract §4/§5), so a
forged Slack POST cannot resolve a gate without a token it does not have. It
still deserves its own fix, and it is out of scope for an ingress-routing task.
