# Direct Line conversation ownership

A Direct Line conversation belongs to the session that created it (anonymous
visitor) or to the same verified identity (signed-in visitor). Knowing a
conversation id is never enough to read it, post to it or open its stream.

The decision is the webchat provider's (`owner::authorize` in
greentic-messaging-providers): it records the creator (`owner_sub`,
`owner_verified`) on the conversation and checks every conversation route
against it. greentic-start's part is to never undercut that decision.

## What greentic-start does

`src/directline_session.rs` screens the conversation routes —
`GET /v3/directline/conversations/{id}` (reconnect) and
`POST`/`GET /v3/directline/conversations/{id}/activities` — before they reach
the provider:

| token | answer |
|---|---|
| `conv` names another conversation | `403 WrongConversation` |
| `conv` names this conversation | renewed with the SAME `conv`, window extended, may re-pin (unchanged) |
| no `conv`, not `verified: true` | `403 ConversationOwnerRequired`, provider not consulted |
| no `conv`, `verified: true`, expired | `401 TokenExpired` (the sliding window rescues bound tokens only) |
| no `conv`, `verified: true`, valid | forwarded UNCHANGED: no rewrite, no renewed token, no window touch, no pin |

Two rules hold everywhere and are pinned by
`directline_session_owner_tests.rs`:

- **start never binds a token to a conversation.** Every token it re-mints
  carries exactly the `conv` it received
  (`start_never_mints_a_conv_it_did_not_receive`). It used to set `conv` to
  the id in the URL for a conversation-less token, which handed any
  conversation to anyone who could mint a `/token` token and learn its id.
- **The refusal is not an existence oracle.** start holds no conversation
  state, and the anonymous refusal is byte-identical whether the conversation
  exists or not. Its body is the provider's own:

  ```json
  {"error":"forbidden","code":"ConversationOwnerRequired","message":"this conversation belongs to another session; start a new conversation"}
  ```

`verified` counts only as an explicit JSON `true` on a token whose signature
already verified. An anonymous `sub` comes from the client (`user.id`, a
per-browser guest id) and proves nothing, so an anonymous visitor proves
ownership only with the token bound to the conversation — the one
`POST /conversations` returned, which the bundled WebChat GUI stores and
resumes with.

The anonymous refusal needs no state, so it closes the anonymous hole even for
a bundle that still carries a provider pack predating the ownership check.
Verified-vs-verified isolation needs the new provider pack.

## Create dedup

The 30 s `POST /conversations` dedup cache (`src/conv_dedup.rs`) returns a
cached response — which carries a BOUND token — only to a request presenting
the same bearer as the one that created it. The key holds a domain-separated
SHA-256 of the bearer the caller sent (`greentic-start/conv-dedup/v1\0` +
token), taken before start's session preflight may re-mint it.

A request without a bearer is not deduplicated. That includes every create on
a provider with no `jwt_signing_key` configured (`SigningKey::NotConfigured`,
Direct Line auth off) whose client sends no `Authorization` header: there the
racing double-create this cache exists for is back, and two near-simultaneous
`createDirectLine` calls start two conversations. Before this change such
requests were keyed on `user.id` alone, which is what let one caller receive
another's conversation; keying them on nothing is the price of closing that.

## No switch, and what that means for a `tokenUrl` embed

start ALWAYS refuses an anonymous conversation-less token on a conversation
route; there is no setting that relaxes it. An earlier draft of this change
carried a warn-only env switch (`GREENTIC_WEBCHAT_REQUIRE_CONVERSATION_TOKEN`).
It was removed before release because it rescued no embed: with a new
provider pack the provider refuses such a token itself, and with an old pack
`POST /activities` refuses it anyway now that start no longer binds it. The
only thing the switch still did was let an old provider pack's reconnect mint
a token bound to someone else's conversation.

An anonymous embed has to send the token bound to its conversation:

1. get a token from `/token` (conversation-less);
2. `POST /v3/directline/conversations` with it;
3. adopt the `token` returned in that response (bound to the new
   conversation) and use it for every later call — `/activities`, reconnect,
   `/tokens/refresh`.

directlinejs and the bundled WebChat GUI already do this. An embed configured
with a `tokenUrl` that keeps fetching a fresh bearer from `/token` and sending
THAT on an existing conversation gets `403 ConversationOwnerRequired` on every
send and every reconnect, and must switch to the token from the create
response (and refresh it through `/v3/directline/tokens/refresh`, which keeps
its `conv`).

## Release note

> **WebChat Direct Line: a conversation belongs to the session that started
> it.** greentic-start no longer binds a conversation-less token to the
> conversation named in the URL, refuses an anonymous conversation-less token
> on reconnect and `/activities` with `403 ConversationOwnerRequired`, and
> matches Direct Line methods case-insensitively (a lower-case `get` used to
> skip the check). There is no switch to relax this. An embed that sends a
> `/token` token on an existing conversation (a `tokenUrl` that re-fetches
> `/token`) must use the token returned by `POST /conversations` instead.
> The create-dedup cache now returns a cached conversation only to the bearer
> that created it.

## Serving artifact bytes (binding on any future route)

No route serves artifact bytes today. Any route that ever does follows this
rule:

A read is authorised only by a host-minted, short-lived, single-artifact
credential (a signed link naming artifact id, conversation id, tenant and
expiry), or by a verified identity equal to the conversation's `owner_sub`
with `owner_verified`. Holding a token for the conversation — bound or not —
is NEVER sufficient on its own, and an artifact id is never a credential.

A Direct Line token — bound to the conversation or not — is never a read
credential for an artifact. A future WebChat download link is minted by the
host per artifact when it sends the message, expires within 15 minutes, and is
checked against the artifact's own tenant and conversation.
