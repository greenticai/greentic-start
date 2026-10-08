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
the same bearer as the one that created it. A request without a bearer is not
deduplicated. The key hashes the bearer the caller sent, before start's
session preflight may re-mint it.

## Escape hatch: `GREENTIC_WEBCHAT_REQUIRE_CONVERSATION_TOKEN`

Default: on (refuse). Setting it to `0`, `false`, `no` or `off` (any case)
switches start's own anonymous refusal to warn-only for ONE release cycle:
such a token is then forwarded unchanged — still never bound — and start logs
one warning per conversation (no conversation id, `sub` or token in it) plus
one at boot. Any other value, including an empty one or a typo, keeps the
refusal.

Use it only for an embed that sends a `/token` token on an existing
conversation (a "tokenUrl mode" client) while it moves to the conversation
token. It does not restore the old behaviour: with a new provider pack the
provider refuses such a token itself, and with an old one `/activities`
refuses a conversation-less token anyway. It only stops start from refusing
first. The switch will be removed in a future release.
