# OpenAI-compatible worker endpoint

A deployed worker can answer `GET /v1/models` and `POST /v1/chat/completions`, so
an OpenAI-style client (an SDK, Open WebUI, `curl`) can call it as if it were a
model. It is `/a2a` with a different body: the same staged credentials, the same
per-credential bucket and per-deployment turn cap, the same turn runner and the
same usage meter. Code: `src/interop/openai/`.

## Enabling it

The unit's staged ingress document carries `"openai": true` (optional, `v` stays
1). Absent means off, and a build that predates the key ignores it and never
serves `/v1`. The designer stages it from the "Answer OpenAI-compatible clients"
switch on the unit.

`openai_resource` is an optional OAuth audience for `/v1`. Absent means the
surface accepts the staged bearer alone, which is what the designer stages today.

**Private units only.** A public unit never serves these paths: anonymous callers
would spend the owner's LLM budget through a surface that invites scripts.

## Behaviour

| Request | Answer |
|---|---|
| no token, a wrong token, a Direct Line token | `401`, `WWW-Authenticate: Bearer` |
| `model` other than `worker:<agent id>` | `404 model_not_found` |
| non-empty `tools` | `400 worker_tools_unsupported` |
| `stream: true` | `400 streaming_unsupported` |
| a non-text content part | `400 unsupported_content` |
| the credential's bucket is empty | `429 rate_limit_exceeded` with `Retry-After` |
| every turn slot of the deployment is busy | `429 worker_busy` |
| the turn failed | `502 worker_turn_failed`, conversation id still returned |

- **`model`** never selects anything. `GET /v1/models` lists one entry,
  `worker:<agent id>` (the staged agent id, else the bundle id).
- **Conversation.** The `X-Greentic-Conversation-Id` header names it, with the
  OpenAI `user` field as an alias. It becomes the session hint
  `openai:<credential or subject>:<id>`, namespaced like the A2A and MCP forms.
  With an id, only the last `user` message is sent (the worker holds the
  history). Without one, a fresh conversation starts and earlier messages are
  framed as context ahead of the last message. A caller `system` message is
  never the worker's system prompt; it is framed as context in both cases. The
  answer carries `X-Greentic-Conversation-Id`.
- **Parked turns.** A turn that asks the caller for input answers
  `finish_reason: "stop"` with the question as the content and
  `x_greentic: {"status": "input_required"}`. Continue with the same id.
- **`usage`** is reported only when the runtime measured tokens for the turn. It
  is never estimated; absent means not measured.
- **Streaming is refused, not faked.** The runtime hands the host whole replies,
  not token deltas, so there is nothing honest to stream.
- **CORS is off.** A browser caller goes through the operator's own backend.

## Not built

`/v1/responses`, `/v1/runs`, jobs, sessions, `Idempotency-Key` (a retried request
spends a second turn), tool-progress events.
