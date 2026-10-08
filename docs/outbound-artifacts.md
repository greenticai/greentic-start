# Outbound artifacts: files an agent creates, delivered as signed links

An agent that creates a file with an extension tool (for example
`greentic.media` `generate_image` / `create_document`) gets back a C5 tool
result `{"ok": true, "artifact": {"id": "artifact://<64 hex>", ...}}`. This
host turns that result into something the end user can open: on WebChat an
attachment, on every other v1 channel a link in the message text. The link is
a short-lived, signed, per-unit URL served by this host at one route.

Contract: the attachments-and-artifacts master plan (C2 id, C3 door, C5 tool
result, C6 fixtures) and the outbound-delivery plan (gap G1), both in the
greentic-designer repository.

**Links are OFF in this build.** `link::OUTBOUND_LINKS_ENABLED` is `false`
until the release that carries the WebChat reconnect-token hardening (gap G2):
a hijacked WebChat conversation would otherwise expose every file link it
holds. While off, a reply that names a file says "A file was created but file
delivery is turned off for this worker." and the route answers every request
with its 404. `GREENTIC_ARTIFACT_LINKS=1` (`true`/`yes`/`on`) forces links on
for a host that has G2 (local testing); there is no off-override. The G2
release flips the constant and its pin test.

## 1. How it works

```text
extension tool put ──> DoorArtifactPort ──> admin door (bytes stored)
        │                    └─ RecentPuts (this DEPLOYMENT's record:
        │                       id -> door's mime, size; port's name)
        ▼
dw.agent reply {reply, trail[*].result = C5}
        │  reply closure: build_reply_envelopes + outbound::collect
        ▼
OutboundSide (envelope id -> ids)          <- out of band, never in the envelope
        │  egress loop: outbound::prepare_replies
        ▼
strip raw artifact:// urls -> resolve (provenance, kill switch, base, mint)
        -> shape per channel -> run_reply_egress
        ▼
user opens  GET /v1/artifacts/<deployment>/<artifact hex>/<exp>/<mac>
        -> verify -> limits -> door read with the unit's token -> bytes
```

- **Collected:** every `trail` step with `kind == "tool_call"` whose `result`
  is `ok: true` with a well-formed `artifact.id`, then a top-level `artifact`
  or `response.artifact`; deduplicated, at most 5 per reply. A payload that is
  itself a full `ChannelMessageEnvelope` (a flow emitting one) names nothing.
- **Provenance gate:** a link is minted only for an id THIS deployment's
  extension port stored within the link TTL. Every revision of a deployment (a
  traffic split) writes into the deployment's one record. Any other id
  (another conversation's upload, an id a flow invented) gets "A file could not
  be sent." The file's name, type and size come from that record (the door's
  answer at put time), never from the tool's claim.
- **Raw ids never leave:** every `artifact://` url in an outgoing envelope's
  `attachments` and in the raw DirectLine `attachments` array is removed before
  egress (no provider validates an outbound url). Count-only log.

## 2. The link

`/v1/artifacts/<deployment ULID>/<artifact hex 64>/<exp unix seconds>/<mac hex 32>`

- **Key, per unit, derived, never stored:**
  `K = HMAC-SHA256(key = the unit's gtm_ metering token, "greentic/artifact-link/v1" 0x1f tenant_slug 0x1f bundle_id 0x1f deployment)`.
  No key is shared across units or tenants; every instance of the unit (cold
  starts, replicas) derives the same key.
- **MAC:** `trunc128(HMAC-SHA256(K, "v1" 0x1f deployment 0x1f artifact_hex 0x1f exp))`,
  checked in constant time. The path alphabet (`[0-9A-Z]`, `[0-9a-f]`) survives
  Slack, Telegram, Webex, Teams and WebChat text without escaping.
- **TTL:** `GREENTIC_ARTIFACT_LINK_TTL_SECS`, default 86 400 (24 h), clamped to
  300..604 800, read once per process. 60 s clock skew is allowed.
- **Revocation.** There is NO per-link revocation. What exists, per unit:
  - lower the TTL and restart: verification refuses any `exp` beyond
    `now + current TTL + 60 s`, so links minted under a longer TTL stop working;
  - re-mint the unit's metering token and redeploy: the key changes, every
    outstanding link of that unit answers 404.
  When the admin revokes the token at teardown, the door answers `401`; the
  route then answers `503` (a misconfiguration, warned once per process with
  the deployment id and a fixed code), not `404`.
- A link appears in platform access logs (Cloud Run, load balancers) and in
  chat history. It grants one file, read-only, until it expires.

## 3. The route

`GET` and `HEAD` only (`405`, `Allow: GET, HEAD` otherwise). Reserved before
deployment resolution, so a `/` route binding cannot capture it; never
CORS-enabled; the metric and span label is the literal `/v1/artifacts/:link`.

Order: kill switch -> method -> per-client window -> exact path shape ->
deployment known with a live signer -> MAC -> expiry -> per-link window ->
egress budget -> read slot -> door read.

**One 404.** A malformed path, an unknown deployment (or a string that is not
a ULID), a unit running without attachments, a bad MAC, an expired link, the
links kill switch, a door `404` (retention sweep, another tenant's id) and a
type outside the allow-list all answer the SAME status, headers and body:
"This link is not valid or has expired. Ask the assistant to send the file
again." No refused link reaches the door.

**Headers (the serving rule, `docs/inbound-attachments.md` §7):**
`Content-Type` = the door's sniffed type (v1 allow-list only);
`Content-Disposition: inline; filename="…"` for `image/jpeg|png|gif|webp`,
`attachment; filename="…"; filename*=UTF-8''…` for PDF, CSV, plain text,
Markdown, JSON; `X-Content-Type-Options: nosniff`;
`Cache-Control: private, no-store`;
`Content-Security-Policy: sandbox; default-src 'none'`;
`Referrer-Policy: no-referrer`; `X-Frame-Options: DENY`; `Content-Length`.
Never `Set-Cookie`, a CORS header, `Location`, `ETag` or `Last-Modified`. The
file name is cleaned (control, bidi and invisible characters removed, `"` and
`\` replaced, at most 120 bytes, `file` when empty).

`HEAD` answers the same headers with no body. The admin door has no HEAD, so a
`HEAD` still reads the file from the door (it is not counted against the
egress budget).

**Limits (fixed text, none an oracle):**

| limit | default | answer |
|---|---|---|
| door reads in flight per process (`GREENTIC_ARTIFACT_LINK_MAX_INFLIGHT`, 1..8) | 2 | `503`, `Retry-After: 2` |
| requests per link (deployment + artifact) | 30 / 60 s | `429`, `Retry-After: 60` |
| requests per client, only when `GREENTIC_TRUSTED_PROXY_HOPS > 0` | 120 / 60 s | `429` |
| bytes served per unit per hour (`GREENTIC_ARTIFACT_LINK_EGRESS_MB_PER_HOUR`, 16..65536 MiB) | 2048 MiB | `429` |

Door failures: `NotFound` is the 404; `Unavailable` is retried once after
250 ms, then `503`; `TooLarge`, `Unauthorized`, `PurposeNotGranted` and a read
over 25 s are `503` with fixed text.

## 4. Per channel

| channel (`provider_type`) | shape |
|---|---|
| WebChat (`messaging.webchat*`) | a typed attachment (`url` = the signed link; the provider maps it to `contentUrl`), also appended to a raw DirectLine `attachments` array when one is present. With no agent text and no card the text becomes "Here is your file: …". With no public https base the link is RELATIVE (`/v1/artifacts/…`), which resolves against the origin that served the WebChat page |
| Slack, Telegram, WhatsApp, Webex, Teams | no typed attachment; one `name: url` line per file appended to the text; when the reply carries an Adaptive Card the lines go in a separate follow-up message. Names in text are reduced to `[A-Za-z0-9 ._-]` (80 characters) |

A refused file becomes its fixed sentence: "A file could not be sent.", "A file
was created but cannot be sent on this channel because this worker has no
public https address." or the "turned off" sentence above. A file-only turn
(no agent text, no shaped reply) still gets a message.

## 5. Public base

First non-empty of: the configured base (env-store `host_config.public_base_url`,
then `PUBLIC_BASE_URL`), the Cloud Run capture, a cloudflared/ngrok tunnel. It
must be a bare origin over `https`, or `http` to a loopback host; otherwise
only WebChat gets a (relative) link. Never derived from a request's `Host`.

## 6. Configuration

| Variable | Default | Purpose |
|---|---|---|
| `GREENTIC_ARTIFACT_LINKS` | off (code) | `1`/`true`/`yes`/`on` forces links on; no off value |
| `GREENTIC_ARTIFACT_LINK_TTL_SECS` | `86400` (300..604800) | Link lifetime; lowering it (with a restart) revokes longer links |
| `GREENTIC_ARTIFACT_LINK_MAX_INFLIGHT` | `2` (1..8) | Door reads at once per process |
| `GREENTIC_ARTIFACT_LINK_EGRESS_MB_PER_HOUR` | `2048` (16..65536) | Bytes served per unit per hour |
| `GREENTIC_TRUSTED_PROXY_HOPS` | `0` | Enables the per-client window when the client address is known |

All are read once per process.

## 7. Not served (stated, never silent)

- The legacy `--bundle` lane: no door, no signer, no route. Raw `artifact://`
  urls are removed and a reply that names a file says "A file was created but
  this host cannot send files."
- Generic JSON ingress, `/workers/invoke`, A2A and MCP answers: they return the
  activity JSON to an API caller; the C5 object stays in it as data and no link
  is minted.
- Agent-graph and deep-worker results (their node outputs carry no tool
  results), and any turn whose final reply is not the `dw.agent` node output.
- A unit with no artifacts door or no staged metering block (no signer).

## 8. Threats

| threat | mitigation |
|---|---|
| link leaks via logs, history, Referer | one file, ≤ TTL; the route never logs a path, MAC or id (`redaction_ratchet_tests`); `no-referrer`; downloads are `attachment` or inert images. Platform access logs record it: accepted |
| cross-tenant / cross-unit read | key bound to token + tenant + bundle + deployment; the door filters by the token's tenant; one 404 |
| forged links from flow-authored envelopes | out-of-band side table; raw ids stripped; provenance gate |
| content sniffing / XSS | allow-list, sniffed type, `nosniff`, `attachment` for documents, sandbox CSP |
| open redirect | the route never redirects |
| bandwidth abuse | per-link and per-unit limits, read slots, `no-store` |
| MAC brute force | 128-bit tag, constant-time compare |
| WebChat conversation hijack exposes links | links off until G2 ships |

## 9. Verifying

Focused tests (never the whole suite):

```text
cargo test -p greentic-start --lib artifacts::link
cargo test -p greentic-start --lib artifacts::serve_link
cargo test -p greentic-start --lib artifacts::outbound
cargo test -p greentic-start --lib artifacts::redaction
```

End to end against a real admin door (ignored by default; the link modules are
crate-private, so it lives in the library, not under `tests/`):

```text
GREENTIC_E2E_ARTIFACT_DOOR=http://127.0.0.1:<port>/api/v1/ingest/artifacts \
GREENTIC_E2E_ARTIFACT_TOKEN=gtm_... \
GREENTIC_E2E_ARTIFACT_TOKEN_OTHER=gtm_...   # optional, another tenant's unit \
cargo test -p greentic-start --lib artifacts::links_e2e -- --ignored --nocapture
```

Manual acceptance (master acceptance item 4), real binaries, local, recorded in
the PR:

1. Start a local greentic-designer-admin with the artifacts door live.
2. Start the designer with `GREENTIC_ARTIFACTS=1` on the env-canvas local lane,
   with `greentic.media` installed (built from its repository).
3. Build a worker that binds `generate_image`; deploy it to a local
   `greentic-start` (`--store-root`) behind a cloudflared tunnel so the link
   base is https, with `GREENTIC_ARTIFACT_LINKS=1` (links are off in code until
   G2 ships).
4. WebChat GUI: ask for an image. Expect the image inline in the chat.
5. Same worker on a Slack test workspace through the tunnel: the message text
   carries `generated.png: https://…/v1/artifacts/…`; opening it downloads the
   PNG (`Content-Type: image/png`, `nosniff`, `no-store`).
6. Restart with `GREENTIC_ARTIFACT_LINK_TTL_SECS=300`, ask again, wait six
   minutes, open the link: the 404 page.
7. Note how often Slack's unfurler fetches the link against the 30/min per-link
   window, and confirm Bot Framework Web Chat renders the cross-origin
   `contentUrl` image.
