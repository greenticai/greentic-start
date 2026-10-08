# Inbound attachments and artifacts

How a file a person sends on a channel becomes something an agent or a flow can
read, what the operator configures, and what this host promises not to do with
it. Code: `src/artifacts/`. Contract (cross-repo, binding): the master plan
`2026-10-06-attachments-and-artifacts-master.md` in greentic-designer, sections
C1-C4.

## 1. How it works

1. A messaging provider turns a channel message into envelopes. For each file
   it emits an `attachments[i]` entry with `url = null` and a fetch reference in
   `extensions["attachment_fetch"][i]`. It never downloads the file and never
   puts a credential in the envelope.
2. After the HTTP ack, after the approval-rail intercept and before any turn
   (`run_provider_inbound_pipeline` in `revision_serve.rs`), the host:
   - removes any `artifact://` URL, `extensions.artifacts` and
     `extensions.attachment_notes` the provider or a client wrote (only the host
     writes those);
   - resolves each fetch reference, downloads with a streaming size cap, sniffs
     the bytes, and stores the file through the admin **artifacts door**;
   - extracts text from documents (PDF, TXT, MD, CSV, JSON) and stores it as a
     derived artifact;
   - rewrites the envelope (below) and deletes `extensions.attachment_fetch`.
3. The runner hands the agent the artifact ids and notes; the agent reads the
   bytes through the door with the unit's own token. A flow reads
   `{{entry.attachments[i]}}`.

A failed attachment never fails the turn and is never removed or reordered.

### Envelope out (C1)

Three arrays parallel by index:

```json
"attachments": [
  { "mime_type": "image/png", "url": "artifact://<64 hex>", "name": "photo.png", "size_bytes": 12345 },
  { "mime_type": "application/pdf", "url": null, "name": "big.pdf" }
],
"extensions": {
  "artifacts": [
    { "sha256": "<hex>", "kind": "image", "text_ref": null },
    null
  ],
  "attachment_notes": [
    null,
    { "code": "too_large", "message": "\"big.pdf\": not read, ..." }
  ]
}
```

A failed slot keeps its place with `url = null`, `artifacts[i] = null` and a
note. Note codes: `too_large`, `unsupported_type`, `fetch_failed`,
`quota_exceeded`, `door_unavailable`. Messages are fixed text plus the file
label (quoted, at most 64 characters), never provider text, a URL or a token.
Provider counters (`metadata.attachments_dropped`, `messages_dropped`) become
notes with the same fixed codes.

### Fetch references (in)

| `kind` | fields | used by |
|---|---|---|
| `bearer` | `url`, `secret_key` | Slack (`SLACK_BOT_TOKEN`), Webex (`WEBEX_BOT_TOKEN`) |
| `telegram_file` | `file_id` | Telegram (`TELEGRAM_BOT_TOKEN`, resolved with `getFile`) |
| `whatsapp_media` | `media_id` | WhatsApp (`WHATSAPP_TOKEN`, resolved through the Graph API) |
| `public` | `url` | Teams `downloadUrl` (pre-authenticated, no credential) |
| `inline` | (none) | WebChat upload: bytes in `attachments[i].content` |

`{"kind":"none"}`, a missing entry and `null` all mean "never fetch": no
network call is made for that slot. A reference may only use its own
channel's credential and id kind: a Slack request cannot make the host spend
the WhatsApp token.

`inline` content is EITHER a JSON string of standard base64 OR
`{ "data_base64": "<base64>" }`. Anything else (a number, an array, a data-URI
prefix, URL-safe or invalid base64) is a `fetch_failed` note. The size is
checked from the base64 length before decoding, the bytes are re-sniffed, and
`content` is set to `null` once the slot is handled, stored or not.

## 2. Limits

| Limit | Value |
|---|---|
| per file | 10 MiB (enforced while streaming; Teams declares no size up front) |
| files per message | 5 (the sixth keeps its slot with a `quota_exceeded` note) |
| per message, all files | 50 MiB |
| per conversation | 50 MiB, enforced by the admin quota (`422` becomes a `quota_exceeded` note) |
| extracted text | 200,000 characters per document |
| PDF | 300 pages; parsed in a separate worker process (section 6) |
| Direct Line `/upload` body | 16 MiB (other provider routes: 1 MiB) |
| uploads per client | 10 per minute, one at a time per client, body within 30 s (`429` / `408`) |
| uploads in flight per process | 4 (`503` beyond, never queued) |
| door writes per message | 2 in parallel; 3 attempts on `408`, `429`, `502`, `503`, `504` and transport failures (`Retry-After` up to 3 s, else doubling backoff); 20 s timeout per request |

The per-conversation quota key is `channel family + pack id + envelope channel
+ sender + session id` (each part escaped). It includes the sender, so in a
group conversation the 50 MiB is per sender. The admin's per-tenant byte quota
is what bounds a WebChat client that rotates its sender id. The door never
sees the key: the host sends its SHA-256 (64 hex characters) as
`conversation_id`, because on WhatsApp the sender is a phone number.

v1 types, decided from the bytes, never from a header or the provider's field
(`application/octet-stream` means unknown): `image/jpeg`, `image/png`,
`image/gif`, `image/webp`, `text/plain`, `text/markdown`, `text/csv`,
`application/json`, `application/pdf`. SVG, HTML and everything else are
`unsupported_type`.

## 3. Download safety (SSRF)

- `https` only, no explicit port, no userinfo, no IP literals.
- Hosts per credential (a credential is only ever sent to its own list):
  Slack `files.slack.com`; Webex `webexapis.com`; WhatsApp
  `graph.facebook.com`, `lookaside.fbsbx.com`, `*.fbcdn.net`, `*.whatsapp.net`;
  Telegram `api.telegram.org`.
- Credential-less (`public`) hosts: `*.sharepoint.com` (exactly ONE label:
  `tenant.sharepoint.com`, never `a.b.sharepoint.com`) and
  `smba.trafficmanager.net`.
- `GREENTIC_ATTACHMENT_ALLOWED_HOSTS` (comma-separated) adds hosts for
  credential-less fetches only. It never widens a credential's list.
- Names resolve through a public-only resolver at connect time: loopback,
  private, link-local, CGNAT and other non-public addresses are refused, so the
  address checked is the address connected to (DNS rebinding included).
- Redirects are followed by hand, at most 3, each hop re-checked against the
  same policy; the credential is dropped on any hop off its list. A Telegram
  file URL (token in the path) follows no redirect at all. The WhatsApp media
  URL returned by Graph is checked before the token is attached.
- No proxy, no content-encoding negotiation or decoding.
- Error strings carry no URL and no token (`artifacts::redaction_tests`).

## 4. Activation and the admin door

The door is `POST {sibling of the unit's worker-usage endpoint}/artifacts/put`
and `/artifacts/get`, authenticated with the unit's metering token
(`Authorization: Bearer gtm_...`) carrying the `artifacts` purpose. The tenant
comes from the token; nothing in a request names one.

At activation each distinct door (URL and token) is probed ONCE, however
many revisions share it; at most 3 probes run at a time (the admin runs four
transfers per process and refuses the rest); each probe has an 8 s budget and
the whole pass a 10 s deadline, after which a door not yet probed counts as
unavailable (and recovers in the background):

| Probe answer | Revision state | Effect |
|---|---|---|
| no metering block staged | `Off(NoDoor)` | slots get `door_unavailable`, "this worker has no file storage configured" |
| `403 purpose_not_granted` | `Off(NotGranted)` | one warning; slots get "file attachments are not enabled for this worker" |
| answers | `Enabled` | attachments are stored |
| unreachable, `5xx`, `429`, a bare `404`, another `403`, slower than the budget | `Off(DoorUnavailable)` | the revision SERVES; slots get "file storage is temporarily unavailable for this worker"; one warning naming the revision and a fixed code |
| `401` | activation refused | the unit's credential is wrong; inbound files would otherwise be lost |
| endpoint unsafe, carrying userinfo/query/fragment, or underivable | activation refused | |

`Off(DoorUnavailable)` re-probes in the background: 30 s, doubling to 5 min,
then every 5 min, with no give-up. On success the unit switches to `Enabled`
without a restart; on `purpose_not_granted` it settles on `Off(NotGranted)`
(one warning, code `purpose_not_granted`, naming the revision). A `401`
during a re-probe is warned ONCE (code `rejected_token`, naming the revision),
the unit stays off and the re-probe keeps going: a redeploy with a valid token
fixes it.
The agent reader and the extension port are installed for a door-down unit
too, so they work as soon as the door answers. If the re-probe ends
`purpose_not_granted`, the port already installed answers `unsupported` at
once (no door call, no warning per call).

Order of deployment: the admin carrying the artifacts door must be live BEFORE
this host. Otherwise every metered unit sits in `Off(DoorUnavailable)` (no
files) until it is.

The extension port (`greentic:extension-host/artifact@0.1.0`, tools that
create files) writes with the unit's token and sends no `conversation_id`, so
an extension's files count against the tenant quota only, never a
conversation's. One extension `put` is bounded by 20 s end to end (the store's
retries included), so a tool waiting on a door that is down gets
`unavailable` instead of blocking for the store's full retry span.

## 5. Channels

| Channel | Inbound files | Why |
|---|---|---|
| WebChat (Direct Line upload) | yes (`inline`) | bytes arrive in the request itself; no outbound fetch |
| Slack | yes | the host verifies the signing secret before any fetch |
| Telegram | yes, ONLY with a webhook secret (`webhook_secret_ref`) on the endpoint | the host verifies the secret token |
| WhatsApp | not yet | no host-side `X-Hub-Signature-256` check |
| Webex | not yet | verification happens inside the provider, invisible to the host |
| Teams (Bot Framework) | not yet | the JWT is decoded, not validated |
| Email, Teams Graph | no | v1 emits no attachments |

A remote reference from a channel the host cannot verify is never resolved; the
slot gets `fetch_failed` "files from this channel are not supported yet", and
activation warns once per class. WhatsApp: an envelope naming another business
number than the instance's is dropped; one with no number (absent, empty or
blank) keeps its message, but each media reference is replaced by a host
marker and the slot is reported with a neutral `fetch_failed` note ("the file
could not be retrieved"); nothing is fetched for it. A unit running without
attachments (any `Off` state, and the legacy path) carries no inline bytes on
for any slot, with or without a fetch reference. The legacy `--bundle` path stores nothing: every
slot gets a `door_unavailable` note and inline bytes are cleared.

## 6. Configuration

| Variable | Default | Purpose |
|---|---|---|
| `GREENTIC_TRUSTED_PROXY_HOPS` | `0` | How many proxies in front of this host append to `X-Forwarded-For`. `0` uses the TCP peer and ignores the header. Behind a load balancer set it (usually `1`), or every client shares the balancer's upload limit (10/min, one at a time for everyone). Unparsable = `0` |
| `GREENTIC_ATTACHMENT_ALLOWED_HOSTS` | empty | Extra credential-less download hosts (section 3) |
| `GREENTIC_PDF_WORKER_SLOTS` | `1` (1..4) | PDF workers at once; also the process-wide text-extraction slots |
| `GREENTIC_PDF_WORKER_MEM_MB` | `320` (64..1024) | Memory limit of one PDF worker |
| `GREENTIC_ARTIFACT_LINKS`, `GREENTIC_ARTIFACT_LINK_TTL_SECS`, `GREENTIC_ARTIFACT_LINK_MAX_INFLIGHT`, `GREENTIC_ARTIFACT_LINK_MAX_INFLIGHT_PER_UNIT`, `GREENTIC_ARTIFACT_LINK_EGRESS_MB_PER_HOUR`, `GREENTIC_ARTIFACT_LINK_EGRESS_MB_PER_LINK_PER_HOUR` | see `docs/outbound-artifacts.md` §6 | Outbound file links (off in code until the WebChat reconnect-token hardening ships) |

## 7. Serving rule (binding for any route that serves artifact bytes)

`/v1/artifacts/...` (signed links, `src/artifacts/serve_link.rs`) is the one
route in this repository that serves artifact bytes; it implements this rule,
see `docs/outbound-artifacts.md`. Any route added later MUST:

- send `Content-Type` = the SNIFFED stored type, never a client- or
  provider-supplied one;
- send `X-Content-Type-Options: nosniff`;
- send `Content-Disposition: attachment` for documents; `inline` is allowed
  only for `image/jpeg`, `image/png`, `image/gif`, `image/webp`;
- never serve SVG or HTML inline (they are not stored in v1; keep it that way);
- send `Cache-Control: private` (plus `no-store` for a signed link);
- authorise the read on the token's tenant, never on possession of an id or of
  a conversation token alone (an id is computable from the bytes).

A file that is both a valid image and something else (a polyglot) is safe ONLY
under this rule.

## 8. Logging

No log line, at any level, prints an envelope, an event, an `HttpIn`/`HttpOut`,
a request body, attachment content or a fetch URL. Log ids, counts and fixed
codes. `artifacts::redaction_ratchet_tests` reads the inbound-path sources and
fails on `{:?}`, `?field` or `serde_json` formatting of those values in a log
call; an unparseable provider envelope is reported by index and error category
only (`ingress_dispatch::envelope_parse_failure`).

## 9. v1 limitations

- The PDF worker is isolated with rlimits, an empty environment, a deadline and
  `PR_SET_PDEATHSIG`, but no seccomp and no Landlock. It is Linux-only: on other
  platforms a PDF is stored with no text.
- WhatsApp, Webex and Teams inbound files wait on host-side verification.
- Slack and Webex files served from other CDN hosts (Slack `files-edge`,
  `files-origin`; Webex regional hosts) are refused as `fetch_failed` until the
  lists are widened from measured provider fixtures.
- The WhatsApp instance number is pack-level; several WhatsApp endpoints on
  different numbers in one unit are not supported.
- A flow node (`component.exec`) cannot create an artifact; only agent tools
  can.

## 10. Release notes (pins)

This branch was built against UNCOMMITTED local `[patch.crates-io]` path
overrides. Nothing below is moved by this branch; each item must land in the
pin-bump commit before release.

Replace (drop the whole `[patch.crates-io]` block in `Cargo.toml` and
re-resolve `Cargo.lock`):

- `greentic-runner-host`, `greentic-aw-runtime`, `greentic-runner-desktop`,
  `runner-core` → the greentic-runner publish carrying the attachments work
  (`RevisionHostOptions::with_artifact_reader`, `with_ext_artifact_port`,
  `HttpArtifactReader`); verified locally at runner `1a7302c2`.
- `greentic-ext-runtime` → the publish carrying `ArtifactPort` /
  `artifact@0.1.0`; verified locally at `bc9d4e9` (1.2.28).

Restore the floors that were relaxed to `>=1.2.0-dev.0` (runner-desktop,
runner-host, aw-runtime normal dependency, aw-runtime dev-dependency) to the
run id of that runner publish.

Add to `[dependencies]` in the same commit (needed by `artifacts::port`;
runner-host does not re-export it):

```toml
[dependencies.greentic-ext-runtime]
version = ">=1.2.0, <1.3.0"
```

with a floor at the ext-runtime publish carrying `ArtifactPort`, and check
`cargo tree -i` shows ONE instance each of runner-host, aw-runtime,
ext-runtime, extension-sdk-contract.

Release order: admin (artifacts door live) → ext-runtime → runner (drops its
own ext-runtime patch) → this crate → providers' WebChat repin in the designer
registry (only after this host is live). Cross-repo work this needs:

- providers: the Teams allow-list narrowed to ONE `*.sharepoint.com` label, in
  step with `PUBLIC_HOSTS` here; the WebChat upload emitting one of the two
  `inline` shapes;
- measured Slack/Webex CDN hosts before widening the credential lists;
- deploy lanes set `GREENTIC_TRUSTED_PROXY_HOPS` (Cloud Run, k8s, ALB);
- greentic-designer: the start pin in `Dockerfile.tools` moves; re-affirm
  `agent_tool_reach::DEPLOYED_RUNTIME_CALLS_A2A`, `RUNTIME_SERVES_TRIGGERS` and
  the playbook verdict there, per its CLAUDE.md;
- greentic-runner: `HttpArtifactReader` builds its client with `no_proxy()`
  since runner `190c1fa3`; the release pinned here must carry it.
