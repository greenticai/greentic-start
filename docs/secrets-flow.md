# Secrets flow — greentic-start (the READ side)

Guidance for Claude Code (and humans) on how the runtime resolves secrets, and
the cross-system contract it shares with **greentic-setup**, which WRITES them.
Read this together with greentic-setup's mirror doc: `docs/secrets-flow.md` in
that repo (the WRITE side). The two MUST stay in agreement — a mismatch makes a
setup-provisioned secret silently go "missing" at runtime, which has been a
recurring bug.

## The one-line contract

> greentic-setup writes a secret at a canonical URI into the **env store**;
> greentic-start reads the **same URI** from the **same file**. Same string,
> same path, both sides.

Both halves are pinned by DO-NOT-CHANGE guard tests (see below). Do not edit
either side's derivation without a new secrets plan verified end-to-end.

## Secret URI grammar

```
secrets://{env}/{tenant}/{team}/{provider}/{key}
```

| Segment    | Rule                                                             |
|------------|-----------------------------------------------------------------|
| `env`      | environment id, e.g. `local`, `dev`, `prod`                     |
| `tenant`   | served tenant (see the gtunnel alias note below)                |
| `team`     | team, or `_` when the team is `default`/absent                  |
| `provider` | pack provider slug, **hyphens → underscores** (`messaging-webex` → `messaging_webex`) |
| `key`      | secret key, e.g. `webex_bot_token`                              |

Canonical example:
`secrets://local/demo/_/messaging_webex/webex_bot_token`

## Where secrets live: env store vs bundle-local

There are two on-disk DevStore files, and picking the wrong one is the classic
seam:

- **Env store** — `‹LocalFsStore root›/‹env›/.greentic/dev/.dev.secrets.env`.
  This is the file the **runtime reads** at serve time (`find_existing` selects
  it). greentic-setup MUST write here.
- **Bundle-local store** — `‹bundle_root›/.greentic/dev/.dev.secrets.env`.
  Legacy/`$GREENTIC_ENV`-gated. If setup writes here while the runtime reads the
  env store, the secret is "missing." (This was the webex_bot_token bug: setup's
  `persist_all_config_as_secrets` opened the bundle-local store while the runtime
  read the env store — fixed by routing setup writes through
  `open_dev_store_for_env`.)

## Read path (this repo)

`secrets_gate.rs::LoggingSecretsManager::read` resolves a requested URI through a
candidate chain, logging each step **redacted** (URI + `value_len`, never the
value):

1. **As requested** — the raw URI the WASM provider asked for. External
   runner-hosts request the raw pack-stem provider (`messaging-webex`).
2. **Provider-canonicalized** — `canonicalize_provider_segment` normalizes the
   provider slug (`messaging-webex` → `messaging_webex`). This is the step that
   lands on the exact URI greentic-setup wrote.
3. **Re-tenanted** — for the gtunnel served-tenant alias (`{base}-{id}`, e.g.
   `default-ba564`), also try the **base tenant** (`default`). This is why a
   webex secret provisioned under `default` still resolves when the tunnel serves
   `default-ba564`.

On a full miss it logs a single redacted **MISS** line (store path + candidate
count) — the anchor to compare against setup's WRITE log when diagnosing.

## The gtunnel tenant alias and secrets

When the gtunnel is active, `lib.rs` rewrites each bundle's served tenant to
`{base}-{suffix}` (see `gtunnel::managed_tenant_alias`). That changes the
`{tenant}` segment of every read URI. The re-tenant fallback (step 3 above) keeps
base-tenant-provisioned secrets resolvable, but the durable fix is for setup to
provision under the tenant the runtime actually serves. If you touch the alias,
re-run the messaging round-trip — it exercises the read fallback.

## The guard tests (DO NOT CHANGE)

- **This repo:** `secrets_gate.rs::webex_secret_read_uri_contract_do_not_change`
  — asserts `canonicalize_provider_segment(raw) == the exact URI setup writes`.
- **greentic-setup:** `lib.rs::webex_secret_uri_contract_do_not_change`
  — asserts `canonical_secret_uri(...) == the same golden string`.

Both hard-code the golden string `secrets://local/demo/_/messaging_webex/webex_bot_token`.
They are intentionally brittle: if either derivation drifts, the build breaks
before a user hits a silent "missing secret." Changing the scheme requires a new
plan verified on **both binaries** (setup + start), **both backends** (local
dev-store + cloud vault), and public.

## Secrets hydrated from the admin (`secrets_door`)

A unit whose staged ingress document (`secrets://<env>/<tenant>/_/ingress/<bundle>`)
carries `"secrets_door": true` keeps its credentials in the admin rather than in
the shipped dev store (Cloud Run caps that store at 64 KiB). At revision
activation, after the document is read, start calls the admin door once and
writes the answer into the dev store it already serves from:

- `POST <metering.endpoint with worker-usage → secrets>/read-all`, bearer = the
  unit's metering token, body `{}`, optional `If-None-Match`.
- `200 {"secrets":[{"path":"<team>/<category>/<name>","value","encoding":"utf8|base64"}],"etag"}`;
  each entry lands at `secrets://default/<tenant>/<path>` — env pinned to
  `default`, path verbatim, i.e. the address `read_secret_for_unit` walks.
- A flagged unit **fails closed**: an unreachable, unauthorised (401/403) or
  absent (404) door, or a flag with no usable `metering` block, fails the
  activation (cold start and reload) after 4 attempts with 0.5 s doubling
  backoff. Absent or `false` flag: no call, no change.
- Retries cover only transient failures (transport errors, 5xx, 408, 429).
  401, 403, 404, any other 4xx and an unusable body fail at once. 403's message
  says the token probably lacks the `secrets` purpose (PATCH purposes). One
  60 s retry budget is shared by all units of an activation; `Retry-After`
  (seconds) is honoured on 429 within it.
- A flagged unit whose door answers 200 with an EMPTY set fails (no ETag is
  recorded). An ingress document the store cannot read (an error other than
  not-found) fails the activation, since the flag is then unknowable; a document
  that is absent or unparseable counts as "no flag" (the parser warns).
- On a reload, if an ETag is already known and the door is transiently down, the
  unit keeps the secrets already hydrated (warning logged). A cold start does
  not get this, and neither does a 401/403/404.
- Values are never logged or put in an error; a malformed entry writes nothing.
- A rotation takes effect on the next activation; a `304` on a reload skips the
  write. Paths written on one hydration but absent from the next answer are
  deleted from the store.
- **Only runner-scoped categories belong in the door.** It writes at env
  `default`, where the runner reads `mcp`, `a2a`, `llm`, `knowledge` and
  `sorla`. Pack-scoped extension secrets and the generated webchat
  `jwt_signing_key` are read at the revision's env (`local`) and must stay in
  the shipped dev store; any other category is written but warned about, since
  nothing will read it.

Code: `src/secrets_door.rs`. A start predating the field ignores it (the
ingress parser does not reject unknown fields), so the designer must not stop
writing a unit's secrets to the store until the unit's runtime is known to
hydrate.

## Diagnosing a "missing secret"

1. Grep the runtime log for `WASM secrets read` — the requested URI, each
   fallback tried, and either `resolved (fallback) … value_len=N` or the `MISS`
   summary with the store path.
2. Compare that store path against setup's WRITE log (`setup secret WRITE …
   store_path=…`). If they differ, it's the env-store-vs-bundle-local seam.
3. Confirm the `{provider}` segment matches (hyphen vs underscore) and the
   `{tenant}` matches (alias vs base).

See also: greentic-setup `docs/secrets-flow.md` (the WRITE side).
