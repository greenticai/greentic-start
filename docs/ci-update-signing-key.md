# CI Update-Plan Signing Key

The `publish-update-plans.yml` workflow signs binary-update plans with an
Ed25519 key stored in `UPDATER_CI_SIGNING_KEY_PEM`. In the current
deployment, **that key is the fleet `did:web` root key** — the same key
published at `did:web:trust.greentic.cloud#root-1` (key_id
`34b690258f1ae48d4a4be0bdbffb7fa3`). The CI key and the fleet root key
are therefore the same key, not two. Individual environments may still
hold operator keys of their own, but an environment anchored on the fleet
channel holds only this one — see the
[kill-switch caveat](#revoking-the-ci-key-kill-switch) for what that means
during an incident.

The recommended shape is a **dedicated CI key** distinct from any
operator's key. With both in each environment's trust root, a compromised
CI key can be revoked without invalidating operator-signed plans. Adopting
it requires minting a second key ([Minting the key](#minting-the-key)),
publishing it as an additional assertion method in the `did:web` document,
letting it propagate, and switching `UPDATER_CI_SIGNING_KEY_PEM` to the
new private key — the publish-then-propagate-then-remove ordering
documented under [Revoking](#revoking-the-ci-key-kill-switch).

Environments learn that key through a `did:web` document. Publishing the
public key once, at a stable URL, is what lets a fresh environment verify
plans without an operator pasting a PEM into it — see
[Trusting the key](#trusting-the-key-in-each-environment) for the three
paths, ordered cheapest first.

## Minting the key

```bash
# Private key (PKCS#8 Ed25519) — this is the CI secret
openssl genpkey -algorithm Ed25519 -out ci-signing-key.pem

# Public key (SPKI PEM) — this is what goes into trust roots
openssl pkey -in ci-signing-key.pem -pubout -out ci-signing-key.pub.pem

# key_id = first 16 bytes of sha256(raw 32-byte public key), lowercase hex
openssl pkey -pubin -in ci-signing-key.pub.pem -outform DER \
  | tail -c 32 | sha256sum | cut -c1-32
```

The last command prints the `key_id` (32 hex chars). Every trust-root entry
is a `(key_id, public_key_pem)` pair, and the `key_id` must be derived this
way — a mismatch makes DSSE verification fail with "unknown key".

`greentic-trust` derives the same id from the published document, so
verifiers never take a `key_id` on faith; they recompute it. That equality
is the whole integration, and it is why the pipeline above must not be
approximated.

## Publishing the key as a `did:web` document

Ed25519 only — the resolver rejects other curves. The document lists the
key as a JWK `x` value (raw 32 bytes, base64url, unpadded):

```bash
JWK_X=$(openssl pkey -pubin -in ci-signing-key.pub.pem -outform DER \
  | tail -c 32 | basenc --base64url | tr -d '=')

mkdir -p public/.well-known
greentic-trust build-doc \
  --did did:web:trust.example.com \
  --root-public "$JWK_X" > public/.well-known/did.json

# Before serving it, and again after
greentic-trust verify-doc --did did:web:trust.example.com \
  --expected-root "$JWK_X" --file public/.well-known/did.json
```

Serve `public/` at `https://trust.example.com/.well-known/did.json` as
static content. Two hosting constraints, both hard:

- **No redirects.** The resolver is `https_only` and refuses every 3xx,
  so an apex-to-`www` or trailing-slash redirect breaks resolution
  outright rather than degrading.
- **Publish as few keys as possible.** Every assertion key in the document
  becomes a trusted plan signer in every environment that anchors on it,
  and trusting a DID is add-only (below), so a rotated-out key does not
  leave an environment on its own.

Greentic's fleet key is published this way at
`did:web:trust.greentic.cloud`; you only need your own document if you run
your own plan server.

## Trusting the key in each environment

### 1. The fleet channel — nothing to type

An environment subscribed to the default plan endpoint anchors on
Greentic's `did:web` root automatically. The whole configuration is:

```json
{
  "schema": "greentic.env-manifest.v1",
  "environment": { "id": "local" },
  "trust_root": "bootstrap",
  "updates": {}
}
```

`greentic-deployer op env apply --answers <manifest>` then plans, before it
subscribes anything:

```
plan (4 step(s)):
  ensure-environment     local     no-op   exists (public_base_url unchanged)
  bootstrap-trust-root   local     create  trust operator key fbe2df74
  trust-did              local     create  trust 34b690258f1ae48d4a4be0bdbffb7fa3 from did:web:trust.greentic.cloud
  configure-updates      local     create  enabled, on-update stage (default) → https://updates.greentic.cloud/v1/environments/_/plan
```

Resolution happens at plan time, so `--dry-run` names the exact key ids it
would trust — in full, never abbreviated — and a document that fails to
resolve aborts before any step mutates the environment.

Declaring the `updates` block at all is the opt-in: a bare install with no
`updates` block resolves nothing, trusts nothing, and polls nothing.

### 2. Your own signer — name the DID

The implicit anchor applies **only** to an enabled subscription to the
default endpoint. Point `plan_endpoint` at your own plan server and no DID
is assumed; say which one you trust:

```json
"updates": {
  "plan_endpoint": "https://updates.example.com/v1/environments/prod/plan",
  "trust_did": "did:web:trust.example.com"
}
```

`trust_did` has three states, and absent is not the same as `null`:

| `updates` block | anchors on |
|---|---|
| `{}` | the fleet DID |
| `{"trust_did": null}` | nothing — explicit opt-out |
| `{"trust_did": "did:web:…"}` | that DID, whatever the endpoint is |
| `{"plan_endpoint": "https://…"}` (custom) | nothing — no implicit trust |
| `{"enabled": false}` | nothing |

Omitting the field means "this manifest predates the feature", never "I
chose the fleet root" — which is why a manifest pointed at your own signer
never silently picks up Greentic's key.

For an environment that already exists, the same thing without a manifest:

```bash
greentic-deployer op trust-root add-did <env-id> --did did:web:trust.example.com
```

```json
{"noun":"trust-root","op":"add-did","result":{
  "did":"did:web:trust.greentic.cloud","environment_id":"local",
  "key_ids":["34b690258f1ae48d4a4be0bdbffb7fa3"],"trusted_key_count":1}}
```

Both paths are **add-only and idempotent**: they never remove a key, so a
hijacked or spoofed document cannot strip the local operator key. The flip
side is that rotation is not automatic — see
[Revoking](#revoking-the-ci-key-kill-switch).

### 3. No document — paste the key

Still supported, and the only option for a key with no `did:web` document:

```bash
# Add the CI key alongside the operator key (idempotent, additive)
greentic-deployer op trust-root add <env-id> \
  --key-id <ci-key-id> \
  --public-key-file ci-signing-key.pub.pem

# Confirm BOTH the operator key and the CI key are present
greentic-deployer op trust-root list <env-id>
```

Repeat for every environment subscribed to the plan server (the workflow
publishes with `--all-envs`, so any env missing the CI key will reject the
plan at verification time). For a remote operator store, add
`--store-url <url> --store-token <token>`. `add-did` is local-only; against
a remote store it refuses rather than decomposing into anonymous `add`
calls that would lose the DID from the audit trail.

An environment's `trust-root.json` then looks like this, whichever path put
the keys there — a DID-sourced key is stored exactly like a hand-added one:

```json
{
  "schema": "greentic.trust-root.v1",
  "keys": [
    {
      "key_id": "<operator-key-id>",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
    },
    {
      "key_id": "<ci-key-id>",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
    }
  ]
}
```

## Repo configuration

| Name | Type | Purpose |
|------|------|---------|
| `UPDATER_CI_SIGNING_KEY_PEM` | Secret | The **private** key PEM from step 1 |
| `PLAN_UPLOAD_TOKEN` | Secret | Plan-server upload credential (`GREENTIC_PLAN_UPLOAD_TOKEN`) |
| `PLAN_SERVER_URL` | Variable | Base URL of the plan server |
| `UPDATER_TRUST_ROOT_JSON` | Variable | A `trust-root.json` containing the CI key's **public** entry — the signing side verifies its own plan against it, so a CI runner needs no local env store |

`PLAN_SERVER_URL` and `UPDATER_TRUST_ROOT_JSON` are repo *variables*, not
secrets: one is a URL, the other holds public keys only.

The workflow runs on `workflow_dispatch` only — cutting a release tag does
not publish plans. Someone dispatches it with the version once the release
is out. Until `PLAN_SERVER_URL` and `UPDATER_CI_SIGNING_KEY_PEM` both
exist, a dispatch fails loudly with "not configured" — an explicit request
to publish should never silently do nothing.

The workflow writes the private key to `$RUNNER_TEMP` with mode `600`,
masks it in the log, and removes it in an `if: always()` cleanup step.

## Revoking the CI key (kill switch)

```bash
greentic-deployer op trust-root remove <env-id> --key-id <ci-key-id>
```

> **Stop — check your key layout first.** The CI workflow currently
> signs with the fleet `did:web` root key (key_id
> `34b690258f1ae48d4a4be0bdbffb7fa3`). A fleet-anchored environment —
> one configured via
> [path 1](#1-the-fleet-channel--nothing-to-type) — holds that key as
> its **only** trust anchor. Removing it does not fall back to an
> operator key; it **empties the trust root**, and the environment can
> then verify nothing — no CI plan, no operator plan. The procedure
> below is safe only once a dedicated CI key is in use alongside a
> separate operator key.

Run it for every environment, then delete the `UPDATER_CI_SIGNING_KEY_PEM`
repo secret. Plans signed by the CI key stop verifying immediately. In
environments that hold a separate operator key (configured via
[path 2](#2-your-own-signer--name-the-did) or
[path 3](#3-no-document--paste-the-key) with an additional key),
operator-signed plans are unaffected.

**Recovery from an emptied trust root.** If `remove` was run against a
fleet-anchored environment before a dedicated CI key was adopted, the
environment's trust root is empty and no plans will verify. To recover,
re-add a key:

```bash
# Re-anchor on the fleet DID (restores the root key)
greentic-deployer op trust-root add-did <env-id> \
  --did did:web:trust.greentic.cloud

# — or add a key directly —
greentic-deployer op trust-root add <env-id> \
  --key-id <key-id> \
  --public-key-file <key>.pub.pem
```

This must be done per environment; there is no fleet-wide undo.

Dropping the key from the `did:web` document is **not** a revocation.
Trusting a DID is add-only, so environments that already resolved it keep
the key until an explicit `remove` runs against each one; removing it from
the document only stops *new* environments from picking it up. Publish the
replacement key, let it propagate, then `remove` the old one — in that
order, or in-flight plans stop verifying.

## Requirements

| Feature | Needs |
|---|---|
| `op trust-root add-did` | `greentic-deployer` ≥ 1.1.23 |
| `updates.trust_did` / the implicit fleet anchor | `greentic-deployer` ≥ 1.1.24 |
| `build-doc` / `verify-doc` | `greentic-trust` ≥ 0.2 (`--features cli`) |
