# CI Update-Plan Signing Key

The `publish-update-plans.yml` workflow signs binary-update plans with a
**dedicated CI key** that is distinct from any human operator's key. Both
keys coexist in each environment's trust root, so a compromised CI key can
be revoked without invalidating operator-signed plans and without rotating
the operator key.

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

## Trusting the key in each environment

Trust roots are per-environment and are managed with `op trust-root`, not
with `op env apply`:

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
`--store-url <url> --store-token <token>`.

An environment's `trust-root.json` then looks like:

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

Run it for every environment, then delete the `UPDATER_CI_SIGNING_KEY_PEM`
repo secret. Plans signed by the CI key stop verifying immediately;
operator-signed plans are unaffected, so recovery never requires rotating
the operator key.
