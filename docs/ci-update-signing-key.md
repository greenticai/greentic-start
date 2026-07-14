# CI Update-Plan Signing Key

The `publish-update-plans.yml` workflow signs binary-update plans with a
**dedicated CI key** that is distinct from any human operator's key. Both
keys coexist in each environment's trust root, so a compromised CI key
can be revoked without invalidating operator-signed plans.

## Minting a new key

```bash
# Generate a PKCS#8 Ed25519 private key
openssl genpkey -algorithm Ed25519 -out ci-signing-key.pem

# Extract the public key (DER, base64)
openssl pkey -in ci-signing-key.pem -pubout -outform DER \
  | tail -c 32 | xxd -p -c 64
```

The 32-byte hex string is the raw public key used in trust roots.

## Adding the public key to environment trust roots

Each environment's `trust-root.json` lists accepted signers. Add the CI
key's public key as an additional entry alongside the existing operator
key:

```json
{
  "schema": "greentic.trust-root.v1",
  "signers": [
    {
      "name": "operator",
      "algorithm": "Ed25519",
      "public_key_hex": "<operator-key-hex>"
    },
    {
      "name": "ci-release",
      "algorithm": "Ed25519",
      "public_key_hex": "<ci-key-hex>"
    }
  ]
}
```

Then apply the updated trust root:

```bash
greentic-deployer op env apply --trust-root trust-root.json <env-id>
```

## Storing the private key in CI

Add the PEM contents as the repo secret `UPDATER_CI_SIGNING_KEY_PEM` in
GitHub Settings > Secrets and Variables > Actions.

The workflow writes it to a temporary file with `chmod 600`, masks its
value in logs, and deletes the file in an `if: always()` cleanup step.

## Revoking the CI key (kill switch)

Remove the `ci-release` entry from every environment's `trust-root.json`
and re-apply. Existing plans signed by the CI key will no longer verify,
and the runtime will refuse to apply them. Plans signed by the operator
key are unaffected.

To prevent further publishing, also delete or rotate the
`UPDATER_CI_SIGNING_KEY_PEM` repo secret.

## Required repo configuration

| Name | Type | Purpose |
|------|------|---------|
| `UPDATER_CI_SIGNING_KEY_PEM` | Secret | Ed25519 private key PEM |
| `PLAN_UPLOAD_TOKEN` | Secret | Plan-server upload credential |
| `PLAN_SERVER_URL` | Variable | Base URL of the plan server |
| `UPDATER_TRUST_ROOT_JSON` | Variable | trust-root.json content (public keys only) |
