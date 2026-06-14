# PR-SECRET-01: Add deployment compatibility harness

## Problem

Runtime/deployer/secrets compatibility is currently validated only after long cloud deploys. This let `greentic-start`, `greentic-deployer`, and the deployed secrets provider contract drift. The webchat failure is the concrete example: deployment output contained secrets, but runtime secret lookup still failed.

Current `greentic-start` already discovers `.gtpack` files under `providers/secrets/{tenant}/{team}`, `providers/secrets/{tenant}`, and `providers/secrets/`, but those packs only select the local runtime backend declared in `assets/secrets_backend.json` (`dev-store` or `env`). There is no deployer-generated secrets-provider binding file yet, so the harness must distinguish today's backend-pack selection from the provider-binding contract proposed in PR-SECRET-02.

## Goal

Add `scripts/test_deployment.sh` to validate a `greentic-start` build against a selected bundle, deployer pack, and secrets provider pack before applying cloud infrastructure.

The script must be useful for AWS/GCP/Azure/local compatibility checks and must default to non-destructive generation/smoke validation.

`scripts/` does not currently exist in this repo, so this PR also establishes that directory as the home for cross-repository smoke/compatibility helpers.

## Proposed CLI

```sh
scripts/test_deployment.sh \
  --bundle <bundle-dir-or-gtbundle> \
  --target <local|aws|gcp|azure> \
  [--deployer-pack <path-to-gtpack>] \
  [--secrets-pack <path-to-gtpack>] \
  [--tenant demo] \
  [--team default] \
  [--environment dev] \
  [--mode generate|local-smoke|apply] \
  [--expect-secrets-provider <provider-id>] \
  [--expect-no-runtime-secret-env]
```

`--mode generate` is the default. Cloud `apply` must require an explicit opt-in flag.

## Behavior

1. Copy the source bundle into a temp directory.
2. Optionally inject the deployer pack into `providers/deployer/`.
3. Optionally inject the secrets provider pack into `providers/secrets/`.
4. Build/normalize the temp bundle with `greentic-bundle build --root`.
5. Run `greentic-deployer <target> generate` with the normalized bundle, selected app pack, selected deployer pack, bundle source, and digest.
6. Validate generated output:
   - deployment config exists
   - secrets provider binding exists when expected
   - the binding uses the PR-SECRET-02 contract, not only the existing `assets/secrets_backend.json` backend selector
   - per-secret runtime env injection is absent when `--expect-no-runtime-secret-env` is set
7. In `local-smoke` mode, start `greentic-start`, wait for readiness, probe health endpoints, and stop cleanly.

## Acceptance Criteria

- The script never mutates the source bundle.
- The default path does not require cloud credentials.
- The script can fail fast when deployer output still relies on runtime secret env injection.
- The script can be used by `greentic-deployer` and `greentic-secrets` PRs as an external compatibility check.
- The harness does not treat the current `providers/secrets/*.gtpack` backend selector as proof that runtime cloud-provider secret lookup is wired.

## Initial Regression Check

This should fail until the secrets-provider binding redesign lands:

```sh
scripts/test_deployment.sh \
  --bundle ../hubspot/greentic-main-website-bundle \
  --target aws \
  --deployer-pack ../hubspot/greentic-main-website-bundle/providers/deployer/aws.gtpack \
  --secrets-pack ../greentic-secrets/dist/packs/aws-sm.gtpack \
  --mode generate \
  --expect-secrets-provider greentic.secrets.aws-sm \
  --expect-no-runtime-secret-env
```

## Out Of Scope

- Changing the runtime secrets implementation.
- Changing deployer Terraform generation.
- Implementing cloud secrets providers.
