# PR-SECRET-02: Use greentic-secrets provider bindings in greentic-start

## Problem

`greentic-start` currently has a two-layer secrets selection path:

- `src/secrets_manager.rs` discovers a `.gtpack` under `providers/secrets/{tenant}/{team}`, `providers/secrets/{tenant}`, `providers/secrets/`, or `GREENTIC_SECRETS_MANAGER_PACK`.
- `src/secrets_backend.rs` then reads a small backend selector from that pack (`assets/secrets_backend.json`, `assets/secrets-backend.json`, `secrets_backend.json`, or `secrets-backend.json`) and only supports `dev-store` or `env`.

So the current code is not just an in-memory enum, but the effective runtime capability is still only dev-store or environment-variable secrets. Env fallback after a backend initialization failure is already gated by `GREENTIC_ALLOW_ENV_SECRETS=1`; however, a selected pack whose backend is explicitly `env` is still accepted directly. Cloud deploys therefore still need environment-variable secret injection unless this PR adds a real provider-binding path.

`greentic-secrets` already provides concrete provider backends and provider packs for:

- `greentic.secrets.aws-sm`
- `greentic.secrets.gcp-sm`
- `greentic.secrets.azure-kv`
- `greentic.secrets.dev`
- `greentic.secrets.k8s`
- `greentic.secrets.vault-kv`

`greentic-start` should not know cloud target details and should not rely on env var names for cloud runtime secrets.

## Goal

Teach `greentic-start` to read a deployer-provided secrets provider binding and resolve runtime secrets through the existing `greentic-secrets` abstraction/provider system.

Runtime code should continue to ask for canonical URIs:

```text
secrets://{environment}/{tenant}/{team}/{provider}/{key}
```

The selected secrets provider is responsible for mapping that URI to AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, local dev store, or another backend.

This should build on the existing runtime call sites:

- `src/secrets_gate.rs::resolve_secrets_manager` is the main selection/instantiation entrypoint.
- `src/runner_host/mod.rs::get_secret` already constructs canonical `secrets://...` URIs through `canonical_secret_uri`.
- Hosted packs receive the selected manager via `SecretsManagerHandle::runtime_manager`.

## Binding Shape

Add support for a deployer-generated config file such as:

```json
{
  "schema_version": "greentic.secrets.binding.v1",
  "provider_id": "greentic.secrets.aws-sm",
  "pack": "providers/secrets/aws-sm.gtpack",
  "config": {
    "region": "eu-north-1",
    "prefix": "greentic"
  }
}
```

The final file path should be stable and documented, for example:

```text
state/config/platform/secrets-provider.json
```

or another bundle/runtime config path agreed with `greentic-deployer`.

The binding is a new contract. It must not be confused with the existing `providers/secrets/*.gtpack` backend-selector file, which only tells `greentic-start` whether to instantiate `SecretsClient` over the dev store or `EnvSecretsManager`.

## Implementation Tasks

1. Add a `SecretsProviderBinding` parser and validator.
2. Extend `SecretsBackendKind` or replace the backend-kind layer so it can represent a binding-backed provider, not only `DevStore` and `Env`.
3. Add a `SecretsManager` adapter backed by a selected `greentic-secrets` provider binding.
4. Resolve provider config without hard-coding AWS/GCP/Azure in `greentic-start`.
5. Keep dev-store as local fallback for existing local development when no binding or pack is present.
6. Keep `GREENTIC_ALLOW_ENV_SECRETS=1` as the only fallback from a failing backend initialization to env.
7. Decide whether explicit `backend: "env"` packs remain supported for local/compatibility use, and ensure cloud mode rejects them unless explicitly allowed.
8. Log which provider binding was selected without logging secret values.

## Tests

Add failing tests first:

- A mock/fake provider binding can resolve `secrets://dev/demo/_/messaging-webchat-gui/jwt_signing_key`.
- The provider id can be arbitrary; `greentic-start` must not switch on `aws`, `gcp`, or `azure`.
- Cloud mode without a provider binding fails with a clear message.
- Env fallback from backend initialization failure is not selected unless `GREENTIC_ALLOW_ENV_SECRETS=1`.
- Explicit `backend: "env"` pack behavior is covered by a test documenting whether cloud mode rejects it or compatibility mode allows it.
- Existing local dev-store behavior still works.
- Existing scoped pack discovery remains intact: tenant/team pack wins over tenant pack, which wins over default pack, and `GREENTIC_SECRETS_MANAGER_PACK` still wins as an override unless the binding contract intentionally supersedes it.

## Acceptance Criteria

- `greentic-start` can use a deployer-selected `greentic-secrets` provider binding.
- `get_secret(provider, key, ctx)` continues to use canonical `secrets://...` URIs.
- No cloud-specific backend enum is introduced in `greentic-start`.
- `scripts/test_deployment.sh` can verify the binding in generated deployment output.
- Existing dev-store tests and scoped secrets-pack discovery tests continue to pass.

## Dependencies

- `greentic-secrets` provider packs must expose the provider metadata/config needed by runtime.
- `greentic-deployer` must generate the binding and provision cloud permissions.
