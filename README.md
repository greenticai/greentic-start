# greentic-start

`greentic-start` is the lifecycle runner for Greentic demo/app-pack execution.
It exposes lifecycle orchestration as a library (`greentic_start::run_from_env`) and a thin CLI binary.

## Ownership

- `greentic-start` owns lifecycle execution (`start`/`up`/`stop`/`restart`).
- `greentic-start` also owns the runtime admin lifecycle surface when lifecycle control is exposed over mTLS.
- `greentic-operator` (including Wizard) owns UX and planning, then delegates lifecycle execution to `greentic-start`.
- Details: `docs/ownership.md`.

## CLI Surface

Primary commands:

- `greentic-start start`
- `greentic-start restart`
- `greentic-start stop`

Primary runtime inputs:

- `--config <path>` to point at the demo config
- `--tenant <name>`
- `--team <name>`
- `--nats`, `--cloudflared`, `--ngrok`
- `--log-dir`, `--verbose`, `--quiet`

## Startup Contract

`greentic-start` performs startup-time launch gating for bundles that declare
`greentic.static-routes.v1`.

- Bundles with no static routes behave as before.
- Bundles with static routes fail before service boot if launch mode cannot
  expose public HTTP, cannot support hosted assets, or cannot resolve
  `PUBLIC_BASE_URL`.
- Resolved startup values are passed forward through child-process env vars and
  persisted runtime metadata (`startup_contract.json`).

For admin mTLS, `greentic-start` also logs which cert source was selected at
startup:

- `explicit_path`
- `bundle_local`
- `env_materialized`
- `bundle_local_fallback`

For production-oriented cloud deploys, deployers may also pass:

- `GREENTIC_ADMIN_CA_SECRET_REF`
- `GREENTIC_ADMIN_SERVER_CERT_SECRET_REF`
- `GREENTIC_ADMIN_SERVER_KEY_SECRET_REF`

These are diagnostics/trace variables. Runtime still boots from the PEM env
payloads, not from raw secret-manager APIs directly.

Admin lifecycle semantics:

- `POST /admin/v1/stop` is implemented through a runtime stop-request file that
  the foreground `greentic-start` loop observes and honors
- `GET /admin/v1/status` and `GET /admin/v1/list` report `stopping` while that
  stop request is pending
- `POST /admin/v1/start` is intentionally not a remote process launcher through
  the embedded admin endpoint; if the runtime is already active it returns an
  idempotent success shape, and if the runtime is inactive it must be started
  by an external `greentic-start` launcher or cloud supervisor

## Extension pack roles

- Core platform packs: runtime-critical packs such as messaging, events, oauth, telemetry, secrets, and state integrations.
- Optional extension packs: packs exposing hooks, contracts, capabilities, subscriptions, or other feature extensions for app packs/components.

`greentic-start` now classifies these roles explicitly so lifecycle boot can reason about platform services separately from optional extensions.

## i18n

- Source catalog: `i18n/en.json`.
- Translator helper: `tools/i18n.sh` (defaults to `LANGS=all`, `BATCH_SIZE=200`).

## CI and Releases

Local validation:

```bash
bash ci/local_check.sh
```

Release flow:

1. Bump `version` in `Cargo.toml`.
2. Create and push tag `vX.Y.Z` (must match `Cargo.toml`).
3. Push tag to trigger `.github/workflows/publish.yml`.

Required secrets:

- `CARGO_REGISTRY_TOKEN` for crates.io publish.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and supported version policy.
