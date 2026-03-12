# greentic-start

`greentic-start` is the lifecycle runner for Greentic demo/app-pack execution.
It exposes lifecycle orchestration as a library (`greentic_start::run_from_env`) and a thin CLI binary.

## Ownership

- `greentic-start` owns lifecycle execution (`start`/`up`/`stop`/`restart`).
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
