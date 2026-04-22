# Coding Agent Guide

This document is the operational source of truth for coding agents and maintainers working in `greentic-start`.

If you only want a gentle human introduction, read the [README](../README.md) first.

## What This Repo Owns

`greentic-start` owns local lifecycle execution for Greentic bundles.

In practice, that means:

- starting a bundle
- stopping a running bundle
- restarting selected services
- loading runtime config from the bundle
- launching local helper services
- exposing local ingress
- optionally exposing the admin API

It also contains app-flow execution glue around `greentic_runner_desktop::run_pack_with_options(...)`.

For broader ownership boundaries, see [ownership.md](ownership.md).

## The Commands

The `clap` surface is defined in [src/cli_args.rs](/projects/ai/greentic-ng/greentic-start/src/cli_args.rs:8).

Available commands:

- `greentic-start start`
- `greentic-start up`
- `greentic-start stop`
- `greentic-start restart`

Important behavior:

- `up` is an alias for `start`
- if no explicit subcommand is provided, argument normalization inserts `start`
- legacy `demo` prefix is stripped during argument normalization

That behavior lives in [src/cli_args.rs](/projects/ai/greentic-ng/greentic-start/src/cli_args.rs:201) and is wired in [src/lib.rs](/projects/ai/greentic-ng/greentic-start/src/lib.rs:79).

## How `start` Is Used

The usual entrypoint is:

```bash
greentic-start start --bundle /path/to/bundle
```

The runtime path is:

1. parse CLI args
2. normalize legacy/default command forms
3. resolve bundle/config paths
4. initialize logging
5. load runtime demo config
6. apply CLI overrides
7. apply tunnel behavior
8. start services and ingress

The main orchestration lives in [src/lib.rs](/projects/ai/greentic-ng/greentic-start/src/lib.rs:113) and [src/runtime.rs](/projects/ai/greentic-ng/greentic-start/src/runtime.rs:742).

## `start` Options

These are the supported `start` and `restart` flags from [src/cli_args.rs](/projects/ai/greentic-ng/greentic-start/src/cli_args.rs:24).

### Bundle and targeting

- `--bundle <path>`
  Points at the bundle root to run.
- `--config <path>`
  Uses an explicit runtime config path instead of bundle auto-resolution.
- `--tenant <name>`
  Overrides the tenant.
- `--team <name>`
  Overrides the team.

Bundle/config resolution is handled through [src/bundle_config.rs](/projects/ai/greentic-ng/greentic-start/src/bundle_config.rs:20).

### NATS

- `--nats off`
  Do not use NATS.
- `--nats on`
  Enable NATS and spawn the bundled/local runtime-managed instance.
- `--nats external`
  Use NATS without spawning it locally.
- `--nats-url <url>`
  Overrides the NATS URL.
- `--no-nats`
  Hidden legacy flag that conflicts with `--nats`.

The override behavior is implemented in [src/lib.rs](/projects/ai/greentic-ng/greentic-start/src/lib.rs:388).

Practical meaning:

- `off` disables NATS features
- `on` means `greentic-start` may spawn NATS
- `external` means the runtime expects an already-running NATS server

### Tunnels

- `--cloudflared on|off`
  Enables or disables Cloudflare Tunnel.
- `--cloudflared-binary <path>`
  Uses a specific `cloudflared` binary.
- `--ngrok on|off`
  Enables or disables ngrok.
- `--ngrok-binary <path>`
  Uses a specific `ngrok` binary.

Important automatic behavior from [src/lib.rs](/projects/ai/greentic-ng/greentic-start/src/lib.rs:194):

- if tunnel flags were not explicitly set, `.greentic/tunnel.json` may influence tunnel mode
- if no deployer packs are detected, local dev mode may auto-enable `cloudflared`
- if still not explicit, the runtime may prompt for tunnel selection in interactive use
- if `--ngrok on` and `--cloudflared on` are both present, `ngrok` wins unless you intentionally override the combination

### Runner selection

- `--runner-binary <path>`
  Uses a specific runner binary when external runner integration paths need it.

Note:

- app-flow execution in this repo also uses embedded desktop-runner execution via [src/runner_exec.rs](/projects/ai/greentic-ng/greentic-start/src/runner_exec.rs:28)
- do not assume `--runner-binary` changes every execution path

### Restart targeting

- `--restart all`
- `--restart cloudflared`
- `--restart ngrok`
- `--restart nats`
- `--restart gateway`
- `--restart egress`
- `--restart subscriptions`

These values are defined in [src/cli_args.rs](/projects/ai/greentic-ng/greentic-start/src/cli_args.rs:120).

Behavior:

- `restart` with no explicit targets becomes `all`
- targeted restarts affect service restart handling during startup/orchestration

That defaulting is applied in [src/lib.rs](/projects/ai/greentic-ng/greentic-start/src/lib.rs:85).

### Logging and terminal output

- `--log-dir <dir>`
  Writes logs to a specific directory.
- `--verbose`
  Sets higher terminal log detail.
- `--quiet`
  Reduces terminal noise.

Logging initialization happens in [src/lib.rs](/projects/ai/greentic-ng/greentic-start/src/lib.rs:137).

### Admin API

- `--admin`
  Enables the mTLS admin API endpoint.
- `--admin-port <port>`
  Sets the admin port. Default is `8443`.
- `--admin-certs-dir <dir>`
  Points at the cert directory containing `server.crt`, `server.key`, and `ca.crt`.
- `--admin-allowed-clients <cn1,cn2,...>`
  Restricts allowed client certificate common names.

The admin server is started from [src/lib.rs](/projects/ai/greentic-ng/greentic-start/src/lib.rs:337) and implemented in [src/admin_server.rs](/projects/ai/greentic-ng/greentic-start/src/admin_server.rs:77).

## `stop` Options

The `stop` command supports the flags defined in [src/cli_args.rs](/projects/ai/greentic-ng/greentic-start/src/cli_args.rs:64).

- `--bundle <path>`
- `--state-dir <path>`
- `--tenant <name>`
- `--team <name>`

The stop request entrypoint is [src/lib.rs](/projects/ai/greentic-ng/greentic-start/src/lib.rs:93).

Use `stop` when you want to shut down an already-running runtime cleanly.

## Automatic Behaviors Agents Must Remember

### Command normalization

- `greentic-start --bundle /tmp/x` behaves like `greentic-start start --bundle /tmp/x`
- `greentic-start demo start ...` still works because the legacy `demo` prefix is stripped

### GREENTIC environment defaults

At startup, [src/lib.rs](/projects/ai/greentic-ng/greentic-start/src/lib.rs:115) ensures:

- `GREENTIC_PROVIDER_CORE_ONLY=0`
- `GREENTIC_ENV=dev` if it is not already set

Do not accidentally break these unless the contract is intentionally changing.

### Setup-derived tunnel behavior

App startup currently consumes setup-derived tunnel configuration from `.greentic/tunnel.json`, but that does not mean all setup answers are automatically merged into app-flow runtime config.

### Provider setup versus app runtime

Provider setup has a dedicated persisted-config envelope flow:

- write config envelope in [src/provider_config_envelope.rs](/projects/ai/greentic-ng/greentic-start/src/provider_config_envelope.rs:59)
- read and reapply that config in [src/providers.rs](/projects/ai/greentic-ng/greentic-start/src/providers.rs:131)

App-flow execution is different:

- [src/messaging_app.rs](/projects/ai/greentic-ng/greentic-start/src/messaging_app.rs:205) forwards `input`, `tenant`, `team`, and `correlation_id`
- [src/event_router.rs](/projects/ai/greentic-ng/greentic-start/src/event_router.rs:30) forwards event payloads directly
- [src/runner_exec.rs](/projects/ai/greentic-ng/greentic-start/src/runner_exec.rs:100) passes the payload through as `RunOptions.input`

If you are debugging “why did my app node not receive setup config,” do not assume `greentic-start` automatically merges app setup values into `component.exec`.

## App Flow Execution Notes

The embedded app-flow runner path is in [src/runner_exec.rs](/projects/ai/greentic-ng/greentic-start/src/runner_exec.rs:28).

Current important details:

- flow input is written to the run directory as `input.json`
- `flow.log` is initialized under the bundle log directory
- secrets manager injection is passed into `RunOptions.secrets_manager`
- execution runs through `greentic_runner_desktop::run_pack_with_options(...)`

This is the first file to inspect when live bundle execution differs from direct runner behavior.

## Logs and State

Expect runtime data under the bundle:

- `logs/`
- `state/`
- `.greentic/`

Useful logs:

- `logs/operator.log`
- `logs/flow.log`

Useful run artifacts:

- `state/runs/.../input.json`
- `state/runs/.../run.json`
- `state/runs/.../summary.txt`

## Recommended Validation Commands

For this repo:

```bash
cargo check
cargo test
cargo build
```

For one test:

```bash
cargo test -p greentic-start test_name_here
```

For a fuller local pass:

```bash
bash ci/local_check.sh
```

## Documentation Rule For Future Changes

If you change:

- command flags
- startup defaults
- tunnel selection behavior
- restart semantics
- admin API behavior
- app-flow execution wiring

update this document and the human-facing [README](../README.md) together.
