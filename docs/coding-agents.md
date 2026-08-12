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
- `--env <id>`
  Environment id whose persisted state the bundle-less boot serves.
  Precedence: flag > `$GREENTIC_ENV` > `local`. The resolved value is
  propagated into `$GREENTIC_ENV` for the process so downstream resolution
  (runner-host paths, secret stores, startup contract) agrees with the
  boot. Ignored (with a warning) on the legacy `--bundle`/`--config` path,
  which has no environment concept.
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

Tunnels on the bundle-less (env-serving) boot, from `src/env_tunnel.rs`:

- `--cloudflared on` / `--ngrok on` also work without `--bundle`: the tunnel
  is spawned against the bound revision-serve port after the listener is up,
  and its URL becomes the highest-precedence public base URL
  (tunnel > env-store `public_base_url` > `PUBLIC_BASE_URL` env var) for
  provider webhook auto-registration, including re-registration on config
  reloads
- there is no auto-enable and no interactive prompt on this path — tunnels
  are off unless a flag asks for one, and a tunnel that fails to start fails
  the boot (explicit opt-in, never a silent local-only fallback)
- tunnel children are tracked under
  `<env_dir>/state/pids/env.<env_id>/<service>.pid` and deliberately survive
  Ctrl+C so a quick restart reuses the same URL; `greentic-start stop` tears
  them down

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

### Updates

- `--no-updates`
  Opts this process out of the environment's update channel: no poll loop runs and
  `/v1/updates/notify` is not reserved (the path falls through to deployment
  routing). It is a host-local kill switch, not a policy knob — the env's
  `update-channel.json` (`enabled`, `on_update`) is left untouched, so a restart
  without the flag resumes whatever the operator declared.

Without the flag the runtime always runs the poll loop. The loop re-reads
`update-channel.json` every cycle and no-ops while the channel is absent, disabled,
or endpoint-less, so an env that subscribes *after* boot starts polling without a
restart. Deny-by-default is unchanged: an env with no `update-channel.json` never
fetches anything, and a notification to a disabled channel is ignored.

`on_update: apply` (deploy-spec 0.2.2) makes a verified, staged plan converge the
environment in place — the apply rewrites `runtime-config.json`, which this process
already watches, so traffic moves with no restart. `stage` (the default) leaves the
content on disk for a human to apply.

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

## WebChat WebSocket Notifier

The WebChat DirectLine WebSocket endpoint (`/v3/directline/conversations/{id}/stream`)
delivers activities to connected clients through a notifier. Two backends are
supported, selected via the optional `webchat.notifier` section in
`greentic.yaml`:

```yaml
webchat:
  notifier:
    backend: redis    # "memory" (default) | "redis"
    url: redis://localhost:6379          # optional override; defaults to state-redis URL
    channel: greentic:webchat:notify     # optional override
    capacity: 64                         # optional; see note below
```

**Memory** — process-local broadcast. No external dependency. Suitable for
single-replica deployments and local development. This is the default when
the `webchat` section is absent.

**Redis** — pub/sub backplane that fans activities out across operator
replicas. URL is auto-detected from the `state-redis` provider's
`ConfigEnvelope` (run `gtc setup --provider state-redis` first to configure
the shared Redis URL). An explicit `url` field overrides auto-detect.

Field notes:

- `url` — Redis connection string. Examples: `redis://localhost:6379` (no auth),
  `rediss://user:pass@host:6380/0` (TLS + auth + database 0). Defaults to the
  `state-redis` provider's configured URL if not specified.
- `channel` — Redis pub/sub channel name. Defaults to `greentic:webchat:notify`.
- `capacity` — Number of buffered events per subscriber. Older events are dropped
  on overflow. Defaults to 64. Lower values reduce memory under high load; higher
  values allow brief Redis outages to recover without dropping messages.

Failure modes:

- Redis configured but unreachable at boot → `gtc start` exits with a clear error.
- Redis disconnects after boot → same-replica sessions keep working; cross-replica
  fan-out resumes on reconnect (exponential backoff up to 5 seconds).
- `state-redis` not configured + `backend: redis` selected → boot error pointing
  at the `gtc setup --provider state-redis` command.

## `stop` Options

The `stop` command supports the flags defined in [src/cli_args.rs](/projects/ai/greentic-ng/greentic-start/src/cli_args.rs:64).

- `--bundle <path>`
- `--env <id>`
- `--state-dir <path>`
- `--tenant <name>`
- `--team <name>`

The stop request entrypoint is [src/lib.rs](/projects/ai/greentic-ng/greentic-start/src/lib.rs:93).

Use `stop` when you want to shut down an already-running runtime cleanly.

With no `--bundle` / `--state-dir` and no legacy `./state` directory in the
CWD, `stop` targets the bundle-less env runtime instead: it writes a
stop-request file under `<env_dir>/state/runtime/env.<env_id>/control/` (a
serving `greentic-start` polls it every 250ms and exits cleanly) and stops
env-rooted tunnel children via their pidfiles. It does NOT pkill arbitrary
`cloudflared`/`ngrok` processes on this path — a hand-started tunnel is left
alone, unlike the legacy bundle stop.

`--env <id>` picks which environment's runtime to stop (flag >
`$GREENTIC_ENV` > `local`). An explicit `--env` naming an environment with
no store directory is an error, not a fall-through to the legacy path; on
the legacy `--bundle`/`--state-dir` path the flag is ignored with a warning.

## Automatic Behaviors Agents Must Remember

### Command normalization

- `greentic-start --bundle /tmp/x` behaves like `greentic-start start --bundle /tmp/x`
- `greentic-start demo start ...` still works because the legacy `demo` prefix is stripped

### GREENTIC environment defaults

At startup, [src/lib.rs](/projects/ai/greentic-ng/greentic-start/src/lib.rs:115) ensures:

- `GREENTIC_PROVIDER_CORE_ONLY=0`
- `GREENTIC_ENV=dev` if it is not already set

Do not accidentally break these unless the contract is intentionally changing.

### DirectLine session-token renewal

The HTTP ingress fronts the webchat provider's `/v3/directline/...` endpoints and
keeps an in-memory sliding window of active conversations: on every accepted
`POST /v3/directline/conversations/<id>/activities` it extends the conversation's
lifetime, re-mints a fresh, correctly-signed bearer (same `conv`/`ctx`), swaps it
into the upstream `Authorization` header, and returns it to the client as
`_directline.renewed_token` — so a long-running chat never hits the 30-minute
`401 invalid token: Expired`. Idle conversations still lapse after the TTL.
`POST /v3/directline/tokens/refresh` is served locally (the WASM provider 404s
it) and returns a full-fresh-TTL token with the same `conversationId`. Auth
failures on these endpoints carry a machine-readable `code`
(`TokenExpired` / `InvalidToken` / `WrongConversation`) plus a `Link` header to
`/tokens/refresh` on the `401`s.

- Base TTL: `GREENTIC_DIRECTLINE_TOKEN_TTL_SECS` (seconds, clamped `[60, 604800]`,
  default `1800`). The activity-driven renewal is the actual fix; this env var is
  only the base-lifetime knob.
- Implementation: [src/http_ingress/directline_session.rs](/projects/ai/greentic-ng/greentic-start/src/http_ingress/directline_session.rs)
  and the `directline_session_preflight` / `apply_directline_forward_plan` hooks
  in [src/http_ingress/mod.rs](/projects/ai/greentic-ng/greentic-start/src/http_ingress/mod.rs).
  Background: [docs/directline-token-renewal.md](/projects/ai/greentic-ng/greentic-start/docs/directline-token-renewal.md).
- WebSocket `/stream` keepalive (re-mint the pump's internal token, `touch` the
  window while connected) is not wired yet — follow-up.

### Inbound provider-webhook authentication (revision path)

The revision-serve path (`greentic start --env`, i.e. `gtc op` environments and
every cloud deploy) runs two gates on a pack-declared provider webhook before
the body is trusted, both inside `dispatch_provider_route`:

- `src/provider_auth.rs` — Telegram. Constant-time compares
  `x-telegram-bot-api-secret-token` against the endpoint's `webhook_secret_ref`.
  Endpoints provisioned before that ref existed are `Skipped` (back-compat).
- `src/provider_webhook_verify.rs` — Slack. Verifies `X-Slack-Signature` by
  invoking the pack's own `messaging.provider_ingress.v1` component
  (`messaging-ingress-slack`), the same component the legacy `http_ingress`
  server dispatches through. This gate exists because the revision path calls
  the provider's `ingest_http` op directly, and `messaging-provider-slack`'s
  `ingest_http` verifies nothing — without the gate a Slack webhook on this path
  was unauthenticated.

Two consequences to remember:

- **It fails closed.** A Slack deployment with no `SLACK_SIGNING_SECRET`
  configured is refused (`401`/`503`) rather than served. The refusal is logged
  with the secret name. Configure the secret — do not weaken the gate.
- **Do not assume a provider component authenticates anything on this path.**
  It does not run the pack's ingress extension. Anything a provider would have
  checked on the legacy path must be checked explicitly here.

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
