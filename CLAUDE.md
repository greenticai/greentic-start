# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rust lifecycle runner for the Greentic platform. Orchestrates start/restart/stop of the local demo runtime, including an embedded HTTP ingress server (Hyper), WASM component execution (via `greentic-runner-host`), static file serving from `.gtpack` archives with bundle overlay, provider setup, secrets management, tunnel integration (Cloudflare/ngrok), and an optional mTLS admin API.

- **Edition:** Rust 2024 | **MSRV:** 1.91
- **Package version:** defined in root `Cargo.toml` (currently 0.4.x)
- **Integrated as** `gtc start` via the main `greentic/greentic` CLI binary

## Build, Test, and Lint Commands

```bash
# Full local CI
./ci/local_check.sh

# Build
cargo build

# Test
cargo test

# Format and lint
cargo fmt --check
cargo clippy -- -D warnings
```

## CLI Subcommands

The binary is `greentic-start` (also `gtc start`/`gtc up`/`gtc stop`).

| Subcommand | Purpose |
|------------|---------|
| `start` / `up` | Start the runtime (HTTP server, WASM runner, tunnels, providers) |
| `stop` | Gracefully stop a running instance |
| `restart` | Stop then start with the same arguments |

### Key `start` flags

| Flag | Description |
|------|-------------|
| `--bundle <PATH>` | Bundle directory (defaults to `.`) |
| `--tenant`, `--team` | Override default tenant/team (demo/default) |
| `--nats off\|on\|external` | NATS mode (default: off) |
| `--nats-url <URL>` | External NATS URL |
| `--cloudflared on\|off` | Cloudflare tunnel (default: on) |
| `--ngrok on\|off` | ngrok tunnel (default: off) |
| `--verbose` / `--quiet` | Log verbosity |
| `--admin` | Enable mTLS admin API endpoint |
| `--admin-port`, `--admin-certs-dir`, `--admin-allowed-clients` | Admin API TLS config |
| `--restart <TARGET>` | Comma-separated restart targets |
| `--log-dir <DIR>` | Directory for log files |
| `--config <FILE>` | Override configuration file |

## Architecture

### Module Map

| Module | Purpose |
|--------|---------|
| `capabilities.rs` | Capability registry with constants and resolution from pack manifests |
| `static_routes.rs` | Static file route discovery from `.gtpack` extensions, validation, bundle assets diagnostic |
| `http_ingress.rs` | Hyper HTTP server, request routing, `serve_static_asset()` with overlay |
| `runner_host.rs` | WASM runtime host, `PackRuntime`, capability registry building, component execution |
| `runtime.rs` | Top-level orchestration: start sequence, tunnel setup, provider init, signal handling |
| `runtime_state.rs` | Runtime state tracking across start/stop/restart cycles |
| `domains.rs` | Domain model: packs, tenants, teams, providers |
| `ingress_dispatch.rs` | HTTP ingress request dispatch to provider components |
| `messaging_app.rs` | Messaging application layer |
| `messaging_egress.rs` | Outbound message delivery |
| `secrets_gate.rs` | Secrets access control and resolution |
| `secrets_manager.rs` | Secrets lifecycle management |
| `secrets_setup.rs` | Provider secret setup with seed file support |
| `cloudflared.rs` | Cloudflare tunnel integration |
| `ngrok.rs` | ngrok tunnel integration |
| `admin_server.rs` | mTLS admin API endpoint (deployments, config, cache, observability) |
| `timer_scheduler.rs` | Timer-based event scheduling |
| `webhook_updater.rs` | Webhook URL registration with providers |
| `startup_contract.rs` | Startup validation and contract checking |
| `supervisor.rs` | Process supervision for child processes |

### Capability System

`capabilities.rs` defines capability constants used to match pack requirements to runtime features:

| Constant | Value |
|----------|-------|
| `CAP_BUNDLE_ASSETS_READ_V1` | `greentic.cap.bundle_assets.read.v1` |
| `CAP_WEBCHAT_OAUTH_V1` | `greentic.cap.webchat.oauth.v1` |
| `CAP_WEBCHAT_I18N_V1` | `greentic.cap.webchat.i18n.v1` |
| `CAP_WEBCHAT_EMBED_V1` | `greentic.cap.webchat.embed.v1` |
| `CAP_OAUTH_BROKER_V1` | `greentic.cap.oauth.broker.v1` |
| `CAP_OAUTH_CARD_V1` | `greentic.cap.oauth.card.v1` |
| `CAP_OP_HOOK_PRE` / `CAP_OP_HOOK_POST` | Pre/post operation hooks |

Capabilities are read from pack manifests via the `greentic.ext.capabilities.v1` extension.

### Static Route System

`static_routes.rs` discovers routes from `.gtpack` files declaring the `greentic.static-routes.v1` extension. Each route descriptor includes: public path, source root, index file, SPA fallback, tenant/team scoping, and cache strategy.

Reserved operator paths (`/healthz`, `/readyz`, `/status`, `/runtime/*`, `/deployments/*`, etc.) are protected from pack route collisions.

### Static Asset Overlay

`http_ingress.rs` implements `serve_static_asset()` with a two-tier resolution:

1. **Bundle filesystem** -- `bundle_root/<source_root>/<asset_path>` checked first
2. **Pack archive fallback** -- asset read from `.gtpack` ZIP if not found on disk

This lets operators customize assets (skins, logos, configs) by placing files in the bundle directory without modifying pack archives.

### Bundle Assets Startup Diagnostic

`static_routes.rs` includes `check_bundle_assets_capability()` which runs at startup. If the bundle has an `./assets/` directory but does not declare `greentic.cap.bundle_assets.read.v1` in `bundle.yaml`, a warning is emitted so operators know to formalize the capability contract.

## Key Dependencies

- `hyper` + `http-body-util` -- HTTP/1.1 server
- `tokio` -- Async runtime (rt-multi-thread, signal, net)
- `greentic-runner-host` -- WASM component execution, pack runtime, host config
- `greentic-runner-desktop` -- Desktop runtime adapter
- `greentic-setup` -- Provider setup orchestration (reused from `gtc setup`)
- `greentic-secrets-lib` -- Secrets store with dev provider support
- `greentic-types` -- Shared platform types (ChannelMessageEnvelope, pack manifest)
- `greentic-i18n` -- Localization
- `greentic-distributor-client` -- OCI pack fetching
- `zip` -- `.gtpack` archive reading
- `tokio-rustls` + `rustls` -- TLS for admin API
- `serde_cbor` -- CBOR decoding for pack manifests
- `serde_yaml_bw` (alias `serde_yaml_gtc`) -- YAML parsing (Greentic fork)

## Git Conventions

- Use conventional commit format: `feat:`, `fix:`, `docs:`, `chore:`, etc.
- Do NOT add `Co-Authored-By: Claude` or AI attribution in commits/PRs
- Always use feature branches, never commit directly to main/master
