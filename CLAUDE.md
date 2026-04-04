# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

greentic-start is the lifecycle runner for Greentic demo/app-pack execution. It owns `start`/`up`/`stop`/`restart` orchestration, exposed both as a library (`greentic_start::run_from_env`) and a thin CLI binary. `greentic-operator` owns wizard UX and delegates lifecycle execution here.

## Build & Test

```bash
# Full local CI (run before PRs) — fmt, clippy, test, build, doc, package
bash ci/local_check.sh

# Standard commands
cargo build -p greentic-start --all-features
cargo test -p greentic-start --all-features
cargo fmt -p greentic-start -- --check
cargo clippy -p greentic-start --all-targets --all-features -- -D warnings

# Run a single test
cargo test -p greentic-start -- test_name_here
```

Rust 1.94.0, edition 2024, pinned via `rust-toolchain.toml`. Cargo.lock is committed.

## Release Flow

1. Bump `version` in `Cargo.toml`
2. Create and push tag `vX.Y.Z` (must match Cargo.toml)
3. Tag push triggers `.github/workflows/publish.yml` (needs `CARGO_REGISTRY_TOKEN`)

## Architecture

### Entry Points

- `src/main.rs` — trivial: calls `greentic_start::run_from_env()`
- `src/lib.rs` — CLI parsing (clap derive), arg normalization (strips legacy `demo` subcommand prefix), dispatches to `run_start`, `run_restart_request`, `run_stop_request`
- Public API: `StartRequest`, `StopRequest`, `run_start_request()`, `run_restart_request()`, `run_stop_request()`, `run_from_env()`
- Public modules: `config`, `runtime`, `runtime_state`, `supervisor`

### Core Layers

| Layer | Key Files | Responsibility |
|-------|-----------|----------------|
| Runtime orchestration | `runtime.rs`, `runtime_state.rs`, `supervisor.rs` | Starts/stops services (cloudflared, ngrok, NATS, gateway, egress, subscriptions), persists service manifests under `state/runtime/<tenant.team>` |
| Bundle resolution | `bundle_ref.rs` | Resolves local dirs, archives (zip/tar/gzip/zstd), and remote refs (`oci://`, `repo://`, `store://`) |
| HTTP ingress | `http_ingress.rs`, `ingress_dispatch.rs`, `ingress_types.rs` | Hyper-based HTTP server for provider ingress (`v1/{domain}/ingress/...`), onboarding endpoints (`/api/onboard`), static route serving |
| Admin server | `admin_server.rs` | mTLS endpoint (default port 8443) for remote lifecycle control (`/admin/v1/start`, `/stop`, `/status`, `/list`) |
| Runner host | `runner_host.rs`, `runner_exec.rs`, `runner_integration.rs` | Builds DemoRunnerHost over discovered packs, secrets, state stores. Supports in-process and external runner execution |
| OAuth card resolution | `cards.rs` | Thin orchestrator: detects OAuth placeholders in Adaptive Cards, delegates resolution to `greentic.cap.oauth.card.v1` capability (provided by greentic-oauth), swaps resolved card into metadata |
| Startup contract | `startup_contract.rs` | Launch gating for bundles declaring `greentic.static-routes.v1`; resolves `PUBLIC_BASE_URL`, persists `startup_contract.json` |
| Onboarding | `onboard/` | Provider listing, tenants/teams, deployment status, QA submit/spec/validate, webhook setup |
| Secrets | `secrets_*.rs`, `secret_*.rs` | Backend selection (pack vs dev-store), secret URI handling, missing secret seeding |
| Services | `services/` | Individual service components: NATS, runner, components |
| Subscriptions | `subscriptions_universal/` | Universal subscription runtime and persistence (e.g., Microsoft Graph) |

### Key Patterns

- **Async/sync boundary**: Runtime creation guards with `tokio::Handle::try_current()` to avoid nested-runtime panics. Onboarding uses a thread-hop pattern for the same reason.
- **Legacy compat**: `normalize_args()` strips legacy `demo` subcommand prefix so old `greentic-start demo start` invocations still work.
- **Restart targets**: Granular restart via `RestartTarget` enum (All, Cloudflared, Ngrok, Nats, Gateway, Egress, Subscriptions).
- **State layout**: Runtime state persisted under `state/runtime/<tenant.team>/` with pid files, log paths, and service manifests.
- **Admin stop**: `POST /admin/v1/stop` writes a stop-request file; the foreground loop observes and honors it.

## Dependencies (Greentic Crates)

- `greentic-distributor-client` — pack fetching (feature: `pack-fetch`)
- `greentic-runner-host` / `greentic-runner-desktop` — runtime execution
- `greentic-secrets-lib` — secrets management (feature: `providers-dev`)
- `greentic-types` — common types (feature: `serde`)
- `greentic-setup` — setup/admin contracts
- `greentic-i18n` — i18n support
- `qa-spec` — QA form specifications

## Conventions

- **YAML**: Uses `serde_yaml_gtc` (imported as `serde_yaml_bw`), not `serde_yaml`
- **Error handling**: `anyhow::Result<T>` with `.context()`
- **i18n**: Source catalog at `i18n/en.json`. Translate via `tools/i18n.sh` (defaults: `LANGS=all`, `BATCH_SIZE=200`). Never hardcode user-facing strings.
- **Docker**: `Dockerfile.distroless` builds a musl static binary into a Chainguard distroless image

## Git Conventions

Do NOT add Claude co-author attribution to commits or PRs.

## Parent Workspace

This project is part of the Greentic platform ecosystem. See the workspace root `CLAUDE.md` for workspace-level conventions including shared crates, WASM component model, pack/bundle formats, and i18n patterns.
