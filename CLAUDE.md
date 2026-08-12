# CLAUDE.md

Agent-specific repository guidance lives in [docs/coding-agents.md](docs/coding-agents.md).

Use that document for:

- command and flag behavior
- startup and restart semantics
- tunnel defaults
- admin API behavior
- app-flow execution notes
- validation expectations

Keep the public-facing overview in [README.md](README.md) focused on humans.

## Build & Test

```bash
# Full local CI (run before PRs) — fmt, clippy, test, build, doc, package
bash ci/local_check.sh

# Standard commands
cargo build -p greentic-start
cargo test -p greentic-start
cargo fmt -p greentic-start -- --check
cargo clippy -p greentic-start --all-targets -- -D warnings

# Run a single test
cargo test -p greentic-start -- test_name_here
```

## One-time setup (new clones)

```bash
git config core.hooksPath .githooks
```

Enables the pre-commit hook that runs `rustfmt` on staged Rust files and `cargo clippy --workspace -- -D warnings`. See `.githooks/README.md`.

Crate version 1.2.0-dev.0, edition 2024, Rust 1.95.0 (pinned via `rust-toolchain.toml`). Cargo.lock is committed.

## Release Flow

1. Bump `version` in `Cargo.toml`
2. Merge the bump to `main` — `tag-on-version-bump.yml` creates and pushes tag `vX.Y.Z` automatically (a manually pushed matching tag also works)
3. The tag triggers `.github/workflows/release-binaries.yml` (release binaries). There is no `publish.yml`; crates.io dev publishing runs separately via `dev-publish.yml` on the nightly train

## Architecture

### Entry Points

- `src/main.rs` — trivial: calls `greentic_start::run_from_env()`
- `src/lib.rs` — CLI parsing (clap derive), arg normalization (strips legacy `demo` subcommand prefix), dispatches to `run_start_request`, `run_restart_request`, `run_stop_request`
- Public API: `StartRequest`, `StopRequest`, `run_start_request()`, `run_restart_request()`, `run_stop_request()`, `run_from_env()`
- Public modules: `config`, `notifier`, `perf_harness`, `provider_config_envelope`, `revision_health_gate`, `runtime`, `runtime_state`, `supervisor`, `ws_test_support`

### Core Layers

| Layer | Key Files | Responsibility |
|-------|-----------|----------------|
| Runtime orchestration | `runtime.rs`, `runtime_state.rs`, `supervisor.rs` | Starts/stops services (cloudflared, ngrok, NATS, gateway, egress, subscriptions), persists service manifests under `state/runtime/<tenant.team>` |
| Bundle resolution | `bundle_ref.rs` | Resolves local dirs, archives (zip/tar/gzip/zstd), and remote refs (`oci://`, `repo://`, `store://`) |
| HTTP ingress | `http_ingress/`, `ingress_dispatch.rs`, `ingress_types.rs` | Hyper-based HTTP server for provider ingress (`v1/{domain}/ingress/...`), onboarding endpoints (`/api/onboard`), static route serving |
| Admin server | `admin_server.rs` | mTLS endpoint (default port 8443) for remote lifecycle control (`/admin/v1/start`, `/stop`, `/status`, `/list`) |
| Runner host | `runner_host/`, `runner_exec.rs`, `runner_integration.rs` | Builds DemoRunnerHost over discovered packs, secrets, state stores. Supports in-process and external runner execution |
| Startup contract | `startup_contract.rs` | Launch gating for bundles declaring `greentic.static-routes.v1`; resolves `PUBLIC_BASE_URL`, persists `startup_contract.json` |
| Onboarding | `onboard/` | Provider listing, tenants/teams, deployment status, QA submit/spec/validate, webhook setup |
| Secrets | `secrets_*.rs`, `secret_*.rs` | Backend selection (pack vs dev-store), secret URI handling, missing secret seeding. **Read side of the setup↔start secret contract — see [docs/secrets-flow.md](docs/secrets-flow.md).** |
| Services | `services/` | Individual service components: NATS, runner, components |
| Subscriptions | `subscriptions_universal/` | Universal subscription runtime and persistence (e.g., Microsoft Graph) |
| Revision engine | `revision_boot.rs`, `revision_serve.rs`, `revision_dispatcher.rs`, `revision_drain.rs`, `revision_pull.rs`, `revision_reload.rs`, `revision_pin.rs`, `revision_webhook_register.rs`, `revision_health_gate.rs` | Multi-revision hot-reload runtime (~20k LOC): boots revisions from env-store, dispatches ingress traffic to the active revision, drains old revisions, pulls remote bundles at startup, registers webhooks, and gates readiness |
| Fast2Flow | `fast2flow/` | Chat-to-flow routing subsystem (gate, host_process, llm_router, mapper, contracts, config) — routes inbound chat messages to the matching flow via BM25 + optional LLM fallback |
| LLM integration | `llm/` | Provider-agnostic LLM layer consumed by fast2flow and other subsystems; wraps `greentic-llm` crate |
| OAuth engine | `oauth_engine.rs`, `oauth_secret_bridge.rs`, `oauth_state.rs` | Broker-side OAuth flow for provider connections: token exchange, secret bridging, per-provider state |
| Doctor | `doctor.rs`, `doctor_env.rs` | Pre-flight environment readiness checks (pack presence, secrets, connectivity) |
| Ingress control | `ingress/` | Control-directive routing layer (CBOR directives, allow/deny policy); separate from `http_ingress/` |

### Key Patterns

- **Async/sync boundary**: Runtime creation guards with `tokio::Handle::try_current()` to avoid nested-runtime panics. Onboarding uses a thread-hop pattern for the same reason.
- **Legacy compat**: `normalize_args()` strips legacy `demo` subcommand prefix so old `greentic-start demo start` invocations still work.
- **Restart targets**: Granular restart via `RestartTarget` enum (All, Cloudflared, Ngrok, Nats, Gateway, Egress, Subscriptions).
- **State layout**: Runtime state persisted under `state/runtime/<tenant.team>/` with pid files, log paths, and service manifests.
- **Admin stop**: `POST /admin/v1/stop` writes a stop-request file; the foreground loop observes and honors it.

## Dependencies (Greentic Crates)

- `greentic-deployer` / `greentic-deploy-spec` — environment lifecycle, revision staging, deploy-spec types (floor-pinned ranges with per-publish rationale)
- `greentic-distributor-client` — pack fetching (feature: `pack-fetch`)
- `greentic-llm` — provider-agnostic LLM abstraction (dev-dep feature: `test-mock` for `TestLlmProvider` doubles)
- `greentic-runner-host` / `greentic-runner-desktop` — runtime execution
- `greentic-secrets-lib` — secrets management (feature: `providers-dev`)
- `greentic-setup` — setup/admin contracts
- `greentic-telemetry` — tenant-aware tracing, OTLP export, rollout events
- `greentic-types` — common types (feature: `serde`)
- `qa-spec` — QA form specifications

## Conventions

- **YAML**: Uses `serde_yaml_gtc` (imported as `serde_yaml_bw`), not `serde_yaml`
- **Error handling**: `anyhow::Result<T>` with `.context()`
- **i18n**: Source catalog at `i18n/en.json`. Translate via `tools/i18n.sh` (defaults: `LANGS=all`, `BATCH_SIZE=200`). Never hardcode user-facing strings.
- **Docker**: `Dockerfile.distroless` builds a musl-static binary into a `gcr.io/distroless/static-debian12:nonroot` image (uid 65532, no shell; Chainguard is the optional hardened upgrade). The image is **ELF-only**: it ships no shell or interpreters, so bundle-supplied service helpers (gateway/egress/subscriptions/runner) must be statically-linked ELF binaries, not `#!`-scripts. `build_service_spec` preflights helper shebangs and fails with an actionable error when the interpreter is absent.
- **Floor-pinned deps**: Cross-repo Greentic deps use `>=M.m.p-dev.RUNID, <M.(m+1).0-0` ranges with inline rationale comments in `Cargo.toml`. Bump the floor when a new publish adds a surface this crate consumes; the comment must explain which PR/feature the floor targets.

## Key Environment Variables

| Variable | Purpose |
|----------|---------|
| `GREENTIC_ENV` | Active environment id; flag > env > `local` |
| `PORT` | HTTP listen port for the revision-serve path |
| `PUBLIC_BASE_URL` | Public URL for webhook auto-registration (tunnel > env-store > this) |
| `GREENTIC_EVENTS_NATS_URL` | NATS bus URL; enables SoRX event subscriptions |
| `GREENTIC_APPROVAL_NATS_URL` | NATS bus URL for the approval rail; enables the approval bridge. Deliberately separate from the events bus — the approval subjects need their own per-tenant read authorization. See [docs/approval-rail-bridge.md](docs/approval-rail-bridge.md) |
| `GREENTIC_APPROVAL_DESTINATION` | Conversation approval requests are delivered to (a DM or a private approver channel). No default: the bridge fails closed without one |
| `GREENTIC_LLM_API_KEY` | LLM provider key for fast2flow routing; keyless for Ollama |
| `GREENTIC_CACHE_DIR` | Component cache root (set automatically by warmup) |
| `GREENTIC_DEV_SECRETS_PATH` | Override path for dev-mode secrets store |
| `GREENTIC_ADMIN_LISTEN` | Admin-relay listen address |
| `GREENTIC_DIRECTLINE_TOKEN_TTL_SECS` | DirectLine session-token base TTL (seconds, clamped `[60, 604800]`, default `1800`) |
| `GREENTIC_PROVIDER_CORE_ONLY` | Set to `0` by default in start; `1` enforces provider-core-only mode |

## Git Conventions

Do NOT add Claude co-author attribution to commits or PRs.

## Parent Workspace

This project is part of the Greentic platform ecosystem. See the workspace root `CLAUDE.md` for workspace-level conventions including shared crates, WASM component model, pack/bundle formats, and i18n patterns.
