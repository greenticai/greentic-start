# Repository Overview

## 1. High-Level Purpose

`greentic-start` is a Rust CLI/library crate that owns lifecycle execution for Greentic demo and app-pack runtimes. It resolves bundles and config, starts and stops local runtime services, launches provider/app execution paths, exposes HTTP ingress and onboarding APIs, and persists runtime state under the selected bundle/config root.

The repo is centered on startup/runtime concerns rather than setup UX. It integrates Greentic shared crates for pack manifests, runner hosting, secrets, QA/setup forms, and bundle distribution. Current code also includes startup-time gating for bundles that declare `greentic.static-routes.v1`, but it does not implement static-route serving itself.

## 2. Main Components and Functionality

- **Path:** `Cargo.toml`
  - **Role:** Single-crate Rust package definition for `greentic-start`.
  - **Key functionality:**
    - Declares the crate as a publishable CLI/library package.
    - Pulls in Greentic runtime, runner-host, pack, secrets, distributor, QA, and HTTP stack dependencies.
  - **Key dependencies / integration points:** `greentic-types`, `greentic-runner-host`, `greentic-secrets-lib`, `greentic-distributor-client`, `hyper`, `tokio`.

- **Path:** `src/main.rs`, `src/lib.rs`
  - **Role:** Main CLI entrypoint and command normalization layer.
  - **Key functionality:**
    - Exposes `start`, `up`, `restart`, and `stop`.
    - Normalizes legacy `demo ...` style invocations into the current CLI.
    - Resolves bundle/config/state paths, logging, tunnel binaries, and runtime launch flags before delegating into `runtime`.
    - On the current branch, inspects bundles for static-route declarations and passes startup contract inputs into the runtime path.
    - Re-exports `config`, `runtime`, `runtime_state`, and `supervisor` as public modules so downstream integration tests can keep using the documented helper types/functions.
  - **Key dependencies / integration points:** `src/runtime.rs`, `src/config.rs`, `src/bundle_ref.rs`, `src/startup_contract.rs`.

- **Path:** `src/runtime.rs`, `src/runtime_state.rs`, `src/supervisor.rs`, `src/services/`
  - **Role:** Runtime orchestration, child-process supervision, and persisted runtime metadata.
  - **Key functionality:**
    - Starts cloudflared/ngrok, NATS, gateway, egress, subscriptions, and embedded messaging modes.
    - Persists service manifests, logs, pid paths, endpoints, and runtime-scoped metadata under `state/runtime/<tenant.team>`.
    - Handles stop/status/log operations for supervised services.
    - On the current branch, writes `startup_contract.json` and exports resolved launch flags via env vars (`PUBLIC_HTTP_ENABLED`, `STATIC_ROUTES_ENABLED`, `ASSET_SERVING_ENABLED`, `BUNDLE_HAS_STATIC_ROUTES`, `PUBLIC_BASE_URL` when present).
  - **Key dependencies / integration points:** `src/cloudflared.rs`, `src/ngrok.rs`, `src/operator_log.rs`, `src/services/nats.rs`, `src/subscriptions_universal/`.

- **Path:** `src/startup_contract.rs`
  - **Role:** Startup-time bundle inspection and launch compatibility resolution for static-route-capable bundles.
  - **Key functionality:**
    - Scans `.gtpack` manifests under bundled `providers/` and `packs/` for `greentic.static-routes.v1`.
    - Normalizes a startup-provided `PUBLIC_BASE_URL` from env.
    - Resolves a small startup contract and rejects incompatible launches before runtime services boot.
  - **Key dependencies / integration points:** `greentic_types::decode_pack_manifest`, `src/lib.rs`, `src/runtime.rs`.

- **Path:** `src/bundle_ref.rs`, `src/config.rs`, `src/bin_resolver.rs`
  - **Role:** Bundle/source/config resolution.
  - **Key functionality:**
    - Resolves local directories, archives, and remote `oci://`, `repo://`, and `store://` bundle refs.
    - Extracts supported archive formats into a temp cache.
    - Loads demo/operator YAML and resolves binary overrides relative to bundle/config roots.
  - **Key dependencies / integration points:** `greentic-distributor-client`, startup path resolution in `src/lib.rs`.

- **Path:** `src/domains.rs`, `src/discovery.rs`, `src/capabilities.rs`, `src/offers/`
  - **Role:** Pack discovery and manifest-driven runtime metadata/capability inspection.
  - **Key functionality:**
    - Discovers provider packs by domain (`messaging`, `events`, `secrets`, `oauth`) across `providers/` and `packs/`.
    - Reads pack metadata from `manifest.cbor` and persists detected providers/domains.
    - Builds capability registries from pack extensions such as `greentic.ext.capabilities.v1`.
  - **Key dependencies / integration points:** `src/runner_host.rs`, runtime startup persistence, onboarding/provider flows.

- **Path:** `src/runner_host.rs`, `src/runner_exec.rs`, `src/runner_integration.rs`, `src/messaging_app.rs`
  - **Role:** In-process and delegated provider/app pack execution.
  - **Key functionality:**
    - Builds a `DemoRunnerHost` over discovered packs, secrets, state stores, and capabilities.
    - Supports execution either directly or through an external runner binary.
    - Routes app-pack messaging flows and capability invocations.
    - Enables HTTP, timers, operator policy, trace, and validation behavior for hosted pack execution.
  - **Key dependencies / integration points:** `greentic-runner-host`, `src/http_ingress.rs`, `src/event_router.rs`, onboarding and capability flows.

- **Path:** `src/http_ingress.rs`, `src/ingress_dispatch.rs`, `src/ingress/`, `src/event_router.rs`, `src/post_ingress_hooks.rs`, `src/timer_scheduler.rs`
  - **Role:** In-process HTTP ingress and event/timer routing.
  - **Key functionality:**
    - Starts a Hyper HTTP server for provider ingress and onboarding endpoints.
    - Handles `/api/onboard`, directline/token endpoints, and `/v1/{domain}/ingress/...` provider ingress routes.
    - Dispatches parsed ingress requests into provider ops and routes event/messaging results onward.
    - Supports timer scheduling and post-ingress control directives/hooks.
  - **Key dependencies / integration points:** `DemoRunnerHost`, pack discovery, onboarding API.

- **Path:** `src/onboard/`, `src/component_qa_ops.rs`, `src/demo_qa_bridge.rs`, `src/setup_to_formspec.rs`, `src/setup_input.rs`, `src/qa_persist.rs`, `src/providers.rs`
  - **Role:** Onboarding, QA/spec translation, setup flow invocation, and persisted setup outputs.
  - **Key functionality:**
    - Serves onboard API endpoints for provider listing, tenants/teams, deployment status, and QA submit/spec/validate.
    - Translates setup specs and QA output into forms and persisted provider config envelopes.
    - Runs `setup_default` and related provider flows, injects `public_base_url` when available, and performs webhook setup for supported providers.
  - **Key dependencies / integration points:** `src/http_ingress.rs`, `src/runner_host.rs`, `src/onboard/webhook_setup.rs`, runtime state.

- **Path:** `src/secrets_*.rs`, `src/dev_store_path.rs`, `src/secret_*.rs`
  - **Role:** Secrets manager selection, canonical secret URI handling, dev-store integration, and setup seeding.
  - **Key functionality:**
    - Chooses a secrets backend pack or falls back to the dev-store/env path based on runtime selection.
    - Canonicalizes tenant/team/provider secret URIs and checks provider secret availability.
    - Seeds or creates missing dev-store secrets and exposes secrets access to hosted packs.
  - **Key dependencies / integration points:** `greentic-secrets-lib`, `src/runner_host.rs`, `src/subscriptions_universal/demo.rs`, onboarding/setup paths.

- **Path:** `src/subscriptions_universal/`
  - **Role:** Universal subscriptions runtime path and persistence.
  - **Key functionality:**
    - Maintains desired subscription state and scheduling for providers such as Microsoft Graph.
    - Builds runner-backed subscription flows and stores subscription metadata under bundle state.
  - **Key dependencies / integration points:** runtime launch path in `src/runtime.rs`, `DemoRunnerHost`, secrets setup.

- **Path:** `ci/local_check.sh`, `ci/package_binstall.sh`, `ci/prepare_publish_workspace.sh`
  - **Role:** Local validation and release preparation helpers.
  - **Key functionality:**
    - Runs formatting, clippy, tests, build, docs, packaging, publish dry-run, and a binstall artifact packaging step.
    - Prepares a publish workspace and checks for path-dependency leaks during release prep.
  - **Key dependencies / integration points:** `README.md`, `AUDIT.md`, release/publish expectations.

- **Path:** `README.md`, `docs/ownership.md`, `AUDIT.md`, `SECURITY.md`, `i18n/`, `tools/i18n.sh`
  - **Role:** Project documentation, lifecycle ownership notes, audit checklist, vulnerability policy, and CLI i18n assets.
  - **Key functionality:**
    - Documents lifecycle ownership split (`greentic-start` vs `greentic-operator` vs `greentic-setup`).
    - Captures local validation and publish expectations.
    - Provides bundled CLI translation catalogs and translator helper script.

## 3. Work In Progress, TODOs, and Stubs

- **Location:** Repo-wide search for `TODO`, `FIXME`, `XXX`, `unimplemented!`, `todo!`
  - **Status:** No meaningful inline TODO/stub markers found in tracked source files.
  - **Short description:** The codebase currently relies more on implicit partial areas and validation failures than explicit TODO comments.

- **Location:** `src/runtime.rs:410` (`demo_up`)
  - **Status:** Partial / likely legacy path
  - **Short description:** A standalone `demo_up` runtime path still exists alongside the actively used `run_start -> demo_up_services` flow. Current startup-contract changes were applied only to `demo_up_services`, which suggests `demo_up` is no longer the primary lifecycle path.

- **Location:** Multiple modules with `#![allow(dead_code)]`, including `src/runtime.rs`, `src/runner_host.rs`, `src/secrets_gate.rs`, `src/domains.rs`, `src/provider_config_envelope.rs`, and others
  - **Status:** Partial / transitional
  - **Short description:** Many modules suppress dead-code warnings at crate or item level, indicating retained legacy paths, test-only helpers, or API surface that is not exercised uniformly by the current CLI path.

- **Location:** `src/subscriptions_universal/mod.rs`
  - **Status:** Partial export surface
  - **Short description:** Re-exports are annotated with `#[allow(unused_imports)]`, which suggests the public module surface is broader than the currently used call sites.

## 4. Broken, Failing, or Conflicting Areas

- **Location:** `ci/local_check.sh` / dependency build during `cargo clippy` and `cargo check`
  - **Evidence:** `greentic-interfaces v0.4.107` build-script failure. In sandboxed runs: `Permission denied`. In escalated `ci/local_check.sh`: `unable to locate package declaration in ... greentic-repo-ui-actions-1.0.0/package.wit`.
  - **Likely cause / nature of issue:** Current validation is blocked by an external dependency/build-script issue in `greentic-interfaces`, not by a compile error in `greentic-start` source.

- **Location:** `src/onboard/api.rs`
  - **Evidence:** Inline comment above `submit_answers` notes: `Run on a dedicated thread to avoid nested Tokio runtime panics.`
  - **Likely cause / nature of issue:** The onboarding submit path still depends on a thread-hop workaround because deeper provider execution paths create their own Tokio runtimes. The behavior is intentionally guarded, but the comment documents a real runtime integration hazard.

- **Location:** `src/runtime.rs` and runtime mode split
  - **Evidence:** Active lifecycle path is `run_start -> demo_up_services`, while `demo_up` remains present and separately maintained.
  - **Likely cause / nature of issue:** The crate carries overlapping lifecycle orchestration paths, which increases the risk of behavior drift between active and legacy code.

- **Location:** Current worktree state
  - **Evidence:** Uncommitted changes exist in `Cargo.toml`, `Cargo.lock`, `README.md`, `src/lib.rs`, `src/runtime.rs`, and new `src/startup_contract.rs`; `.codex/` is also untracked.
  - **Likely cause / nature of issue:** The repository is mid-change. Any overview or validation result should be interpreted as a snapshot of the current worktree, not only the last committed `master` state.

## 5. Notes for Future Work

- Consolidate or retire legacy lifecycle paths if `demo_up_services` is the only supported startup route.
- Fix or pin the `greentic-interfaces` release/build behavior so local and CI validation can run end-to-end again.
- Replace thread-hop workarounds in onboarding/provider execution with a cleaner async/runtime boundary.
- Reduce broad `dead_code` allowances by pruning unused helpers or making the supported module surface more explicit.
- If static-route support continues, the next steps are likely runtime serving and operator-side asset hosting, not additional startup gating logic.
