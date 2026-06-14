PR-DOCTOR-01 - Doctor commands for setup/start diagnostics

## Scope

Add read-only doctor commands for bundle diagnostics:

- `greentic-setup doctor <bundle>`
- `greentic-start doctor <bundle>`

This audit is scoped to the `greentic-start` repository. The setup lifecycle is grounded in the setup paths visible here: `src/providers.rs`, `src/setup_input.rs`, `src/component_qa_ops.rs`, `src/qa_persist.rs`, `src/provider_config_envelope.rs`, and the `greentic_setup` dependency usage in `src/admin_server.rs`. The actual `greentic-setup` binary implementation is external to this repo and should be audited in its own crate before implementing that command.

## Implementation Status

Initial `greentic-start doctor <bundle>` support is now implemented as a read-only command in this repo. It covers bundle resolution, runtime config load, shipped cache presence, pack manifest readability, pack dependency discovery, provider discovery, static route planning, setup envelope freshness, runtime metadata JSON validity, declared secret requirements, public URL validation, and gateway port availability. The `greentic-setup doctor <bundle>` implementation remains a separate follow-up in the setup crate.

## Audit Summary

### Setup lifecycle visible in this repo

Primary local setup path:

1. `providers::run_provider_setup(config_dir, config, public_base_url, options)` selects configured providers from `DemoConfig.providers`.
2. `resolve_pack_path` maps each provider to `cfg.pack` or `provider-packs/<provider>.gtpack` / `demo/provider-packs/<provider>.gtpack`.
3. `SecretsSetup::new` opens the dev secrets store and `ensure_pack_secrets` seeds pack-declared secrets from `seeds.yaml`, `state/seeds.yaml`, or placeholders.
4. `collect_setup_answers` loads `assets/setup.yaml` or `setup.yaml` from the `.gtpack`, validates required questions, and prompts or reads `--setup-input`.
5. `component_qa_ops::persist_answers_artifacts` writes provider answers to `state/runtime/<tenant.team>/providers/<provider>/answers/{setup.answers.json,setup.answers.cbor}`.
6. `provider_config_envelope::ensure_contract_compatible` compares the stored config envelope's `describe_hash` with the currently resolved pack's describe hash.
7. `component_qa_ops::apply_answers_via_component_qa` optionally invokes `qa-spec`, `i18n-keys`, and `apply-answers` through `DemoRunnerHost`.
8. If QA returns config, `providers.rs` writes a synthetic setup success record and `config.envelope.cbor`. Otherwise it invokes the configured setup flow through `runner_integration::run_flow`.
9. `write_run_output`, `write_status`, and `write_provider_config_envelope` persist setup/verify/status records under `state/runtime/<tenant.team>/providers`.

Admin/API setup path:

- `admin_server::handle_setup`, `handle_deploy`, and `handle_update` instantiate `greentic_setup::SetupEngine`, build a `SetupRequest`, call `plan`, and then `execute`.
- These paths expose only `err.to_string()` to the HTTP response, so doctor should not rely on admin API errors as the best diagnostic surface.

Setup inputs observed locally:

- Runtime/demo config: `greentic.demo.yaml`, `greentic.operator.yaml`, `demo/demo.yaml`, or normalized `bundle.yaml`.
- Bundle metadata: `bundle.yaml`, `bundle-manifest.json`, `resolved/*.yaml`.
- Pack manifests: `manifest.cbor` preferred; `pack.manifest.json` fallback in some non-CBOR paths.
- Setup schema: `assets/setup.yaml` or `setup.yaml` inside provider packs.
- Answers: explicit setup input file, interactive answers, and persisted `answers/*.answers.{json,cbor}`.
- Provider config outputs: `config.envelope.cbor`, `<provider>.setup.json`, `<provider>.verify.json`, `<provider>.status.json`.
- Secrets/config: `.greentic` dev store, `seeds.yaml`, `state/seeds.yaml`, pack `assets/secret-requirements.json`.
- Generated runtime artifacts: `state/runtime/<tenant.team>/detected_domains.json`, `detected_providers.json`, `startup_contract.json`, `endpoints.json`, `services.json`, `providers/_contracts/*.contract.cbor`.

### Start lifecycle

Active CLI path:

1. `run_from_env` parses `start`, `up`, `restart`, `stop`, and `warmup`; there is no `doctor` subcommand today.
2. `run_start` sets `GREENTIC_PROVIDER_CORE_ONLY=0` and defaults `GREENTIC_ENV=dev`.
3. `bundle_config::resolve_demo_paths` resolves `--config`, `--bundle`, or CWD fallback.
4. `bundle_ref::resolve_bundle_ref` resolves local dirs, local archives, HTTP, `oci://`, `repo://`, and `store://` refs, then extracts archives into `/tmp/greentic-start/bundles/<digest>`.
5. `warmup::adopt_bundle_cache_dir` adopts `<bundle>/.cache/v1` as `GREENTIC_CACHE_DIR` if present.
6. `bundle_config::load_runtime_demo_config` loads legacy config or normalized `bundle.yaml` plus target inference from `bundle-manifest.json` / `resolved/*.yaml`.
7. `startup_contract::inspect_bundle` scans `providers/` and `packs/` for `greentic.static-routes.v1`.
8. Tunnel mode is resolved from `.greentic/tunnel.json`, deployer pack discovery via `greentic_setup::deployment_targets`, CLI flags, or interactive prompt.
9. `runtime::demo_up_services` performs dependency checks, discovery, secrets manager selection, runner-host construction, notifier config resolution, HTTP ingress startup, tunnel startup, startup contract writing, process spawning, endpoints writing, and optional browser open.

Start inputs observed locally:

- Bundle/config source and normalized bundle metadata.
- Pack manifests under `providers/` and `packs/`.
- Cached extracted bundles in `/tmp/greentic-start`.
- Optional shipped component cache under `<bundle>/.cache/v1`.
- Runtime state under `state/runtime/<tenant.team>`.
- Provider config envelopes and contract cache entries.
- Secrets backend selection, dev-store path, env fallback, secret requirements.
- `PUBLIC_BASE_URL`, tunnel config, gateway listen address/port, NATS config.
- Static route extension payloads and reserved route table.
- External binaries: `cloudflared`, `ngrok`, `greentic-runner`, NATS/gateway/egress/subscriptions binaries.

## Failure Map

| Area | Current code path | Failure mode | Current behavior | Doctor opportunity |
| --- | --- | --- | --- | --- |
| Bundle reference | `bundle_ref::resolve_bundle_ref` | unsupported ref, bad archive, missing `unsquashfs`, stale extraction marker | fails before config load, message is per-stage but not grouped | report source kind, digest, cache path, marker consistency, archive kind |
| Moving tags | `OciPackFetcher` in `bundle_ref` uses `allow_tags: true` | `repo://...:latest` / `oci://...:latest` can drift after pinning expectations | allowed and fetched normally | warn/error on tag refs in `--strict`; recommend digest refs |
| Extraction cache | `extract_bundle_archive` | marker exists while extracted dir is incomplete/corrupt | marker short-circuits re-extraction | verify marker, root config files, extracted root, source/digest consistency |
| Config selection | `bundle_config::resolve_bundle_config_path` | normalized bundle missing runtime payload | generic config-not-found error | list searched files and normalized payload evidence |
| Normalized target | `infer_normalized_bundle_target` | missing or stale `bundle-manifest.json` / `resolved/*.yaml` | falls back silently to defaults if no target | warn when normalized bundle lacks target metadata |
| Pack manifests | `domains`, `discovery`, `startup_contract`, `static_routes`, `capabilities`, `dependency_resolver` | duplicate parsing logic and inconsistent CBOR strictness | some paths allow JSON fallback; demo path may require CBOR-only | centralize manifest inspection and emit one result per pack |
| Pack ID fallback | `domains::build_pack_meta`, `discovery` | missing pack id becomes filename | warning to stderr or silent filename source | warn with `id_source=filename`, path, expected manifest field |
| Pack meta cache | `domains::read_pack_meta_cached` | cache keyed only by len and mtime seconds | stale metadata possible if content changes with same len/mtime | doctor recomputes manifest digest and compares cached metadata |
| Pack deps | `dependency_resolver::check_all` | missing dependency packs | only logs warnings during start | doctor should surface as warning or strict error |
| Static routes | `static_routes::discover_from_bundle` | invalid schema, route conflicts, asset path issues | blocking failures live in plan; startup may fail later when ingress uses plan | doctor should run route plan validation before startup |
| Static-route inspection | `startup_contract::inspect_bundle` | invalid `manifest.cbor` while checking static routes | fail during start before runtime services | doctor should classify as pack manifest/static-routes issue |
| Setup schema | `setup_input::load_setup_spec` | missing setup schema, invalid YAML, required questions | missing schema is okay; required answers fail only during setup | doctor should say whether schema exists and which answers are required |
| Answers shape | `SetupInputAnswers::answers_for_provider` | ambiguous raw object vs provider-keyed map | can apply same raw object to all providers | doctor should explain selected interpretation |
| Setup outputs | `providers.rs` | existing `<provider>.setup.json` skips setup unless forced | stale success can mask changed pack/config | doctor should compare setup output timestamp/envelope provenance to pack digest/hash |
| Config envelope | `provider_config_envelope` | digest is local blake3 over pack bytes, not OCI digest; manifest decode fallback can synthesize weak provenance | contract drift catches describe hash only if envelope exists | doctor should validate envelope decode, ABI, component id, operation, describe hash, digest, and contract cache entry |
| QA setup | `component_qa_ops::apply_answers_via_component_qa` | missing `qa-spec` returns fallback, invalid i18n/config schema errors | good diagnostic code exists but only in setup path | doctor should reuse `QaDiagnosticCode` mapping |
| Secret setup | `SecretsSetup`, `secrets_gate` | placeholders can make setup "succeed" while real runtime secrets are absent | setup seeds placeholders by design | doctor should flag placeholder values and missing required secrets |
| Runtime discovery | `discovery::discover`, `DemoRunnerHost::new` | malformed provider pack or missing capability extension | startup fails while building host | doctor should run discovery with same CBOR mode and report exact pack |
| Notifier config | `notifier::config` | `state-redis` envelope missing or lacks URL | startup fails during notifier config resolution | doctor should pre-check provider config envelope needed by notifier |
| Ports | `runtime::start_http_ingress_server`, service spawns | occupied gateway/admin/tunnel service ports | failure after partial runtime setup | doctor should bind-test planned ports without launching services |
| External binaries | `bin_resolver`, supervisor | missing `cloudflared`, `ngrok`, runner, NATS/gateway binaries | fails when tunnel/service selected | doctor should resolve paths and print exact missing binary |
| Service spawn | `supervisor::spawn_service` | child exits immediately or pid stale | failure can be far from config root cause | doctor dry-run should build service specs and inspect stale pids/log paths |
| Public URL | `startup_contract::configured_public_base_url_from_env`, tunnel path | invalid `PUBLIC_BASE_URL` or route/tunnel mismatch | fails or silently derives local URL | doctor should validate URL shape and route compatibility |

## Proposed Doctor Checks

### `greentic-setup doctor <bundle>`

Read-only checks grounded in local setup code plus follow-up checks for the external `greentic-setup` crate:

- `setup.bundle.resolve`: resolve bundle path/ref using the same rules as start/setup.
- `setup.bundle.structure`: verify expected config root files and normalized bundle payload (`bundle.yaml`, `bundle-manifest.json`, `resolved/`).
- `setup.bundle.manifest`: parse `bundle-manifest.json` and `resolved/*.yaml`; flag missing tenants/teams or stale normalized target metadata.
- `setup.pack.discover`: discover providers using the same domain rules as `domains.rs` and `discovery.rs`.
- `setup.pack.manifest`: validate each `.gtpack` archive, `manifest.cbor`, pack id, components, operations, dependencies, and JSON fallback usage.
- `setup.pack.cbor_only`: when legacy demo mode is active, enforce the same CBOR-only requirement used by `discover_provider_packs_cbor_only`.
- `setup.pack.locks`: in `greentic-setup` crate, validate pack/component lock files and exact versions; in this repo, report missing lock files as external implementation needed.
- `setup.pack.tag_refs`: flag `latest` or other tag refs where digest pins are expected.
- `setup.component.refs`: verify manifest component ids/versions/digests are internally consistent.
- `setup.cache.oci`: inspect local artifact cache entries for referenced pack/component digests and corrupt ZIP/CBOR payloads.
- `setup.schema.available`: locate `assets/setup.yaml` / `setup.yaml` for each provider with setup flow.
- `setup.answers.required`: load setup schema and report missing required answers without prompting.
- `setup.answers.compat`: validate answer object shape and schema compatibility; show whether input is provider-keyed or shared raw object.
- `setup.secrets.requirements`: read `assets/secret-requirements.json`, check dev-store availability, and flag placeholders.
- `setup.qa.contract`: check `qa-spec`, `i18n-keys`, and `apply-answers` support via manifest extension without invoking long-running setup.
- `setup.outputs.present`: verify `<provider>.setup.json`, `<provider>.status.json`, answers JSON/CBOR, and `config.envelope.cbor`.
- `setup.outputs.current`: compare setup output/envelope provenance against current pack digest/describe hash.
- `setup.outputs.valid`: decode canonical CBOR envelope and `_contracts/<digest>.contract.cbor`.
- `setup.paths.deterministic`: verify runtime paths use `RuntimePaths::new(state, tenant, team)` and no provider output is outside that tree.
- `setup.messages.actionable`: every error includes provider id, pack path, expected file, actual file/result, and fix hint.

### `greentic-start doctor <bundle>`

Read-only checks grounded in the active `run_start -> demo_up_services` path:

- `start.bundle.resolve`: resolve bundle refs and archive cache state using `bundle_ref`.
- `start.config.resolve`: run `resolve_demo_paths` and `load_runtime_demo_config`; list config source and tenant/team.
- `start.setup.completed`: verify setup output files for providers expected by config/discovery.
- `start.setup.current`: compare `config.envelope.cbor` and contract cache entries against current pack manifests.
- `start.cache.component`: inspect `<bundle>/.cache/v1` and `GREENTIC_CACHE_DIR`; verify cached artifacts match component digests when available.
- `start.pack.manifest`: validate all runtime pack manifests in `providers/` and `packs/`.
- `start.pack.dependencies`: reuse `dependency_resolver::check_all`, promoted to diagnostic output.
- `start.discovery`: run `discovery::discover` with the same CBOR mode as startup.
- `start.secrets.backend`: run secrets manager selection and required-secret checks without reading secret values into output.
- `start.notifier.config`: validate notifier config and required provider envelopes such as `state-redis`.
- `start.routes.inspect`: run `startup_contract::inspect_bundle`.
- `start.routes.plan`: run `static_routes::discover_from_bundle` with `ReservedRouteSet::operator_defaults`.
- `start.routes.public_url`: validate `PUBLIC_BASE_URL`, tunnel config, static routes, and local URL derivation.
- `start.ports.available`: bind-test gateway/admin/NATS planned ports.
- `start.binaries.resolve`: resolve `cloudflared`, `ngrok`, `greentic-runner`, NATS/gateway/egress/subscriptions binaries according to selected mode.
- `start.services.plan`: construct service specs and environment maps, but do not spawn.
- `start.runtime.metadata`: validate existing `startup_contract.json`, `endpoints.json`, `services.json`, detected provider/domain files.
- `start.runtime.dry_run`: assemble runner host, capabilities, secrets manager, route tables, and service specs without starting long-running services.
- `start.root_cause`: map failures to nearest likely root: bundle, cache, lock, answers, routes, runtime, provider, or secrets.

## CLI/API Shape

Recommended CLI:

```text
greentic-start doctor <bundle> [--json] [--strict] [--fix-hints] [--stage <stage>]
greentic-setup doctor <bundle> [--json] [--strict] [--fix-hints] [--stage <stage>]
```

Stages:

- `setup`
- `cache`
- `locks`
- `answers`
- `runtime`
- `routes`
- `provider`
- `secrets`
- `all` (default)

Default human output:

```text
greentic-start doctor /path/to/bundle

error start.setup.current provider=messaging-slack
  Setup config was produced for a different provider contract.
  expected describe_hash: 9e...
  actual describe_hash:   3a...
  file: state/runtime/demo.default/providers/messaging-slack/config.envelope.cbor
  fix: rerun greentic-setup for this provider, or pass the explicit contract-change flow if intentional.

warn start.pack.tag_refs pack=deep-research-demo
  Bundle references repo://packs/deep-research-demo:latest while exact pins are expected.
  fix: rebuild the bundle with a digest-pinned pack reference.
```

Exit behavior:

- Exit `0` when no errors are found.
- Exit `1` when any `error` diagnostic is found.
- With `--strict`, promote selected drift/tag/cache warnings to errors.
- With `--json`, emit stable JSON only; no progress spinners or logs on stdout.
- With `--fix-hints`, include longer suggested commands/paths in human output. JSON should always include `fix_hint` when known.

## Diagnostic JSON Schema

```json
{
  "schema_version": 1,
  "tool": "greentic-start",
  "command": "doctor",
  "bundle": {
    "input": "repo://bundles/demo@sha256:...",
    "resolved_root": "/tmp/greentic-start/bundles/...",
    "source_kind": "oci",
    "digest": "sha256:..."
  },
  "summary": {
    "errors": 1,
    "warnings": 2,
    "infos": 4
  },
  "diagnostics": [
    {
      "check_id": "start.setup.current",
      "severity": "error",
      "component": "setup",
      "message": "Provider setup output was produced for a different provider contract.",
      "evidence": {
        "provider": "messaging-slack",
        "operation_id": "setup_default"
      },
      "expected": {
        "describe_hash": "9e..."
      },
      "actual": {
        "describe_hash": "3a..."
      },
      "fix_hint": "Rerun greentic-setup for messaging-slack, then retry greentic-start.",
      "related_file": "state/runtime/demo.default/providers/messaging-slack/config.envelope.cbor",
      "related_pack": "providers/messaging/messaging-slack.gtpack",
      "related_component": "messaging-slack"
    }
  ]
}
```

Rust model:

```rust
pub struct Diagnostic {
    pub check_id: String,
    pub severity: Severity,
    pub component: DiagnosticComponent,
    pub message: String,
    pub evidence: serde_json::Value,
    pub expected: serde_json::Value,
    pub actual: serde_json::Value,
    pub fix_hint: Option<String>,
    pub related_file: Option<PathBuf>,
    pub related_pack: Option<String>,
    pub related_component: Option<String>,
}

pub enum Severity {
    Error,
    Warn,
    Info,
}

pub enum DiagnosticComponent {
    Setup,
    Start,
    Cache,
    Lock,
    Answers,
    Routes,
    Runtime,
    Provider,
}
```

## Missing Checks Identified

- No `doctor` subcommand exists in `src/cli_args.rs`.
- Bundle extraction cache markers are trusted without revalidating extracted contents.
- OCI/tag bundle refs are allowed even when exact pins are expected.
- Pack/component lock validation is not implemented locally; likely belongs to `greentic-setup` and/or shared pack resolution crates.
- Pack manifest validation is duplicated across `domains`, `discovery`, `startup_contract`, `static_routes`, `capabilities`, `dependency_resolver`, and `offers`.
- Pack meta cache uses length and mtime seconds, not content digest.
- Setup success records can skip setup even if pack provenance changed.
- Contract drift compares describe hash, but not all start-time consumers validate envelope ABI, component id, operation id, contract cache entry, or digest before use.
- Placeholder secrets are not distinguished from real setup values at start.
- Missing pack dependencies are warnings only during start.
- Static route conflicts are available as `blocking_failures`, but not exposed before runtime start.
- Port and binary availability are discovered only during startup.
- Admin setup/deploy/update paths collapse `SetupEngine` failures to strings.

## Implementation Split

### PR 1 - Shared doctor diagnostics module

- Add `src/doctor/diagnostic.rs` with `Diagnostic`, `Severity`, `DiagnosticComponent`, JSON summary, and human renderer.
- Add reusable helpers for `--json`, `--strict`, `--fix-hints`, and `--stage`.
- Keep it local to `greentic-start` first; promote to shared crate only after `greentic-setup` validates the same shape.

### PR 2 - Manifest and bundle inspection reuse

- Add `src/doctor/pack_inspect.rs` that wraps existing `domains`, `discovery`, `startup_contract`, `static_routes`, `capabilities`, and `dependency_resolver` checks.
- Do not add another ad hoc manifest parser; route all doctor checks through one wrapper that records source module failures.
- Add tests with corrupt ZIP, missing `manifest.cbor`, JSON fallback, bad pack id, and static route conflicts.

### PR 3 - `greentic-start doctor` read-only runtime validation

- Add `Command::Doctor(DoctorArgs)` in `src/cli_args.rs`.
- Implement `run_doctor_request` in `src/lib.rs`.
- Validate bundle/config resolution, setup outputs, provider envelopes, dependency report, discovery, secrets backend selection, routes, public URL, ports, binary resolution, and service spec planning.
- Ensure no long-running services are spawned and no browser/tunnel is opened.

### PR 4 - Setup-output/provenance validation

- Reuse `provider_config_envelope::{read_provider_config_envelope, resolved_describe_hash}` and add validation for ABI, component id, operation id, digest, describe hash, schema hash, and `_contracts` entries.
- Validate `answers/*.json` and `answers/*.cbor` equivalence where both exist.
- Compare setup output timestamps/provenance against pack metadata and warn on stale outputs.

### PR 5 - `greentic-setup doctor` in setup crate

- Implement the external setup command in the `greentic-setup` crate, reusing the same diagnostic schema.
- Add lock-file, exact version, OCI digest, answer compatibility, provider setup requirements, and generated setup-output checks that are not owned by `greentic-start`.
- Wire `SetupEngine::plan` dry-run diagnostics to structured results instead of plain strings.

### PR 6 - JSON output and fixtures

- Add stable JSON snapshots for representative valid and invalid bundles.
- Add fixture bundles covering missing answers, corrupt pack cache, digest drift, stale setup outputs, bad static routes, and missing secrets.
- Document schema compatibility guarantees.

### PR 7 - Demo regression and CI integration

- Add smoke tests that run `greentic-start doctor --json` against demo bundles before start.
- Add CI job or local check stage that fails on doctor errors for pinned demo bundles.
- Keep `--strict` opt-in until all existing demos are clean.

## Acceptance Criteria

- `greentic-start doctor <bundle>` runs without starting tunnel, NATS, gateway, egress, subscriptions, browser, or long-lived runner processes.
- Human output names the nearest failing root cause and the exact file/pack/provider involved.
- JSON output is stable and includes all diagnostic fields listed above.
- Existing validation code is reused instead of duplicated.
- Exact-version/digest/tag checks are implemented where the owning crate has the necessary lock/cache context.
- Tests cover corrupt cache/pack, stale setup output, missing answers, missing secrets, route conflicts, and occupied ports.
