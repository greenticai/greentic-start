# Unconditional HTTP listener: decouple `expose` from messaging channels

Date: 2026-07-15
Status: implemented
Repo: `greentic-start` (branch `research`)

## Problem

A bundle with no messaging channel never binds an HTTP port, so `/healthz` never
answers and the worker is reported dead. The failure is silent — the only symptom
is a generic health timeout in whatever supervises the process.

The gate is `src/runtime.rs:1679-1681`:

```rust
// Start HTTP server if we have ingress domains, static routes, or health probes to serve.
if domains.is_empty() && !enable_static_routes && !health_probe_listener_required {
    return Ok(None);
}
```

`domains` comes from `detect_http_ingress_domains` (`src/runtime.rs:1617-1651`), which
requires a discovered provider pack supporting `ingest_http`. Every component in the
ecosystem that declares `ingest_http` is a messaging provider. So "does a port open?"
is decided by "did you attach a chat channel?" — two questions that have nothing to
do with each other.

`discovery::discover_with_options` (`src/discovery.rs:42-100`) scans only
`root.join("providers")`. Flows are never inspected, so a flows-only bundle cannot
open the gate no matter what it declares.

### This is not hypothetical

`greentic-flow`'s `map_flow_type` (`src/lib.rs:63-75`) admits five flow kinds:
`messaging`, `event`/`events`, `component-config`, `job`, `http`. Four need no channel.

`greentic-secrets/packs/{aws-sm,azure-kv,gcp-sm,k8s,vault-kv}/` ships 5 packs × 6 flows
= 30 `type: event` flows with zero messaging references. Booting one under `gtc start` today
yields no listener and no health — which is what this spec fixes.

*(Corrected 2026-07-15: this paragraph originally said those flows "are driven by named
entrypoints declared in `pack.yaml`". They are not — see the `/workers/invoke` non-goal below.
Named entrypoints are discoverability metadata with no runtime dispatcher. This does not change
the problem statement: the flows are real, legitimately channel-less, and were silently portless.
It changes what triggers them once they are up — today, only NATS business events.)*

### Why `--store-root` does not already solve it

The env-home boot (SP1, #352) is a *resolver*, not a boot mode. `src/env_home/loader.rs:5-12`
states it verifies pinned packs in place, points `bundle_config::resolve_bundle_dir_paths`
at `<rev>/bundle/`, then calls the unchanged loader. The only fork is `src/lib.rs:318-342`;
both arms rejoin at `src/lib.rs:343` and converge on `src/runtime.rs:859` →
the same gate. `--store-root` is channel-gated identically to `--bundle`.

### Why `main` does not already solve it

`main` carries `src/revision_serve.rs` (9838 lines), whose listener binds unconditionally
and which routes `/workers/invoke`. But `main`'s gate at `src/runtime.rs:1679` is
byte-identical to `research`'s: `revision_serve` is a *parallel* path taken only when
`bundle_less == true` (`main:src/lib.rs:404`). Callers passing `--bundle` — including
`greentic-designer` (`src/orchestrate/local_deploy/manager.rs:113`) — stay on the legacy
ingress on both branches. `main:src/lib.rs:662` records this as deliberate.

Adopting `revision_serve` here is not available: `research` cannot absorb `main`
(`greentic-deploy-spec` caps `greentic-config-types <1.2.0-0` against `research`'s
`=1.3.0-research.0` pins — a release-train blocker, not a merge conflict).

## Goals

- The HTTP listener always binds. Probes (`/healthz`, `/readyz`, `/status`) answer for
  every booted bundle, channel or not.
- Channel presence decides *routing* only, never whether a port opens.
- One change serves both `--bundle` and `--store-root`, since the gate sits below their
  convergence point.

## Non-goals

- **No `/workers/invoke`.** Adding an inbound invoke surface is a separate decision with its
  own attack surface; `main` deliberately loopback-gates it (`revision_serve.rs:1394`).

  *(Corrected 2026-07-15. This bullet originally justified itself with "channel-less workers
  are triggered by NATS business events, cron, or named entrypoints." Two of those three are
  false, and the correction weakens — not strengthens — the case for omitting an invoke
  surface. Recording it rather than quietly editing the sentence.*
  - ***cron does not exist.*** `greentic-triggers` is a 209-line library whose only
    `Cargo.toml` reference is its own — **zero consumers**. Its `src/lib.rs:6-7` claims "the
    running scheduler lives in operax"; `grep -riE "cron|scheduler"` across all of
    `greentic-operax` returns **zero hits**. The live timer path
    (`greentic-start/src/timer_scheduler.rs`, wired at `runtime.rs:876-905`) is
    interval-only, provider-mediated, and understands no cron expressions.
  - ***Named entrypoints are not a trigger.*** `PackFlowEntry.entrypoints` documents itself
    as "for discoverability". `read_secret` is a **host Rust function**
    (`greentic-runner-host/src/secrets.rs:277`), called from Rust — not dispatched to by any
    runtime. Worse, the runner reads only the `"default"` key
    (`greentic-runner-host/src/runner/engine.rs:2843`) and `flow_adapter.rs:126` only ever
    *writes* `"default"` — every other entrypoint name is silently discarded.
  - **So NATS business events are the *only* working trigger for a channel-less worker**
    (`greentic-start/src/business_event_listener.rs`, gated solely on
    `GREENTIC_EVENTS_NATS_URL`, needing no provider pack). The 30 `type: event` flows in
    `greentic-secrets` cited above have no other path in. Whether that justifies
    `/workers/invoke` is now an open question, not a settled non-goal.)*
- **No flow→ingress wiring.** Making `type: event` flows serve real webhooks requires
  discovery to read flows — a domain-model change, tracked separately.

  *(Corrected 2026-07-15: this originally said "flows with `http:/path` entrypoints", which
  implied that syntax means something. It does not — `http:/path` appears only in a schema
  description (`greentic-flow/schemas/ygtc.flow.schema.json:58-61`, `additionalProperties:
  true`, zero validation) and no parser anywhere reads it. The runtime's actual flow-selection
  key is `subscribes_to` (`greentic-start/src/event_router.rs:36`), which **cannot be authored
  at all**: it is absent from `FlowDoc` and `PackFlowEntry`, and no `.ygtc`/`.yaml`/`.json` in
  any repo declares it. `select_target_flows` therefore returns empty and every event falls back
  to `select_app_flow` — one default flow per pack, regardless of the event.)*
- **No designer changes.** See "Relationship to designer" below.
- **No `revision_serve` port.** Blocked by the release train; also unnecessary for probes.

## Design

### 1. Remove the gate

Delete `src/runtime.rs:1679-1681`. `start_http_ingress_server` always returns `Some`.

No new probe code is needed: `handle_builtin_health_request` is already dispatched ahead
of all routing at `src/http_ingress/mod.rs:456` (implementation at
`src/http_ingress/helpers.rs:123-141`) and never consults a provider. Probes go green the
moment a listener exists.

Requests for a domain with no provider keep returning 404 (`src/http_ingress/mod.rs:713`,
`:723-728`). That is correct: the port is open, the route genuinely does not exist.

### 2. Port conflicts fail loudly (keep strict bind)

`research` binds with `find_available_port(&listen_addr_str, requested_port, 0)`
(`src/http_ingress/mod.rs:241`) — range 0, no fallback. `main`'s ingress and
`revision_serve` both use range 10.

**Keep range 0.** The rationale at `src/http_ingress/mod.rs:230-237` still holds: displayed
URLs are hardcoded to the requested port, so silently rebinding points browsers at an
orphaned process and surfaces as `secret_error`/stale-state symptoms that masquerade as
runtime bugs. `src/port_utils.rs:60-72` locks this in as a contract test
(`range_zero_refuses_fallback_when_port_busy`).

This is consistent with the change's purpose: we are deleting a *silent* failure. Replacing
it with a *silent port shift* would relocate the disease, not cure it.

**Accepted behavior change.** `gtc start` on a channel-less bundle while the default port
8080 (`src/config.rs:409-411`) is occupied now fails to boot where it previously ran
portless. This is honest and actionable. The operator-facing error at
`src/http_ingress/mod.rs:242-250` already names the port, gives an `ss` command to find the
owning process, and tells you to kill the orphan. It has one gap: it never mentions
`GREENTIC_GATEWAY_PORT`, the supported way to run side-by-side instances — which matters
more now that channel-less bundles bind where they previously did not. Add that line.

Designer is unaffected: it allocates a free port and passes `GREENTIC_GATEWAY_PORT`
explicitly (`greentic-designer/src/orchestrate/local_deploy/manager.rs:94`, `:125`).

### 3. The static-routes guard stays

*(Amended 2026-07-15 after reading the code during planning. An earlier revision of this
spec called for deleting the guard. That was wrong.)*

`src/startup_contract.rs:116-121` fails fast with *"bundle declares static routes but this
launch mode does not expose public HTTP"*. It is tempting to call this unreachable once the
listener always binds — but `startup_contract::resolve` is a **pure function** and
`http_listener_enabled` is one of its *inputs*, not a global. The real caller
(`src/runtime.rs:1308` → `:1335`) will always pass `true`; `resolve` itself stays callable
with `false`, and the guard stays ordinary input validation.

Keep the guard and its test `resolve_rejects_missing_public_http` (`src/startup_contract.rs:275`).
`greentic_types::FlowKind::Job` ("Batch/background jobs") already exists as a spec-only
variant — a batch launch mode with no listener is exactly when this guard would catch a real
bug.

### 4. The pack HTTP route table is out of scope

*(Amended 2026-07-15. An earlier revision folded this in; planning showed it cannot be
honestly delivered here.)*

`src/http_ingress/mod.rs:146` builds the `greentic.http-routes.v1` route table only when
`enable_static_routes` is true, so a pack declaring HTTP routes but not static routes has
its table silently dropped to `HttpRouteTable::default()`. That is a real bug — but it
belongs to the flow→ingress project, not here:

- **It is unobservable on its own.** A pack-declared route matches at
  `src/http_ingress/mod.rs:687`, then still passes `state.domains.contains(&domain)`
  (`:718` → 404 "domain disabled") and `supports_op(domain, provider, "ingest_http")`
  (`:721` → 404). Populating the table changes behaviour only when a real `ingest_http`
  provider is present *and* the pack declares http-routes *and* ships no static assets.
- **It has no test fixture.** `discover_http_routes_from_bundle` (`src/http_routes.rs:240`)
  has zero coverage; `src/http_routes.rs`'s tests build in-memory descriptors only
  (`make_route`, `:359`). Covering it needs a `.gtpack` fixture writing
  `greentic.http-routes.v1` into `manifest.cbor`, plus a real provider to observe the effect.
- Adding an uncovered, unobservable change to a PR whose purpose is to stop silent
  behaviour would repeat the mistake in a new place.

Fix it together with the `:718`/`:721` domain check, where it becomes observable.

## Consequences to announce

- `startup_contract.json` now reports `public_http_enabled: true` for probes-only runs.
  (Verified live.)
- **`PUBLIC_HTTP_ENABLED` flips `false` → `true` in the environment of four supervised child
  processes.** `StartupContract::apply_env` (`src/startup_contract.rs:67-87`) injects the
  resolved launch flags into every child spawned via `build_env(…, Some(&startup_contract))`:
  nats (`src/runtime.rs:1357`), gateway (`:1387`), egress (`:1401`), subscriptions (`:1424`).
  `.codex/repo_overview.md:35` documents this env export — not `startup_contract.json` — as the
  real cross-process interface, so it is the contract that actually moves here. Since
  `run_gsm_services = config.services.nats.enabled` (`:1075`) and NATS defaults on, a
  channel-less bundle booted with default NATS now hands all four children
  `PUBLIC_HTTP_ENABLED=true` where they previously got `false`.
  **Resolved 2026-07-15 — the flip is inert, because nothing reads the variable.**
  `greentic-start/src/startup_contract.rs` is its only occurrence in the entire workspace, and
  `strings $(which greentic-runner)` finds zero hits — the compiled runner does not even contain
  the string. `greentic-runner`'s tree (crates: greentic-runner, greentic-runner-host,
  greentic-aw-runtime, runner-core, …) has no occurrence in any file type, and neither does
  `~/.cargo/registry/src/`. The `gateway` / `egress` binaries are external, resolved by bare name
  from PATH (`src/config.rs:401`, `default_gateway_binary() -> "gateway"`), and are not installed
  here at all. `PUBLIC_HTTP_ENABLED` is a write-only contract.
  *(An earlier revision of this bullet called this unverified, on the grounds that `greentic-runner`
  is `.git`-only per the workspace `CLAUDE.md`. That claim is stale — the runner is fully checked
  out, and the question was answerable with one grep.)*
- The startup banner now prints an `HTTP: http://…` line for probes-only runs, where it
  previously printed none — `StartupInfo.http_url` (`src/runtime.rs:71`, populated at
  `:1482`) is `Some` whenever the listener exists. Operators will see a URL that serves
  only probes.
- `endpoints.json` is **unchanged**. An earlier revision of this spec claimed it would gain
  `http_url`/`gateway_port`; both halves were wrong. `DemoEndpoints` (`src/runtime.rs:2074-2082`)
  has no `http_url` field at all — that belongs to the banner struct — and its `gateway_port`
  was always written, falling back to `config.services.gateway.port` when no listener existed
  (`:1470-1473`). Since strict bind means `actual_port == config port`, the file is
  byte-identical before and after. Do not repeat this claim in the PR body.
- `--cloudflared on` / `--ngrok on` on a zero-provider bundle now opens a real tunnel to a
  probes-only listener instead of warning and skipping (`src/runtime.rs:1106`, `:1182`).
- The `GREENTIC_HEALTH_LIVENESS_PATH` / `GREENTIC_HEALTH_READINESS_PATH` escape hatch
  (`src/runtime.rs:1671-1677`) becomes redundant. Leave it in place — it is set by
  `greentic-deployer/src/single_vm.rs:892-893` and removing it is a separate cross-repo
  change. It simply stops being load-bearing.

## Testing

### Tests that must be inverted (intentional behavior change)

- `src/runtime.rs:2422-2431` — asserts `start_http_ingress_server(&config, &[], …)?.is_none()`
- `src/runtime.rs:2547` — `assert!(handles.ingress_server.is_none())`
- `src/runtime.rs:2556` — `assert!(!startup_contract.public_http_enabled)`

### Hermetic boot tests that will now bind — must pin a port

These currently rely on "zero packs → no network ports" and will otherwise race for 8080:

- `src/lib.rs:1217` `run_start_request_embedded_mode_stops_cleanly`
- `src/lib.rs:1241` `run_restart_request_embedded_mode_stops_cleanly`
- `tests/env_home_boot.rs:98` `boots_from_env_home_and_stops_cleanly`

Each must pin a fixed high port (19903/19904/19905) via `GREENTIC_GATEWAY_PORT`. Fixed ports
beat dynamic allocation here because under strict bind (range 0) a lost TOCTOU race between
"find a free port" and "bind it" is a hard boot failure, so allocating is *less* reliable than
pinning ports nothing else claims — which is also the existing convention in `src/port_utils.rs`'s
own tests (19876, 19890, …). Update the module doc at `tests/env_home_boot.rs:15-19`, which
advertises "no network ports" as a design property.

**This is mandatory, not hygiene.** `ci/local_check.sh:19` runs `cargo test` with default
parallelism, and cargo runs test *binaries* as separate processes. `test_env_lock()`
(`src/lib.rs:942`) is an in-process mutex and cannot serialize `tests/env_home_boot.rs`.
Without explicit ports these three race for 8080 and the loser hard-fails under range 0.

### New tests

- Zero-provider bundle boots → `ingress_server.is_some()` and `/healthz` returns 200.
- Zero-provider bundle on an occupied port → boot fails with an error naming the port and
  pointing at `GREENTIC_GATEWAY_PORT`.

### Live verification (required — tests alone do not answer the question)

Boot `greentic-secrets/packs/vault-kv` (6 `type: event` flows, zero messaging providers)
via `gtc start` and `curl /healthz` → 200. This is the only evidence that the original
report is fixed.

## Relationship to designer

**This change is a no-op for `greentic-designer`.** Since #1046, designer injects
`messaging-webchat-gui` into every bundle unconditionally
(`src/orchestrate/local_deploy/provider_refs.rs:23-25`), so its bundles already always bind.
Only bundles that are portless today change behavior — exactly the ones this targets.

Consequently this work has no designer prerequisite and cannot regress designer.

Two designer-side problems were found while scoping this and are **explicitly separate
projects** — neither blocks nor is blocked by this spec:

- **Designer has no flow-kind concept.** `type: messaging` is hardcoded at
  `src/orchestrate/pack_via_packc/mod.rs:1300`, `src/orchestrate/dw_application_pack.rs:65`,
  and defaulted on the single-flow path. No `flow_kind` column exists; the frontend has no
  such concept. Every designer-built pack is `messaging` by construction, which is why
  designer's "No channel" option (`web/src/features/deploy-run/setup-wizard/ChannelStep.tsx:30`)
  cannot be made honest without first making flow kind an authored property.
- **`FlowType::Scheduled` emits an uncompilable flow.** `src/flow_generator/compiler/emit.rs:71`
  emits `"scheduled"`, which `map_flow_type` rejects as `UnknownFlowType`. Designer's
  `FlowType {Messaging, Event, Scheduled}` (`src/flow_generator/intent.rs:67`) does not match
  `greentic_types::FlowKind {Messaging, Event, ComponentConfig, Job, Http}`, though
  `greentic-types` is already a designer dependency (`Cargo.toml:106`) and `FlowKind` is
  already used at `src/orchestrate/cbor_flow_post.rs:30`.

## Rollout

Branch `feat/unconditional-http-listener` off `origin/research`. Single PR: the gate, the
port-error hint, and all test updates belong together — landing the gate without the test
port pinning leaves CI flaky.

Implementation plan: `docs/superpowers/plans/2026-07-15-unconditional-http-listener.md`.

`bash ci/local_check.sh` must pass before the PR is declared done.
