# greentic-start environment-home loader — Slice 1a

Status: Draft for review
Date: 2026-07-06
Branch: `feat/env-home-loader`
Repo: `greentic-start`
Epic: Operator-environment deploy in the designer's Deploy & Run page.
This is **sub-project 1 of 2** and a **prerequisite** for the designer work
(sub-project 2, `greentic-designer` branch `feat/operator-env-deploy-run`).

## 1. Summary

Teach `greentic-start` to boot a workload directly from a **greentic-deployer
environment home** (the `--store-root/<env_id>/` directory produced by
`greentic-deployer op env init` + `op deploy`), instead of only from a
`--bundle <.gtbundle>` or `--config <yaml>`.

This closes the one missing link that makes the operator-environment model a real
deployment backbone: `greentic-deployer op` (control plane) writes declarative
deploy state into the env-home; `greentic-start` (data plane) reads that state
and serves. Today the two speak different languages — `op` writes
`runtime-config.json` + pinned pack locks that **nothing reads**, and
`greentic-start` only understands a bundle path.

Scope is deliberately minimal: **read the routed revision from an env-home,
verify and load its packs, boot, and reload on change.** Traffic-split /
blue-green semantics beyond "the single routed revision at 100%" and graceful
in-flight drain are out of scope (they are deferred in `greentic-deployer` too).

## 2. Background (verified against code)

### 2.1 The env-home is self-contained

`op deploy --bundle app.gtbundle --env local` (which runs
`bundles add → revisions stage → warm → traffic set`) **copies** the bundle and
its extracted packs into the env-home and pins them by digest. After deploy, the
original `.gtbundle` path is never referenced again and may be deleted. On-disk
tree (`greentic-deployer/src/environment/store.rs`,
`src/cli/bundle_stage.rs`):

```
<store-root>/<env_id>/
  .lock
  environment.json          # Environment compose-view
  runtime.json              # host-config (optional)
  runtime-config.json       # greentic.runtime-config.v1 — the routed revisions
  env-packs/<slot>/answers.json
  revisions/<revision_ulid>/
      bundle.gtbundle        # full copy of the deployed bundle (not needed by us)
      bundle/
          bundle-manifest.json
          packs/**/<pack>.gtpack     # <-- runnable packs, already extracted
          state/pack-configs/*.json
      pack-list.lock         # env-relative path + sha256 per .gtpack
      pack-configs/<pack_id>.json    # finalized pack-config.v1
```

### 2.2 What `runtime-config.json` and `pack-list.lock` contain

`runtime-config.json` deserializes to (mirrors of
`greentic_deploy_spec::runtime_config`):

```rust
struct RuntimeConfig { schema: String, env_id: String, revisions: Vec<RevisionRuntimeBlock> }
struct RevisionRuntimeBlock {
    deployment_id: String,
    revision_id: String,
    bundle_id: String,               // a NAME (bundle filename stem), not a digest/path
    pack_list_refs:   Vec<PathBuf>,  // env-relative: revisions/<rev>/pack-list.lock
    pack_config_refs: Vec<PathBuf>,  // env-relative: revisions/<rev>/pack-configs/<pack_id>.json
    weight_bps: u32,                 // basis points; per deployment_id must sum to 10000
}
```

`schema` is the literal `"greentic.runtime-config.v1"`. `pack-list.lock`
deserializes to:

```rust
struct PackListLock { /* ...schema/meta... */ packs: Vec<LockedPack> }
struct LockedPack { pack_id: String, path: PathBuf /* env-relative */, digest: String /* "sha256:<hex>" */ }
```

The `pack-list.lock` doc string in `greentic-deployer` explicitly states it is
"read by greentic-start at boot to build the runner load set … verify the
artifact on disk still matches" — i.e. this loader is the intended consumer.

### 2.3 No reader exists yet

Neither `greentic-deployer` nor `greentic-start` reads `runtime-config.json`
back into a load set. `greentic-start` does **not** depend on
`greentic-deploy-spec` and its own `RuntimeConfig` type
(`src/startup_contract.rs`) is an unrelated `public_base_url`/tunnel concept — a
name collision. This spec adds that missing reader.

### 2.4 How greentic-start loads a bundle today

`greentic-start` resolves `--bundle`/`--config` via `resolve_demo_paths`
(`src/bundle_config.rs`) → `resolve_bundle_ref` (`src/bundle_ref.rs`), which for
a directory/archive extracts the squashfs to `bundle/` and finds
`greentic.demo.yaml`/`greentic.operator.yaml`/normalized `bundle.yaml`; the packs
under `bundle/packs/**.gtpack` become the runner load set. Gateway listen
addr/port come from config + the `GREENTIC_GATEWAY_LISTEN_ADDR` /
`GREENTIC_GATEWAY_PORT` env overrides (`apply_target_overrides`). Health is
`GET /healthz → 200 {"status":"healthy"}` (`src/http_ingress/helpers.rs`). The
env-home path reuses the same post-extraction loader and the same gateway
override seam; only the **front-end** (how the pack set + configs are discovered)
is new.

## 3. Design

### 3.1 New input mode: `--store-root` + `--env`

Add two args to `StartArgs` (`src/cli_args.rs`):

```rust
/// Boot from a greentic-deployer environment home instead of a bundle.
#[arg(long = "store-root")]
store_root: Option<PathBuf>,
/// Environment id within the store root (defaults to "local").
#[arg(long = "env", default_value = "local")]
env_id: String,
```

Precedence in `resolve_demo_paths` / `run_start` (`src/lib.rs`):

1. If `--store-root` is set → **env-home mode** (this spec). `--bundle` /
   `--config` must not also be set; if they are, error
   `"--store-root is mutually exclusive with --bundle/--config"`.
2. Else the existing `--config` → `--bundle` → cwd fallback (unchanged).

The env-home directory is `<store-root>/<env_id>/`.

### 3.2 The env-home loader

New module `src/env_home/` (mirrors, reader, resolver):

- `src/env_home/spec.rs` — **mirrored** minimal structs `RuntimeConfig`,
  `RevisionRuntimeBlock`, `PackListLock`, `LockedPack` with `serde` derives.
  Mirroring (rather than depending on `greentic-deploy-spec`) is deliberate:
  `greentic-deploy-spec 0.1.0` pins `greentic-types "<1.2.0-0"`, which is
  unsatisfiable against the research line, so a direct crate dependency will not
  compile. The mirror is tiny and version-checked against the
  `"greentic.runtime-config.v1"` schema string so a producer change is caught
  loudly.
- `src/env_home/loader.rs`:
  - `load_env_home(store_root, env_id) -> Result<RunnerLoadSet>`:
    1. Read `<env-home>/runtime-config.json`; if missing →
       `EnvHomeError::NotDeployed` (clear "run `op deploy` first" message).
    2. Assert `schema == "greentic.runtime-config.v1"` (else
       `EnvHomeError::SchemaMismatch`).
    3. Group `revisions` by `deployment_id`; assert each group's `weight_bps`
       sums to exactly `10000` (`EnvHomeError::InvalidTrafficSplit`).
    4. **Slice 1a routing:** select, per deployment, the single block with
       `weight_bps == 10000` (the only shape `op deploy` currently produces).
       If a deployment has a partial split (multiple non-zero weights), error
       `EnvHomeError::UnsupportedSplit` — do not silently pick one.
    5. For each selected block: for each `pack_list_refs` path, join under the
       env-home, read the `PackListLock`; for each `LockedPack`, resolve
       `<env-home>/<path>`, recompute sha256 and assert it equals
       `LockedPack.digest` (else `EnvHomeError::DigestMismatch` — refuse to
       boot, tamper-evident). Collect the verified `.gtpack` paths.
    6. Load each `pack_config_refs` `pack-config.v1` for provider config; resolve
       any `secret://<env>/<bundle>/<pack>/<key>` URIs through the existing
       secrets path (reuse whatever `greentic-start` already uses for
       demo/operator secret resolution — a plan-time wiring detail).
    7. Return a `RunnerLoadSet { packs, pack_configs, listen_addr }` where
       `listen_addr` comes from `<env-home>/runtime.json`
       `discovered.listen_addr` when present, still overridable by
       `GREENTIC_GATEWAY_*` env vars.
- The `RunnerLoadSet` is fed into the **same** runner-load path the bundle mode
  produces post-extraction — the seam is the extracted-packs-to-runner handoff
  in `bundle_config.rs`/`lib.rs`; env-home mode supplies that set directly
  without a squashfs extract (packs are already extracted in the env-home).

### 3.3 Reload on change (watch)

Add a lightweight watcher (new `notify` dependency) on
`<env-home>/runtime-config.json`. On a debounced modify/create event,
re-run `load_env_home` and swap the runner load set. Scope for slice 1a:

- **In:** reload the load set when the routed revision changes (e.g. a redeploy
  writes a new `runtime-config.json`), and stop serving when
  `runtime-config.json` is deleted (traffic cleared) — matching how
  `greentic-deployer` clears routing.
- **Out:** graceful in-flight session drain / zero-downtime cutover (deferred in
  `greentic-deployer` as well; a hard swap is acceptable for slice 1a).

Gate the watcher behind the presence of env-home mode; bundle mode is unchanged
(still load-once).

### 3.4 Error handling

All new failures are typed `EnvHomeError` and surfaced as a clear startup error
(non-zero exit, message on stderr), never a silent fallback to bundle mode:

- `NotDeployed` — no `runtime-config.json` under the env-home.
- `SchemaMismatch` — unexpected `schema` string.
- `InvalidTrafficSplit` — weights don't sum to 10000.
- `UnsupportedSplit` — a partial split (slice 1a supports single-revision only).
- `DigestMismatch` — a `.gtpack` on disk doesn't match its pinned sha256.
- `MissingArtifact` — a `pack_list_refs` / pack path doesn't exist.

## 4. Scope

**In (slice 1a):**

- `--store-root` + `--env` env-home input mode.
- Read + validate `runtime-config.json`; resolve + sha256-verify packs via
  `pack-list.lock`; load pack-configs.
- Boot the routed single-revision (100%) load set through the existing runner
  path.
- Reload on `runtime-config.json` change (hard swap); stop on delete.
- Reuse existing gateway addr/port override + `/healthz`.

**Out:**

- Partial traffic splits / blue-green / canary cutover.
- Graceful in-flight drain.
- Remote/HTTP env stores (`--store-url`); only the local FS env-home.
- Any dependency on `greentic-deploy-spec` (mirror the structs instead).
- Changes to bundle/`--config` mode behaviour.

## 5. Testing

- **Unit** (`src/env_home/`):
  - Parse a fixture `runtime-config.json` → `RuntimeConfig`; reject a wrong
    `schema` string.
  - Weight validation: sum==10000 passes; sum!=10000 → `InvalidTrafficSplit`;
    a two-nonzero-weight split → `UnsupportedSplit`.
  - `pack-list.lock` resolution: a fixture env-home with a small `.gtpack` whose
    recomputed sha256 matches loads; a byte-flipped `.gtpack` → `DigestMismatch`;
    a missing path → `MissingArtifact`.
  - `NotDeployed` when `runtime-config.json` is absent.
- **Integration** (gated on `greentic-deployer` binary presence, skipped cleanly
  when absent — mirror existing gated tests): run `op env init --store-root
  <tmp>` + `op deploy --bundle <fixture.gtbundle>`, then
  `run_start` in env-home mode against `<tmp>`, and assert `GET /healthz` returns
  200. If a real fixture bundle is unavailable in CI, fall back to a hand-built
  env-home fixture tree checked into `tests/fixtures/env-home/`.
- **Watch**: write an updated `runtime-config.json` into the fixture env-home and
  assert the load set is re-resolved (unit-level against the loader, not a full
  process).
- Run the repo's canonical `bash ci/local_check.sh` (fmt + clippy -D warnings +
  full test), not a `--lib`-scoped subset.

## 6. Resolved facts (from verification) and remaining plan-time details

Resolved:

- `op` global store-root flag is `--store-root`; `op deploy` uses `--env`
  (default `local`), `--tenant`, `--team`; success JSON on stdout
  `{op,noun,result}`, errors on stderr `{op,noun,error:{kind,message}}`.
- env-home is self-contained; original bundle disposable; refs are env-relative
  paths; digests live in `pack-list.lock`.
- Direct `greentic-deploy-spec` dependency is blocked by a `greentic-types`
  version-ceiling clash → mirror the structs.

Remaining for the plan:

1. The exact runner-load seam in `bundle_config.rs`/`lib.rs` where a
   `RunnerLoadSet` can be injected without an squashfs extract.
2. How `greentic-start` currently resolves provider secrets for demo/operator
   mode, so env-home `pack-config` `secret://` URIs reuse it.
3. Debounce/interval for the `runtime-config.json` watcher and how it interacts
   with the existing foreground admin-stop poll loop.

## 7. Non-goals

- No change to `greentic-deployer` (it already produces everything needed).
- No new deployer slots; local-process only, driven by whatever `op deploy`
  wrote.
- No graceful-drain / zero-downtime guarantees in this slice.
