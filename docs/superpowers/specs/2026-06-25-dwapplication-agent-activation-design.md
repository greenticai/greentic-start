# `gtc start` auto-activates DwApplication agents from the bundle manifest — Design

- **Date:** 2026-06-25
- **Status:** Draft (design approved in brainstorm; pending spec review)
- **Scope:** Make `gtc start <bundle>` derive a `greentic_aw_runtime::AgentConfig`
  from a `DwApplication` app-pack already present in the bundle and **register it
  into `HostConfig.agents`**, removing the need to hand-author
  `GREENTIC_AW_AGENTS_FILE`. Registration only — serve loop, dispatch, messaging,
  ingress, credential setup, bundle composition, and an AW-enabled release are
  explicit prerequisites handled elsewhere.
- **Repos touched:** `greentic-runner` (`greentic-aw-runtime` crate),
  `greentic-start`. Designer reuse is a separate follow-up (`greentic-designer`,
  greentic-biz).
- **Companion docs:** `docs/agentic-worker-bundle.md` (AW env vars, runner pin),
  `greentic-aw-runtime/src/config.rs` (`AgentConfig`),
  `greentic-designer/src/orchestrate/dw_form_to_agent_config.rs` (the existing
  `DwFormState → AgentConfig` converter whose leaf rules this design shares).

## Background

A designer-exported `DwApplication` `.gtpack` is a declarative agentic-worker
pack: a `manifest.json` carrying `manifest_id`, `defaults.values.system_prompt`,
`capability_plan.default_provider_ids` (e.g. `cap://llm/chat →
provider.llm.deepseek.chat`), `provider_overrides`, a model default
(`provider.llm.deepseek.chat::model`), and memory capabilities. It carries **no
flow graph** and **no pre-baked agent blob**.

`greentic-start` builds a synthetic `HostConfig` and today sources Digital
Worker agents **only** from `GREENTIC_AW_AGENTS_FILE` (`apply_demo_agents` in
`src/runner_host/helpers.rs`). Consequently a bundle that contains a
`DwApplication` pack boots to "Ready" but registers **zero** agents — the pack's
declared worker never becomes an `AgentConfig`. The conversion logic already
exists in the designer (`dw_form_to_agent_config.rs`: `provider_slug`,
`resolve_model`, `build_memory_settings`) but operates on the in-memory
`DwFormState`, not on the exported pack manifest, and lives in a different repo.

This design closes that gap for the `gtc start` path with a **shared converter**
so the designer and the runtime never diverge on mapping rules.

## Goals / Non-goals

**Goal:** With no `GREENTIC_AW_AGENTS_FILE` set, `gtc start <bundle>` registers
the bundle's `DwApplication` agent(s) into `HostConfig.agents`; the runner logs a
non-zero agent count.

**Non-goals (prerequisites owned elsewhere):** starting the NATS serve loop /
making the agent dispatch-reachable; wiring a messaging channel + HTTP ingress;
`gtc setup` credential surfacing; auto-wrapping a bare `.gtpack` into a bundle;
shipping an `agentic-worker`-enabled release. This design assumes an AW-enabled
runner (built from source per `docs/agentic-worker-bundle.md`) and a bundle that
already contains the pack.

## Architecture

The mapping lives in **`greentic-aw-runtime`** because it owns `AgentConfig` and
is already a shared dependency of both consumers: `greentic-start` (transitively
via `greentic-runner-host`) and `greentic-designer` (direct import in
`dw_form_to_agent_config.rs`). Placing it there yields one source of truth.

```
                greentic-aw-runtime (new: dw module)
                  ├─ DwApplicationManifest        (shared interchange contract)
                  ├─ agent_config_from_dw_manifest(&DwApplicationManifest) -> AgentConfig
                  └─ provider_slug / resolve_model / memory_settings  (shared leaf rules)
                        ▲                                   ▲
                        │ consumes                          │ reuses leaf rules (follow-up)
                greentic-start                       greentic-designer
                  apply_bundle_dw_agents(...)          dw_form_to_agent_config(...)
```

### Component 1 — `greentic-aw-runtime::dw` (new module)

- **`DwApplicationManifest`** — a typed, minimal view of the export contract:
  `manifest_id: String`, `system_prompt: String`, `default_provider_ids:
  BTreeMap<String,String>`, `provider_overrides: BTreeMap<String,String>`,
  `model_defaults: BTreeMap<String,String>`, plus a `Deserialize` impl that reads
  the designer's `manifest.json` shape (`manifest.defaults.values.*`,
  `manifest.capability_plan.default_provider_ids`, top-level
  `provider_overrides`). Tolerant of unknown fields (`#[serde(default)]`,
  `deny_unknown_fields` OFF) so future pack additions don't break parsing.
- **`agent_config_from_dw_manifest(&DwApplicationManifest) -> AgentConfig`** —
  pure function:
  - `agent_id ← manifest_id`
  - `system_prompt ← system_prompt`
  - `llm.provider ← provider_slug(default_provider_ids["cap://llm/chat"])`
    (strips `provider.llm.{slug}.{variant}` → `{slug}`, e.g. `deepseek`)
  - `llm.model ← model_defaults["{llm_provider_id}::model"]`. If absent, leave
    empty and log a `warn` rather than substituting a foreign default — the
    runtime forwards `model` to the provider verbatim, so a wrong fallback (e.g.
    the designer playground's `gpt-4o-mini`) would silently mis-route a DeepSeek
    agent. (Differs intentionally from the designer's playground fallback.)
  - `llm.credential_ref ←` conventional secret name derived from the provider id
    (resolution itself is out of scope; the field is populated so the
    prerequisite credential work has a stable target)
  - `memory ← memory_settings(default_provider_ids, cap://memory/{long,short}-term)`
  - `tools = []`, `guardrails = []`, `limits = AgentLimits::default()`,
    `knowledge = None`
- **Shared leaf rules** (`provider_slug`, `resolve_model`, memory mapping) moved
  here from the designer so both converters apply identical rules.

### Component 2 — `greentic-start::apply_bundle_dw_agents`

A new function called from the synthetic-`HostConfig` build path (next to the
existing `apply_demo_agents`), signature roughly
`apply_bundle_dw_agents(&mut HostConfig, bundle_root: &Path, tenant: &str)`:

1. Resolve the app pack via the **existing** `messaging_app::resolve_app_pack_path`
   + `load_app_pack_info` (already used by `event_router`, `http_ingress`,
   `doctor`).
2. Detect `kind == DwApplication` (from pack `metadata.json`); skip non-DW packs.
3. Parse `manifest.json` into `DwApplicationManifest`; call
   `agent_config_from_dw_manifest`; `config.agents.insert(agent_id, cfg)`.

**Precedence:** bundle-derived agents are primary. A present
`GREENTIC_AW_AGENTS_FILE` is applied *after* (dev override/supplement), so the
existing manual-file workflow keeps working and can shadow a bundle agent by id.

## Data flow

```
gtc start <bundle>
  → greentic-start builds synthetic HostConfig
  → apply_bundle_dw_agents(bundle_root, tenant)
        → resolve_app_pack_path → load pack → kind==DwApplication?
        → parse manifest.json → DwApplicationManifest
        → agent_config_from_dw_manifest → AgentConfig
        → HostConfig.agents.insert(agent_id, cfg)
  → apply_demo_agents (env override, if set)
  → runner host constructed with agent_count > 0   ← DoD
```

## Error handling

Fail-soft, matching `apply_demo_agents`: a missing pack, a non-DwApplication
kind, an unreadable/unparseable manifest, or an unmappable provider id logs a
`warn` and skips that agent — it never aborts `gtc start`. A bundle with no
DwApplication pack simply registers no agents (unchanged behavior).

## Testing

- **`greentic-aw-runtime`** unit tests:
  - `agent_config_from_dw_manifest` over a fixture of the real
    onboarding-companion `manifest.json` → asserts each field
    (`agent_id`, `system_prompt`, `llm.provider=="deepseek"`,
    `llm.model=="deepseek-chat"`, memory settings).
  - `provider_slug` table (`provider.llm.deepseek.chat → deepseek`,
    edge/empty cases) — mirrors the designer's existing `provider_slug` test.
  - model fallback when the `::model` default is absent.
- **`greentic-start`** unit tests:
  - `apply_bundle_dw_agents` over a bundle fixture (pack under
    `tenants/<t>/packs/`) → `config.agents` has exactly one entry with the
    expected id.
  - precedence: `GREENTIC_AW_AGENTS_FILE` override shadows the bundle agent.
  - fail-soft: malformed manifest → empty agents, no error.
- **Parity:** a test asserting the shared `provider_slug`/model rules produce the
  same result the designer relied on (guards the follow-up refactor).

## Sequencing (cross-repo)

1. **`greentic-runner`** (`greentic-aw-runtime`): add `dw` module
   (`DwApplicationManifest`, converter, shared leaf rules) + unit tests. Tag/rev.
2. **`greentic-start`**: bump the runner git pin; add `apply_bundle_dw_agents`
   and call it in the host-config build; tests; update
   `docs/agentic-worker-bundle.md` to note bundle-derived agents (env file now
   optional).
3. **`greentic-designer`** (follow-up PR, greentic-biz): refactor
   `dw_form_to_agent_config` to consume the shared leaf rules. Not required for
   this design's DoD; parity test guards against drift until then.

## Out of scope (named so they are not silently assumed done)

Auto-wrap `.gtpack` → bundle (capability_plan → provider-pack resolution);
`gtc setup` LLM/Redis/Chronicle credential surfacing; NATS serve-loop startup
from `gtc start`; messaging channel + HTTP ingress wiring; `agentic-worker`
release build. Each is a separate prerequisite tracked outside this spec.
