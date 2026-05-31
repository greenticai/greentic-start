# Running the agentic worker in a `gtc start` bundle

The agentic worker (`DwAgent` flow nodes) requires the `agentic-worker` feature,
which is **only** present in the git-sourced `greentic-runner-host` /
`greentic-runner-desktop` (the published `1.2.x-research` crates strip it, along
with `greentic-aw-runtime` / `greentic-ext-runtime`). greentic-start therefore
pins the runner via git **tag `aw-overlay-v1`** with `features =
["agentic-worker"]` on both crates (see `Cargo.toml`).

## Dependency notes

- The git dep pulls `greentic-ext-runtime` v1.2.14-research, which requires
  `greentic-extension-sdk-contract = "=1.2.4-research"`. That SDK version is
  git-tagged only (never republished to crates.io), so greentic-start carries a
  `[patch.crates-io]` redirect to the git tag — Cargo `[patch]` does not
  propagate through git dependencies, so it must be declared here as well as in
  the runner workspace.
- `agentic-worker` is enabled on **both** `greentic-runner-host` and
  `greentic-runner-desktop`. The feature gates a `HostConfig.agents` field; the
  desktop shim constructs `HostConfig`, so its feature must match the host's or
  the field set diverges (a `missing field agents` compile error).

## Runtime prerequisites

| Env var | Purpose | Default |
|---------|---------|---------|
| `GREENTIC_AW_REDIS_URL` | AW session-state store (REQUIRED; unset → agent disabled) | — |
| `GREENTIC_EXTENSIONS_DIR` | extension discovery dir | `~/.greentic/extensions` |
| `GREENTIC_AGENT_MANIFESTS_DIR` | DW manifest overlay dir | `~/.greentic/agents` |
| `OPENAI_API_KEY` / LLM bridge vars | LLM backend | — |

If `GREENTIC_AW_REDIS_URL` is unset, the runner logs `DwAgent nodes disabled`
and the agent path is skipped — that is graceful degradation, not a failure.

## Per-agent config

- Operator YAML `agents.<id>` (bindings YAML, parsed by
  `HostConfig::load_from_path`): `system_prompt`, `llm`, optional `limits`,
  optional `tools`.
- Optional `<id>.json` manifest in the manifests dir overlays the tool set —
  see greentic-runner `docs/agentic-worker-tools.md`.

## Smoke test (manual)

With a bundle that declares an agent in its bindings YAML and an installed
extension:

```bash
export GREENTIC_AW_REDIS_URL=redis://127.0.0.1:6379
export GREENTIC_EXTENSIONS_DIR=$HOME/.greentic/extensions
export GREENTIC_AGENT_MANIFESTS_DIR=$HOME/.greentic/agents   # optional (overlay)
cargo run -p greentic-start -- start ./my-bundle --cloudflared off
```

Expected: a log line `AW runtime constructed` with `agent_count > 0`. Drive a
`DwAgent` flow node and confirm a tool is invoked (the step trail contains a
`tool_call` entry).

> Follow-up: `build_demo_host_config` (the non-bindings demo path) currently
> declares no agents, so DwAgent nodes only activate via the bindings-YAML
> `agents:` path. Sourcing agents into the demo host config is a separate task.
