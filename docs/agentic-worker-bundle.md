# Running the agentic worker in a `gtc start` bundle

The agentic worker (`DwAgent` flow nodes) requires the `agentic-worker` feature,
which is **only** present in the git-sourced `greentic-runner-host` /
`greentic-runner-desktop` (the published `1.2.x-research` crates strip it, along
with `greentic-aw-runtime` / `greentic-ext-runtime`). greentic-start therefore
pins the runner via git **rev `74dff3f`** (research line, successor of the
`aw-overlay-v1` tag; adds the admin-registry HTTP config provider read from
`GREENTIC_AW_ADMIN_ENDPOINT` / `GREENTIC_AW_ADMIN_TOKEN`) with `features =
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
| `GREENTIC_AW_AGENTS_FILE` | YAML map of `<agent_id>: AgentConfig` (the agents) | — |
| `GREENTIC_EXTENSIONS_DIR` | extension discovery dir | `~/.greentic/extensions` |
| `GREENTIC_AGENT_MANIFESTS_DIR` | DW manifest overlay dir | `~/.greentic/agents` |
| `OPENAI_API_KEY` / LLM bridge vars | LLM backend | — |

If `GREENTIC_AW_REDIS_URL` is unset, the runner logs `DwAgent nodes disabled`
and the agent path is skipped — that is graceful degradation, not a failure.

## Per-agent config

greentic-start builds a synthetic `HostConfig` (no bindings-YAML path), so agents
are sourced from the file pointed to by **`GREENTIC_AW_AGENTS_FILE`** — a YAML map
of `<agent_id>: AgentConfig`:

```yaml
research-bot:
  agent_id: research-bot
  system_prompt: "You are a research assistant. Use tools when helpful."
  llm:
    provider: openai
    model: gpt-4o-mini
  tools:                       # optional; replaced by a manifest overlay if present
    - extension_id: greentic.tavily
      tool_name: web_search
  # limits: { ... }            # optional; sensible defaults apply when omitted
```

A missing, empty, unreadable, or unparseable file is logged and ignored (no
agents) rather than failing `gtc start`. An optional `<agent_id>.json` manifest in
the manifests dir overlays the tool set onto each agent — see greentic-runner
`docs/agentic-worker-tools.md`.

## Smoke test (manual)

With a bundle that declares an agent in its bindings YAML and an installed
extension:

```bash
export GREENTIC_AW_REDIS_URL=redis://127.0.0.1:6379
export GREENTIC_AW_AGENTS_FILE=$HOME/.greentic/agents.yaml    # the agents map
export GREENTIC_EXTENSIONS_DIR=$HOME/.greentic/extensions
export GREENTIC_AGENT_MANIFESTS_DIR=$HOME/.greentic/agents    # optional (overlay)
cargo run -p greentic-start -- start ./my-bundle --cloudflared off
```

Expected: a log line `AW runtime constructed` with `agent_count > 0`. Drive a
`DwAgent` flow node and confirm a tool is invoked (the step trail contains a
`tool_call` entry).

## Smoke test (cross-host registry path)

`scripts/smoke-agent-deploy.sh` automates the deterministic half of the
designer→runtime pipeline: it boots the `greentic-designer-admin` agent registry
(dev/ephemeral), mints a tenant `gtc_live` key, publishes a sample `AgentConfig`
(the designer "Deploy" / `PUT /api/v1/designer/agents/{id}`), and verifies the
runtime-facing pull (`GET`, the exact call `HttpConfigProvider` makes) plus the
401/404 paths. It then prints the precise `GREENTIC_AW_ADMIN_ENDPOINT` /
`GREENTIC_AW_ADMIN_TOKEN` env + `gtc start` command and the agent-loop
verification checklist (which needs your Redis + LLM key + an installed
extension, so it stays manual).

```bash
# build the admin binary first: (cd ../greentic-designer-admin && cargo build)
scripts/smoke-agent-deploy.sh
```
