#!/usr/bin/env bash
#
# smoke-agent-deploy.sh — end-to-end smoke for the designer→runtime Digital
# Worker deployment pipeline.
#
# This script automates the DETERMINISTIC half (boot the designer-admin agent
# registry, mint a tenant gtc_live key, publish a sample AgentConfig, and verify
# the runtime-facing pull). It then prints the exact `gtc start` env + the manual
# verification steps for the agent loop (which needs Redis + an LLM key + an
# installed extension on YOUR machine, so it can't be fully scripted here).
#
# Prereqs: a built `greentic-designer-admin` binary, curl, python3.
# Optional (for the agent-loop half you run by hand): redis-server, an LLM key,
# an installed extension, and a bundle whose flow has a DwAgent node.
#
# Usage:
#   scripts/smoke-agent-deploy.sh [--admin-bin PATH] [--port 8097] [--agent-id smoke-bot]
#
set -euo pipefail

ADMIN_BIN="${ADMIN_BIN:-}"
PORT="${PORT:-8097}"
AGENT_ID="${AGENT_ID:-smoke-bot}"
# The tool the sample agent is granted — set to a tool from an extension you have
# installed so the agent-loop half can actually invoke it.
EXT_ID="${EXT_ID:-greentic.tavily}"
TOOL_NAME="${TOOL_NAME:-web_search}"
LLM_PROVIDER="${LLM_PROVIDER:-openai}"
LLM_MODEL="${LLM_MODEL:-gpt-4o-mini}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --admin-bin) ADMIN_BIN="$2"; shift 2;;
    --port) PORT="$2"; shift 2;;
    --agent-id) AGENT_ID="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

# Locate the admin binary if not given.
if [[ -z "$ADMIN_BIN" ]]; then
  for cand in \
    "../greentic-designer-admin/target/debug/greentic-designer-admin" \
    "../greentic-designer-admin/target/release/greentic-designer-admin" \
    "$(command -v greentic-designer-admin || true)"; do
    if [[ -n "$cand" && -x "$cand" ]]; then ADMIN_BIN="$cand"; break; fi
  done
fi
if [[ -z "$ADMIN_BIN" || ! -x "$ADMIN_BIN" ]]; then
  echo "ERROR: greentic-designer-admin binary not found. Build it:" >&2
  echo "  (cd ../greentic-designer-admin && cargo build)" >&2
  echo "or pass --admin-bin PATH." >&2
  exit 1
fi
command -v curl  >/dev/null || { echo "ERROR: curl required"  >&2; exit 1; }
command -v python3 >/dev/null || { echo "ERROR: python3 required" >&2; exit 1; }

BASE="http://127.0.0.1:${PORT}"
DB="$(mktemp -u /tmp/gt-smoke-admin.XXXXXX.db)"
JAR="$(mktemp -u /tmp/gt-smoke-jar.XXXXXX)"
LOG="$(mktemp -u /tmp/gt-smoke-admin.XXXXXX.log)"
SRV_PID=""

cleanup() {
  [[ -n "$SRV_PID" ]] && kill "$SRV_PID" 2>/dev/null || true
  rm -f "$DB" "${DB}"* "$JAR" "$LOG" 2>/dev/null || true
}
trap cleanup EXIT

jget() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)"; }
pass() { echo "  ✓ $1"; }
fail() { echo "  ✗ $1" >&2; exit 1; }

echo "==> Booting designer-admin registry on ${BASE} (dev, ephemeral)…"
GREENTIC_ADMIN_DEV=1 "$ADMIN_BIN" start --dev --port "$PORT" \
  --db "sqlite://${DB}?mode=rwc" > "$LOG" 2>&1 &
SRV_PID=$!
for _ in $(seq 1 30); do
  if curl -fsS -o /dev/null "${BASE}/api/health" 2>/dev/null; then break; fi
  sleep 0.5
done
curl -fsS -o /dev/null "${BASE}/api/health" || { echo "admin failed to start:"; tail -20 "$LOG"; exit 1; }
pass "admin server up"

echo "==> Operator setup + tenant key…"
CSRF=$(curl -fsS -c "$JAR" -X POST "${BASE}/api/admin/setup" \
  -H 'content-type: application/json' \
  -d '{"email":"smoke@example.com","display_name":"Smoke","password":"longenough12"}' | jget '["csrf_token"]')
KEY=$(curl -fsS -b "$JAR" -X POST "${BASE}/api/admin/tenants" \
  -H "x-csrf-token: ${CSRF}" -H 'content-type: application/json' \
  -d '{"name":"Smoke","slug":"smoke"}' | jget '["api_key"]["value"]')
[[ "$KEY" == gtc_live_* ]] && pass "tenant gtc_live key minted" || fail "expected gtc_live_* key"

echo "==> Publish AgentConfig (designer Deploy / PUT)…"
CONFIG=$(printf '{"agent_id":"%s","system_prompt":"You are a smoke-test assistant. Use a tool.","tools":[{"extension_id":"%s","tool_name":"%s"}],"llm":{"provider":"%s","model":"%s"}}' \
  "$AGENT_ID" "$EXT_ID" "$TOOL_NAME" "$LLM_PROVIDER" "$LLM_MODEL")
V1=$(curl -fsS -X PUT "${BASE}/api/v1/designer/agents/${AGENT_ID}" \
  -H "authorization: Bearer ${KEY}" -H 'content-type: application/json' -d "$CONFIG" | jget '["version"]')
[[ "$V1" == "1" ]] && pass "published version 1" || fail "expected version 1, got $V1"

echo "==> Runtime pull (what HttpConfigProvider does)…"
PULLED=$(curl -fsS "${BASE}/api/v1/designer/agents/${AGENT_ID}" -H "authorization: Bearer ${KEY}")
echo "$PULLED" | jget '["agent_id"]' >/dev/null && pass "pulled AgentConfig: $PULLED" || fail "pull did not return AgentConfig"

echo "==> Negative checks…"
[[ "$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/api/v1/designer/agents/${AGENT_ID}")" == "401" ]] \
  && pass "no token → 401" || fail "expected 401 without token"
[[ "$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/api/v1/designer/agents/ghost" -H "authorization: Bearer ${KEY}")" == "404" ]] \
  && pass "unknown agent → 404" || fail "expected 404 for unknown agent"

echo ""
echo "================================================================"
echo "Registry contract smoke PASSED ✅  (admin server will stop on exit)"
echo "================================================================"
echo ""
echo "To finish the AGENT-LOOP smoke on this machine, run gtc start against a"
echo "bundle whose flow has a DwAgent node for agent_id='${AGENT_ID}', with:"
echo ""
echo "  export GREENTIC_AW_REDIS_URL=redis://127.0.0.1:6379   # start redis-server first"
echo "  export GREENTIC_AW_ADMIN_ENDPOINT=${BASE}             # (keep this admin running)"
echo "  export GREENTIC_AW_ADMIN_TOKEN=${KEY}"
echo "  export GREENTIC_EXTENSIONS_DIR=\$HOME/.greentic/extensions  # install '${EXT_ID}' here"
echo "  export OPENAI_API_KEY=sk-...                          # or your LLM bridge vars"
echo "  cargo run -p greentic-start -- start ./my-bundle --cloudflared off"
echo ""
echo "Then drive the DwAgent node and verify in the logs:"
echo "  • 'AW runtime constructed' with agent_count > 0"
echo "  • the agent's reply trail contains a 'tool_call' entry for ${EXT_ID}/${TOOL_NAME}"
echo ""
echo "NOTE: this script keeps the registry server alive only while it runs. To do"
echo "the gtc start half, re-run the admin server yourself (or 'gtc start' the"
echo "bundle that injects it) so GREENTIC_AW_ADMIN_ENDPOINT stays reachable."
