#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@"
fi
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBLISH_DRY_RUN_TIMEOUT_SEC="${PUBLISH_DRY_RUN_TIMEOUT_SEC:-120}"

pushd "$ROOT_DIR" >/dev/null

echo "[local_check] cargo fmt -p greentic-start -- --check"
cargo fmt -p greentic-start -- --check

echo "[local_check] cargo clippy -p greentic-start --all-targets --all-features -- -D warnings"
cargo clippy -p greentic-start --all-targets --all-features -- -D warnings

echo "[local_check] cargo test -p greentic-start --all-features"
cargo test -p greentic-start --all-features

echo "[local_check] cargo build -p greentic-start --all-features"
cargo build -p greentic-start --all-features

echo "[local_check] cargo doc -p greentic-start --no-deps --all-features"
cargo doc -p greentic-start --no-deps --all-features

run_package_step() {
  local label="$1"
  shift
  echo "[local_check] $label"
  set +e
  local output
  output="$("$@" 2>&1)"
  local status=$?
  set -e
  if [[ -n "$output" ]]; then
    echo "$output"
  fi
  if [[ "$status" -ne 0 ]]; then
    if echo "$output" | grep -E -q "Could not resolve host|download of config.json failed|failed to download"; then
      echo "Warning: skipping '$label' due to missing network access."
      return 0
    fi
    echo "$output" >&2
    exit "$status"
  fi
}

run_package_step "cargo package --allow-dirty --no-verify -p greentic-start" \
  cargo package --allow-dirty --no-verify -p greentic-start
run_package_step "cargo package --allow-dirty -p greentic-start" \
  cargo package --allow-dirty -p greentic-start

echo "[local_check] cargo publish --dry-run --allow-dirty"
set +e
if command -v timeout >/dev/null 2>&1; then
  timeout_cmd=(timeout "$PUBLISH_DRY_RUN_TIMEOUT_SEC")
elif command -v gtimeout >/dev/null 2>&1; then
  timeout_cmd=(gtimeout "$PUBLISH_DRY_RUN_TIMEOUT_SEC")
else
  timeout_cmd=()
fi
publish_output="$("${timeout_cmd[@]}" cargo publish --dry-run --allow-dirty -p greentic-start 2>&1)"
publish_status=$?
set -e
if [[ -n "$publish_output" ]]; then
  echo "$publish_output"
fi
if [[ "$publish_status" -ne 0 ]]; then
  if [[ "$publish_status" -eq 124 ]]; then
    echo "Warning: publish dry-run timed out after ${PUBLISH_DRY_RUN_TIMEOUT_SEC}s; continuing."
    publish_status=0
  fi
  if echo "$publish_output" | grep -E -q "Could not resolve host|download of config.json failed|failed to download"; then
    echo "Warning: skipping publish dry-run due to missing network access."
  else
    if [[ "$publish_status" -ne 0 ]]; then
      echo "$publish_output" >&2
      exit "$publish_status"
    fi
  fi
fi

PACKAGE_OUT="$(mktemp -d)"
HOST_TARGET="$(rustc -vV | grep '^host:' | awk '{print $2}')"
VERSION="$(python3 - <<'PY'
import tomllib
with open("Cargo.toml", "rb") as f:
    data = tomllib.load(f)
print(data["package"]["version"])
PY
)"
echo "[local_check] package binstall artifact for $HOST_TARGET (version=$VERSION)"
"$ROOT_DIR/ci/package_binstall.sh" --target "$HOST_TARGET" --out "$PACKAGE_OUT" --version "$VERSION"

if ! ls "$PACKAGE_OUT"/greentic-start-"$VERSION"-"$HOST_TARGET"* >/dev/null 2>&1; then
  echo "Package artifact not created." >&2
  exit 1
fi

rm -rf "$PACKAGE_OUT"

popd >/dev/null
