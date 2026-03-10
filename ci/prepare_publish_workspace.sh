#!/usr/bin/env bash
set -euo pipefail

PATH_DEPS=0

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
  shift
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"

copy_repo() {
  if command -v rsync >/dev/null 2>&1; then
    rsync -a \
      --exclude ".git" \
      --exclude ".codex" \
      --exclude "target" \
      "$ROOT_DIR"/ "$WORK_DIR"/
  else
    cp -a "$ROOT_DIR"/. "$WORK_DIR"/
    rm -rf "$WORK_DIR/.git" "$WORK_DIR/.codex" "$WORK_DIR/target"
  fi
}

strip_path_deps() {
  local file="$1"
  perl -0pi -e 's/,\s*path\s*=\s*"[^"]*"//g; s/path\s*=\s*"[^"]*"\s*,\s*//g' "$file"
  perl -0pi -e 's/^\s*path\s*=\s*".*"\s*\n//mg' "$file"
}

copy_repo

while IFS= read -r -d '' file; do
  strip_path_deps "$file"
done < <(find "$WORK_DIR" -name "Cargo.toml" -print0)

if command -v rg >/dev/null 2>&1; then
  PATH_DEP_LINES="$(rg -n "path\\s*=" -g "Cargo.toml" "$WORK_DIR" || true)"
else
  PATH_DEP_LINES="$(grep -R -n --include "Cargo.toml" -E "path\\s*=" "$WORK_DIR" || true)"
fi
if [[ -n "$PATH_DEP_LINES" ]]; then
  echo "path dependencies remain in publish workspace." >&2
  echo "$PATH_DEP_LINES" >&2
  PATH_DEPS=1
  touch "$WORK_DIR/.path-deps"
fi

echo "$WORK_DIR"

if [[ "$DRY_RUN" -eq 1 ]]; then
  exit 0
fi
