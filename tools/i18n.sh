#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MODE="${1:-all}"
AUTH_MODE="${AUTH_MODE:-auto}"
LOCALE="${LOCALE:-en}"
LANGS="${LANGS:-all}"
BATCH_SIZE="${BATCH_SIZE:-200}"
I18N_TRANSLATOR_MANIFEST="${I18N_TRANSLATOR_MANIFEST:-../greentic-i18n/Cargo.toml}"

if [[ -z "${EN_PATH:-}" ]]; then
  if [[ -f "i18n/en.json" ]]; then
    EN_PATH="i18n/en.json"
  else
    echo "Could not infer EN_PATH (expected i18n/en.json). Set EN_PATH explicitly." >&2
    exit 2
  fi
fi

usage() {
  cat <<'EOF'
Usage: tools/i18n.sh [translate|validate|status|all]

Environment overrides:
  EN_PATH=...                     English source file path (default: i18n/en.json)
  LANGS=...                       Language list for translator (default: all)
  BATCH_SIZE=...                  Translation batch size (default: 200)
  AUTH_MODE=...                   Translator auth mode for translate (default: auto)
  LOCALE=...                      CLI locale used for translator output (default: en)
  I18N_TRANSLATOR_MANIFEST=...    Path to greentic-i18n Cargo.toml

Examples:
  tools/i18n.sh all
  AUTH_MODE=api-key tools/i18n.sh translate
  LANGS=all EN_PATH=i18n/en.json tools/i18n.sh validate
EOF
}

check_paths() {
  if [[ ! -f "$EN_PATH" ]]; then
    echo "EN_PATH does not exist: $EN_PATH" >&2
    exit 2
  fi
  if [[ ! -f "$I18N_TRANSLATOR_MANIFEST" ]]; then
    echo "I18N_TRANSLATOR_MANIFEST does not exist: $I18N_TRANSLATOR_MANIFEST" >&2
    exit 2
  fi
}

run_translate() {
  cargo run --manifest-path "$I18N_TRANSLATOR_MANIFEST" -p greentic-i18n-translator -- \
    --locale "$LOCALE" \
    translate --langs "$LANGS" --en "$EN_PATH" --auth-mode "$AUTH_MODE" --batch-size "$BATCH_SIZE"
}

run_validate() {
  cargo run --manifest-path "$I18N_TRANSLATOR_MANIFEST" -p greentic-i18n-translator -- \
    --locale "$LOCALE" \
    validate --langs "$LANGS" --en "$EN_PATH"
}

run_status() {
  cargo run --manifest-path "$I18N_TRANSLATOR_MANIFEST" -p greentic-i18n-translator -- \
    --locale "$LOCALE" \
    status --langs "$LANGS" --en "$EN_PATH"
}

if [[ "${MODE}" == "-h" || "${MODE}" == "--help" ]]; then
  usage
  exit 0
fi

check_paths

case "$MODE" in
  translate) run_translate ;;
  validate) run_validate ;;
  status) run_status ;;
  all)
    run_translate
    run_validate
    run_status
    ;;
  *)
    echo "Unknown mode: $MODE" >&2
    usage
    exit 2
    ;;
esac
