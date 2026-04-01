#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@"
fi
set -euo pipefail

TARGET=""
OUT_DIR=""
VERSION=""
BIN_NAME="greentic-start"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET="$2"
      shift 2
      ;;
    --out)
      OUT_DIR="$2"
      shift 2
      ;;
    --version)
      VERSION="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$TARGET" || -z "$OUT_DIR" || -z "$VERSION" ]]; then
  echo "Usage: ci/package_binstall.sh --target <triple> --out <dir> --version <x.y.z>" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_TARGET="$(rustc -vV | awk '/^host:/ {print $2}')"
pushd "$ROOT_DIR" >/dev/null

if [[ "$TARGET" != "$HOST_TARGET" ]]; then
  rustup target add "$TARGET"
fi

BUILD_CMD=(cargo build --release --target "$TARGET" --bin "$BIN_NAME")
if [[ "${USE_CROSS:-0}" == "1" ]]; then
  if ! command -v cross >/dev/null 2>&1; then
    echo "cross is required when USE_CROSS=1. Install it first (CI should use taiki-e/install-action)." >&2
    exit 1
  fi
  BUILD_CMD=(cross build --release --target "$TARGET" --bin "$BIN_NAME")
fi
"${BUILD_CMD[@]}"

BIN_PATH="target/$TARGET/release/$BIN_NAME"
BIN_ARCHIVE_PATH="$BIN_PATH"
if [[ "$TARGET" == *windows* ]]; then
  BIN_ARCHIVE_PATH="${BIN_PATH}.exe"
fi

if [[ ! -f "$BIN_ARCHIVE_PATH" ]]; then
  echo "Binary not found: $BIN_ARCHIVE_PATH" >&2
  exit 1
fi

PKG_BASENAME="${BIN_NAME}-${VERSION}-${TARGET}"
STAGE_DIR="$(mktemp -d)"
cp "$BIN_ARCHIVE_PATH" "$STAGE_DIR/"

if [[ "$TARGET" == *windows* ]]; then
  ARCHIVE="$OUT_DIR/$PKG_BASENAME.zip"
  (
    cd "$STAGE_DIR"
    if command -v zip >/dev/null 2>&1; then
      zip -q "$ARCHIVE" "$(basename "$BIN_ARCHIVE_PATH")"
    elif command -v 7z >/dev/null 2>&1; then
      7z a -tzip "$ARCHIVE" "$(basename "$BIN_ARCHIVE_PATH")" >/dev/null
    elif command -v powershell >/dev/null 2>&1; then
      powershell -NoProfile -Command \
        "Compress-Archive -Path '$(basename "$BIN_ARCHIVE_PATH")' -DestinationPath '$ARCHIVE' -Force"
    else
      echo "No zip tool found (zip/7z/powershell Compress-Archive)." >&2
      exit 1
    fi
  )
else
  ARCHIVE="$OUT_DIR/$PKG_BASENAME.tar.gz"
  (
    cd "$STAGE_DIR"
    tar -czf "$ARCHIVE" "$(basename "$BIN_ARCHIVE_PATH")"
  )
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$ARCHIVE" > "$ARCHIVE.sha256"
else
  echo "No sha256 tool found (sha256sum/shasum)." >&2
  exit 1
fi

rm -rf "$STAGE_DIR"
popd >/dev/null
