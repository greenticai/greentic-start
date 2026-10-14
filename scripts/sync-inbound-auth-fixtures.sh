#!/usr/bin/env bash
# Copy the shared inbound signature vectors from greentic-messaging-providers
# (the single source of truth) into this repo, byte for byte, and verify them.
#
#   scripts/sync-inbound-auth-fixtures.sh <providers checkout>          # copy + verify
#   scripts/sync-inbound-auth-fixtures.sh --check <providers checkout>  # compare only
#
# After a copy, move PROVIDERS_CHECKSUMS in
# src/inbound_verify/shared_vectors_tests.rs to the new CHECKSUMS.sha256.
set -euo pipefail

mode=copy
if [[ "${1:-}" == "--check" ]]; then
  mode=check
  shift
fi
providers="${1:?usage: $0 [--check] <greentic-messaging-providers checkout>}"
src="$providers/crates/provider-tests/tests/fixtures/inbound-auth-v1"
dst="$(cd "$(dirname "$0")/.." && pwd)/src/inbound_verify/fixtures/inbound-auth-v1"
files=(whatsapp.json webex.json teams.json CHECKSUMS.sha256)

[[ -d "$src" ]] || { echo "no vectors at $src" >&2; exit 2; }
(cd "$src" && sha256sum --quiet -c CHECKSUMS.sha256) || {
  echo "the providers' vectors do not match their own CHECKSUMS.sha256" >&2
  exit 1
}

status=0
for f in "${files[@]}"; do
  if [[ "$mode" == copy ]]; then
    mkdir -p "$dst"
    cp "$src/$f" "$dst/$f"
  elif ! cmp -s "$src/$f" "$dst/$f"; then
    echo "differs from providers: $f" >&2
    status=1
  fi
done
(cd "$dst" && sha256sum --quiet -c CHECKSUMS.sha256)
[[ $status -eq 0 ]] && echo "inbound-auth-v1 vectors match the providers' set"
exit $status
