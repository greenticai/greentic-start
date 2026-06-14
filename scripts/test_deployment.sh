#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/test_deployment.sh <bundle-dir> [--target <local|aws|gcp|azure>] [options]
  scripts/test_deployment.sh --bundle <bundle-dir> [--target <local|aws|gcp|azure>] [options]

Options:
  --target <local|aws|gcp|azure>      Limit validation to one target. If omitted, all detected deployer packs are tested.
  --deployer-pack <path>              Inject and test a deployer .gtpack. Requires --target.
  --secrets-pack <path>               Inject a secrets .gtpack into providers/secrets/.
  --tenant <tenant>                   Tenant passed to the deployer (default: demo).
  --team <team>                       Team used for local smoke metadata (default: default).
  --environment <env>                 Environment passed to the deployer (default: dev).
  --mode <generate|local-smoke|apply> Validation mode (default: generate).
  --expect-secrets-provider <id>      Override the expected generated secrets provider binding provider_id.
  --expect-no-runtime-secret-env      Fail if generated output injects GREENTIC_SECRET__ runtime env vars.
  --allow-runtime-secret-env          Allow GREENTIC_SECRET__ output for cloud targets.
  --allow-apply                       Required with --mode apply.
  --keep-temp                         Keep the temp workspace for debugging.
  --help                              Show this help.

Environment:
  GREENTIC_BUNDLE_BIN                 Bundle builder executable (default: greentic-bundle).
  GREENTIC_DEPLOYER_BIN               Deployer executable (default: greentic-deployer).
  GREENTIC_START_BIN                  Runtime executable for local-smoke (default: greentic-start).
  GREENTIC_DEPLOYER_EXTRA_ARGS        Extra args appended to deployer invocation.
USAGE
}

die() {
  echo "error: $*" >&2
  exit 1
}

log() {
  echo "[test_deployment] $*" >&2
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

copy_file_into_dir() {
  local file="$1"
  local dir="$2"
  mkdir -p "$dir"
  cp "$file" "$dir/"
}

find_binding_file() {
  local root="$1"
  find "$root" -type f \( \
    -path '*/state/config/platform/secrets-provider.json' -o \
    -path '*/config/platform/secrets-provider.json' -o \
    -name 'secrets-provider.json' \
  \) | sort | head -n 1
}

deployer_metadata_dir() {
  local stdout_file="$1"

  [[ -f "$stdout_file" ]] || return 0
  sed -n 's/^Deployment executor not registered; runtime metadata stored under //p' "$stdout_file" | tail -n 1
}

json_field_equals() {
  local file="$1"
  local field="$2"
  local expected="$3"

  if command -v jq >/dev/null 2>&1; then
    jq -e --arg expected "$expected" ".$field == \$expected" "$file" >/dev/null
    return
  fi

  python3 - "$file" "$field" "$expected" <<'PY'
import json
import sys

path, field, expected = sys.argv[1:]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)
value = data
for part in field.split("."):
    value = value[part]
if value != expected:
    raise SystemExit(1)
PY
}

json_field_value() {
  local file="$1"
  local field="$2"

  if command -v jq >/dev/null 2>&1; then
    jq -r ".$field // empty" "$file"
    return
  fi

  python3 - "$file" "$field" <<'PY'
import json
import sys

path, field = sys.argv[1:]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)
value = data
for part in field.split("."):
    if not isinstance(value, dict) or part not in value:
        raise SystemExit(0)
    value = value[part]
if value is not None:
    print(value)
PY
}

is_cloud_target() {
  [[ "$1" =~ ^(aws|gcp|azure)$ ]]
}

expected_provider_for_target() {
  case "$1" in
    aws)
      echo "greentic.secrets.aws-sm"
      ;;
    gcp)
      echo "greentic.secrets.gcp-sm"
      ;;
    azure)
      echo "greentic.secrets.azure-kv"
      ;;
    local)
      echo "greentic.secrets.dev"
      ;;
    *)
      return 1
      ;;
  esac
}

detect_target_from_pack() {
  local pack_name
  pack_name="$(basename "$1" | tr '[:upper:]' '[:lower:]')"

  case "$pack_name" in
    *aws*|*amazon*)
      echo "aws"
      ;;
    *gcp*|*google*)
      echo "gcp"
      ;;
    *azure*)
      echo "azure"
      ;;
    *local*)
      echo "local"
      ;;
    *)
      return 1
      ;;
  esac
}

find_deployer_pack_entries() {
  local root="$1"
  local requested_target="$2"
  local pack
  local detected

  [[ -d "$root/providers/deployer" ]] || return 0

  while IFS= read -r pack; do
    detected="$(detect_target_from_pack "$pack" || true)"
    if [[ -n "$requested_target" ]]; then
      if [[ -z "$detected" || "$detected" == "$requested_target" ]]; then
        printf '%s|%s\n' "$requested_target" "$pack"
      fi
    elif [[ -n "$detected" ]]; then
      printf '%s|%s\n' "$detected" "$pack"
    fi
  done < <(find "$root/providers/deployer" -type f -name '*.gtpack' | sort)
}

has_matching_secrets_pack() {
  local root="$1"
  local target_name="$2"
  local pack
  local pack_name

  [[ -d "$root/providers/secrets" ]] || return 1

  while IFS= read -r pack; do
    pack_name="$(basename "$pack" | tr '[:upper:]' '[:lower:]')"
    case "$target_name:$pack_name" in
      aws:*aws*|aws:*secrets-manager*|aws:*secret-manager*)
        return 0
        ;;
      gcp:*gcp*|gcp:*google*|gcp:*secret-manager*)
        return 0
        ;;
      azure:*azure*|azure:*key-vault*|azure:*keyvault*|azure:*kv*)
        return 0
        ;;
      local:*dev*|local:*local*)
        return 0
        ;;
    esac
  done < <(find "$root/providers/secrets" -type f -name '*.gtpack' | sort)

  return 1
}

find_bundle_pack() {
  local root="$1"
  local pack

  if [[ -d "$root/packs" ]]; then
    pack="$(find "$root/packs" -maxdepth 1 -type f -name '*.gtpack' | sort | head -n 1)"
    if [[ -n "$pack" ]]; then
      echo "$pack"
      return 0
    fi
  fi

  return 1
}

bundle=""
target=""
deployer_pack=""
secrets_pack=""
tenant="demo"
team="default"
environment="dev"
mode="generate"
expect_secrets_provider=""
expect_no_runtime_secret_env=0
allow_runtime_secret_env=0
allow_apply=0
keep_temp=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle)
      bundle="${2:-}"
      shift 2
      ;;
    --target)
      target="${2:-}"
      shift 2
      ;;
    --deployer-pack)
      deployer_pack="${2:-}"
      shift 2
      ;;
    --secrets-pack)
      secrets_pack="${2:-}"
      shift 2
      ;;
    --tenant)
      tenant="${2:-}"
      shift 2
      ;;
    --team)
      team="${2:-}"
      shift 2
      ;;
    --environment)
      environment="${2:-}"
      shift 2
      ;;
    --mode)
      mode="${2:-}"
      shift 2
      ;;
    --expect-secrets-provider)
      expect_secrets_provider="${2:-}"
      shift 2
      ;;
    --expect-no-runtime-secret-env)
      expect_no_runtime_secret_env=1
      shift
      ;;
    --allow-runtime-secret-env)
      allow_runtime_secret_env=1
      shift
      ;;
    --allow-apply)
      allow_apply=1
      shift
      ;;
    --keep-temp)
      keep_temp=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    --*)
      die "unknown argument: $1"
      ;;
    *)
      if [[ -z "$bundle" ]]; then
        bundle="$1"
        shift
      else
        die "unknown argument: $1"
      fi
      ;;
  esac
done

[[ -n "$bundle" ]] || die "--bundle is required"
[[ -z "$target" || "$target" =~ ^(local|aws|gcp|azure)$ ]] || die "--target must be local, aws, gcp, or azure"
[[ -z "$deployer_pack" || -n "$target" ]] || die "--deployer-pack requires --target"
[[ "$mode" =~ ^(generate|local-smoke|apply)$ ]] || die "--mode must be generate, local-smoke, or apply"
[[ "$mode" != "apply" || "$allow_apply" == "1" ]] || die "--mode apply requires --allow-apply"
[[ -e "$bundle" ]] || die "bundle not found: $bundle"
[[ -z "$deployer_pack" || -f "$deployer_pack" ]] || die "deployer pack not found: $deployer_pack"
[[ -z "$secrets_pack" || -f "$secrets_pack" ]] || die "secrets pack not found: $secrets_pack"

bundle_bin="${GREENTIC_BUNDLE_BIN:-greentic-bundle}"
deployer_bin="${GREENTIC_DEPLOYER_BIN:-greentic-deployer}"
start_bin="${GREENTIC_START_BIN:-greentic-start}"

require_cmd "$bundle_bin"
require_cmd "$deployer_bin"
if [[ "$mode" == "local-smoke" ]]; then
  require_cmd "$start_bin"
  require_cmd curl
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/greentic-deploy-test.XXXXXX")"
if [[ "$keep_temp" == "0" ]]; then
  trap 'rm -rf "$work_dir"' EXIT
else
  trap 'echo "[test_deployment] kept temp workspace: '"$work_dir"'" >&2' EXIT
fi

bundle_root="$work_dir/bundle"
artifact="$work_dir/bundle.gtbundle"
deploy_output="$work_dir/deploy-output"

mkdir -p "$bundle_root" "$deploy_output"

if [[ -d "$bundle" ]]; then
  log "copying bundle directory to $bundle_root"
  cp -R "$bundle"/. "$bundle_root"/
else
  die "bundle archives are not mutable; pass a bundle directory when injecting or validating generated deployment contracts"
fi

if [[ -n "$deployer_pack" ]]; then
  log "injecting deployer pack"
  copy_file_into_dir "$deployer_pack" "$bundle_root/providers/deployer"
fi

if [[ -n "$secrets_pack" ]]; then
  log "injecting secrets pack"
  copy_file_into_dir "$secrets_pack" "$bundle_root/providers/secrets"
fi

log "building normalized bundle artifact"
"$bundle_bin" build --root "$bundle_root" --output "$artifact" >/dev/null
[[ -f "$artifact" ]] || die "bundle build did not create $artifact"

case "$(uname -s)" in
  Darwin)
    digest="sha256:$(shasum -a 256 "$artifact" | awk '{print $1}')"
    ;;
  *)
    digest="sha256:$(sha256sum "$artifact" | awk '{print $1}')"
    ;;
esac

selected_deployers=()
if [[ -n "$deployer_pack" ]]; then
  selected_deployers+=( "$target|$deployer_pack" )
else
  while IFS= read -r entry; do
    selected_deployers+=( "$entry" )
  done < <(find_deployer_pack_entries "$bundle_root" "$target")
fi

if [[ "${#selected_deployers[@]}" -eq 0 ]]; then
  if [[ -n "$target" ]]; then
    die "no deployer .gtpack found for target $target under $bundle_root/providers/deployer"
  fi
  die "no deployer .gtpack files with known targets found under $bundle_root/providers/deployer"
fi

for entry in "${selected_deployers[@]}"; do
  run_target="${entry%%|*}"
  run_deployer_pack="${entry#*|}"
  run_name="$(basename "$run_deployer_pack" .gtpack)"
  run_output="$deploy_output/$run_target-$run_name"
  expected_provider="$expect_secrets_provider"
  enforce_no_runtime_secret_env="$expect_no_runtime_secret_env"
  deployer_mode="$mode"

  if [[ "$deployer_mode" == "local-smoke" ]]; then
    deployer_mode="generate"
  fi

  if is_cloud_target "$run_target"; then
    [[ "$allow_runtime_secret_env" == "1" ]] || enforce_no_runtime_secret_env=1
    if [[ -z "$expected_provider" ]]; then
      expected_provider="$(expected_provider_for_target "$run_target")"
    fi
    if ! has_matching_secrets_pack "$bundle_root" "$run_target"; then
      log "no filename-matched secrets pack found for $run_target; generated binding must point to the target provider pack"
    fi
  fi

  deployer_help="$("$deployer_bin" "$run_target" "$deployer_mode" --help 2>/dev/null || true)"
  if grep -q -- '--pack-path' <<<"$deployer_help"; then
    deployer_args=(
      "$run_target"
      "$deployer_mode"
      --tenant "$tenant"
      --environment "$environment"
      --pack-path "$run_deployer_pack"
      --bundle-root "$bundle_root"
      --deploy-bundle-source "file://$artifact"
      --bundle-digest "$digest"
      --output-dir "$run_output"
    )
    captures_output=0
  elif grep -q -- '--bundle-pack' <<<"$deployer_help"; then
    bundle_pack="$(find_bundle_pack "$bundle_root" || true)"
    [[ -n "$bundle_pack" ]] || die "no app .gtpack found under $bundle_root/packs for deployer --bundle-pack"
    mkdir -p "$run_output"
    deployer_args=(
      "$run_target"
      "$deployer_mode"
      --tenant "$tenant"
      --environment "$environment"
      --bundle-pack "$bundle_pack"
      --bundle-root "$bundle_root"
      --bundle-source "file://$artifact"
      --bundle-digest "$digest"
      --provider-pack "$run_deployer_pack"
      --output json
    )
    captures_output=1
  else
    die "$deployer_bin $run_target $deployer_mode does not expose a recognized bundle/deployer pack interface"
  fi

  if [[ -n "${GREENTIC_DEPLOYER_EXTRA_ARGS:-}" ]]; then
    # shellcheck disable=SC2206
    extra_args=( ${GREENTIC_DEPLOYER_EXTRA_ARGS} )
    deployer_args+=( "${extra_args[@]}" )
  fi

  log "running deployer for $run_target: $deployer_bin ${deployer_args[*]}"
  if [[ "$captures_output" == "1" ]]; then
    if ! "$deployer_bin" "${deployer_args[@]}" >"$run_output/deployer.stdout" 2>"$run_output/deployer.stderr"; then
      cat "$run_output/deployer.stderr" >&2 || true
      die "deployer failed for $run_target"
    fi
  else
    "$deployer_bin" "${deployer_args[@]}"
  fi

  [[ -d "$run_output" ]] || die "deployment output directory missing: $run_output"
  if ! find "$run_output" -type f | grep -q .; then
    die "deployment output directory is empty: $run_output"
  fi

  output_roots=( "$run_output" )
  metadata_dir="$(deployer_metadata_dir "$run_output/deployer.stdout")"
  if [[ -n "$metadata_dir" && -d "$metadata_dir" ]]; then
    output_roots+=( "$metadata_dir" )
  fi

  if [[ -n "$expected_provider" ]]; then
    binding_file=""
    for output_root in "${output_roots[@]}"; do
      binding_file="$(find_binding_file "$output_root")"
      [[ -z "$binding_file" ]] || break
    done
    [[ -n "$binding_file" ]] || die "expected secrets provider binding for $run_target, but none was generated"
    json_field_equals "$binding_file" "schema_version" "greentic.secrets.binding.v1" \
      || die "binding $binding_file does not use schema_version greentic.secrets.binding.v1"
    json_field_equals "$binding_file" "provider_id" "$expected_provider" \
      || die "binding $binding_file provider_id does not match $expected_provider"
    if is_cloud_target "$run_target"; then
      binding_pack="$(json_field_value "$binding_file" "pack" || true)"
      [[ -n "$binding_pack" ]] || die "binding $binding_file does not name a secrets provider pack"
      if [[ "$binding_pack" = /* ]]; then
        binding_pack_path="$binding_pack"
      else
        binding_pack_path="$bundle_root/$binding_pack"
      fi
      [[ -f "$binding_pack_path" ]] || die "binding $binding_file points to missing secrets provider pack: $binding_pack"
    fi
    log "validated $run_target secrets provider binding: $binding_file"
  fi

  if [[ "$enforce_no_runtime_secret_env" == "1" ]]; then
    for output_root in "${output_roots[@]}"; do
      if grep -R --line-number 'GREENTIC_SECRET__' "$output_root" >/dev/null 2>&1; then
        grep -R --line-number 'GREENTIC_SECRET__' "$output_root" >&2 || true
        die "generated output for $run_target still injects per-secret runtime environment variables"
      fi
    done
  fi
done

if [[ "$mode" == "local-smoke" ]]; then
  log "starting local smoke runtime"
  "$start_bin" start --bundle "$bundle_root" --tenant "$tenant" --team "$team" >"$work_dir/local-smoke.log" 2>&1 &
  runtime_pid="$!"
  for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:8080/health" >/dev/null 2>&1; then
      break
    fi
    if ! kill -0 "$runtime_pid" >/dev/null 2>&1; then
      cat "$work_dir/local-smoke.log" >&2 || true
      die "runtime exited before becoming healthy"
    fi
    sleep 1
  done
  curl -fsS "http://127.0.0.1:8080/health" >/dev/null || {
    cat "$work_dir/local-smoke.log" >&2 || true
    die "runtime health probe failed"
  }
  "$start_bin" stop --bundle "$bundle_root" --tenant "$tenant" --team "$team" >/dev/null 2>&1 || true
  wait "$runtime_pid" >/dev/null 2>&1 || true
fi

log "deployment compatibility check passed"
