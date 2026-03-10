# greentic-start Audit Notes

## Scope

This document tracks security and reliability audit notes specific to `greentic-start`.
It is intentionally focused on lifecycle delegation/start-stop behavior and release hygiene.

## Current Surface

- Crate type: library + thin binary wrapper.
- Primary entrypoint: `greentic_start::run_from_env` in `src/lib.rs`.
- CLI compatibility layer normalizes legacy `demo ...` forms.
- Runtime orchestration stays local to `greentic-start`; `greentic-operator` delegates lifecycle into this crate.

## Key Operational Risks to Re-check

- Start/restart/stop semantics parity with historical `greentic-operator demo start`.
- Packaging/release reproducibility across Linux/macOS/Windows artifact matrix.

## Audit Checklist (per release)

- Run `bash ci/local_check.sh`.
- Confirm `publish.yml` tag/version guard (`vX.Y.Z` == `Cargo.toml`).
- Confirm `cargo publish --dry-run -p greentic-start` (networked environment).
- Verify generated release artifacts and checksums for all configured targets.
- Smoke test lifecycle commands against a real demo config:
  - `start`
  - `restart`
  - `stop`

## Notes

- In offline CI/dev environments, package/publish dry-run can be skipped only for explicit network resolution failures (handled by `ci/local_check.sh`).
