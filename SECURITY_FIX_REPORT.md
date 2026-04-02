# SECURITY_FIX_REPORT

## Summary
Remediated all open CodeQL alerts in this PR scope for `rust/hard-coded-cryptographic-value` by removing hard-coded cryptographic key literals in `src/directline.rs` tests.

## Alerts Addressed
1. Alert #3 (`src/directline.rs:304`) `rust/hard-coded-cryptographic-value`
2. Alert #4 (`src/directline.rs:311`) `rust/hard-coded-cryptographic-value`
3. Alert #5 (`src/directline.rs:389`) `rust/hard-coded-cryptographic-value`

## Root Cause
Test code used the literal key `b"secret"` for JWT signing in multiple places. CodeQL flags hard-coded key material regardless of test/runtime context.

## Fixes Applied
### File: `src/directline.rs`
- Added `rand::RngExt` import in test module.
- Added helper `random_signing_key() -> [u8; 32]` that generates key bytes at runtime using `rand::rng().fill(&mut key)`.
- Replaced hard-coded key literals with generated key material:
  - `generate_jwt(b"secret", ...)` -> `generate_jwt(&signing_key, ...)`
  - `handle_create_conversation(..., b"secret")` -> `handle_create_conversation(..., &signing_key)`

## Security Impact
- Eliminates embedded cryptographic key literals from source.
- Aligns with CWE-259/CWE-321/CWE-798 guidance and CodeQL rule requirements.
- Preserves existing behavior while removing vulnerable pattern.

## Validation
- Static validation: searched updated file to confirm no remaining `b"secret"` literals in `src/directline.rs`.
- Dynamic validation: unable to execute `cargo test` in this CI sandbox due read-only rustup temp path:
  - `error: could not create temp file /home/runner/.rustup/tmp/...: Read-only file system (os error 30)`

## Minimality Notes
- Changes are intentionally scoped to the exact flagged locations and supporting test helper code only.
- No production runtime cryptographic flow changes were introduced.
