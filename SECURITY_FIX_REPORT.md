## Security Fix Report

Date: 2026-03-27 (UTC)
Role: Security Reviewer (CI)

### Inputs Reviewed
- Dependabot alerts: `[]`
- Code scanning alerts: `[]`
- New PR dependency vulnerabilities:
  - `rustls-webpki@0.102.8` (Cargo.lock, runtime)
  - Severity: `moderate`
  - Advisory: `GHSA-pwjx-qhcg-rvj4`
  - Summary: CRL distribution point matching logic issue in `webpki`

### Findings
1. No active Dependabot or code scanning alerts were provided.
2. One PR-introduced vulnerable dependency was present in `Cargo.lock`:
   - `rustls-webpki@0.102.8`
3. Vulnerable chain traced to:
   - `greentic-runner-host 0.4.70` -> `wasmtime-wasi-http` / `wasmtime-wasi-tls`
   - `wasmtime-wasi-http` / `wasmtime-wasi-tls` -> `tokio-rustls 0.25.0` -> `rustls 0.22.4` -> `rustls-webpki 0.102.8`

### Remediation Applied
Updated `Cargo.lock` to remove the vulnerable chain by rolling back the introducing transitive update:
- `greentic-runner-desktop` downgraded: `0.4.70` -> `0.4.69`
- `greentic-runner-host` downgraded: `0.4.70` -> `0.4.69`
- Removed from lock graph:
  - `wasmtime-wasi-http 43.0.0`
  - `wasmtime-wasi-tls 43.0.0`
  - `tokio-rustls 0.25.0`
  - `rustls 0.22.4`
  - `rustls-webpki 0.102.8`

Resulting `rustls-webpki` in lockfile:
- `rustls-webpki 0.103.10` only

### Verification
Executed checks:
- `rg -n '0\.22\.4|tokio-rustls 0\.25\.0|wasmtime-wasi-http|wasmtime-wasi-tls' Cargo.lock` -> no matches
- `rg -n 'version = "0\.102\.8"' Cargo.lock` -> no matches
- `rg -n 'name = "rustls-webpki"' Cargo.lock` -> only one package entry remains (`0.103.10`)

### Notes / Constraints
- Cargo-based resolution checks (`cargo tree`, `cargo audit`) could not be run in this CI sandbox because external network/toolchain sync is blocked.
- Remediation was performed via deterministic `Cargo.lock` edits with targeted dependency rollback.

### Files Changed
- `Cargo.lock`
- `SECURITY_FIX_REPORT.md`
