# Git hooks

Project-local hooks to catch formatting/lint errors before they hit CI.

## Enable (one-time per clone)

```bash
git config core.hooksPath .githooks
```

This tells git to look in `.githooks/` instead of `.git/hooks/`. Once set, the hooks listed below run automatically.

## Hooks

### `pre-commit`

Runs on every `git commit`:

1. `rustfmt --check` on all staged `.rs` files — fails if any isn't formatted. Run `cargo fmt --all` and re-stage.
2. `cargo clippy --workspace --all-targets -- -D warnings` when a Rust file or `Cargo.{toml,lock}` is staged — fails if clippy reports any warnings.

Skip temporarily (not recommended): `git commit --no-verify`.
