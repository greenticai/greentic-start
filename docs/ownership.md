# Lifecycle Ownership (Operator vs Start)

## Split

- `greentic-operator` owns wizard UX flow, user prompts, and planning.
- `greentic-start` owns runtime lifecycle execution: `start`, `up`, `stop`, and `restart`.
- `greentic-setup` is expected to own setup and bundle-specific flows outside `greentic-start`.

## Invocation Model

- `greentic-operator` is a passthrough for lifecycle commands and delegates runtime execution to `greentic-start`.
- `Wizard` remains in `greentic-operator`; when lifecycle is needed, it triggers `greentic-start`.
- `greentic-start` should stay focused on lifecycle runtime behavior, not Wizard or setup UX.

## Why this split

- Keeps UX and lifecycle execution responsibilities separate.
- Allows `greentic-start` to evolve lifecycle behavior independently.
- Reduces duplicated lifecycle logic in `greentic-operator`.
