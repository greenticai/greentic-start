# SQL Gateway — greentic-start injection (ready-to-apply draft)

**Status:** DRAFT — blocked on publishing `greentic-runner-host` (with the `sql`
module + `sql::routes::router()` helper). Apply after that version is published
and greentic-start's dependency is bumped. Spec/plan:
`greentic-designer-extensions/docs/superpowers/{specs,plans}/2026-05-31-greentic-sql-gateway-runtime*`.

## Serving topology — RESOLVED (was the open question)
Traced live: **`greentic_runner_host::HostServer` is NOT used by `gtc start`** — it's
only instantiated in the standalone `greentic-runner` binary (`greentic-runner-host/src/lib.rs`
`run()`). `gtc start` (greentic-start) stands up two **hyper** (non-axum) servers —
`HttpIngressServer` (`src/http_ingress/`, ~:8080) and `AdminServer` (mTLS, ~:9443) —
and `DemoRunnerHost` (`src/runner_host/`) is a WASM executor with **no HTTP server**.
So the `/sql` routes registered on `HostServer` (Task 6) are NOT reachable in a bundle.

**Resolution: a dedicated localhost axum server in greentic-start** serving the SQL
gateway via the reusable `greentic_runner_host::sql::routes::router(gateway)` helper
(added on `research`, commit `5490ca7`). Bind it to **127.0.0.1** (internal only — the
in-process design extension reaches it over localhost; no external exposure, which
also sidesteps the network-allowlist worry). HostServer keeps its routes for the
standalone runner binary; greentic-start gets its own tiny server.

## Current state (on `research`)
- `greentic-runner-host` (research, `a504139` + `5490ca7`): full `src/sql/` gateway,
  `sql::routes::router(gateway) -> axum::Router`, `SqlGateway`, `HostServer::with_sql`.
  25 sql tests pass.
- `greentic-start` (research, `fe0bdb6`): re-declared `SqlConfig`/`SqlConnectionConfig`/
  `SqlEngine` in `src/config.rs` + `DemoConfig.sql: Option<SqlConfig>`. Depends on the
  **published** `greentic-runner-host` crate (not local).

## Post-publish steps (apply in order)

### 1. Switch to the crate types + bump the dep
- Bump the `greentic-runner-host` dependency in `greentic-start/Cargo.toml` to the
  newly published version (the one containing the `sql` module + `router()`).
- Delete the re-declared `SqlConfig`/`SqlConnectionConfig`/`SqlEngine` in `src/config.rs`;
  change `DemoConfig.sql` to `Option<greentic_runner_host::sql::config::SqlConfig>`.

### 2. Add a gateway port to the `sql:` config
Add `port: Option<u16>` to `SqlConfig` (default e.g. 8765) so the bundle controls the
local gateway port. (If editing the crate's `SqlConfig` is undesirable, keep the port
in greentic-start's bundle/service config instead.)

### 3. Build the gateway from config + secrets
Near the runner-host construction in `src/runtime.rs` (after
`secrets_gate::resolve_secrets_manager(...)` ~line 785), build the gateway. Match the
live secrets-handle API (find its `get`/`resolve` method):
```rust
let sql_gateway = if let Some(sql_cfg) = demo_config.sql.as_ref() {
    let token = secrets_handle.resolve(&sql_cfg.auth_token_secret).await?;
    if token.is_empty() && !sql_cfg.connections.is_empty() {
        anyhow::bail!("sql.auth_token_secret resolved empty — refusing to start SQL gateway");
    }
    let mut conns = std::collections::HashMap::new();
    for (name, c) in &sql_cfg.connections {
        let dsn = secrets_handle.resolve(&c.dsn_secret).await?;
        match greentic_runner_host::sql::pool::build(c.engine, &dsn, c.read_only).await {
            Ok(pool) => { conns.insert(name.clone(),
                greentic_runner_host::sql::SqlConnection { engine: c.engine, pool }); }
            Err(e) => tracing::warn!("sql gateway: skip connection {name}: {e}"),
        }
    }
    Some((greentic_runner_host::sql::SqlGateway::new(conns, token),
          sql_cfg.port.unwrap_or(8765)))
} else { None };
```

### 4. Spawn the dedicated localhost axum server
Alongside where `HttpIngressServer`/`AdminServer` are spawned (`src/runtime.rs` ~822):
```rust
if let Some((gateway, port)) = sql_gateway {
    let app = greentic_runner_host::sql::routes::router(gateway);
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
            Ok(listener) => {
                tracing::info!("sql gateway listening on 127.0.0.1:{port}");
                if let Err(e) = axum::serve(listener, app).await {
                    tracing::error!("sql gateway server error: {e}");
                }
            }
            Err(e) => tracing::error!("sql gateway bind 127.0.0.1:{port}: {e}"),
        }
    });
}
```
(Requires `axum` + `tokio` net in greentic-start — both are already deps; confirm.)

### 5. Extension wiring (operator config)
- `greentic.sql` extension's `secret://sql/connections` registry `base_url` per
  connection → `http://127.0.0.1:<port>/sql/<conn>` (matching step 2's port).
- Same token at `secret://sql/<name>/token` as `auth_token_secret`.
- The extension's host-`http` already allows `127.0.0.1`/`localhost`
  (net_allowlist in greentic-start's `runner_exec.rs`), so no extra allow-list needed
  for the localhost gateway.

## Validation
- `gtc start` a bundle with a `sql:` block + a temp SQLite DSN in secrets.
- `curl -H "Authorization: Bearer <token>" http://127.0.0.1:<port>/sql/<conn>/schema`.
- End-to-end via the `greentic.sql` extension's `sql_ask`.

## Known follow-ups (from review)
- PG/MySQL compile-verified but untested (no live servers during build).
- Empty-result → empty `columns` (v1 limitation).
- Remove the `SqlConfig` duplication once on the published crate type (step 1).
