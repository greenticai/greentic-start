# SQL Gateway — greentic-start injection (ready-to-apply draft)

**Status:** DRAFT — blocked on publishing `greentic-runner-host` with the `sql`
module. Do not apply until that crate version is published and greentic-start's
dependency is bumped. See spec/plan:
`greentic-designer-extensions/docs/superpowers/{specs,plans}/2026-05-31-greentic-sql-gateway-runtime*`.

## Current state (on `research`)
- `greentic-runner-host` (branch merged to `research`, commit `a504139`) has the
  full `src/sql/` gateway + `/sql/<conn>/{schema,query}` routes registered on
  **`HostServer`** (`src/runner/mod.rs`) + `SqlGateway` in `ServerState` +
  `HostServer::with_sql(...)` injection.
- `greentic-start` (research) has a **re-declared** `SqlConfig`/`SqlConnectionConfig`/
  `SqlEngine` in `src/config.rs` (mirrors `greentic_runner_host::sql::config`) and a
  `DemoConfig.sql: Option<SqlConfig>` field. It depends on the **published**
  `greentic-runner-host` crate (a `1.1.0-dev.<id>` version), NOT the local checkout.

## ⚠️ OPEN QUESTION — resolve FIRST (blocks reachability)
greentic-start does **not** construct `greentic_runner_host::HostServer`. It boots
its own **`DemoRunnerHost`** (`src/runner_host/`) plus ingress/admin servers
(`src/runtime.rs`, `src/admin_server.rs`). The `/sql/<conn>/...` routes were
registered on `HostServer`, which may **not** be the HTTP server the bundle
exposes / that the `greentic.sql` extension's host-`http` calls can reach.

Before the gateway works end-to-end, confirm and reconcile ONE of:
1. The bundle deployment actually serves `HostServer` somewhere (then injecting via
   `HostServer::with_sql(...)` is enough — find that construction site), OR
2. The `/sql` routes must be mounted on the server greentic-start really exposes
   (DemoRunnerHost's router / the ingress axum app). In that case, expose a small
   helper from `greentic-runner-host` to build an `axum::Router` for the SQL
   gateway (e.g. `sql::routes::router(gateway) -> Router`) and `.merge()` it into
   greentic-start's serving router, instead of relying on `HostServer`.

Recommended: add `pub fn sql::routes::router(gateway: SqlGateway) -> axum::Router`
to greentic-runner-host (a 5-line helper wrapping the two `.route(...)` calls
with `.with_state(gateway)`), so BOTH `HostServer` and greentic-start's own server
can mount it. Do this in the same runner-host change that gets published.

## Post-publish greentic-start wiring (apply after the above is resolved + published)

1. **Switch to the crate type** — delete the re-declared `SqlConfig`/`SqlConnectionConfig`/
   `SqlEngine` in `src/config.rs` and change `DemoConfig.sql` to
   `Option<greentic_runner_host::sql::config::SqlConfig>`. Bump the
   `greentic-runner-host` dependency to the newly published version.

2. **Build the gateway from config + secrets** — near where the runner host is
   constructed (`src/runtime.rs`, after `secrets_gate::resolve_secrets_manager(...)`
   at ~line 785), add (pseudocode against the live secrets API):
   ```rust
   let sql_gateway = if let Some(sql_cfg) = demo_config.sql.as_ref() {
       let token = secrets_handle.resolve(&sql_cfg.auth_token_secret).await?;
       let mut conns = std::collections::HashMap::new();
       for (name, c) in &sql_cfg.connections {
           let dsn = secrets_handle.resolve(&c.dsn_secret).await?;
           match greentic_runner_host::sql::pool::build(c.engine, &dsn, c.read_only).await {
               Ok(pool) => { conns.insert(name.clone(),
                   greentic_runner_host::sql::SqlConnection { engine: c.engine, pool }); }
               Err(e) => tracing::warn!("sql gateway: skip connection {name}: {e}"),
           }
       }
       Some(greentic_runner_host::sql::SqlGateway::new(conns, token))
   } else { None };
   ```
   (Match the live secrets-resolution method name — `resolve_secrets_manager` returns
   a handle; find its `get`/`resolve` method.)

3. **Inject** — pass `sql_gateway` into whichever server serves `/sql` (per the OPEN
   QUESTION resolution): either `HostServer::with_sql(..., sql_gateway)` or
   `.merge(sql::routes::router(gw))` into greentic-start's router.

4. **Startup guard** (security follow-up from review) — refuse to start the gateway
   if the resolved `auth_token` is empty while `connections` is non-empty:
   ```rust
   if let Some(gw_cfg) = demo_config.sql.as_ref() {
       if token.is_empty() && !gw_cfg.connections.is_empty() {
           anyhow::bail!("sql.auth_token_secret resolved empty — refusing to start SQL gateway");
       }
   }
   ```

5. **Extension wiring** — the operator sets the `greentic.sql` extension's
   `secret://sql/connections` registry `base_url` to `http://<runner-host>:<port>/sql/<conn>`
   and stores the same token at `secret://sql/<name>/token`. Ensure the extension's
   `permissions.network` (or a runtime host-override) permits the runner's own host.

## Validation after wiring
- Build greentic-start; `gtc start` a bundle with a `sql:` block + a temp SQLite DSN.
- `curl -H "Authorization: Bearer <token>" http://localhost:<port>/sql/<conn>/schema`.
- Then end-to-end via the `greentic.sql` extension's `sql_ask`.

## Known follow-ups (carried from the review)
- PG/MySQL are compile-verified but untested (no live servers during build).
- Empty-result → empty `columns` (v1 limitation).
- Remove the `SqlConfig` duplication (step 1) once published.
