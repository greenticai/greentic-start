# Release smoke test

What the unit and integration tests cannot show: behaviour of a built
`greentic-start` against real peers. Run it on the release binary
(`greentic-start-dev-<tag>-<target>.tgz` from the GitHub pre-release), not a
local `cargo run`, and record the tag and the SHA-256 of the tarball.

Everything below is a manual check. Each item states the expected result and
what a failure points at. Never paste a key, token or message body into the
notes; log lines carry classes and status codes only.

## 1. Jev routing tier

Config and rules: [fast2flow-jev.md](fast2flow-jev.md).

1. A router pack that declares Fast2Flow, with `jev.position: after_router`
   and a usable `api_key_secret` (`jev/...`). Send a free-text message the
   BM25 index cannot match.
   Expect: the route signal carries `source: "jev"`, the turn dispatches to
   the option Jev chose.
2. Same pack with `position: only`. Send a message BM25 *would* match.
   Expect: the Jev route wins; the BM25 `Dispatch` is discarded.
3. Remove the secret (or point `endpoint` at a closed loopback port).
   Expect: the turn falls to the LLM fallback / miss policy, one `warn` for
   the cause, and **no** return to BM25.
4. `enabled: false` in `bundle.yaml`.
   Expect: no request to the endpoint, nothing logged.

## 2. Secrets door hydration

Contract: [secrets-flow.md](secrets-flow.md#secrets-hydrated-from-the-admin-secrets_door).

1. A unit whose ingress document has `"secrets_door": true` and a reachable
   door. Expect: activation succeeds and the paths from `read-all` exist in the
   unit's dev store.
2. Door answering 403. Expect: activation fails at once (no retries), message
   says the token probably lacks the `secrets` purpose.
3. Door down on a **reload** after a successful hydration. Expect: the unit
   keeps the secrets already hydrated, with a warning. On a **cold start**
   with the door down: activation fails after 4 attempts.
4. Door answering 200 with an empty set. Expect: activation fails.

## 3. OAuth token refresh

Source: `src/oauth_secret_bridge.rs` (refreshes stored provider tokens through
the stored `refresh_token`). The `oauth_client_credentials` grant for outbound
routes lives in the runner dependency, not in this crate: smoke it as an
ordinary route and check only that it fetches a token and the call succeeds.

1. A provider connection whose access token has expired. Expect: one refresh
   against the token endpoint, the new token persisted, the call succeeds.
2. Make the token endpoint fail. Expect: the caller keeps the existing access
   token (logged as `skipping refresh ... last attempt failed recently`) and,
   for the next 60 s (`REFRESH_FAILURE_BACKOFF`), no further request reaches
   the token endpoint. After the window one retry is made. A refresh that hangs
   gives up after 30 s.

## 4. Tunnels and loopback trust

`--cloudflared on`, `--ngrok on` and `--gtunnel on` all turn loopback trust off
for the main listener; the loopback-only admin/console listener (main port + 1)
is what stays reachable to a local caller.

- With a tunnel on, `/chat` and `/workers/invoke` on the main port from
  loopback **without** a bearer: expect refusal.
- The same calls on the admin/console listener: expect them served.
- Confirm with whoever drives start (designer, deployer) that nothing calls it
  with `--gtunnel on` over loopback without a bearer.

## 5. SQL gateway

1. Start with the gateway's port already taken. Expect: boot aborts with a bind
   error (the ready signal is sent only after the bind).
2. Stop a foreground runtime, then start another in the same process or
   wait for the old one to exit. Expect: the port is free again within about
   5 s. If connections stay open past that, `stop` logs a warning and detaches
   the thread instead of hanging.

## 6. Admin mTLS

Covered end to end by `admin_server::mtls_tests`. Smoke check only: remove a
client with `POST /admin/v1/admins/remove` while it holds an open connection;
its next request must be `403`.

## Not covered by any test

- The 5 s detach path in item 5 (needs a live sqlx pool with an open
  connection).
- `token_url` is resolved and checked, but the connection is not pinned to the
  resolved IP (small TOCTOU).
- The pin Lua script is not Redis Cluster compatible (multi-key script across
  slots).
