# Hosted runner enablement — devops handoff

> **Audience:** whoever operates the production hosted runner (the
> `greentic-webchat` Cloud Run service named in the store runbook, or its
> actual equivalent).
> **Goal:** complete the runner half of run-from-store. The store half is live:
> `POST /api/v1/agentic-workers/{name}/{version}/run` registers agents into the
> shared `store-runs` admin tenant. The deployed runner must now resolve those
> agents from the admin registry.
> **Authoritative companion:** greentic-store-server
> `docs/run-from-store-runbook.md` (research branch) — this doc executes its
> Step 4 and Step 5.

## State found during prep (2026-06-06)

- No `greentic-webchat` Cloud Run service was visible from the preparing
  operator's GCP access (~35 projects scanned, Cloud Run API disabled on
  `greentic-489320`). **Devops: confirm where the hosted runner actually runs
  (or that it has not been deployed yet).** If it does not exist,
  greentic-runner `deploy/gcp/webchat-ws.sh` provisions the GCP variant
  (VPC, Memorystore Redis, SA, Cloud Run).
- `ghcr.io/greenticai/greentic-start-distroless:latest` is built from `main`
  (v0.5.38) and **does not contain the agentic-worker feature at all** — do
  not use it for this.

## 1. Image (ready)

Use the research-line image:

```
ghcr.io/greenticai/greentic-start-distroless:research
```

Built from greentic-start `research` @ `00c38d6` (runner git pin `74dff3f`,
`features = ["agentic-worker"]`, includes the admin-registry HTTP config
provider). Published by `publish-distroless` workflow dispatch
(actions/runs/27061798634; tag scheme fixed in PR #235 so branch builds never
move `:latest`).

## 2. Issue the runner's tenant key (do this yourselves; do not reuse other keys)

1. Admin UI (`https://admin.research.greentic.cloud`): **Tenants → store-runs
   → API Keys → Issue New Key**, label **`deployed-runner`**.
   (API: `POST /api/admin/tenants/{id}/api-keys`, session + CSRF.)
2. The `gtc_live_*` value is shown **once**. Put it straight into your secret
   store (Secret Manager / SSM); never in plaintext env or logs.
3. Keep it separate from the `deployed-store-server` key so the two consumers
   rotate independently. Rotation order: issue new → update consumer →
   revoke old. Revoking first breaks live runs.

Sanity check (expect `404` = authenticated; `401`/`403` = bad key):

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer gtc_live_…" \
  https://admin.research.greentic.cloud/api/v1/designer/agents/__nonexistent__
```

## 3. Runner env

| Env var | Value | Notes |
| --- | --- | --- |
| `GREENTIC_AW_REDIS_URL` | redis endpoint | **Hard gate.** If unset, the runner logs `DwAgent nodes disabled` and the admin vars do nothing. |
| `GREENTIC_AW_ADMIN_ENDPOINT` | `https://admin.research.greentic.cloud` | same base URL as the store's `ADMIN_REGISTRY_URL` |
| `GREENTIC_AW_ADMIN_TOKEN` | the `deployed-runner` key | secret binding, not plaintext |

Both admin vars set → the runtime layers an HTTP config provider fetching
`GET {endpoint}/api/v1/designer/agents/{agent_id}`. Either missing → local /
manifest agents only (graceful degradation, no outage). LLM execution uses the
`store-runs` tenant's configured LLM providers (admin-side), not runner env.

Cloud Run example:

```bash
gcloud run services update greentic-webchat --region <REGION> \
  --image ghcr.io/greenticai/greentic-start-distroless:research \
  --update-env-vars GREENTIC_AW_ADMIN_ENDPOINT=https://admin.research.greentic.cloud \
  --update-secrets GREENTIC_AW_ADMIN_TOKEN=<secret-name>:latest
```

Rollback = shift traffic back to the previous revision.

## 4. Smoke (acceptance — store runbook §5)

1. `POST /api/v1/agentic-workers/{name}/{version}/run` (store-publisher auth)
   → `200` with `agents[]` (ids namespaced `{worker}.{agent}`).
2. `GET https://admin.research.greentic.cloud/api/v1/designer/agents/{worker}.{agent}`
   with the tenant key → `200`.
3. Drive one chat turn; runner logs show the registry fetch with **no
   `401`/`403`**.
4. If `RUN_CHAT_URL_TEMPLATE` is set store-side, the returned `chat_url` loads.
5. A worker with any `byo-required` secret → run returns `409` (by design).

`scripts/smoke-agent-deploy.sh` in this repo automates the registry-contract
half.

## 5. Failure semantics quick reference

| Symptom | Meaning |
| --- | --- |
| `503` from run endpoint | store-side env regression (`ADMIN_REGISTRY_URL`/`_TOKEN`) |
| `401`/`403` in runner logs | bad/revoked tenant key or inactive tenant |
| `DwAgent nodes disabled` in runner logs | `GREENTIC_AW_REDIS_URL` unset |
| Agents register but chat fails at LLM call | no LLM provider on the `store-runs` tenant (admin UI → LLM Providers) |
