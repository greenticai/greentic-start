# AW Hosted Runner Enablement (run-from-store E2E) — Design

- **Date:** 2026-06-06
- **Status:** Executed 2026-06-06 as **prep + handoff** (see Execution record)
- **Scope:** Operational enablement of the deployed hosted runner (Cloud Run
  `greentic-webchat`) so that agents registered by the store's run-from-store
  hand-off (M5) are resolvable and executable. No code changes expected.
- **Companion docs:**
  - Store-side runbook: `greentic-store-server` `docs/run-from-store-runbook.md`
    (research branch) — this design executes its Step 4 ("Wire up the runner")
    plus the smoke checklist in its Step 5.
  - `docs/agentic-worker-bundle.md` (this repo) — runner pin and AW env vars.

## Background

Run-from-store (M5) is live store-side: `POST
/api/v1/agentic-workers/{name}/{version}/run` extracts per-agent configs from a
published `.gtpack` and registers them into the shared `store-runs` tenant of
the admin registry (`greentic-designer-admin`). The missing half is the
deployed runner: it must layer the admin-registry HTTP config provider
(`GET {endpoint}/api/v1/designer/agents/{agent_id}`) so registered agents
actually resolve at chat time.

The runner-side reader exists since greentic-runner rev `74dff3f` (successor of
the `aw-overlay-v1` tag), which this repo already pins via git dep with
`features = ["agentic-worker"]`. The deployed Cloud Run image may predate that
rev, in which case it must be rebuilt — discovery decides.

## Goal

A store user clicks "Run" on a published agentic worker and can chat with it on
the hosted runner, with the agent config served from the `store-runs` admin
tenant. Acceptance = store runbook §5 smoke checklist passes.

## Approach decision

Discovery-first; pick the cheapest sufficient path:

- **A. Env-vars only** — if the deployed image was built from greentic-start at
  a commit whose runner pin ≥ `74dff3f`, only the two env vars are missing.
- **B. Rebuild from `origin/research` as-is + env vars** — if the deployed
  image predates the pin. Uses `Dockerfile.distroless` with the current,
  already-reviewed pin. No code or pin changes.
- **C (rejected for this work):** bumping the runner pin to the research tip
  (`1b92b1d`, token-streaming opt-in) is a code change with its own CI cycle —
  tracked as follow-up, not part of enablement.

## Plan of record

1. **Discovery.** Verify gcloud auth and access to the Greentic GCP project
   (note: operator's personal billing account is closed; the Greentic project
   must be confirmed independently). `gcloud run services describe
   greentic-webchat`: capture current image, revision, and env.
   **Hard gate:** `GREENTIC_AW_REDIS_URL` must already be set on the service —
   without it the runner logs `DwAgent nodes disabled` regardless of admin
   vars. If absent, setting it joins this change.
2. **Credentials.** Issue a dedicated `deployed-runner` API key on the
   `store-runs` tenant (admin API; the `gtc_live_*` value is shown once).
   Do not reuse the `deployed-store-server` key — independent rotation.
3. **Apply A or B** per discovery. Prefer a secret binding for
   `GREENTIC_AW_ADMIN_TOKEN` over plaintext env where the deploy path
   supports it.
4. **Deploy.** Confirm with the operator immediately before the production
   update, then `gcloud run services update greentic-webchat
   --update-env-vars GREENTIC_AW_ADMIN_ENDPOINT=...,GREENTIC_AW_ADMIN_TOKEN=...`
   (plus `--image` when path B). Rollback = route traffic back to the previous
   Cloud Run revision.
5. **Smoke.** Store runbook §5: trigger a run on a published worker; confirm
   the agent registers under `store-runs` (`{worker-name}.{agent-id}`
   namespacing); confirm runner logs show the registry fetch with no
   `401`/`403`; open `chat_url` if a template is set; confirm a
   `byo-required` worker returns `409`.

## Failure modes

- **Either admin env var missing/typo'd** → runner serves local/manifest
  agents only; graceful degradation, no outage. Fix-forward by re-running the
  env update.
- **401/403 in runner logs** → bad/revoked token or inactive tenant; rotate
  per runbook ("issue new key → update both consumers → revoke old", never
  revoke first).
- **Registry unreachable from runner** → agents fail to resolve at chat time;
  store-side `/run` keeps returning 200 (registration is admin-side). Surface
  via runner logs during smoke.

## Testing

No new automated tests: zero code change (paths A/B). The smoke checklist is
the acceptance gate; `scripts/smoke-agent-deploy.sh` already automates the
registry-contract half and can be reused during step 5.

## Execution record (2026-06-06)

Discovery overturned the runbook's assumption that a deployed Cloud Run
`greentic-webchat` service exists and is reachable from this operator's
credentials:

- No Cloud Run service named `greentic-webchat` in any of the ~35 GCP projects
  visible to the preparing operator; `greentic-489320` has the Cloud Run and
  Artifact Registry APIs disabled and none of the prerequisite infra (VPC,
  Memorystore, runtime SA).
- `ghcr.io/greenticai/greentic-start-distroless:latest` is built from `main`
  (v0.5.38) and contains no agentic-worker support; the research line had
  never been image-built.

Per operator decision, scope changed from "deploy + smoke" to **prep +
handoff**:

- Published `ghcr.io/greenticai/greentic-start-distroless:research` (research
  @ `00c38d6`, runner pin `74dff3f`) via `publish-distroless`
  workflow_dispatch. Two latent CI bugs fixed on the way (PR #235): `:latest`
  clobber on branch dispatch, and the Dockerfile bench-strip perl hack that
  broke against the reformatted research manifest.
- Wrote `docs/aw-hosted-runner-handoff.md` — image ref, key issuance for the
  `store-runs` tenant, env table (incl. the `GREENTIC_AW_REDIS_URL` hard
  gate), smoke checklist, failure semantics. Tasks 2, 4, 5 of the plan
  transfer to the infra owner via that doc.

## Follow-ups (out of scope)

- Bump the runner git pin to the research tip (token-streaming opt-in) and
  redeploy — separate PR with CI.
- Per-worker isolation in the shared `store-runs` tenant (runbook gotcha).
