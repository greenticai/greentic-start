# AW Hosted Runner Enablement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the deployed Cloud Run runner (`greentic-webchat`) to the `store-runs` admin-registry tenant so run-from-store works end-to-end.

**Architecture:** Pure ops change — no code. Discovery decides Path A (env vars only) vs Path B (rebuild image from `origin/research`, which already pins greentic-runner rev `74dff3f` with the admin reader). Token goes into Secret Manager, service update is gated on operator confirmation, acceptance is the store runbook §5 smoke checklist.

**Tech Stack:** gcloud (at `~/google-cloud-sdk/bin/gcloud`), Docker + Artifact Registry, Cloud Run, greentic-store API, greentic-designer-admin API.

**Spec:** `docs/superpowers/specs/2026-06-06-aw-hosted-runner-enablement-design.md`
**Companion runbook:** greentic-store-server `docs/run-from-store-runbook.md` (research branch)

---

## Conventions

All tasks use these shell variables, captured in Task 1. Re-export them at the
top of every shell session:

```bash
export GCLOUD="$HOME/google-cloud-sdk/bin/gcloud"
export REGION="europe-west1"          # confirm in Task 1 (deploy script default)
export SERVICE="greentic-webchat"
export PROJECT_ID="..."               # captured in Task 1
export ADMIN_URL="https://admin.research.greentic.cloud"   # confirm in Task 1
export STORE_URL="https://store.greentic.cloud"
```

**STOP rule:** any step whose output contradicts its "Expected" block → stop,
do not improvise, report back with the actual output.

---

### Task 1: Discovery — auth, project, deployed service state

**Files:** none (read-only investigation; findings recorded in the PR description / session notes)

- [ ] **Step 1: Verify gcloud auth and project access**

```bash
"$GCLOUD" auth list
"$GCLOUD" config get-value project
"$GCLOUD" projects list --format='value(projectId)' 2>/dev/null | head
```

Expected: an ACTIVE account; a project list that includes the Greentic
project. **Operator's personal GCP billing is closed — that is irrelevant if
the Greentic project is on its own billing.** If no Greentic project is
accessible, STOP: ask the operator to run `! ~/google-cloud-sdk/bin/gcloud auth login`
or provide the right account. Set `PROJECT_ID` from the result.

- [ ] **Step 2: Describe the Cloud Run service**

```bash
"$GCLOUD" run services describe "$SERVICE" \
  --project "$PROJECT_ID" --region "$REGION" \
  --format='yaml(spec.template.spec.containers[0].image,
                 spec.template.spec.containers[0].env,
                 spec.template.spec.serviceAccountName,
                 status.latestReadyRevisionName,status.url)'
```

If `NOT_FOUND`, retry with other plausible regions:
`for r in us-east1 us-central1 europe-west4; do "$GCLOUD" run services describe "$SERVICE" --project "$PROJECT_ID" --region "$r" --format='value(status.url)' 2>/dev/null && echo "REGION=$r"; done`

Expected: current image ref (Artifact Registry path + tag), env list, service
URL. Record: `DEPLOYED_IMAGE`, `SERVICE_URL`, `RUNTIME_SA`
(`serviceAccountName`), `PREVIOUS_REVISION` (`latestReadyRevisionName`, the
Task 4 rollback target), and whether these env vars exist:
`GREENTIC_AW_REDIS_URL`, `GREENTIC_AW_ADMIN_ENDPOINT`, `GREENTIC_AW_ADMIN_TOKEN`.

- [ ] **Step 3: Gate — `GREENTIC_AW_REDIS_URL`**

If `GREENTIC_AW_REDIS_URL` is **absent** from the env list: the runner will log
`DwAgent nodes disabled` no matter what we add. Locate the Redis instance
(`"$GCLOUD" redis instances list --project "$PROJECT_ID" --region "$REGION"`,
default instance name `greentic-webchat-redis` per
greentic-runner `deploy/gcp/webchat-ws.sh`) and add setting this var to the
Task 4 update command. If present: no action.

- [ ] **Step 4: Decide Path A vs Path B**

Determine whether `DEPLOYED_IMAGE` was built from greentic-start at/after
commit `88bc00e` ("git-dep runner research with agentic-worker" — the commit
that pins runner rev `74dff3f`):

```bash
git -C ~/Works/greentic/greentic-start log -1 --format='%ci' 88bc00e
"$GCLOUD" artifacts docker images describe "$DEPLOYED_IMAGE" \
  --project "$PROJECT_ID" --format='value(image_summary.upload_time)' 2>/dev/null \
|| "$GCLOUD" container images describe "$DEPLOYED_IMAGE" 2>/dev/null
```

Decision rule:
- Image upload time **after** the `88bc00e` commit date AND its tag matches the
  current research version line → **Path A** (skip Task 3).
- Anything else, or ambiguous → **Path B** (do Task 3). Rebuilding when not
  strictly needed is safe; deploying an image without the reader is the failure
  we are here to fix, so ambiguity resolves to B.

- [ ] **Step 5: Report discovery summary to operator**

Present: project, region, deployed image + upload time, env var status, chosen
path. Wait for acknowledgement before Task 2 (Task 2 involves issuing a
production credential).

---

### Task 2: Issue the `deployed-runner` tenant key (operator-assisted)

**Files:** none (credential handling only — the key must never be committed or echoed into logs)

- [ ] **Step 1: Check who can mint the key**

Issuing a key needs an **admin operator session** (session + CSRF) on
greentic-designer-admin. Claude cannot log in interactively. Ask the operator
to either:

1. Issue via admin UI: **Tenants → store-runs → API Keys → Issue New Key**,
   label `deployed-runner`, and paste the `gtc_live_*` value into the chat
   **once** (it is shown once by the admin; we move it straight into Secret
   Manager), or
2. Run the API call themselves with their session cookie:
   `POST $ADMIN_URL/api/admin/tenants/{store-runs-id}/api-keys` with
   `{"label":"deployed-runner"}`.

Expected: a 73-char `gtc_live_*` string in hand.

- [ ] **Step 2: Store the key in Secret Manager immediately**

```bash
printf '%s' 'gtc_live_…' | "$GCLOUD" secrets create greentic-aw-admin-token \
  --project "$PROJECT_ID" --replication-policy=automatic --data-file=-
# If the secret already exists, add a version instead:
# printf '%s' 'gtc_live_…' | "$GCLOUD" secrets versions add greentic-aw-admin-token --project "$PROJECT_ID" --data-file=-
```

Expected: `Created secret [greentic-aw-admin-token]` (or a new version). Then
grant the runner's runtime service account access (SA name from Task 1
describe output, field `spec.template.spec.serviceAccountName`):

```bash
"$GCLOUD" secrets add-iam-policy-binding greentic-aw-admin-token \
  --project "$PROJECT_ID" \
  --member "serviceAccount:${RUNTIME_SA}" \
  --role roles/secretmanager.secretAccessor
```

- [ ] **Step 3: Sanity-check the key against the admin registry**

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer gtc_live_…" \
  "$ADMIN_URL/api/v1/designer/agents/__nonexistent__"
```

Expected: `404` (authenticated, agent not found). `401`/`403` = bad key or
inactive tenant → STOP and re-issue.

---

### Task 3: Build + push image from `origin/research` (Path B only)

**Files:**
- Read: `Dockerfile.distroless` (no modification)

- [ ] **Step 1: Clean checkout of origin/research**

```bash
git -C ~/Works/greentic/greentic-start fetch origin
git -C ~/Works/greentic/greentic-start worktree add \
  ~/.cache/greentic-build/start-research origin/research
```

(Worktree under `~/.cache`, not `/tmp` — tmpfs quota kills builds.)

- [ ] **Step 2: Determine the new image tag**

Take the Artifact Registry repo path from `DEPLOYED_IMAGE` (everything before
the last `:`), and tag with the greentic-start version + short SHA:

```bash
cd ~/.cache/greentic-build/start-research
VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
SHORT_SHA=$(git rev-parse --short HEAD)
export NEW_IMAGE="${DEPLOYED_IMAGE%:*}:${VERSION}-aw-${SHORT_SHA}"
echo "$NEW_IMAGE"
```

Expected: e.g. `europe-west1-docker.pkg.dev/PROJECT/greentic/webchat:0.5.x-aw-1b92b1d`.

- [ ] **Step 3: Build**

```bash
cd ~/.cache/greentic-build/start-research
docker build -f Dockerfile.distroless -t "$NEW_IMAGE" .
```

Expected: successful build (release musl build of `greentic-start`; this is a
long compile, ~20–40 min cold). On Cargo errors mentioning
`greentic-extension-sdk-contract`, STOP — the `[patch.crates-io]` redirect in
this repo's Cargo.toml is load-bearing (see `docs/agentic-worker-bundle.md`);
do not "fix" by editing pins.

- [ ] **Step 4: Push**

```bash
"$GCLOUD" auth configure-docker "${NEW_IMAGE%%/*}" --quiet
docker push "$NEW_IMAGE"
```

Expected: push succeeds; digest printed.

- [ ] **Step 5: Clean up the worktree**

```bash
git -C ~/Works/greentic/greentic-start worktree remove ~/.cache/greentic-build/start-research
```

---

### Task 4: Production update (HARD CONFIRMATION GATE)

**Files:** none

- [ ] **Step 1: Present the exact update command to the operator and get an explicit "go"**

Show the operator the literal command about to run (with the token as a secret
reference, never inline) and the current `latestReadyRevisionName` (rollback
target). **Do not run it until the operator confirms in this conversation.**

- [ ] **Step 2: Apply the update**

Path A (env only):

```bash
"$GCLOUD" run services update "$SERVICE" \
  --project "$PROJECT_ID" --region "$REGION" \
  --update-env-vars "GREENTIC_AW_ADMIN_ENDPOINT=$ADMIN_URL" \
  --update-secrets "GREENTIC_AW_ADMIN_TOKEN=greentic-aw-admin-token:latest"
```

Path B adds `--image "$NEW_IMAGE"` to the same command. If Task 1 Step 3 found
`GREENTIC_AW_REDIS_URL` missing, append it to `--update-env-vars` with the
Redis instance address.

Expected: new revision deployed, `Service [greentic-webchat] revision … has
been deployed and is serving 100 percent of traffic.`

- [ ] **Step 3: Health check**

```bash
curl -s -o /dev/null -w '%{http_code}\n' "$SERVICE_URL/health" || curl -s -o /dev/null -w '%{http_code}\n' "$SERVICE_URL/"
"$GCLOUD" run services logs read "$SERVICE" --project "$PROJECT_ID" --region "$REGION" --limit 50
```

Expected: HTTP 200; startup logs show no panic; if agents file/registry
configured, look for `AW runtime constructed`. **Rollback if unhealthy:**

```bash
"$GCLOUD" run services update-traffic "$SERVICE" \
  --project "$PROJECT_ID" --region "$REGION" \
  --to-revisions "${PREVIOUS_REVISION}=100"
```

---

### Task 5: End-to-end smoke (store runbook §5)

**Files:** none

- [ ] **Step 1: Pick a published, non-yanked worker**

```bash
curl -s "$STORE_URL/api/v1/agentic-workers?page=1" | head -c 2000
```

Expected: JSON list (paginated 20/page). Record a `{name, version}` pair. If
the list is empty, STOP: ask the operator which worker to publish first.

- [ ] **Step 2: Trigger the run (operator-assisted auth)**

Needs a store-publisher credential (JWT session or `gts_` API token) — ask the
operator to provide a `gts_` token or run the curl themselves:

```bash
curl -s -X POST -H "Authorization: Bearer gts_…" \
  "$STORE_URL/api/v1/agentic-workers/{name}/{version}/run"
```

Expected: `200` with `agents[]` (each: `agent_id` namespaced
`{worker-name}.{agent-id}`, `admin_version`, optional `chat_url`).
`503` = store env regression; `409` = picked a byo-required worker (pick
another); `502` = admin unreachable from store.

- [ ] **Step 3: Confirm registration in the admin registry**

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer gtc_live_…(deployed-runner key)" \
  "$ADMIN_URL/api/v1/designer/agents/{worker-name}.{agent-id}"
```

Expected: `200`.

- [ ] **Step 4: Confirm the runner resolves it**

Drive one chat turn against the runner (open `chat_url` from Step 2 if
`RUN_CHAT_URL_TEMPLATE` is set; otherwise use the service's webchat UI at
`SERVICE_URL` pointed at the agent id), then:

```bash
"$GCLOUD" run services logs read "$SERVICE" --project "$PROJECT_ID" --region "$REGION" --limit 100 | grep -iE "designer/agents|401|403"
```

Expected: a registry fetch line for the agent id, **no 401/403**.

- [ ] **Step 5: byo-required negative test (if such a worker exists)**

`POST …/run` on a worker whose `secrets-policy.json` has any `byo-required`
key. Expected: `409`.

- [ ] **Step 6: Record results**

All five outcomes go into the PR description and the final report. Any failure
→ systematic-debugging, not ad-hoc retries.

---

### Task 6: Land the docs branch

**Files:**
- Already committed: `docs/superpowers/specs/2026-06-06-aw-hosted-runner-enablement-design.md`
- This plan: `docs/superpowers/plans/2026-06-06-aw-hosted-runner-enablement.md`

- [ ] **Step 1: Commit the plan**

```bash
cd ~/Works/greentic/greentic-start
git add docs/superpowers/plans/2026-06-06-aw-hosted-runner-enablement.md
git commit -m "docs: implementation plan for AW hosted runner enablement"
```

- [ ] **Step 2: Append the smoke outcome to the spec** (one-line status flip: `Status: Approved` → `Status: Executed YYYY-MM-DD`, plus discovery facts: image, path taken, region)

- [ ] **Step 3: Push and open PR to `research`**

```bash
git push -u origin docs/aw-hosted-runner-enablement
gh pr create --repo greenticai/greentic-start --base research \
  --title "docs: AW hosted runner enablement (run-from-store E2E)" \
  --body "Spec + plan + execution record for wiring the deployed runner to the store-runs admin tenant. No code changes."
```

(Verify the org first: `git remote -v` — greentic-start may live in
`greenticai` or `greentic-biz`.) No Claude attribution trailers on commits or
the PR body.

Expected: PR open against `research`; verify `headRefOid` matches local
`git rev-parse HEAD` before any merge.
