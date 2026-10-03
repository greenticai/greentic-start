# Runtime release registration (unarmed)

The `publish-distroless` workflow (`.github/workflows/distroless.yml`, `v*`
tags) builds the multi-arch `greentic-start-distroless` image. Its `merge` job
also prepares a **platform release** for the admin's release catalogue so the
unified update flow can roll the runtime image out.

## What it does

1. Resolves the image **index** digest (`docker buildx imagetools inspect`).
2. `ci/register_runtime_release.py` builds `release-request.json`:
   `kind=platform`, `publisher=github:greenticai/greentic-start`,
   `name=greentic-start`, `version` = tag without `v`, and exactly ONE
   artifact (`greentic-start-distroless`, OCI image index media type, the
   index digest, source `ghcr.io/greenticai/greentic-start-distroless`).
   Exactly one runtime-image artifact is what makes the release executable.
3. Uploads `release-request.json` as the `release-request` workflow artifact
   (always, even on failure).
4. POSTs it to `{RELEASE_ADMIN_URL}/api/v1/releases` with
   `Authorization: Bearer $RELEASE_PUBLISHER_KEY` and
   `Idempotency-Key: greentic-start-distroless-<version>`. HTTP 200 (same
   content) and 201 are success.

## Why it is unarmed

Nothing is sent unless BOTH repository secrets `RELEASE_ADMIN_URL` and
`RELEASE_PUBLISHER_KEY` exist AND the `register_dry_run` dispatch input is not
`true` (it is empty on a tag push). With either secret missing the step
succeeds with a notice. The workflow creates no secret and no tag.

## Arming (user-only)

1. In `greenticai/greentic-start` create secrets `RELEASE_ADMIN_URL` (the
   admin base URL) and `RELEASE_PUBLISHER_KEY` (a `gts_` key with scope
   `release_publisher`, minted with `greentic-admin service-key create`).
2. Verify first with a dry run: dispatch with `register_dry_run=true` and read
   the `release-request` artifact. `workflow_dispatch` may be disabled for the
   account; then inspect the artifact of the next unarmed tag run (secrets
   absent) before creating the secrets.
3. Create the secrets, then push the next `v*` tag. The step registers the
   release.

## Failure modes

- `409 release_version_immutable`: the version already exists with different
  content. The job fails hard; cut a new version, never edit a release.
- `401`/`403`: the key is wrong or not scoped `release_publisher`.
- Digest/version validation failure (exit 2): the index digest could not be
  resolved or the tag is not semver.

## Dev lane

`distroless-dev.yml` is intentionally NOT registered: its Cargo version is the
static `1.2.0-dev.0`, which is not unique per push, so every second
registration would 409.
