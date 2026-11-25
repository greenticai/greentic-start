# Chunked encrypted Cloud Run seed stores

This runtime reconstructs `greentic.secret-store.chunks.v1` before the first
store open (`maybe_seed_env_store` in the synchronous boot section). The shared
wire codec is `greentic-deploy-spec::secret_chunks`, owned in the deployer repo.
The deployer design/release/Designer handover is
`greentic-deployer/docs/cloudrun-secret-store-chunks.md`.

The seed uses one Secret Manager resource/volume, immutable numeric versions,
61,440-byte chunks, and a last-published manifest at
`.greentic/dev/.dev.secrets.chunks.v1.json`. Stores up to 65,536 bytes retain the
legacy `.greentic/dev/.dev.secrets.env` file. v1 bounds stores to 64 chunks
(3,932,160 bytes); larger inputs fail without truncation.

Boot validates the schema, canonical paths/order, unique versions, exact file
set, lengths and per-chunk/whole-store SHA-256 before copying the seed. It
rejects source symlinks and ambiguous legacy/chunked mounts. Only verified
bytes are atomically installed at the legacy writable path (0600 under a
private dev directory); transport artifacts are not copied. Failed validation
preserves prior files and aborts startup; no memory fallback is selected.

`Dockerfile.distroless` advertises `io.greentic.secret-store.chunks=1` on the
runtime stage, inherited by its variants. The deployer fetches the exact
pinned image's OCI manifest/config, verifies their digests and selected
linux/amd64 platform, and checks this label before sending chunks. Do not add
the label to an image containing an older start binary.

The protocol API is published in **greentic-deploy-spec and greentic-deployer
`1.2.0-dev.45669060982`**, from [deployer PR #705](https://github.com/greenticai/greentic-deployer/pull/705),
merge `a4ce269cb9f2fc63b5a98d0f25ea588072acf37b`, and successful
[Dev Publish run 45669060982](https://github.com/greenticai/greentic-deployer/actions/runs/45669060982).
The registry archive was inspected to verify `pub mod secret_chunks` and the
v1 schema; this is an actual published API floor, not an invented run ID.

Both direct dependency floors and Cargo.lock now select that release cohort
from crates.io. The ranges exclude stable `1.2.0`, which predates the API and
sorts above every `1.2.0-dev.*`; retaining the former `<1.3.0-0` upper bound
could silently restore an incompatible stable package on a fresh resolve.
The Docker build uses `--locked`. No local source overlay is needed or included.

Then publish the matching runtime image and record its immutable digest. Only
after both the deployer and runtime artifacts are pinned may Designer replace
its old monolithic-size refusal with protocol/capability/count/length checks.
The change itself neither deploys an image nor modifies production credentials.

Chunked revisions must set `GREENTIC_SECRET_STORE_TRANSPORT=greentic.secret-store.chunks.v1`. This requires a manifest even if the entire chunk mount is absent. Unknown markers and missing seed directories fail startup. Legacy revisions omit the marker; manual seed copying also retains format auto-detection.


Initial implementation validation on 2026-11-25: formatting, strict Clippy, all-feature build/docs and
package verification passed with the matching local deployer/spec overlay.
All 22 seed-copy tests passed. The full runtime suite had 3,421 passing unit
tests, 27 ignored and two independently reproduced failures in untouched
network fixtures (metering connection classification and unauthenticated A2A
response reset). With those two explicitly excluded, the remaining unit,
integration and doc tests passed. See the deployer handover's validation table
for exact names and release-check limitations. The overlay was removed and the
original Cargo.lock restored. The dependency repair below replaces that initial
source-only validation boundary with actual published package floors.


## PR and release sequencing

Follow Bima's *Greentic handover* (2026-11-16, updated 2026-11-17), sections
13.2–13.4: feature PRs target `develop`, with no feature-PR version bump.
The upstream prerequisite is [greentic-deployer PR #705](https://github.com/greenticai/greentic-deployer/pull/705).
That prerequisite is now merged and published; this follow-up repair records
both verified floors and their registry lockfile entries. A merge to runtime
`develop` triggers publication, so normal CI and both native image builds must
validate the published dependency graph before landing; a local source overlay
is not release validation.

After the compatible runtime image is published, record its exact digest and
verified capability. Designer must coordinate its Cargo/tool pins,
`Dockerfile.tools`, effective runtime digests and relevant ratchet verdicts.
Keep its current size guard until the compatible capability/preflight changes
land; make the Designer release bump a separate `chore(release)` PR.


## Dependency repair checks

The dependency-only repair extends `publish-distroless-dev` pull-request inputs
to Cargo manifests/lockfiles, the toolchain and runtime source. Both native
Linux image builds now run for dependency fixes before merge, with image
publication disabled on pull requests. This covers the gap that let the old
lockfile reach the develop publication jobs. No workflow gate or test is skipped
by this repair, and no runtime capability is removed to hide a missing API.


Dependency repair validation (published crates, no overlay): formatting and
strict all-target/all-feature Clippy passed; the locked graph contains one
copy each of deploy-spec and deployer at `1.2.0-dev.45669060982`, shared with
runner-host and setup. All 22 seed-copy tests passed. The full local wrapper
reached tests with 3,421 passing and the same two previously documented macOS
network-fixture failures (27 ignored); these failures are not suppressed by
the PR. Actionlint passed for the image workflow. Full Linux CI and both native
image builds are required PR validation before calling the actions repaired.
