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

Release dependency: first publish the coordinated deploy-spec protocol API and matching
deployer; then update both dependency floors and Cargo.lock to that exact
release cohort. No published version is claimed to have the new API yet. Local
validation uses an external Cargo patch config and temporary copies of the
matching deployer and protocol crates; no path dependency is committed. Package/publish checks without
that overlay cannot pass until the protocol release and floor update exist.

Then publish the matching runtime image and record its immutable digest. Only
after both the deployer and runtime artifacts are pinned may Designer replace
its old monolithic-size refusal with protocol/capability/count/length checks.
The change itself neither deploys an image nor modifies production credentials.

Chunked revisions must set `GREENTIC_SECRET_STORE_TRANSPORT=greentic.secret-store.chunks.v1`. This requires a manifest even if the entire chunk mount is absent. Unknown markers and missing seed directories fail startup. Legacy revisions omit the marker; manual seed copying also retains format auto-detection.


Validation on 2026-11-25: formatting, strict Clippy, all-feature build/docs and
package verification passed with the matching local deployer/spec overlay.
All 22 seed-copy tests passed. The full runtime suite had 3,421 passing unit
tests, 27 ignored and two independently reproduced failures in untouched
network fixtures (metering connection classification and unauthenticated A2A
response reset). With those two explicitly excluded, the remaining unit,
integration and doc tests passed. See the deployer handover's validation table
for exact names and release-check limitations. The overlay was removed and the
original Cargo.lock restored; compatible published dependency floors are still
required before this runtime can be released.
