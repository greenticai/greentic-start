# Pointer seeds (`environment.json` beyond the 64 KiB Secret Manager cap)

Cloud Run mounts the env-store seed (`GREENTIC_SEED_DIR`, e.g. `/seed`) from Secret
Manager, where one secret version is capped at 64 KiB. `environment.json` grows by
one revision per deploy per unit, so a long-lived environment outgrows the cap.
When the deployer finds the real document too large it stages a small **pointer**
as `<seed>/environment.json` and pushes the real bytes to an OCI registry.

`seed_copy::maybe_seed_env_store` resolves the pointer before installing the file.
A seed whose `environment.json` has no marker is copied byte-identically, exactly
as before. Only the seed-root `environment.json` is ever treated as a pointer.

## Pointer contract (version 1)

```json
{"$greentic_seed_pointer":1,"kind":"oci",
 "uri":"<registry-path>@sha256:<manifest digest>",
 "sha256":"<hex sha256 of the real environment.json bytes>","size":<bytes>}
```

- `uri` must be digest-addressed (`oci://` prefix optional); a tag is refused.
- `sha256` is 64 hex characters, `size` the exact byte length of the real document.
- Unknown extra keys are ignored. An unknown marker version or `kind` is refused.

## Artifact the deployer must push

An OCI manifest with exactly **one layer** whose blob is the raw `environment.json`
bytes, layer media type `application/vnd.greentic.environment.v1+json`
(`application/json` and `application/octet-stream` are also accepted). The config
blob is ignored. With oras:

```bash
oras push <registry-path>:<any-tag> \
  environment.json:application/vnd.greentic.environment.v1+json
# pin the printed manifest digest as  uri = <registry-path>@sha256:<digest>
```

## Authentication

Same rules as the boot bundle pull (`bundle_ref.rs`): explicit
`OCI_USERNAME`/`OCI_PASSWORD` win; otherwise, for `*-docker.pkg.dev` hosts, the GCP
metadata-server token of the attached service account. Registries listed in
`GREENTIC_OCI_INSECURE_REGISTRIES` may be reached over plain HTTP (safe: the bytes
are gated by `sha256`/`size`).

## Failure behaviour (boot fails loudly, never with an empty environment)

- pull failure: 3 attempts (1 s, 2 s backoff) on top of the registry client's own
  transport retries, then boot aborts naming the `uri`;
- size or sha256 mismatch: refused immediately (not retried), nothing is installed;
- malformed pointer, unknown version or `kind`, tag-addressed uri: refused.

The verified bytes are installed atomically (`O_EXCL` temp + rename) with mode
`0600`, like every other seeded file. The pulled layer is cached only in a
throwaway temp directory that is deleted after the pull.
