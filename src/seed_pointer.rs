//! Pointer seeds: an `environment.json` too large for the Secret Manager mount.
//!
//! A Cloud Run seed is mounted from Secret Manager, which caps one secret
//! version at 64 KiB. A long-lived environment (one revision per deploy per
//! unit) outgrows that. When the deployer finds the real document too large it
//! stages this small JSON in its place and pushes the real bytes to an OCI
//! registry instead:
//!
//! ```json
//! {"$greentic_seed_pointer":1,"kind":"oci",
//!  "uri":"<registry-path>@sha256:<manifest digest>",
//!  "sha256":"<hex sha256 of the real environment.json bytes>","size":<bytes>}
//! ```
//!
//! [`resolve_if_pointer`] is called by `seed_copy` for the file it is about to
//! install as `<seed>/environment.json`. A document without the marker is
//! returned untouched (`None`), so an inline seed behaves exactly as before.
//!
//! ## Artifact the deployer must push
//!
//! An OCI image manifest (or artifact manifest) with exactly ONE layer holding
//! the raw `environment.json` bytes, layer media type
//! [`ENVIRONMENT_LAYER_MEDIA_TYPE`] (`application/vnd.greentic.environment.v1+json`;
//! `application/json` and `application/octet-stream` are also accepted). With
//! oras: `oras push <repo>@... environment.json:application/vnd.greentic.environment.v1+json`
//! (pin the printed manifest digest into `uri`). The config blob is ignored.
//! `uri` MUST be digest-addressed (a tag is refused): the registry verifies the
//! manifest against it, and the `sha256`/`size` fields verify the layer bytes,
//! so nothing unverified is ever installed.
//!
//! ## Failure policy
//!
//! Every failure is fatal to boot and names the uri: an unknown marker version
//! or `kind`, a malformed pointer, a pull that still fails after the bounded
//! retry, a size or sha256 mismatch. Booting with an empty or partial
//! environment would be worse than not booting.

use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use greentic_distributor_client::{
    OciPackFetcher, PackFetchOptions, oci_packs::DefaultRegistryClient,
};
use sha2::{Digest, Sha256};

use crate::bundle_ref;
use crate::operator_log;

/// Key whose presence marks an `environment.json` as a pointer.
pub(crate) const POINTER_MARKER: &str = "$greentic_seed_pointer";

/// The only pointer version this build understands.
const POINTER_VERSION: u64 = 1;

/// The only pointer `kind` this build understands.
const KIND_OCI: &str = "oci";

/// Layer media type the deployer pushes the raw `environment.json` under.
pub(crate) const ENVIRONMENT_LAYER_MEDIA_TYPE: &str =
    "application/vnd.greentic.environment.v1+json";

/// Upper bound on the resolved document, so a corrupt pointer cannot make boot
/// allocate without limit. Far above the 64 KiB cap this exists to escape.
const MAX_ENVIRONMENT_BYTES: u64 = 64 * 1024 * 1024;

/// A pointer document is tiny; anything larger is not one, so it is installed
/// inline without being parsed.
const MAX_POINTER_BYTES: usize = 64 * 1024;

/// Total attempts for a pull (the registry client also retries transport
/// errors internally; this covers token/metadata blips around it).
const PULL_ATTEMPTS: u32 = 3;

/// Delay before the second attempt; doubles each time.
const PULL_BACKOFF: Duration = Duration::from_secs(1);

/// Fetches the single blob a pointer names. A seam so tests need no registry.
pub(crate) trait BlobPuller {
    fn pull(&self, uri: &str) -> anyhow::Result<Vec<u8>>;
}

/// Production puller: the registry client and credential rules of boot-time
/// bundle pulls (`OCI_USERNAME`/`OCI_PASSWORD` first, else the GCP metadata
/// token for Artifact Registry hosts).
pub(crate) struct OciBlobPuller;

impl BlobPuller for OciBlobPuller {
    fn pull(&self, uri: &str) -> anyhow::Result<Vec<u8>> {
        let reference = uri.strip_prefix("oci://").unwrap_or(uri);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build tokio runtime for seed pointer pull")?;
        // Plain HTTP is allowed for listed registries because the bytes are
        // gated by the pointer's own sha256 below, like the boot bundle pull.
        let insecure = bundle_ref::insecure_oci_registries_from_env();
        let credentials = bundle_ref::resolve_pull_credentials(
            reference,
            bundle_ref::generic_registry_credentials(),
        );
        let client = bundle_ref::build_registry_client(credentials, insecure.clone())?;
        bundle_ref::ensure_plain_http_honoured(&client, reference, &insecure)?;
        // The fetcher caches pulled layers on disk; the environment document
        // must not outlive this call there, so use a throwaway cache dir.
        let cache = tempfile::tempdir().context("create temp cache for seed pointer pull")?;
        let opts = PackFetchOptions {
            allow_tags: false,
            offline: false,
            cache_dir: cache.path().to_path_buf(),
            ..PackFetchOptions::default()
        }
        .add_accepted_layer_media_type(ENVIRONMENT_LAYER_MEDIA_TYPE);
        let fetcher: OciPackFetcher<DefaultRegistryClient> =
            OciPackFetcher::with_client(client, opts);
        rt.block_on(fetcher.fetch_pack(reference))
            .map_err(|e| anyhow!("{e:#}"))
    }
}

/// A parsed, validated pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SeedPointer {
    pub uri: String,
    pub sha256: String,
    pub size: u64,
}

/// Parse `bytes` as a pointer. `Ok(None)` when it is not one (not JSON, not an
/// object, or no marker key): the caller installs the bytes inline.
/// `Err` when the marker is present but the pointer is unusable.
pub(crate) fn parse_pointer(bytes: &[u8]) -> anyhow::Result<Option<SeedPointer>> {
    if bytes.len() > MAX_POINTER_BYTES {
        return Ok(None);
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return Ok(None);
    };
    let Some(obj) = value.as_object() else {
        return Ok(None);
    };
    let Some(version) = obj.get(POINTER_MARKER) else {
        return Ok(None);
    };
    if version.as_u64() != Some(POINTER_VERSION) {
        bail!(
            "seed environment.json is a pointer of unsupported version {version} \
             (this build understands {POINTER_VERSION}); refusing to boot"
        );
    }
    let text = |key: &str| -> anyhow::Result<&str> {
        obj.get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("seed pointer is missing a string `{key}`"))
    };
    let uri = text("uri");
    let kind = text("kind")?;
    if kind != KIND_OCI {
        bail!(
            "seed pointer has unsupported kind `{kind}` (this build understands `{KIND_OCI}`); \
             refusing to boot"
        );
    }
    let uri = uri?.to_string();
    let sha256 = text("sha256")?.to_ascii_lowercase();
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("seed pointer for `{uri}` has a malformed `sha256` (expected 64 hex characters)");
    }
    let size = obj
        .get("size")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("seed pointer for `{uri}` is missing an integer `size`"))?;
    if size == 0 || size > MAX_ENVIRONMENT_BYTES {
        bail!("seed pointer for `{uri}` has an implausible `size` {size}");
    }
    let reference = uri.strip_prefix("oci://").unwrap_or(&uri);
    if !reference.contains("@sha256:") {
        bail!("seed pointer uri `{uri}` is not digest-addressed (`<path>@sha256:<digest>`)");
    }
    Ok(Some(SeedPointer { uri, sha256, size }))
}

/// Resolve the bytes a pointer names and verify them. Retries the pull with a
/// short bounded budget; verification failures are final.
pub(crate) fn resolve_pointer(
    pointer: &SeedPointer,
    puller: &dyn BlobPuller,
    backoff: Duration,
) -> anyhow::Result<Vec<u8>> {
    let mut delay = backoff;
    let mut last = None;
    for attempt in 1..=PULL_ATTEMPTS {
        match puller.pull(&pointer.uri) {
            Ok(bytes) => return verify(pointer, bytes),
            Err(err) => {
                operator_log::warn(
                    module_path!(),
                    format!(
                        "seed pointer pull attempt {attempt}/{PULL_ATTEMPTS} failed for `{}`: {err:#}",
                        pointer.uri
                    ),
                );
                last = Some(err);
                if attempt < PULL_ATTEMPTS {
                    std::thread::sleep(delay);
                    delay = delay.saturating_mul(2);
                }
            }
        }
    }
    let err = last.unwrap_or_else(|| anyhow!("no attempt was made"));
    Err(err.context(format!(
        "could not pull the environment document named by the seed pointer `{}` \
         after {PULL_ATTEMPTS} attempts; refusing to boot with an empty environment",
        pointer.uri
    )))
}

fn verify(pointer: &SeedPointer, bytes: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    if bytes.len() as u64 != pointer.size {
        bail!(
            "environment document pulled from `{}` is {} bytes but the seed pointer says {}; \
             refusing to install it",
            pointer.uri,
            bytes.len(),
            pointer.size
        );
    }
    let actual = hex_sha256(&bytes);
    if actual != pointer.sha256 {
        bail!(
            "environment document pulled from `{}` has sha256 {actual} but the seed pointer \
             says {}; refusing to install it",
            pointer.uri,
            pointer.sha256
        );
    }
    Ok(bytes)
}

fn hex_sha256(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// If `source_bytes` is a pointer, return the verified real document;
/// `Ok(None)` means "not a pointer, install the original bytes".
pub(crate) fn resolve_if_pointer(
    source_bytes: &[u8],
    puller: &dyn BlobPuller,
    backoff: Duration,
) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(pointer) = parse_pointer(source_bytes)? else {
        return Ok(None);
    };
    operator_log::info(
        module_path!(),
        format!(
            "seed environment.json is a pointer; pulling {} bytes from `{}`",
            pointer.size, pointer.uri
        ),
    );
    resolve_pointer(&pointer, puller, backoff).map(Some)
}

/// Production backoff for [`resolve_if_pointer`].
pub(crate) const fn default_backoff() -> Duration {
    PULL_BACKOFF
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct Stub {
        result: Result<Vec<u8>, String>,
        calls: Cell<u32>,
    }

    impl Stub {
        fn ok(bytes: &[u8]) -> Self {
            Self {
                result: Ok(bytes.to_vec()),
                calls: Cell::new(0),
            }
        }
        fn err(msg: &str) -> Self {
            Self {
                result: Err(msg.to_string()),
                calls: Cell::new(0),
            }
        }
    }

    impl BlobPuller for Stub {
        fn pull(&self, _uri: &str) -> anyhow::Result<Vec<u8>> {
            self.calls.set(self.calls.get() + 1);
            self.result.clone().map_err(|m| anyhow!(m))
        }
    }

    const URI: &str = "reg.example/p/env@sha256:abc";

    fn pointer_json(real: &[u8], kind: &str, version: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            POINTER_MARKER: version,
            "kind": kind,
            "uri": URI,
            "sha256": hex_sha256(real),
            "size": real.len(),
        }))
        .unwrap()
    }

    #[test]
    fn inline_document_is_not_a_pointer() {
        let stub = Stub::ok(b"unused");
        let inline = br#"{"id":"local","revisions":[]}"#;
        assert!(
            resolve_if_pointer(inline, &stub, Duration::ZERO)
                .unwrap()
                .is_none()
        );
        assert!(
            resolve_if_pointer(b"not json at all", &stub, Duration::ZERO)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            stub.calls.get(),
            0,
            "an inline seed must not touch the network"
        );
    }

    #[test]
    fn pointer_happy_path_returns_verified_bytes() {
        let real = br#"{"id":"local","big":true}"#;
        let stub = Stub::ok(real);
        let out = resolve_if_pointer(&pointer_json(real, "oci", 1), &stub, Duration::ZERO)
            .unwrap()
            .unwrap();
        assert_eq!(out, real);
    }

    #[test]
    fn sha_mismatch_is_refused_and_names_the_uri() {
        let real = br#"{"id":"local"}"#;
        let tampered = br#"{"id":"evil!"}"#; // same length, different bytes
        assert_eq!(real.len(), tampered.len());
        let stub = Stub::ok(tampered);
        let err = resolve_if_pointer(&pointer_json(real, "oci", 1), &stub, Duration::ZERO)
            .unwrap_err()
            .to_string();
        assert!(err.contains("sha256") && err.contains(URI), "{err}");
        assert_eq!(stub.calls.get(), 1, "a mismatch is final, never retried");
    }

    #[test]
    fn size_mismatch_is_refused() {
        let real = br#"{"id":"local"}"#;
        let stub = Stub::ok(b"{}");
        let err = resolve_if_pointer(&pointer_json(real, "oci", 1), &stub, Duration::ZERO)
            .unwrap_err()
            .to_string();
        assert!(err.contains("bytes") && err.contains(URI), "{err}");
    }

    #[test]
    fn pull_failure_retries_then_fails_loudly() {
        let real = br#"{"id":"local"}"#;
        let stub = Stub::err("503 from registry");
        let err =
            resolve_if_pointer(&pointer_json(real, "oci", 1), &stub, Duration::ZERO).unwrap_err();
        let text = format!("{err:#}");
        assert!(
            text.contains(URI) && text.contains("503 from registry"),
            "{text}"
        );
        assert!(text.contains("refusing to boot"), "{text}");
        assert_eq!(stub.calls.get(), PULL_ATTEMPTS);
    }

    #[test]
    fn unknown_kind_and_version_are_refused() {
        let real = b"{}";
        let stub = Stub::ok(real);
        let kind = resolve_if_pointer(&pointer_json(real, "s3", 1), &stub, Duration::ZERO)
            .unwrap_err()
            .to_string();
        assert!(kind.contains("unsupported kind `s3`"), "{kind}");
        let ver = resolve_if_pointer(&pointer_json(real, "oci", 2), &stub, Duration::ZERO)
            .unwrap_err()
            .to_string();
        assert!(ver.contains("unsupported version"), "{ver}");
        assert_eq!(stub.calls.get(), 0);
    }

    #[test]
    fn tag_addressed_or_malformed_pointers_are_refused() {
        let stub = Stub::ok(b"{}");
        let tag = serde_json::to_vec(&serde_json::json!({
            POINTER_MARKER: 1, "kind": "oci", "uri": "reg.example/p/env:latest",
            "sha256": hex_sha256(b"{}"), "size": 2,
        }))
        .unwrap();
        assert!(
            resolve_if_pointer(&tag, &stub, Duration::ZERO)
                .unwrap_err()
                .to_string()
                .contains("not digest-addressed")
        );
        let bad_sha = serde_json::to_vec(&serde_json::json!({
            POINTER_MARKER: 1, "kind": "oci", "uri": URI, "sha256": "zz", "size": 2,
        }))
        .unwrap();
        assert!(
            resolve_if_pointer(&bad_sha, &stub, Duration::ZERO)
                .unwrap_err()
                .to_string()
                .contains("malformed `sha256`")
        );
    }
}
