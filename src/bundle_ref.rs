use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use flate2::read::GzDecoder;
use greentic_distributor_client::{
    OciPackFetcher, PackFetchOptions, oci_packs::DefaultRegistryClient,
};
use sha2::{Digest, Sha256};
use zstd::stream::read::Decoder as ZstdDecoder;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BundleSourceKind {
    LocalArchive,
    Oci,
    Repo,
    Store,
}

#[derive(Clone, Debug)]
pub struct ResolvedBundle {
    pub source_ref: String,
    pub bundle_dir: PathBuf,
}

#[derive(Clone, Debug)]
struct FetchedBundle {
    source_ref: String,
    digest: String,
    media_type: Option<String>,
    path: PathBuf,
    kind: BundleSourceKind,
}

pub fn resolve_bundle_ref(reference: &str) -> anyhow::Result<ResolvedBundle> {
    let trimmed = reference.trim();
    if trimmed.is_empty() {
        anyhow::bail!("bundle reference cannot be empty");
    }

    if let Some(path) = parse_local_bundle_ref(trimmed) {
        if path.is_dir() {
            return Ok(ResolvedBundle {
                source_ref: trimmed.to_string(),
                bundle_dir: path,
            });
        }
        let digest = local_file_digest(&path)?;
        return extract_bundle_archive(
            &FetchedBundle {
                source_ref: trimmed.to_string(),
                digest,
                media_type: media_type_from_path(&path).map(str::to_string),
                path,
                kind: BundleSourceKind::LocalArchive,
            },
            trimmed,
        );
    }

    let fetched = fetch_remote_bundle(trimmed)?;
    extract_bundle_archive(&fetched, trimmed)
}

pub fn parse_local_bundle_ref(reference: &str) -> Option<PathBuf> {
    if let Some(value) = reference.strip_prefix("file://") {
        let path = PathBuf::from(value);
        return path.exists().then_some(path);
    }
    if reference.contains("://") {
        return None;
    }
    let path = PathBuf::from(reference);
    path.exists().then_some(path)
}

pub fn map_remote_bundle_ref(reference: &str) -> anyhow::Result<(String, BundleSourceKind)> {
    let trimmed = reference.trim();
    if let Some(rest) = trimmed.strip_prefix("oci://") {
        return Ok((rest.to_string(), BundleSourceKind::Oci));
    }
    if let Some(rest) = trimmed.strip_prefix("repo://") {
        return map_registry_target(rest, std::env::var("GREENTIC_REPO_REGISTRY_BASE").ok())
            .map(|mapped| (mapped, BundleSourceKind::Repo))
            .ok_or_else(|| {
                anyhow!(
                    "repo:// reference {trimmed} requires GREENTIC_REPO_REGISTRY_BASE to map to OCI"
                )
            });
    }
    if let Some(rest) = trimmed.strip_prefix("store://") {
        return map_registry_target(rest, std::env::var("GREENTIC_STORE_REGISTRY_BASE").ok())
            .map(|mapped| (mapped, BundleSourceKind::Store))
            .ok_or_else(|| {
                anyhow!(
                    "store:// reference {trimmed} requires GREENTIC_STORE_REGISTRY_BASE to map to OCI"
                )
            });
    }
    anyhow::bail!(
        "unsupported bundle reference {trimmed}; expected local path, file://, oci://, repo://, or store://"
    );
}

fn fetch_remote_bundle(reference: &str) -> anyhow::Result<FetchedBundle> {
    let (mapped_ref, kind) = map_remote_bundle_ref(reference)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build tokio runtime for bundle resolution")?;
    let fetcher: OciPackFetcher<DefaultRegistryClient> = OciPackFetcher::new(PackFetchOptions {
        allow_tags: true,
        offline: false,
        ..PackFetchOptions::default()
    });
    let fetched = rt
        .block_on(fetcher.fetch_pack_to_cache(&mapped_ref))
        .with_context(|| format!("fetch bundle reference {reference}"))?;
    Ok(FetchedBundle {
        source_ref: reference.to_string(),
        digest: fetched.resolved_digest,
        media_type: Some(fetched.media_type),
        path: fetched.path,
        kind,
    })
}

fn extract_bundle_archive(
    fetched: &FetchedBundle,
    reference: &str,
) -> anyhow::Result<ResolvedBundle> {
    let out_dir = bundle_cache_dir(&fetched.digest);
    let marker = out_dir.join(".bundle-ready");
    if marker.exists() {
        return Ok(ResolvedBundle {
            source_ref: fetched.source_ref.clone(),
            bundle_dir: out_dir,
        });
    }

    if out_dir.exists() {
        fs::remove_dir_all(&out_dir)
            .with_context(|| format!("clear stale extracted bundle {}", out_dir.display()))?;
    }
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("create extracted bundle dir {}", out_dir.display()))?;

    let media_type = fetched.media_type.as_deref();
    if should_extract_zip(media_type, &fetched.path) {
        extract_zip(&fetched.path, &out_dir)?;
    } else if should_extract_tar_gz(media_type, &fetched.path) {
        extract_tar_gz(&fetched.path, &out_dir)?;
    } else if should_extract_tar_zstd(media_type, &fetched.path) {
        extract_tar_zstd(&fetched.path, &out_dir)?;
    } else if should_extract_tar(media_type, &fetched.path) {
        extract_tar(&fetched.path, &out_dir)?;
    } else {
        anyhow::bail!(
            "bundle archive format is not supported for {} (kind={:?}, media_type={:?}, path={})",
            reference,
            fetched.kind,
            media_type,
            fetched.path.display()
        );
    }

    let marker_contents = format!("source={}\ndigest={}\n", fetched.source_ref, fetched.digest);
    fs::write(&marker, marker_contents)
        .with_context(|| format!("write bundle extraction marker {}", marker.display()))?;
    Ok(ResolvedBundle {
        source_ref: fetched.source_ref.clone(),
        bundle_dir: out_dir,
    })
}

fn bundle_cache_dir(digest: &str) -> PathBuf {
    let slug = digest
        .strip_prefix("sha256:")
        .unwrap_or(digest)
        .replace(':', "-");
    std::env::temp_dir()
        .join("greentic-start")
        .join("bundles")
        .join(slug)
}

fn extract_zip(path: &Path, out_dir: &Path) -> anyhow::Result<()> {
    let file =
        fs::File::open(path).with_context(|| format!("open zip bundle {}", path.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .with_context(|| format!("read zip bundle {}", path.display()))?;
    archive
        .extract(out_dir)
        .with_context(|| format!("extract zip bundle into {}", out_dir.display()))
}

fn extract_tar(path: &Path, out_dir: &Path) -> anyhow::Result<()> {
    let file =
        fs::File::open(path).with_context(|| format!("open tar bundle {}", path.display()))?;
    let mut archive = tar::Archive::new(file);
    archive
        .unpack(out_dir)
        .with_context(|| format!("extract tar bundle into {}", out_dir.display()))
}

fn extract_tar_gz(path: &Path, out_dir: &Path) -> anyhow::Result<()> {
    let file =
        fs::File::open(path).with_context(|| format!("open tar.gz bundle {}", path.display()))?;
    let decoder = GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    archive
        .unpack(out_dir)
        .with_context(|| format!("extract tar.gz bundle into {}", out_dir.display()))
}

fn extract_tar_zstd(path: &Path, out_dir: &Path) -> anyhow::Result<()> {
    let file =
        fs::File::open(path).with_context(|| format!("open tar.zst bundle {}", path.display()))?;
    let decoder = ZstdDecoder::new(file)
        .with_context(|| format!("decode tar.zst bundle {}", path.display()))?;
    let mut archive = tar::Archive::new(decoder);
    archive
        .unpack(out_dir)
        .with_context(|| format!("extract tar.zst bundle into {}", out_dir.display()))
}

fn should_extract_zip(media_type: Option<&str>, path: &Path) -> bool {
    matches!(
        media_type,
        Some("application/vnd.greentic.gtpack.v1+zip")
            | Some("application/vnd.greentic.gtpack+zip")
            | Some("application/vnd.greentic.pack+zip")
            | Some("application/zip")
    ) || has_any_suffix(path, &[".zip", ".gtbundle.zip", ".gtpack"])
}

fn should_extract_tar(media_type: Option<&str>, path: &Path) -> bool {
    matches!(media_type, Some("application/vnd.oci.image.layer.v1.tar"))
        || has_any_suffix(path, &[".tar", ".gtbundle.tar"])
}

fn should_extract_tar_gz(media_type: Option<&str>, path: &Path) -> bool {
    matches!(
        media_type,
        Some("application/vnd.oci.image.layer.v1.tar+gzip")
    ) || has_any_suffix(path, &[".tar.gz", ".tgz", ".gtbundle.tgz"])
}

fn should_extract_tar_zstd(media_type: Option<&str>, path: &Path) -> bool {
    matches!(
        media_type,
        Some("application/vnd.oci.image.layer.v1.tar+zstd")
    ) || has_any_suffix(path, &[".tar.zst", ".gtbundle.tar.zst"])
}

fn has_any_suffix(path: &Path, suffixes: &[&str]) -> bool {
    let value = path.to_string_lossy();
    suffixes.iter().any(|suffix| value.ends_with(suffix))
}

fn media_type_from_path(path: &Path) -> Option<&'static str> {
    let value = path.to_string_lossy();
    if value.ends_with(".zip") || value.ends_with(".gtpack") {
        return Some("application/zip");
    }
    if value.ends_with(".tar.gz") || value.ends_with(".tgz") {
        return Some("application/vnd.oci.image.layer.v1.tar+gzip");
    }
    if value.ends_with(".tar.zst") {
        return Some("application/vnd.oci.image.layer.v1.tar+zstd");
    }
    if value.ends_with(".tar") {
        return Some("application/vnd.oci.image.layer.v1.tar");
    }
    None
}

fn local_file_digest(path: &Path) -> anyhow::Result<String> {
    let mut file =
        fs::File::open(path).with_context(|| format!("open bundle file {}", path.display()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("read bundle file {}", path.display()))?;
    let digest = sha256_hex(&bytes);
    Ok(format!("sha256:{digest}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn map_registry_target(target: &str, base: Option<String>) -> Option<String> {
    let base = base?;
    let normalized_base = base.trim_end_matches('/');
    let normalized_target = target.trim_start_matches('/');
    Some(format!("{normalized_base}/{normalized_target}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_ref_accepts_existing_path_and_file_scheme() {
        let dir = tempfile::tempdir().expect("tempdir");
        let direct = parse_local_bundle_ref(dir.path().to_string_lossy().as_ref());
        assert_eq!(direct.as_deref(), Some(dir.path()));

        let file_ref = format!("file://{}", dir.path().display());
        let file = parse_local_bundle_ref(&file_ref);
        assert_eq!(file.as_deref(), Some(dir.path()));
    }

    #[test]
    fn remote_repo_and_store_refs_require_mapping() {
        unsafe {
            std::env::set_var("GREENTIC_REPO_REGISTRY_BASE", "ghcr.io/acme/repo");
            std::env::set_var("GREENTIC_STORE_REGISTRY_BASE", "ghcr.io/acme/store");
        }
        assert_eq!(
            map_remote_bundle_ref("repo://bundles/demo:latest").expect("repo"),
            (
                "ghcr.io/acme/repo/bundles/demo:latest".to_string(),
                BundleSourceKind::Repo
            )
        );
        assert_eq!(
            map_remote_bundle_ref("store://bundles/demo@sha256:abc").expect("store"),
            (
                "ghcr.io/acme/store/bundles/demo@sha256:abc".to_string(),
                BundleSourceKind::Store
            )
        );
    }
}
