use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

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
    Http,
    Oci,
    Repo,
    Store,
}

#[derive(Clone, Debug)]
pub struct ResolvedBundle {
    #[allow(dead_code)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BundleArchiveKind {
    Zip,
    Tar,
    TarGz,
    TarZstd,
    Squashfs,
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
    if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
        return Ok((trimmed.to_string(), BundleSourceKind::Http));
    }
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
        "unsupported bundle reference {trimmed}; expected local path, file://, http(s)://, oci://, repo://, or store://"
    );
}

fn fetch_remote_bundle(reference: &str) -> anyhow::Result<FetchedBundle> {
    let (mapped_ref, kind) = map_remote_bundle_ref(reference)?;
    if kind == BundleSourceKind::Http {
        return fetch_http_bundle(reference);
    }
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

fn fetch_http_bundle(reference: &str) -> anyhow::Result<FetchedBundle> {
    let mut response = ureq::get(reference)
        .call()
        .with_context(|| format!("download bundle reference {reference}"))?;
    let media_type = response.body().mime_type().map(str::to_string);
    let bytes = response
        .body_mut()
        .with_config()
        .limit(512 * 1024 * 1024)
        .read_to_vec()
        .with_context(|| format!("read downloaded bundle body {reference}"))?;
    let digest = bytes_digest(&bytes);
    let path = http_download_path(reference, &digest);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create bundle download dir {}", parent.display()))?;
    }
    fs::write(&path, bytes)
        .with_context(|| format!("write downloaded bundle {}", path.display()))?;
    Ok(FetchedBundle {
        source_ref: reference.to_string(),
        digest,
        media_type,
        path,
        kind: BundleSourceKind::Http,
    })
}

fn extract_bundle_archive(
    fetched: &FetchedBundle,
    reference: &str,
) -> anyhow::Result<ResolvedBundle> {
    let out_dir = bundle_cache_dir(&fetched.digest);
    let marker = bundle_cache_marker_path(&fetched.digest);
    if marker.exists() {
        return Ok(ResolvedBundle {
            source_ref: fetched.source_ref.clone(),
            bundle_dir: resolve_extracted_bundle_root(&out_dir),
        });
    }

    if out_dir.exists() {
        fs::remove_dir_all(&out_dir)
            .with_context(|| format!("clear stale extracted bundle {}", out_dir.display()))?;
    }
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("create extracted bundle dir {}", out_dir.display()))?;

    let media_type = fetched.media_type.as_deref();
    match detect_bundle_archive_kind(media_type, &fetched.path)? {
        Some(BundleArchiveKind::Zip) => extract_zip(&fetched.path, &out_dir)?,
        Some(BundleArchiveKind::Tar) => extract_tar(&fetched.path, &out_dir)?,
        Some(BundleArchiveKind::TarGz) => extract_tar_gz(&fetched.path, &out_dir)?,
        Some(BundleArchiveKind::TarZstd) => extract_tar_zstd(&fetched.path, &out_dir)?,
        Some(BundleArchiveKind::Squashfs) => extract_squashfs(&fetched.path, &out_dir)?,
        None => {
            anyhow::bail!(
                "bundle archive format is not supported for {} (kind={:?}, media_type={:?}, path={})",
                reference,
                fetched.kind,
                media_type,
                fetched.path.display()
            );
        }
    }

    let marker_contents = format!("source={}\ndigest={}\n", fetched.source_ref, fetched.digest);
    fs::write(&marker, marker_contents)
        .with_context(|| format!("write bundle extraction marker {}", marker.display()))?;
    Ok(ResolvedBundle {
        source_ref: fetched.source_ref.clone(),
        bundle_dir: resolve_extracted_bundle_root(&out_dir),
    })
}

fn bundle_cache_dir(digest: &str) -> PathBuf {
    bundle_cache_root().join(bundle_cache_slug(digest))
}

fn bundle_cache_marker_path(digest: &str) -> PathBuf {
    bundle_cache_root().join(format!("{}.bundle-ready", bundle_cache_slug(digest)))
}

fn bundle_cache_root() -> PathBuf {
    std::env::temp_dir().join("greentic-start").join("bundles")
}

fn bundle_cache_slug(digest: &str) -> String {
    digest
        .strip_prefix("sha256:")
        .unwrap_or(digest)
        .replace(':', "-")
}

fn resolve_extracted_bundle_root(out_dir: &Path) -> PathBuf {
    if extracted_bundle_root_has_config(out_dir) {
        return out_dir.to_path_buf();
    }
    let nested = out_dir.join("squashfs-root");
    if extracted_bundle_root_has_config(&nested) {
        return nested;
    }
    out_dir.to_path_buf()
}

fn extracted_bundle_root_has_config(root: &Path) -> bool {
    root.join("greentic.demo.yaml").exists()
        || root.join("greentic.operator.yaml").exists()
        || root.join("demo").join("demo.yaml").exists()
        || (root.join("bundle.yaml").exists()
            && (root.join("bundle-manifest.json").exists() || root.join("resolved").is_dir()))
}

fn http_download_path(reference: &str, digest: &str) -> PathBuf {
    let slug = digest
        .strip_prefix("sha256:")
        .unwrap_or(digest)
        .replace(':', "-");
    let filename = reference
        .split('?')
        .next()
        .and_then(|value| value.rsplit('/').next())
        .filter(|value| !value.is_empty())
        .map(sanitize_download_name)
        .unwrap_or_else(|| "bundle.gtbundle".to_string());
    std::env::temp_dir()
        .join("greentic-start")
        .join("downloads")
        .join(format!("{slug}-{filename}"))
}

fn sanitize_download_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-' => ch,
            _ => '-',
        })
        .collect()
}

fn bytes_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut output = String::with_capacity("sha256:".len() + digest.len() * 2);
    output.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
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

fn extract_squashfs(path: &Path, out_dir: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("create squashfs output dir {}", out_dir.display()))?;
    let output = Command::new("unsquashfs")
        .args([
            "-no-progress",
            "-quiet",
            "-dest",
            out_dir.to_str().unwrap_or_default(),
            path.to_str().unwrap_or_default(),
        ])
        .output()
        .map_err(|error| match error.kind() {
            ErrorKind::NotFound => anyhow!(
                "required tool `unsquashfs` was not found on PATH; install SquashFS tools to read `.gtbundle` artifacts"
            ),
            _ => anyhow::Error::new(error).context("spawn unsquashfs"),
        })?;
    if !output.status.success() {
        anyhow::bail!(
            "unsquashfs failed while extracting {} into {}: {}",
            path.display(),
            out_dir.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn detect_bundle_archive_kind(
    media_type: Option<&str>,
    path: &Path,
) -> anyhow::Result<Option<BundleArchiveKind>> {
    let magic = read_magic(path)?;
    if is_zip_magic(&magic) {
        return Ok(Some(BundleArchiveKind::Zip));
    }
    if is_squashfs_magic(&magic) {
        return Ok(Some(BundleArchiveKind::Squashfs));
    }
    if should_extract_tar_gz(media_type, path) {
        return Ok(Some(BundleArchiveKind::TarGz));
    }
    if should_extract_tar_zstd(media_type, path) {
        return Ok(Some(BundleArchiveKind::TarZstd));
    }
    if should_extract_tar(media_type, path) {
        return Ok(Some(BundleArchiveKind::Tar));
    }
    if should_extract_zip(media_type, path) {
        return Ok(Some(BundleArchiveKind::Zip));
    }
    Ok(None)
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

fn read_magic(path: &Path) -> anyhow::Result<[u8; 4]> {
    let mut file =
        fs::File::open(path).with_context(|| format!("open bundle file {}", path.display()))?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)
        .with_context(|| format!("read bundle header {}", path.display()))?;
    Ok(magic)
}

fn is_zip_magic(magic: &[u8; 4]) -> bool {
    matches!(
        magic,
        [b'P', b'K', 0x03, 0x04] | [b'P', b'K', 0x05, 0x06] | [b'P', b'K', 0x07, 0x08]
    )
}

fn is_squashfs_magic(magic: &[u8; 4]) -> bool {
    magic == b"hsqs"
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
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    use tar::Builder as TarBuilder;
    use tempfile::tempdir;
    use zip::write::FileOptions;

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

    #[test]
    fn remote_http_refs_are_supported() {
        assert_eq!(
            map_remote_bundle_ref("https://example.com/demo.gtbundle").expect("https ref"),
            (
                "https://example.com/demo.gtbundle".to_string(),
                BundleSourceKind::Http
            )
        );
        assert_eq!(
            map_remote_bundle_ref("http://example.com/demo.gtbundle").expect("http ref"),
            (
                "http://example.com/demo.gtbundle".to_string(),
                BundleSourceKind::Http
            )
        );
    }

    #[test]
    fn http_download_path_preserves_filename_shape_safely() {
        let path = http_download_path(
            "https://example.com/releases/demo bundle.gtbundle?sig=abc",
            "sha256:deadbeef",
        );
        let rendered = path.to_string_lossy();
        assert!(rendered.contains("deadbeef-demo-bundle.gtbundle"));
    }

    #[test]
    fn gtbundle_suffix_is_treated_as_zip_archive() {
        let path = Path::new("/tmp/cloud-deploy-demo.gtbundle");
        assert!(!should_extract_zip(Some("application/octet-stream"), path));
        assert_eq!(media_type_from_path(path), None);
    }

    #[test]
    fn magic_bytes_identify_zip_and_squashfs() {
        assert!(is_zip_magic(b"PK\x03\x04"));
        assert!(is_squashfs_magic(b"hsqs"));
    }

    #[test]
    fn registry_target_mapping_trims_duplicate_slashes() {
        assert_eq!(
            map_registry_target("/packs/demo:latest", Some("ghcr.io/acme/repo/".to_string())),
            Some("ghcr.io/acme/repo/packs/demo:latest".to_string())
        );
    }

    #[test]
    fn detect_bundle_archive_kind_prefers_magic_bytes_over_suffix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bundle.tar");
        fs::write(&path, b"PK\x03\x04not-really-a-tar").expect("write archive");

        let kind = detect_bundle_archive_kind(None, &path).expect("kind");
        assert_eq!(kind, Some(BundleArchiveKind::Zip));
    }

    #[test]
    fn detect_bundle_archive_kind_uses_media_type_and_suffix_fallbacks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tgz = dir.path().join("bundle.tgz");
        fs::write(&tgz, b"xxxxpayload").expect("write tgz");
        assert_eq!(
            detect_bundle_archive_kind(None, &tgz).expect("tgz"),
            Some(BundleArchiveKind::TarGz)
        );

        let zst = dir.path().join("bundle.tar.zst");
        fs::write(&zst, b"xxxxpayload").expect("write zst");
        assert_eq!(
            detect_bundle_archive_kind(Some("application/vnd.oci.image.layer.v1.tar+zstd"), &zst)
                .expect("zst"),
            Some(BundleArchiveKind::TarZstd)
        );
    }

    #[test]
    fn parse_local_bundle_ref_rejects_missing_paths_and_remote_urls() {
        assert!(parse_local_bundle_ref("/definitely/missing").is_none());
        assert!(parse_local_bundle_ref("oci://ghcr.io/acme/demo:latest").is_none());
    }

    #[test]
    fn empty_and_unsupported_bundle_references_error() {
        assert!(resolve_bundle_ref("   ").is_err());
        assert!(map_remote_bundle_ref("ftp://example.com/demo").is_err());
    }

    #[test]
    fn path_media_type_and_hash_helpers_cover_known_suffixes() {
        assert_eq!(
            media_type_from_path(Path::new("/tmp/demo.gtpack")),
            Some("application/zip")
        );
        assert_eq!(
            media_type_from_path(Path::new("/tmp/demo.tar.gz")),
            Some("application/vnd.oci.image.layer.v1.tar+gzip")
        );
        assert_eq!(
            sanitize_download_name("demo bundle?.gtbundle"),
            "demo-bundle-.gtbundle"
        );
        assert_eq!(
            bytes_digest(b"abc"),
            format!("sha256:{}", sha256_hex(b"abc"))
        );
    }

    #[test]
    fn bundle_cache_marker_path_is_outside_extracted_bundle_dir() {
        let digest = "sha256:deadbeef";
        let bundle_dir = bundle_cache_dir(digest);
        let marker = bundle_cache_marker_path(digest);

        assert_eq!(marker.parent(), bundle_dir.parent());
        assert_ne!(marker.parent(), Some(bundle_dir.as_path()));
        assert_eq!(
            marker.file_name().and_then(|value| value.to_str()),
            Some("deadbeef.bundle-ready")
        );
    }

    #[test]
    fn resolve_extracted_bundle_root_prefers_nested_squashfs_root_layout() {
        let dir = tempdir().expect("tempdir");
        let nested = dir.path().join("squashfs-root");
        fs::create_dir_all(nested.join("resolved")).expect("mkdir");
        fs::write(nested.join("bundle.yaml"), "tenant: demo\n").expect("write bundle yaml");

        assert_eq!(resolve_extracted_bundle_root(dir.path()), nested);
    }

    #[test]
    fn extract_zip_and_tar_archives_populate_output_directory() {
        let dir = tempdir().expect("tempdir");

        let zip_path = dir.path().join("demo.zip");
        {
            let file = fs::File::create(&zip_path).expect("zip");
            let mut zip = zip::ZipWriter::new(file);
            zip.start_file("app/config.json", FileOptions::<()>::default())
                .expect("start zip");
            zip.write_all(br#"{"ok":true}"#).expect("write zip");
            zip.finish().expect("finish zip");
        }
        let zip_out = dir.path().join("zip-out");
        extract_zip(&zip_path, &zip_out).expect("extract zip");
        assert_eq!(
            fs::read_to_string(zip_out.join("app").join("config.json")).expect("zip output"),
            r#"{"ok":true}"#
        );

        let tar_path = dir.path().join("demo.tar");
        {
            let file = fs::File::create(&tar_path).expect("tar");
            let mut tar = TarBuilder::new(file);
            let mut header = tar::Header::new_gnu();
            let bytes = b"hello tar";
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, "bundle/readme.txt", &bytes[..])
                .expect("append tar");
            tar.finish().expect("finish tar");
        }
        let tar_out = dir.path().join("tar-out");
        extract_tar(&tar_path, &tar_out).expect("extract tar");
        assert_eq!(
            fs::read_to_string(tar_out.join("bundle").join("readme.txt")).expect("tar output"),
            "hello tar"
        );
    }

    #[test]
    fn extract_tar_gz_archive_and_bundle_resolution_work_for_local_archives() {
        let dir = tempdir().expect("tempdir");
        let tar_gz_path = dir.path().join("demo.tar.gz");
        {
            let file = fs::File::create(&tar_gz_path).expect("tar.gz");
            let encoder = GzEncoder::new(file, Compression::default());
            let mut tar = TarBuilder::new(encoder);
            let mut header = tar::Header::new_gnu();
            let bytes = b"hello gz";
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, "bundle/index.txt", &bytes[..])
                .expect("append tar.gz");
            tar.finish().expect("finish tar.gz");
        }

        let out = dir.path().join("targz-out");
        extract_tar_gz(&tar_gz_path, &out).expect("extract tar.gz");
        assert_eq!(
            fs::read_to_string(out.join("bundle").join("index.txt")).expect("tar.gz output"),
            "hello gz"
        );

        let resolved = resolve_bundle_ref(tar_gz_path.to_string_lossy().as_ref()).expect("resolve");
        assert!(
            resolved
                .bundle_dir
                .join("bundle")
                .join("index.txt")
                .exists()
        );
    }
}
