use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AutoInstallFormat {
    DirectBinary,
    Tgz,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AutoInstallSource {
    url: String,
    format: AutoInstallFormat,
}

pub struct ResolveCtx {
    pub config_dir: PathBuf,
    pub explicit_path: Option<PathBuf>,
}

pub fn resolve_binary(name: &str, ctx: &ResolveCtx) -> anyhow::Result<PathBuf> {
    if let Some(explicit) = ctx.explicit_path.as_ref() {
        let resolved = resolve_relative(&ctx.config_dir, explicit);
        if resolved.exists() {
            return Ok(resolved);
        }
        return Err(anyhow::anyhow!(
            "explicit binary path not found: {}",
            resolved.display()
        ));
    }

    if let Some(env_path) = env_binary_override(name) {
        if env_path.exists() {
            return Ok(env_path);
        }
        return Err(anyhow::anyhow!(
            "binary override from environment not found: {}",
            env_path.display()
        ));
    }

    let mut tried = Vec::new();

    let local_candidates = vec![
        ctx.config_dir.join("bin").join(binary_name(name)),
        ctx.config_dir
            .join("target")
            .join("debug")
            .join(binary_name(name)),
        ctx.config_dir
            .join("target")
            .join("release")
            .join(binary_name(name)),
    ];
    for candidate in local_candidates {
        if candidate.exists() {
            return Ok(candidate);
        }
        tried.push(candidate);
    }

    if let Some(path) = find_on_path(name) {
        return Ok(path);
    }

    // Auto-install known binaries when missing.
    if let Some(path) = try_auto_install(name, &ctx.config_dir)? {
        return Ok(path);
    }

    let mut message = format!("binary not found: {name}");
    if !tried.is_empty() {
        message.push_str("\nTried:");
        for path in &tried {
            message.push_str(&format!("\n  - {}", path.display()));
        }
    }
    message.push_str(&format!(
        "\nSuggestions:\n  - set binaries.{name} in greentic.yaml\n  - set GREENTIC_OPERATOR_BINARY_{}",
        normalize_env_key(name)
    ));
    Err(anyhow::anyhow!(message))
}

/// Return a download URL for known external binaries, or `None` if the binary
/// is not in the auto-install list.
fn auto_install_source(name: &str) -> Option<AutoInstallSource> {
    let (os, ext, format) = if cfg!(target_os = "linux") {
        ("linux", "", AutoInstallFormat::DirectBinary)
    } else if cfg!(target_os = "macos") {
        // Cloudflare publishes macOS release assets as tarballs, not as
        // extensionless binaries. The old extensionless URL redirects to 404.
        ("darwin", ".tgz", AutoInstallFormat::Tgz)
    } else if cfg!(target_os = "windows") {
        ("windows", ".exe", AutoInstallFormat::DirectBinary)
    } else {
        return None;
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "amd64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        return None;
    };

    match name {
        "cloudflared" => Some(AutoInstallSource {
            url: format!(
                "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-{os}-{arch}{ext}"
            ),
            format,
        }),
        _ => None,
    }
}

/// Try to download and install a known binary into `{config_dir}/bin/`.
fn try_auto_install(name: &str, config_dir: &Path) -> anyhow::Result<Option<PathBuf>> {
    let source = match auto_install_source(name) {
        Some(source) => source,
        None => return Ok(None),
    };

    let bin_dir = config_dir.join("bin");
    let dest = bin_dir.join(binary_name(name));

    eprintln!("Installing {name} → {}", dest.display());
    eprintln!("  Downloading {}", source.url);

    let response = ureq::get(&source.url)
        .call()
        .map_err(|err| anyhow::anyhow!("failed to download {name} from {}: {err}", source.url))?;

    std::fs::create_dir_all(&bin_dir)?;
    match source.format {
        AutoInstallFormat::DirectBinary => {
            let mut file = std::fs::File::create(&dest)?;
            std::io::copy(&mut response.into_body().into_reader(), &mut file)?;
        }
        AutoInstallFormat::Tgz => {
            install_tgz_binary(response.into_body().into_reader(), name, &dest)?;
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
    }

    eprintln!("  Installed {name} successfully");
    Ok(Some(dest))
}

fn install_tgz_binary(reader: impl std::io::Read, binary: &str, dest: &Path) -> anyhow::Result<()> {
    let decoder = flate2::read::GzDecoder::new(reader);
    let mut archive = tar::Archive::new(decoder);
    let expected_name = binary_name(binary);

    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }

        let path = entry.path()?;
        let is_binary = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == expected_name);
        if !is_binary {
            continue;
        }

        let mut file = std::fs::File::create(dest)?;
        std::io::copy(&mut entry, &mut file)?;
        return Ok(());
    }

    Err(anyhow::anyhow!(
        "downloaded archive did not contain {}",
        expected_name
    ))
}

fn resolve_relative(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn binary_name(name: &str) -> String {
    if cfg!(windows) {
        if name.ends_with(".exe") {
            name.to_string()
        } else {
            format!("{name}.exe")
        }
    } else {
        name.to_string()
    }
}

fn find_on_path(binary: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(binary_name(binary));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn env_binary_override(name: &str) -> Option<PathBuf> {
    let key = format!("GREENTIC_OPERATOR_BINARY_{}", normalize_env_key(name));
    std::env::var_os(key).map(PathBuf::from)
}

fn normalize_env_key(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn resolves_explicit_relative_binary_from_config_dir() {
        let dir = tempdir().expect("tempdir");
        let bin = dir.path().join("bin").join("runner");
        std::fs::create_dir_all(bin.parent().expect("parent")).expect("mkdir");
        std::fs::write(&bin, "").expect("write binary");

        let resolved = resolve_binary(
            "runner",
            &ResolveCtx {
                config_dir: dir.path().to_path_buf(),
                explicit_path: Some(PathBuf::from("bin/runner")),
            },
        )
        .expect("resolved");

        assert_eq!(resolved, bin);
    }

    #[test]
    fn explicit_missing_binary_reports_resolved_path() {
        let dir = tempdir().expect("tempdir");
        let err = resolve_binary(
            "runner",
            &ResolveCtx {
                config_dir: dir.path().to_path_buf(),
                explicit_path: Some(PathBuf::from("bin/runner")),
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("explicit binary path not found"));
        assert!(err.to_string().contains("bin/runner"));
    }

    #[test]
    fn env_override_is_used_before_local_candidates() {
        let _env_guard = crate::test_env_lock().lock().unwrap();
        let dir = tempdir().expect("tempdir");
        let env_bin = dir.path().join("custom-runner");
        std::fs::write(&env_bin, "").expect("write env binary");
        unsafe {
            std::env::set_var("GREENTIC_OPERATOR_BINARY_RUNNER", &env_bin);
        }

        let resolved = resolve_binary(
            "runner",
            &ResolveCtx {
                config_dir: dir.path().to_path_buf(),
                explicit_path: None,
            },
        )
        .expect("resolved");

        unsafe {
            std::env::remove_var("GREENTIC_OPERATOR_BINARY_RUNNER");
        }
        assert_eq!(resolved, env_bin);
    }

    #[test]
    fn missing_env_override_reports_the_override_path() {
        let _env_guard = crate::test_env_lock().lock().unwrap();
        let dir = tempdir().expect("tempdir");
        let missing = dir.path().join("missing-runner");
        unsafe {
            std::env::set_var("GREENTIC_OPERATOR_BINARY_RUNNER", &missing);
        }

        let err = resolve_binary(
            "runner",
            &ResolveCtx {
                config_dir: dir.path().to_path_buf(),
                explicit_path: None,
            },
        )
        .unwrap_err();

        unsafe {
            std::env::remove_var("GREENTIC_OPERATOR_BINARY_RUNNER");
        }
        assert!(
            err.to_string()
                .contains("binary override from environment not found")
        );
        assert!(err.to_string().contains(missing.to_string_lossy().as_ref()));
    }

    #[test]
    fn missing_binary_lists_candidates_and_env_key_suggestion() {
        let dir = tempdir().expect("tempdir");
        let err = resolve_binary(
            "operator-runner",
            &ResolveCtx {
                config_dir: dir.path().to_path_buf(),
                explicit_path: None,
            },
        )
        .unwrap_err();

        let message = err.to_string();
        assert!(message.contains("binary not found: operator-runner"));
        assert!(message.contains("target/debug/operator-runner"));
        assert!(message.contains("GREENTIC_OPERATOR_BINARY_OPERATOR_RUNNER"));
    }

    #[test]
    fn normalize_env_key_replaces_non_alphanumeric_characters() {
        assert_eq!(
            normalize_env_key("operator-runner.v2"),
            "OPERATOR_RUNNER_V2"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn cloudflared_macos_auto_install_uses_tgz_asset() {
        let source = auto_install_source("cloudflared").expect("source");

        assert_eq!(source.format, AutoInstallFormat::Tgz);
        assert!(source.url.ends_with(".tgz"));
        assert!(source.url.contains("cloudflared-darwin-"));
    }

    #[test]
    fn install_tgz_binary_extracts_matching_file() {
        let dir = tempdir().expect("tempdir");
        let archive_path = dir.path().join("cloudflared.tgz");
        let archive_file = std::fs::File::create(&archive_path).expect("create archive");
        let encoder = flate2::write::GzEncoder::new(archive_file, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let payload = b"#!/bin/sh\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        archive
            .append_data(&mut header, "cloudflared", &payload[..])
            .expect("append");
        let encoder = archive.into_inner().expect("finish tar");
        encoder.finish().expect("finish gzip");

        let dest = dir.path().join("cloudflared-out");
        let reader = std::fs::File::open(&archive_path).expect("open archive");
        install_tgz_binary(reader, "cloudflared", &dest).expect("extract");

        assert_eq!(std::fs::read(&dest).expect("read dest"), payload);
    }
}
