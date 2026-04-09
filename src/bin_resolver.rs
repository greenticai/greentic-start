use std::path::{Path, PathBuf};

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
fn auto_install_url(name: &str) -> Option<String> {
    let (os, ext) = if cfg!(target_os = "linux") {
        ("linux", "")
    } else if cfg!(target_os = "macos") {
        ("darwin", "")
    } else if cfg!(target_os = "windows") {
        ("windows", ".exe")
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
        "cloudflared" => Some(format!(
            "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-{os}-{arch}{ext}"
        )),
        _ => None,
    }
}

/// Try to download and install a known binary into `{config_dir}/bin/`.
fn try_auto_install(name: &str, config_dir: &Path) -> anyhow::Result<Option<PathBuf>> {
    let url = match auto_install_url(name) {
        Some(url) => url,
        None => return Ok(None),
    };

    let bin_dir = config_dir.join("bin");
    let dest = bin_dir.join(binary_name(name));

    eprintln!("Installing {name} → {}", dest.display());
    eprintln!("  Downloading {url}");

    let response = ureq::get(&url)
        .call()
        .map_err(|err| anyhow::anyhow!("failed to download {name} from {url}: {err}"))?;

    std::fs::create_dir_all(&bin_dir)?;
    let mut file = std::fs::File::create(&dest)?;
    std::io::copy(&mut response.into_body().into_reader(), &mut file)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
    }

    eprintln!("  Installed {name} successfully");
    Ok(Some(dest))
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
}
