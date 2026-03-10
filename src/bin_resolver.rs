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
