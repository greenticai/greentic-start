#![allow(dead_code)]

use std::borrow::Cow;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};

use crate::operator_log;
use crate::secrets_backend::{self, SecretsBackendKind};

const OVERRIDE_ENV: &str = "GREENTIC_SECRETS_MANAGER_PACK";
const DEFAULT_SECRETS_DIR: &str = "providers/secrets";

#[derive(Clone, Debug)]
pub struct SecretsManagerSelection {
    pub scope: SelectedKind,
    pub pack_path: Option<PathBuf>,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectedKind {
    TenantTeam,
    Tenant,
    Default,
    Override,
    None,
}

impl SecretsManagerSelection {
    pub fn description(&self) -> String {
        match &self.pack_path {
            Some(path) => format!("{} (pack={})", self.reason, path.display()),
            None => self.reason.clone(),
        }
    }

    pub fn kind(&self) -> Result<SecretsBackendKind> {
        if let Some(pack_path) = &self.pack_path {
            secrets_backend::backend_kind_from_pack(pack_path)
        } else {
            Ok(SecretsBackendKind::DevStore)
        }
    }
}

pub fn canonical_team<'a>(team: Option<&'a str>) -> Cow<'a, str> {
    match team
        .map(|value| value.trim())
        .filter(|trimmed| !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("default"))
    {
        Some(value) => Cow::Borrowed(value),
        None => Cow::Borrowed("_"),
    }
}

pub fn select_secrets_manager(
    bundle_root: &Path,
    tenant: &str,
    team: &str,
) -> Result<SecretsManagerSelection> {
    if let Some(override_path) = resolve_override(bundle_root)? {
        return Ok(SecretsManagerSelection {
            scope: SelectedKind::Override,
            pack_path: Some(override_path.clone()),
            reason: format!("override secrets manager pack {}", override_path.display()),
        });
    }

    let candidate_dirs = [
        (
            SelectedKind::TenantTeam,
            bundle_root
                .join(DEFAULT_SECRETS_DIR)
                .join(tenant)
                .join(team),
        ),
        (
            SelectedKind::Tenant,
            bundle_root.join(DEFAULT_SECRETS_DIR).join(tenant),
        ),
        (SelectedKind::Default, bundle_root.join(DEFAULT_SECRETS_DIR)),
    ];

    for (kind, dir) in &candidate_dirs {
        if let Some(pack) = find_best_pack(dir).context("scan secrets manager packs")? {
            return Ok(SecretsManagerSelection {
                scope: *kind,
                pack_path: Some(pack.clone()),
                reason: match kind {
                    SelectedKind::TenantTeam => "tenant/team secrets manager pack".to_string(),
                    SelectedKind::Tenant => "tenant secrets manager pack".to_string(),
                    SelectedKind::Default => "default secrets manager pack".to_string(),
                    _ => "secrets manager pack".to_string(),
                },
            });
        }
    }

    Ok(SecretsManagerSelection {
        scope: SelectedKind::None,
        pack_path: None,
        reason: "no secrets manager pack found".to_string(),
    })
}

fn resolve_override(bundle_root: &Path) -> Result<Option<PathBuf>> {
    let value = match env::var_os(OVERRIDE_ENV) {
        Some(value) => value,
        None => return Ok(None),
    };
    let candidate = PathBuf::from(value);
    let resolved = if candidate.is_absolute() {
        candidate
    } else {
        bundle_root.join(candidate)
    };
    if !resolved.exists() {
        return Err(anyhow!(
            "override secrets manager pack {} not found",
            resolved.display()
        ));
    }
    Ok(Some(resolved))
}

fn find_best_pack(dir: &Path) -> Result<Option<PathBuf>> {
    if !dir.is_dir() {
        return Ok(None);
    }
    let mut packs = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("read secrets dir {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("gtpack"))
            .unwrap_or(false)
            && path.is_file()
        {
            packs.push(path);
        }
    }
    if packs.is_empty() {
        return Ok(None);
    }
    packs.sort();
    if packs.len() > 1 {
        operator_log::warn(
            module_path!(),
            format!(
                "multiple secrets manager packs found in {}; using {}",
                dir.display(),
                packs[0]
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("unknown")
            ),
        );
    }
    Ok(Some(packs.into_iter().next().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tempfile::tempdir;

    #[test]
    fn canonical_team_maps_default_and_empty_to_underscore() {
        assert_eq!(canonical_team(Some("default")), "_");
        assert_eq!(canonical_team(Some("")), "_");
        assert_eq!(canonical_team(Some("team")), "team");
    }

    #[test]
    fn selects_tenant_team_over_tenant_and_default() {
        let _env_guard = crate::test_env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let base = dir.path().join(DEFAULT_SECRETS_DIR);
        fs::create_dir_all(base.join("tenant").join("team")).unwrap();
        fs::create_dir_all(base.join("tenant")).unwrap();
        fs::create_dir_all(&base).unwrap();
        let team_pack = base.join("tenant").join("team").join("foo.gtpack");
        fs::write(&team_pack, "").unwrap();
        let tenant_pack = base.join("tenant").join("bar.gtpack");
        fs::write(&tenant_pack, "").unwrap();
        let default_pack = base.join("default.gtpack");
        fs::write(&default_pack, "").unwrap();
        let selection = select_secrets_manager(dir.path(), "tenant", "team").unwrap();
        assert_eq!(selection.scope, SelectedKind::TenantTeam);
        assert_eq!(
            selection.pack_path.unwrap().file_name().unwrap(),
            "foo.gtpack"
        );
    }

    #[test]
    fn override_env_wins() {
        let _env_guard = crate::test_env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let alt = dir.path().join("alt.gtpack");
        fs::write(&alt, "").unwrap();
        unsafe {
            env::set_var(OVERRIDE_ENV, alt.strip_prefix(dir.path()).unwrap());
        }
        let selection = select_secrets_manager(dir.path(), "tenant", "team").unwrap();
        unsafe {
            env::remove_var(OVERRIDE_ENV);
        }
        assert_eq!(selection.scope, SelectedKind::Override);
        assert_eq!(selection.pack_path.unwrap(), alt);
    }
}
