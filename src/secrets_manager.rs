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
    Binding,
    TenantTeam,
    Tenant,
    Default,
    EnvImplicit,
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
        if self.scope == SelectedKind::EnvImplicit {
            return Ok(SecretsBackendKind::Env);
        }
        if let Some(pack_path) = &self.pack_path {
            secrets_backend::backend_kind_from_pack(pack_path)
        } else {
            Ok(SecretsBackendKind::DevStore)
        }
    }
}

/// Canonicalize a team value for secret scoping, rendering the default/empty
/// team as the `_` placeholder.
///
/// Delegates the normalization rule to `greentic-secrets`
/// ([`greentic_secrets_lib::normalize_team`]) — the single source of truth for
/// the "`_` everywhere" convention — so `default` and `_` can never diverge
/// across producers and readers.
pub fn canonical_team<'a>(team: Option<&'a str>) -> Cow<'a, str> {
    match greentic_secrets_lib::normalize_team(team) {
        Some(value) => Cow::Owned(value),
        None => Cow::Borrowed(greentic_secrets_lib::TEAM_PLACEHOLDER),
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
                    SelectedKind::Binding => "secrets provider binding".to_string(),
                    _ => "secrets manager pack".to_string(),
                },
            });
        }
    }

    if has_env_secret_vars() {
        return Ok(SecretsManagerSelection {
            scope: SelectedKind::EnvImplicit,
            pack_path: None,
            reason: "environment secrets detected in process environment".to_string(),
        });
    }

    Ok(SecretsManagerSelection {
        scope: SelectedKind::None,
        pack_path: None,
        reason: "no secrets manager pack found".to_string(),
    })
}

fn has_env_secret_vars() -> bool {
    env::vars_os().any(|(key, _)| {
        key.to_str()
            .map(|name| name.starts_with("GREENTIC_SECRET__"))
            .unwrap_or(false)
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
            match secrets_backend::backend_kind_from_pack(&path) {
                Ok(_) => packs.push(path),
                Err(err)
                    if err
                        .to_string()
                        .contains("missing secrets backend config in pack") =>
                {
                    operator_log::debug(
                        module_path!(),
                        format!(
                            "ignoring secrets provider adapter pack without local backend config: {}",
                            path.display()
                        ),
                    );
                }
                Err(err) => return Err(err),
            }
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
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;
    use zip::ZipWriter;
    use zip::write::FileOptions;

    #[test]
    fn canonical_team_maps_default_and_empty_to_underscore() {
        assert_eq!(canonical_team(Some("default")), "_");
        assert_eq!(canonical_team(Some("")), "_");
        assert_eq!(canonical_team(Some(" Default ")), "_");
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
        write_backend_pack(&team_pack, "dev-store");
        let tenant_pack = base.join("tenant").join("bar.gtpack");
        write_backend_pack(&tenant_pack, "dev-store");
        let default_pack = base.join("default.gtpack");
        write_backend_pack(&default_pack, "dev-store");
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
        write_backend_pack(&alt, "env");
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

    #[test]
    fn auto_selects_env_backend_when_greentic_secret_vars_exist() {
        let _env_guard = crate::test_env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe {
            env::set_var(
                "GREENTIC_SECRET__DEMO__ACME_____MESSAGING_WEBCHAT_GUI__JWT_SIGNING_KEY",
                "x",
            );
        }
        let selection = select_secrets_manager(dir.path(), "tenant", "team").unwrap();
        unsafe {
            env::remove_var(
                "GREENTIC_SECRET__DEMO__ACME_____MESSAGING_WEBCHAT_GUI__JWT_SIGNING_KEY",
            );
        }
        assert_eq!(selection.scope, SelectedKind::EnvImplicit);
        assert!(selection.pack_path.is_none());
        assert_eq!(selection.kind().unwrap(), SecretsBackendKind::Env);
    }

    #[test]
    fn override_env_errors_when_pack_is_missing() {
        let _env_guard = crate::test_env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        unsafe {
            env::set_var(OVERRIDE_ENV, "missing.gtpack");
        }
        let err = select_secrets_manager(dir.path(), "tenant", "team").unwrap_err();
        unsafe {
            env::remove_var(OVERRIDE_ENV);
        }
        assert!(err.to_string().contains("override secrets manager pack"));
    }

    #[test]
    fn selects_lexicographically_first_pack_within_scope() {
        let _env_guard = crate::test_env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let base = dir.path().join(DEFAULT_SECRETS_DIR);
        fs::create_dir_all(&base).unwrap();
        let alpha = base.join("alpha.gtpack");
        let zeta = base.join("zeta.gtpack");
        write_backend_pack(&zeta, "dev-store");
        write_backend_pack(&alpha, "dev-store");

        let selection = select_secrets_manager(dir.path(), "tenant", "team").unwrap();

        assert_eq!(selection.scope, SelectedKind::Default);
        assert_eq!(selection.pack_path.unwrap(), alpha);
    }

    #[test]
    fn default_discovery_ignores_cloud_provider_adapter_packs_without_local_backend_config() {
        let _env_guard = crate::test_env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let base = dir.path().join(DEFAULT_SECRETS_DIR);
        fs::create_dir_all(&base).unwrap();
        write_provider_adapter_pack(&base.join("aws-sm.gtpack"));
        write_provider_adapter_pack(&base.join("azure-kv.gtpack"));
        write_provider_adapter_pack(&base.join("gcp-sm.gtpack"));

        let selection = select_secrets_manager(dir.path(), "tenant", "team").unwrap();

        assert_eq!(selection.scope, SelectedKind::None);
        assert!(selection.pack_path.is_none());
        assert_eq!(selection.kind().unwrap(), SecretsBackendKind::DevStore);
    }

    #[test]
    fn default_discovery_still_errors_on_invalid_local_backend_config() {
        let _env_guard = crate::test_env_lock().lock().unwrap();
        let dir = tempdir().unwrap();
        let base = dir.path().join(DEFAULT_SECRETS_DIR);
        fs::create_dir_all(&base).unwrap();
        // `vault` is now a supported backend (Phase E), so use a genuinely
        // unknown backend to exercise the rejection. `select_secrets_manager`
        // validates the backend while scanning packs (find_best_pack →
        // backend_kind_from_pack), so an unknown backend errors at selection.
        write_backend_pack(&base.join("bad.gtpack"), "bogus");

        let err = select_secrets_manager(dir.path(), "tenant", "team").unwrap_err();

        let message = format!("{err:#}");
        assert!(message.contains("unsupported secrets backend 'bogus'"));
    }

    fn write_backend_pack(path: &Path, backend: &str) {
        let file = File::create(path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options: FileOptions<'_, ()> = FileOptions::default();
        zip.start_file("assets/secrets_backend.json", options)
            .unwrap();
        zip.write_all(format!(r#"{{"backend":"{backend}"}}"#).as_bytes())
            .unwrap();
        zip.finish().unwrap();
    }

    fn write_provider_adapter_pack(path: &Path) {
        let file = File::create(path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options: FileOptions<'_, ()> = FileOptions::default();
        zip.start_file("pack.json", options).unwrap();
        zip.write_all(br#"{"pack_id":"greentic.secrets.aws-sm"}"#)
            .unwrap();
        zip.finish().unwrap();
    }
}
