use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

#[derive(Clone, Debug, Default, Deserialize)]
struct AdminRegistryDocument {
    #[serde(default)]
    admins: Vec<AdminRegistryEntry>,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminRegistryEntry {
    client_cn: String,
}

pub(crate) fn load_admin_allowed_clients(bundle_root: &Path, explicit: &[String]) -> Vec<String> {
    let mut allowed = explicit.to_vec();
    if let Ok(raw) = std::env::var("GREENTIC_ADMIN_ALLOWED_CLIENTS") {
        allowed.extend(
            raw.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        );
    }
    let path = bundle_root
        .join(".greentic")
        .join("admin")
        .join("admins.json");
    let Ok(raw) = std::fs::read_to_string(&path) else {
        allowed.sort();
        allowed.dedup();
        return allowed;
    };
    let Ok(doc) = serde_json::from_str::<AdminRegistryDocument>(&raw) else {
        allowed.sort();
        allowed.dedup();
        return allowed;
    };
    allowed.extend(
        doc.admins
            .into_iter()
            .map(|entry| entry.client_cn)
            .filter(|cn| !cn.trim().is_empty()),
    );
    allowed.sort();
    allowed.dedup();
    allowed
}

pub(crate) fn resolve_admin_certs_dir(
    bundle_root: &Path,
    state_dir: &Path,
    explicit: Option<&Path>,
) -> anyhow::Result<ResolvedAdminCertsDir> {
    if let Some(path) = explicit {
        return Ok(ResolvedAdminCertsDir {
            path: path.to_path_buf(),
            source: AdminCertsSource::ExplicitPath,
        });
    }

    let bundle_local = bundle_root.join(".greentic").join("admin").join("certs");
    if has_admin_cert_files(&bundle_local) {
        return Ok(ResolvedAdminCertsDir {
            path: bundle_local,
            source: AdminCertsSource::BundleLocal,
        });
    }

    let generated = maybe_materialize_admin_certs_from_env(state_dir)?;
    if let Some(path) = generated {
        return Ok(ResolvedAdminCertsDir {
            path,
            source: AdminCertsSource::EnvMaterialized,
        });
    }

    Ok(ResolvedAdminCertsDir {
        path: bundle_local,
        source: AdminCertsSource::BundleLocalFallback,
    })
}

fn has_admin_cert_files(dir: &Path) -> bool {
    ["ca.crt", "server.crt", "server.key"]
        .into_iter()
        .all(|name| dir.join(name).exists())
}

fn maybe_materialize_admin_certs_from_env(state_dir: &Path) -> anyhow::Result<Option<PathBuf>> {
    let ca_pem = std::env::var("GREENTIC_ADMIN_CA_PEM").ok();
    let cert_pem = std::env::var("GREENTIC_ADMIN_SERVER_CERT_PEM").ok();
    let key_pem = std::env::var("GREENTIC_ADMIN_SERVER_KEY_PEM").ok();

    let Some(ca_pem) = ca_pem else {
        return Ok(None);
    };
    let Some(cert_pem) = cert_pem else {
        return Ok(None);
    };
    let Some(key_pem) = key_pem else {
        return Ok(None);
    };

    let cert_dir = state_dir.join("admin").join("certs");
    fs::create_dir_all(&cert_dir).with_context(|| {
        format!(
            "failed to create generated admin cert directory {}",
            cert_dir.display()
        )
    })?;
    fs::write(cert_dir.join("ca.crt"), ca_pem)
        .with_context(|| format!("failed to write {}", cert_dir.join("ca.crt").display()))?;
    fs::write(cert_dir.join("server.crt"), cert_pem)
        .with_context(|| format!("failed to write {}", cert_dir.join("server.crt").display()))?;
    fs::write(cert_dir.join("server.key"), key_pem)
        .with_context(|| format!("failed to write {}", cert_dir.join("server.key").display()))?;
    Ok(Some(cert_dir))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedAdminCertsDir {
    pub(crate) path: PathBuf,
    pub(crate) source: AdminCertsSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdminCertsSource {
    ExplicitPath,
    BundleLocal,
    EnvMaterialized,
    BundleLocalFallback,
}

impl AdminCertsSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitPath => "explicit_path",
            Self::BundleLocal => "bundle_local",
            Self::EnvMaterialized => "env_materialized",
            Self::BundleLocalFallback => "bundle_local_fallback",
        }
    }
}

pub(crate) fn load_admin_cert_refs() -> Vec<String> {
    [
        ("GREENTIC_ADMIN_CA_SECRET_REF", "ca"),
        ("GREENTIC_ADMIN_SERVER_CERT_SECRET_REF", "server_cert"),
        ("GREENTIC_ADMIN_SERVER_KEY_SECRET_REF", "server_key"),
    ]
    .into_iter()
    .filter_map(|(env_key, label)| {
        std::env::var(env_key)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| format!("{label}={value}"))
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_admin_certs_dir_prefers_bundle_local_certs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        let certs = bundle.join(".greentic").join("admin").join("certs");
        std::fs::create_dir_all(&certs).expect("cert dir");
        std::fs::write(certs.join("ca.crt"), "ca").expect("ca");
        std::fs::write(certs.join("server.crt"), "cert").expect("cert");
        std::fs::write(certs.join("server.key"), "key").expect("key");

        let resolved = resolve_admin_certs_dir(bundle, &bundle.join("state"), None).expect("dir");
        assert_eq!(resolved.path, certs);
        assert_eq!(resolved.source, AdminCertsSource::BundleLocal);
    }

    #[test]
    fn resolve_admin_certs_dir_materializes_env_pems_into_state_dir() {
        let _lock = crate::test_env_lock().lock().unwrap();
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        let state_dir = bundle.join("state");

        unsafe {
            std::env::set_var("GREENTIC_ADMIN_CA_PEM", "ca-pem");
            std::env::set_var("GREENTIC_ADMIN_SERVER_CERT_PEM", "cert-pem");
            std::env::set_var("GREENTIC_ADMIN_SERVER_KEY_PEM", "key-pem");
        }

        let resolved = resolve_admin_certs_dir(bundle, &state_dir, None).expect("dir");
        assert_eq!(resolved.path, state_dir.join("admin").join("certs"));
        assert_eq!(resolved.source, AdminCertsSource::EnvMaterialized);
        assert_eq!(
            std::fs::read_to_string(resolved.path.join("ca.crt")).expect("read ca"),
            "ca-pem"
        );
        assert_eq!(
            std::fs::read_to_string(resolved.path.join("server.crt")).expect("read cert"),
            "cert-pem"
        );
        assert_eq!(
            std::fs::read_to_string(resolved.path.join("server.key")).expect("read key"),
            "key-pem"
        );

        unsafe {
            std::env::remove_var("GREENTIC_ADMIN_CA_PEM");
            std::env::remove_var("GREENTIC_ADMIN_SERVER_CERT_PEM");
            std::env::remove_var("GREENTIC_ADMIN_SERVER_KEY_PEM");
        }
    }

    #[test]
    fn resolve_admin_certs_dir_marks_explicit_source() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        let explicit = bundle.join("custom-certs");

        let resolved =
            resolve_admin_certs_dir(bundle, &bundle.join("state"), Some(&explicit)).expect("dir");
        assert_eq!(resolved.path, explicit);
        assert_eq!(resolved.source, AdminCertsSource::ExplicitPath);
    }

    #[test]
    fn load_admin_cert_refs_reads_optional_env_vars() {
        let _lock = crate::test_env_lock().lock().unwrap();
        unsafe {
            std::env::set_var("GREENTIC_ADMIN_CA_SECRET_REF", "ca-ref");
            std::env::set_var("GREENTIC_ADMIN_SERVER_CERT_SECRET_REF", "cert-ref");
            std::env::set_var("GREENTIC_ADMIN_SERVER_KEY_SECRET_REF", "key-ref");
        }

        let refs = load_admin_cert_refs();
        assert_eq!(
            refs,
            vec![
                "ca=ca-ref".to_string(),
                "server_cert=cert-ref".to_string(),
                "server_key=key-ref".to_string()
            ]
        );

        unsafe {
            std::env::remove_var("GREENTIC_ADMIN_CA_SECRET_REF");
            std::env::remove_var("GREENTIC_ADMIN_SERVER_CERT_SECRET_REF");
            std::env::remove_var("GREENTIC_ADMIN_SERVER_KEY_SECRET_REF");
        }
    }

    #[test]
    fn load_admin_allowed_clients_merges_env_and_registry() {
        let _lock = crate::test_env_lock().lock().unwrap();
        let temp = tempfile::tempdir().expect("tempdir");
        let bundle = temp.path();
        let admin_dir = bundle.join(".greentic").join("admin");
        std::fs::create_dir_all(&admin_dir).expect("admin dir");
        std::fs::write(
            admin_dir.join("admins.json"),
            r#"{"admins":[{"client_cn":"bundle-admin"}]}"#,
        )
        .expect("admins");

        unsafe {
            std::env::set_var("GREENTIC_ADMIN_ALLOWED_CLIENTS", "env-a, env-b");
        }

        let allowed = load_admin_allowed_clients(bundle, &["explicit-a".to_string()]);
        assert_eq!(
            allowed,
            vec![
                "bundle-admin".to_string(),
                "env-a".to_string(),
                "env-b".to_string(),
                "explicit-a".to_string()
            ]
        );

        unsafe {
            std::env::remove_var("GREENTIC_ADMIN_ALLOWED_CLIENTS");
        }
    }
}
