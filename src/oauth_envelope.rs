//! Helpers for constructing the WitDispatchInput envelope used by
//! oauth-oidc-generic provider WASM operations.
//!
//! These helpers exist because `runner_host::invoke_capability` passes raw
//! payload bytes to the WASM component, but the oidc-provider-runtime
//! component requires them to be wrapped in `{host, provider, input}`.

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OauthProviderConfig {
    pub provider_id: String,
    pub auth_url: String,
    pub token_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub default_scopes: Vec<String>,
}

#[derive(Deserialize)]
struct SetupAnswers {
    provider_id: String,
    auth_url: String,
    token_url: String,
    client_id: String,
    client_secret: String,
    #[serde(default)]
    default_scopes: Option<String>,
}

pub fn load_provider_config(
    bundle_root: &Path,
    provider_pack_id: &str,
) -> Result<OauthProviderConfig> {
    let path: PathBuf = bundle_root
        .join("state")
        .join("config")
        .join(provider_pack_id)
        .join("setup-answers.json");
    let raw = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "oauth provider config not found at {} (run setup or check provider_pack_id)",
            path.display()
        )
    })?;
    let parsed: SetupAnswers = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    let default_scopes = parsed
        .default_scopes
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();

    if parsed.client_id.trim().is_empty() {
        return Err(anyhow!("setup-answers.json: client_id is empty"));
    }
    if parsed.client_secret.trim().is_empty() {
        return Err(anyhow!("setup-answers.json: client_secret is empty"));
    }

    Ok(OauthProviderConfig {
        provider_id: parsed.provider_id,
        auth_url: parsed.auth_url,
        token_url: parsed.token_url,
        client_id: parsed.client_id,
        client_secret: parsed.client_secret,
        default_scopes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn write_setup_answers(bundle_root: &Path, pack_id: &str, body: &serde_json::Value) {
        let dir = bundle_root.join("state").join("config").join(pack_id);
        std::fs::create_dir_all(&dir).expect("mkdirs");
        std::fs::write(
            dir.join("setup-answers.json"),
            serde_json::to_vec_pretty(body).expect("ser"),
        )
        .expect("write");
    }

    #[test]
    fn load_provider_config_reads_setup_answers_json() {
        let dir = tempdir().expect("tempdir");
        write_setup_answers(
            dir.path(),
            "oauth-oidc-generic",
            &json!({
                "provider_id": "github",
                "auth_url": "https://github.com/login/oauth/authorize",
                "token_url": "https://github.com/login/oauth/access_token",
                "client_id": "abc123",
                "client_secret": "supersecret",
                "default_scopes": "repo read:org"
            }),
        );

        let cfg = load_provider_config(dir.path(), "oauth-oidc-generic").expect("ok");
        assert_eq!(cfg.provider_id, "github");
        assert_eq!(cfg.auth_url, "https://github.com/login/oauth/authorize");
        assert_eq!(cfg.client_id, "abc123");
        assert_eq!(cfg.client_secret, "supersecret");
        assert_eq!(
            cfg.default_scopes,
            vec!["repo".to_string(), "read:org".to_string()]
        );
    }

    #[test]
    fn load_provider_config_errors_when_file_missing() {
        let dir = tempdir().expect("tempdir");
        let err = load_provider_config(dir.path(), "oauth-oidc-generic").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn load_provider_config_errors_when_client_id_empty() {
        let dir = tempdir().expect("tempdir");
        write_setup_answers(
            dir.path(),
            "oauth-oidc-generic",
            &json!({
                "provider_id": "github",
                "auth_url": "https://github.com/login/oauth/authorize",
                "token_url": "https://github.com/login/oauth/access_token",
                "client_id": "",
                "client_secret": "x",
                "default_scopes": "repo"
            }),
        );
        let err = load_provider_config(dir.path(), "oauth-oidc-generic").unwrap_err();
        assert!(err.to_string().contains("client_id is empty"));
    }
}
