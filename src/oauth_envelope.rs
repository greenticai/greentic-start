//! Helpers for constructing the WitDispatchInput envelope used by
//! oauth-oidc-generic provider WASM operations.
//!
//! These helpers exist because `runner_host::invoke_capability` passes raw
//! payload bytes to the WASM component, but the oidc-provider-runtime
//! component requires them to be wrapped in `{host, provider, input}`.

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use serde_json::Value;
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

pub fn load_public_base_url(
    bundle_root: &Path,
    tenant: &str,
    team: Option<&str>,
    fallback_port: u16,
) -> Result<String> {
    let team_segment = match team {
        Some(t) if !t.is_empty() => format!("{tenant}.{t}"),
        _ => format!("{tenant}.default"),
    };
    let runtime_dir = bundle_root
        .join("state")
        .join("runtime")
        .join(&team_segment);

    // Try endpoints.json first.
    let endpoints_path = runtime_dir.join("endpoints.json");
    if let Ok(raw) = std::fs::read_to_string(&endpoints_path)
        && let Ok(value) = serde_json::from_str::<Value>(&raw)
        && let Some(url) = value.get("public_base_url").and_then(Value::as_str)
        && !url.trim().is_empty()
    {
        return Ok(url.trim_end_matches('/').to_string());
    }

    // Fall back to public_base_url.txt.
    let txt_path = runtime_dir.join("public_base_url.txt");
    if let Ok(raw) = std::fs::read_to_string(&txt_path) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.trim_end_matches('/').to_string());
        }
    }

    // Final fallback: local loopback at the configured gateway port.
    Ok(format!("http://127.0.0.1:{fallback_port}"))
}

pub fn wrap_dispatch_envelope(
    public_base_url: &str,
    provider: &OauthProviderConfig,
    inner_input: Value,
) -> Result<Vec<u8>> {
    let envelope = serde_json::json!({
        "host": {
            "public_base_url": public_base_url,
        },
        "provider": {
            "provider_id": provider.provider_id,
            "client_id": provider.client_id,
            "client_secret": provider.client_secret,
            "client_id_key": Value::Null,
            "client_secret_key": Value::Null,
            "auth_url": provider.auth_url,
            "token_url": provider.token_url,
            "default_scopes": provider.default_scopes,
        },
        "input": inner_input,
    });
    serde_json::to_vec(&envelope).with_context(|| "failed to serialize WitDispatchInput envelope")
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

    #[test]
    fn load_public_base_url_reads_endpoints_json() {
        let dir = tempdir().expect("tempdir");
        let runtime = dir.path().join("state/runtime/demo.default");
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::write(
            runtime.join("endpoints.json"),
            json!({"public_base_url": "https://abc.ngrok-free.app/"}).to_string(),
        )
        .unwrap();

        let url = load_public_base_url(dir.path(), "demo", Some("default"), 9999).unwrap();
        assert_eq!(url, "https://abc.ngrok-free.app");
    }

    #[test]
    fn load_public_base_url_falls_back_to_txt_then_loopback() {
        let dir = tempdir().expect("tempdir");
        let runtime = dir.path().join("state/runtime/demo.default");
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::write(runtime.join("public_base_url.txt"), "http://from-txt:1234/").unwrap();

        let url = load_public_base_url(dir.path(), "demo", Some("default"), 9999).unwrap();
        assert_eq!(url, "http://from-txt:1234");
    }

    #[test]
    fn load_public_base_url_falls_back_to_local_loopback() {
        let dir = tempdir().expect("tempdir");
        let url = load_public_base_url(dir.path(), "demo", Some("default"), 8090).unwrap();
        assert_eq!(url, "http://127.0.0.1:8090");
    }

    #[test]
    fn wrap_dispatch_envelope_produces_correct_shape() {
        let cfg = OauthProviderConfig {
            provider_id: "github".to_string(),
            auth_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            client_id: "abc".to_string(),
            client_secret: "secret".to_string(),
            default_scopes: vec!["repo".to_string()],
        };
        let inner = json!({
            "adaptive_card": "{}",
            "tenant": "demo",
            "state": "state-1",
            "code_challenge": "ch-1"
        });
        let bytes = wrap_dispatch_envelope("http://127.0.0.1:8090", &cfg, inner.clone()).unwrap();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(parsed["host"]["public_base_url"], "http://127.0.0.1:8090");
        assert_eq!(parsed["provider"]["provider_id"], "github");
        assert_eq!(parsed["provider"]["client_id"], "abc");
        assert_eq!(parsed["provider"]["client_secret"], "secret");
        assert_eq!(
            parsed["provider"]["auth_url"],
            "https://github.com/login/oauth/authorize"
        );
        assert_eq!(parsed["input"], inner);
    }
}
