//! Resolve a `NotifierConfig` for boot, including auto-detect of the
//! state-redis URL when `backend: redis` is selected without an explicit URL.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use greentic_secrets_lib::SecretsManager;

use crate::config::OperatorConfig;
use crate::notifier::NotifierConfig;
use crate::provider_config_envelope::{ConfigEnvelope, require_provider_config_envelope};

/// Resolve the effective notifier configuration.
///
/// - `Memory` and `Redis { url: Some(_) }` pass through unchanged.
/// - `Redis { url: None }` triggers auto-detect from the state-redis
///   provider's `ConfigEnvelope`, with secret URI resolution if the URL
///   field is a `secret://` reference.
pub async fn resolve_notifier_config(
    operator_root: &Path,
    operator_config: &OperatorConfig,
    secret_resolver: &dyn SecretResolver,
) -> Result<NotifierConfig> {
    let raw = operator_config
        .webchat
        .as_ref()
        .map(|w| w.notifier.clone())
        .unwrap_or_default();

    match raw {
        NotifierConfig::Memory { .. } => Ok(raw),
        NotifierConfig::Redis { url: Some(_), .. } => Ok(raw),
        NotifierConfig::Redis {
            url: None,
            channel,
            capacity,
        } => {
            let providers_root = operator_root.join("providers");
            let envelope: ConfigEnvelope =
                require_provider_config_envelope(&providers_root, "state-redis").with_context(
                    || {
                        "Redis notifier backend selected but the state-redis provider is not \
                     configured. Run `gtc setup --provider state-redis` first, or set \
                     webchat.notifier.url explicitly in greentic.yaml."
                    },
                )?;
            let url_field = envelope
                .config
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    anyhow!("state-redis ConfigEnvelope missing required `url` field")
                })?;
            let resolved_url = secret_resolver
                .resolve(url_field)
                .await
                .context("failed to resolve state-redis url secret reference")?;
            Ok(NotifierConfig::Redis {
                url: Some(resolved_url),
                channel,
                capacity,
            })
        }
    }
}

/// Indirection so unit tests can inject a fake without depending on the full
/// secrets manager construction.
#[async_trait::async_trait]
pub trait SecretResolver: Send + Sync {
    /// If `raw` is a literal URL, return it as-is. If it's a `secret://` URI,
    /// resolve to the underlying value.
    async fn resolve(&self, raw: &str) -> Result<String>;
}

/// Production adapter that wraps `Arc<dyn SecretsManager>` so the notifier
/// auto-detect path can resolve `secret://` URIs without requiring callers
/// to know the full secrets-manager surface.
pub struct SecretsManagerResolver {
    pub manager: Arc<dyn SecretsManager>,
}

#[async_trait::async_trait]
impl SecretResolver for SecretsManagerResolver {
    async fn resolve(&self, raw: &str) -> Result<String> {
        if !raw.starts_with("secret://") {
            return Ok(raw.to_string());
        }
        let bytes = self
            .manager
            .read(raw)
            .await
            .map_err(|err| anyhow!("resolve secret URI {raw}: {err}"))?;
        String::from_utf8(bytes).with_context(|| format!("secret {raw} is not valid UTF-8"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WebchatConfig;
    use crate::provider_config_envelope::ConfigEnvelope;
    use serde_json::json;
    use std::sync::Mutex;
    use tempfile::tempdir;

    struct FakeResolver {
        // Maps `secret://...` URIs to literal values; literal `redis://...`
        // is returned as-is.
        map: Mutex<std::collections::HashMap<String, String>>,
    }
    impl FakeResolver {
        fn new() -> Self {
            Self {
                map: Mutex::new(Default::default()),
            }
        }
        fn with(secret: &str, literal: &str) -> Self {
            let r = Self::new();
            r.map.lock().unwrap().insert(secret.into(), literal.into());
            r
        }
    }
    #[async_trait::async_trait]
    impl SecretResolver for FakeResolver {
        async fn resolve(&self, raw: &str) -> Result<String> {
            if raw.starts_with("secret://") {
                self.map
                    .lock()
                    .unwrap()
                    .get(raw)
                    .cloned()
                    .ok_or_else(|| anyhow!("no fake mapping for {raw}"))
            } else {
                Ok(raw.to_string())
            }
        }
    }

    fn op_with_redis(url: Option<&str>) -> OperatorConfig {
        OperatorConfig {
            webchat: Some(WebchatConfig {
                notifier: NotifierConfig::Redis {
                    url: url.map(String::from),
                    channel: None,
                    capacity: 64,
                },
            }),
            ..Default::default()
        }
    }

    fn write_state_redis_envelope(operator_root: &std::path::Path, url_field: &str) {
        let providers_root = operator_root.join("providers");
        let path = providers_root
            .join("state-redis")
            .join("config.envelope.cbor");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let env = ConfigEnvelope {
            config: json!({"url": url_field}),
            component_id: "state-redis".into(),
            abi_version: crate::provider_config_envelope::ABI_VERSION.to_string(),
            resolved_digest: "sha256:0".into(),
            describe_hash: "h".into(),
            schema_hash: None,
            operation_id: "configure".into(),
            updated_at: None,
        };
        let bytes = greentic_types::cbor::canonical::to_canonical_cbor(&env).unwrap();
        std::fs::write(&path, bytes).unwrap();
    }

    #[tokio::test]
    async fn explicit_url_skips_autodetect() {
        let dir = tempdir().unwrap();
        // Note: no envelope written — auto-detect would fail if it ran.
        let op = op_with_redis(Some("redis://override:1"));
        let resolved = resolve_notifier_config(dir.path(), &op, &FakeResolver::new())
            .await
            .unwrap();
        match resolved {
            NotifierConfig::Redis { url, .. } => {
                assert_eq!(url.as_deref(), Some("redis://override:1"))
            }
            _ => panic!("expected Redis variant"),
        }
    }

    #[tokio::test]
    async fn autodetect_missing_state_redis_errors() {
        let dir = tempdir().unwrap();
        let op = op_with_redis(None);
        let err = resolve_notifier_config(dir.path(), &op, &FakeResolver::new())
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("state-redis"),
            "error must mention state-redis: {msg}"
        );
    }

    #[tokio::test]
    async fn autodetect_uses_literal_url_from_envelope() {
        let dir = tempdir().unwrap();
        write_state_redis_envelope(dir.path(), "redis://envelope:6379");
        let op = op_with_redis(None);
        let resolved = resolve_notifier_config(dir.path(), &op, &FakeResolver::new())
            .await
            .unwrap();
        match resolved {
            NotifierConfig::Redis { url, .. } => {
                assert_eq!(url.as_deref(), Some("redis://envelope:6379"))
            }
            _ => panic!("expected Redis variant"),
        }
    }

    #[tokio::test]
    async fn autodetect_resolves_secret_uri() {
        let dir = tempdir().unwrap();
        write_state_redis_envelope(dir.path(), "secret://state-redis/url");
        let op = op_with_redis(None);
        let resolver = FakeResolver::with("secret://state-redis/url", "redis://resolved:6379");
        let resolved = resolve_notifier_config(dir.path(), &op, &resolver)
            .await
            .unwrap();
        match resolved {
            NotifierConfig::Redis { url, .. } => {
                assert_eq!(url.as_deref(), Some("redis://resolved:6379"))
            }
            _ => panic!("expected Redis variant"),
        }
    }

    #[tokio::test]
    async fn memory_backend_passes_through() {
        let dir = tempdir().unwrap();
        let op = OperatorConfig::default();
        let resolved = resolve_notifier_config(dir.path(), &op, &FakeResolver::new())
            .await
            .unwrap();
        assert!(matches!(resolved, NotifierConfig::Memory { .. }));
    }
}
