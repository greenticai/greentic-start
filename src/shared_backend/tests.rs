use std::sync::Arc;

use async_trait::async_trait;
use greentic_secrets_lib::{Result as SecretResult, SecretError, SecretsManager};

use super::*;
use crate::triggers::store::{self, Selection};

fn some(s: &str) -> Option<String> {
    Some(s.to_string())
}

#[test]
fn nothing_shared_leaves_the_environment_exactly_as_it_was() {
    let v = merge_storage_vars(None, some("memory"), None, &SharedBackend::none());
    assert_eq!(v.session_backend, None);
    assert_eq!(v.state_backend, some("memory"));
    assert_eq!(v.redis_url, None);
}

#[test]
fn a_shared_url_names_redis_for_both_stores_the_environment_left_unset() {
    let shared = SharedBackend::from_url(some("redis://shared:6379"));
    let v = merge_storage_vars(None, None, None, &shared);
    assert_eq!(v.session_backend, some("redis"));
    assert_eq!(v.state_backend, some("redis"));
    assert_eq!(v.redis_url, some("redis://shared:6379"));
}

#[test]
fn environment_variables_override_the_shared_backend_per_setting() {
    let shared = SharedBackend::from_url(some("redis://shared:6379"));
    let v = merge_storage_vars(some("memory"), None, some("redis://override:6379"), &shared);
    assert_eq!(v.session_backend, some("memory"));
    assert_eq!(v.state_backend, some("redis"));
    assert_eq!(v.redis_url, some("redis://override:6379"));
}

#[test]
fn a_blank_shared_url_is_no_shared_backend() {
    assert_eq!(SharedBackend::from_url(some("   ")), SharedBackend::none());
}

#[test]
fn the_capabilities_document_names_the_shared_backend_flag() {
    let doc: serde_json::Value = serde_json::from_str(&capabilities_json()).unwrap();
    assert_eq!(doc["schema"], CAPABILITIES_SCHEMA);
    assert_eq!(doc["capabilities"][0], "shared-state-backend");
    assert_eq!(doc["version"], env!("CARGO_PKG_VERSION"));
}

// ── trigger store selection and the fail-loud rule ───────────────────

#[test]
fn trigger_env_beats_the_shared_secret_which_beats_the_pin_fallback() {
    let shared = SharedBackend::from_url(some("redis://shared"));
    let sel = store::select(some("redis://trig"), some("redis://pin"), &shared);
    assert_eq!(sel.url, some("redis://trig"));
    assert!(sel.strict);
    let sel = store::select(None, some("redis://pin"), &shared);
    assert_eq!(sel.url, some("redis://shared"));
    assert!(sel.strict);
    let sel = store::select(None, some("redis://pin"), &SharedBackend::none());
    assert_eq!(sel.url, some("redis://pin"));
    assert!(!sel.strict, "the pin URL fallback never promised sharing");
}

async fn unreachable_connect(_url: String) -> anyhow::Result<Arc<dyn store::TriggerStore>> {
    Err(anyhow::anyhow!("connection refused"))
}

#[tokio::test]
async fn an_unreachable_shared_backend_fails_the_boot_instead_of_going_in_memory() {
    let sel = store::select(
        None,
        None,
        &SharedBackend::from_url(some("redis://shared:6379")),
    );
    let err = store::resolve_selection(&sel, unreachable_connect)
        .await
        .map(|_| ())
        .expect_err("a configured shared backend that is down must not fall back");
    let text = format!("{err:#}");
    assert!(text.contains("refusing to boot"), "got: {text}");
    assert!(text.contains("connection refused"), "got: {text}");
}

#[tokio::test]
async fn an_unreachable_pin_fallback_still_fails_open() {
    let sel = Selection {
        url: some("redis://pin"),
        strict: false,
        origin: "pin",
    };
    assert!(
        store::resolve_selection(&sel, unreachable_connect)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn no_url_resolves_to_in_memory_without_connecting() {
    let sel = store::select(None, None, &SharedBackend::none());
    let resolved = store::resolve_selection(&sel, |_| async {
        Err(anyhow::anyhow!("must not be called"))
    })
    .await;
    assert!(resolved.is_ok());
}

// ── reading the staged secret ─────────────────────────────────────────

struct FakeSecrets(Vec<(String, SecretResult<Vec<u8>>)>);

#[async_trait]
impl SecretsManager for FakeSecrets {
    async fn read(&self, path: &str) -> SecretResult<Vec<u8>> {
        for (uri, answer) in &self.0 {
            if uri == path {
                return match answer {
                    Ok(bytes) => Ok(bytes.clone()),
                    Err(_) => Err(SecretError::Backend("store down".into())),
                };
            }
        }
        Err(SecretError::NotFound(path.to_string()))
    }
    async fn write(&self, _: &str, _: &[u8]) -> SecretResult<()> {
        Ok(())
    }
    async fn delete(&self, _: &str) -> SecretResult<()> {
        Ok(())
    }
}

fn canonical(tenant: &str) -> String {
    crate::secrets_gate::canonical_secret_uri("prod", tenant, None, SECRET_PROVIDER, SECRET_KEY)
}

#[tokio::test]
async fn the_staged_secret_is_read_under_the_served_tenant_then_default() {
    let secrets: crate::secrets_gate::DynSecretsManager = Arc::new(FakeSecrets(vec![(
        canonical("default"),
        Ok(b" redis://staged:6379\n".to_vec()),
    )]));
    let shared = SharedBackend::read(&secrets, "prod", "acme").await.unwrap();
    assert_eq!(shared.url(), Some("redis://staged:6379"));
}

#[tokio::test]
async fn an_absent_secret_means_no_shared_backend() {
    let secrets: crate::secrets_gate::DynSecretsManager = Arc::new(FakeSecrets(vec![]));
    let shared = SharedBackend::read(&secrets, "prod", "acme").await.unwrap();
    assert_eq!(shared, SharedBackend::none());
}

#[tokio::test]
async fn a_failing_secret_store_is_an_error_not_an_absent_secret() {
    let secrets: crate::secrets_gate::DynSecretsManager = Arc::new(FakeSecrets(vec![(
        canonical("acme"),
        Err(SecretError::Backend("x".into())),
    )]));
    assert!(SharedBackend::read(&secrets, "prod", "acme").await.is_err());
}
