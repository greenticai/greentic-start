#![allow(dead_code)]

use std::{
    collections::{BTreeMap, HashSet},
    env,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Error as AnyhowError, Result as AnyhowResult, anyhow};
use async_trait::async_trait;
use greentic_secrets_lib::env::EnvSecretsManager;
use greentic_secrets_lib::{Result as SecretResult, SecretError, SecretsManager};
use serde::Deserialize;
use serde_cbor::value::Value as CborValue;
use tokio::runtime::Builder;
use tracing::info;
use zip::{ZipArchive, result::ZipError};

use crate::operator_log;
use crate::secret_name;
use crate::secret_value::SecretValue;
use crate::secrets_backend::SecretsBackendKind;
use crate::secrets_client::SecretsClient;
use crate::secrets_manager;

type CborMap = BTreeMap<CborValue, CborValue>;

pub type DynSecretsManager = Arc<dyn SecretsManager>;

struct LoggingSecretsManager {
    inner: DynSecretsManager,
    dev_store_path_display: String,
    using_env_fallback: bool,
}

impl LoggingSecretsManager {
    fn new(
        inner: DynSecretsManager,
        dev_store_path: Option<&Path>,
        using_env_fallback: bool,
    ) -> Self {
        let dev_store_path_display = dev_store_path
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<default>".to_string());
        Self {
            inner,
            dev_store_path_display,
            using_env_fallback,
        }
    }
}

#[async_trait]
impl SecretsManager for LoggingSecretsManager {
    async fn read(&self, path: &str) -> SecretResult<Vec<u8>> {
        operator_log::info(
            module_path!(),
            format!(
                "WASM secrets read requested uri={path}; backend dev_store_path={} using_env_fallback={}",
                self.dev_store_path_display, self.using_env_fallback,
            ),
        );
        match self.inner.read(path).await {
            Ok(value) => {
                operator_log::debug(
                    module_path!(),
                    format!(
                        "WASM secrets read resolved uri={path}; value={}",
                        SecretValue::new(value.as_slice()),
                    ),
                );
                Ok(value)
            }
            Err(err) => {
                // Fallback: if team-specific secret not found, try team="_" (wildcard).
                // Secrets saved at tenant-level (no team) live under "_" but runtime
                // may read with a specific team from the routing context.
                if let Some(fallback_path) = team_wildcard_fallback(path) {
                    operator_log::info(
                        module_path!(),
                        format!(
                            "WASM secrets read fallback: team-specific not found, trying uri={fallback_path}",
                        ),
                    );
                    if let Ok(value) = self.inner.read(&fallback_path).await {
                        operator_log::debug(
                            module_path!(),
                            format!(
                                "WASM secrets read fallback resolved uri={fallback_path}; value={}",
                                SecretValue::new(value.as_slice()),
                            ),
                        );
                        return Ok(value);
                    }
                }
                Err(err)
            }
        }
    }

    async fn write(&self, path: &str, value: &[u8]) -> SecretResult<()> {
        self.inner.write(path, value).await
    }

    async fn delete(&self, path: &str) -> SecretResult<()> {
        self.inner.delete(path).await
    }
}

/// If `path` is `secrets://env/tenant/TEAM/provider/key` and TEAM != "_",
/// return the same URI with TEAM replaced by "_".
fn team_wildcard_fallback(path: &str) -> Option<String> {
    let trimmed = path.strip_prefix("secrets://")?;
    let segments: Vec<&str> = trimmed.split('/').collect();
    if segments.len() != 5 {
        return None;
    }
    let team = segments[2];
    if team == "_" || team.is_empty() {
        return None; // Already wildcard, no fallback needed
    }
    Some(format!(
        "secrets://{}/{}/{}/{}/{}",
        segments[0], segments[1], "_", segments[3], segments[4]
    ))
}
const ENV_ALLOW_ENV_SECRETS: &str = "GREENTIC_ALLOW_ENV_SECRETS";

#[derive(Clone)]
pub struct SecretsManagerHandle {
    manager: DynSecretsManager,
    pub selection: secrets_manager::SecretsManagerSelection,
    pub dev_store_path: Option<PathBuf>,
    pub canonical_team: String,
    pub using_env_fallback: bool,
}

impl SecretsManagerHandle {
    pub fn manager(&self) -> DynSecretsManager {
        self.manager.clone()
    }

    pub fn runtime_manager(&self, _pack_id: Option<&str>) -> DynSecretsManager {
        Arc::new(LoggingSecretsManager::new(
            self.manager(),
            self.dev_store_path.as_deref(),
            self.using_env_fallback,
        ))
    }
}

pub fn resolve_secrets_manager(
    bundle_root: &Path,
    tenant: &str,
    team: Option<&str>,
) -> AnyhowResult<SecretsManagerHandle> {
    let canonical_team = secrets_manager::canonical_team(team);
    let team_owned = canonical_team.into_owned();
    let selection = secrets_manager::select_secrets_manager(bundle_root, tenant, &team_owned)?;
    let allow_env = matches!(env::var(ENV_ALLOW_ENV_SECRETS).as_deref(), Ok("1"));
    let pack_desc = selection
        .pack_path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<none>".to_string());
    let backend_kind_result = selection.kind();
    let backend_label = match &backend_kind_result {
        Ok(kind) => kind.to_string(),
        Err(_) => "<unknown>".to_string(),
    };
    let selection_kind_desc = backend_kind_result
        .as_ref()
        .map(|kind| kind.to_string())
        .unwrap_or_else(|err| format!("ERR({err})"));
    let dev_secrets_path =
        env::var("GREENTIC_DEV_SECRETS_PATH").unwrap_or_else(|_| "<unset>".to_string());
    operator_log::info(
        module_path!(),
        format!(
            "secrets selection: kind={} pack_path={} bundle_root={} env_allow_env_secrets={} GREENTIC_DEV_SECRETS_PATH={}",
            selection_kind_desc,
            pack_desc,
            bundle_root.display(),
            allow_env,
            dev_secrets_path,
        ),
    );
    let (manager, store_path, using_env_fallback) = instantiate_manager_from_selection(
        bundle_root,
        &selection,
        allow_env,
        &pack_desc,
        backend_kind_result,
    )?;
    operator_log::info(
        module_path!(),
        format!(
            "secrets runtime backend chosen: dev_store_path={} using_env_fallback={}",
            store_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            using_env_fallback
        ),
    );
    let runtime_dev_store_desc = store_path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<none>".to_string());
    eprintln!(
        "secrets: backend={} using_env_fallback={} dev_store_path={} selection_pack={} GREENTIC_DEV_SECRETS_PATH={}",
        backend_label, using_env_fallback, runtime_dev_store_desc, pack_desc, dev_secrets_path,
    );
    if let Some(pack_path) = &selection.pack_path {
        let dev_store_desc = store_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<default>".to_string());
        operator_log::info(
            module_path!(),
            format!(
                "secrets manager selected: {} (backend={} dev_store={})",
                pack_path.display(),
                backend_label,
                dev_store_desc
            ),
        );
    }
    Ok(SecretsManagerHandle {
        manager,
        selection,
        dev_store_path: store_path,
        canonical_team: team_owned,
        using_env_fallback,
    })
}

fn instantiate_manager_from_selection(
    bundle_root: &Path,
    selection: &secrets_manager::SecretsManagerSelection,
    allow_env: bool,
    pack_desc: &str,
    backend_kind_result: Result<SecretsBackendKind, AnyhowError>,
) -> AnyhowResult<(DynSecretsManager, Option<PathBuf>, bool)> {
    match backend_kind_result {
        Ok(kind) => match instantiate_manager_for_backend(bundle_root, selection, kind) {
            Ok((manager, path)) => Ok((manager, path, false)),
            Err(err) => fallback_to_env(allow_env, kind.to_string(), pack_desc, err),
        },
        Err(err) => fallback_to_env(allow_env, "<unknown>".to_string(), pack_desc, err),
    }
}

fn fallback_to_env(
    allow_env: bool,
    kind_label: String,
    pack_desc: &str,
    err: AnyhowError,
) -> AnyhowResult<(DynSecretsManager, Option<PathBuf>, bool)> {
    if allow_env {
        operator_log::warn(
            module_path!(),
            format!(
                "secrets backend {kind} ({pack}) failed to initialize; falling back to env secrets backend: {err}",
                kind = kind_label,
                pack = pack_desc,
            ),
        );
        Ok((Arc::new(EnvSecretsManager) as DynSecretsManager, None, true))
    } else {
        Err(err)
    }
}

fn instantiate_manager_for_backend(
    bundle_root: &Path,
    _selection: &secrets_manager::SecretsManagerSelection,
    backend_kind: SecretsBackendKind,
) -> AnyhowResult<(DynSecretsManager, Option<PathBuf>)> {
    match backend_kind {
        SecretsBackendKind::DevStore => open_dev_store_manager(bundle_root),
        SecretsBackendKind::Env => Ok((Arc::new(EnvSecretsManager) as DynSecretsManager, None)),
    }
}

fn open_dev_store_manager(
    bundle_root: &Path,
) -> AnyhowResult<(DynSecretsManager, Option<PathBuf>)> {
    let client = SecretsClient::open(bundle_root)?;
    let path = client.store_path().map(|path| path.to_path_buf());
    Ok((Arc::new(client) as DynSecretsManager, path))
}

/// Build the canonical secrets URI for the provided identity.
pub fn canonical_secret_uri(
    env: &str,
    tenant: &str,
    team: Option<&str>,
    provider: &str,
    key: &str,
) -> String {
    let team_segment = secrets_manager::canonical_team(team);
    let provider_segment = if provider.is_empty() {
        "messaging".to_string()
    } else {
        provider.to_string()
    };
    let normalized_key = secret_name::canonical_secret_name(key);
    format!(
        "secrets://{}/{}/{}/{}/{}",
        env, tenant, team_segment, provider_segment, normalized_key
    )
}

pub fn canonical_secret_store_key(uri: &str) -> Option<String> {
    let trimmed = uri.strip_prefix("secrets://")?;
    let segments: Vec<&str> = trimmed.split('/').collect();
    if segments.len() != 5 {
        return None;
    }
    let normalized = segments
        .into_iter()
        .map(normalize_store_segment)
        .collect::<Vec<_>>();
    let mut parts = vec!["GREENTIC_SECRET".to_string()];
    parts.extend(normalized);
    Some(parts.join("__"))
}

fn normalize_store_segment(segment: &str) -> String {
    let mut normalized = String::with_capacity(segment.len());
    for ch in segment.chars() {
        let replacement = match ch {
            'A'..='Z' | '0'..='9' => ch,
            'a'..='z' => ch.to_ascii_uppercase(),
            '_' => '_',
            _ => '_',
        };
        normalized.push(replacement);
    }
    normalized
}

fn secret_uri_candidates(
    env: &str,
    tenant: &str,
    canonical_team: &str,
    key: &str,
    provider_id: &str,
) -> Vec<String> {
    let normalized_key = secret_name::canonical_secret_name(key);
    let prefix = format!("secrets://{}/{}/{}/", env, tenant, canonical_team);
    vec![format!("{prefix}{provider_id}/{normalized_key}")]
}

fn display_secret_candidates(
    env: &str,
    tenant: &str,
    canonical_team: &str,
    key: &str,
    provider_id: &str,
) -> Vec<String> {
    let normalized_key = secret_name::canonical_secret_name(key);
    let prefix = format!("secrets://{}/{}/{}/", env, tenant, canonical_team);
    vec![format!("{prefix}{provider_id}/{normalized_key}")]
}

/// Check that the required secrets for the provider exist.
#[allow(clippy::too_many_arguments)]
pub fn check_provider_secrets(
    manager: &DynSecretsManager,
    env: &str,
    tenant: &str,
    team: Option<&str>,
    pack_path: &Path,
    provider_id: &str,
    _provider_type: Option<&str>,
    store_path: Option<&Path>,
    using_env_fallback: bool,
) -> anyhow::Result<Option<Vec<String>>> {
    let keys = load_secret_keys_from_pack(pack_path)?;
    if keys.is_empty() {
        return Ok(None);
    }

    let canonical_team = secrets_manager::canonical_team(team);
    let canonical_team_owned = canonical_team.into_owned();
    let team_display = team.unwrap_or("default");
    let store_desc = store_path
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| {
            if using_env_fallback {
                "<env store>".to_string()
            } else {
                "<default dev store>".to_string()
            }
        });
    let store_path_display = store_path
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<none>".to_string());

    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build secrets runtime")?;
    runtime.block_on(async {
        let mut missing = Vec::new();
        for key in keys {
            let normalized_key = secret_name::canonical_secret_name(&key);
            let candidates = secret_uri_candidates(
                env,
                tenant,
                &canonical_team_owned,
                &key,
                provider_id,
            );
            let display_candidates = display_secret_candidates(
                env,
                tenant,
                &canonical_team_owned,
                &key,
                provider_id,
            );
            operator_log::info(
                module_path!(),
                format!(
                    "checking secret URIs for provider {}: {}",
                    provider_id,
                    candidates
                        .iter()
                        .map(|uri| uri.as_str())
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            );
            if !display_candidates.is_empty() {
                let candidate_list = display_candidates
                    .iter()
                    .map(|uri| format!("  - {}", uri))
                    .collect::<Vec<_>>()
                    .join("\n");
                info!(
                    target: "secrets",
                    "checked secret URIs (store={} dev_store_path={}):\n{}",
                    store_desc,
                    store_path_display,
                    candidate_list
                );
            }
            let mut resolved = false;
            let mut candidate_missing = Vec::new();
            let mut matched_uri: Option<String> = None;
            for uri in &candidates {
                info!(
                    target: "secrets",
                    "secret lookup: uri={} secret_key={} dev_store_path={}",
                    uri,
                    normalized_key,
                    store_path_display
                );
                match manager.read(uri).await {
                    Ok(_) => {
                        resolved = true;
                        matched_uri = Some(uri.clone());
                        break;
                    }
                    Err(SecretError::NotFound(_)) => {
                        candidate_missing.push(uri.clone());
                    }
                    Err(err) => {
                        candidate_missing.push(uri.clone());
                        operator_log::warn(
                            module_path!(),
                            format!("secret lookup failed for {uri}: {err}"),
                        );
                    }
                }
            }
            let matched_display = matched_uri
                .as_deref()
                .map(|uri| uri.to_string())
                .unwrap_or_else(|| "<none>".to_string());
            operator_log::debug(
                module_path!(),
                format!(
                    "secrets: resolved {key}; store={} env={} tenant={} team={} canonical_team={} provider={} tried_keys={:?} matched_key={matched_display}",
                    store_desc,
                    env,
                    tenant,
                    team_display,
                    canonical_team_owned,
                    provider_id,
                    candidates
                ),
            );
            if !resolved {
                let display_set: HashSet<_> =
                    display_candidates.iter().collect();
                missing.extend(
                    candidate_missing
                        .into_iter()
                        .filter(|uri| display_set.contains(uri)),
                );
            }
        }
        if missing.is_empty() {
            Ok(None)
        } else {
            Ok(Some(missing))
        }
    })
}

fn load_secret_keys_from_pack(pack_path: &Path) -> anyhow::Result<Vec<String>> {
    let keys = load_keys_from_assets(pack_path)?;
    if !keys.is_empty() {
        return Ok(keys);
    }
    load_keys_from_manifest(pack_path)
}

fn load_keys_from_assets(pack_path: &Path) -> anyhow::Result<Vec<String>> {
    let file = File::open(pack_path)?;
    let mut archive = ZipArchive::new(file)?;
    const ASSET_PATHS: &[&str] = &[
        "assets/secret-requirements.json",
        "assets/secret_requirements.json",
        "secret-requirements.json",
        "secret_requirements.json",
    ];
    for asset in ASSET_PATHS {
        if let Ok(mut entry) = archive.by_name(asset) {
            let mut contents = String::new();
            entry.read_to_string(&mut contents)?;
            let requirements: Vec<AssetSecretRequirement> = serde_json::from_str(&contents)?;
            return Ok(requirements
                .into_iter()
                .filter(|req| req.required.unwrap_or(true))
                .filter_map(|req| req.key)
                .map(|key| key.to_lowercase())
                .collect());
        }
    }
    Ok(Vec::new())
}

fn load_keys_from_manifest(pack_path: &Path) -> anyhow::Result<Vec<String>> {
    let file = File::open(pack_path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut manifest = match archive.by_name("manifest.cbor") {
        Ok(file) => file,
        Err(ZipError::FileNotFound) => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    let mut bytes = Vec::new();
    manifest.read_to_end(&mut bytes)?;
    let value: CborValue = serde_cbor::from_slice(&bytes)?;
    if let CborValue::Map(map) = &value {
        return extract_keys_from_manifest_map(map);
    }
    Ok(Vec::new())
}

fn extract_keys_from_manifest_map(map: &CborMap) -> anyhow::Result<Vec<String>> {
    let symbols = symbols_map(map);
    let mut keys = Vec::new();
    if let Some(CborValue::Array(entries)) = map_get(map, "secret_requirements") {
        for entry in entries {
            if let CborValue::Map(entry_map) = entry {
                if !is_required(entry_map) {
                    continue;
                }
                if let Some(key_value) = map_get(entry_map, "key")
                    && let Some(key) =
                        resolve_string_symbol(Some(key_value), symbols, "secret_requirements")?
                {
                    keys.push(key.to_lowercase());
                }
            }
        }
    }
    Ok(keys)
}

fn is_required(entry: &CborMap) -> bool {
    match map_get(entry, "required") {
        Some(CborValue::Bool(value)) => *value,
        _ => true,
    }
}

fn map_get<'a>(map: &'a CborMap, key: &str) -> Option<&'a CborValue> {
    map.iter().find_map(|(k, v)| match k {
        CborValue::Text(text) if text == key => Some(v),
        _ => None,
    })
}

fn symbols_map(map: &CborMap) -> Option<&CborMap> {
    let symbols = map_get(map, "symbols")?;
    match symbols {
        CborValue::Map(map) => Some(map),
        _ => None,
    }
}

fn resolve_string_symbol(
    value: Option<&CborValue>,
    symbols: Option<&CborMap>,
    symbol_key: &str,
) -> anyhow::Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value {
        CborValue::Text(text) => Ok(Some(text.clone())),
        CborValue::Integer(idx) => {
            let Some(symbols) = symbols else {
                return Ok(Some(idx.to_string()));
            };
            let Some(values) = symbol_array(symbols, symbol_key) else {
                return Ok(Some(idx.to_string()));
            };
            let idx = usize::try_from(*idx).unwrap_or(usize::MAX);
            match values.get(idx) {
                Some(CborValue::Text(text)) => Ok(Some(text.clone())),
                _ => Ok(Some(idx.to_string())),
            }
        }
        _ => Err(anyhow!("expected string or symbol index")),
    }
}

fn symbol_array<'a>(symbols: &'a CborMap, key: &'a str) -> Option<&'a Vec<CborValue>> {
    if let Some(CborValue::Array(values)) = map_get(symbols, key) {
        return Some(values);
    }
    if let Some(stripped) = key.strip_suffix('s')
        && let Some(CborValue::Array(values)) = map_get(symbols, stripped)
    {
        return Some(values);
    }
    None
}

#[derive(Deserialize)]
struct AssetSecretRequirement {
    key: Option<String>,
    #[serde(default)]
    required: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use greentic_secrets_lib::Result as SecretResult;
    use greentic_secrets_lib::core::seed::{ApplyOptions, DevStore, apply_seed};
    use greentic_secrets_lib::{SecretFormat, SeedDoc, SeedEntry, SeedValue};
    use once_cell::sync::Lazy;
    use rand::RngExt;
    use std::collections::HashMap;
    use std::env;
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;
    use tokio::runtime::Runtime;
    use zip::ZipWriter;
    use zip::write::FileOptions;

    static PACK_FIXTURE: Lazy<PackFixture> = Lazy::new(build_test_pack);

    struct PackFixture {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    struct FakeManager {
        values: HashMap<String, Vec<u8>>,
    }

    impl FakeManager {
        fn new(values: HashMap<String, Vec<u8>>) -> Self {
            Self { values }
        }
    }

    #[async_trait]
    impl SecretsManager for FakeManager {
        async fn read(&self, path: &str) -> SecretResult<Vec<u8>> {
            self.values
                .get(path)
                .cloned()
                .ok_or_else(|| SecretError::NotFound(path.to_string()))
        }

        async fn write(&self, _: &str, _: &[u8]) -> SecretResult<()> {
            Err(SecretError::Permission("read-only".into()))
        }

        async fn delete(&self, _: &str) -> SecretResult<()> {
            Err(SecretError::Permission("read-only".into()))
        }
    }

    fn telegram_pack_path() -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("..");
        path.push("tests/demo-bundle/providers/messaging/messaging-telegram.gtpack");
        if path.exists() {
            return path.canonicalize().unwrap_or(path);
        }
        PACK_FIXTURE.path.clone()
    }

    fn build_test_pack() -> PackFixture {
        let dir = tempdir().expect("create temp dir for test pack");
        let path = dir.path().join("messaging-telegram.gtpack");
        let file = File::create(&path).expect("create test pack file");
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::<()>::default();
        zip.start_file("assets/secret-requirements.json", options)
            .expect("add secret requirements asset");
        zip.write_all(br#"[{"key":"telegram_bot_token","required":true}]"#)
            .expect("write secret requirements");
        zip.finish().expect("finish test pack");
        PackFixture { _dir: dir, path }
    }

    #[test]
    fn canonical_uri_uses_team_placeholder() {
        let uri = canonical_secret_uri("demo", "acme", None, "messaging", "FOO");
        assert_eq!(uri, "secrets://demo/acme/_/messaging/foo");
    }

    #[test]
    fn provider_secrets_missing_when_unsupported() -> anyhow::Result<()> {
        let manager: DynSecretsManager = Arc::new(FakeManager::new(HashMap::new()));
        let result = check_provider_secrets(
            &manager,
            "demo",
            "tenant",
            Some("default"),
            &telegram_pack_path(),
            "messaging-telegram",
            Some("messaging.telegram.bot"),
            None,
            false,
        )?;
        assert_eq!(
            result,
            Some(vec![
                "secrets://demo/tenant/_/messaging-telegram/telegram_bot_token".to_string()
            ])
        );
        Ok(())
    }

    #[test]
    fn provider_secrets_pass_when_supplied() -> anyhow::Result<()> {
        let mut values = HashMap::new();
        values.insert(
            "secrets://demo/tenant/_/messaging-telegram/telegram_bot_token".to_string(),
            b"token".to_vec(),
        );
        let manager: DynSecretsManager = Arc::new(FakeManager::new(values));
        let result = check_provider_secrets(
            &manager,
            "demo",
            "tenant",
            None,
            &telegram_pack_path(),
            "messaging-telegram",
            Some("messaging.telegram.bot"),
            None,
            false,
        )?;
        assert!(result.is_none());
        Ok(())
    }

    #[test]
    fn reads_provider_namespace_secret() -> anyhow::Result<()> {
        let dir = tempdir().unwrap();
        let store_path = dir.path().join("secrets.env");
        let store = DevStore::with_path(store_path.clone())?;
        let seed = SeedDoc {
            entries: vec![SeedEntry {
                uri: "secrets://demo/3point/_/messaging-telegram/telegram_bot_token".to_string(),
                format: SecretFormat::Text,
                value: SeedValue::Text {
                    text: "token".to_string(),
                },
                description: None,
            }],
        };
        let runtime = Runtime::new()?;
        let report =
            runtime.block_on(async { apply_seed(&store, &seed, ApplyOptions::default()).await });
        assert_eq!(report.ok, 1);
        let env_guard = crate::test_env_lock().lock().unwrap();
        unsafe {
            env::set_var("GREENTIC_DEV_SECRETS_PATH", store_path.clone());
        }
        let handle = resolve_secrets_manager(dir.path(), "3point", Some("default"))?;
        unsafe {
            env::remove_var("GREENTIC_DEV_SECRETS_PATH");
        }
        drop(env_guard);
        let missing = check_provider_secrets(
            &handle.manager(),
            "demo",
            "3point",
            Some("default"),
            &telegram_pack_path(),
            "messaging-telegram",
            Some("messaging.telegram.bot"),
            handle.dev_store_path.as_deref(),
            handle.using_env_fallback,
        )?;
        assert!(missing.is_none());
        Ok(())
    }

    #[test]
    fn resolves_dev_store_secret_with_canonical_team() -> anyhow::Result<()> {
        let dir = tempdir().unwrap();
        let store_path = dir.path().join("secrets.env");
        let store = DevStore::with_path(store_path.clone())?;
        let seed = SeedDoc {
            entries: vec![SeedEntry {
                uri: "secrets://demo/3point/_/messaging-telegram/telegram_bot_token".to_string(),
                format: SecretFormat::Text,
                value: SeedValue::Text {
                    text: "XYZ".to_string(),
                },
                description: None,
            }],
        };
        let runtime = Runtime::new()?;
        let report =
            runtime.block_on(async { apply_seed(&store, &seed, ApplyOptions::default()).await });
        assert_eq!(report.ok, 1);
        let env_guard = crate::test_env_lock().lock().unwrap();
        unsafe {
            env::set_var("GREENTIC_DEV_SECRETS_PATH", store_path);
        }
        let handle = resolve_secrets_manager(dir.path(), "3point", Some("default"))?;
        unsafe {
            env::remove_var("GREENTIC_DEV_SECRETS_PATH");
        }
        drop(env_guard);
        let missing = check_provider_secrets(
            &handle.manager(),
            "demo",
            "3point",
            Some("default"),
            &telegram_pack_path(),
            "messaging-telegram",
            Some("messaging.telegram.bot"),
            handle.dev_store_path.as_deref(),
            handle.using_env_fallback,
        )?;
        assert!(missing.is_none());
        Ok(())
    }

    #[test]
    fn secrets_handle_reads_dev_store_secret() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let store_path = dir.path().join("secrets.env");
        let store = DevStore::with_path(store_path.clone())?;
        let seed = SeedDoc {
            entries: vec![SeedEntry {
                uri: "secrets://demo/3point/_/messaging-telegram/telegram_bot_token".to_string(),
                format: SecretFormat::Text,
                value: SeedValue::Text {
                    text: "token".to_string(),
                },
                description: None,
            }],
        };
        let runtime = Runtime::new()?;
        let report =
            runtime.block_on(async { apply_seed(&store, &seed, ApplyOptions::default()).await });
        assert_eq!(report.ok, 1);
        let env_guard = crate::test_env_lock().lock().unwrap();
        unsafe {
            env::set_var("GREENTIC_DEV_SECRETS_PATH", store_path.clone());
        }
        let handle = resolve_secrets_manager(dir.path(), "demo", Some("default"))?;
        unsafe {
            env::remove_var("GREENTIC_DEV_SECRETS_PATH");
        }
        drop(env_guard);
        let value = runtime.block_on(async {
            handle
                .manager()
                .read("secrets://demo/3point/_/messaging-telegram/telegram_bot_token")
                .await
        })?;
        assert_eq!(value, b"token".to_vec());
        assert_eq!(handle.dev_store_path.as_deref(), Some(store_path.as_path()));
        Ok(())
    }

    #[test]
    fn dev_store_selection_uses_secrets_client() -> anyhow::Result<()> {
        let bundle_root = tempdir()?;
        let handle = resolve_secrets_manager(bundle_root.path(), "demo", Some("default"))?;
        assert!(handle.dev_store_path.is_some());
        assert!(!handle.using_env_fallback);
        Ok(())
    }

    #[test]
    fn resolve_secrets_manager_defaults_to_devstore_when_no_pack() -> anyhow::Result<()> {
        let bundle_root = tempdir()?;
        let handle = resolve_secrets_manager(bundle_root.path(), "demo", Some("default"))?;
        assert!(handle.selection.pack_path.is_none());
        assert!(handle.dev_store_path.is_some());
        assert!(!handle.using_env_fallback);
        Ok(())
    }

    #[test]
    fn env_selection_pack_uses_env_manager() -> anyhow::Result<()> {
        let bundle_root = tempdir()?;
        let tenant = "demo";
        let team = "default";
        let pack_dir = secrets_pack_dir(bundle_root.path(), tenant, team);
        let pack_path =
            write_secrets_pack(&pack_dir, "env-backend.gtpack", r#"{"backend":"env"}"#)?;
        let handle = resolve_secrets_manager(bundle_root.path(), tenant, Some(team))?;
        assert_eq!(
            handle.selection.pack_path.as_deref(),
            Some(pack_path.as_path())
        );
        assert!(handle.dev_store_path.is_none());
        assert!(!handle.using_env_fallback);
        let secret_value = random_secret_value();
        let expected_bytes = secret_value.clone().into_bytes();
        let secret_uri = canonical_secret_uri(
            "demo",
            tenant,
            Some(team),
            "messaging-webex",
            "webex_bot_token",
        );
        let runtime = Runtime::new()?;
        {
            let _env_guard = crate::test_env_lock().lock().unwrap();
            unsafe {
                env::set_var(&secret_uri, secret_value);
            }
            let value = runtime.block_on(async { handle.manager().read(&secret_uri).await })?;
            unsafe {
                env::remove_var(&secret_uri);
            }
            assert_eq!(value, expected_bytes);
        }
        Ok(())
    }

    #[test]
    fn resolve_secrets_manager_env_fallback_only_when_allowed() -> anyhow::Result<()> {
        let bundle_root = tempdir()?;
        let tenant = "demo";
        let team = "default";
        let pack_dir = secrets_pack_dir(bundle_root.path(), tenant, team);
        let _ = write_secrets_pack(&pack_dir, "bad-backend.gtpack", r#"{"backend":"vault"}"#)?;
        let env_guard = crate::test_env_lock().lock().unwrap();
        unsafe {
            env::remove_var(ENV_ALLOW_ENV_SECRETS);
        }
        let result = resolve_secrets_manager(bundle_root.path(), tenant, Some(team));
        drop(env_guard);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn resolve_secrets_manager_env_fallback_is_allowed_with_flag() -> anyhow::Result<()> {
        let bundle_root = tempdir()?;
        let tenant = "demo";
        let team = "default";
        let pack_dir = secrets_pack_dir(bundle_root.path(), tenant, team);
        let _ = write_secrets_pack(&pack_dir, "bad-backend.gtpack", r#"{"backend":"vault"}"#)?;
        let env_guard = crate::test_env_lock().lock().unwrap();
        unsafe {
            env::set_var(ENV_ALLOW_ENV_SECRETS, "1");
        }
        let handle = resolve_secrets_manager(bundle_root.path(), tenant, Some(team))?;
        unsafe {
            env::remove_var(ENV_ALLOW_ENV_SECRETS);
        }
        drop(env_guard);
        assert!(handle.dev_store_path.is_none());
        assert!(handle.using_env_fallback);
        Ok(())
    }

    fn write_secrets_pack(dir: &Path, name: &str, backend_config: &str) -> anyhow::Result<PathBuf> {
        fs::create_dir_all(dir)?;
        let pack_path = dir.join(name);
        let file = File::create(&pack_path)?;
        let mut zip = ZipWriter::new(file);
        let options: FileOptions<'_, ()> = FileOptions::default();
        zip.start_file("assets/secrets_backend.json", options)?;
        zip.write_all(backend_config.as_bytes())?;
        zip.finish()?;
        Ok(pack_path)
    }

    fn secrets_pack_dir(bundle_root: &Path, tenant: &str, team: &str) -> PathBuf {
        let canonical_team = secrets_manager::canonical_team(Some(team)).into_owned();
        bundle_root
            .join("providers")
            .join("secrets")
            .join(tenant)
            .join(canonical_team)
    }

    fn random_secret_value() -> String {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        format!("TEST_OPAQUE_{encoded}")
    }
}
