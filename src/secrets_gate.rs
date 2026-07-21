#![allow(dead_code)]

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Error as AnyhowError, Result as AnyhowResult, anyhow};
use async_trait::async_trait;
use greentic_secrets_lib::core::rt::sync_await;
use greentic_secrets_lib::core::{CoreBuilder, SecretsCore, SecretsError as CoreSecretsError};
use greentic_secrets_lib::env::EnvSecretsManager;
use greentic_secrets_lib::spec::Error as SpecError;
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
use crate::secrets_provider_binding::SecretsProviderBinding;

type CborMap = BTreeMap<CborValue, CborValue>;

pub type DynSecretsManager = Arc<dyn SecretsManager>;

// ---------------------------------------------------------------------------
// Caching wrapper — avoids hitting the secrets backend on every WASM call.
// ---------------------------------------------------------------------------

const CACHE_TTL_SECS: u64 = 300;
const CACHE_MAX_ENTRIES: usize = 512;

struct CacheEntry {
    data: Vec<u8>,
    inserted_at: Instant,
}

struct CachingSecretsManager {
    inner: DynSecretsManager,
    cache: Mutex<HashMap<String, CacheEntry>>,
    ttl: Duration,
    max_entries: usize,
}

impl CachingSecretsManager {
    fn wrap(inner: DynSecretsManager) -> DynSecretsManager {
        let ttl_secs = env::var("SECRETS_CACHE_TTL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(CACHE_TTL_SECS);
        if ttl_secs == 0 {
            return inner;
        }
        let max = env::var("SECRETS_CACHE_MAX_ENTRIES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(CACHE_MAX_ENTRIES);
        Arc::new(Self {
            inner,
            cache: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
            max_entries: max,
        })
    }
}

#[async_trait]
impl SecretsManager for CachingSecretsManager {
    async fn read(&self, path: &str) -> SecretResult<Vec<u8>> {
        {
            let mut cache = self.cache.lock().expect("secrets cache poisoned");
            if let Some(entry) = cache.get(path) {
                if entry.inserted_at.elapsed() < self.ttl {
                    return Ok(entry.data.clone());
                }
                cache.remove(path);
            }
        }
        let data = self.inner.read(path).await?;
        {
            let mut cache = self.cache.lock().expect("secrets cache poisoned");
            if cache.len() >= self.max_entries {
                // Evict oldest entry.
                if let Some(oldest_key) = cache
                    .iter()
                    .min_by_key(|(_, e)| e.inserted_at)
                    .map(|(k, _)| k.clone())
                {
                    cache.remove(&oldest_key);
                }
            }
            cache.insert(
                path.to_owned(),
                CacheEntry {
                    data: data.clone(),
                    inserted_at: Instant::now(),
                },
            );
        }
        Ok(data)
    }

    async fn write(&self, path: &str, bytes: &[u8]) -> SecretResult<()> {
        self.inner.write(path, bytes).await?;
        self.cache
            .lock()
            .expect("secrets cache poisoned")
            .remove(path);
        Ok(())
    }

    async fn delete(&self, path: &str) -> SecretResult<()> {
        self.inner.delete(path).await?;
        self.cache
            .lock()
            .expect("secrets cache poisoned")
            .remove(path);
        Ok(())
    }
}

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
                // Fallback candidates. The dev store canonicalizes the provider/key
                // segments at write time (setup uses canonical_secret_name), but the
                // WASM provider-invoke path in the external runner-host crate requests
                // the raw pack-stem provider (e.g. `messaging-webchat-gui`), so a
                // verbatim lookup misses the stored `messaging_webchat_gui`. Try the
                // canonicalized URI, plus the team="_" wildcard variants (secrets saved
                // at tenant-level live under "_" but the runtime may read with a
                // specific team from the routing context).
                let mut candidates: Vec<String> = Vec::new();
                if let Some(canon) = canonicalize_provider_segment(path) {
                    candidates.push(canon);
                }
                if let Some(fallback_path) = team_wildcard_fallback(path) {
                    if let Some(canon_fb) = canonicalize_provider_segment(&fallback_path) {
                        candidates.push(canon_fb);
                    }
                    candidates.push(fallback_path);
                }
                for candidate in candidates {
                    operator_log::info(
                        module_path!(),
                        format!("WASM secrets read fallback: trying uri={candidate}"),
                    );
                    if let Ok(value) = self.inner.read(&candidate).await {
                        operator_log::debug(
                            module_path!(),
                            format!(
                                "WASM secrets read fallback resolved uri={candidate}; value={}",
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

/// If `path` is `secrets://env/tenant/team/provider/key`, return the same URI with the
/// provider and key segments canonicalized (lowercase, `-`/`.`/`/`/space -> `_`) to match
/// how setup/store keys are normalized at write time. Returns None if it is already
/// canonical or not a 5-segment `secrets://` URI. This bridges the external runner-host
/// requesting a raw pack-stem provider (e.g. `messaging-webchat-gui`) against a store
/// keyed by the canonical `messaging_webchat_gui`.
fn canonicalize_provider_segment(path: &str) -> Option<String> {
    let trimmed = path.strip_prefix("secrets://")?;
    let segments: Vec<&str> = trimmed.split('/').collect();
    if segments.len() != 5 {
        return None;
    }
    let canonical_provider = secret_name::canonical_secret_name(segments[3]);
    let canonical_key = secret_name::canonical_secret_name(segments[4]);
    if canonical_provider == segments[3] && canonical_key == segments[4] {
        return None;
    }
    Some(format!(
        "secrets://{}/{}/{}/{}/{}",
        segments[0], segments[1], segments[2], canonical_provider, canonical_key
    ))
}
const ENV_ALLOW_ENV_SECRETS: &str = "GREENTIC_ALLOW_ENV_SECRETS";
const ENV_REQUIRE_PROVIDER_BINDING: &str = "GREENTIC_REQUIRE_SECRETS_PROVIDER_BINDING";
/// Selects the runtime secrets backend on the bundle-less `start --env` serve
/// path. The deployer renders this onto the worker pod (E.3); unlike the
/// `--bundle` path, the serve loop has no `.gtpack` to read a
/// `secrets_backend.json` from, so the kind comes from the process environment
/// instead. Absent/empty/`dev-store` keeps the env's own DevStore.
pub const ENV_SERVE_SECRETS_BACKEND: &str = "GREENTIC_SECRETS_BACKEND";

#[derive(Clone)]
pub struct SecretsManagerHandle {
    manager: DynSecretsManager,
    pub selection: secrets_manager::SecretsManagerSelection,
    pub provider_binding: Option<SecretsProviderBinding>,
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
    let allow_env = matches!(env::var(ENV_ALLOW_ENV_SECRETS).as_deref(), Ok("1"));
    if let Some((binding_path, binding)) = SecretsProviderBinding::load_from_bundle(bundle_root)? {
        return resolve_bound_secrets_manager(
            bundle_root,
            tenant,
            team,
            allow_env,
            binding_path,
            binding,
        );
    }
    if matches!(
        env::var(ENV_REQUIRE_PROVIDER_BINDING).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE")
    ) {
        return Err(anyhow!(
            "cloud secrets mode requires a secrets provider binding at .providers/platform/secrets-provider.json"
        ));
    }
    let selection = match secrets_manager::select_secrets_manager(bundle_root, tenant, &team_owned)
    {
        Ok(selection) => selection,
        Err(err) => {
            let (manager, store_path, using_env_fallback) =
                fallback_to_env(allow_env, "<selection>".to_string(), "<none>", err)?;
            let manager = CachingSecretsManager::wrap(manager);
            let manager = crate::oauth_secret_bridge::OAuthBridgingSecretsManager::wrap(
                manager,
                Some(Arc::new(
                    crate::oauth_secret_bridge::NoopProviderTokenResolver,
                )),
            );
            return Ok(SecretsManagerHandle {
                manager,
                selection: secrets_manager::SecretsManagerSelection {
                    scope: secrets_manager::SelectedKind::None,
                    pack_path: None,
                    reason: "secrets manager selection failed; using env fallback".to_string(),
                },
                provider_binding: None,
                dev_store_path: store_path,
                canonical_team: team_owned,
                using_env_fallback,
            });
        }
    };
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
        tenant,
        &team_owned,
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
    let manager = CachingSecretsManager::wrap(manager);
    // OAuth bake-in: refresh-on-read. `/oauth/callback` persists the token at the
    // pack-scoped key the adapter reads; this resolver serves it and silently
    // refreshes via the native OAuth engine when it's near expiry (using the sibling
    // refresh_token/client_id/secret). Non-OAuth keys and tokens without an
    // `expires_at` fall through unchanged.
    let resolver: std::sync::Arc<dyn crate::oauth_secret_bridge::ProviderTokenResolver> =
        std::sync::Arc::new(crate::oauth_secret_bridge::RefreshingResolver::new(
            manager.clone(),
        ));
    let manager =
        crate::oauth_secret_bridge::OAuthBridgingSecretsManager::wrap(manager, Some(resolver));
    Ok(SecretsManagerHandle {
        manager,
        selection,
        provider_binding: None,
        dev_store_path: store_path,
        canonical_team: team_owned,
        using_env_fallback,
    })
}

fn resolve_bound_secrets_manager(
    bundle_root: &Path,
    tenant: &str,
    team: Option<&str>,
    allow_env: bool,
    binding_path: PathBuf,
    binding: SecretsProviderBinding,
) -> AnyhowResult<SecretsManagerHandle> {
    let canonical_team = secrets_manager::canonical_team(team).into_owned();
    let pack_path = binding.resolved_pack_path(bundle_root);
    let selection = secrets_manager::SecretsManagerSelection {
        scope: secrets_manager::SelectedKind::Binding,
        pack_path: pack_path.clone(),
        reason: format!(
            "secrets provider binding {} selected provider {}",
            binding_path.display(),
            binding.provider_id
        ),
    };
    let pack_desc = pack_path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<none>".to_string());
    operator_log::info(
        module_path!(),
        format!(
            "secrets provider binding selected: path={} provider_id={} pack_path={}",
            binding_path.display(),
            binding.provider_id,
            pack_desc,
        ),
    );

    let backend_kind = binding.backend_kind(bundle_root);
    let backend_label = backend_kind
        .as_ref()
        .map(|kind| match kind {
            Some(kind) => kind.to_string(),
            None => format!("binding:{}", binding.provider_id),
        })
        .unwrap_or_else(|err| format!("ERR({err})"));
    let (manager, store_path, using_env_fallback) = match backend_kind {
        Ok(Some(kind)) => match instantiate_manager_for_backend(
            bundle_root,
            tenant,
            &canonical_team,
            &selection,
            kind,
        ) {
            Ok((manager, path)) => Ok((manager, path, false)),
            Err(err) => fallback_to_env(allow_env, kind.to_string(), &pack_desc, err),
        },
        Ok(None) => {
            let err = anyhow!(
                "secrets provider binding {} does not declare a supported runtime backend; provider_id={} requires a linked greentic-secrets provider adapter",
                binding_path.display(),
                binding.provider_id
            );
            fallback_to_env(
                allow_env,
                format!("binding:{}", binding.provider_id),
                &pack_desc,
                err,
            )
        }
        Err(err) => fallback_to_env(
            allow_env,
            format!("binding:{}", binding.provider_id),
            &pack_desc,
            err,
        ),
    }?;

    operator_log::info(
        module_path!(),
        format!(
            "secrets runtime backend chosen from binding: provider_id={} backend={} dev_store_path={} using_env_fallback={}",
            binding.provider_id,
            backend_label,
            store_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            using_env_fallback
        ),
    );
    eprintln!(
        "secrets: binding_provider={} backend={} using_env_fallback={} dev_store_path={} selection_pack={}",
        binding.provider_id,
        backend_label,
        using_env_fallback,
        store_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        pack_desc,
    );

    let manager = CachingSecretsManager::wrap(manager);
    // OAuth bake-in (host resolver): intercept `auth.oauth2.*.access_token` reads
    // and resolve a valid token via greentic-oauth (mint/refresh). With the no-op
    // resolver these fall through to the store unchanged; the greentic-oauth-backed
    // resolver is wired in separately.
    let manager = crate::oauth_secret_bridge::OAuthBridgingSecretsManager::wrap(
        manager,
        Some(Arc::new(
            crate::oauth_secret_bridge::NoopProviderTokenResolver,
        )),
    );
    Ok(SecretsManagerHandle {
        manager,
        selection,
        provider_binding: Some(binding),
        dev_store_path: store_path,
        canonical_team,
        using_env_fallback,
    })
}

fn instantiate_manager_from_selection(
    bundle_root: &Path,
    tenant: &str,
    canonical_team: &str,
    selection: &secrets_manager::SecretsManagerSelection,
    allow_env: bool,
    pack_desc: &str,
    backend_kind_result: Result<SecretsBackendKind, AnyhowError>,
) -> AnyhowResult<(DynSecretsManager, Option<PathBuf>, bool)> {
    match backend_kind_result {
        Ok(kind) => {
            match instantiate_manager_for_backend(
                bundle_root,
                tenant,
                canonical_team,
                selection,
                kind,
            ) {
                Ok((manager, path)) => Ok((manager, path, false)),
                Err(err) => fallback_to_env(allow_env, kind.to_string(), pack_desc, err),
            }
        }
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
    tenant: &str,
    canonical_team: &str,
    _selection: &secrets_manager::SecretsManagerSelection,
    backend_kind: SecretsBackendKind,
) -> AnyhowResult<(DynSecretsManager, Option<PathBuf>)> {
    match backend_kind {
        SecretsBackendKind::DevStore => open_dev_store_manager(bundle_root),
        SecretsBackendKind::Env => Ok((Arc::new(EnvSecretsManager) as DynSecretsManager, None)),
        SecretsBackendKind::Vault => build_vault_manager(tenant, canonical_team),
    }
}

/// Select the bundle-less serve-path secrets manager from
/// [`ENV_SERVE_SECRETS_BACKEND`] (the env var the deployer renders onto the
/// worker pod).
///
/// Unlike [`resolve_secrets_manager`], the `start --env` serve loop has no
/// `.gtpack` to read a `secrets_backend.json` from, so the backend kind comes
/// from the process environment. An absent/empty/`dev-store` value opens the
/// env's own DevStore rooted at `env_dir` — byte-identical to the prior
/// hardcoded boot. `vault` resolves `secret://` refs under the pod's workload
/// identity, scoped to `tenant` (the env's single `tenant_org_id`) and the
/// whole-env team placeholder (tenant-level, no specific team). An unknown kind
/// fails closed. HostBuilder's default env-var backend rejects non-local envs,
/// so the serve path always supplies its own manager here.
///
/// Returns the manager and the tenant org it is scoped to: `Some(tenant)` for
/// Vault (whose embedded `SecretsCore` resolves a single tenant org), `None`
/// for the unscoped DevStore/Env backends. The serve path uses this scope to
/// fail closed when a served deployment's tenant falls outside it (a single
/// worker pod's Vault manager cannot resolve another tenant org's secrets) —
/// see `activate_runtime_config`.
pub fn resolve_serve_secrets_manager(
    env_dir: &Path,
    tenant: &str,
) -> AnyhowResult<(DynSecretsManager, Option<String>)> {
    let raw = env::var(ENV_SERVE_SECRETS_BACKEND).unwrap_or_default();
    let kind = SecretsBackendKind::parse(&raw)
        .with_context(|| format!("invalid {ENV_SERVE_SECRETS_BACKEND}={raw:?}"))?;
    let (manager, dev_store_path) = serve_secrets_manager_for_kind(kind, env_dir, tenant)?;
    // Wrap with the same canonicalization/team-wildcard fallback chain the
    // `--bundle` runner-host gets via `SecretsManagerHandle::runtime_manager`:
    // stores are keyed with canonical underscore provider segments while the
    // external runner-host requests raw pack-stem providers (e.g.
    // `messaging-webchat-gui`), so a raw manager misses on every provider
    // self-read (webchat `jwt_signing_key` → 500 secret_error → token 502).
    let manager: DynSecretsManager = Arc::new(LoggingSecretsManager::new(
        manager,
        dev_store_path.as_deref(),
        false,
    ));
    let tenant_scope = matches!(kind, SecretsBackendKind::Vault).then(|| tenant.to_string());
    Ok((manager, tenant_scope))
}

/// Pure backend dispatch behind [`resolve_serve_secrets_manager`], split out so
/// the DevStore/Vault/Env mapping is unit-testable without mutating the
/// process-wide [`ENV_SERVE_SECRETS_BACKEND`]. Returns the dev-store path (the
/// `DevStore` arm only) for assertion + logging.
fn serve_secrets_manager_for_kind(
    kind: SecretsBackendKind,
    env_dir: &Path,
    tenant: &str,
) -> AnyhowResult<(DynSecretsManager, Option<PathBuf>)> {
    let (manager, dev_store_path) = match kind {
        SecretsBackendKind::DevStore => open_dev_store_manager(env_dir)?,
        SecretsBackendKind::Env => (Arc::new(EnvSecretsManager) as DynSecretsManager, None),
        SecretsBackendKind::Vault => {
            build_vault_manager(tenant, greentic_secrets_lib::TEAM_PLACEHOLDER)?
        }
    };
    operator_log::info(
        module_path!(),
        format!(
            "serve-path secrets backend selected: kind={kind} tenant={tenant} dev_store_path={}",
            dev_store_path
                .as_deref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<none>".to_string()),
        ),
    );
    Ok((manager, dev_store_path))
}

fn open_dev_store_manager(
    bundle_root: &Path,
) -> AnyhowResult<(DynSecretsManager, Option<PathBuf>)> {
    // `818e5da` routed the setup *writer* and the `dev_store_path` helpers to
    // the shared env store (`~/.greentic/environments/<env>/.greentic/dev/…`)
    // when `$GREENTIC_ENV` is set, but this runtime *reader* still rooted the
    // dev store at the (ephemeral) bundle root — so it never saw the secrets
    // `gtc setup` registered, and every WASM secret read (weather API key, …)
    // came back not-found. Resolve the same env-store-aware path the writer
    // uses; fall back to the bundle root only when no store exists yet.
    let client = match crate::dev_store_path::find_existing(bundle_root) {
        Some(store_path) => SecretsClient::open_with_path(store_path)?,
        None => SecretsClient::open(bundle_root)?,
    };
    let path = client.store_path().map(|path| path.to_path_buf());
    Ok((Arc::new(client) as DynSecretsManager, path))
}

/// Construct a Vault-backed runtime secrets manager under the pod's workload
/// identity.
///
/// The Vault connection (`VAULT_ADDR`, `VAULT_K8S_ROLE` or `VAULT_TOKEN`, KV
/// mount/prefix) is read from the process environment, which the deployer
/// renders onto the worker pod (E.3). With `VAULT_K8S_ROLE` set, the provider
/// exchanges the pod's projected ServiceAccount JWT for a short-lived Vault
/// token — no long-lived secret is baked into the workload. Records are
/// envelope-decrypted by the embedded [`SecretsCore`]; the pod's Vault role is
/// expected to grant read-only access to its KV path, so the resulting manager
/// rejects writes.
///
/// The core is scoped to `tenant` and — for a concrete team — to
/// `canonical_team`, so it rejects reads of another team's
/// `secrets://<env>/<tenant>/<other-team>/...` even when the pod's Vault role
/// would permit the broader tenant path. The `_` placeholder means tenant-level
/// (no specific team); it is left unscoped so the tenant-level wildcard (which
/// parses to no team) still resolves — matching the dev-store manager.
///
/// `build_backend()` and `CoreBuilder::build()` are async, so the whole
/// construction is driven via [`sync_await`] — which reuses the ambient Tokio
/// runtime when present and otherwise spins the shared secrets runtime, never
/// nesting runtimes.
fn build_vault_manager(
    tenant: &str,
    canonical_team: &str,
) -> AnyhowResult<(DynSecretsManager, Option<PathBuf>)> {
    let tenant = tenant.to_string();
    let team = (canonical_team != greentic_secrets_lib::TEAM_PLACEHOLDER)
        .then(|| canonical_team.to_string());
    let core = sync_await(async move {
        let components = greentic_secrets_lib::vault::build_backend()
            .await
            .context("initialize vault secrets backend")?;
        let mut builder = CoreBuilder::default().tenant(tenant);
        if let Some(team) = team {
            builder = builder.team(team);
        }
        builder
            .backend(components.backend, components.key_provider)
            .build()
            .await
            .context("build vault secrets core")
    })?;
    Ok((
        Arc::new(CoreSecretsManager { core }) as DynSecretsManager,
        None,
    ))
}

/// Adapts an embedded [`SecretsCore`] — which envelope-decrypts records,
/// enforces the configured tenant/team scope, and caches reads — to the runtime
/// [`SecretsManager`] interface. Backend-agnostic: the Vault wiring lives in
/// [`build_vault_manager`]. Writes and deletes are rejected because runtime
/// workloads resolve secrets under a read-only identity.
struct CoreSecretsManager {
    core: SecretsCore,
}

#[async_trait]
impl SecretsManager for CoreSecretsManager {
    async fn read(&self, path: &str) -> SecretResult<Vec<u8>> {
        match self.core.get_bytes(path).await {
            Ok(bytes) => Ok(bytes),
            Err(CoreSecretsError::Core(SpecError::NotFound { .. })) => {
                Err(SecretError::NotFound(path.to_string()))
            }
            Err(err) => Err(SecretError::Backend(err.to_string().into())),
        }
    }

    async fn write(&self, _: &str, _: &[u8]) -> SecretResult<()> {
        Err(SecretError::Permission(
            "vault runtime secrets backend is read-only".into(),
        ))
    }

    async fn delete(&self, _: &str) -> SecretResult<()> {
        Err(SecretError::Permission(
            "vault runtime secrets backend is read-only".into(),
        ))
    }
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
    // Normalize the provider segment the same way as the key (and as the cloud
    // secret name / env-bridge key already do), so a value written under a
    // provider id like `messaging-webchat-gui` resolves when a component fetches
    // it under `messaging.webchat-gui` — both collapse to `messaging_webchat_gui`.
    let provider_segment = if provider.is_empty() {
        "messaging".to_string()
    } else {
        secret_name::canonical_secret_name(provider)
    };
    let normalized_key = secret_name::canonical_secret_name(key);
    format!(
        "secrets://{}/{}/{}/{}/{}",
        env, tenant, team_segment, provider_segment, normalized_key
    )
}

/// Derive the env-var lookup key for a 5-segment `secrets://` store URI.
///
/// Delegates to `greentic-secrets`
/// ([`greentic_secrets_lib::canonical_secret_store_key`]) — the single shared
/// definition the runtime reader and the deployer's resolver both use, so a
/// secret exported as an env var is found under exactly the key it was written
/// as.
pub fn canonical_secret_store_key(uri: &str) -> Option<String> {
    greentic_secrets_lib::canonical_secret_store_key(uri)
}

/// Store-key candidates for a secret, reconciling differing provider string forms
/// (raw `messaging-webchat-gui` vs canonical `messaging_webchat_gui`). The raw
/// provider form is first; the canonical (underscored) form is added when it
/// differs. This is the canonicalization middleware for read/existence CRITICAL
/// PATHS — without it a writer and reader that disagree on the provider segment
/// resolve different keys (e.g. a regenerated `jwt_signing_key` → a minted token
/// that fails to verify → 401).
pub fn secret_uri_candidates(
    env: &str,
    tenant: &str,
    canonical_team: &str,
    key: &str,
    provider_id: &str,
) -> Vec<String> {
    let normalized_key = secret_name::canonical_secret_name(key);
    let prefix = format!("secrets://{}/{}/{}/", env, tenant, canonical_team);
    let mut out = vec![format!("{prefix}{provider_id}/{normalized_key}")];
    let canonical_provider = secret_name::canonical_secret_name(provider_id);
    if canonical_provider != provider_id {
        let canon = format!("{prefix}{canonical_provider}/{normalized_key}");
        if !out.contains(&canon) {
            out.push(canon);
        }
    }
    out
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
    fn canonical_uri_normalizes_provider_segment() {
        // A secret stored under the pack provider id `messaging-webchat-gui`
        // must resolve when a component fetches it under its dotted manifest id
        // `messaging.webchat-gui` — both collapse to `messaging_webchat_gui`.
        let stored = canonical_secret_uri(
            "dev",
            "demo",
            None,
            "messaging-webchat-gui",
            "jwt_signing_key",
        );
        let fetched = canonical_secret_uri(
            "dev",
            "demo",
            None,
            "messaging.webchat-gui",
            "jwt_signing_key",
        );
        assert_eq!(stored, fetched);
        assert_eq!(
            stored,
            "secrets://dev/demo/_/messaging_webchat_gui/jwt_signing_key"
        );
    }

    #[test]
    fn canonicalize_provider_segment_normalizes_provider_and_key() {
        // The external runner-host requests the raw pack-stem provider; the read
        // chokepoint must canonicalize it to match the stored key.
        assert_eq!(
            canonicalize_provider_segment(
                "secrets://dev/demo/_/messaging-webchat-gui/jwt_signing_key"
            ),
            Some("secrets://dev/demo/_/messaging_webchat_gui/jwt_signing_key".to_string())
        );
        // Dotted manifest id collapses the same way.
        assert_eq!(
            canonicalize_provider_segment(
                "secrets://dev/demo/team-a/messaging.webchat-gui/JWT-Signing-Key"
            ),
            Some("secrets://dev/demo/team-a/messaging_webchat_gui/jwt_signing_key".to_string())
        );
    }

    #[test]
    fn canonicalize_provider_segment_skips_already_canonical_and_malformed() {
        // Already canonical -> None (no redundant retry).
        assert_eq!(
            canonicalize_provider_segment(
                "secrets://dev/demo/_/messaging_webchat_gui/jwt_signing_key"
            ),
            None
        );
        // Not a 5-segment secrets URI -> None.
        assert_eq!(
            canonicalize_provider_segment("secrets://dev/demo/_/key"),
            None
        );
        assert_eq!(canonicalize_provider_segment("not-a-secret-uri"), None);
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
            env::remove_var("GREENTIC_SECRETS_MANAGER_PACK");
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
        let env_guard = crate::test_env_lock().lock().unwrap();
        unsafe {
            env::remove_var("GREENTIC_SECRETS_MANAGER_PACK");
        }
        let handle = resolve_secrets_manager(bundle_root.path(), "demo", Some("default"))?;
        drop(env_guard);
        assert!(handle.dev_store_path.is_some());
        assert!(!handle.using_env_fallback);
        Ok(())
    }

    #[test]
    fn resolve_secrets_manager_defaults_to_devstore_when_no_pack() -> anyhow::Result<()> {
        let bundle_root = tempdir()?;
        let env_guard = crate::test_env_lock().lock().unwrap();
        unsafe {
            env::remove_var("GREENTIC_SECRETS_MANAGER_PACK");
        }
        let handle = resolve_secrets_manager(bundle_root.path(), "demo", Some("default"))?;
        drop(env_guard);
        assert!(handle.selection.pack_path.is_none());
        assert!(handle.dev_store_path.is_some());
        assert!(!handle.using_env_fallback);
        Ok(())
    }

    /// Regression guard for the env-store secrets move (setup #226 / start #423).
    ///
    /// When `$GREENTIC_ENV` is set, the setup *writer* (`dev_store_path::ensure_path`,
    /// as `gtc setup` uses) and the runtime *reader* (`open_dev_store_manager` ->
    /// `find_existing`) must independently resolve the SAME shared env store under
    /// the greentic home — never the ephemeral bundle root. Before the fix the
    /// reader rooted the store at the bundle root, so secrets `gtc setup`
    /// registered came back not-found at runtime (the weather-API-key symptom).
    /// This test deliberately does NOT set `GREENTIC_DEV_SECRETS_PATH`, so it
    /// exercises the real env-store rendezvous rather than the override shortcut.
    #[test]
    fn setup_writer_and_runtime_reader_rendezvous_on_env_store() -> anyhow::Result<()> {
        let home = tempdir()?;
        let bundle_root = tempdir()?;
        let uri = "secrets://local/acme/_/weatherapi_pack/auth_param_get_weather_key";
        let runtime = Runtime::new()?;

        let env_guard = crate::test_env_lock().lock().unwrap();
        let prev_home = env::var_os("HOME");
        let prev_env = env::var_os("GREENTIC_ENV");
        let prev_override = env::var_os("GREENTIC_DEV_SECRETS_PATH");
        unsafe {
            env::set_var("HOME", home.path());
            env::set_var("GREENTIC_ENV", "local");
            env::remove_var("GREENTIC_DEV_SECRETS_PATH");
        }

        // All env-dependent, fallible work in one closure so the env is restored
        // unconditionally afterwards (keeping `test_env_lock` unpoisoned) and every
        // assertion runs only once the process env is back to normal.
        let captured =
            (|| -> anyhow::Result<(PathBuf, usize, DynSecretsManager, Option<PathBuf>)> {
                // WRITER: resolve + create the store exactly as `gtc setup` would, then seed.
                let writer_path = crate::dev_store_path::ensure_path(bundle_root.path())?;
                let store = DevStore::with_path(writer_path.clone())?;
                let seed = SeedDoc {
                    entries: vec![SeedEntry {
                        uri: uri.to_string(),
                        format: SecretFormat::Text,
                        value: SeedValue::Text {
                            text: "WEATHER_KEY".to_string(),
                        },
                        description: None,
                    }],
                };
                let report = runtime
                    .block_on(async { apply_seed(&store, &seed, ApplyOptions::default()).await });
                // READER: the runtime side resolves + reads back independently.
                let (manager, reader_path) = open_dev_store_manager(bundle_root.path())?;
                Ok((writer_path, report.ok, manager, reader_path))
            })();

        unsafe {
            match prev_home {
                Some(value) => env::set_var("HOME", value),
                None => env::remove_var("HOME"),
            }
            match prev_env {
                Some(value) => env::set_var("GREENTIC_ENV", value),
                None => env::remove_var("GREENTIC_ENV"),
            }
            if let Some(value) = prev_override {
                env::set_var("GREENTIC_DEV_SECRETS_PATH", value);
            }
        }
        drop(env_guard);

        let (writer_path, seeded, manager, reader_path) = captured?;
        assert_eq!(seeded, 1, "writer should have seeded exactly one secret");
        assert!(
            writer_path.starts_with(home.path()),
            "writer resolved {writer_path:?}; expected the shared env store under {:?}",
            home.path()
        );
        assert!(
            !writer_path.starts_with(bundle_root.path()),
            "writer must not fall back to the ephemeral bundle root ({:?})",
            bundle_root.path()
        );
        assert_eq!(
            reader_path.as_deref(),
            Some(writer_path.as_path()),
            "runtime reader must rendezvous on the writer's env-store path"
        );
        let value = runtime.block_on(async { manager.read(uri).await })?;
        assert_eq!(value, b"WEATHER_KEY".to_vec());
        Ok(())
    }

    #[test]
    fn local_runtime_ignores_cloud_provider_packs_and_defaults_to_devstore() -> anyhow::Result<()> {
        let bundle_root = tempdir()?;
        let providers_secrets = bundle_root.path().join("providers").join("secrets");
        write_cloud_provider_pack(&providers_secrets, "aws-sm.gtpack")?;
        write_cloud_provider_pack(&providers_secrets, "azure-kv.gtpack")?;
        write_cloud_provider_pack(&providers_secrets, "gcp-sm.gtpack")?;

        let env_guard = crate::test_env_lock().lock().unwrap();
        unsafe {
            env::remove_var("GREENTIC_SECRETS_MANAGER_PACK");
            env::remove_var(ENV_REQUIRE_PROVIDER_BINDING);
        }
        let handle = resolve_secrets_manager(bundle_root.path(), "demo", Some("default"))?;
        drop(env_guard);

        assert_eq!(handle.selection.scope, secrets_manager::SelectedKind::None);
        assert!(handle.selection.pack_path.is_none());
        assert!(handle.provider_binding.is_none());
        assert!(handle.dev_store_path.is_some());
        assert!(!handle.using_env_fallback);
        Ok(())
    }

    #[test]
    fn provider_binding_env_backend_accepts_arbitrary_provider_id() -> anyhow::Result<()> {
        let bundle_root = tempdir()?;
        write_provider_binding(
            bundle_root.path(),
            "greentic.secrets.custom-vendor",
            r#""backend":"env""#,
            None,
        )?;
        let env_guard = crate::test_env_lock().lock().unwrap();
        unsafe {
            env::remove_var("GREENTIC_SECRETS_MANAGER_PACK");
        }
        let handle = resolve_secrets_manager(bundle_root.path(), "demo", Some("default"))?;
        drop(env_guard);

        assert_eq!(
            handle.selection.scope,
            secrets_manager::SelectedKind::Binding
        );
        assert_eq!(
            handle
                .provider_binding
                .as_ref()
                .map(|binding| binding.provider_id.as_str()),
            Some("greentic.secrets.custom-vendor")
        );
        assert!(handle.dev_store_path.is_none());
        assert!(!handle.using_env_fallback);
        Ok(())
    }

    #[test]
    fn provider_binding_wins_over_scoped_pack_discovery() -> anyhow::Result<()> {
        let bundle_root = tempdir()?;
        write_provider_binding(
            bundle_root.path(),
            "greentic.secrets.custom-vendor",
            r#""backend":"env""#,
            None,
        )?;
        let pack_dir = secrets_pack_dir(bundle_root.path(), "demo", "default");
        let _ = write_secrets_pack(
            &pack_dir,
            "dev-backend.gtpack",
            r#"{"backend":"dev-store"}"#,
        )?;
        let env_guard = crate::test_env_lock().lock().unwrap();
        unsafe {
            env::remove_var("GREENTIC_SECRETS_MANAGER_PACK");
        }
        let handle = resolve_secrets_manager(bundle_root.path(), "demo", Some("default"))?;
        drop(env_guard);

        assert_eq!(
            handle.selection.scope,
            secrets_manager::SelectedKind::Binding
        );
        assert!(handle.dev_store_path.is_none());
        Ok(())
    }

    #[test]
    fn explicit_provider_binding_wins_over_cloud_provider_packs() -> anyhow::Result<()> {
        let bundle_root = tempdir()?;
        let providers_secrets = bundle_root.path().join("providers").join("secrets");
        write_cloud_provider_pack(&providers_secrets, "aws-sm.gtpack")?;
        write_cloud_provider_pack(&providers_secrets, "azure-kv.gtpack")?;
        write_cloud_provider_pack(&providers_secrets, "gcp-sm.gtpack")?;
        write_provider_binding(
            bundle_root.path(),
            "greentic.secrets.aws-sm",
            r#""backend":"env""#,
            Some("providers/secrets/aws-sm.gtpack"),
        )?;

        let env_guard = crate::test_env_lock().lock().unwrap();
        unsafe {
            env::remove_var("GREENTIC_SECRETS_MANAGER_PACK");
            env::remove_var(ENV_REQUIRE_PROVIDER_BINDING);
        }
        let handle = resolve_secrets_manager(bundle_root.path(), "demo", Some("default"))?;
        drop(env_guard);

        assert_eq!(
            handle.selection.scope,
            secrets_manager::SelectedKind::Binding
        );
        assert_eq!(
            handle
                .provider_binding
                .as_ref()
                .map(|binding| binding.provider_id.as_str()),
            Some("greentic.secrets.aws-sm")
        );
        assert!(handle.dev_store_path.is_none());
        assert!(!handle.using_env_fallback);
        Ok(())
    }

    #[test]
    fn cloud_mode_requires_provider_binding_when_flagged() -> anyhow::Result<()> {
        let bundle_root = tempdir()?;
        let env_guard = crate::test_env_lock().lock().unwrap();
        unsafe {
            env::remove_var("GREENTIC_SECRETS_MANAGER_PACK");
            env::set_var(ENV_REQUIRE_PROVIDER_BINDING, "1");
        }
        let err = match resolve_secrets_manager(bundle_root.path(), "demo", Some("default")) {
            Ok(_) => anyhow!("expected provider binding requirement to fail"),
            Err(err) => err,
        };
        unsafe {
            env::remove_var(ENV_REQUIRE_PROVIDER_BINDING);
        }
        drop(env_guard);

        assert!(
            err.to_string()
                .contains("requires a secrets provider binding")
        );
        Ok(())
    }

    #[test]
    fn cloud_mode_requires_provider_binding_even_with_cloud_provider_packs() -> anyhow::Result<()> {
        let bundle_root = tempdir()?;
        let providers_secrets = bundle_root.path().join("providers").join("secrets");
        write_cloud_provider_pack(&providers_secrets, "aws-sm.gtpack")?;
        write_cloud_provider_pack(&providers_secrets, "azure-kv.gtpack")?;
        write_cloud_provider_pack(&providers_secrets, "gcp-sm.gtpack")?;

        let env_guard = crate::test_env_lock().lock().unwrap();
        unsafe {
            env::remove_var("GREENTIC_SECRETS_MANAGER_PACK");
            env::set_var(ENV_REQUIRE_PROVIDER_BINDING, "1");
        }
        let err = match resolve_secrets_manager(bundle_root.path(), "demo", Some("default")) {
            Ok(_) => anyhow!("expected provider binding requirement to fail"),
            Err(err) => err,
        };
        unsafe {
            env::remove_var(ENV_REQUIRE_PROVIDER_BINDING);
        }
        drop(env_guard);

        assert!(
            err.to_string()
                .contains("requires a secrets provider binding")
        );
        Ok(())
    }

    #[test]
    fn provider_binding_without_supported_backend_fails_clearly() -> anyhow::Result<()> {
        let bundle_root = tempdir()?;
        write_provider_binding(
            bundle_root.path(),
            "greentic.secrets.aws-sm",
            r#""region":"eu-north-1""#,
            None,
        )?;
        let env_guard = crate::test_env_lock().lock().unwrap();
        unsafe {
            env::remove_var("GREENTIC_SECRETS_MANAGER_PACK");
            env::remove_var(ENV_ALLOW_ENV_SECRETS);
        }
        let err = match resolve_secrets_manager(bundle_root.path(), "demo", Some("default")) {
            Ok(_) => anyhow!("expected unsupported provider binding to fail"),
            Err(err) => err,
        };
        drop(env_guard);

        assert!(
            err.to_string()
                .contains("requires a linked greentic-secrets provider adapter")
        );
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
        let env_guard = crate::test_env_lock().lock().unwrap();
        unsafe {
            env::remove_var("GREENTIC_SECRETS_MANAGER_PACK");
        }
        let handle = resolve_secrets_manager(bundle_root.path(), tenant, Some(team))?;
        drop(env_guard);
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
        let _ = write_secrets_pack(&pack_dir, "bad-backend.gtpack", r#"{"backend":"nonsense"}"#)?;
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
        let _ = write_secrets_pack(&pack_dir, "bad-backend.gtpack", r#"{"backend":"nonsense"}"#)?;
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

    fn write_cloud_provider_pack(dir: &Path, name: &str) -> anyhow::Result<PathBuf> {
        fs::create_dir_all(dir)?;
        let pack_path = dir.join(name);
        let file = File::create(&pack_path)?;
        let mut zip = ZipWriter::new(file);
        let options: FileOptions<'_, ()> = FileOptions::default();
        zip.start_file("pack.json", options)?;
        zip.write_all(br#"{"pack_id":"greentic.secrets.adapter"}"#)?;
        zip.finish()?;
        Ok(pack_path)
    }

    fn write_provider_binding(
        bundle_root: &Path,
        provider_id: &str,
        config_fields: &str,
        pack: Option<&str>,
    ) -> anyhow::Result<PathBuf> {
        let binding_dir = bundle_root.join("state/config/platform");
        fs::create_dir_all(&binding_dir)?;
        let binding_path = binding_dir.join("secrets-provider.json");
        let pack_field = pack
            .map(|pack| format!(r#","pack":"{}""#, pack))
            .unwrap_or_default();
        fs::write(
            &binding_path,
            format!(
                r#"{{
                  "schema_version":"greentic.secrets.binding.v1",
                  "provider_id":"{}"{},
                  "config":{{{}}}
                }}"#,
                provider_id, pack_field, config_fields
            ),
        )?;
        Ok(binding_path)
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

    #[test]
    fn vault_backend_kind_parsed_from_pack() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let pack_path =
            write_secrets_pack(dir.path(), "vault-backend.gtpack", r#"{"backend":"vault"}"#)?;
        assert_eq!(
            crate::secrets_backend::backend_kind_from_pack(&pack_path)?,
            SecretsBackendKind::Vault
        );
        assert_eq!(SecretsBackendKind::Vault.to_string(), "vault");

        let alias_path = write_secrets_pack(
            dir.path(),
            "vault-alias.gtpack",
            r#"{"backend":"hashicorp-vault"}"#,
        )?;
        assert_eq!(
            crate::secrets_backend::backend_kind_from_pack(&alias_path)?,
            SecretsBackendKind::Vault
        );
        Ok(())
    }

    #[test]
    fn core_secrets_manager_reads_plaintext_and_is_read_only() -> anyhow::Result<()> {
        use greentic_secrets_lib::core::{MemoryBackend, MemoryKeyProvider};

        let runtime = Runtime::new()?;
        let uri = "secrets://dev/acme/_/messaging-telegram/telegram_bot_token";
        let payload = serde_json::json!("XYZ");

        // A single core so the in-memory key provider decrypts what it wrote.
        let manager = runtime.block_on(async {
            let core = CoreBuilder::default()
                .tenant("acme")
                .backend(MemoryBackend::new(), MemoryKeyProvider::default())
                .build()
                .await?;
            core.put_json(uri, &payload).await?;
            anyhow::Ok(CoreSecretsManager { core })
        })?;

        // Reads return the decrypted plaintext bytes.
        let bytes = runtime.block_on(async { manager.read(uri).await })?;
        assert_eq!(bytes, serde_json::to_vec(&payload)?);

        // Missing secrets surface as NotFound so the missing-secret UX works.
        let missing = runtime.block_on(async {
            manager
                .read("secrets://dev/acme/_/messaging-telegram/absent")
                .await
        });
        assert!(matches!(missing, Err(SecretError::NotFound(_))));

        // Runtime resolution is read-only: writes and deletes are rejected.
        let write = runtime.block_on(async { manager.write(uri, b"new").await });
        assert!(matches!(write, Err(SecretError::Permission(_))));
        let delete = runtime.block_on(async { manager.delete(uri).await });
        assert!(matches!(delete, Err(SecretError::Permission(_))));
        Ok(())
    }

    #[test]
    fn core_secrets_manager_enforces_team_scope() -> anyhow::Result<()> {
        use greentic_secrets_lib::core::{MemoryBackend, MemoryKeyProvider};

        let runtime = Runtime::new()?;
        let own = "secrets://dev/acme/sales/messaging-telegram/telegram_bot_token";
        let wildcard = "secrets://dev/acme/_/messaging-telegram/shared_token";

        // A team-scoped core — what build_vault_manager configures for a
        // concrete team: tenant `acme`, team `sales`.
        let manager = runtime.block_on(async {
            let core = CoreBuilder::default()
                .tenant("acme")
                .team("sales")
                .backend(MemoryBackend::new(), MemoryKeyProvider::default())
                .build()
                .await?;
            core.put_json(own, &serde_json::json!("S")).await?;
            core.put_json(wildcard, &serde_json::json!("W")).await?;
            anyhow::Ok(CoreSecretsManager { core })
        })?;

        // The configured team and the `_` wildcard (which parses to no team)
        // both resolve.
        assert!(runtime.block_on(async { manager.read(own).await }).is_ok());
        assert!(
            runtime
                .block_on(async { manager.read(wildcard).await })
                .is_ok()
        );

        // Another concrete team is refused by the scope guard before the backend
        // is consulted — a hard denial, not a NotFound.
        let cross = runtime.block_on(async {
            manager
                .read("secrets://dev/acme/marketing/messaging-telegram/telegram_bot_token")
                .await
        });
        assert!(cross.is_err());
        assert!(!matches!(cross, Err(SecretError::NotFound(_))));
        Ok(())
    }

    #[test]
    fn serve_secrets_manager_for_kind_dev_store_opens_env_dir() -> anyhow::Result<()> {
        // DevStore is the byte-identical replacement for the prior hardcoded
        // `SecretsClient::open(env_dir)` serve-path boot: it roots the dev store
        // at the env dir and reports its path.
        let env_dir = tempdir()?;
        let (_manager, dev_store_path) =
            serve_secrets_manager_for_kind(SecretsBackendKind::DevStore, env_dir.path(), "demo")?;
        assert!(dev_store_path.is_some());
        Ok(())
    }

    #[test]
    fn serve_secrets_manager_for_kind_env_has_no_dev_store() -> anyhow::Result<()> {
        let env_dir = tempdir()?;
        let (_manager, dev_store_path) =
            serve_secrets_manager_for_kind(SecretsBackendKind::Env, env_dir.path(), "demo")?;
        assert!(dev_store_path.is_none());
        Ok(())
    }

    #[test]
    fn resolve_serve_secrets_manager_defaults_to_dev_store_when_unset() -> anyhow::Result<()> {
        // Unset env var → DevStore (the deployer omits the var for dev-store
        // envs). `parse("")` pins the default; the resolver then succeeds.
        assert_eq!(SecretsBackendKind::parse("")?, SecretsBackendKind::DevStore);
        let env_dir = tempdir()?;
        let env_guard = crate::test_env_lock().lock().unwrap();
        unsafe {
            env::remove_var(ENV_SERVE_SECRETS_BACKEND);
        }
        let resolved = resolve_serve_secrets_manager(env_dir.path(), "demo");
        drop(env_guard);
        let (_manager, tenant_scope) = resolved?;
        assert!(tenant_scope.is_none(), "dev-store is tenant-unscoped");
        Ok(())
    }

    #[test]
    fn resolve_serve_secrets_manager_rejects_unknown_backend() -> anyhow::Result<()> {
        let env_dir = tempdir()?;
        let env_guard = crate::test_env_lock().lock().unwrap();
        unsafe {
            env::set_var(ENV_SERVE_SECRETS_BACKEND, "bogus");
        }
        let result = resolve_serve_secrets_manager(env_dir.path(), "demo");
        unsafe {
            env::remove_var(ENV_SERVE_SECRETS_BACKEND);
        }
        drop(env_guard);
        assert!(result.is_err());
        Ok(())
    }

    /// Seed a DevStore at the env dir's default location with a single
    /// underscore-keyed entry (the canonical form greentic-setup and
    /// `SecretsSetup` persist), then hand back the serve-path manager.
    fn serve_manager_over_underscore_store(
        env_dir: &Path,
        runtime: &Runtime,
    ) -> anyhow::Result<DynSecretsManager> {
        let store_path = env_dir.join(".greentic/dev/.dev.secrets.env");
        std::fs::create_dir_all(store_path.parent().unwrap())?;
        let store = DevStore::with_path(store_path)?;
        let seed = SeedDoc {
            entries: vec![SeedEntry {
                uri: "secrets://local/demo/_/messaging_webchat_gui/jwt_signing_key".to_string(),
                format: SecretFormat::Text,
                value: SeedValue::Text {
                    text: "signing-key".to_string(),
                },
                description: None,
            }],
        };
        let report =
            runtime.block_on(async { apply_seed(&store, &seed, ApplyOptions::default()).await });
        assert_eq!(report.ok, 1);
        let env_guard = crate::test_env_lock().lock().unwrap();
        unsafe {
            env::remove_var(ENV_SERVE_SECRETS_BACKEND);
            env::remove_var("GREENTIC_DEV_SECRETS_PATH");
        }
        let resolved = resolve_serve_secrets_manager(env_dir, "demo");
        drop(env_guard);
        let (manager, _tenant_scope) = resolved?;
        Ok(manager)
    }

    #[test]
    fn serve_manager_resolves_underscore_store_from_hyphenated_uri() -> anyhow::Result<()> {
        // The external runner-host (provider self-reads on the revision path)
        // requests raw pack-stem providers: `messaging-webchat-gui`. The store
        // is keyed canonically: `messaging_webchat_gui`. Without the fallback
        // wrapper this read is NotFound and the webchat token op 500s.
        let env_dir = tempdir()?;
        let runtime = Runtime::new()?;
        let manager = serve_manager_over_underscore_store(env_dir.path(), &runtime)?;
        let value = runtime.block_on(async {
            manager
                .read("secrets://local/demo/_/messaging-webchat-gui/jwt_signing_key")
                .await
        })?;
        assert_eq!(value, b"signing-key");
        Ok(())
    }

    #[test]
    fn serve_manager_applies_team_wildcard_fallback() -> anyhow::Result<()> {
        // Reads carrying a concrete team (e.g. `default` from the routing
        // context) must fall back to the tenant-level `_` wildcard entry.
        let env_dir = tempdir()?;
        let runtime = Runtime::new()?;
        let manager = serve_manager_over_underscore_store(env_dir.path(), &runtime)?;
        let value = runtime.block_on(async {
            manager
                .read("secrets://local/demo/default/messaging-webchat-gui/jwt_signing_key")
                .await
        })?;
        assert_eq!(value, b"signing-key");
        Ok(())
    }
}
