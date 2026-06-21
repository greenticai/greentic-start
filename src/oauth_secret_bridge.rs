//! OAuth bake-in token bridge (host resolver — "Option A").
//!
//! Retained as a dormant fallback: the Phase 4 signed-state flow persists the
//! token directly at the adapter's pack-scoped key, so `secrets_gate` wires this
//! bridge with `resolver = None`. The provider-scoped resolver below is kept for
//! the broker-backed (greentic-oauth refresh) path and its tests.
#![allow(dead_code)]
//!
//! The MCP bake-in adapter/router read an OAuth access token from the secret
//! store under a per-tool key like `auth.oauth2.<scheme>.access_token` (scoped to
//! `secrets://<env>/<tenant>/<team>/<segment>/auth_oauth2_<scheme>_access_token`).
//! greentic-oauth, meanwhile, owns the OAuth dance + token persistence/refresh.
//!
//! This module bridges the two: a [`SecretsManager`] wrapper that intercepts
//! reads of an oauth2 access-token key and delegates to a [`ProviderTokenResolver`]
//! (backed by greentic-oauth) to mint/refresh and return a *valid* token. Any
//! other key — or an unresolved token — falls through to the inner manager, so a
//! manually-seeded token still works and non-OAuth secrets are unaffected.
//!
//! The resolver is the seam: the default [`NoopProviderTokenResolver`] returns
//! `None` (behaviour identical to no bridge), and the greentic-oauth-backed
//! resolver is wired in separately.

use std::sync::Arc;

use async_trait::async_trait;
use greentic_secrets_lib::{Result as SecretResult, SecretsManager};

use crate::secrets_gate::DynSecretsManager;

/// Parsed identity of an OAuth2 access-token secret key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthTokenKey {
    pub env: String,
    pub tenant: String,
    /// Team segment as stored in the scoped key (`_` for the default team).
    pub team: String,
    /// The pack/provider segment of the scoped key.
    pub segment: String,
    /// OAuth security-scheme name (lower-cased), e.g. `githuboauth`.
    pub scheme: String,
    /// The full scoped key as received.
    pub scoped_key: String,
}

impl OAuthTokenKey {
    /// greentic-oauth provider id for this key. The MCP key carries the OpenAPI
    /// security-scheme name (e.g. `githuboauth`); the broker is keyed by provider
    /// id (e.g. `github`). Default heuristic: drop a trailing `oauth`/`oidc`
    /// suffix; otherwise use the scheme as-is. Callers can override via a map.
    pub fn provider_id(&self) -> String {
        let s = self.scheme.as_str();
        for suffix in ["_oauth", "oauth", "_oidc", "oidc"] {
            if let Some(stripped) = s.strip_suffix(suffix)
                && !stripped.is_empty()
            {
                return stripped.trim_end_matches('_').to_string();
            }
        }
        s.to_string()
    }
}

/// Resolves a valid OAuth access token for a bake-in secret key.
///
/// Implementations (backed by greentic-oauth) perform: token lookup → refresh
/// when expired → return a valid token, or `None` when no token can be produced
/// (so the adapter falls back to rendering the sign-in card).
#[async_trait]
pub trait ProviderTokenResolver: Send + Sync {
    async fn resolve_access_token(&self, key: &OAuthTokenKey) -> Option<String>;
}

/// Fetches a valid provider access token (load → refresh-if-expired) for a
/// `(provider_id, tenant, team, subject)` tuple. Implemented in the host over
/// greentic-oauth-broker; kept as a seam so this module stays free of the broker
/// dependency and is unit-testable. `subject = None` is the shared-credential
/// mode; `Some(subject)` is user-owned (per the credential-modes design).
#[async_trait]
pub trait ProviderTokenFetch: Send + Sync {
    async fn fetch(
        &self,
        provider_id: &str,
        tenant: &str,
        team: &str,
        subject: Option<&str>,
    ) -> Option<String>;
}

/// [`ProviderTokenResolver`] that maps the MCP key to a broker token request and
/// delegates to a [`ProviderTokenFetch`] (the greentic-oauth-broker integration).
pub struct BrokerTokenResolver<F: ProviderTokenFetch> {
    fetch: F,
}

impl<F: ProviderTokenFetch> BrokerTokenResolver<F> {
    pub fn new(fetch: F) -> Self {
        Self { fetch }
    }
}

#[async_trait]
impl<F: ProviderTokenFetch> ProviderTokenResolver for BrokerTokenResolver<F> {
    async fn resolve_access_token(&self, key: &OAuthTokenKey) -> Option<String> {
        // Shared-credential mode for now (subject=None). User-owned mode threads
        // the envelope subject through once it's available at this layer.
        self.fetch
            .fetch(&key.provider_id(), &key.tenant, &key.team, None)
            .await
    }
}

/// Canonical secret URI where our own OAuth callback persists a provider access
/// token: `secrets://<env>/<tenant>/<team>/oauth/<provider>/access_token`.
/// Shared by the callback (write) and the resolver (read).
pub fn provider_token_uri(env: &str, tenant: &str, team: &str, provider_id: &str) -> String {
    // Store URI is exactly secrets://<env>/<tenant>/<team>/<provider>/<key> (5
    // segments); the provider segment is the provider id, the key is access_token.
    format!("secrets://{env}/{tenant}/{team}/{provider_id}/access_token")
}

/// Resolver for our own OAuth card flow: when the MCP component reads
/// `auth.oauth2.<scheme>.access_token`, return the token our `/oauth/callback`
/// persisted at `oauth/<provider>/access_token` (scheme→provider mapped). Reads
/// the inner secret store directly (no broker, no host call → no chicken-egg).
pub struct SecretStoreResolver {
    inner: DynSecretsManager,
}

impl SecretStoreResolver {
    pub fn new(inner: DynSecretsManager) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl ProviderTokenResolver for SecretStoreResolver {
    async fn resolve_access_token(&self, key: &OAuthTokenKey) -> Option<String> {
        let uri = provider_token_uri(&key.env, &key.tenant, &key.team, &key.provider_id());
        match self.inner.read(&uri).await {
            Ok(bytes) => {
                let token = String::from_utf8(bytes).ok()?;
                let token = token.trim();
                if token.is_empty() {
                    None
                } else {
                    Some(token.to_string())
                }
            }
            Err(_) => None,
        }
    }
}

/// Default resolver: never resolves (the bridge then falls through to the inner
/// secret store). Keeps behaviour identical to having no bridge until a real
/// greentic-oauth-backed resolver is wired in.
pub struct NoopProviderTokenResolver;

#[async_trait]
impl ProviderTokenResolver for NoopProviderTokenResolver {
    async fn resolve_access_token(&self, _key: &OAuthTokenKey) -> Option<String> {
        None
    }
}

/// Refresh-on-read resolver: serves the stored pack-scoped access token, refreshing
/// it via the native OAuth engine when it's near expiry — using the sibling
/// `refresh_token` / `client_id` / `client_secret` secrets and the provider's token
/// endpoint. Tokens with no recorded `expires_at` (e.g. GitHub classic) are returned
/// as-is. Returns `None` only when there's nothing to serve, so the bridge falls
/// through to the inner store.
pub struct RefreshingResolver {
    inner: DynSecretsManager,
}

impl RefreshingResolver {
    pub fn new(inner: DynSecretsManager) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl ProviderTokenResolver for RefreshingResolver {
    async fn resolve_access_token(&self, key: &OAuthTokenKey) -> Option<String> {
        let base = key.scoped_key.strip_suffix("_access_token")?;
        let sib = |suffix: &str| format!("{base}_{suffix}");
        let read = |uri: String| {
            let m = self.inner.clone();
            async move {
                m.read(&uri)
                    .await
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            }
        };

        let access = read(key.scoped_key.clone()).await;
        let now = chrono::Utc::now().timestamp();
        let expired = match read(sib("expires_at"))
            .await
            .and_then(|s| s.parse::<i64>().ok())
        {
            Some(exp) => now >= exp - 60, // 60s skew
            None => false,                // no expiry recorded => treat as long-lived
        };
        if let Some(tok) = &access
            && !expired
        {
            return Some(tok.clone());
        }

        // Expired (or missing) + refreshable: refresh via the engine and persist.
        let refresh_token = read(sib("refresh_token")).await?;
        let client_id = read(sib("client_id")).await?;
        let client_secret = read(sib("client_secret")).await;
        let token_url = crate::oauth_engine::provider_profile(&key.provider_id())?.token_url;
        let (turl, cid, csec, rt) = (
            token_url.to_string(),
            client_id,
            client_secret,
            refresh_token,
        );
        let refreshed = tokio::task::spawn_blocking(move || {
            crate::oauth_engine::refresh(&turl, &cid, csec.as_deref(), &rt)
        })
        .await
        .ok()?
        .ok()?;

        let _ = self
            .inner
            .write(&key.scoped_key, refreshed.access_token.as_bytes())
            .await;
        if let Some(secs) = refreshed.expires_in {
            let _ = self
                .inner
                .write(
                    &sib("expires_at"),
                    (now + secs as i64).to_string().as_bytes(),
                )
                .await;
        }
        if let Some(new_rt) = &refreshed.refresh_token {
            let _ = self
                .inner
                .write(&sib("refresh_token"), new_rt.as_bytes())
                .await;
        }
        Some(refreshed.access_token)
    }
}

/// Parse a scoped secret key into an [`OAuthTokenKey`] when it names an oauth2
/// access token (`auth_oauth2_<scheme>_access_token`), else `None`.
pub fn parse_oauth_access_token_key(scoped_key: &str) -> Option<OAuthTokenKey> {
    let rest = scoped_key.strip_prefix("secrets://")?;
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() < 5 {
        return None;
    }
    let safe_key = *parts.last()?;
    let scheme = safe_key
        .strip_prefix("auth_oauth2_")
        .and_then(|mid| mid.strip_suffix("_access_token"))
        .filter(|scheme| !scheme.is_empty())?;
    Some(OAuthTokenKey {
        env: parts[0].to_string(),
        tenant: parts[1].to_string(),
        team: parts[2].to_string(),
        segment: parts[3].to_string(),
        scheme: scheme.to_string(),
        scoped_key: scoped_key.to_string(),
    })
}

/// [`SecretsManager`] decorator that resolves oauth2 access-token reads via a
/// [`ProviderTokenResolver`], falling through to `inner` for everything else.
pub struct OAuthBridgingSecretsManager {
    inner: DynSecretsManager,
    resolver: Arc<dyn ProviderTokenResolver>,
}

impl OAuthBridgingSecretsManager {
    pub fn new(inner: DynSecretsManager, resolver: Arc<dyn ProviderTokenResolver>) -> Self {
        Self { inner, resolver }
    }

    /// Wrap `inner`, returning it unchanged when `resolver` is `None` (no bridge).
    pub fn wrap(
        inner: DynSecretsManager,
        resolver: Option<Arc<dyn ProviderTokenResolver>>,
    ) -> DynSecretsManager {
        match resolver {
            Some(resolver) => Arc::new(Self::new(inner, resolver)) as DynSecretsManager,
            None => inner,
        }
    }
}

#[async_trait]
impl SecretsManager for OAuthBridgingSecretsManager {
    async fn read(&self, path: &str) -> SecretResult<Vec<u8>> {
        if let Some(key) = parse_oauth_access_token_key(path)
            && let Some(token) = self.resolver.resolve_access_token(&key).await
        {
            return Ok(token.into_bytes());
        }
        // Not an oauth2 token key, or the resolver produced nothing — fall
        // through so seeded tokens and ordinary secrets still resolve.
        self.inner.read(path).await
    }

    async fn write(&self, path: &str, bytes: &[u8]) -> SecretResult<()> {
        self.inner.write(path, bytes).await
    }

    async fn delete(&self, path: &str) -> SecretResult<()> {
        self.inner.delete(path).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_secrets_lib::SecretError;
    use std::sync::Mutex;

    #[test]
    fn parses_oauth2_access_token_key() {
        let key = parse_oauth_access_token_key(
            "secrets://local/demo/_/github-review-pack/auth_oauth2_githuboauth_access_token",
        )
        .expect("should parse");
        assert_eq!(key.env, "local");
        assert_eq!(key.tenant, "demo");
        assert_eq!(key.team, "_");
        assert_eq!(key.segment, "github-review-pack");
        assert_eq!(key.scheme, "githuboauth");
    }

    #[test]
    fn ignores_non_oauth_keys() {
        assert!(parse_oauth_access_token_key("secrets://local/demo/_/pack/some_api_key").is_none());
        assert!(parse_oauth_access_token_key("not-a-secrets-uri").is_none());
        assert!(
            parse_oauth_access_token_key("secrets://local/demo/_/pack/auth_oauth2__access_token")
                .is_none()
        );
    }

    struct StubInner {
        reads: Mutex<Vec<String>>,
    }
    #[async_trait]
    impl SecretsManager for StubInner {
        async fn read(&self, path: &str) -> SecretResult<Vec<u8>> {
            self.reads.lock().unwrap().push(path.to_string());
            Err(SecretError::NotFound(path.to_string()))
        }
        async fn write(&self, _path: &str, _bytes: &[u8]) -> SecretResult<()> {
            Ok(())
        }
        async fn delete(&self, _path: &str) -> SecretResult<()> {
            Ok(())
        }
    }

    struct FixedResolver(Option<String>);
    #[async_trait]
    impl ProviderTokenResolver for FixedResolver {
        async fn resolve_access_token(&self, _key: &OAuthTokenKey) -> Option<String> {
            self.0.clone()
        }
    }

    #[tokio::test]
    async fn resolves_oauth_token_without_hitting_inner() {
        let inner = Arc::new(StubInner {
            reads: Mutex::new(Vec::new()),
        });
        let mgr = OAuthBridgingSecretsManager::new(
            inner.clone(),
            Arc::new(FixedResolver(Some("gho_resolved".into()))),
        );
        let out = mgr
            .read("secrets://local/demo/_/github-review-pack/auth_oauth2_githuboauth_access_token")
            .await
            .expect("resolved");
        assert_eq!(out, b"gho_resolved");
        assert!(
            inner.reads.lock().unwrap().is_empty(),
            "inner not consulted"
        );
    }

    #[tokio::test]
    async fn falls_through_when_resolver_returns_none() {
        let inner = Arc::new(StubInner {
            reads: Mutex::new(Vec::new()),
        });
        let mgr = OAuthBridgingSecretsManager::new(inner.clone(), Arc::new(FixedResolver(None)));
        let _ = mgr
            .read("secrets://local/demo/_/github-review-pack/auth_oauth2_githuboauth_access_token")
            .await;
        assert_eq!(
            inner.reads.lock().unwrap().len(),
            1,
            "fell through to inner"
        );
    }

    #[test]
    fn maps_scheme_to_provider_id() {
        let mk = |scheme: &str| OAuthTokenKey {
            env: "local".into(),
            tenant: "demo".into(),
            team: "_".into(),
            segment: "pack".into(),
            scheme: scheme.into(),
            scoped_key: String::new(),
        };
        assert_eq!(mk("githuboauth").provider_id(), "github");
        assert_eq!(mk("github_oauth").provider_id(), "github");
        assert_eq!(mk("google").provider_id(), "google");
        assert_eq!(mk("microsoftoidc").provider_id(), "microsoft");
    }

    /// (provider_id, tenant, team, subject) captured by the stub.
    type SeenFetch = (String, String, String, Option<String>);
    struct StubFetch {
        token: Option<String>,
        seen: Mutex<Option<SeenFetch>>,
    }
    #[async_trait]
    impl ProviderTokenFetch for StubFetch {
        async fn fetch(
            &self,
            provider_id: &str,
            tenant: &str,
            team: &str,
            subject: Option<&str>,
        ) -> Option<String> {
            *self.seen.lock().unwrap() = Some((
                provider_id.to_string(),
                tenant.to_string(),
                team.to_string(),
                subject.map(str::to_string),
            ));
            self.token.clone()
        }
    }

    #[tokio::test]
    async fn broker_resolver_maps_key_to_provider_request() {
        let fetch = StubFetch {
            token: Some("gho_from_broker".into()),
            seen: Mutex::new(None),
        };
        let resolver = BrokerTokenResolver::new(fetch);
        let key = parse_oauth_access_token_key(
            "secrets://local/demo/_/github-review-pack/auth_oauth2_githuboauth_access_token",
        )
        .unwrap();
        let token = resolver.resolve_access_token(&key).await;
        assert_eq!(token.as_deref(), Some("gho_from_broker"));
        let seen = resolver.fetch.seen.lock().unwrap().clone().unwrap();
        assert_eq!(seen.0, "github");
        assert_eq!(seen.1, "demo");
        assert_eq!(seen.2, "_");
        assert_eq!(seen.3, None, "shared mode: no subject yet");
    }

    #[tokio::test]
    async fn passes_non_oauth_keys_through() {
        let inner = Arc::new(StubInner {
            reads: Mutex::new(Vec::new()),
        });
        let mgr = OAuthBridgingSecretsManager::new(
            inner.clone(),
            Arc::new(FixedResolver(Some("unused".into()))),
        );
        let _ = mgr.read("secrets://local/demo/_/pack/some_api_key").await;
        assert_eq!(
            inner.reads.lock().unwrap().len(),
            1,
            "non-oauth fell through"
        );
    }
}
