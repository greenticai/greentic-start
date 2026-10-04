//! The HTTP key/value client behind `state-sorla`.
//!
//! Wire contract (admin state door, bearer = the unit's `gtm_` token):
//!
//! | call | body | answer |
//! |---|---|---|
//! | `POST {door}/read` | `{"key"}` | `200 {"value":"<b64>"}` or `404` |
//! | `POST {door}/write` | `{"key","value":"<b64>","ttl_secs"?}` | `204` |
//! | `POST {door}/delete` | `{"key"}` | `204` |
//!
//! The trait it implements, [`StateStore`], is synchronous, like the Redis
//! store's: runner-host reaches it from blocking contexts only (`Offloaded` for
//! the flow-state host, the component call for the WIT `state-store` import),
//! so a blocking `reqwest` client is the honest fit. Construct it from a
//! blocking context as well — `reqwest::blocking` panics when built inside an
//! async worker thread.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use greentic_state::error::{internal, invalid_input, unavailable};
use greentic_state::util::get_at_path;
use greentic_state::{StateKey, StatePath, StateStore, TenantCtx, fqn};
use greentic_types::{GResult, GreenticError};
use reqwest::StatusCode;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::{Value, json};

use super::config::SorlaStateSelection;
use crate::operator_log;

/// A cached read is served without asking the door for this long. Short on
/// purpose: the door is the source of truth, and another writer (a second
/// revision of the same unit never shares a key, but a retry on a new instance
/// does) must not be hidden for long.
const CACHE_FRESH_FOR: Duration = Duration::from_secs(30);
/// How long past freshness an entry may still answer a read the door could not.
const CACHE_STALE_GRACE: Duration = Duration::from_secs(600);
/// The key the boot probe reads. Never written, so the probe leaves no litter.
const PROBE_KEY: &str = "boot-probe";

/// Why one door call failed. Carries a status or a transport reason, never the
/// token and never the response body.
#[derive(Debug, thiserror::Error)]
enum DoorError {
    #[error("the state door did not answer: {0}")]
    Transport(String),
    #[error("the state door answered {0}")]
    Status(u16),
    #[error("the state door rejected the unit's credential ({0})")]
    Rejected(u16),
    #[error("the state door answered with a body this build cannot read: {0}")]
    Body(String),
}

impl From<DoorError> for GreenticError {
    fn from(err: DoorError) -> Self {
        unavailable(err.to_string())
    }
}

struct CacheEntry {
    value: Value,
    stored_at: Instant,
    used: u64,
}

struct ReadCache {
    max_entries: usize,
    fresh_for: Duration,
    stale_grace: Duration,
    tick: u64,
    entries: HashMap<String, CacheEntry>,
}

impl ReadCache {
    fn new(max_entries: usize, fresh_for: Duration, stale_grace: Duration) -> Self {
        Self {
            max_entries,
            fresh_for,
            stale_grace,
            tick: 0,
            entries: HashMap::new(),
        }
    }

    /// `(value, is_fresh)` for a key still inside the grace window.
    fn get(&mut self, key: &str) -> Option<(Value, bool)> {
        self.tick += 1;
        let tick = self.tick;
        let entry = self.entries.get_mut(key)?;
        let age = entry.stored_at.elapsed();
        if age > self.fresh_for + self.stale_grace {
            self.entries.remove(key);
            return None;
        }
        entry.used = tick;
        Some((entry.value.clone(), age <= self.fresh_for))
    }

    fn put(&mut self, key: String, value: Value) {
        if self.max_entries == 0 {
            return;
        }
        self.tick += 1;
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
            // Least recently used. A linear scan: the cache is bounded in the
            // low thousands and an insert already costs an HTTP round trip.
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.used)
                .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            key,
            CacheEntry {
                value,
                stored_at: Instant::now(),
                used: self.tick,
            },
        );
    }

    fn remove(&mut self, key: &str) {
        self.entries.remove(key);
    }
}

#[derive(Deserialize)]
struct ReadBody {
    value: String,
}

/// [`StateStore`] over the admin's HTTP state door.
pub(crate) struct HttpStateStore {
    client: Client,
    read_url: String,
    write_url: String,
    delete_url: String,
    token: String,
    /// `<key_prefix>:<revision suffix>` — folded into every door key.
    namespace: String,
    default_ttl: Option<u32>,
    cache: Mutex<ReadCache>,
}

impl std::fmt::Debug for HttpStateStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpStateStore")
            .field("read_url", &self.read_url)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl HttpStateStore {
    /// Build the store for ONE revision and prove the door answers.
    ///
    /// `revision_suffix` is the per-revision isolation digest
    /// ([`crate::durable_state::isolation_suffix`]). An unreachable or
    /// unauthorised door is an `Err`, never a store that fails later in front
    /// of a user — the contract `crate::durable_state` already holds Redis to.
    pub(crate) fn connect(
        selection: &SorlaStateSelection,
        revision_suffix: &str,
    ) -> anyhow::Result<Self> {
        let store = Self::build(
            selection,
            revision_suffix,
            CACHE_FRESH_FOR,
            CACHE_STALE_GRACE,
        )?;
        store.probe()?;
        Ok(store)
    }

    fn build(
        selection: &SorlaStateSelection,
        revision_suffix: &str,
        fresh_for: Duration,
        stale_grace: Duration,
    ) -> anyhow::Result<Self> {
        let config = &selection.config;
        let client = Client::builder()
            .timeout(config.request_timeout)
            .build()
            .map_err(|err| anyhow::anyhow!("building the state-sorla HTTP client: {err}"))?;
        let base = &selection.door.base_url;
        Ok(Self {
            client,
            read_url: format!("{base}/read"),
            write_url: format!("{base}/write"),
            delete_url: format!("{base}/delete"),
            token: selection.door.token.expose().to_string(),
            namespace: crate::durable_state::revision_namespace(
                &config.key_prefix,
                revision_suffix,
            ),
            default_ttl: config.default_ttl_seconds,
            cache: Mutex::new(ReadCache::new(
                config.cache_max_entries,
                fresh_for,
                stale_grace,
            )),
        })
    }

    #[cfg(test)]
    pub(crate) fn connect_with_cache_policy(
        selection: &SorlaStateSelection,
        revision_suffix: &str,
        fresh_for: Duration,
        stale_grace: Duration,
    ) -> anyhow::Result<Self> {
        Self::build(selection, revision_suffix, fresh_for, stale_grace)
    }

    /// One read of a key that is never written: `404` and `200` both prove the
    /// door is up and accepts the credential.
    pub(crate) fn probe(&self) -> anyhow::Result<()> {
        let key = format!("{}:{PROBE_KEY}", self.namespace);
        self.read_remote(&key).map(|_| ()).map_err(|err| {
            anyhow::anyhow!(
                "the state-sorla door `{}` is not usable: {err}; refusing to serve on in-memory \
                 state, which would silently lose every conversation",
                self.read_url
            )
        })
    }

    fn door_key(&self, tenant: &TenantCtx, prefix: &str, key: &StateKey) -> String {
        format!("{}:{}", self.namespace, fqn(tenant, prefix, key))
    }

    fn post(&self, url: &str, body: &Value) -> Result<reqwest::blocking::Response, DoorError> {
        let response = self
            .client
            .post(url)
            .bearer_auth(&self.token)
            .json(body)
            .send()
            // `without_url`: the URL is not secret, but a transport error is
            // the one place a future auth-in-URL change would leak.
            .map_err(|err| DoorError::Transport(err.without_url().to_string()))?;
        match response.status() {
            status if status.is_success() => Ok(response),
            StatusCode::NOT_FOUND => Ok(response),
            status @ (StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) => {
                Err(DoorError::Rejected(status.as_u16()))
            }
            status => Err(DoorError::Status(status.as_u16())),
        }
    }

    fn read_remote(&self, key: &str) -> Result<Option<Value>, DoorError> {
        let response = self.post(&self.read_url, &json!({ "key": key }))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let body: ReadBody = response
            .json()
            .map_err(|err| DoorError::Body(err.without_url().to_string()))?;
        let bytes = B64
            .decode(body.value.as_bytes())
            .map_err(|err| DoorError::Body(format!("value is not base64: {err}")))?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|err| DoorError::Body(format!("value is not JSON: {err}")))
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, ReadCache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl StateStore for HttpStateStore {
    fn get_json(
        &self,
        tenant: &TenantCtx,
        prefix: &str,
        key: &StateKey,
        path: Option<&StatePath>,
    ) -> GResult<Option<Value>> {
        let door_key = self.door_key(tenant, prefix, key);
        let cached = self.cache().get(&door_key);
        let document = match cached {
            Some((value, true)) => Some(value),
            stale => match self.read_remote(&door_key) {
                Ok(Some(value)) => {
                    self.cache().put(door_key, value.clone());
                    Some(value)
                }
                Ok(None) => {
                    self.cache().remove(&door_key);
                    None
                }
                Err(err) => match stale {
                    // Reads may outlive an outage; the operator is told.
                    Some((value, false)) => {
                        operator_log::warn(
                            module_path!(),
                            format!(
                                "state-sorla: {err}; serving a cached read past its freshness \
                                 window"
                            ),
                        );
                        Some(value)
                    }
                    _ => return Err(err.into()),
                },
            },
        };
        Ok(match (document, path) {
            (Some(value), Some(path)) => get_at_path(&value, path).cloned(),
            (value, None) => value,
            (None, Some(_)) => None,
        })
    }

    fn set_json(
        &self,
        tenant: &TenantCtx,
        prefix: &str,
        key: &StateKey,
        path: Option<&StatePath>,
        value: &Value,
        ttl_secs: Option<u32>,
    ) -> GResult<()> {
        if path.is_some() {
            // Patching inside a document would be a read-modify-write across
            // two requests with no compare-and-swap; refuse rather than race.
            return Err(invalid_input(
                "state-sorla does not support writing at a JSON path",
            ));
        }
        let door_key = self.door_key(tenant, prefix, key);
        let bytes = serde_json::to_vec(value).map_err(|err| internal(err.to_string()))?;
        let mut body = json!({ "key": door_key, "value": B64.encode(bytes) });
        // `Some(0)` clears expiry (the trait's contract); `None` is the default.
        let ttl = match ttl_secs {
            Some(0) => None,
            Some(secs) => Some(secs),
            None => self.default_ttl,
        };
        if let (Some(ttl), Some(object)) = (ttl, body.as_object_mut()) {
            object.insert("ttl_secs".into(), json!(ttl));
        }
        match self.post(&self.write_url, &body) {
            Ok(_) => {
                self.cache().put(door_key, value.clone());
                Ok(())
            }
            Err(err) => {
                // Whatever the door now holds is unknown, so a cached copy of
                // the old value must not keep answering reads.
                self.cache().remove(&door_key);
                Err(err.into())
            }
        }
    }

    fn del(&self, tenant: &TenantCtx, prefix: &str, key: &StateKey) -> GResult<bool> {
        let door_key = self.door_key(tenant, prefix, key);
        self.cache().remove(&door_key);
        self.post(&self.delete_url, &json!({ "key": door_key }))?;
        Ok(true)
    }

    fn del_prefix(&self, _tenant: &TenantCtx, _prefix: &str) -> GResult<u64> {
        // The door has no prefix delete, and runner-host never forwards one
        // (`StateStoreHost::del_prefix` is a deliberate no-op). Refuse rather
        // than claim a deletion that did not happen.
        Err(invalid_input(
            "state-sorla does not support prefix deletion",
        ))
    }
}
