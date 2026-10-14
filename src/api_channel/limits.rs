//! Per-credential limits for the stream route, in the style of
//! `interop/limits.rs`: a token bucket for opens and a cap on concurrent
//! streams. Both are per PROCESS: N instances multiply the ceiling by N.
//!
//! The key is a digest of the bearer token, never the token. It is only used
//! after the provider has accepted the credential, so a stranger cannot create
//! entries.

use crate::interop::limits::RateLimiter;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Streams one credential may hold open at once.
pub(crate) const DEFAULT_MAX_STREAMS_PER_CREDENTIAL: usize = 8;

/// Cost of opening a stream, against the shared per-credential bucket.
const OPEN_COST: f64 = crate::interop::limits::CHEAP_COST;

/// Why a stream was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Too many opens; retry after this many seconds.
    RateLimited { retry_after_secs: u64 },
    /// The credential already holds its maximum number of streams.
    TooManyStreams,
}

/// Held for the life of a stream; releases the slot on drop.
pub(crate) struct StreamPermit {
    _permit: OwnedSemaphorePermit,
}

pub(crate) struct StreamLimits {
    rate: RateLimiter,
    max_streams: usize,
    slots: DashMap<String, Arc<Semaphore>>,
}

/// An opaque, non-reversible key for a bearer token.
pub(crate) fn credential_key(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let hex: String = digest.iter().take(16).map(|b| format!("{b:02x}")).collect();
    format!("api-stream:{hex}")
}

impl StreamLimits {
    pub(crate) fn new(max_streams: usize) -> Self {
        Self {
            rate: RateLimiter::default(),
            max_streams: max_streams.max(1),
            slots: DashMap::new(),
        }
    }

    pub(crate) fn admit(&self, credential: &str) -> Result<StreamPermit, Refusal> {
        self.rate
            .check(credential, OPEN_COST)
            .map_err(|retry_after_secs| Refusal::RateLimited { retry_after_secs })?;
        let semaphore = Arc::clone(
            self.slots
                .entry(credential.to_string())
                .or_insert_with(|| Arc::new(Semaphore::new(self.max_streams)))
                .value(),
        );
        let permit = semaphore
            .try_acquire_owned()
            .map_err(|_| Refusal::TooManyStreams)?;
        Ok(StreamPermit { _permit: permit })
    }
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_STREAMS_PER_CREDENTIAL)
    }
}

/// The process-wide limiter: every connection of every listener shares one
/// accounting pool, as `interop` does.
pub(crate) fn shared() -> Arc<StreamLimits> {
    static SHARED: std::sync::OnceLock<Arc<StreamLimits>> = std::sync::OnceLock::new();
    Arc::clone(SHARED.get_or_init(|| Arc::new(StreamLimits::default())))
}
