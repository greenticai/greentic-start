//! The async client for the admin `artifacts` door (master plan C3).
//!
//! - Bearer is the unit's metering token; it never appears in `Debug`, an
//!   error, or a log line. Redirects are never followed (one would carry the
//!   bearer to a host the unit never named).
//! - At most [`PUT_CONCURRENCY`] requests are in flight per client: the door
//!   runs four transfers per admin process and refuses the rest (`503
//!   artifact_busy`), so a message's five files go two at a time.
//! - `408`, `429`, `502`, `503` (`artifact_busy`, `artifact_store_unavailable`),
//!   `504` and transport failures are retried, [`PUT_ATTEMPTS`] attempts in
//!   all, waiting the door's `Retry-After` (at most 3 s) or else a doubling
//!   backoff. Environment proxies are not used. A put is content-addressed, so a retry stores nothing
//!   twice. `401`/`403`/`404`/`413`/`415`/`422` and the `400`s are final.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::StatusCode;
use serde::Serialize;
use tokio::sync::Semaphore;

use super::wire::{GetBody, PutBody, PutResponse, get_url, put_url};
pub(crate) use super::wire::{PROBE_ID, is_artifact_id};

pub(crate) const ARTIFACTS_SEGMENT: &str = "artifacts";
/// Requests in flight per client.
pub(crate) const PUT_CONCURRENCY: usize = 2;
/// Attempts per request, the first included.
pub(crate) const PUT_ATTEMPTS: usize = 3;
const DEFAULT_BACKOFF: Duration = Duration::from_millis(250);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest wait a door's `Retry-After` can impose.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(3);
/// Largest success answer read from the door (its answers are a few hundred
/// bytes).
const MAX_ANSWER_BYTES: usize = 64 * 1024;

pub(crate) struct PutRequest<'a> {
    pub name: &'a str,
    pub mime: &'a str,
    pub bytes: &'a [u8],
    pub derived_from: Option<&'a str>,
    pub conversation_id: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Stored {
    pub id: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub kind: String,
    pub mime_type: String,
}

/// Fixed texts only: never the token, a URL or a response body.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StoreError {
    #[error("the artifact door rejected this unit's credential ({0})")]
    Rejected(u16),
    #[error("the artifact door refused the file as too large")]
    TooLarge,
    #[error("the artifact door does not accept this file type")]
    Unsupported,
    #[error("the artifact quota for this conversation is exhausted")]
    Quota,
    #[error("the artifact door has no such artifact")]
    NotFound,
    #[error("the artifact door is unavailable: {0}")]
    Unavailable(String),
}

#[async_trait]
pub(crate) trait ArtifactStore: Send + Sync {
    async fn put(&self, request: PutRequest<'_>) -> Result<Stored, StoreError>;

    /// Proves the door is up and accepts the credential, writing nothing.
    async fn probe(&self) -> Result<(), StoreError>;
}

pub(crate) struct HttpArtifactStore {
    client: reqwest::Client,
    door: String,
    token: String,
    slots: Arc<Semaphore>,
    backoff: Duration,
}

impl std::fmt::Debug for HttpArtifactStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpArtifactStore")
            .field("door", &self.door)
            .field("token", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// One attempt's outcome: final, or worth another try.
enum Attempt {
    Done(Result<reqwest::Response, StoreError>),
    /// Retryable; carries the door's `Retry-After`, already capped.
    Retry(StoreError, Option<Duration>),
}

impl HttpArtifactStore {
    /// `door` is the sibling base (`…/ingest/artifacts`); `timeout` bounds each
    /// attempt end to end.
    pub(crate) fn new(
        door: String,
        token: String,
        timeout: Duration,
    ) -> Result<Self, reqwest::Error> {
        install_crypto_provider();
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(CONNECT_TIMEOUT.min(timeout))
            .redirect(reqwest::redirect::Policy::none())
            // The bearer goes to the door and nowhere else: an environment
            // proxy would be a second party holding it (and, for plain-http
            // doors, reading it).
            .no_proxy()
            .build()?;
        Ok(Self {
            client,
            door,
            token,
            slots: Arc::new(Semaphore::new(PUT_CONCURRENCY)),
            backoff: DEFAULT_BACKOFF,
        })
    }

    /// The first wait between attempts; it doubles after each retry.
    pub(crate) fn with_backoff(mut self, backoff: Duration) -> Self {
        self.backoff = backoff;
        self
    }

    async fn send(
        &self,
        url: &str,
        body: &impl Serialize,
    ) -> Result<reqwest::Response, StoreError> {
        let _slot = self
            .slots
            .acquire()
            .await
            .map_err(|_| StoreError::Unavailable("the client is shutting down".into()))?;
        let mut wait = self.backoff;
        let mut attempt = 1;
        loop {
            match self.attempt(url, body).await {
                Attempt::Done(result) => return result,
                Attempt::Retry(err, _) if attempt >= PUT_ATTEMPTS => return Err(err),
                Attempt::Retry(_, retry_after) => {
                    tokio::time::sleep(retry_after.unwrap_or(wait)).await;
                    wait = wait.saturating_mul(2);
                    attempt += 1;
                }
            }
        }
    }

    async fn attempt(&self, url: &str, body: &impl Serialize) -> Attempt {
        let sent = self
            .client
            .post(url)
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await;
        let response = match sent {
            Ok(response) => response,
            Err(err) => {
                let reason = if err.is_timeout() {
                    "the request timed out"
                } else if err.is_connect() {
                    "the door could not be reached"
                } else {
                    "the request failed"
                };
                return Attempt::Retry(StoreError::Unavailable(reason.into()), None);
            }
        };
        let status = response.status();
        let unavailable =
            || StoreError::Unavailable(format!("the door answered {}", status.as_u16()));
        Attempt::Done(match status {
            s if s.is_success() => Ok(response),
            StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT => {
                return Attempt::Retry(unavailable(), retry_after(response.headers()));
            }
            s @ (StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) => {
                Err(StoreError::Rejected(s.as_u16()))
            }
            StatusCode::NOT_FOUND => Err(StoreError::NotFound),
            StatusCode::PAYLOAD_TOO_LARGE => Err(StoreError::TooLarge),
            StatusCode::UNSUPPORTED_MEDIA_TYPE => Err(StoreError::Unsupported),
            StatusCode::UNPROCESSABLE_ENTITY => Err(StoreError::Quota),
            _ => Err(unavailable()),
        })
    }
}

#[async_trait]
impl ArtifactStore for HttpArtifactStore {
    async fn put(&self, request: PutRequest<'_>) -> Result<Stored, StoreError> {
        let body = PutBody::new(
            request.name,
            request.mime,
            request.bytes,
            request.derived_from,
            request.conversation_id,
        );
        let response = self.send(&put_url(&self.door), &body).await?;
        let raw = read_capped_body(response, MAX_ANSWER_BYTES).await?;
        let parsed: PutResponse = serde_json::from_slice(&raw)
            .map_err(|_| StoreError::Unavailable("the door's answer was unreadable".into()))?;
        if !is_artifact_id(&parsed.id) {
            return Err(StoreError::Unavailable(
                "the door answered a malformed artifact id".into(),
            ));
        }
        Ok(Stored {
            id: parsed.id,
            sha256: parsed.sha256,
            size_bytes: parsed.size_bytes,
            kind: parsed.kind,
            mime_type: parsed.mime_type,
        })
    }

    async fn probe(&self) -> Result<(), StoreError> {
        // A get for a well-formed id that cannot exist (the admin refuses a
        // malformed one with `400 invalid_id` before any lookup): 404 proves the door is up and the
        // token is accepted; 401/403 prove the opposite (403 = no `artifacts`
        // purpose).
        match self
            .send(&get_url(&self.door), &GetBody { id: PROBE_ID })
            .await
        {
            Ok(_) | Err(StoreError::NotFound) => Ok(()),
            Err(other) => Err(other),
        }
    }
}

/// The door's `Retry-After` in whole seconds, at most [`MAX_RETRY_AFTER`]. An
/// HTTP-date or anything else unreadable is ignored (the backoff applies).
fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let seconds: u64 = headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some(Duration::from_secs(seconds).min(MAX_RETRY_AFTER))
}

/// A success answer, read chunk by chunk and refused past `cap` bytes.
async fn read_capped_body(
    mut response: reqwest::Response,
    cap: usize,
) -> Result<Vec<u8>, StoreError> {
    let unreadable = || StoreError::Unavailable("the door's answer was unreadable".into());
    let mut out = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| unreadable())? {
        if out.len() + chunk.len() > cap {
            return Err(StoreError::Unavailable(
                "the door's answer was too large".into(),
            ));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// This binary carries both `ring` and `aws-lc-rs`, so rustls cannot pick a
/// provider on its own and the client builder panics without a default.
fn install_crypto_provider() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
