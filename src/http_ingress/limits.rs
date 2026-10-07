//! Request body caps and the upload limiter for the revision ingress (host
//! checklist 13).
//!
//! - A Direct Line upload (`POST …/v3/directline/conversations/{id}/upload`)
//!   may carry up to [`UPLOAD_BODY_BYTES`]: all files of one WebChat message
//!   share ONE upload of at most 15 MiB, plus multipart framing. Every other
//!   route keeps [`MAX_BODY_BYTES`].
//! - A declared `Content-Length` over the cap is refused before a byte is
//!   read; an undeclared body is read until the cap and refused there.
//! - Uploads are limited to [`UPLOADS_PER_MINUTE`] per client (on top of the
//!   provider's own per-subject limit) and to [`UPLOAD_CONCURRENCY`] at once:
//!   an upload holds up to 16 MiB here and far more inside the provider's
//!   guest, so a busy host answers `503` rather than queueing without bound.
//! - A provider guest handling an upload needs ~160 MiB of linear memory;
//!   nothing here or in the pinned runner host caps it lower (pinned by
//!   `limits_tests::no_guest_memory_cap_below_the_upload_floor`).
//! - The body is passed on byte for byte; the provider receives it with the
//!   request's own `Content-Type` (the multipart boundary lives there).

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Bytes};
use hyper::{HeaderMap, Request, Response, StatusCode, header};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::revision_serve::MAX_BODY_BYTES;

pub(crate) const UPLOAD_BODY_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const UPLOADS_PER_MINUTE: usize = 10;
/// Uploads processed at once per process. Each may hold 16 MiB in the host
/// and ~160 MiB in the provider guest while it parses and re-encodes the
/// multipart body; four bound that to well under a gigabyte.
pub(crate) const UPLOAD_CONCURRENCY: usize = 4;
const WINDOW: Duration = Duration::from_secs(60);
/// Clients remembered at most; past it, idle ones are forgotten first.
const MAX_TRACKED_CLIENTS: usize = 10_000;

/// The TCP peer of the connection, put on the request by the accept loop.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PeerIp(pub IpAddr);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyKind {
    Upload,
    Other,
}

pub(crate) fn body_kind(method: &str, path: &str) -> BodyKind {
    let mut segments = path.trim_end_matches('/').rsplit('/');
    let is_upload = method.eq_ignore_ascii_case("POST")
        && segments.next() == Some("upload")
        && segments.next().is_some()
        && segments.next() == Some("conversations")
        && path.contains("/v3/directline/");
    if is_upload {
        BodyKind::Upload
    } else {
        BodyKind::Other
    }
}

/// The client an upload is counted against: the TCP peer when it is a public
/// address; behind a proxy or load balancer (a private or loopback peer), the
/// LAST `X-Forwarded-For` entry, the one the nearest proxy appended. A header
/// sent by a public peer is never trusted.
pub(crate) fn client_key(peer: Option<IpAddr>, headers: &HeaderMap) -> Option<IpAddr> {
    match peer {
        Some(ip) if crate::artifacts::dns::is_public_ip(ip) => Some(ip),
        other => headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|list| list.rsplit(',').next())
            .and_then(|last| last.trim().parse().ok())
            .or(other),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// `429`: this client sent too many uploads in the window.
    TooMany,
    /// `503`: every upload slot is in use.
    Busy,
}

pub(crate) struct UploadLimiter {
    per_minute: usize,
    windows: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
    slots: Arc<Semaphore>,
}

impl UploadLimiter {
    pub(crate) fn new(per_minute: usize, concurrency: usize) -> Self {
        Self {
            per_minute,
            windows: Mutex::new(HashMap::new()),
            slots: Arc::new(Semaphore::new(concurrency)),
        }
    }

    /// A slot for one upload, held until the returned permit drops. An
    /// unidentified client is not rate limited (the slot bound still holds).
    pub(crate) fn admit(
        &self,
        client: Option<IpAddr>,
        now: Instant,
    ) -> Result<OwnedSemaphorePermit, Refusal> {
        if let Some(client) = client {
            let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
            if windows.len() >= MAX_TRACKED_CLIENTS && !windows.contains_key(&client) {
                windows
                    .retain(|_, seen| seen.back().is_some_and(|t| now.duration_since(*t) < WINDOW));
            }
            let seen = windows.entry(client).or_default();
            while seen
                .front()
                .is_some_and(|t| now.duration_since(*t) >= WINDOW)
            {
                seen.pop_front();
            }
            if seen.len() >= self.per_minute {
                return Err(Refusal::TooMany);
            }
            seen.push_back(now);
        }
        Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| Refusal::Busy)
    }
}

fn upload_limiter() -> &'static UploadLimiter {
    static LIMITER: OnceLock<UploadLimiter> = OnceLock::new();
    LIMITER.get_or_init(|| UploadLimiter::new(UPLOADS_PER_MINUTE, UPLOAD_CONCURRENCY))
}

/// A body read under its route's cap. `_slot` holds an upload slot for as long
/// as the caller keeps this value (through the provider call).
pub(crate) struct IngressBody {
    pub bytes: Bytes,
    pub _slot: Option<OwnedSemaphorePermit>,
}

pub(crate) async fn read_ingress_body<B>(
    req: Request<B>,
    path: &str,
) -> Result<IngressBody, Response<Full<Bytes>>>
where
    B: Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    read_ingress_body_with(upload_limiter(), req, path).await
}

pub(crate) async fn read_ingress_body_with<B>(
    limiter: &UploadLimiter,
    req: Request<B>,
    path: &str,
) -> Result<IngressBody, Response<Full<Bytes>>>
where
    B: Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let kind = body_kind(req.method().as_str(), path);
    let cap = match kind {
        BodyKind::Upload => UPLOAD_BODY_BYTES,
        BodyKind::Other => MAX_BODY_BYTES,
    };
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    if declared.is_some_and(|len| len > cap as u64) {
        return Err(refuse(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body exceeds the size limit",
        ));
    }
    let slot = match kind {
        BodyKind::Upload => {
            let peer = req.extensions().get::<PeerIp>().map(|p| p.0);
            let client = client_key(peer, req.headers());
            match limiter.admit(client, Instant::now()) {
                Ok(slot) => Some(slot),
                Err(Refusal::TooMany) => {
                    return Err(refuse(
                        StatusCode::TOO_MANY_REQUESTS,
                        "too many uploads; try again in a minute",
                    ));
                }
                Err(Refusal::Busy) => {
                    return Err(refuse(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "uploads are busy; try again shortly",
                    ));
                }
            }
        }
        BodyKind::Other => None,
    };
    let bytes = Limited::new(req.into_body(), cap)
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .map_err(|_| {
            refuse(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeds the size limit",
            )
        })?;
    Ok(IngressBody { bytes, _slot: slot })
}

fn refuse(status: StatusCode, message: &'static str) -> Response<Full<Bytes>> {
    crate::revision_serve::error_response(status, message)
}
