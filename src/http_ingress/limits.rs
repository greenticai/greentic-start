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
//!   provider's own per-subject limit), ONE at a time per client, and to
//!   [`UPLOAD_CONCURRENCY`] at once overall: an upload holds up to 16 MiB here
//!   and far more inside the provider's guest, so a busy host answers `503`
//!   rather than queueing without bound.
//! - The client is the TCP peer. `X-Forwarded-For` is trusted only when the
//!   operator says how many proxies append to it
//!   (`GREENTIC_TRUSTED_PROXY_HOPS=N`): the client is then the N-th entry
//!   from the right across every header line. IPv6 clients are counted per
//!   /64 (one host normally holds the whole /64).
//! - An upload body must arrive within [`UPLOAD_READ_DEADLINE`] (`408`
//!   otherwise), so a client that trickles bytes cannot hold a slot; a body
//!   that breaks off is `400`, only a body over the cap is `413`.
//! - A provider guest handling an upload needs ~160 MiB of linear memory;
//!   nothing here or in the pinned runner host caps it lower (pinned by
//!   `limits_tests::no_guest_memory_cap_below_the_upload_floor`).
//! - The body is passed on byte for byte; the provider receives it with the
//!   request's own `Content-Type` (the multipart boundary lives there).

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
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
/// How long an upload body may take to arrive in full.
pub(crate) const UPLOAD_READ_DEADLINE: Duration = Duration::from_secs(30);
const WINDOW: Duration = Duration::from_secs(60);
/// Clients remembered at most; past it, idle ones are forgotten first, then
/// the least recently seen.
const MAX_TRACKED_CLIENTS: usize = 10_000;
/// How many proxies in front of this host append to `X-Forwarded-For`.
const TRUSTED_PROXY_HOPS_ENV: &str = "GREENTIC_TRUSTED_PROXY_HOPS";

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

/// The bucket an upload is counted against: an IPv4 address, or an IPv6 /64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ClientKey(IpAddr);

impl ClientKey {
    pub(crate) fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => ClientKey(IpAddr::V4(v4)),
                None => {
                    let s = v6.segments();
                    ClientKey(IpAddr::V6(Ipv6Addr::new(
                        s[0], s[1], s[2], s[3], 0, 0, 0, 0,
                    )))
                }
            },
            v4 => ClientKey(v4),
        }
    }
}

/// `GREENTIC_TRUSTED_PROXY_HOPS`, read once. Absent or unreadable is 0: the
/// header is not trusted.
pub(crate) fn trusted_proxy_hops() -> usize {
    static HOPS: OnceLock<usize> = OnceLock::new();
    *HOPS.get_or_init(|| {
        std::env::var(TRUSTED_PROXY_HOPS_ENV)
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0)
    })
}

/// The client an upload is counted against. With `trusted_hops == 0` (the
/// default) it is the TCP peer and `X-Forwarded-For` is ignored: any client
/// can write that header. With `N` trusted proxies it is the N-th entry from
/// the right of the header (every line, in order), the one the outermost
/// trusted proxy appended; too few entries, or one that is not an address,
/// and the peer is used.
pub(crate) fn client_key(
    peer: Option<IpAddr>,
    headers: &HeaderMap,
    trusted_hops: usize,
) -> Option<ClientKey> {
    let forwarded = (trusted_hops > 0)
        .then(|| {
            let entries: Vec<&str> = headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|value| value.to_str().ok())
                .flat_map(|line| line.split(','))
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .collect();
            entries
                .len()
                .checked_sub(trusted_hops)
                .and_then(|index| entries.get(index))
                .and_then(|entry| entry.parse::<IpAddr>().ok())
        })
        .flatten();
    forwarded.or(peer).map(ClientKey::of)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// `429`: this client sent too many uploads in the window.
    TooMany,
    /// `503`: every upload slot is in use.
    Busy,
    /// `429`: this client already has an upload in progress.
    ClientBusy,
}

/// Uploads in progress per client.
type InFlight = Arc<Mutex<HashMap<ClientKey, usize>>>;

pub(crate) struct UploadLimiter {
    per_minute: usize,
    max_clients: usize,
    read_deadline: Duration,
    windows: Mutex<HashMap<ClientKey, VecDeque<Instant>>>,
    in_flight: InFlight,
    slots: Arc<Semaphore>,
}

/// One admitted upload: an overall slot and, for an identified client, its
/// one in-flight mark. Both are released when this drops.
pub(crate) struct UploadSlot {
    _slot: OwnedSemaphorePermit,
    client: Option<(ClientKey, InFlight)>,
}

impl Drop for UploadSlot {
    fn drop(&mut self) {
        if let Some((key, in_flight)) = self.client.take() {
            let mut in_flight = in_flight.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(count) = in_flight.get_mut(&key) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    in_flight.remove(&key);
                }
            }
        }
    }
}

impl UploadLimiter {
    pub(crate) fn new(per_minute: usize, concurrency: usize) -> Self {
        Self::with_max_clients(per_minute, concurrency, MAX_TRACKED_CLIENTS)
    }

    pub(crate) fn with_max_clients(
        per_minute: usize,
        concurrency: usize,
        max_clients: usize,
    ) -> Self {
        Self {
            per_minute,
            max_clients: max_clients.max(1),
            read_deadline: UPLOAD_READ_DEADLINE,
            windows: Mutex::new(HashMap::new()),
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            slots: Arc::new(Semaphore::new(concurrency)),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_read_deadline(mut self, deadline: Duration) -> Self {
        self.read_deadline = deadline;
        self
    }

    #[cfg(test)]
    pub(crate) fn tracked_clients(&self) -> usize {
        self.windows.lock().map(|w| w.len()).unwrap_or_default()
    }

    #[cfg(test)]
    pub(crate) fn tracks(&self, key: ClientKey) -> bool {
        self.windows
            .lock()
            .map(|w| w.contains_key(&key))
            .unwrap_or_default()
    }

    /// A slot for one upload, held until the returned value drops. An
    /// unidentified client is not rate limited (the slot bound still holds).
    pub(crate) fn admit(
        &self,
        client: Option<ClientKey>,
        now: Instant,
    ) -> Result<UploadSlot, Refusal> {
        if let Some(client) = client {
            if self
                .in_flight
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&client)
            {
                return Err(Refusal::ClientBusy);
            }
            let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
            if windows.len() >= self.max_clients && !windows.contains_key(&client) {
                windows
                    .retain(|_, seen| seen.back().is_some_and(|t| now.duration_since(*t) < WINDOW));
                while windows.len() >= self.max_clients {
                    let oldest = windows
                        .iter()
                        .min_by_key(|(_, seen)| seen.back().copied())
                        .map(|(key, _)| *key);
                    match oldest {
                        Some(key) => {
                            windows.remove(&key);
                        }
                        None => break,
                    }
                }
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
        let slot = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| Refusal::Busy)?;
        let client = client.map(|key| {
            *self
                .in_flight
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(key)
                .or_default() += 1;
            (key, Arc::clone(&self.in_flight))
        });
        Ok(UploadSlot {
            _slot: slot,
            client,
        })
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
    pub _slot: Option<UploadSlot>,
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
            let client = client_key(peer, req.headers(), trusted_proxy_hops());
            match limiter.admit(client, Instant::now()) {
                Ok(slot) => Some(slot),
                Err(Refusal::TooMany) => {
                    return Err(refuse(
                        StatusCode::TOO_MANY_REQUESTS,
                        "too many uploads; try again in a minute",
                    ));
                }
                Err(Refusal::ClientBusy) => {
                    return Err(refuse(
                        StatusCode::TOO_MANY_REQUESTS,
                        "an upload from this client is already in progress",
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
    let read = Limited::new(req.into_body(), cap).collect();
    let collected = match kind {
        BodyKind::Upload => match tokio::time::timeout(limiter.read_deadline, read).await {
            Ok(collected) => collected,
            Err(_) => {
                return Err(refuse(
                    StatusCode::REQUEST_TIMEOUT,
                    "the upload did not arrive in time",
                ));
            }
        },
        BodyKind::Other => read.await,
    };
    let bytes = collected.map(|c| c.to_bytes()).map_err(|err| {
        if err
            .downcast_ref::<http_body_util::LengthLimitError>()
            .is_some()
        {
            refuse(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeds the size limit",
            )
        } else {
            refuse(
                StatusCode::BAD_REQUEST,
                "the request body could not be read",
            )
        }
    })?;
    Ok(IngressBody { bytes, _slot: slot })
}

fn refuse(status: StatusCode, message: &'static str) -> Response<Full<Bytes>> {
    crate::revision_serve::error_response(status, message)
}
