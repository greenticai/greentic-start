//! `GET`/`HEAD /v1/artifacts/<deployment>/<artifact hex>/<exp>/<mac>`: the
//! one route that serves artifact bytes (docs/outbound-artifacts.md).
//!
//! Order: kill switch -> method -> per-client window -> exact path shape ->
//! deployment known to this activation with a live signer -> MAC (constant
//! time) -> expiry -> per-link window -> unit egress budget -> read slot ->
//! door read. Every refusal about WHICH file or WHICH unit (and the kill
//! switch) is [`not_found`], byte for byte the same, so the route is no
//! existence oracle across tenants or units. Bytes come from the unit's own
//! door with the unit's own token: the door decides the tenant.
//!
//! Serving rule (docs/inbound-attachments.md §7): `Content-Type` is the
//! door's sniffed type and must be on the v1 allow-list; images are `inline`
//! only for raster types; everything else is an `attachment`; `nosniff`,
//! `private, no-store`, a sandbox CSP, no referrer, no framing; never a
//! cookie, a CORS header or a redirect.
//!
//! Nothing here logs the path, the MAC, the artifact id or the token.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use greentic_aw_runtime::{ArtifactBytes, ArtifactError, ArtifactReader};
use greentic_deploy_spec::ids::DeploymentId;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Method, Request, Response, StatusCode, header};

use super::link::{self, LINK_PREFIX, LinkPath, Verdict};
use super::link_table::{ArtifactLinkTable, LinkUnit};
use super::serve_link_limits::LinkLimits;
use crate::http_ingress::limits::{ClientKey, PeerIp, client_key, trusted_proxy_hops};

const NOT_FOUND_BODY: &str =
    "This link is not valid or has expired. Ask the assistant to send the file again.";
const METHOD_BODY: &str = "Use GET or HEAD.";
const TOO_MANY_BODY: &str = "Too many requests for this file. Try again shortly.";
const BUSY_BODY: &str = "The file service is busy. Try again shortly.";
const DOOR_BODY: &str = "The file is temporarily unavailable. Try again shortly.";
/// One door read (the runner reader's own budget is 20 s).
const DOOR_TIMEOUT: Duration = Duration::from_secs(25);
const RETRY_DELAY: Duration = Duration::from_millis(250);
/// Longest filename kept, in bytes.
const MAX_NAME_BYTES: usize = 120;
const INLINE_TYPES: &[&str] = &["image/jpeg", "image/png", "image/gif", "image/webp"];
const ATTACHMENT_TYPES: &[&str] = &[
    "application/pdf",
    "text/csv",
    "text/plain",
    "text/markdown",
    "application/json",
];

pub(crate) fn is_link_path(path: &str) -> bool {
    path.starts_with(LINK_PREFIX)
}

pub(crate) struct LinkRequest<'a> {
    pub method: &'a Method,
    pub path: &'a str,
    /// Only when proxy hops are trusted (else every user behind the load
    /// balancer would share one window).
    pub client: Option<ClientKey>,
    /// Unix seconds, from the system clock.
    pub now: u64,
    /// The CURRENT link TTL: lowering it revokes longer links already sent.
    pub ttl_max: u64,
    /// [`link::links_enabled`]: off answers every request with the 404.
    pub links_on: bool,
}

/// The route for the live activation's `table`, with the process limits.
pub(crate) async fn handle<B>(
    req: &Request<B>,
    table: &ArtifactLinkTable,
) -> Response<Full<Bytes>> {
    let hops = trusted_proxy_hops();
    let client = (hops > 0)
        .then(|| {
            let peer = req.extensions().get::<PeerIp>().map(|peer| peer.0);
            client_key(peer, req.headers(), hops)
        })
        .flatten();
    serve_link(
        LinkRequest {
            method: req.method(),
            path: req.uri().path(),
            client,
            now: unix_now(),
            ttl_max: link::ttl_secs(),
            links_on: link::links_enabled(),
        },
        |deployment| table.get(deployment),
        LinkLimits::global(),
    )
    .await
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub(crate) async fn serve_link(
    req: LinkRequest<'_>,
    lookup: impl Fn(&DeploymentId) -> Option<Arc<LinkUnit>>,
    limits: &LinkLimits,
) -> Response<Full<Bytes>> {
    if !req.links_on {
        return not_found();
    }
    if req.method != Method::GET && req.method != Method::HEAD {
        let (body, builder) = fixed(StatusCode::METHOD_NOT_ALLOWED, METHOD_BODY, None);
        return builder
            .header(header::ALLOW, "GET, HEAD")
            .body(Full::new(Bytes::from_static(body.as_bytes())))
            .unwrap_or_else(|_| not_found());
    }
    if let Some(client) = req.client
        && !limits.client_allows(client)
    {
        return refusal(StatusCode::TOO_MANY_REQUESTS, TOO_MANY_BODY, "60");
    }
    let Some((link, unit, artifact_id)) = authorise(&req, lookup) else {
        return not_found();
    };
    if !limits.link_allows(&format!("{}/{}", link.deployment, link.artifact_hex))
        || !limits.egress_allows(&unit.deployment, req.now)
    {
        tracing::debug!(deployment = %unit.deployment, outcome = "limited", "artifact link");
        return refusal(StatusCode::TOO_MANY_REQUESTS, TOO_MANY_BODY, "60");
    }
    let Some(_slot) = limits.try_read_slot() else {
        tracing::debug!(deployment = %unit.deployment, outcome = "busy", "artifact link");
        return refusal(StatusCode::SERVICE_UNAVAILABLE, BUSY_BODY, "2");
    };
    let file = match read(unit.reader.as_ref(), &artifact_id, &unit.deployment).await {
        Ok(file) => file,
        Err(DoorOutcome::NotFound) => return not_found(),
        Err(DoorOutcome::Down) => {
            return refusal(StatusCode::SERVICE_UNAVAILABLE, DOOR_BODY, "5");
        }
    };
    let Some(disposition) = disposition(&file.mime_type, file.name.as_deref()) else {
        return not_found();
    };
    let head = req.method == Method::HEAD;
    if !head {
        limits.egress_add(&unit.deployment, req.now, file.bytes.len() as u64);
    }
    tracing::debug!(deployment = %unit.deployment, outcome = "served", "artifact link");
    let length = file.bytes.len();
    let body = if head {
        Bytes::new()
    } else {
        Bytes::from(file.bytes)
    };
    security_headers(Response::builder().status(StatusCode::OK))
        .header(header::CONTENT_TYPE, file.mime_type)
        .header(header::CONTENT_DISPOSITION, disposition)
        .header(header::CONTENT_LENGTH, length)
        .body(Full::new(body))
        .unwrap_or_else(|_| not_found())
}

/// Path shape, unit, MAC and expiry. `None` is always the uniform 404.
fn authorise(
    req: &LinkRequest<'_>,
    lookup: impl Fn(&DeploymentId) -> Option<Arc<LinkUnit>>,
) -> Option<(LinkPath, Arc<LinkUnit>, String)> {
    let link = LinkPath::parse(req.path)?;
    // A 26-char Crockford string above `7ZZ…` is no ULID: same 404.
    let deployment = DeploymentId(ulid::Ulid::from_string(&link.deployment).ok()?);
    let unit = lookup(&deployment)?;
    if unit.deployment != link.deployment {
        return None;
    }
    match link::verify(&unit.key, &link, req.now, req.ttl_max) {
        Verdict::Valid { artifact_id } => Some((link, unit, artifact_id)),
        Verdict::Invalid => None,
    }
}

enum DoorOutcome {
    NotFound,
    Down,
}

/// One retry after 250 ms on `Unavailable` (the runner reader does not
/// retry); every read bounded by [`DOOR_TIMEOUT`].
async fn read(
    reader: &dyn ArtifactReader,
    artifact_id: &str,
    deployment: &str,
) -> Result<ArtifactBytes, DoorOutcome> {
    for attempt in 0..2 {
        let answer = match tokio::time::timeout(DOOR_TIMEOUT, reader.get(artifact_id)).await {
            Ok(answer) => answer,
            Err(_) => return Err(DoorOutcome::Down),
        };
        match answer {
            Ok(file) => return Ok(file),
            Err(ArtifactError::NotFound) => return Err(DoorOutcome::NotFound),
            Err(ArtifactError::Unavailable(_)) if attempt == 0 => {
                tokio::time::sleep(RETRY_DELAY).await;
            }
            Err(ArtifactError::Unauthorized) => {
                misconfigured(deployment, "unauthorized");
                return Err(DoorOutcome::Down);
            }
            Err(ArtifactError::PurposeNotGranted) => {
                misconfigured(deployment, "purpose_not_granted");
                return Err(DoorOutcome::Down);
            }
            Err(ArtifactError::Unavailable(_) | ArtifactError::TooLarge) => {
                return Err(DoorOutcome::Down);
            }
        }
    }
    Err(DoorOutcome::Down)
}

/// Once per process: the door refuses the unit's own token (revoked or
/// re-minted without a redeploy, or the purpose removed). Deployment id and a
/// fixed code only.
fn misconfigured(deployment: &str, code: &'static str) {
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            deployment = %deployment,
            code,
            "the artifacts door refused this unit's token while serving a file link \
             (later occurrences are not repeated)"
        );
    }
}

/// `None` for a type outside the v1 allow-list (the reader already refuses
/// one; this is defence in depth).
fn disposition(mime: &str, name: Option<&str>) -> Option<String> {
    let name = clean_name(name.unwrap_or_default());
    let ascii: String = name
        .chars()
        .map(|c| if c.is_ascii() { c } else { '_' })
        .collect();
    if INLINE_TYPES.contains(&mime) {
        return Some(format!("inline; filename=\"{ascii}\""));
    }
    if ATTACHMENT_TYPES.contains(&mime) {
        return Some(format!(
            "attachment; filename=\"{ascii}\"; filename*=UTF-8''{}",
            pct_encode(&name)
        ));
    }
    None
}

/// Control, bidi and invisible characters removed; `"` and `\` replaced; at
/// most [`MAX_NAME_BYTES`]; `file` when nothing is left.
fn clean_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() && !super::provenance::is_invisible_format(*c))
        .map(|c| if c == '"' || c == '\\' { '_' } else { c })
        .collect();
    let cleaned = cleaned.trim();
    let mut end = cleaned.len().min(MAX_NAME_BYTES);
    while !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    let cleaned = cleaned[..end].trim();
    if cleaned.is_empty() {
        "file".to_string()
    } else {
        cleaned.to_string()
    }
}

/// RFC 5987 `attr-char` kept, every other byte percent-encoded.
fn pct_encode(value: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(value.len() * 3);
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn security_headers(builder: hyper::http::response::Builder) -> hyper::http::response::Builder {
    builder
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::CACHE_CONTROL, "private, no-store")
        .header(
            header::CONTENT_SECURITY_POLICY,
            "sandbox; default-src 'none'",
        )
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(header::X_FRAME_OPTIONS, "DENY")
}

/// A fixed text answer with the security headers (and `Retry-After`).
fn fixed(
    status: StatusCode,
    body: &'static str,
    retry_after: Option<&'static str>,
) -> (&'static str, hyper::http::response::Builder) {
    let mut builder = security_headers(Response::builder().status(status))
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, body.len());
    if let Some(seconds) = retry_after {
        builder = builder.header(header::RETRY_AFTER, seconds);
    }
    (body, builder)
}

fn refusal(
    status: StatusCode,
    body: &'static str,
    retry_after: &'static str,
) -> Response<Full<Bytes>> {
    let (body, builder) = fixed(status, body, Some(retry_after));
    builder
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .unwrap_or_else(|_| not_found())
}

/// The ONE 404 every refusal about which file or which unit answers.
pub(crate) fn not_found() -> Response<Full<Bytes>> {
    let (body, builder) = fixed(StatusCode::NOT_FOUND, NOT_FOUND_BODY, None);
    builder
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .unwrap_or_else(|_| {
            let mut response = Response::new(Full::new(Bytes::from_static(body.as_bytes())));
            *response.status_mut() = StatusCode::NOT_FOUND;
            response
        })
}
