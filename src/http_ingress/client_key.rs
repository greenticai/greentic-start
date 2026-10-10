//! Which client an upload is counted against (host checklist 13).
//!
//! The client is the TCP peer unless `N` proxies are trusted to append to
//! `X-Forwarded-For`: the client is then the N-th entry from the right across
//! every header line. `N` is `GREENTIC_TRUSTED_PROXY_HOPS` when set (an
//! unparsable value is `0`), else `1` on Cloud Run (`K_SERVICE`), else `0`
//! ([`resolve_hops`]). IPv6 clients are counted per /64 (one
//! host normally holds the whole /64).

use std::net::{IpAddr, Ipv6Addr};
use std::sync::OnceLock;

use hyper::HeaderMap;

/// How many proxies in front of this host append to `X-Forwarded-For`.
const TRUSTED_PROXY_HOPS_ENV: &str = "GREENTIC_TRUSTED_PROXY_HOPS";

/// The bucket an upload is counted against: an IPv4 address, an IPv6 /64,
/// or — when the client address cannot be known — a conversation
/// ([`upload_client_key`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ClientKey {
    Ip(IpAddr),
    /// The first 16 bytes of a SHA-256 over the conversation id and the
    /// request's `Authorization` value: never the id or the token itself.
    Conversation([u8; 16]),
}

impl ClientKey {
    pub(crate) fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => ClientKey::Ip(IpAddr::V4(v4)),
                None => {
                    let s = v6.segments();
                    ClientKey::Ip(IpAddr::V6(Ipv6Addr::new(
                        s[0], s[1], s[2], s[3], 0, 0, 0, 0,
                    )))
                }
            },
            v4 => ClientKey::Ip(v4),
        }
    }
}

/// A Direct Line conversation id longer than this is not a conversation key.
const MAX_CONVERSATION_ID_BYTES: usize = 256;

/// The `{id}` of `…/v3/directline/conversations/{id}/upload`: exactly that one
/// path segment, non-empty and at most [`MAX_CONVERSATION_ID_BYTES`].
pub(crate) fn conversation_id(path: &str) -> Option<&str> {
    if !path.contains("/v3/directline/") {
        return None;
    }
    let mut segments = path.trim_end_matches('/').rsplit('/');
    if segments.next() != Some("upload") {
        return None;
    }
    let id = segments.next()?;
    if segments.next() != Some("conversations")
        || id.is_empty()
        || id.len() > MAX_CONVERSATION_ID_BYTES
    {
        return None;
    }
    Some(id)
}

/// The conversation bucket. The `Authorization` value is part of the key, so
/// a caller who knows another user's conversation id but not their Direct
/// Line token lands in its own bucket and cannot use up theirs.
fn conversation_key(path: &str, headers: &HeaderMap) -> Option<ClientKey> {
    use sha2::{Digest, Sha256};
    let id = conversation_id(path)?;
    let authorization = headers
        .get(hyper::header::AUTHORIZATION)
        .map(|v| v.as_bytes())
        .unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(b"greentic-upload-conversation-v1\0");
    hasher.update(id.as_bytes());
    hasher.update(b"\0");
    hasher.update(authorization);
    let digest = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    Some(ClientKey::Conversation(key))
}

/// The key an UPLOAD is counted against. A usable trusted forwarded entry or
/// a public peer is the client; a NON-public peer with no usable forwarded
/// entry (k8s behind its router, any proxy that appends nothing) hides every
/// client behind one address, so the conversation is the bucket instead. The
/// global upload cap still bounds the whole process.
pub(crate) fn upload_client_key(
    peer: Option<IpAddr>,
    headers: &HeaderMap,
    trusted_hops: usize,
    path: &str,
) -> Option<ClientKey> {
    if let Some(ip) = forwarded_client(headers, trusted_hops) {
        return Some(ClientKey::of(ip));
    }
    match peer {
        Some(ip) if !crate::artifacts::dns::is_public_ip(ip) => {
            match conversation_key(path, headers) {
                Some(key) => {
                    warn_addresses_unknown_once();
                    Some(key)
                }
                None => Some(ClientKey::of(ip)),
            }
        }
        other => other.map(ClientKey::of),
    }
}

fn warn_addresses_unknown_once() {
    static SAID: std::sync::Once = std::sync::Once::new();
    SAID.call_once(|| {
        crate::operator_log::warn(
            module_path!(),
            format!(
                "client addresses are not visible behind this proxy; uploads are limited \
                 per conversation. Set {TRUSTED_PROXY_HOPS_ENV} if the proxy appends \
                 X-Forwarded-For"
            ),
        );
    });
}

/// Where the effective hop count came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HopsSource {
    /// `GREENTIC_TRUSTED_PROXY_HOPS` set to a number (`0` included).
    Explicit,
    /// Set, but not a number: the safe value `0`, never the platform default.
    Unparsable,
    /// Unset on Cloud Run (`K_SERVICE`): its front end appends the address it
    /// received the connection from, so the right-most entry is not
    /// client-writable.
    CloudRun,
    /// Unset elsewhere: the TCP peer is the client.
    Default,
}

impl HopsSource {
    fn code(self) -> &'static str {
        match self {
            HopsSource::Explicit => "explicit",
            HopsSource::Unparsable => "unparsable",
            HopsSource::CloudRun => "cloud_run",
            HopsSource::Default => "default",
        }
    }
}

/// The hop count from the operator's value (`None` or blank = unset) and the
/// platform. An explicit value always wins, `0` included.
pub(crate) fn resolve_hops(explicit: Option<&str>, on_cloud_run: bool) -> (usize, HopsSource) {
    match explicit.map(str::trim).filter(|v| !v.is_empty()) {
        Some(value) => match value.parse() {
            Ok(hops) => (hops, HopsSource::Explicit),
            Err(_) => (0, HopsSource::Unparsable),
        },
        None if on_cloud_run => (1, HopsSource::CloudRun),
        None => (0, HopsSource::Default),
    }
}

/// The line said once when the count is first used.
pub(crate) fn hops_line(hops: usize, source: HopsSource) -> String {
    let mut line = format!(
        "upload client addresses: trusting {hops} ({}) proxy hop(s) of X-Forwarded-For",
        source.code()
    );
    if source == HopsSource::Unparsable {
        line.push_str(&format!(
            "; {TRUSTED_PROXY_HOPS_ENV} is not a number, so the header is not trusted"
        ));
    }
    line
}

/// The effective hop count, decided once per process ([`resolve_hops`]).
pub(crate) fn trusted_proxy_hops() -> usize {
    static HOPS: OnceLock<usize> = OnceLock::new();
    *HOPS.get_or_init(|| {
        let explicit = std::env::var(TRUSTED_PROXY_HOPS_ENV).ok();
        let (hops, source) = resolve_hops(
            explicit.as_deref(),
            crate::startup_contract::running_on_cloud_run(),
        );
        let line = hops_line(hops, source);
        if source == HopsSource::Unparsable {
            crate::operator_log::warn(module_path!(), line);
        } else {
            crate::operator_log::info(module_path!(), line);
        }
        hops
    })
}

/// The client by address alone, with no conversation fallback: the signed
/// file-link route's per-client window (`artifacts::serve_link`), and the
/// reference the upload tests compare against. With `trusted_hops == 0` it is
/// the TCP peer and `X-Forwarded-For` is ignored: any client can write that
/// header. With `N` trusted proxies it is the N-th entry from the right of the
/// header (every line, in order), the one the outermost trusted proxy
/// appended; too few entries, or one that is not an address, and the peer is
/// used.
pub(crate) fn client_key(
    peer: Option<IpAddr>,
    headers: &HeaderMap,
    trusted_hops: usize,
) -> Option<ClientKey> {
    forwarded_client(headers, trusted_hops)
        .or(peer)
        .map(ClientKey::of)
}

/// The N-th `X-Forwarded-For` entry from the right (every line, in order),
/// when `trusted_hops == N > 0` and that entry is an address.
fn forwarded_client(headers: &HeaderMap, trusted_hops: usize) -> Option<IpAddr> {
    if trusted_hops == 0 {
        return None;
    }
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
}
