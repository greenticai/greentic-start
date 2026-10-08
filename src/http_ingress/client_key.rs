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
