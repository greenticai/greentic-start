//! Which client an upload is counted against (host checklist 13).
//!
//! The client is the TCP peer. `X-Forwarded-For` is trusted only when the
//! operator says how many proxies append to it
//! (`GREENTIC_TRUSTED_PROXY_HOPS=N`): the client is then the N-th entry from
//! the right across every header line. IPv6 clients are counted per /64 (one
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
