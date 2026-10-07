//! A resolver that only ever returns public addresses. The host-name allow-list
//! decides WHICH names are fetched; this decides WHERE they may point, at
//! connect time. The client connects to exactly the addresses this returned
//! (one lookup per connection, no second resolution), so a DNS answer pointing
//! at an internal address — or a name that changes its answer between a check
//! and the connect (rebinding) — cannot reach it.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Fixed text: never names the address or the host.
#[derive(Debug)]
pub(crate) struct NoPublicAddress;

impl std::fmt::Display for NoPublicAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the host does not resolve to a public address")
    }
}

impl std::error::Error for NoPublicAddress {}

pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(addr: Ipv4Addr) -> bool {
    let o = addr.octets();
    !(addr.is_loopback()
        || addr.is_private()
        || addr.is_link_local()
        || addr.is_unspecified()
        || addr.is_broadcast()
        || addr.is_multicast()
        || addr.is_documentation()
        || o[0] == 0 // 0.0.0.0/8
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT 100.64/10
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
        || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 6to4 relay 192.88.99/24
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // benchmarking 198.18/15
        || o[0] >= 240) // reserved 240/4 and broadcast
}

fn is_public_v6(v6: Ipv6Addr) -> bool {
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return is_public_v4(mapped);
    }
    let s = v6.segments();
    !(v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || s[..6].iter().all(|&x| x == 0) // ::/96, IPv4-compatible (embeds a v4)
        || (s[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
        || (s[0] & 0xffc0) == 0xfe80 // link local fe80::/10
        || (s[0] == 0x64 && s[1] == 0xff9b) // NAT64 64:ff9b::/32 and 64:ff9b:1::/48
        || (s[0] == 0x100 && s[1..4].iter().all(|&x| x == 0)) // discard 100::/64
        || (s[0] == 0x2001 && s[1] < 0x200) // IETF special 2001::/23 (Teredo, ORCHID…)
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || s[0] == 0x2002) // 6to4 embeds a v4
}

pub(crate) type LookupFuture<'a> =
    Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send + 'a>>;

/// Where names are looked up: the system resolver in production, a double in
/// tests.
pub(crate) trait Lookup: Send + Sync {
    fn lookup<'a>(&'a self, host: &'a str) -> LookupFuture<'a>;
}

pub(crate) struct SystemLookup;

impl Lookup for SystemLookup {
    fn lookup<'a>(&'a self, host: &'a str) -> LookupFuture<'a> {
        Box::pin(async move { Ok(tokio::net::lookup_host((host, 443)).await?.collect()) })
    }
}

pub(crate) async fn resolve_public(host: &str) -> Result<Vec<SocketAddr>, NoPublicAddress> {
    resolve_public_with(&SystemLookup, host).await
}

/// The public addresses `host` resolves to; an error when there are none.
pub(crate) async fn resolve_public_with(
    lookup: &dyn Lookup,
    host: &str,
) -> Result<Vec<SocketAddr>, NoPublicAddress> {
    let found = lookup.lookup(host).await.map_err(|_| NoPublicAddress)?;
    let public: Vec<SocketAddr> = found
        .into_iter()
        .filter(|addr| is_public_ip(addr.ip()))
        .collect();
    if public.is_empty() {
        Err(NoPublicAddress)
    } else {
        Ok(public)
    }
}

/// `reqwest` resolver over [`resolve_public_with`].
pub(crate) struct PublicOnlyResolver {
    lookup: std::sync::Arc<dyn Lookup>,
}

impl PublicOnlyResolver {
    pub(crate) fn new() -> Self {
        Self::with_lookup(SystemLookup)
    }

    pub(crate) fn with_lookup(lookup: impl Lookup + 'static) -> Self {
        Self {
            lookup: std::sync::Arc::new(lookup),
        }
    }
}

impl Resolve for PublicOnlyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let lookup = std::sync::Arc::clone(&self.lookup);
        Box::pin(async move {
            let addrs = resolve_public_with(lookup.as_ref(), name.as_str()).await?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}
