//! The public origin a signed artifact link is built on
//! (docs/outbound-artifacts.md).
//!
//! First non-empty source wins, exactly `interop_base_url`'s precedence plus
//! the tunnel: the configured base (env-store `host_config.public_base_url`,
//! then `PUBLIC_BASE_URL`), the Cloud Run capture, then a cloudflared/ngrok
//! tunnel. The winner must be a bare origin over `https`, or `http` to a
//! loopback host (local development); anything else yields
//! [`LinkBase::RelativeOnly`]. It is never derived from a request's `Host`
//! (any caller controls it), never `http` to a public host (the link would
//! travel in cleartext), and never a guess at a unit's mount: the link route
//! is reserved at the service root.

// Staged: outbound shaping (outbound-delivery plan Task 6) is the reader.
#![allow(dead_code)]

use std::net::IpAddr;

use reqwest::Url;

use super::link::LinkPath;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LinkBase {
    /// `scheme://host[:port]`, no trailing slash.
    Absolute(String),
    /// No usable public origin: only a path relative to the start origin.
    RelativeOnly,
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|v| !v.is_empty())
}

/// `localhost`, `127.0.0.0/8` or `::1` (`host_str` brackets an IPv6 literal).
fn is_loopback(host: &str) -> bool {
    let unbracketed = host.trim_start_matches('[').trim_end_matches(']');
    match unbracketed.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => host.eq_ignore_ascii_case("localhost"),
    }
}

fn bare_origin(raw: &str) -> Option<String> {
    let url = Url::parse(raw).ok()?;
    let host = url.host_str()?;
    let scheme_ok = match url.scheme() {
        "https" => true,
        "http" => is_loopback(host),
        _ => false,
    };
    let bare = url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    (scheme_ok && bare).then(|| url.origin().ascii_serialization())
}

pub(crate) fn link_base(
    configured: Option<&str>,
    captured: Option<&str>,
    tunnel: Option<&str>,
) -> LinkBase {
    non_empty(configured)
        .or_else(|| non_empty(captured))
        .or_else(|| non_empty(tunnel))
        .and_then(bare_origin)
        .map_or(LinkBase::RelativeOnly, LinkBase::Absolute)
}

/// The link as the user receives it. `RelativeOnly` gives the bare path,
/// which only a WebChat page served by this origin can resolve: a caller
/// shaping any other channel must not send it (outbound shaping refuses with
/// a fixed sentence instead).
pub(crate) fn link_url(base: &LinkBase, path: &LinkPath) -> String {
    match base {
        LinkBase::Absolute(origin) => format!("{origin}{}", path.to_path()),
        LinkBase::RelativeOnly => path.to_path(),
    }
}
