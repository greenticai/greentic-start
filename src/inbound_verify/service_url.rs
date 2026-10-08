//! Where a Microsoft Teams activity's `serviceUrl` may point.
//!
//! The Teams provider replies to the activity's `serviceUrl` WITH the bot's
//! token. A request this host could not verify (no bot app id, key set
//! unreachable) is still admitted, so without this check anyone could post an
//! activity naming their own `serviceUrl` and receive the bot token. It runs on
//! every UNVERIFIED Teams activity (not configured, or verification
//! unavailable), after the token check (`super::teams`). A VERIFIED activity
//! skips it: its signed `serviceurl` claim already matched the activity's
//! `serviceUrl`, and the list would only refuse genuine Microsoft hosts such
//! as GCC's `smba.infra.gcc.teams.microsoft.com`.
//!
//! Allowed: `https`, no userinfo, no explicit port, a DNS name (never an IP
//! literal) that is exactly [`EXACT_HOSTS`] or a subdomain of
//! [`SUFFIX_DOMAINS`] (public cloud Bot Framework only), or one of the exact
//! hosts in [`EXTRA_HOSTS_ENV`]. `*.trafficmanager.net` is NOT a suffix here:
//! any Azure customer can create a name under it, so only Bot Framework's own
//! `smba.trafficmanager.net` is trusted.

use std::sync::OnceLock;

use reqwest::Url;
use serde_json::Value;

/// Exact host names an operator adds (comma-separated; no wildcard).
pub(crate) const EXTRA_HOSTS_ENV: &str = "GREENTIC_TEAMS_SERVICE_URL_HOSTS";

const EXACT_HOSTS: &[&str] = &["smba.trafficmanager.net"];
/// A host under one of these (any depth, never the apex) is Bot Framework's.
const SUFFIX_DOMAINS: &[&str] = &["botframework.com"];

/// What the activity body says about its `serviceUrl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ServiceUrl {
    /// No body JSON, or no `serviceUrl` key: nothing to reply to.
    Absent,
    Allowed,
    Refused,
}

/// Classify the `serviceUrl` of a raw activity body.
pub(crate) fn classify(body: &[u8], extra: &[String]) -> ServiceUrl {
    let Ok(activity) = serde_json::from_slice::<Value>(body) else {
        return ServiceUrl::Absent;
    };
    match activity.get("serviceUrl") {
        None | Some(Value::Null) => ServiceUrl::Absent,
        Some(Value::String(url)) if allowed(url, extra) => ServiceUrl::Allowed,
        Some(_) => ServiceUrl::Refused,
    }
}

/// Whether `url` may receive the bot's token.
pub(crate) fn allowed(url: &str, extra: &[String]) -> bool {
    // Defence in depth, before the parser: these are where URL parsers
    // disagree with each other (`\` is `/` to WHATWG, userinfo `@`, escapes,
    // stray whitespace), and the provider that sends the token parses the URL
    // again with its own client. A genuine Bot Framework URL carries none.
    if url
        .chars()
        .any(|c| c == '\\' || c == '@' || c == '%' || c.is_whitespace() || c.is_control())
    {
        return false;
    }
    let Ok(url) = Url::parse(url) else {
        return false;
    };
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
    {
        return false;
    }
    let Some(host) = url.domain().map(str::to_ascii_lowercase) else {
        return false;
    };
    EXACT_HOSTS.contains(&host.as_str())
        || SUFFIX_DOMAINS.iter().any(|domain| {
            host.strip_suffix(domain)
                .and_then(|rest| rest.strip_suffix('.'))
                .is_some_and(|label| !label.is_empty())
        })
        || extra.contains(&host)
}

/// [`EXTRA_HOSTS_ENV`] parsed: exact DNS names only; a wildcard or anything
/// that is not a host name is dropped.
pub(crate) fn parse_extra(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or("")
        .split(',')
        .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|h| {
            h.contains('.')
                && !h.starts_with('.')
                && !h.contains("..")
                && h.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                && h.chars().any(|c| c.is_ascii_alphabetic())
        })
        .collect()
}

/// The process-wide extra hosts, read once.
pub(crate) fn extra_hosts() -> &'static [String] {
    static EXTRA: OnceLock<Vec<String>> = OnceLock::new();
    EXTRA.get_or_init(|| parse_extra(std::env::var(EXTRA_HOSTS_ENV).ok().as_deref()))
}
