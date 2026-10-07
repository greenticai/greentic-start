//! Which hosts an attachment download may touch, and which hosts may receive a
//! channel credential. A provider supplies the URL; the host decides whether it
//! may be fetched. Never widen a credential's list from configuration.
//!
//! This decides WHICH names may be fetched; [`super::dns`] decides WHERE they
//! may point (public addresses only, checked at connect time).

use reqwest::Url;

pub(crate) const EXTRA_HOSTS_ENV: &str = "GREENTIC_ATTACHMENT_ALLOWED_HOSTS";

/// Hosts that need no credential (pre-authenticated download links). A
/// wildcard here matches exactly ONE label: `tenant.sharepoint.com`, never
/// `a.b.sharepoint.com`. The providers' Teams list must change with this one.
pub(crate) const PUBLIC_HOSTS: &[&str] = &["*.sharepoint.com", "smba.trafficmanager.net"];

/// Credential name → the only hosts it may be sent to. A wildcard here matches
/// any depth of subdomain (WhatsApp media CDNs serve from
/// `scontent.xx.fbcdn.net`), never the apex.
const CREDENTIAL_HOSTS: &[(&str, &[&str])] = &[
    ("SLACK_BOT_TOKEN", &["files.slack.com"]),
    ("WEBEX_BOT_TOKEN", &["webexapis.com"]),
    (
        "WHATSAPP_TOKEN",
        &[
            "lookaside.fbsbx.com",
            "*.fbcdn.net",
            "*.whatsapp.net",
            "graph.facebook.com",
        ],
    ),
    ("TELEGRAM_BOT_TOKEN", &["api.telegram.org"]),
];

/// Credentials carried IN the download URL (Telegram puts the bot token in the
/// path), so a redirect would replay them to wherever it points: never follow
/// one, whatever the target.
const NO_REDIRECT_CREDENTIALS: &[&str] = &["TELEGRAM_BOT_TOKEN"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Blocked {
    NotHttps,
    IpLiteral,
    UserInfo,
    Port,
    HostNotAllowed,
    UnknownCredential,
    /// A redirect `Location` that is not a URL.
    BadLocation,
    /// A redirect for a credential whose URL itself carries the secret.
    NoRedirect,
}

/// Where a redirect may go, and whether the credential goes with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hop<'a> {
    pub url: Url,
    pub credential: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub(crate) struct HostPolicy {
    extra: Vec<String>,
    #[cfg(test)]
    loopback: bool,
}

impl HostPolicy {
    pub(crate) fn from_env() -> Self {
        Self::from_value(std::env::var(EXTRA_HOSTS_ENV).ok().as_deref())
    }

    pub(crate) fn from_value(extra: Option<&str>) -> Self {
        let extra = extra
            .unwrap_or("")
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| is_valid_pattern(s))
            .collect();
        Self {
            extra,
            #[cfg(test)]
            loopback: false,
        }
    }

    /// Test servers listen on `127.0.0.1`; this policy lets exactly that host
    /// through (any scheme, any credential) and applies every other rule.
    #[cfg(test)]
    pub(crate) fn loopback_for_tests() -> Self {
        Self {
            extra: Vec::new(),
            loopback: true,
        }
    }

    pub(crate) fn check(&self, url: &Url, credential: Option<&str>) -> Result<(), Blocked> {
        #[cfg(test)]
        if self.loopback
            && url.host_str() == Some("127.0.0.1")
            && matches!(url.scheme(), "http" | "https")
        {
            return Ok(());
        }
        if url.scheme() != "https" {
            return Err(Blocked::NotHttps);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(Blocked::UserInfo);
        }
        if url.port().is_some() {
            return Err(Blocked::Port);
        }
        // `domain()` is `None` for every IP literal, including the integer and
        // short IPv4 forms the parser normalises (`https://2130706433/`).
        let Some(domain) = url.domain() else {
            return Err(Blocked::IpLiteral);
        };
        let host = domain.to_ascii_lowercase();
        let allowed = match credential {
            Some(name) => match credential_hosts(name) {
                Some(patterns) => patterns.iter().any(|p| host_matches(p, &host, false)),
                None => return Err(Blocked::UnknownCredential),
            },
            None => {
                PUBLIC_HOSTS.iter().any(|p| host_matches(p, &host, true))
                    || self.extra.iter().any(|p| host_matches(p, &host, true))
            }
        };
        if allowed {
            Ok(())
        } else {
            Err(Blocked::HostNotAllowed)
        }
    }

    /// A redirect from `from` to `location`, checked like a first request.
    /// The credential follows only to a host on its own list; to any other
    /// host the hop is checked as a credential-less fetch and the credential
    /// (the `Authorization` header) is dropped.
    pub(crate) fn redirect<'a>(
        &self,
        from: &Url,
        location: &str,
        credential: Option<&'a str>,
    ) -> Result<Hop<'a>, Blocked> {
        if credential.is_some_and(|name| NO_REDIRECT_CREDENTIALS.contains(&name)) {
            return Err(Blocked::NoRedirect);
        }
        let url = from.join(location).map_err(|_| Blocked::BadLocation)?;
        if let Some(name) = credential
            && self.check(&url, Some(name)).is_ok()
        {
            return Ok(Hop {
                url,
                credential: Some(name),
            });
        }
        self.check(&url, None)?;
        Ok(Hop {
            url,
            credential: None,
        })
    }
}

fn credential_hosts(name: &str) -> Option<&'static [&'static str]> {
    CREDENTIAL_HOSTS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, hosts)| *hosts)
}

/// `*.x.com` matches `a.x.com` (and, unless `single_label`, `a.b.x.com`),
/// never `x.com` or `notx.com`. Anything else matches exactly.
fn host_matches(pattern: &str, host: &str, single_label: bool) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => host
            .strip_suffix(suffix)
            .and_then(|rest| rest.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty() && (!single_label || !label.contains('.'))),
        None => host == pattern,
    }
}

fn is_valid_pattern(p: &str) -> bool {
    let body = p.strip_prefix("*.").unwrap_or(p);
    !body.is_empty()
        && body.contains('.')
        && !body.starts_with('.')
        && !body.ends_with('.')
        && body.chars().any(|c| c.is_ascii_alphabetic())
        && body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}
