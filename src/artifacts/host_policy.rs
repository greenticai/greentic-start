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
/// `a.b.sharepoint.com`. The providers' Teams list must change with this one;
/// today it still accepts any depth under `.sharepoint.com`, so a deeper name
/// passes the provider and is refused here (`docs/inbound-attachments.md`
/// section 10).
pub(crate) const PUBLIC_HOSTS: &[&str] = &["*.sharepoint.com", "smba.trafficmanager.net"];

/// Credential name → the only hosts it may be sent to. A host joins a list
/// only as an EXACT vendor-owned name measured (or shown by the provider's
/// own code) to serve that credential's files; never a wildcard. WhatsApp's
/// media CDNs are the one exception: a wildcard there matches any depth of
/// subdomain (Meta serves from `scontent.xx.fbcdn.net`), never the apex.
/// `api.ciscospark.com` is Cisco's legacy name for the same Webex API the bot
/// token is for; the Webex provider recognises content links on it.
const CREDENTIAL_HOSTS: &[(&str, &[&str])] = &[
    ("SLACK_BOT_TOKEN", &["files.slack.com"]),
    ("WEBEX_BOT_TOKEN", &["webexapis.com", "api.ciscospark.com"]),
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

/// Credential name → hosts its OWN host may redirect to, reached WITHOUT the
/// credential (the `Authorization` header is never sent there). Only as hop
/// 2..3, only from a URL on that credential's list, and never as a first
/// request. A host joins only from a MEASURED redirect trace of that
/// credential's own downloads (providers
/// `crates/provider-tests/tests/fixtures/cdn-measurements/`, cited per
/// entry); a wildcard matches exactly ONE label under a vendor-owned
/// registrable domain (`*.wbx2.com`, never `*.com`). Empty until measured.
const REDIRECT_ONLY_HOSTS: &[(&str, &[&str])] =
    &[("SLACK_BOT_TOKEN", &[]), ("WEBEX_BOT_TOKEN", &[])];

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
    #[cfg(test)]
    named: Option<NamedRules>,
    /// Test-only replacement for [`REDIRECT_ONLY_HOSTS`].
    #[cfg(test)]
    redirect_only: Option<Vec<(String, Vec<String>)>>,
}

/// Test-only host lists for stub servers reached by NAME (`a.test:port`) over
/// plain http: lets a test tell an allowed host from a refused one, which the
/// all-loopback policy cannot. Production never builds one.
#[cfg(test)]
#[derive(Debug, Clone)]
struct NamedRules {
    credentials: Vec<(String, Vec<String>)>,
    public: Vec<String>,
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
            #[cfg(test)]
            named: None,
            #[cfg(test)]
            redirect_only: None,
        }
    }

    /// This policy with `table` in place of [`REDIRECT_ONLY_HOSTS`].
    #[cfg(test)]
    pub(crate) fn with_redirect_only_for_tests(mut self, table: &[(&str, &[&str])]) -> Self {
        self.redirect_only = Some(
            table
                .iter()
                .map(|(name, hosts)| {
                    (
                        name.to_string(),
                        hosts.iter().map(|h| h.to_string()).collect(),
                    )
                })
                .collect(),
        );
        self
    }

    /// Test policy over named stub hosts: exact names only, http and any port
    /// allowed, IP literals still refused, a credential only to its own names.
    #[cfg(test)]
    pub(crate) fn named_for_tests(credentials: &[(&str, &[&str])], public: &[&str]) -> Self {
        Self {
            extra: Vec::new(),
            loopback: false,
            named: Some(NamedRules {
                credentials: credentials
                    .iter()
                    .map(|(name, hosts)| {
                        (
                            name.to_string(),
                            hosts.iter().map(|h| h.to_string()).collect(),
                        )
                    })
                    .collect(),
                public: public.iter().map(|h| h.to_string()).collect(),
            }),
            redirect_only: None,
        }
    }

    /// Test servers listen on `127.0.0.1`; this policy lets exactly that host
    /// through (any scheme, any credential) and applies every other rule.
    #[cfg(test)]
    pub(crate) fn loopback_for_tests() -> Self {
        Self {
            extra: Vec::new(),
            loopback: true,
            named: None,
            redirect_only: None,
        }
    }

    /// Mandatory for every attachment URL and every redirect hop, before any
    /// connection: the HTTP connector does not ask the resolver about an
    /// IP-literal host, so this check is what stops one.
    /// [`super::client::AttachmentClient::get`] calls it.
    pub(crate) fn check(&self, url: &Url, credential: Option<&str>) -> Result<(), Blocked> {
        #[cfg(test)]
        if self.loopback
            && url.host_str() == Some("127.0.0.1")
            && matches!(url.scheme(), "http" | "https")
        {
            return Ok(());
        }
        #[cfg(test)]
        if let Some(rules) = &self.named {
            let host = url.domain().ok_or(Blocked::IpLiteral)?;
            let allowed = match credential {
                Some(name) => match rules.credentials.iter().find(|(n, _)| n == name) {
                    Some((_, hosts)) => hosts.iter().any(|h| h == host),
                    None => return Err(Blocked::UnknownCredential),
                },
                None => rules.public.iter().any(|h| h == host),
            };
            return if allowed {
                Ok(())
            } else {
                Err(Blocked::HostNotAllowed)
            };
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
        if let Some(name) = credential
            && self.check(from, Some(name)).is_ok()
            && self.redirect_only_allows(name, &url)?
        {
            return Ok(Hop {
                url,
                credential: None,
            });
        }
        self.check(&url, None)?;
        Ok(Hop {
            url,
            credential: None,
        })
    }

    /// `name`'s redirect-only patterns: the test table when one was set,
    /// else [`REDIRECT_ONLY_HOSTS`].
    fn redirect_only_patterns(&self, name: &str) -> Vec<&str> {
        #[cfg(test)]
        if let Some(table) = &self.redirect_only {
            return table
                .iter()
                .filter(|(n, _)| n == name)
                .flat_map(|(_, hosts)| hosts.iter().map(String::as_str))
                .collect();
        }
        REDIRECT_ONLY_HOSTS
            .iter()
            .filter(|(n, _)| *n == name)
            .flat_map(|(_, hosts)| hosts.iter().copied())
            .collect()
    }

    /// Whether `url` is on `name`'s redirect-only list. A URL that breaks a
    /// shape rule (scheme, userinfo, port, IP literal) is refused with that
    /// rule whatever the list says.
    fn redirect_only_allows(&self, name: &str, url: &Url) -> Result<bool, Blocked> {
        let patterns = self.redirect_only_patterns(name);
        if patterns.is_empty() {
            return Ok(false);
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
        let Some(domain) = url.domain() else {
            return Err(Blocked::IpLiteral);
        };
        let host = domain.to_ascii_lowercase();
        Ok(patterns.iter().any(|p| host_matches(p, &host, true)))
    }
}

/// The credential → hosts table, for the list ratchets.
#[cfg(test)]
pub(crate) fn credential_host_table() -> &'static [(&'static str, &'static [&'static str])] {
    CREDENTIAL_HOSTS
}

/// The production [`REDIRECT_ONLY_HOSTS`], for the list ratchets.
#[cfg(test)]
pub(crate) fn redirect_only_table() -> &'static [(&'static str, &'static [&'static str])] {
    REDIRECT_ONLY_HOSTS
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
