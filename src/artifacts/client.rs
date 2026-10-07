//! The ONLY HTTP client attachment downloads may use.
//!
//! [`attachment_client`] builds it with: the public-only resolver
//! ([`super::dns`]), no proxy (environment proxies are ignored), no automatic
//! redirects, `https` only, a total and a connect timeout. [`AttachmentClient::get`]
//! runs [`HostPolicy::check`] on the URL first and sends a credential only when
//! the policy allows that credential for that host.
//!
//! The policy check is mandatory for EVERY URL and EVERY redirect hop (use
//! [`HostPolicy::redirect`] to build the next hop and call `get` again): the
//! connector does not consult the resolver for an IP-literal host, so an IP
//! literal is stopped only by the check. Never issue an attachment request
//! through any other client.

use std::time::Duration;

use reqwest::Url;

use super::dns::with_public_only_resolver;
use super::host_policy::{Blocked, HostPolicy};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How a request authenticates. `Debug` never shows a token.
#[derive(Clone, Copy)]
pub(crate) enum Auth<'a> {
    None,
    /// `Authorization: Bearer <token>`, allowed only to `name`'s hosts.
    Bearer {
        name: &'a str,
        token: &'a str,
    },
    /// The secret is already in the URL (Telegram file paths): the host must be
    /// on `name`'s list, and no header is added.
    InUrl {
        name: &'a str,
    },
}

impl Auth<'_> {
    pub(crate) fn credential_name(&self) -> Option<&str> {
        match self {
            Auth::None => None,
            Auth::Bearer { name, .. } | Auth::InUrl { name } => Some(name),
        }
    }
}

impl std::fmt::Debug for Auth<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Auth::None => f.write_str("None"),
            Auth::Bearer { name, .. } => write!(f, "Bearer({name}, [redacted])"),
            Auth::InUrl { name } => write!(f, "InUrl({name})"),
        }
    }
}

/// Fixed texts only: never a URL, a token, or a response body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum FetchError {
    #[error("the download URL is not allowed ({0:?})")]
    Blocked(Blocked),
    #[error("the download timed out")]
    Timeout,
    #[error("the download host could not be reached")]
    Unreachable,
    #[error("the download failed")]
    Failed,
}

pub(crate) struct AttachmentClient {
    client: reqwest::Client,
    policy: HostPolicy,
}

impl std::fmt::Debug for AttachmentClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentClient")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// Settings every attachment client shares, test or production.
fn base_builder(timeout: Duration) -> reqwest::ClientBuilder {
    install_crypto_provider();
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(CONNECT_TIMEOUT.min(timeout))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
}

/// The production attachment client. `timeout` bounds one request end to end.
pub(crate) fn attachment_client(
    policy: HostPolicy,
    timeout: Duration,
) -> Result<AttachmentClient, reqwest::Error> {
    let client = with_public_only_resolver(base_builder(timeout))
        .https_only(true)
        .build()?;
    Ok(AttachmentClient { client, policy })
}

impl AttachmentClient {
    /// Test servers are `http://127.0.0.1`: the same client minus `https_only`
    /// and the public-only resolver, with [`HostPolicy::loopback_for_tests`].
    #[cfg(test)]
    pub(crate) fn loopback_for_tests(timeout: Duration) -> Result<Self, reqwest::Error> {
        Ok(Self {
            client: base_builder(timeout).build()?,
            policy: HostPolicy::loopback_for_tests(),
        })
    }

    pub(crate) fn policy(&self) -> &HostPolicy {
        &self.policy
    }

    /// `GET url`, after the policy allowed it for `auth`'s credential.
    pub(crate) async fn get(
        &self,
        url: &Url,
        auth: Auth<'_>,
    ) -> Result<reqwest::Response, FetchError> {
        self.policy
            .check(url, auth.credential_name())
            .map_err(FetchError::Blocked)?;
        let mut request = self.client.get(url.clone());
        if let Auth::Bearer { token, .. } = auth {
            request = request.bearer_auth(token);
        }
        request.send().await.map_err(|err| {
            if err.is_timeout() {
                FetchError::Timeout
            } else if err.is_connect() {
                FetchError::Unreachable
            } else {
                FetchError::Failed
            }
        })
    }
}

/// This binary carries both `ring` and `aws-lc-rs`, so rustls cannot pick a
/// provider on its own and the client builder panics without a default.
fn install_crypto_provider() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
