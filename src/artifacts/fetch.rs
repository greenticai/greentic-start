//! Downloads the bytes a provider referred to.
//!
//! Every request goes through [`AttachmentClient`], so every URL and every
//! redirect hop meets the host policy before anything is sent, names resolve
//! to public addresses only, no proxy is used and no redirect is followed
//! automatically. On top of that this module:
//!
//! - looks a credential up only after the policy allowed its name for the
//!   first URL (a provider-supplied name never reads an arbitrary secret);
//! - follows at most [`MAX_REDIRECTS`] redirects by hand, each built by
//!   [`super::host_policy::HostPolicy::redirect`], which drops the credential
//!   when a hop leaves its host list and refuses every hop for a credential
//!   carried in the URL (Telegram);
//! - streams the body and stops at the size cap, declared length or not;
//! - reports fixed texts only: never a URL, a token or a response body.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::Url;
use reqwest::header::LOCATION;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::client::{AttachmentClient, Auth, RequestError, attachment_client};
use super::fetch_ref::FetchRef;
use super::host_policy::HostPolicy;
use super::limits::MAX_FILE_BYTES;

/// The credential NAMES the host resolves for the two id-based kinds: the
/// providers' default secret names (`messaging-provider-telegram`
/// `TOKEN_SECRET`, `messaging-provider-whatsapp` `DEFAULT_TOKEN_KEY`).
pub(crate) const TELEGRAM_TOKEN_KEY: &str = "TELEGRAM_BOT_TOKEN";
pub(crate) const WHATSAPP_TOKEN_KEY: &str = "WHATSAPP_TOKEN";
const WHATSAPP_GRAPH: &str = "https://graph.facebook.com/v20.0";
const TELEGRAM_API: &str = "https://api.telegram.org";
const MAX_REDIRECTS: usize = 3;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest metadata answer (Telegram `getFile`, WhatsApp media lookup) read.
const MAX_METADATA_BYTES: u64 = 64 * 1024;

#[async_trait]
pub(crate) trait SecretLookup: Send + Sync {
    async fn get(&self, name: &str) -> Option<String>;
}

/// Fixed texts only.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum FetchError {
    #[error("the credential for this download is not available")]
    MissingCredential,
    #[error("the channel refused the download ({0})")]
    Denied(u16),
    #[error("the file is larger than the allowed size")]
    TooLarge,
    #[error("the channel answered {0}")]
    Status(u16),
    #[error("the download failed: {0}")]
    Transport(String),
    #[error("the channel's file reference could not be resolved")]
    BadReference,
    #[error("the download address is not on the allowed list")]
    BlockedHost,
    #[error("the download was redirected too many times")]
    TooManyRedirects,
}

impl From<RequestError> for FetchError {
    fn from(err: RequestError) -> Self {
        match err {
            RequestError::Blocked(_) => FetchError::BlockedHost,
            other => FetchError::Transport(other.to_string()),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Fetched {
    pub bytes: Vec<u8>,
    pub name_hint: Option<String>,
}

#[async_trait]
pub(crate) trait Fetcher: Send + Sync {
    async fn fetch(&self, reference: &FetchRef) -> Result<Fetched, FetchError>;
}

pub(crate) struct HttpFetcher {
    client: AttachmentClient,
    secrets: Arc<dyn SecretLookup>,
    cap: u64,
    telegram_api: String,
    whatsapp_graph: String,
}

impl HttpFetcher {
    /// The production fetcher: [`attachment_client`] with the policy from the
    /// environment.
    pub(crate) fn new(secrets: Arc<dyn SecretLookup>) -> Result<Self, reqwest::Error> {
        let client = attachment_client(HostPolicy::from_env(), DOWNLOAD_TIMEOUT)?;
        Ok(Self::with_client(client, secrets))
    }

    pub(crate) fn with_client(client: AttachmentClient, secrets: Arc<dyn SecretLookup>) -> Self {
        Self {
            client,
            secrets,
            cap: MAX_FILE_BYTES,
            telegram_api: TELEGRAM_API.into(),
            whatsapp_graph: WHATSAPP_GRAPH.into(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_cap(mut self, cap: u64) -> Self {
        self.cap = cap;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_whatsapp_graph(mut self, base: String) -> Self {
        self.whatsapp_graph = base;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_telegram_api(mut self, base: String) -> Self {
        self.telegram_api = base;
        self
    }

    /// A credential by name, looked up only after the policy allowed that
    /// name for `url`.
    async fn credential(&self, url: &Url, name: &str) -> Result<String, FetchError> {
        self.client
            .policy()
            .check(url, Some(name))
            .map_err(|_| FetchError::BlockedHost)?;
        self.secrets
            .get(name)
            .await
            .ok_or(FetchError::MissingCredential)
    }

    /// `GET url` and its redirects, the body capped at `cap` bytes.
    async fn download(&self, url: Url, auth: Auth<'_>, cap: u64) -> Result<Vec<u8>, FetchError> {
        let mut current = url;
        let mut auth = auth;
        // The first request plus at most MAX_REDIRECTS hops.
        for _ in 0..=MAX_REDIRECTS {
            let response = self.client.get(&current, auth).await?;
            let status = response.status();
            if status.is_redirection() {
                let location = response
                    .headers()
                    .get(LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or(FetchError::BadReference)?;
                let next = self
                    .client
                    .policy()
                    .redirect(&current, location, auth.credential_name())
                    .map_err(|_| FetchError::BlockedHost)?;
                if next.credential.is_none() {
                    auth = Auth::None;
                }
                current = next.url;
                continue;
            }
            match status {
                s if s.is_success() => {}
                s @ (reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN) => {
                    return Err(FetchError::Denied(s.as_u16()));
                }
                s => return Err(FetchError::Status(s.as_u16())),
            }
            return read_capped(response, cap).await;
        }
        Err(FetchError::TooManyRedirects)
    }

    async fn metadata<T: DeserializeOwned>(
        &self,
        url: Url,
        auth: Auth<'_>,
    ) -> Result<T, FetchError> {
        let raw = self.download(url, auth, MAX_METADATA_BYTES).await?;
        serde_json::from_slice(&raw).map_err(|_| FetchError::BadReference)
    }

    async fn fetch_telegram(&self, file_id: &str) -> Result<Fetched, FetchError> {
        let api = Url::parse(&self.telegram_api).map_err(|_| FetchError::BadReference)?;
        let token = self.credential(&api, TELEGRAM_TOKEN_KEY).await?;
        // The token goes into the URL path Telegram requires: refuse one that
        // could change the URL's shape, and never log or return it.
        if !valid_telegram_token(&token) {
            return Err(FetchError::MissingCredential);
        }
        let auth = Auth::InUrl {
            name: TELEGRAM_TOKEN_KEY,
        };
        let mut lookup = join(&api, &format!("bot{token}/getFile"))?;
        lookup.query_pairs_mut().append_pair("file_id", file_id);
        let meta: TelegramFileResult = self.metadata(lookup, auth).await?;
        let path = meta
            .result
            .and_then(|result| result.file_path)
            .filter(|path| meta.ok && valid_telegram_path(path))
            .ok_or(FetchError::BadReference)?;
        let file = join(&api, &format!("file/bot{token}/{path}"))?;
        let bytes = self.download(file, auth, self.cap).await?;
        Ok(Fetched {
            bytes,
            name_hint: None,
        })
    }

    async fn fetch_whatsapp(&self, media_id: &str) -> Result<Fetched, FetchError> {
        let graph = Url::parse(&self.whatsapp_graph).map_err(|_| FetchError::BadReference)?;
        let lookup = join(&graph, media_id)?;
        let token = self.credential(&lookup, WHATSAPP_TOKEN_KEY).await?;
        let auth = Auth::Bearer {
            name: WHATSAPP_TOKEN_KEY,
            token: &token,
        };
        let meta: WhatsappMedia = self.metadata(lookup, auth).await?;
        // The media URL comes from a response body, so it is untrusted: the
        // client checks it (and every redirect) before the token is attached.
        let url = meta
            .url
            .and_then(|url| Url::parse(&url).ok())
            .ok_or(FetchError::BadReference)?;
        let bytes = self.download(url, auth, self.cap).await?;
        Ok(Fetched {
            bytes,
            name_hint: None,
        })
    }
}

#[async_trait]
impl Fetcher for HttpFetcher {
    async fn fetch(&self, reference: &FetchRef) -> Result<Fetched, FetchError> {
        let bytes = match reference {
            FetchRef::Public { url } => {
                let url = Url::parse(url).map_err(|_| FetchError::BadReference)?;
                self.download(url, Auth::None, self.cap).await?
            }
            FetchRef::Bearer { url, secret_key } => {
                let url = Url::parse(url).map_err(|_| FetchError::BadReference)?;
                let token = self.credential(&url, secret_key).await?;
                let auth = Auth::Bearer {
                    name: secret_key,
                    token: &token,
                };
                self.download(url, auth, self.cap).await?
            }
            FetchRef::TelegramFile { file_id } => return self.fetch_telegram(file_id).await,
            FetchRef::WhatsappMedia { media_id } => return self.fetch_whatsapp(media_id).await,
            // Bytes already in the envelope: the pipeline stores them itself.
            FetchRef::Inline => return Err(FetchError::BadReference),
        };
        Ok(Fetched {
            bytes,
            name_hint: None,
        })
    }
}

/// The body, read chunk by chunk; past `cap` bytes the transfer is dropped.
async fn read_capped(mut response: reqwest::Response, cap: u64) -> Result<Vec<u8>, FetchError> {
    if response.content_length().is_some_and(|len| len > cap) {
        return Err(FetchError::TooLarge);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| FetchError::Transport("the download was interrupted".into()))?
    {
        if bytes.len() as u64 + chunk.len() as u64 > cap {
            return Err(FetchError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// `base` + `/` + `tail`, keeping `base`'s path (which `Url::join` would drop).
fn join(base: &Url, tail: &str) -> Result<Url, FetchError> {
    let text = format!("{}/{tail}", base.as_str().trim_end_matches('/'));
    Url::parse(&text).map_err(|_| FetchError::BadReference)
}

/// Telegram's `file_path` becomes part of a URL that carries the bot token.
pub(crate) fn valid_telegram_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && !path.starts_with('/')
        && !path
            .split('/')
            .any(|segment| segment == ".." || segment.is_empty())
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '.' | '-'))
}

/// A bot token is `<digits>:<base64url>`; anything else could reshape the URL.
fn valid_telegram_token(token: &str) -> bool {
    (1..=256).contains(&token.len())
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '-'))
}

#[derive(Deserialize)]
struct TelegramFileResult {
    ok: bool,
    result: Option<TelegramFile>,
}

#[derive(Deserialize)]
struct TelegramFile {
    file_path: Option<String>,
}

#[derive(Deserialize)]
struct WhatsappMedia {
    url: Option<String>,
}
