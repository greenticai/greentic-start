//! The real IMAP client behind [`ImapConnector`]: `async-imap` over `rustls`.
//!
//! Rules this file keeps, each silent if broken:
//! - **Certificate verification is mandatory and there is no plaintext mode.**
//!   `tls` is implicit TLS; `starttls` connects in the clear only long enough to
//!   issue STARTTLS and is refused if the upgrade fails. The password is sent
//!   only after the channel is encrypted.
//! - **The crypto provider is named explicitly (`ring`).** The binary links both
//!   `ring` and `aws-lc-rs`, and rustls panics building a config when it cannot
//!   pick one.
//! - **Reading never marks mail seen.** Messages are fetched with `BODY.PEEK[]`;
//!   only `mark_seen` / `move_to`, called after a successful firing, change flags.
//! - **Size is checked before the body is downloaded** (`RFC822.SIZE`).
//! - **Every network step has a deadline**, and no error text carries the password.

use std::sync::Arc;
use std::time::Duration;

use async_imap::error::Error as ImapLibError;
use async_imap::{Client, Session};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::TryStreamExt;
use mail_parser::{Address, MessageParser, MimeHeaders};
use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::email::{EmailImapSpec, SearchFilter, TlsMode};
use super::email_poller::{
    Fetched, ImapConnector, ImapError, ImapSession, MailAttachment, MailMessage, MailboxState,
};

const STEP_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

type Stream = TlsStream<TcpStream>;

pub(crate) struct RustlsImapConnector {
    roots: Arc<RootCertStore>,
}

impl RustlsImapConnector {
    /// Trusts the bundled Mozilla roots, the same set the rest of the binary uses.
    pub(crate) fn new() -> Self {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self {
            roots: Arc::new(roots),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_roots(roots: RootCertStore) -> Self {
        Self {
            roots: Arc::new(roots),
        }
    }

    fn tls(&self) -> Result<TlsConnector, ImapError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| transport(format!("tls config: {e}")))?
            .with_root_certificates(self.roots.clone())
            .with_no_client_auth();
        Ok(TlsConnector::from(Arc::new(config)))
    }
}

/// Read the greeting, then issue STARTTLS on the plaintext socket and wait for
/// the tagged OK. Done by hand because the client library never sees the
/// plaintext phase. Nothing sensitive is sent here, and the server sends
/// nothing after its OK until the TLS handshake starts, so the line reader
/// cannot swallow handshake bytes.
async fn start_tls(tcp: &mut TcpStream) -> Result<(), ImapError> {
    const TAG: &str = "a001";
    let mut reader = BufReader::new(&mut *tcp);
    let mut line = String::new();
    read_line(&mut reader, &mut line).await?;
    if !line.starts_with("* OK") {
        return Err(transport("no usable greeting from the server"));
    }
    reader
        .get_mut()
        .write_all(format!("{TAG} STARTTLS\r\n").as_bytes())
        .await
        .map_err(|e| transport(format!("starttls: {}", e.kind())))?;
    loop {
        read_line(&mut reader, &mut line).await?;
        if let Some(rest) = line.strip_prefix(TAG) {
            return if rest.trim_start().starts_with("OK") {
                Ok(())
            } else {
                Err(transport("the server refused STARTTLS"))
            };
        }
    }
}

async fn read_line(
    reader: &mut BufReader<&mut TcpStream>,
    line: &mut String,
) -> Result<(), ImapError> {
    line.clear();
    match timeout(STEP_TIMEOUT, reader.read_line(line)).await {
        Ok(Ok(0)) => Err(transport("connection closed during starttls")),
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(transport(format!("starttls: {}", e.kind()))),
        Err(_) => Err(transport("starttls: timed out")),
    }
}

fn transport(text: impl Into<String>) -> ImapError {
    ImapError::Transport(text.into())
}

/// Library errors are mapped to text without echoing the command line, which
/// for LOGIN contains the password.
fn lib_err(context: &str, err: &ImapLibError) -> ImapError {
    let kind = match err {
        ImapLibError::Io(_) => "io",
        ImapLibError::Bad(_) => "bad",
        ImapLibError::No(_) => "no",
        ImapLibError::ConnectionLost => "connection lost",
        ImapLibError::Parse(_) => "parse",
        _ => "other",
    };
    transport(format!("{context}: {kind} error"))
}

async fn within<T>(
    context: &str,
    fut: impl std::future::Future<Output = Result<T, ImapLibError>>,
) -> Result<T, ImapError> {
    match timeout(STEP_TIMEOUT, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(lib_err(context, &e)),
        Err(_) => Err(transport(format!("{context}: timed out"))),
    }
}

#[async_trait]
impl ImapConnector for RustlsImapConnector {
    async fn connect(
        &self,
        spec: &EmailImapSpec,
        password: &str,
    ) -> Result<Box<dyn ImapSession>, ImapError> {
        let connector = self.tls()?;
        let name = ServerName::try_from(spec.host.clone())
            .map_err(|_| transport("the host is not a valid server name"))?;
        let tcp = timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect((spec.host.as_str(), spec.port)),
        )
        .await
        .map_err(|_| transport("connect: timed out"))?
        .map_err(|e| transport(format!("connect: {}", e.kind())))?;

        let tls_stream: Stream = match spec.tls {
            TlsMode::Tls => connector
                .connect(name, tcp)
                .await
                .map_err(|e| transport(format!("tls handshake: {}", e.kind())))?,
            TlsMode::StartTls => {
                let mut tcp = tcp;
                start_tls(&mut tcp).await?;
                connector
                    .connect(name, tcp)
                    .await
                    .map_err(|e| transport(format!("starttls upgrade: {}", e.kind())))?
            }
        };

        let mut client = Client::new(tls_stream);
        if spec.tls == TlsMode::Tls {
            match timeout(STEP_TIMEOUT, client.read_response()).await {
                Ok(Ok(Some(_))) => {}
                _ => return Err(transport("no greeting from the server")),
            }
        }
        let session = match timeout(STEP_TIMEOUT, client.login(&spec.username, password)).await {
            Ok(Ok(session)) => session,
            Ok(Err((ImapLibError::No(_), _))) => return Err(ImapError::Auth),
            Ok(Err((err, _))) => return Err(lib_err("login", &err)),
            Err(_) => return Err(transport("login: timed out")),
        };
        Ok(Box::new(RustlsSession { session }))
    }
}

struct RustlsSession {
    session: Session<Stream>,
}

/// An IMAP quoted string. Control characters are refused rather than escaped:
/// they have no legitimate place in a mailbox, address or subject filter.
pub(crate) fn quoted(value: &str) -> Result<String, ImapError> {
    if value.chars().any(char::is_control) {
        return Err(transport("a search value contains a control character"));
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        if matches!(c, '"' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    Ok(out)
}

/// The `UID SEARCH` criteria for a filter: `UNSEEN` and/or `FROM`/`SUBJECT`,
/// or `ALL` when the filter selects nothing in particular.
pub(crate) fn search_query(filter: &SearchFilter) -> Result<String, ImapError> {
    let mut parts: Vec<String> = Vec::new();
    if filter.unseen {
        parts.push("UNSEEN".into());
    }
    if let Some(from) = &filter.from {
        parts.push(format!("FROM {}", quoted(from)?));
    }
    if let Some(subject) = &filter.subject {
        parts.push(format!("SUBJECT {}", quoted(subject)?));
    }
    Ok(if parts.is_empty() {
        "ALL".into()
    } else {
        parts.join(" ")
    })
}

#[async_trait]
impl ImapSession for RustlsSession {
    async fn select(&mut self, mailbox: &str) -> Result<MailboxState, ImapError> {
        let selected = within("select", self.session.select(mailbox)).await?;
        Ok(MailboxState {
            uid_validity: selected.uid_validity.unwrap_or(0),
        })
    }

    async fn search(&mut self, filter: &SearchFilter) -> Result<Vec<u32>, ImapError> {
        let query = search_query(filter)?;
        let found = within("search", self.session.uid_search(query)).await?;
        let mut uids: Vec<u32> = found.into_iter().collect();
        uids.sort_unstable();
        Ok(uids)
    }

    async fn fetch(&mut self, uid: u32, max_bytes: usize) -> Result<Fetched, ImapError> {
        let size = {
            let fetches = within(
                "fetch size",
                self.session.uid_fetch(uid.to_string(), "(RFC822.SIZE)"),
            )
            .await?;
            let list: Vec<_> = within("fetch size", fetches.try_collect::<Vec<_>>()).await?;
            match list.iter().find_map(|f| f.size) {
                Some(size) => u64::from(size),
                None => return Ok(Fetched::Gone),
            }
        };
        if size > max_bytes as u64 {
            return Ok(Fetched::TooLarge { size });
        }
        let fetches = within(
            "fetch",
            self.session.uid_fetch(uid.to_string(), "(BODY.PEEK[])"),
        )
        .await?;
        let list: Vec<_> = within("fetch", fetches.try_collect::<Vec<_>>()).await?;
        let Some(raw) = list.iter().find_map(|f| f.body()) else {
            return Ok(Fetched::Gone);
        };
        Ok(Fetched::Message(Box::new(parse_message(raw))))
    }

    async fn mark_seen(&mut self, uid: u32) -> Result<(), ImapError> {
        store_flag(&mut self.session, uid, "+FLAGS.SILENT (\\Seen)").await
    }

    async fn move_to(&mut self, uid: u32, mailbox: &str) -> Result<(), ImapError> {
        let id = uid.to_string();
        match timeout(STEP_TIMEOUT, self.session.uid_mv(&id, mailbox)).await {
            Ok(Ok(())) => return Ok(()),
            // No MOVE extension (or the server refused it): COPY + delete below.
            // A missing destination fails the COPY too, so it still surfaces.
            Ok(Err(ImapLibError::No(_) | ImapLibError::Bad(_))) => {}
            Ok(Err(e)) => return Err(lib_err("move", &e)),
            Err(_) => return Err(transport("move: timed out")),
        }
        within("copy", self.session.uid_copy(&id, mailbox)).await?;
        store_flag(&mut self.session, uid, "+FLAGS.SILENT (\\Deleted)").await?;
        let expunged = within("expunge", self.session.uid_expunge(&id)).await?;
        within("expunge", expunged.try_collect::<Vec<_>>()).await?;
        Ok(())
    }
}

async fn store_flag(session: &mut Session<Stream>, uid: u32, flags: &str) -> Result<(), ImapError> {
    let updated = within("store", session.uid_store(uid.to_string(), flags)).await?;
    within("store", updated.try_collect::<Vec<_>>()).await?;
    Ok(())
}

fn first_address(address: Option<&Address<'_>>) -> String {
    address
        .and_then(|a| a.first())
        .and_then(|a| a.address())
        .unwrap_or_default()
        .to_string()
}

fn all_addresses(address: Option<&Address<'_>>) -> Vec<String> {
    address
        .map(|a| {
            a.iter()
                .filter_map(|m| m.address().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// RFC 822 bytes to the poller's message. A message that does not parse as MIME
/// still yields a value (empty fields) rather than failing the whole poll.
pub(crate) fn parse_message(raw: &[u8]) -> MailMessage {
    let Some(msg) = MessageParser::default().parse(raw) else {
        return MailMessage {
            message_id: None,
            from: String::new(),
            to: Vec::new(),
            subject: String::new(),
            text: String::new(),
            html: None,
            received_at: Utc::now(),
            attachments: Vec::new(),
        };
    };
    let received_at = msg
        .date()
        .and_then(|d| DateTime::from_timestamp(d.to_timestamp(), 0))
        .unwrap_or_else(Utc::now);
    let attachments = msg
        .attachments()
        .map(|part| MailAttachment {
            name: part.attachment_name().unwrap_or("attachment").to_string(),
            mime_type: part
                .content_type()
                .map(|ct| match ct.subtype() {
                    Some(sub) => format!("{}/{}", ct.ctype(), sub),
                    None => ct.ctype().to_string(),
                })
                .unwrap_or_else(|| "application/octet-stream".into()),
            size_bytes: part.contents().len() as u64,
            bytes: Some(part.contents().to_vec()),
        })
        .collect();
    MailMessage {
        message_id: msg.message_id().map(str::to_string),
        from: first_address(msg.from()),
        to: all_addresses(msg.to()),
        subject: msg.subject().unwrap_or_default().to_string(),
        text: msg.body_text(0).map(|t| t.into_owned()).unwrap_or_default(),
        html: msg.body_html(0).map(|h| h.into_owned()),
        received_at,
        attachments,
    }
}

#[cfg(test)]
#[path = "imap_client_tests.rs"]
mod tests;
