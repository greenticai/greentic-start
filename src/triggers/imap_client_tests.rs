use std::sync::{Arc, Mutex};

use rustls::RootCertStore;
use rustls::pki_types::PrivateKeyDer;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::*;
use crate::triggers::email;

const MAIL: &str = "From: Jane <jane@example.com>\r\nTo: support@acme.example, other@acme.example\r\n\
Subject: Refund please\r\nMessage-ID: <abc@example.com>\r\nDate: Tue, 20 Oct 2026 10:00:00 +0000\r\n\
MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n\
--b\r\nContent-Type: text/plain\r\n\r\nPlease refund order 7.\r\n\
--b\r\nContent-Type: text/plain; name=\"note.txt\"\r\nContent-Disposition: attachment; filename=\"note.txt\"\r\n\r\nhello\r\n--b--\r\n";

#[test]
fn values_are_quoted_and_control_characters_refused() {
    assert_eq!(quoted("a\"b\\c").unwrap(), r#""a\"b\\c""#);
    assert!(quoted("line\nbreak").is_err());
}

#[test]
fn the_search_query_follows_the_filter() {
    let f = SearchFilter {
        unseen: true,
        from: Some("a@x.com".into()),
        subject: Some("Re: \"hi\"".into()),
    };
    assert_eq!(
        search_query(&f).unwrap(),
        r#"UNSEEN FROM "a@x.com" SUBJECT "Re: \"hi\"""#
    );
    assert_eq!(search_query(&SearchFilter::default()).unwrap(), "ALL");
}

#[test]
fn a_mime_message_becomes_the_pollers_message() {
    let m = parse_message(MAIL.as_bytes());
    assert_eq!(m.from, "jane@example.com");
    assert_eq!(m.to, vec!["support@acme.example", "other@acme.example"]);
    assert_eq!(m.subject, "Refund please");
    assert_eq!(m.message_id.as_deref(), Some("abc@example.com"));
    assert!(m.text.contains("Please refund order 7."));
    assert_eq!(m.received_at.to_rfc3339(), "2026-10-20T10:00:00+00:00");
    assert_eq!(m.attachments.len(), 1);
    assert_eq!(m.attachments[0].name, "note.txt");
    assert_eq!(m.attachments[0].bytes.as_deref(), Some(&b"hello"[..]));
}

#[test]
fn garbage_still_yields_a_message_instead_of_failing_the_poll() {
    let m = parse_message(b"");
    assert!(m.subject.is_empty() && m.text.is_empty());
}

struct Fake {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
    roots: RootCertStore,
}

/// A TLS IMAP server that speaks just enough of the protocol for one session.
async fn fake_server(password: &'static str) -> Fake {
    fake_server_with(password, false).await
}

async fn fake_server_with(password: &'static str, starttls: bool) -> Fake {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        if starttls {
            tcp.write_all(b"* OK ready\r\n").await.unwrap();
            let mut plain = BufReader::new(&mut tcp);
            let mut cmd = String::new();
            plain.read_line(&mut cmd).await.unwrap();
            log.lock().unwrap().push(cmd.trim_end().to_string());
            plain
                .get_mut()
                .write_all(b"a001 OK begin TLS\r\n")
                .await
                .unwrap();
        }
        let tls = acceptor.accept(tcp).await.unwrap();
        let (r, mut w) = tokio::io::split(tls);
        let mut r = BufReader::new(r);
        if !starttls {
            w.write_all(b"* OK ready\r\n").await.unwrap();
        }
        let mut line = String::new();
        loop {
            line.clear();
            if r.read_line(&mut line).await.unwrap() == 0 {
                break;
            }
            let cmd = line.trim_end().to_string();
            let mut it = cmd.splitn(2, ' ');
            let tag = it.next().unwrap_or_default().to_string();
            let rest = it.next().unwrap_or_default().to_string();
            log.lock().unwrap().push(rest.clone());
            let reply = if rest.starts_with("LOGIN") {
                if rest.contains(&format!("\"{password}\"")) || rest.ends_with(password) {
                    format!("{tag} OK logged in\r\n")
                } else {
                    format!("{tag} NO [AUTHENTICATIONFAILED] nope\r\n")
                }
            } else if rest.starts_with("SELECT") {
                format!("* 2 EXISTS\r\n* OK [UIDVALIDITY 42] ok\r\n{tag} OK [READ-WRITE] done\r\n")
            } else if rest.starts_with("UID SEARCH") {
                format!("* SEARCH 7 5\r\n{tag} OK done\r\n")
            } else if rest.contains("RFC822.SIZE") {
                format!(
                    "* 1 FETCH (UID 5 RFC822.SIZE {})\r\n{tag} OK done\r\n",
                    MAIL.len()
                )
            } else if rest.contains("BODY.PEEK[]") {
                format!(
                    "* 1 FETCH (UID 5 BODY[] {{{}}}\r\n{MAIL})\r\n{tag} OK done\r\n",
                    MAIL.len()
                )
            } else if rest.starts_with("UID STORE") {
                format!("* 1 FETCH (UID 5 FLAGS (\\Seen))\r\n{tag} OK done\r\n")
            } else if rest.starts_with("LOGOUT") {
                let _ = w
                    .write_all(format!("* BYE\r\n{tag} OK bye\r\n").as_bytes())
                    .await;
                break;
            } else {
                format!("{tag} BAD unknown\r\n")
            };
            w.write_all(reply.as_bytes()).await.unwrap();
        }
        let mut sink = Vec::new();
        let _ = r.read_to_end(&mut sink).await;
    });
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    Fake { port, seen, roots }
}

fn spec(port: u16) -> email::EmailImapSpec {
    email::parse(&json!({
        "host": "localhost",
        "port": port,
        "tls": "tls",
        "username": "support@acme.example",
        "password_ref": "mail/imap_password",
        "search": { "unseen": true, "from": "jane@example.com" },
    }))
    .unwrap()
}

#[tokio::test]
async fn a_full_session_against_a_tls_server() {
    let fake = fake_server("s3cret").await;
    let connector = RustlsImapConnector::with_roots(fake.roots.clone());
    let spec = spec(fake.port);
    let mut session = connector.connect(&spec, "s3cret").await.expect("login");

    assert_eq!(session.select("INBOX").await.unwrap().uid_validity, 42);
    let uids = session.search(&spec.search).await.unwrap();
    assert_eq!(uids, vec![5, 7], "sorted ascending");

    let Fetched::Message(m) = session.fetch(5, 1_000_000).await.unwrap() else {
        panic!("expected a message")
    };
    assert_eq!(m.subject, "Refund please");
    assert!(matches!(
        session.fetch(5, 10).await.unwrap(),
        Fetched::TooLarge { .. }
    ));
    session.mark_seen(5).await.unwrap();

    let seen = fake.seen.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|c| c == r#"UID SEARCH UNSEEN FROM "jane@example.com""#),
        "{seen:?}"
    );
    assert!(
        seen.iter().any(|c| c.contains("BODY.PEEK[]")),
        "reading must not mark mail seen"
    );
    assert!(
        seen.iter().any(|c| c.contains(r"+FLAGS.SILENT (\Seen)")),
        "{seen:?}"
    );
    // The too-large message was never downloaded: BODY.PEEK[] was issued once.
    assert_eq!(seen.iter().filter(|c| c.contains("BODY.PEEK[]")).count(), 1);
}

#[tokio::test]
async fn a_refused_login_is_auth_not_transport_and_hides_the_password() {
    let fake = fake_server("right").await;
    let connector = RustlsImapConnector::with_roots(fake.roots.clone());
    let err = match connector.connect(&spec(fake.port), "wrong-pw-123").await {
        Ok(_) => panic!("login should be refused"),
        Err(e) => e,
    };
    assert!(matches!(err, ImapError::Auth), "{err:?}");
    assert!(!format!("{err:?}").contains("wrong-pw-123"));
}

#[tokio::test]
async fn an_untrusted_certificate_is_refused() {
    let fake = fake_server("pw").await;
    // Empty trust store: the self-signed certificate must not be accepted.
    let connector = RustlsImapConnector::with_roots(RootCertStore::empty());
    let err = match connector.connect(&spec(fake.port), "pw").await {
        Ok(_) => panic!("an untrusted certificate must be refused"),
        Err(e) => e,
    };
    assert!(matches!(err, ImapError::Transport(_)), "{err:?}");
    assert!(
        fake.seen
            .lock()
            .unwrap()
            .iter()
            .all(|c| !c.starts_with("LOGIN")),
        "the password must never be sent over an unverified channel"
    );
}

#[tokio::test]
async fn starttls_upgrades_before_the_password_is_sent() {
    let fake = fake_server_with("pw", true).await;
    let connector = RustlsImapConnector::with_roots(fake.roots.clone());
    let mut spec = spec(fake.port);
    spec.tls = TlsMode::StartTls;
    let mut session = connector
        .connect(&spec, "pw")
        .await
        .expect("login after upgrade");
    assert_eq!(session.select("INBOX").await.unwrap().uid_validity, 42);
    let seen = fake.seen.lock().unwrap().clone();
    assert_eq!(
        seen.first().map(String::as_str),
        Some("a001 STARTTLS"),
        "{seen:?}"
    );
    let starttls_at = seen.iter().position(|c| c == "a001 STARTTLS").unwrap();
    let login_at = seen.iter().position(|c| c.starts_with("LOGIN")).unwrap();
    assert!(
        starttls_at < login_at,
        "LOGIN must follow the upgrade: {seen:?}"
    );
}
