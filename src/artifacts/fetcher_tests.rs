use super::time_testkit::within_ceiling;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::interop::metering::testkit::StubAdmin;

use super::client::AttachmentClient;
use super::fetch::*;
use super::fetch_ref::FetchRef;
use super::host_policy::HostPolicy;
use super::ingest_testkit::{origin_of, slack};
use super::origin::SecretScope;

pub(super) const OK: &str = "HTTP/1.1 200 OK";

/// Secret store double: one value for every name, and a record of the names
/// asked for.
pub(super) struct Secrets {
    pub(super) value: Option<&'static str>,
    pub(super) asked: Mutex<Vec<String>>,
}

impl Secrets {
    pub(super) fn new(value: Option<&'static str>) -> Arc<Self> {
        Arc::new(Self {
            value,
            asked: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait]
impl SecretLookup for Secrets {
    async fn get(&self, _: &SecretScope, name: &str) -> Option<String> {
        self.asked.lock().unwrap().push(name.to_string());
        self.value.map(str::to_string)
    }
}

/// Everything on 127.0.0.1 allowed, every other rule applied.
pub(super) fn loopback(secrets: Arc<Secrets>) -> HttpFetcher {
    let client = AttachmentClient::loopback_for_tests(Duration::from_secs(3)).unwrap();
    HttpFetcher::with_client(client, secrets)
}

pub(super) fn addr(stub: &StubAdmin) -> SocketAddr {
    let url = reqwest::Url::parse(&stub.url).unwrap();
    SocketAddr::from(([127, 0, 0, 1], url.port().unwrap()))
}

pub(super) fn named_url(name: &str, stub: &StubAdmin) -> String {
    format!("http://{name}:{}/file", addr(stub).port())
}

pub(super) fn header_lines(raw: &str) -> String {
    raw.split("\r\n\r\n")
        .next()
        .unwrap_or_default()
        .to_lowercase()
}

#[tokio::test]
async fn public_ref_downloads_bytes() {
    let stub = StubAdmin::answering(OK, "", "BODY").await;
    let r = FetchRef::Public {
        url: stub.url.clone(),
    };
    let got = loopback(Secrets::new(None))
        .fetch(&origin_of(&r), &r)
        .await
        .unwrap();
    assert_eq!(got.bytes, b"BODY");
    assert!(!header_lines(&stub.received()[0]).contains("authorization"));
}

#[tokio::test]
async fn bearer_ref_without_its_secret_is_a_missing_credential() {
    let r = FetchRef::Bearer {
        url: "https://files.slack.com/x".into(),
        secret_key: "SLACK_BOT_TOKEN".into(),
    };
    let err = loopback(Secrets::new(None))
        .fetch(&origin_of(&r), &r)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::MissingCredential), "{err:?}");
}

#[tokio::test]
async fn a_401_is_denied_and_does_not_leak_the_secret() {
    let stub = StubAdmin::answering("HTTP/1.1 401 Unauthorized", "", "no").await;
    let r = FetchRef::Bearer {
        url: stub.url.clone(),
        secret_key: "SLACK_BOT_TOKEN".into(),
    };
    let err = loopback(Secrets::new(Some("xoxb-SECRET")))
        .fetch(&origin_of(&r), &r)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::Denied(401)), "{err:?}");
    assert!(!format!("{err:?}{err}").contains("xoxb-SECRET"));
    assert!(
        header_lines(&stub.received()[0]).contains("authorization: bearer xoxb-secret"),
        "the bearer reaches an allowed host"
    );
}

#[tokio::test]
async fn a_declared_body_over_the_cap_is_refused() {
    let stub = StubAdmin::answering(OK, "", &"x".repeat(64)).await;
    let r = FetchRef::Public {
        url: stub.url.clone(),
    };
    let err = loopback(Secrets::new(None))
        .with_cap(16)
        .fetch(&origin_of(&r), &r)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::TooLarge), "{err:?}");
}

#[tokio::test]
async fn an_undeclared_body_is_cut_off_at_the_cap() {
    // No Content-Length (Teams gives no size): the cap is enforced while
    // streaming, and the transfer stops instead of being buffered.
    let (url, written) = endless_body_stub().await;
    let r = FetchRef::Public { url };
    let started = std::time::Instant::now();
    let fetcher = loopback(Secrets::new(None)).with_cap(64 * 1024);
    let err = within_ceiling(fetcher.fetch(&origin_of(&r), &r))
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::TooLarge), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(2));
    // The server could push at most the cap plus what socket buffers held
    // before the client hung up.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let sent = written.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        sent < 8 * 1024 * 1024,
        "the client kept reading: {sent} bytes"
    );
}

#[tokio::test]
async fn a_bearer_is_never_sent_to_a_host_off_its_list() {
    let secrets = Secrets::new(Some("xoxb-SECRET"));
    let r = FetchRef::Bearer {
        url: "https://tenant.sharepoint.com/x".into(),
        secret_key: "SLACK_BOT_TOKEN".into(),
    };
    let err = loopback(Arc::clone(&secrets))
        .fetch(&origin_of(&r), &r)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::BlockedHost), "{err:?}");
    assert!(!format!("{err:?}{err}").contains("xoxb-SECRET"));
}

#[tokio::test]
async fn an_unknown_credential_name_is_blocked_before_the_store_is_asked() {
    let secrets = Secrets::new(Some("t"));
    let r = FetchRef::Bearer {
        url: "https://files.slack.com/x".into(),
        secret_key: "ATTACKER_TOKEN".into(),
    };
    let err = loopback(Arc::clone(&secrets))
        .fetch(&origin_of(&r), &r)
        .await
        .unwrap_err();
    // Refused by the channel rule first, the host policy behind it.
    assert!(
        matches!(err, FetchError::NotThisChannel | FetchError::BlockedHost),
        "{err:?}"
    );
    assert!(
        secrets.asked.lock().unwrap().is_empty(),
        "a provider-named secret must not be read before the policy allows it"
    );
}

#[tokio::test]
async fn redirects_to_refused_hosts_are_blocked() {
    for target in [
        "https://evil.example/x",
        "http://169.254.169.254/latest/meta-data",
        "https://169.254.169.254/latest",
    ] {
        let stub =
            StubAdmin::answering("HTTP/1.1 302 Found", &format!("Location: {target}\r\n"), "")
                .await;
        let r = FetchRef::Public {
            url: stub.url.clone(),
        };
        let err = loopback(Secrets::new(None))
            .fetch(&origin_of(&r), &r)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::BlockedHost), "{target}: {err:?}");
    }
}

#[tokio::test]
async fn redirects_are_bounded() {
    // A stub that redirects to itself forever.
    let stub = StubAdmin::answering("HTTP/1.1 302 Found", "Location: /again\r\n", "").await;
    let r = FetchRef::Public {
        url: stub.url.clone(),
    };
    let err = loopback(Secrets::new(None))
        .fetch(&origin_of(&r), &r)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::TooManyRedirects), "{err:?}");
    assert_eq!(stub.count(), 4, "the first request and three redirects");
}

// --- Credential stripping across named hosts (host checklist 3) --------------

#[tokio::test]
async fn a_redirect_off_the_credential_list_sends_nothing_there() {
    let c = StubAdmin::answering(OK, "", "C").await;
    let a = StubAdmin::answering(
        "HTTP/1.1 302 Found",
        &format!("Location: {}\r\n", named_url("c.test", &c)),
        "",
    )
    .await;
    let policy = HostPolicy::named_for_tests(&[("SLACK_BOT_TOKEN", &["a.test"])], &[]);
    let client = AttachmentClient::named_for_tests(
        policy,
        &[("a.test", addr(&a)), ("c.test", addr(&c))],
        Duration::from_secs(3),
    )
    .unwrap();
    let fetcher = HttpFetcher::with_client(client, Secrets::new(Some("xoxb-SECRET")));
    let r = FetchRef::Bearer {
        url: named_url("a.test", &a),
        secret_key: "SLACK_BOT_TOKEN".into(),
    };
    let err = fetcher.fetch(&origin_of(&r), &r).await.unwrap_err();
    assert!(matches!(err, FetchError::BlockedHost), "{err:?}");
    assert_eq!(c.count(), 0, "no request at all reached the other host");
}

#[tokio::test]
async fn a_redirect_to_a_public_host_drops_the_authorization() {
    let c = StubAdmin::answering(OK, "", "C").await;
    let a = StubAdmin::answering(
        "HTTP/1.1 302 Found",
        &format!("Location: {}\r\n", named_url("c.test", &c)),
        "",
    )
    .await;
    let policy = HostPolicy::named_for_tests(&[("SLACK_BOT_TOKEN", &["a.test"])], &["c.test"]);
    let client = AttachmentClient::named_for_tests(
        policy,
        &[("a.test", addr(&a)), ("c.test", addr(&c))],
        Duration::from_secs(3),
    )
    .unwrap();
    let fetcher = HttpFetcher::with_client(client, Secrets::new(Some("xoxb-SECRET")));
    let r = FetchRef::Bearer {
        url: named_url("a.test", &a),
        secret_key: "SLACK_BOT_TOKEN".into(),
    };
    assert_eq!(fetcher.fetch(&origin_of(&r), &r).await.unwrap().bytes, b"C");
    assert!(header_lines(&a.received()[0]).contains("authorization: bearer xoxb-secret"));
    assert!(
        !header_lines(&c.received()[0]).contains("authorization"),
        "the credential crossed to a host off its list"
    );
}

#[tokio::test]
async fn a_redirect_within_the_credential_list_keeps_it_per_hop() {
    let b = StubAdmin::answering(OK, "", "B").await;
    let a = StubAdmin::answering(
        "HTTP/1.1 302 Found",
        &format!("Location: {}\r\n", named_url("b.test", &b)),
        "",
    )
    .await;
    let policy = HostPolicy::named_for_tests(&[("SLACK_BOT_TOKEN", &["a.test", "b.test"])], &[]);
    let client = AttachmentClient::named_for_tests(
        policy,
        &[("a.test", addr(&a)), ("b.test", addr(&b))],
        Duration::from_secs(3),
    )
    .unwrap();
    let fetcher = HttpFetcher::with_client(client, Secrets::new(Some("xoxb-SECRET")));
    let r = FetchRef::Bearer {
        url: named_url("a.test", &a),
        secret_key: "SLACK_BOT_TOKEN".into(),
    };
    assert_eq!(fetcher.fetch(&origin_of(&r), &r).await.unwrap().bytes, b"B");
    for stub in [&a, &b] {
        assert!(header_lines(&stub.received()[0]).contains("authorization: bearer xoxb-secret"));
    }
}

// --- WhatsApp -----------------------------------------------------------------

#[tokio::test]
async fn inline_is_not_fetched() {
    let err = loopback(Secrets::new(None))
        .fetch(&slack(), &FetchRef::Inline)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::BadReference));
}

/// An http server that sends headers with no `Content-Length` and then an
/// endless body.
async fn endless_body_stub() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let written = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&written);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                    .await;
                let chunk = vec![b'x'; 16 * 1024];
                // At most 64 MiB, so a broken cap cannot exhaust memory.
                for _ in 0..4096 {
                    if stream.write_all(&chunk).await.is_err() {
                        return;
                    }
                    counter.fetch_add(chunk.len(), std::sync::atomic::Ordering::SeqCst);
                }
            });
        }
    });
    (format!("http://127.0.0.1:{port}/big"), written)
}

#[tokio::test]
async fn a_declared_size_over_the_cap_is_refused_before_the_body_is_read() {
    // Declares 100 MiB and sends 4 bytes: only the declared length can
    // refuse it as too large (reading would end as an interrupted transfer).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 104857600\r\nConnection: close\r\n\r\nabcd")
                .await;
        }
    });
    let r = FetchRef::Public {
        url: format!("http://127.0.0.1:{port}/big"),
    };
    let err = loopback(Secrets::new(None))
        .fetch(&origin_of(&r), &r)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::TooLarge), "{err:?}");
}
