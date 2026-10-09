//! Test-only helpers shared by every metering test: a stub admin ingest door
//! and a ready-made queue item.
//!
//! The stub is raw TCP, the same shape [`crate::interop::mcp::auth_tests`]'s
//! stub issuer uses and for the same reason — nothing between the assertion
//! and the wire, so a test can read the `Authorization` header and the body
//! bytes exactly as the admin would receive them.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::event::{Surface, UsageEvent, new_event_id, now_rfc3339};
use super::{MeteringConfig, MeteringToken, Queued};

/// The token every stub-facing test stages, so an assertion on the header can
/// name it.
pub(crate) const TEST_TOKEN: &str = "gtm_usage-token";

/// The tenant every staged fixture records against. Spelled once so an
/// assertion can name it.
pub(crate) const TEST_TENANT: &str = "acme";

/// A stub admin `POST /ingest`: one fixed answer, every request recorded.
pub(crate) struct StubAdmin {
    pub url: String,
    requests: Arc<AtomicUsize>,
    raw: Arc<std::sync::Mutex<Vec<String>>>,
}

impl StubAdmin {
    pub(crate) async fn answering(status_line: &str, extra_headers: &str, body: &str) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let requests = Arc::new(AtomicUsize::new(0));
        let raw = Arc::new(std::sync::Mutex::new(Vec::new()));
        let counted = Arc::clone(&requests);
        let collected = Arc::clone(&raw);
        let response = format!(
            "{status_line}\r\nContent-Type: application/json\r\n{extra_headers}\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let response = response.clone();
                let counted = Arc::clone(&counted);
                let collected = Arc::clone(&collected);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16384];
                    let read = stream.read(&mut buf).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..read]).to_string();
                    if let Ok(mut raw) = collected.lock() {
                        raw.push(request);
                    }
                    counted.fetch_add(1, Ordering::Relaxed);
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });
        Self {
            url: format!("http://127.0.0.1:{port}/ingest"),
            requests,
            raw,
        }
    }

    /// The admin's success answer (§8.3): `202 {event_id, stored}`.
    pub(crate) async fn accepting() -> Self {
        Self::answering(
            "HTTP/1.1 202 Accepted",
            "",
            r#"{"event_id":"01J","stored":true}"#,
        )
        .await
    }

    pub(crate) fn count(&self) -> usize {
        self.requests.load(Ordering::Relaxed)
    }

    pub(crate) fn received(&self) -> Vec<String> {
        self.raw.lock().map(|raw| raw.clone()).unwrap_or_default()
    }

    /// The staged block pointing at this stub. Loopback `http` is accepted by
    /// [`super::parse_metering`] precisely so this is possible.
    pub(crate) fn metering(&self) -> MeteringConfig {
        MeteringConfig {
            endpoint: self.url.clone(),
            token: MeteringToken(TEST_TOKEN.into()),
            tenant_slug: TEST_TENANT.into(),
        }
    }

    /// Poll until the stub has seen `at_least` requests, or give up. Polling
    /// rather than sleeping a fixed time: the assertion is about what
    /// happened, not about how long it took.
    pub(crate) async fn wait_for(&self, at_least: usize) -> usize {
        for _ in 0..300 {
            if self.count() >= at_least {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.count()
    }

    /// The JSON body of the last request, parsed.
    pub(crate) fn last_body(&self) -> serde_json::Value {
        let raw = self.received().pop().unwrap_or_default();
        let body = raw.split("\r\n\r\n").nth(1).unwrap_or_default().to_string();
        serde_json::from_str(&body).unwrap_or(serde_json::Value::Null)
    }
}

/// A TCP peer that accepts a connection and then says nothing, ever.
///
/// The half of a transport failure a stub admin cannot produce: over `http`
/// the connector completes and the ANSWER never arrives (a request timeout);
/// over `https` the `ClientHello` is never replied to, so the TLS handshake —
/// which lives inside the connector — stalls instead (a connect timeout). One
/// listener covers both because the difference is entirely the scheme the
/// caller uses.
///
/// Returns its port. Nothing here leaves the loopback interface.
pub(crate) async fn silent_peer() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        // Accepted streams are HELD rather than dropped: dropping one closes
        // it, which turns the stall this exists to produce into a reset, and
        // a reset is a different classification.
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    port
}

/// A loopback port with nothing listening on it, so a connection to it is
/// REFUSED rather than dropped — the one transport failure that needs no
/// waiting at all.
pub(crate) async fn closed_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

/// A ready-made queue item aimed at `endpoint`.
pub(crate) fn queued(endpoint: &str) -> Queued {
    Queued {
        endpoint: endpoint.to_string(),
        token: MeteringToken(TEST_TOKEN.into()),
        event: UsageEvent {
            event_id: new_event_id(),
            occurred_at: now_rfc3339(),
            tenant_slug: TEST_TENANT.into(),
            deployment_id: "01J0000000000000000000000".into(),
            bundle_id: "support-bot".into(),
            agent_id: "support-bot".into(),
            credential_id: Some("c_01J".into()),
            surface: Surface::A2a.as_str(),
            tokens_in: 12,
            tokens_out: 4,
            iterations: 1,
            duration_ms: 90,
        },
    }
}

/// A staged block naming an endpoint nothing listens on.
///
/// For the tests that inspect the QUEUE rather than a stub: they run against
/// an [`super::Meter::inspectable`], whose sink never starts, so this must
/// never be reachable — `.invalid` is reserved by RFC 2606 precisely so it
/// cannot resolve.
pub(crate) fn unreachable_metering() -> MeteringConfig {
    MeteringConfig {
        endpoint: "https://admin.invalid/api/v1/ingest/worker-usage".into(),
        token: MeteringToken(TEST_TOKEN.into()),
        tenant_slug: TEST_TENANT.into(),
    }
}
