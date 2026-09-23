//! The MCP gate, against a real RS256 keypair and a stub JWKS endpoint.
//!
//! Each test gets its own issuer (a fresh loopback port), because the JWKS
//! cache is a process-global static shared by the whole test binary: a shared
//! issuer would let one test's key set — or its refresh floor — decide another
//! test's outcome.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::interop::config::{Credential, InteropConfig};
use crate::interop::mcp::testkit;

const TENANT: &str = "acme";
const RESOURCE: &str = "https://w.example/mcp";
const BEARER_TOKEN: &str = "gtw_staged-token";

/// A stub authorization server that answers `/.well-known/jwks.json`.
struct StubIssuer {
    url: String,
    fetches: Arc<AtomicUsize>,
}

impl StubIssuer {
    /// Serve `connections` requests, then stop. The caller's issuer URL is
    /// unique to this listener's port.
    async fn start(connections: usize, body: String) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let fetches = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&fetches);
        tokio::spawn(async move {
            for _ in 0..connections {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                counted.fetch_add(1, Ordering::Relaxed);
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = stream.read(&mut buf).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });
        let url = format!("http://127.0.0.1:{port}");
        crate::interop::mcp::jwks::clear_issuer_for_tests(&url);
        Self { url, fetches }
    }

    async fn serving_keys(connections: usize) -> Self {
        Self::start(connections, testkit::jwks_document().to_string()).await
    }
}

fn config(issuer: Option<&str>) -> InteropConfig {
    InteropConfig {
        mcp: true,
        a2a: true,
        credentials: vec![Credential {
            id: "c1".into(),
            sha256: Sha256::digest(BEARER_TOKEN.as_bytes()).into(),
            expires_at_ms: None,
        }],
        tenant_slug: Some(TENANT.to_string()),
        issuer: issuer.map(str::to_string),
        mcp_resource: Some(RESOURCE.to_string()),
        ..InteropConfig::default()
    }
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

#[tokio::test]
async fn a_valid_token_authenticates_as_its_subject() {
    let issuer = StubIssuer::serving_keys(1).await;
    let sub = testkit::unique_sub();
    let token = testkit::mint_token(&issuer.url, RESOURCE, &sub, TENANT, 600);
    let outcome = authenticate(
        &config(Some(&issuer.url)),
        RESOURCE,
        Some(&bearer(&token)),
        0,
    )
    .await;
    assert_eq!(outcome, McpAuth::Allowed(McpCaller::Oauth(sub.clone())));
    // The caller key is the `sub` — the rate-limit bucket and the conversation
    // namespace.
    if let McpAuth::Allowed(caller) = outcome {
        assert_eq!(caller.key(), sub);
    }
    assert_eq!(issuer.fetches.load(Ordering::Relaxed), 1);
}

/// An issuer with a trailing slash denotes the same origin, and refusing it
/// would be a one-character difference nothing names.
#[tokio::test]
async fn a_trailing_slash_on_the_issuer_is_tolerated() {
    let issuer = StubIssuer::serving_keys(1).await;
    let sub = testkit::unique_sub();
    let with_slash = format!("{}/", issuer.url);
    let token = testkit::mint_token(&with_slash, RESOURCE, &sub, TENANT, 600);
    let outcome = authenticate(
        &config(Some(&with_slash)),
        RESOURCE,
        Some(&bearer(&token)),
        0,
    )
    .await;
    assert_eq!(outcome, McpAuth::Allowed(McpCaller::Oauth(sub)));
}

#[tokio::test]
async fn a_token_for_another_audience_is_refused() {
    let issuer = StubIssuer::serving_keys(1).await;
    let token = testkit::mint_token(
        &issuer.url,
        "https://someone-else.example/mcp",
        &testkit::unique_sub(),
        TENANT,
        600,
    );
    let outcome = authenticate(
        &config(Some(&issuer.url)),
        RESOURCE,
        Some(&bearer(&token)),
        0,
    )
    .await;
    assert_eq!(outcome, McpAuth::Unauthorized);
}

#[tokio::test]
async fn a_token_from_another_issuer_is_refused() {
    let configured = StubIssuer::serving_keys(1).await;
    let token = testkit::mint_token(
        "https://evil.example",
        RESOURCE,
        &testkit::unique_sub(),
        TENANT,
        600,
    );
    let outcome = authenticate(
        &config(Some(&configured.url)),
        RESOURCE,
        Some(&bearer(&token)),
        0,
    )
    .await;
    assert_eq!(outcome, McpAuth::Unauthorized);
}

/// The cross-tenant boundary: a perfectly-signed token minted for another
/// workspace must not run a turn here.
#[tokio::test]
async fn a_token_naming_another_tenant_is_refused() {
    let issuer = StubIssuer::serving_keys(1).await;
    let token = testkit::mint_token(
        &issuer.url,
        RESOURCE,
        &testkit::unique_sub(),
        "someone-else",
        600,
    );
    let outcome = authenticate(
        &config(Some(&issuer.url)),
        RESOURCE,
        Some(&bearer(&token)),
        0,
    )
    .await;
    assert_eq!(outcome, McpAuth::Unauthorized);
}

#[tokio::test]
async fn an_expired_token_is_refused() {
    let issuer = StubIssuer::serving_keys(1).await;
    // Well past the five-second leeway; `jsonwebtoken`'s own default is sixty,
    // which is why the leeway is set explicitly.
    let token = testkit::mint_token(&issuer.url, RESOURCE, &testkit::unique_sub(), TENANT, -600);
    let outcome = authenticate(
        &config(Some(&issuer.url)),
        RESOURCE,
        Some(&bearer(&token)),
        0,
    )
    .await;
    assert_eq!(outcome, McpAuth::Unauthorized);
}

#[tokio::test]
async fn a_token_naming_an_unknown_kid_is_refused() {
    let issuer = StubIssuer::serving_keys(1).await;
    let token = testkit::mint_token_with_kid(
        "not-the-served-key",
        &issuer.url,
        RESOURCE,
        &testkit::unique_sub(),
        TENANT,
        600,
    );
    let outcome = authenticate(
        &config(Some(&issuer.url)),
        RESOURCE,
        Some(&bearer(&token)),
        0,
    )
    .await;
    assert_eq!(outcome, McpAuth::Unauthorized);
}

/// An issuer that cannot be reached is a `503`, not a `401`: nothing is known
/// to be wrong with the caller's token, and a `401` would send it to
/// re-authenticate against the very thing not answering.
#[tokio::test]
async fn an_unreachable_issuer_is_reported_as_unavailable() {
    // A listener that accepts nothing: the port is bound and then dropped, so
    // the connection is refused.
    let dead = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        format!("http://127.0.0.1:{port}")
    };
    crate::interop::mcp::jwks::clear_issuer_for_tests(&dead);
    let token = testkit::mint_token(&dead, RESOURCE, &testkit::unique_sub(), TENANT, 600);
    let outcome = authenticate(&config(Some(&dead)), RESOURCE, Some(&bearer(&token)), 0).await;
    assert_eq!(outcome, McpAuth::IssuerUnavailable);
}

#[tokio::test]
async fn a_unit_with_no_issuer_refuses_every_token() {
    let issuer = StubIssuer::serving_keys(0).await;
    let token = testkit::mint_token(&issuer.url, RESOURCE, &testkit::unique_sub(), TENANT, 600);
    let outcome = authenticate(&config(None), RESOURCE, Some(&bearer(&token)), 0).await;
    assert_eq!(outcome, McpAuth::Unauthorized);
    assert_eq!(
        issuer.fetches.load(Ordering::Relaxed),
        0,
        "no issuer configured means no outbound fetch"
    );
}

/// Contract D2: `/mcp` also accepts the A2A bearer server-side.
#[tokio::test]
async fn the_staged_a2a_bearer_is_accepted_without_touching_the_issuer() {
    let issuer = StubIssuer::serving_keys(0).await;
    let outcome = authenticate(
        &config(Some(&issuer.url)),
        RESOURCE,
        Some(&bearer(BEARER_TOKEN)),
        0,
    )
    .await;
    assert_eq!(outcome, McpAuth::Allowed(McpCaller::Bearer("c1".into())));
    assert_eq!(
        issuer.fetches.load(Ordering::Relaxed),
        0,
        "a staged credential must not cost a JWKS fetch"
    );
}

#[tokio::test]
async fn no_token_and_a_non_bearer_scheme_are_refused() {
    let issuer = StubIssuer::serving_keys(0).await;
    let config = config(Some(&issuer.url));
    for header in [
        None,
        Some("Basic abc".to_string()),
        Some("Bearer ".to_string()),
    ] {
        assert_eq!(
            authenticate(&config, RESOURCE, header.as_deref(), 0).await,
            McpAuth::Unauthorized,
            "{header:?}"
        );
    }
}

#[test]
fn the_bearer_scheme_is_case_insensitive_and_needs_a_token() {
    assert_eq!(bearer_token(Some("Bearer abc")), Some("abc"));
    assert_eq!(bearer_token(Some("bearer  abc ")), Some("abc"));
    assert_eq!(bearer_token(Some("Bearer")), None);
    assert_eq!(bearer_token(Some("Basic abc")), None);
    assert_eq!(bearer_token(None), None);
}
