//! The signed-link route (docs/outbound-artifacts.md): the serving rule's
//! headers, ONE 404 for every refusal about which file or which unit, the
//! limits, and the door's failures mapped to fixed answers.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use greentic_aw_runtime::{ArtifactBytes, ArtifactError, ArtifactReader};
use greentic_deploy_spec::ids::DeploymentId;
use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper::{Method, Response, StatusCode};

use super::ingest_testkit::{FakeStore, pipeline};
use super::link::{LinkKey, LinkPath, mint};
use super::link_table::{ArtifactLinkTable, LinkUnit};
use super::recent_puts::RecentPuts;
use super::serve_link::{LinkRequest, is_link_path, serve_link};
use super::serve_link_limits::LinkLimits;
use super::unit::{Off, UnitAttachments, UnitCell};
use crate::http_ingress::limits::ClientKey;

const TOKEN: &str = "gtm_route-token";
const TENANT: &str = "acme";
const BUNDLE: &str = "b1";
const ID: &str = "artifact://dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const NOW: u64 = 1_800_000_000;
const TTL: u64 = 86_400;
const NOT_FOUND_BODY: &[u8] =
    b"This link is not valid or has expired. Ask the assistant to send the file again.";

/// A scripted door answer: (mime type, name, bytes) or an error.
type Scripted = Result<(String, Option<String>, Vec<u8>), ArtifactError>;

/// Answers from a script, in order; the last answer repeats.
struct StubReader {
    answers: Mutex<VecDeque<Scripted>>,
    calls: AtomicUsize,
}

impl StubReader {
    fn new(answers: Vec<Scripted>) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.into()),
            calls: AtomicUsize::new(0),
        })
    }

    fn file(mime: &str, name: Option<&str>, bytes: &[u8]) -> Arc<Self> {
        Self::new(vec![Ok((
            mime.to_string(),
            name.map(str::to_string),
            bytes.to_vec(),
        ))])
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

fn copy(error: &ArtifactError) -> ArtifactError {
    match error {
        ArtifactError::NotFound => ArtifactError::NotFound,
        ArtifactError::Unauthorized => ArtifactError::Unauthorized,
        ArtifactError::PurposeNotGranted => ArtifactError::PurposeNotGranted,
        ArtifactError::TooLarge => ArtifactError::TooLarge,
        ArtifactError::Unavailable(why) => ArtifactError::Unavailable(why.clone()),
    }
}

impl ArtifactReader for StubReader {
    fn get<'a>(
        &'a self,
        _id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ArtifactBytes, ArtifactError>> + Send + 'a>,
    > {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let answer = {
            let mut answers = self.answers.lock().unwrap();
            if answers.len() > 1 {
                answers.pop_front().unwrap()
            } else {
                match answers.front().unwrap() {
                    Ok(file) => Ok(file.clone()),
                    Err(error) => Err(copy(error)),
                }
            }
        };
        Box::pin(async move {
            answer.map(|(mime_type, name, bytes)| ArtifactBytes {
                mime_type,
                name,
                bytes,
            })
        })
    }
}

/// Never answers: the route must bound the wait.
struct HangingReader;

impl ArtifactReader for HangingReader {
    fn get<'a>(
        &'a self,
        _id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ArtifactBytes, ArtifactError>> + Send + 'a>,
    > {
        Box::pin(std::future::pending())
    }
}

fn enabled_cell() -> Arc<UnitCell> {
    Arc::new(UnitCell::new(UnitAttachments::Enabled {
        pipeline: Arc::new(pipeline(vec![], Arc::new(FakeStore::default()))),
    }))
}

struct Fixture {
    deployment: DeploymentId,
    unit: Arc<LinkUnit>,
    _cell: Arc<UnitCell>,
}

fn fixture(reader: Arc<dyn ArtifactReader>) -> Fixture {
    let cell = enabled_cell();
    let deployment = DeploymentId::new();
    let unit = Arc::new(LinkUnit {
        key: LinkKey::derive(TOKEN, TENANT, BUNDLE, &deployment.to_string()),
        reader,
        recent: Arc::new(RecentPuts::default()),
        cells: vec![Arc::downgrade(&cell)],
        deployment: deployment.to_string(),
    });
    Fixture {
        deployment,
        unit,
        _cell: cell,
    }
}

impl Fixture {
    fn link(&self) -> LinkPath {
        self.link_for(ID, NOW, TTL)
    }

    fn link_for(&self, id: &str, now: u64, ttl: u64) -> LinkPath {
        let key = LinkKey::derive(TOKEN, TENANT, BUNDLE, &self.deployment.to_string());
        mint(&key, &self.deployment.to_string(), id, now, ttl).expect("mint")
    }

    async fn request(&self, method: Method, path: &str, limits: &LinkLimits) -> Answer {
        self.request_with(method, path, limits, None, true, NOW)
            .await
    }

    async fn request_with(
        &self,
        method: Method,
        path: &str,
        limits: &LinkLimits,
        client: Option<ClientKey>,
        links_on: bool,
        now: u64,
    ) -> Answer {
        let unit = Arc::clone(&self.unit);
        let deployment = self.deployment;
        let lookup = move |id: &DeploymentId| (*id == deployment).then(|| Arc::clone(&unit));
        let response = serve_link(
            LinkRequest {
                method: &method,
                path,
                client,
                now,
                ttl_max: TTL,
                links_on,
            },
            lookup,
            limits,
        )
        .await;
        Answer::of(response).await
    }
}

fn limits() -> LinkLimits {
    LinkLimits::new(2, 1 << 30)
}

#[derive(Debug, PartialEq)]
struct Answer {
    status: StatusCode,
    headers: Vec<(String, String)>,
    body: Bytes,
}

impl Answer {
    async fn of(response: Response<http_body_util::Full<Bytes>>) -> Self {
        let status = response.status();
        let mut headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap().to_string()))
            .collect();
        headers.sort();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        Self {
            status,
            headers,
            body,
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

fn assert_security_headers(answer: &Answer) {
    assert_eq!(answer.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(answer.header("cache-control"), Some("private, no-store"));
    assert_eq!(
        answer.header("content-security-policy"),
        Some("sandbox; default-src 'none'")
    );
    assert_eq!(answer.header("referrer-policy"), Some("no-referrer"));
    assert_eq!(answer.header("x-frame-options"), Some("DENY"));
    for absent in [
        "set-cookie",
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "location",
        "etag",
        "last-modified",
    ] {
        assert!(answer.header(absent).is_none(), "{absent}: {answer:?}");
    }
}

#[test]
fn only_paths_under_the_prefix_are_link_paths() {
    assert!(is_link_path("/v1/artifacts/x"));
    assert!(is_link_path("/v1/artifacts/"));
    assert!(!is_link_path("/v1/artifacts"));
    assert!(!is_link_path("/acme/v1/artifacts/x"));
    assert!(!is_link_path("/v1/artifactsx/y"));
}

#[tokio::test]
async fn a_safe_image_is_served_inline_under_the_serving_rule() {
    for mime in ["image/png", "image/jpeg", "image/gif", "image/webp"] {
        let f = fixture(StubReader::file(mime, Some("pic.png"), b"IMG"));
        let answer = f.request(Method::GET, &f.link().to_path(), &limits()).await;
        assert_eq!(answer.status, StatusCode::OK, "{mime}");
        assert_eq!(answer.header("content-type"), Some(mime));
        assert_eq!(
            answer.header("content-disposition"),
            Some("inline; filename=\"pic.png\"")
        );
        assert_eq!(answer.header("content-length"), Some("3"));
        assert_eq!(answer.body.as_ref(), b"IMG");
        assert_security_headers(&answer);
    }
}

#[tokio::test]
async fn a_document_is_always_an_attachment_with_both_filename_forms() {
    for mime in [
        "application/pdf",
        "text/csv",
        "text/plain",
        "text/markdown",
        "application/json",
    ] {
        let f = fixture(StubReader::file(mime, Some("Résumé 1.pdf"), b"DOC!"));
        let answer = f.request(Method::GET, &f.link().to_path(), &limits()).await;
        assert_eq!(answer.status, StatusCode::OK, "{mime}");
        assert_eq!(answer.header("content-type"), Some(mime));
        assert_eq!(
            answer.header("content-disposition"),
            Some(
                "attachment; filename=\"R_sum_ 1.pdf\"; filename*=UTF-8''R%C3%A9sum%C3%A9%201.pdf"
            )
        );
        assert_eq!(answer.header("content-length"), Some("4"));
        assert_security_headers(&answer);
    }
}

#[tokio::test]
async fn a_type_outside_the_allow_list_is_refused_like_a_missing_file() {
    for mime in ["image/svg+xml", "text/html", "application/octet-stream", ""] {
        let f = fixture(StubReader::file(mime, Some("x"), b"<svg/>"));
        let answer = f.request(Method::GET, &f.link().to_path(), &limits()).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{mime}");
        assert_eq!(answer.body.as_ref(), NOT_FOUND_BODY);
    }
}

#[tokio::test]
async fn every_refusal_about_which_file_or_unit_is_the_same_404() {
    let f = fixture(StubReader::file("image/png", Some("a.png"), b"IMG"));
    let good = f.link();
    let path = good.to_path();
    let flip = |s: &str, at: usize| {
        let mut chars: Vec<char> = s.chars().collect();
        chars[at] = if chars[at] == '0' { '1' } else { '0' };
        chars.into_iter().collect::<String>()
    };
    let mut paths = vec![
        // malformed
        "/v1/artifacts/".to_string(),
        "/v1/artifacts/x/y/z/w".to_string(),
        format!("{path}/"),
        format!("{path}/extra"),
        path.replace(&good.mac_hex, &good.mac_hex.to_uppercase()),
        path.replacen('/', "%2F", 4),
        // another (unknown) deployment
        path.replace(&good.deployment, &DeploymentId::new().to_string()),
        // the right shape, but no ULID can start above `7`
        path.replace(&good.deployment, "8ZZZZZZZZZZZZZZZZZZZZZZZZZ"),
        // tampered artifact / exp / mac
        LinkPath {
            artifact_hex: flip(&good.artifact_hex, 3),
            ..good.clone()
        }
        .to_path(),
        LinkPath {
            exp: good.exp + 1,
            ..good.clone()
        }
        .to_path(),
        LinkPath {
            mac_hex: flip(&good.mac_hex, 0),
            ..good.clone()
        }
        .to_path(),
        // expired: minted long ago
        f.link_for(ID, NOW - 2 * TTL, TTL).to_path(),
        // exp beyond the current TTL ceiling (the TTL was lowered)
        f.link_for(ID, NOW, TTL * 4).to_path(),
    ];
    // a minted link for another unit's key
    let other = fixture(StubReader::file("image/png", None, b"IMG"));
    paths.push(
        LinkPath {
            deployment: good.deployment.clone(),
            ..other.link()
        }
        .to_path(),
    );

    let reference = f
        .request(Method::GET, "/v1/artifacts/nope", &limits())
        .await;
    assert_eq!(reference.status, StatusCode::NOT_FOUND);
    assert_eq!(reference.body.as_ref(), NOT_FOUND_BODY);
    assert_security_headers(&reference);
    for p in &paths {
        let answer = f.request(Method::GET, p, &limits()).await;
        assert_eq!(answer, reference, "{p}");
    }

    // The door says the file is gone (retention sweep, another tenant's id).
    let gone = fixture(StubReader::new(vec![Err(ArtifactError::NotFound)]));
    let answer = gone
        .request(Method::GET, &gone.link().to_path(), &limits())
        .await;
    assert_eq!(answer, reference);

    // Links switched off: even a perfect link.
    let answer = f
        .request_with(Method::GET, &path, &limits(), None, false, NOW)
        .await;
    assert_eq!(answer, reference);

    // A unit that runs without attachments (re-probe turned it off).
    let cell = Arc::new(UnitCell::new(UnitAttachments::Off(Off::NotGranted)));
    let deployment = f.deployment;
    let table = ArtifactLinkTable::new(
        [(
            deployment,
            Arc::new(LinkUnit {
                key: LinkKey::derive(TOKEN, TENANT, BUNDLE, &deployment.to_string()),
                reader: StubReader::file("image/png", None, b"IMG"),
                recent: Arc::new(RecentPuts::default()),
                cells: vec![Arc::downgrade(&cell)],
                deployment: deployment.to_string(),
            }),
        )]
        .into_iter()
        .collect(),
    );
    let response = serve_link(
        LinkRequest {
            method: &Method::GET,
            path: &path,
            client: None,
            now: NOW,
            ttl_max: TTL,
            links_on: true,
        },
        |id: &DeploymentId| table.get(id),
        &limits(),
    )
    .await;
    assert_eq!(Answer::of(response).await, reference);
}

#[tokio::test]
async fn a_refused_link_never_reaches_the_door() {
    let reader = StubReader::file("image/png", None, b"IMG");
    let f = fixture(reader.clone());
    let mut tampered = f.link();
    tampered.exp += 1;
    let _ = f.request(Method::GET, &tampered.to_path(), &limits()).await;
    let _ = f
        .request_with(
            Method::GET,
            &f.link().to_path(),
            &limits(),
            None,
            false,
            NOW,
        )
        .await;
    assert_eq!(reader.calls(), 0);
}

#[tokio::test]
async fn head_answers_the_same_headers_with_no_body() {
    let f = fixture(StubReader::file(
        "application/pdf",
        Some("r.pdf"),
        b"%PDF-1",
    ));
    let path = f.link().to_path();
    let get = f.request(Method::GET, &path, &limits()).await;
    let head = f.request(Method::HEAD, &path, &limits()).await;
    assert_eq!(head.status, StatusCode::OK);
    assert_eq!(head.headers, get.headers);
    assert_eq!(head.header("content-length"), Some("6"));
    assert!(head.body.is_empty());
}

#[tokio::test]
async fn other_methods_are_405_with_allow() {
    let f = fixture(StubReader::file("image/png", None, b"IMG"));
    for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
        let answer = f
            .request(method.clone(), &f.link().to_path(), &limits())
            .await;
        assert_eq!(answer.status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
        assert_eq!(answer.header("allow"), Some("GET, HEAD"));
        assert_security_headers(&answer);
    }
}

#[tokio::test]
async fn an_unavailable_door_is_retried_once() {
    let reader = StubReader::new(vec![
        Err(ArtifactError::Unavailable("x".into())),
        Ok(("image/png".into(), None, b"IMG".to_vec())),
    ]);
    let f = fixture(reader.clone());
    let answer = f.request(Method::GET, &f.link().to_path(), &limits()).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(
        answer.header("content-disposition"),
        Some("inline; filename=\"file\"")
    );
    assert_eq!(reader.calls(), 2);

    let reader = StubReader::new(vec![Err(ArtifactError::Unavailable("x".into()))]);
    let f = fixture(reader.clone());
    let answer = f.request(Method::GET, &f.link().to_path(), &limits()).await;
    assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(answer.header("retry-after").is_some());
    assert_eq!(reader.calls(), 2);
    assert_security_headers(&answer);
}

#[tokio::test]
async fn door_misconfiguration_and_oversize_are_503_without_detail() {
    for error in [
        ArtifactError::Unauthorized,
        ArtifactError::PurposeNotGranted,
        ArtifactError::TooLarge,
    ] {
        let reader = StubReader::new(vec![Err(error)]);
        let f = fixture(reader.clone());
        let answer = f.request(Method::GET, &f.link().to_path(), &limits()).await;
        assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(answer.header("retry-after").is_some());
        let body = String::from_utf8_lossy(&answer.body);
        assert!(
            !body.contains("purpose") && !body.contains("credential"),
            "{body}"
        );
        assert_eq!(reader.calls(), 1, "only Unavailable is retried");
    }
}

#[tokio::test(start_paused = true)]
async fn a_door_that_never_answers_is_bounded() {
    let f = fixture(Arc::new(HangingReader));
    // Virtual time: a route without its own bound would outlive this.
    let answer = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        f.request(Method::GET, &f.link().to_path(), &limits()),
    )
    .await
    .expect("the door read was not bounded");
    assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn one_link_answers_at_most_thirty_times_a_minute() {
    let f = fixture(StubReader::file("image/png", None, b"IMG"));
    let limits = limits();
    let path = f.link().to_path();
    for i in 0..30 {
        let answer = f.request(Method::GET, &path, &limits).await;
        assert_eq!(answer.status, StatusCode::OK, "request {i}");
    }
    let answer = f.request(Method::GET, &path, &limits).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(answer.header("retry-after").is_some());
    assert_security_headers(&answer);
    // Another link of the same unit has its own window.
    let other = f.link_for(
        "artifact://eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        NOW,
        TTL,
    );
    let answer = f.request(Method::GET, &other.to_path(), &limits).await;
    assert_eq!(answer.status, StatusCode::OK);
}

#[tokio::test]
async fn busy_reads_answer_503_retry_after_two() {
    let f = fixture(StubReader::file("image/png", None, b"IMG"));
    let limits = LinkLimits::new(1, 1 << 30);
    let held = limits.try_read_slot().expect("one slot");
    let answer = f.request(Method::GET, &f.link().to_path(), &limits).await;
    assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(answer.header("retry-after"), Some("2"));
    drop(held);
    let answer = f.request(Method::GET, &f.link().to_path(), &limits).await;
    assert_eq!(answer.status, StatusCode::OK);
}

#[tokio::test]
async fn a_units_hourly_egress_budget_is_enforced() {
    let f = fixture(StubReader::file("image/png", None, &[7u8; 100]));
    let limits = LinkLimits::new(2, 250);
    let path = f.link().to_path();
    for _ in 0..3 {
        assert_eq!(
            f.request(Method::GET, &path, &limits).await.status,
            StatusCode::OK
        );
    }
    let answer = f.request(Method::GET, &path, &limits).await;
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    // The next hour has a fresh budget.
    let next = f
        .request_with(Method::GET, &path, &limits, None, true, NOW + 3_600)
        .await;
    assert_eq!(next.status, StatusCode::OK);
}

#[tokio::test]
async fn a_head_request_spends_no_egress() {
    let f = fixture(StubReader::file("image/png", None, &[7u8; 100]));
    let limits = LinkLimits::new(2, 150);
    let path = f.link().to_path();
    for _ in 0..5 {
        assert_eq!(
            f.request(Method::HEAD, &path, &limits).await.status,
            StatusCode::OK
        );
    }
    assert_eq!(
        f.request(Method::GET, &path, &limits).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_per_client_limit_applies_only_to_an_identified_client() {
    let f = fixture(StubReader::file("image/png", None, b"IMG"));
    let limits = LinkLimits::new(2, 1 << 30);
    let client = ClientKey::of(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));
    // 121 distinct links from one client: the client window, not the link one.
    let mut refused = 0;
    for i in 0..121u64 {
        let link = f.link_for(&format!("artifact://{i:064x}"), NOW, TTL);
        let answer = f
            .request_with(
                Method::GET,
                &link.to_path(),
                &limits,
                Some(client),
                true,
                NOW,
            )
            .await;
        if answer.status == StatusCode::TOO_MANY_REQUESTS {
            refused += 1;
        }
    }
    assert_eq!(refused, 1);
    // Without a client key nothing is counted per client.
    let limits = LinkLimits::new(2, 1 << 30);
    for i in 0..121u64 {
        let link = f.link_for(&format!("artifact://{i:064x}"), NOW, TTL);
        let answer = f
            .request_with(Method::GET, &link.to_path(), &limits, None, true, NOW)
            .await;
        assert_eq!(answer.status, StatusCode::OK);
    }
}

#[tokio::test]
async fn a_hostile_name_becomes_a_safe_filename() {
    let long = "a".repeat(300);
    for (raw, ascii) in [
        ("evil\"\r\n.pdf", "evil_.pdf"),
        ("a\u{202E}fdp.exe", "afdp.exe"),
        ("back\\slash.pdf", "back_slash.pdf"),
        ("", "file"),
        ("\u{200B}\u{202E}", "file"),
    ] {
        let f = fixture(StubReader::file("application/pdf", Some(raw), b"%PDF"));
        let answer = f.request(Method::GET, &f.link().to_path(), &limits()).await;
        let disposition = answer.header("content-disposition").unwrap().to_string();
        assert!(
            disposition.starts_with(&format!("attachment; filename=\"{ascii}\"")),
            "{raw:?} -> {disposition}"
        );
        assert!(!disposition.contains('\r') && !disposition.contains('\n'));
    }
    let f = fixture(StubReader::file("application/pdf", Some(&long), b"%PDF"));
    let answer = f.request(Method::GET, &f.link().to_path(), &limits()).await;
    let disposition = answer.header("content-disposition").unwrap();
    assert!(disposition.contains(&format!("filename=\"{}\"", "a".repeat(120))));
    assert!(!disposition.contains(&"a".repeat(121)));
}

/// The hook in `revision_serve.rs` sits at the SERVE level, before the one
/// per-request activation snapshot (the file has several
/// `let activation = state.current();` lines), and the CORS rule excludes
/// link paths.
#[test]
fn the_route_is_reserved_before_deployment_resolution() {
    const SERVE: &str = include_str!("../revision_serve.rs");
    let notify = SERVE
        .find("if path == \"/v1/updates/notify\" {")
        .expect("notify block");
    let hook = SERVE
        .find("crate::artifacts::serve_link::is_link_path(&path)")
        .expect("hook");
    let snapshot = SERVE
        .find("// Snapshot the activation ONCE per request so dispatch and execute see a")
        .expect("serve-level snapshot comment");
    assert!(notify < hook && hook < snapshot);
    assert_eq!(
        SERVE
            .matches("crate::artifacts::serve_link::handle(")
            .count(),
        1
    );
    assert!(SERVE.contains("&& !crate::artifacts::serve_link::is_link_path(path)\n"));
}

/// The kill switch is read by the route itself, never left to a caller.
#[test]
fn the_route_reads_the_kill_switch() {
    const ROUTE: &str = include_str!("serve_link.rs");
    let handle = ROUTE.find("pub(crate) async fn handle").expect("handle");
    assert!(ROUTE[handle..].contains("links_on: link::links_enabled(),"));
}
