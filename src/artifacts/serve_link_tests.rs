//! The signed-link route (docs/outbound-artifacts.md): the serving rule's
//! headers, ONE 404 for every refusal about which file or which unit, and the
//! door's failures mapped to fixed answers.

use std::sync::Arc;

use greentic_aw_runtime::ArtifactError;
use greentic_deploy_spec::ids::DeploymentId;
use hyper::{Method, StatusCode};

use super::link::{LinkKey, LinkPath};
use super::link_table::{ArtifactLinkTable, LinkUnit};
use super::recent_puts::RecentPuts;
use super::serve_link::{LinkRequest, is_link_path, serve_link};
use super::serve_link_testkit::*;
use super::unit::{Off, UnitAttachments, UnitCell};

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
    // The TTL ceiling is the CURRENT configured TTL, never a constant.
    assert!(ROUTE[handle..].contains("ttl_max: link::ttl_secs(),"));
}

/// A refused token is warned once per unit, not once per process, and the
/// set of units remembered is bounded.
#[test]
fn a_misconfigured_unit_is_warned_once_and_the_memory_is_bounded() {
    use super::serve_link::OncePerKey;
    let once = OncePerKey::new(2);
    assert!(once.first("unit-a"));
    assert!(!once.first("unit-a"));
    assert!(once.first("unit-b"));
    assert!(!once.first("unit-b"));
    // Full: a third unit is not remembered (and not warned again and again).
    assert!(!once.first("unit-c"));
    assert!(!once.first("unit-a"));
    // The route keys it on the unit's deployment.
    const ROUTE: &str = include_str!("serve_link.rs");
    let warn = ROUTE.find("fn misconfigured(").expect("misconfigured");
    assert!(ROUTE[warn..].contains("if warned.first(deployment) {"));
}
