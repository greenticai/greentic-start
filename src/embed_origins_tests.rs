use super::*;
use hyper::StatusCode;
use serde_json::json;

fn html(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .header(X_FRAME_OPTIONS, "SAMEORIGIN")
        .body(Full::from(Bytes::from_static(b"<html></html>")))
        .expect("response")
}

#[test]
fn absent_or_blank_answer_means_not_configured() {
    assert_eq!(parse_answer(&json!(null)), None);
    assert_eq!(parse_answer(&json!("")), None);
    assert_eq!(parse_answer(&json!("  , \n ")), None);
    assert_eq!(parse_answer(&json!([])), None);
    assert_eq!(parse_answer(&json!(42)), None);
}

#[test]
fn valid_origins_are_normalised_and_deduplicated() {
    let parsed = parse_answer(&json!(
        "https://Intranet.Example.com, https://intranet.example.com https://app.example.com:8443"
    ))
    .expect("configured");
    assert_eq!(
        parsed.origins,
        vec![
            "https://intranet.example.com",
            "https://app.example.com:8443"
        ]
    );
    assert_eq!(
        parsed.csp_value(),
        "frame-ancestors 'self' https://intranet.example.com https://app.example.com:8443"
    );
}

#[test]
fn array_form_is_accepted() {
    let parsed = parse_answer(&json!(["https://a.example.com", " http://localhost:3000 "]))
        .expect("configured");
    assert_eq!(
        parsed.origins,
        vec!["https://a.example.com", "http://localhost:3000"]
    );
}

#[test]
fn invalid_origins_are_rejected() {
    for bad in [
        "*",
        "https://*.example.com",
        "https://example.com/",
        "https://example.com/path",
        "https://example.com?x=1",
        "https://user@example.com",
        "http://example.com",
        "ftp://example.com",
        "example.com",
        "https://",
        "https://exa mple.com",
        "https://example.com:0",
        "https://example.com:99999",
        "https://example.com:80a",
        "https://127.0.0.1",
        "https://[::1]",
        "https://-bad.example.com",
        "https://example..com",
        "https://example.com;script-src *",
        "https://example.com'",
    ] {
        assert_eq!(normalise_origin(bad), None, "{bad} must be rejected");
    }
}

#[test]
fn http_is_allowed_only_for_localhost() {
    assert_eq!(
        normalise_origin("http://localhost"),
        Some("http://localhost".to_string())
    );
    assert_eq!(normalise_origin("http://intranet.example.com"), None);
}

#[test]
fn configured_but_all_invalid_fails_closed_to_self() {
    let parsed = parse_answer(&json!("*, http://evil.example.com")).expect("configured");
    assert!(parsed.origins.is_empty());
    assert_eq!(parsed.csp_value(), "frame-ancestors 'self'");
}

#[test]
fn apply_sets_csp_and_drops_x_frame_options_on_html() {
    let allowed = parse_answer(&json!("https://a.example.com")).expect("configured");
    let response = apply(html(StatusCode::OK), &allowed);
    assert_eq!(
        response.headers()[CONTENT_SECURITY_POLICY],
        "frame-ancestors 'self' https://a.example.com"
    );
    assert!(response.headers().get(X_FRAME_OPTIONS).is_none());
}

#[test]
fn apply_leaves_non_html_and_errors_alone() {
    let allowed = parse_answer(&json!("https://a.example.com")).expect("configured");
    let js = Response::builder()
        .header(CONTENT_TYPE, "application/javascript")
        .body(Full::from(Bytes::new()))
        .expect("response");
    assert!(
        apply(js, &allowed)
            .headers()
            .get(CONTENT_SECURITY_POLICY)
            .is_none()
    );
    let missing = apply(html(StatusCode::NOT_FOUND), &allowed);
    assert!(missing.headers().get(CONTENT_SECURITY_POLICY).is_none());
}

#[test]
fn read_for_pack_reads_setup_answers_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let answers = dir.path().join("state/config/webchat-pack");
    std::fs::create_dir_all(&answers).expect("mkdir");
    std::fs::write(
        answers.join("setup-answers.json"),
        r#"{"allowed_embed_origins":"https://a.example.com"}"#,
    )
    .expect("write");
    let parsed = read_for_pack(dir.path(), "webchat-pack").expect("configured");
    assert_eq!(parsed.origins, vec!["https://a.example.com"]);
    assert_eq!(read_for_pack(dir.path(), "other-pack"), None);
}
