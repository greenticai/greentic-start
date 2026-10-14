//! The provider handling a Direct Line `/upload` parses the multipart body
//! itself: it must receive the RAW bytes (base64 in `HttpInV1`) and the
//! request's `Content-Type` unchanged, since the boundary lives there.

use base64::Engine as _;

use super::build_provider_http_in;

#[test]
fn an_upload_reaches_the_provider_byte_for_byte_with_its_boundary() {
    let mut body = b"--XyZ\r\nContent-Type: image/png\r\n\r\n".to_vec();
    body.extend_from_slice(&[0x89, b'P', b'N', b'G', 0, 0xff, 0xfe, 0x0d, 0x0a]);
    body.extend_from_slice(b"\r\n--XyZ--\r\n");
    let content_type = "multipart/form-data; boundary=XyZ";
    let headers = vec![("content-type".to_string(), content_type.to_string())];
    let http_in = build_provider_http_in(
        "messaging.webchat-gui",
        "acme",
        "POST",
        "/v3/directline/conversations/c1/upload",
        &[],
        &headers,
        &body,
        None,
    );
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&http_in.body_b64)
        .expect("base64");
    assert_eq!(decoded, body);
    assert!(
        http_in
            .headers
            .iter()
            .any(|(name, value)| name == "content-type" && value == content_type)
    );
}
