use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, StatusCode};

use super::limits::*;

const MIB: usize = 1024 * 1024;
/// The linear memory a messaging provider's guest needs for one upload: the
/// 15 MiB multipart body is held, parsed and base64-encoded inside it.
const PROVIDER_GUEST_MEMORY_FLOOR_BYTES: u64 = 160 * 1024 * 1024;
const UPLOAD: &str = "/v1/messaging/webchat/acme/v3/directline/conversations/c1/upload";
const ACTIVITIES: &str = "/v1/messaging/webchat/acme/v3/directline/conversations/c1/activities";

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(93, 184, 216, last))
}

fn post(path: &str, body: Vec<u8>, peer: IpAddr) -> Request<Full<Bytes>> {
    let mut req = Request::post(path)
        .header("content-type", "multipart/form-data; boundary=XyZ")
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    req.extensions_mut().insert(PeerIp(peer));
    req
}

fn status(result: Result<IngressBody, hyper::Response<Full<Bytes>>>) -> StatusCode {
    match result {
        Ok(_) => StatusCode::OK,
        Err(response) => response.status(),
    }
}

#[test]
fn only_a_direct_line_upload_gets_the_large_cap() {
    assert_eq!(body_kind("POST", UPLOAD), BodyKind::Upload);
    for (method, path) in [
        ("POST", ACTIVITIES),
        ("GET", UPLOAD),
        ("POST", "/hooks/upload"),
        ("POST", "/v1/messaging/slack/acme/webhook/slack"),
    ] {
        assert_eq!(body_kind(method, path), BodyKind::Other, "{method} {path}");
    }
}

#[tokio::test]
async fn an_upload_over_16_mib_is_413_and_one_at_the_cap_is_read() {
    let limiter = UploadLimiter::new(100, 4);
    let over = post(UPLOAD, vec![b'a'; 16 * MIB + 1], ip(1));
    assert_eq!(
        status(read_ingress_body_with(&limiter, over, UPLOAD).await),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let at = post(UPLOAD, vec![b'a'; 16 * MIB], ip(2));
    let body = read_ingress_body_with(&limiter, at, UPLOAD)
        .await
        .expect("at the cap");
    assert_eq!(body.bytes.len(), 16 * MIB);
}

#[tokio::test]
async fn a_declared_length_over_the_cap_is_refused_before_reading() {
    let limiter = UploadLimiter::new(100, 4);
    let mut req = post(UPLOAD, b"tiny".to_vec(), ip(1));
    req.headers_mut()
        .insert("content-length", (17 * MIB).to_string().parse().unwrap());
    assert_eq!(
        status(read_ingress_body_with(&limiter, req, UPLOAD).await),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn any_other_route_keeps_the_1_mib_cap() {
    let limiter = UploadLimiter::new(100, 4);
    let req = post(ACTIVITIES, vec![b'a'; MIB + 1], ip(1));
    assert_eq!(
        status(read_ingress_body_with(&limiter, req, ACTIVITIES).await),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn the_eleventh_upload_in_a_minute_from_one_client_is_429() {
    let limiter = UploadLimiter::new(UPLOADS_PER_MINUTE, 64);
    for n in 0..UPLOADS_PER_MINUTE {
        let req = post(UPLOAD, b"x".to_vec(), ip(7));
        assert_eq!(
            status(read_ingress_body_with(&limiter, req, UPLOAD).await),
            StatusCode::OK,
            "upload {n}"
        );
    }
    let req = post(UPLOAD, b"x".to_vec(), ip(7));
    assert_eq!(
        status(read_ingress_body_with(&limiter, req, UPLOAD).await),
        StatusCode::TOO_MANY_REQUESTS
    );
    // Another client is not affected, and other routes are not counted.
    let req = post(UPLOAD, b"x".to_vec(), ip(8));
    assert_eq!(
        status(read_ingress_body_with(&limiter, req, UPLOAD).await),
        StatusCode::OK
    );
    let req = post(ACTIVITIES, b"x".to_vec(), ip(7));
    assert_eq!(
        status(read_ingress_body_with(&limiter, req, ACTIVITIES).await),
        StatusCode::OK
    );
}

#[test]
fn the_window_slides() {
    let limiter = UploadLimiter::new(2, 64);
    let t0 = Instant::now();
    assert!(limiter.admit(Some(ip(1)), t0).is_ok());
    assert!(limiter.admit(Some(ip(1)), t0).is_ok());
    assert!(matches!(
        limiter.admit(Some(ip(1)), t0),
        Err(Refusal::TooMany)
    ));
    assert!(
        limiter
            .admit(Some(ip(1)), t0 + Duration::from_secs(61))
            .is_ok()
    );
}

#[test]
fn concurrent_uploads_above_the_bound_are_503_never_queued() {
    let limiter = UploadLimiter::new(100, 2);
    let now = Instant::now();
    let a = limiter.admit(Some(ip(1)), now).expect("first");
    let _b = limiter.admit(Some(ip(2)), now).expect("second");
    assert!(matches!(
        limiter.admit(Some(ip(3)), now),
        Err(Refusal::Busy)
    ));
    drop(a);
    assert!(
        limiter.admit(Some(ip(3)), now).is_ok(),
        "a released slot is reused"
    );
}

#[tokio::test]
async fn the_raw_body_is_kept_byte_for_byte() {
    // The multipart boundary lives in Content-Type; a binary part must reach
    // the provider unchanged.
    let mut body = b"--XyZ\r\nContent-Type: image/png\r\n\r\n".to_vec();
    body.extend_from_slice(&[0x89, b'P', b'N', b'G', 0, 0xff, 0xfe, 0x00, 0x0d, 0x0a]);
    body.extend_from_slice(b"\r\n--XyZ--\r\n");
    let limiter = UploadLimiter::new(100, 4);
    let req = post(UPLOAD, body.clone(), ip(1));
    let read = read_ingress_body_with(&limiter, req, UPLOAD)
        .await
        .expect("read");
    assert_eq!(read.bytes.as_ref(), body.as_slice());
}

#[test]
fn behind_a_proxy_the_client_is_the_entry_the_proxy_appended() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        "198.51.100.9, 93.184.216.50".parse().unwrap(),
    );
    let proxy = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    assert_eq!(client_key(Some(proxy), &headers), Some(ip(50)));
    // A public peer is the client itself; a header it sent is not trusted.
    assert_eq!(client_key(Some(ip(1)), &headers), Some(ip(1)));
}

#[test]
fn no_guest_memory_cap_below_the_upload_floor() {
    // A wasm memory limit set anywhere in this crate must be reviewed against
    // the floor below; today there is none.
    let _floor = PROVIDER_GUEST_MEMORY_FLOOR_BYTES;
    let mut offenders = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("src") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs")
                && !path.ends_with("http_ingress/limits_tests.rs")
            {
                let text = std::fs::read_to_string(&path).expect("read");
                for needle in ["StoreLimitsBuilder", ".memory_size(", "ResourceLimiter"] {
                    if text.contains(needle) {
                        offenders.push(format!("{}: {needle}", path.display()));
                    }
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "review against the upload floor: {offenders:?}"
    );
}
