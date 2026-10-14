use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::body::{Body, Frame};
use hyper::{HeaderMap, Request, StatusCode};

use crate::artifacts::time_testkit::within_ceiling;

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
    assert!(limiter.admit(key(ip(1)), t0).is_ok());
    assert!(limiter.admit(key(ip(1)), t0).is_ok());
    assert!(matches!(
        limiter.admit(key(ip(1)), t0),
        Err(Refusal::TooMany)
    ));
    assert!(
        limiter
            .admit(key(ip(1)), t0 + Duration::from_secs(61))
            .is_ok()
    );
}

#[test]
fn concurrent_uploads_above_the_bound_are_503_never_queued() {
    let limiter = UploadLimiter::new(100, 2);
    let now = Instant::now();
    let a = limiter.admit(key(ip(1)), now).expect("first");
    let _b = limiter.admit(key(ip(2)), now).expect("second");
    assert!(matches!(limiter.admit(key(ip(3)), now), Err(Refusal::Busy)));
    drop(a);
    assert!(
        limiter.admit(key(ip(3)), now).is_ok(),
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

fn xff(lines: &[&str]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for line in lines {
        headers.append("x-forwarded-for", line.parse().unwrap());
    }
    headers
}

fn key(ip: IpAddr) -> Option<ClientKey> {
    Some(ClientKey::of(ip))
}

#[test]
fn by_default_a_forwarded_header_is_never_trusted() {
    let proxy = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let spoofed = xff(&["93.184.216.50"]);
    assert_eq!(client_key(Some(proxy), &spoofed, 0), key(proxy));
    assert_eq!(client_key(Some(ip(1)), &spoofed, 0), key(ip(1)));
    assert_eq!(client_key(None, &spoofed, 0), None);
}

#[test]
fn trusted_hops_count_from_the_right_across_every_header_line() {
    let proxy = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    // A client spoofs the leftmost entries; each trusted proxy appends one.
    let headers = xff(&["1.1.1.1, 2.2.2.2", "93.184.216.50", "93.184.216.60"]);
    assert_eq!(client_key(Some(proxy), &headers, 1), key(ip(60)));
    assert_eq!(client_key(Some(proxy), &headers, 2), key(ip(50)));
    // Fewer entries than trusted hops: nothing the header says can be
    // trusted, so the peer is the client.
    assert_eq!(
        client_key(Some(proxy), &xff(&["93.184.216.50"]), 2),
        key(proxy)
    );
    // An unparsable entry is not a client either.
    assert_eq!(client_key(Some(proxy), &xff(&["garbage"]), 1), key(proxy));
}

#[test]
fn ipv6_clients_are_counted_per_64() {
    let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 1));
    let b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0xffff, 1, 2, 3));
    let other = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1));
    assert_eq!(ClientKey::of(a), ClientKey::of(b));
    assert_ne!(ClientKey::of(a), ClientKey::of(other));
    let limiter = UploadLimiter::new(2, 64);
    let now = Instant::now();
    let _x = limiter.admit(key(a), now).expect("first");
    drop(_x);
    let _y = limiter.admit(key(b), now).expect("second, same /64");
    drop(_y);
    assert!(matches!(limiter.admit(key(b), now), Err(Refusal::TooMany)));
}

#[test]
fn the_client_map_never_grows_past_its_cap_and_forgets_the_oldest() {
    let limiter = UploadLimiter::with_max_clients(10, 64, 3);
    let t0 = Instant::now();
    for (n, last) in [1u8, 2, 3].into_iter().enumerate() {
        drop(limiter.admit(key(ip(last)), t0 + Duration::from_millis(n as u64)));
    }
    drop(limiter.admit(key(ip(4)), t0 + Duration::from_millis(10)));
    assert_eq!(limiter.tracked_clients(), 3);
    assert!(
        !limiter.tracks(key(ip(1)).unwrap()),
        "the oldest was forgotten"
    );
    assert!(limiter.tracks(key(ip(4)).unwrap()));
}

#[test]
fn one_client_holds_at_most_one_upload_slot() {
    let limiter = UploadLimiter::new(100, 8);
    let now = Instant::now();
    let held = limiter.admit(key(ip(1)), now).expect("first");
    assert!(matches!(
        limiter.admit(key(ip(1)), now),
        Err(Refusal::ClientBusy)
    ));
    assert!(
        limiter.admit(key(ip(2)), now).is_ok(),
        "other clients unaffected"
    );
    drop(held);
    assert!(
        limiter.admit(key(ip(1)), now).is_ok(),
        "released with the slot"
    );
}

/// A body that never sends another byte (slowloris).
struct Stalled;

impl Body for Stalled {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        Poll::Pending
    }
}

/// A body whose client went away mid-transfer.
struct Broken;

impl Body for Broken {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        Poll::Ready(Some(Err(std::io::Error::other("connection reset"))))
    }
}

fn upload_with<B>(body: B) -> Request<B> {
    let mut req = Request::post(UPLOAD).body(body).unwrap();
    req.extensions_mut().insert(PeerIp(ip(1)));
    req
}

#[tokio::test]
async fn a_stalled_upload_body_is_408_and_frees_its_slot() {
    let limiter = UploadLimiter::new(100, 4).with_read_deadline(Duration::from_millis(200));
    let got = within_ceiling(read_ingress_body_with(
        &limiter,
        upload_with(Stalled),
        UPLOAD,
    ))
    .await;
    assert_eq!(
        got.err().map(|r| r.status()),
        Some(StatusCode::REQUEST_TIMEOUT)
    );
    assert!(
        limiter.admit(key(ip(1)), Instant::now()).is_ok(),
        "the slot was released"
    );
}

#[tokio::test]
async fn a_broken_body_is_400_not_413() {
    let limiter = UploadLimiter::new(100, 4);
    let got = within_ceiling(read_ingress_body_with(
        &limiter,
        upload_with(Broken),
        UPLOAD,
    ))
    .await;
    assert_eq!(got.err().map(|r| r.status()), Some(StatusCode::BAD_REQUEST));
    let other = within_ceiling(read_ingress_body_with(
        &limiter,
        Request::post(ACTIVITIES).body(Broken).unwrap(),
        ACTIVITIES,
    ))
    .await;
    assert_eq!(
        other.err().map(|r| r.status()),
        Some(StatusCode::BAD_REQUEST)
    );
}

#[test]
fn the_production_read_deadline_is_thirty_seconds() {
    assert_eq!(UPLOAD_READ_DEADLINE, Duration::from_secs(30));
}

/// Through the real read path, with no operator configuration: a client
/// behind the load balancer cannot dodge the per-client limit by writing a
/// different `X-Forwarded-For` on each upload.
#[tokio::test]
async fn a_spoofed_forwarded_header_does_not_reset_the_limit() {
    assert!(
        std::env::var("GREENTIC_TRUSTED_PROXY_HOPS").is_err(),
        "this test asserts the default"
    );
    let limiter = UploadLimiter::new(UPLOADS_PER_MINUTE, 64);
    let balancer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    for n in 0..=UPLOADS_PER_MINUTE {
        let mut req = post(UPLOAD, b"x".to_vec(), balancer);
        req.headers_mut()
            .insert("x-forwarded-for", format!("203.0.113.{n}").parse().unwrap());
        let got = status(read_ingress_body_with(&limiter, req, UPLOAD).await);
        let want = if n < UPLOADS_PER_MINUTE {
            StatusCode::OK
        } else {
            StatusCode::TOO_MANY_REQUESTS
        };
        assert_eq!(got, want, "upload {n}");
    }
}
