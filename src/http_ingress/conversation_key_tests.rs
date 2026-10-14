//! S8: when the client address is unknowable (a private peer and no trusted
//! hop), uploads are limited per Direct Line conversation instead of every
//! user sharing the proxy's one bucket.

use std::net::{IpAddr, Ipv4Addr};

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{HeaderMap, Request, StatusCode};

use super::client_key::{ClientKey, conversation_id, upload_client_key};
use super::limits::{IngressBody, PeerIp, UploadLimiter, read_ingress_body_with};

fn upload_path(conversation: &str) -> String {
    format!("/v1/messaging/webchat/acme/v3/directline/conversations/{conversation}/upload")
}

fn private_peer() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4))
}

fn public_peer() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
}

fn headers(token: Option<&str>) -> HeaderMap {
    let mut h = HeaderMap::new();
    if let Some(token) = token {
        h.insert("authorization", format!("Bearer {token}").parse().unwrap());
    }
    h
}

fn post(path: &str, peer: IpAddr, token: Option<&str>) -> Request<Full<Bytes>> {
    let mut builder = Request::post(path).header("content-type", "multipart/form-data; boundary=X");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let mut req = builder.body(Full::new(Bytes::from_static(b"x"))).unwrap();
    req.extensions_mut().insert(PeerIp(peer));
    req
}

fn status(result: &Result<IngressBody, hyper::Response<Full<Bytes>>>) -> StatusCode {
    match result {
        Ok(_) => StatusCode::OK,
        Err(response) => response.status(),
    }
}

#[test]
fn the_parser_takes_exactly_the_conversation_segment() {
    assert_eq!(conversation_id(&upload_path("c1")), Some("c1"));
    assert_eq!(
        conversation_id(&format!("{}/", upload_path("c1"))),
        Some("c1")
    );
    assert_eq!(conversation_id(&upload_path("a-b_C.9")), Some("a-b_C.9"));
    assert_eq!(
        conversation_id(&upload_path(&"x".repeat(256))).map(str::len),
        Some(256)
    );
    assert_eq!(
        conversation_id(&upload_path(&"x".repeat(257))),
        None,
        "too long"
    );
    assert_eq!(conversation_id(&upload_path("")), None);
    assert_eq!(
        conversation_id("/v3/directline/conversations/c1/activities"),
        None
    );
    assert_eq!(conversation_id("/hooks/conversations/c1/upload"), None);
}

#[test]
fn a_private_peer_without_trusted_hops_keys_by_conversation() {
    let a = upload_client_key(Some(private_peer()), &headers(None), 0, &upload_path("a"));
    let b = upload_client_key(Some(private_peer()), &headers(None), 0, &upload_path("b"));
    let a_again = upload_client_key(Some(private_peer()), &headers(None), 0, &upload_path("a"));
    assert_ne!(a, b);
    assert_eq!(a, a_again);
    assert_ne!(a, Some(ClientKey::of(private_peer())));
}

#[test]
fn a_public_peer_still_keys_by_address() {
    for conversation in ["a", "b"] {
        assert_eq!(
            upload_client_key(
                Some(public_peer()),
                &headers(None),
                0,
                &upload_path(conversation)
            ),
            Some(ClientKey::of(public_peer()))
        );
    }
}

#[test]
fn a_usable_forwarded_entry_still_keys_by_address() {
    let mut h = headers(None);
    h.insert("x-forwarded-for", "198.51.100.7".parse().unwrap());
    let client = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    assert_eq!(
        upload_client_key(Some(private_peer()), &h, 1, &upload_path("a")),
        Some(ClientKey::of(client))
    );
    // Unusable entry, private peer: the conversation, not the proxy.
    let mut bad = headers(None);
    bad.insert("x-forwarded-for", "garbage".parse().unwrap());
    assert_ne!(
        upload_client_key(Some(private_peer()), &bad, 1, &upload_path("a")),
        Some(ClientKey::of(private_peer()))
    );
}

/// A caller who knows another user's conversation id but not their token
/// lands in a DIFFERENT bucket: it cannot use up that user's uploads.
#[test]
fn a_conversation_bucket_cannot_be_taken_without_its_token() {
    let path = upload_path("victim");
    let victim = upload_client_key(
        Some(private_peer()),
        &headers(Some("victim-token")),
        0,
        &path,
    );
    let attacker = upload_client_key(Some(private_peer()), &headers(Some("guess")), 0, &path);
    let anonymous = upload_client_key(Some(private_peer()), &headers(None), 0, &path);
    assert_ne!(victim, attacker);
    assert_ne!(victim, anonymous);
    let again = upload_client_key(
        Some(private_peer()),
        &headers(Some("victim-token")),
        0,
        &path,
    );
    assert_eq!(victim, again);
}

#[test]
fn the_key_never_prints_the_conversation_or_token() {
    let key = upload_client_key(
        Some(private_peer()),
        &headers(Some("secret-token-value")),
        0,
        &upload_path("conv-identifier"),
    )
    .unwrap();
    let printed = format!("{key:?}");
    assert!(!printed.contains("secret-token-value"), "{printed}");
    assert!(!printed.contains("conv-identifier"), "{printed}");
}

#[tokio::test]
async fn two_conversations_behind_one_private_peer_upload_in_parallel() {
    let limiter = UploadLimiter::new(100, 4);
    let (a, b) = (upload_path("a"), upload_path("b"));
    let first = read_ingress_body_with(&limiter, post(&a, private_peer(), None), &a).await;
    assert_eq!(status(&first), StatusCode::OK);
    let second = read_ingress_body_with(&limiter, post(&b, private_peer(), None), &b).await;
    assert_eq!(status(&second), StatusCode::OK, "one shared bucket");
    let same = read_ingress_body_with(&limiter, post(&a, private_peer(), None), &a).await;
    assert_eq!(
        status(&same),
        StatusCode::TOO_MANY_REQUESTS,
        "one at a time"
    );
}

#[tokio::test]
async fn the_global_cap_still_holds_across_conversations() {
    let limiter = UploadLimiter::new(100, 4);
    let mut held = Vec::new();
    for n in 0..4 {
        let path = upload_path(&format!("c{n}"));
        let got = read_ingress_body_with(&limiter, post(&path, private_peer(), None), &path).await;
        assert_eq!(status(&got), StatusCode::OK);
        held.push(got);
    }
    let path = upload_path("c4");
    let fifth = read_ingress_body_with(&limiter, post(&path, private_peer(), None), &path).await;
    assert_eq!(status(&fifth), StatusCode::SERVICE_UNAVAILABLE);
}
