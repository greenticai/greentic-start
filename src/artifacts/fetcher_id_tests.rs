//! The id-based kinds: WhatsApp media and Telegram files, looked up through
//! the platform API before the download.

use crate::interop::metering::testkit::StubAdmin;

use super::fetch::*;
use super::fetch_ref::FetchRef;
use super::fetcher_tests::{OK, Secrets, header_lines, loopback};
use super::ingest_testkit::origin_of;

#[tokio::test]
async fn the_whatsapp_media_url_is_checked_before_the_bearer_is_sent() {
    for hostile in [
        "https://evil.example/media",
        "https://169.254.169.254/latest/meta-data",
        "http://lookaside.fbsbx.com/x",
    ] {
        let graph = StubAdmin::answering(OK, "", &format!(r#"{{"url":"{hostile}"}}"#)).await;
        let r = FetchRef::WhatsappMedia {
            media_id: "123".into(),
        };
        let err = loopback(Secrets::new(Some("WA-SECRET")))
            .with_whatsapp_graph(graph.url.clone())
            .fetch(&origin_of(&r), &r)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::BlockedHost), "{hostile}: {err:?}");
        assert_eq!(
            graph.count(),
            1,
            "{hostile}: only the Graph lookup may happen"
        );
        assert!(!format!("{err:?}{err}").contains("WA-SECRET"));
    }
}

#[tokio::test]
async fn whatsapp_media_is_looked_up_then_downloaded_with_the_token() {
    let media = StubAdmin::answering(OK, "", "IMG").await;
    let graph = StubAdmin::answering(OK, "", &format!(r#"{{"url":"{}"}}"#, media.url)).await;
    let r = FetchRef::WhatsappMedia {
        media_id: "123".into(),
    };
    let got = loopback(Secrets::new(Some("WA-SECRET")))
        .with_whatsapp_graph(graph.url.clone())
        .fetch(&origin_of(&r), &r)
        .await
        .unwrap();
    assert_eq!(got.bytes, b"IMG");
    let lookup = &graph.received()[0];
    assert!(lookup.starts_with("GET /ingest/123 HTTP/1.1"), "{lookup}");
    assert!(header_lines(lookup).contains("authorization: bearer wa-secret"));
    assert!(header_lines(&media.received()[0]).contains("authorization: bearer wa-secret"));
}

// --- Telegram -----------------------------------------------------------------

#[tokio::test]
async fn telegram_files_are_looked_up_then_downloaded() {
    let api = StubAdmin::answering_in_turn(&[
        (
            OK,
            "",
            r#"{"ok":true,"result":{"file_path":"photos/file_1.jpg"}}"#,
        ),
        (OK, "", "JPEG"),
    ])
    .await;
    let base = api.url.trim_end_matches("/ingest").to_string();
    let r = FetchRef::TelegramFile {
        file_id: "AgAD-1".into(),
    };
    let got = loopback(Secrets::new(Some("123:ABC")))
        .with_telegram_api(base)
        .fetch(&origin_of(&r), &r)
        .await
        .unwrap();
    assert_eq!(got.bytes, b"JPEG");
    let raw = api.received();
    assert!(
        raw[0].starts_with("GET /bot123:ABC/getFile?file_id=AgAD-1 HTTP/1.1"),
        "{}",
        raw[0]
    );
    assert!(
        raw[1].starts_with("GET /file/bot123:ABC/photos/file_1.jpg HTTP/1.1"),
        "{}",
        raw[1]
    );
    assert!(!header_lines(&raw[0]).contains("authorization"));
}

#[tokio::test]
async fn a_telegram_download_follows_no_redirect() {
    let elsewhere = StubAdmin::answering(OK, "", "X").await;
    let api = StubAdmin::answering_in_turn(&[
        (
            OK,
            "",
            r#"{"ok":true,"result":{"file_path":"photos/a.jpg"}}"#,
        ),
        (
            "HTTP/1.1 302 Found",
            &format!("Location: {}\r\n", elsewhere.url),
            "",
        ),
    ])
    .await;
    let r = FetchRef::TelegramFile {
        file_id: "AgAD".into(),
    };
    let err = loopback(Secrets::new(Some("123:ABC")))
        .with_telegram_api(api.url.trim_end_matches("/ingest").to_string())
        .fetch(&origin_of(&r), &r)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::BlockedHost), "{err:?}");
    assert_eq!(elsewhere.count(), 0, "the token in the path was replayed");
    assert!(!format!("{err:?}{err}").contains("123:ABC"));
}

#[tokio::test]
async fn a_telegram_path_that_could_escape_is_refused() {
    let api = StubAdmin::answering(OK, "", r#"{"ok":true,"result":{"file_path":"../x"}}"#).await;
    let r = FetchRef::TelegramFile {
        file_id: "AgAD".into(),
    };
    let err = loopback(Secrets::new(Some("123:ABC")))
        .with_telegram_api(api.url.trim_end_matches("/ingest").to_string())
        .fetch(&origin_of(&r), &r)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::BadReference), "{err:?}");
    assert_eq!(api.count(), 1);
}

#[tokio::test]
async fn a_telegram_token_that_would_reshape_the_url_is_not_used() {
    let api = StubAdmin::answering(OK, "", "{}").await;
    let r = FetchRef::TelegramFile {
        file_id: "AgAD".into(),
    };
    let err = loopback(Secrets::new(Some("123/../evil?x=")))
        .with_telegram_api(api.url.trim_end_matches("/ingest").to_string())
        .fetch(&origin_of(&r), &r)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::MissingCredential), "{err:?}");
    assert_eq!(api.count(), 0);
}

#[test]
fn telegram_file_paths_cannot_escape_or_inject() {
    assert!(valid_telegram_path("photos/file_1.jpg"));
    for bad in [
        "../x", "a/../b", "/abs", "a?x=1", "a#b", "a\\b", "", "a b", "a//b",
    ] {
        assert!(!valid_telegram_path(bad), "{bad:?}");
    }
}
