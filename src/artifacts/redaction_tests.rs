//! Nothing sensitive reaches an error string that a caller may log.
//!
//! The 401 and host-policy cases are covered in `fetcher_tests`,
//! `store_tests` and `ingest_tests`. This file adds the Telegram cases, where
//! the bot token is part of the URL PATH (`/bot<token>/getFile`,
//! `/file/bot<token>/...`) and so is the one place a careless `{err}` would
//! leak it, and the inbound envelope parser, whose failure used to print the
//! whole envelope (inline file bytes and access URLs included).

use serde_json::json;

use crate::interop::metering::testkit::{StubAdmin, closed_port};

use super::fetch::{FetchError, Fetcher, HttpFetcher};
use super::fetch_ref::FetchRef;
use super::fetcher_tests::{OK, Secrets, loopback};
use super::ingest_testkit::origin_of;

const TOKEN: &str = "123:SECRETTOKEN";

fn fetcher_against(base: String) -> HttpFetcher {
    loopback(Secrets::new(Some(TOKEN))).with_telegram_api(base)
}

fn reference() -> FetchRef {
    FetchRef::TelegramFile {
        file_id: "AgACAgIAAxkBAAI".to_string(),
    }
}

fn assert_no_token(err: &FetchError) {
    let text = format!("{err:?}{err}");
    assert!(!text.contains("SECRETTOKEN"), "{text}");
    assert!(
        !text.contains("/bot"),
        "the token-bearing path must not be echoed: {text}"
    );
}

#[tokio::test]
async fn a_failing_telegram_getfile_never_prints_the_bot_token() {
    let stub = StubAdmin::answering("HTTP/1.1 500 Internal Server Error", "", "boom").await;
    let base = stub.url.trim_end_matches("/ingest").to_string();
    let r = reference();
    let err = fetcher_against(base)
        .fetch(&origin_of(&r), &r)
        .await
        .unwrap_err();
    assert_no_token(&err);
    // The stub did see the token (it is the URL Telegram requires); the point
    // is that it stops there.
    assert!(stub.received().join("\n").contains("SECRETTOKEN"));
}

#[tokio::test]
async fn a_failing_telegram_download_never_prints_the_bot_token() {
    let api = StubAdmin::answering_in_turn(&[
        (
            OK,
            "",
            r#"{"ok":true,"result":{"file_path":"photos/file_1.jpg"}}"#,
        ),
        ("HTTP/1.1 500 Internal Server Error", "", "boom"),
    ])
    .await;
    let r = reference();
    let err = fetcher_against(api.url.trim_end_matches("/ingest").to_string())
        .fetch(&origin_of(&r), &r)
        .await
        .unwrap_err();
    assert_no_token(&err);
    assert_eq!(api.count(), 2, "both the lookup and the download were made");
}

#[tokio::test]
async fn a_refused_connection_to_telegram_never_prints_the_bot_token() {
    let closed = closed_port().await;
    let port = closed.port;
    let r = reference();
    let err = fetcher_against(format!("http://127.0.0.1:{port}"))
        .fetch(&origin_of(&r), &r)
        .await
        .unwrap_err();
    let text = format!("{err:?}{err}");
    assert!(matches!(err, FetchError::Transport(_)), "{text}");
    assert_no_token(&err);
    assert!(
        !text.contains("127.0.0.1"),
        "the URL is stripped from transport errors: {text}"
    );
}

/// An envelope the host cannot parse is skipped with a warning. That warning
/// used to print the whole entry: inline file bytes, fetch URLs, message text.
/// It now names the index and the kind of error, never a value: a serde
/// message itself quotes the offending value (`invalid type: string "..."`).
#[test]
fn an_unparseable_envelope_is_reported_without_its_contents() {
    let entry = json!({
        "id": "msg-1",
        "from": "SECRET-FROM-VALUE",
        "attachments": [{"content": "U0VDUkVULUJZVEVT", "url": "https://x/SECRET-URL"}]
    });
    let err = serde_json::from_value::<greentic_types::ChannelMessageEnvelope>(entry)
        .expect_err("`from` is not an actor");
    assert!(
        err.to_string().contains("SECRET-FROM-VALUE"),
        "the serde message quotes the value, which is why it is not logged: {err}"
    );
    let line = crate::ingress_dispatch::envelope_parse_failure(3, &err);
    for secret in ["SECRET-FROM-VALUE", "U0VDUkVULUJZVEVT", "SECRET-URL"] {
        assert!(!line.contains(secret), "{line}");
    }
    assert!(line.contains("envelope 3"), "{line}");
    assert!(line.contains("data"), "the error category is named: {line}");
}
