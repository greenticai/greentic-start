//! G21: which hosts may receive a channel credential, and which hosts a
//! credential's own host may redirect to without it.

use reqwest::Url;

use super::host_policy::*;

fn url(s: &str) -> Url {
    Url::parse(s).unwrap()
}

fn prod() -> HostPolicy {
    HostPolicy::from_value(None)
}

const WEBEX: Option<&str> = Some("WEBEX_BOT_TOKEN");

#[test]
fn webex_token_may_go_to_the_legacy_api_host_exactly() {
    assert!(
        prod()
            .check(&url("https://api.ciscospark.com/v1/contents/abc"), WEBEX)
            .is_ok()
    );
    assert!(
        prod()
            .check(&url("https://webexapis.com/v1/contents/abc"), WEBEX)
            .is_ok()
    );
}

#[test]
fn webex_token_never_goes_to_a_lookalike() {
    for u in [
        "https://api.ciscospark.com.evil.example/v1/contents/a",
        "https://x.api.ciscospark.com/v1/contents/a",
        "https://ciscospark.com/v1/contents/a",
        "https://evilapi.ciscospark.com/v1/contents/a",
        "https://api.ciscospark.com:8443/v1/contents/a",
        "https://user@api.ciscospark.com/v1/contents/a",
    ] {
        assert!(prod().check(&url(u), WEBEX).is_err(), "{u}");
    }
    // Another channel's credential never reaches it.
    assert_eq!(
        prod().check(
            &url("https://api.ciscospark.com/v1/contents/a"),
            Some("SLACK_BOT_TOKEN")
        ),
        Err(Blocked::HostNotAllowed)
    );
}

/// A token is only ever sent to EXACT vendor names. WhatsApp's media CDNs
/// are the one pre-existing exception (Meta serves media from
/// `scontent.xx.fbcdn.net`-style names that cannot be listed exactly).
#[test]
fn only_the_whatsapp_token_carries_a_wildcard() {
    for (credential, hosts) in credential_host_table() {
        if *credential == "WHATSAPP_TOKEN" {
            continue;
        }
        assert!(
            hosts.iter().all(|h| !h.contains('*')),
            "{credential} gained a wildcard: {hosts:?}"
        );
    }
}
