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

const SLACK: Option<&str> = Some("SLACK_BOT_TOKEN");

fn with_cdn() -> HostPolicy {
    let table: &[(&str, &[&str])] = &[
        (
            "SLACK_BOT_TOKEN",
            &["*.example-cdn.test", "dl.example-files.test"],
        ),
        ("WEBEX_BOT_TOKEN", &["files.example-webex.test"]),
    ];
    prod().with_redirect_only_for_tests(table)
}

fn from_slack() -> Url {
    url("https://files.slack.com/files-pri/T1/F1/download/a.png")
}

#[test]
fn a_redirect_from_the_credentials_host_to_a_listed_host_drops_the_credential() {
    for target in [
        "https://a.example-cdn.test/f/a.png?sig=1",
        "https://dl.example-files.test/a.png",
    ] {
        let hop = with_cdn()
            .redirect(&from_slack(), target, SLACK)
            .unwrap_or_else(|e| panic!("{target}: {e:?}"));
        assert_eq!(hop.credential, None, "{target} would receive the token");
        assert_eq!(hop.url.as_str(), target);
    }
    let webex = with_cdn()
        .redirect(
            &url("https://webexapis.com/v1/contents/x"),
            "https://files.example-webex.test/x",
            Some("WEBEX_BOT_TOKEN"),
        )
        .expect("webex hop");
    assert_eq!(webex.credential, None);
}

#[test]
fn a_redirect_only_host_is_never_a_first_request() {
    let target = url("https://a.example-cdn.test/f");
    assert_eq!(
        with_cdn().check(&target, SLACK),
        Err(Blocked::HostNotAllowed)
    );
    assert_eq!(
        with_cdn().check(&target, None),
        Err(Blocked::HostNotAllowed)
    );
}

#[test]
fn a_redirect_only_host_belongs_to_its_own_credential() {
    assert!(
        with_cdn()
            .redirect(
                &url("https://webexapis.com/v1/contents/x"),
                "https://a.example-cdn.test/f",
                Some("WEBEX_BOT_TOKEN"),
            )
            .is_err(),
        "Slack's CDN reached from Webex"
    );
}

#[test]
fn a_redirect_only_wildcard_matches_exactly_one_label() {
    for target in [
        "https://a.b.example-cdn.test/f",
        "https://example-cdn.test/f",
        "https://aexample-cdn.test/f",
        "https://a.example-cdn.test.evil.example/f",
    ] {
        assert!(
            with_cdn().redirect(&from_slack(), target, SLACK).is_err(),
            "{target}"
        );
    }
}

#[test]
fn a_redirect_only_host_keeps_every_url_rule() {
    for (target, why) in [
        ("http://a.example-cdn.test/f", Blocked::NotHttps),
        ("https://u:p@a.example-cdn.test/f", Blocked::UserInfo),
        ("https://a.example-cdn.test:8443/f", Blocked::Port),
        ("https://203.0.113.9/f", Blocked::IpLiteral),
    ] {
        assert_eq!(
            with_cdn().redirect(&from_slack(), target, SLACK),
            Err(why),
            "{target}"
        );
    }
}

/// The list applies only to a hop that LEAVES the credential's own host
/// carrying it; a hop from anywhere else is an ordinary credential-less one.
#[test]
fn a_redirect_only_host_is_reached_only_from_the_credentials_host() {
    for (from, credential) in [
        ("https://a.example-cdn.test/f", None),
        ("https://a.example-cdn.test/f", SLACK),
        ("https://evil.example/f", SLACK),
    ] {
        assert!(
            with_cdn()
                .redirect(&url(from), "https://b.example-cdn.test/g", credential)
                .is_err(),
            "{from} {credential:?}"
        );
    }
}

/// Nothing is widened before a measurement lands (G21): the production
/// table names Slack and Webex with no hosts, and any entry added later must
/// be a valid pattern whose wildcard covers ONE label under a registrable
/// domain (`*.wbx2.com`, never `*.com`).
#[test]
fn the_production_redirect_only_lists_are_empty_and_well_formed() {
    let table = redirect_only_table();
    let names: Vec<&str> = table.iter().map(|(name, _)| *name).collect();
    assert_eq!(names, ["SLACK_BOT_TOKEN", "WEBEX_BOT_TOKEN"]);
    for (name, hosts) in table {
        assert!(hosts.is_empty(), "{name} widened without a measurement");
        for host in *hosts {
            let body = host.strip_prefix("*.").unwrap_or(host);
            assert!(body.split('.').count() >= 2, "{name}: {host}");
            assert!(!host[1..].contains('*'), "{name}: {host}");
        }
    }
    // With the production table a Slack redirect off its host is checked as
    // a credential-less fetch and refused.
    assert!(
        prod()
            .redirect(&from_slack(), "https://files-edge.slack.com/a.png", SLACK)
            .is_err()
    );
}
