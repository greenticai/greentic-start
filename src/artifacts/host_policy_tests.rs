use reqwest::Url;

use super::host_policy::*;

fn url(s: &str) -> Url {
    Url::parse(s).unwrap()
}

fn prod() -> HostPolicy {
    HostPolicy::from_value(None)
}

const SLACK: Option<&str> = Some("SLACK_BOT_TOKEN");

#[test]
fn only_https_is_accepted() {
    assert_eq!(
        prod().check(&url("http://files.slack.com/x"), SLACK),
        Err(Blocked::NotHttps)
    );
    assert_eq!(
        prod().check(&url("ftp://files.slack.com/x"), SLACK),
        Err(Blocked::NotHttps)
    );
    assert!(
        prod()
            .check(&url("https://files.slack.com/x"), SLACK)
            .is_ok()
    );
}

#[test]
fn ip_literals_are_always_refused() {
    for u in [
        "https://169.254.169.254/latest/meta-data",
        "https://127.0.0.1/",
        "https://10.0.0.5/",
        "https://0.0.0.0/",
        "https://8.8.8.8/",
        "https://[::1]/",
        "https://[fd00::1]/",
        "https://[::ffff:169.254.169.254]/",
        // Integer and short forms the URL parser normalises to an IPv4 address.
        "https://2130706433/",
        "https://0x7f.1/",
        "https://127.1/",
    ] {
        assert_eq!(prod().check(&url(u), None), Err(Blocked::IpLiteral), "{u}");
        assert_eq!(prod().check(&url(u), SLACK), Err(Blocked::IpLiteral), "{u}");
    }
}

#[test]
fn userinfo_and_lookalike_hosts_do_not_pass() {
    let p = prod();
    assert_eq!(
        p.check(&url("https://files.slack.com@evil.example/x"), SLACK),
        Err(Blocked::UserInfo)
    );
    assert_eq!(
        p.check(&url("https://user:pw@files.slack.com/x"), SLACK),
        Err(Blocked::UserInfo)
    );
    for u in [
        "https://files.slack.com.evil.example/x",
        "https://evil.example/x?h=files.slack.com",
        "https://evil.example/files.slack.com",
        "https://evilfiles.slack.com.example/x",
        "https://xfiles.slack.com/x",
        "https://files.slack.co/x",
        // Trailing dot: a different name to this check; refused, never guessed.
        "https://files.slack.com./x",
        // Cyrillic `і`: punycode, not the real host.
        "https://f\u{0456}les.slack.com/x",
    ] {
        assert_eq!(p.check(&url(u), SLACK), Err(Blocked::HostNotAllowed), "{u}");
    }
}

#[test]
fn a_non_default_port_is_refused() {
    assert_eq!(
        prod().check(&url("https://files.slack.com:8443/x"), SLACK),
        Err(Blocked::Port)
    );
    assert!(
        prod()
            .check(&url("https://files.slack.com:443/x"), SLACK)
            .is_ok()
    );
}

#[test]
fn public_wildcards_match_exactly_one_label() {
    let p = prod();
    assert!(
        p.check(&url("https://tenant.sharepoint.com/x"), None)
            .is_ok()
    );
    assert!(
        p.check(&url("https://contoso-my.sharepoint.com/x"), None)
            .is_ok()
    );
    for u in [
        "https://a.b.sharepoint.com/x",
        "https://sharepoint.com/x",
        "https://notsharepoint.com/x",
        "https://.sharepoint.com/x",
    ] {
        assert_eq!(p.check(&url(u), None), Err(Blocked::HostNotAllowed), "{u}");
    }
}

#[test]
fn every_public_wildcard_refuses_two_labels() {
    for pattern in PUBLIC_HOSTS {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            let one = format!("https://one.{suffix}/x");
            let two = format!("https://one.two.{suffix}/x");
            assert!(prod().check(&url(&one), None).is_ok(), "{one}");
            assert_eq!(
                prod().check(&url(&two), None),
                Err(Blocked::HostNotAllowed),
                "{two}"
            );
        }
    }
}

#[test]
fn matching_is_case_insensitive() {
    assert!(
        prod()
            .check(&url("https://FILES.Slack.COM/x"), SLACK)
            .is_ok()
    );
}

#[test]
fn a_credential_goes_only_to_its_own_hosts() {
    let p = prod();
    assert_eq!(
        p.check(&url("https://tenant.sharepoint.com/x"), SLACK),
        Err(Blocked::HostNotAllowed)
    );
    assert_eq!(
        p.check(&url("https://files.slack.com/x"), Some("WEBEX_BOT_TOKEN")),
        Err(Blocked::HostNotAllowed)
    );
    assert!(
        p.check(
            &url("https://webexapis.com/v1/contents/x"),
            Some("WEBEX_BOT_TOKEN")
        )
        .is_ok()
    );
    assert!(
        p.check(
            &url("https://api.telegram.org/file/botX/y"),
            Some("TELEGRAM_BOT_TOKEN")
        )
        .is_ok()
    );
    assert_eq!(
        p.check(&url("https://files.slack.com/x"), Some("ATTACKER_TOKEN")),
        Err(Blocked::UnknownCredential)
    );
    // A credential-less public host does not accept a credential either.
    assert_eq!(
        p.check(&url("https://smba.trafficmanager.net/x"), SLACK),
        Err(Blocked::HostNotAllowed)
    );
}

#[test]
fn whatsapp_media_hosts_pass_for_the_whatsapp_token_only() {
    let p = prod();
    for u in [
        "https://lookaside.fbsbx.com/whatsapp_business/x",
        "https://scontent.xx.fbcdn.net/x",
        "https://mmg.whatsapp.net/x",
        "https://graph.facebook.com/v19.0/123",
    ] {
        assert!(p.check(&url(u), Some("WHATSAPP_TOKEN")).is_ok(), "{u}");
        assert_eq!(p.check(&url(u), SLACK), Err(Blocked::HostNotAllowed), "{u}");
        assert_eq!(p.check(&url(u), None), Err(Blocked::HostNotAllowed), "{u}");
    }
    assert_eq!(
        p.check(&url("https://evil.example/media"), Some("WHATSAPP_TOKEN")),
        Err(Blocked::HostNotAllowed)
    );
    assert_eq!(
        p.check(&url("https://fbcdn.net/x"), Some("WHATSAPP_TOKEN")),
        Err(Blocked::HostNotAllowed)
    );
}

#[test]
fn the_environment_list_extends_public_fetches_never_a_credential() {
    let p = HostPolicy::from_value(Some(
        "cdn.example.com, *.corp.example, bad/host, *, *., 10.0.0.1",
    ));
    assert!(p.check(&url("https://cdn.example.com/a"), None).is_ok());
    assert!(p.check(&url("https://x.corp.example/a"), None).is_ok());
    assert_eq!(
        p.check(&url("https://evil.com/a"), None),
        Err(Blocked::HostNotAllowed)
    );
    assert_eq!(
        p.check(&url("https://anything.example/a"), None),
        Err(Blocked::HostNotAllowed),
        "a bare `*` is dropped"
    );
    assert_eq!(
        p.check(&url("https://cdn.example.com/a"), SLACK),
        Err(Blocked::HostNotAllowed)
    );
}

// --- Redirects ----------------------------------------------------------------

#[test]
fn a_redirect_is_checked_like_a_first_request() {
    let p = prod();
    let from = url("https://files.slack.com/files-pri/T1/x");
    let hop = p.redirect(&from, "/files-pri/T1/y", SLACK).unwrap();
    assert_eq!(hop.url.as_str(), "https://files.slack.com/files-pri/T1/y");
    assert_eq!(hop.credential, SLACK, "same host keeps the credential");
    for location in [
        "http://files.slack.com/y",
        "https://169.254.169.254/latest/meta-data",
        "https://evil.example/steal",
        "https://files.slack.com:8443/y",
        "https://u:p@files.slack.com/y",
    ] {
        assert!(p.redirect(&from, location, SLACK).is_err(), "{location}");
    }
}

#[test]
fn a_redirect_to_another_host_drops_the_credential() {
    let p = prod();
    let from = url("https://graph.facebook.com/v19.0/media");
    // From the credential's list to a public host: allowed without it.
    let hop = p
        .redirect(
            &from,
            "https://tenant.sharepoint.com/f",
            Some("WHATSAPP_TOKEN"),
        )
        .unwrap();
    assert_eq!(hop.credential, None);
    // To another host on the same credential's list: kept.
    let hop = p
        .redirect(
            &from,
            "https://lookaside.fbsbx.com/m",
            Some("WHATSAPP_TOKEN"),
        )
        .unwrap();
    assert_eq!(hop.credential, Some("WHATSAPP_TOKEN"));
}

#[test]
fn an_unparseable_location_is_refused() {
    let from = url("https://files.slack.com/x");
    assert_eq!(
        prod()
            .redirect(&from, "https://[not an ip/", SLACK)
            .unwrap_err(),
        Blocked::BadLocation
    );
}
