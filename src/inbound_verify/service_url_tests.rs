use greentic_deploy_spec::DeploymentId;
use serde_json::json;

use super::mod_tests::{deps, empty_store, inbound};
use super::notices::Notices;
use super::service_url::{ServiceUrl, allowed, classify, parse_extra};
use super::{Verdict, verify_with};

fn none() -> Vec<String> {
    Vec::new()
}

#[test]
fn bot_framework_hosts_are_allowed() {
    for url in [
        "https://smba.trafficmanager.net/amer/",
        "https://smba.trafficmanager.net/emea/",
        "https://SMBA.TrafficManager.net/apac/",
        "https://webchat.botframework.com/",
        "https://directline.botframework.com/v3/",
        "https://europe.webchat.botframework.com",
        "https://smba.trafficmanager.net:443/amer/",
    ] {
        assert!(allowed(url, &none()), "{url}");
    }
}

#[test]
fn everything_else_is_refused() {
    for url in [
        "http://smba.trafficmanager.net/amer/",
        "https://evil.trafficmanager.net/amer/",
        "https://trafficmanager.net/",
        "https://botframework.com/",
        "https://evilbotframework.com/",
        "https://smba.trafficmanager.net.evil.example/",
        "https://webchat.botframework.com.evil.example/",
        "https://user@smba.trafficmanager.net/",
        "https://user:pw@webchat.botframework.com/",
        "https://smba.trafficmanager.net:8443/",
        "https://evil.example/smba.trafficmanager.net",
        "https://evil.example\\@smba.trafficmanager.net/",
        "https://13.107.6.152/",
        "https://[::1]/",
        "smba.trafficmanager.net/amer/",
        "",
        "not a url",
    ] {
        assert!(!allowed(url, &none()), "{url}");
    }
}

#[test]
fn extra_hosts_are_exact_names_only() {
    let extra = parse_extra(Some(
        " bots.Example.com ,*.wild.example, ,bad host,10.0.0.1, x.test.",
    ));
    assert_eq!(extra, ["bots.example.com", "x.test"]);
    assert!(allowed("https://bots.example.com/", &extra));
    assert!(allowed("https://x.test/a", &extra));
    assert!(
        !allowed("https://a.bots.example.com/", &extra),
        "no wildcard"
    );
    assert!(!allowed("https://a.wild.example/", &extra));
    assert!(!allowed("http://bots.example.com/", &extra), "https only");
    assert!(
        !allowed("https://bots.example.com:8443/", &extra),
        "no port"
    );
}

#[test]
fn the_body_is_classified() {
    let body = |v: serde_json::Value| v.to_string().into_bytes();
    assert_eq!(classify(b"not json", &none()), ServiceUrl::Absent);
    assert_eq!(classify(&body(json!({})), &none()), ServiceUrl::Absent);
    assert_eq!(
        classify(&body(json!({"serviceUrl": null})), &none()),
        ServiceUrl::Absent
    );
    assert_eq!(
        classify(
            &body(json!({"serviceUrl": "https://smba.trafficmanager.net/amer/"})),
            &none()
        ),
        ServiceUrl::Allowed
    );
    assert_eq!(
        classify(
            &body(json!({"serviceUrl": "https://evil.example/"})),
            &none()
        ),
        ServiceUrl::Refused
    );
    assert_eq!(
        classify(&body(json!({"serviceUrl": 42})), &none()),
        ServiceUrl::Refused
    );
}

fn teams_body(service_url: &str) -> Vec<u8> {
    json!({"type": "message", "channelId": "msteams", "serviceUrl": service_url})
        .to_string()
        .into_bytes()
}

/// Review G4 #3: an UNVERIFIED Teams activity (no bot app id) naming a
/// foreign `serviceUrl` is refused `403`, so the provider never sends the bot
/// token there.
#[tokio::test]
async fn an_unverified_teams_activity_with_a_foreign_service_url_is_refused() {
    let secrets = empty_store();
    let (notices, said) = Notices::recording();
    for url in [
        "https://evil.example/",
        "https://evil.trafficmanager.net/amer/",
        "https://user@smba.trafficmanager.net/",
        "https://smba.trafficmanager.net:8443/",
    ] {
        let body = teams_body(url);
        let refused = verify_with(
            inbound("messaging.teams", "POST", &[], &body, DeploymentId::new()),
            &deps(&secrets, &notices),
        )
        .await
        .expect_err("refused");
        assert_eq!(refused.status(), hyper::StatusCode::FORBIDDEN, "{url}");
    }
    let lines = said.lock().unwrap().clone();
    assert!(
        lines.iter().all(|l| !l.contains("evil")),
        "an operator line named the url: {lines:?}"
    );
}

#[tokio::test]
async fn an_unverified_teams_activity_to_bot_framework_is_admitted_unverified() {
    let secrets = empty_store();
    let (notices, _) = Notices::recording();
    let body = teams_body("https://smba.trafficmanager.net/emea/");
    let verdict = verify_with(
        inbound("messaging.teams", "POST", &[], &body, DeploymentId::new()),
        &deps(&secrets, &notices),
    )
    .await
    .expect("admitted");
    assert_eq!(verdict, Verdict::NotConfigured);
}

#[tokio::test]
async fn an_operator_host_is_admitted_only_when_listed() {
    let secrets = empty_store();
    let (notices, _) = Notices::recording();
    let body = teams_body("https://bots.example.com/");
    let extra = parse_extra(Some("bots.example.com"));
    let mut listed = deps(&secrets, &notices);
    listed.teams_service_hosts = &extra;
    assert_eq!(
        verify_with(
            inbound("messaging.teams", "POST", &[], &body, DeploymentId::new()),
            &listed,
        )
        .await
        .expect("admitted"),
        Verdict::NotConfigured
    );
    let refused = verify_with(
        inbound("messaging.teams", "POST", &[], &body, DeploymentId::new()),
        &deps(&secrets, &notices),
    )
    .await
    .expect_err("not listed");
    assert_eq!(refused.status(), hyper::StatusCode::FORBIDDEN);
}
