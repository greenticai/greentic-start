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

const APP_ID: &str = "9f6b3c2e-1d4a-4b7f-8e2a-5c1d0e9f7a3b";
const NOW: u64 = 1_800_000_000;
/// A real Microsoft host outside the built-in list (US Government GCC).
const GCC_SERVICE_URL: &str = "https://smba.infra.gcc.teams.microsoft.com/teams/";

struct OneKey;

#[async_trait::async_trait]
impl super::bot_framework::BfKeys for OneKey {
    async fn key(&self, kid: &str) -> super::bf_keys::BfKeyLookup {
        use crate::interop::mcp::testkit::{TEST_JWKS_E, TEST_JWKS_N};
        if kid != "k" {
            return super::bf_keys::BfKeyLookup::UnknownKid;
        }
        super::bf_keys::BfKeyLookup::Found(super::bf_keys::BfKey {
            key: std::sync::Arc::new(
                jsonwebtoken::DecodingKey::from_rsa_components(TEST_JWKS_N, TEST_JWKS_E)
                    .expect("key"),
            ),
            endorsements: vec!["msteams".to_string()].into(),
        })
    }
}

fn signed_token(service_url: &str) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("k".to_string());
    jsonwebtoken::encode(
        &header,
        &json!({
            "iss": super::bf_keys::BF_ISSUER,
            "aud": APP_ID,
            "exp": NOW + 3600,
            "nbf": NOW - 60,
            "serviceurl": service_url,
        }),
        &jsonwebtoken::EncodingKey::from_rsa_pem(
            crate::interop::mcp::testkit::TEST_PRIVATE_KEY_PEM.as_bytes(),
        )
        .expect("test key"),
    )
    .expect("token")
}

fn app_id_config() -> std::collections::BTreeMap<String, serde_json::Value> {
    std::collections::BTreeMap::from([("ms_bot_app_id".to_string(), json!(APP_ID))])
}

/// Re-review G4 I2: on a VERIFIED activity the signed `serviceurl` claim
/// already matched the activity's `serviceUrl`, so the host list adds nothing
/// and would refuse genuine Microsoft hosts (GCC). It is not applied.
#[tokio::test]
async fn a_verified_teams_activity_to_a_host_outside_the_list_is_admitted() {
    let secrets = empty_store();
    let (notices, _) = Notices::recording();
    let body = teams_body(GCC_SERVICE_URL);
    let headers = vec![(
        "authorization".to_string(),
        format!("Bearer {}", signed_token(GCC_SERVICE_URL)),
    )];
    let config = app_id_config();
    let mut request = inbound(
        "messaging.teams",
        "POST",
        &headers,
        &body,
        DeploymentId::new(),
    );
    request.pack_non_secret = Some(&config);
    let keys = OneKey;
    let mut with_keys = deps(&secrets, &notices);
    with_keys.bf_keys = Some(&keys);
    with_keys.now = NOW;
    let verdict = verify_with(request, &with_keys)
        .await
        .expect("a verified activity is admitted");
    assert_eq!(verdict, Verdict::Verified);
}

/// Re-review G4 I2: verification UNAVAILABLE (app id set, no key set) still
/// gets the host list: nothing proved who named that `serviceUrl`.
#[tokio::test]
async fn an_unavailable_teams_activity_to_a_host_outside_the_list_is_refused() {
    let secrets = empty_store();
    let (notices, _) = Notices::recording();
    let body = teams_body(GCC_SERVICE_URL);
    let headers = vec![(
        "authorization".to_string(),
        format!("Bearer {}", signed_token(GCC_SERVICE_URL)),
    )];
    let config = app_id_config();
    let mut request = inbound(
        "messaging.teams",
        "POST",
        &headers,
        &body,
        DeploymentId::new(),
    );
    request.pack_non_secret = Some(&config);
    let mut no_keys = deps(&secrets, &notices);
    no_keys.now = NOW;
    let refused = verify_with(request, &no_keys).await.expect_err("refused");
    assert_eq!(refused.status(), hyper::StatusCode::FORBIDDEN);
}

/// Not configured (no app id) and a host outside the list: refused.
#[tokio::test]
async fn a_not_configured_teams_activity_to_a_microsoft_host_outside_the_list_is_refused() {
    let secrets = empty_store();
    let (notices, _) = Notices::recording();
    let body = teams_body(GCC_SERVICE_URL);
    let refused = verify_with(
        inbound("messaging.teams", "POST", &[], &body, DeploymentId::new()),
        &deps(&secrets, &notices),
    )
    .await
    .expect_err("refused");
    assert_eq!(refused.status(), hyper::StatusCode::FORBIDDEN);
}
