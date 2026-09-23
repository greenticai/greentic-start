//! Card-synthesis tests. No turn runner is involved: the card is served
//! before any authentication and runs no flow.

use http_body_util::BodyExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::*;
use greentic_deploy_spec::ids::DeploymentId;

use crate::interop::a2a::{A2aContext, A2aRequest};
use crate::interop::config::{AgentMeta, AgentSkillMeta, Credential, InteropConfig};
use crate::interop::limits::{RateLimiter, TurnGate};

const TOKEN: &str = "gtw_test-token";

fn config() -> InteropConfig {
    InteropConfig {
        a2a: true,
        credentials: vec![Credential {
            id: "c1".into(),
            sha256: Sha256::digest(TOKEN.as_bytes()).into(),
            expires_at_ms: None,
        }],
        ..InteropConfig::default()
    }
}

struct Fixture {
    config: InteropConfig,
    limiter: RateLimiter,
    turns: TurnGate,
    deployment_id: DeploymentId,
}

impl Fixture {
    fn new(config: InteropConfig) -> Self {
        Self {
            config,
            limiter: RateLimiter::default(),
            turns: TurnGate::new(4),
            deployment_id: DeploymentId::new(),
        }
    }

    fn ctx(&self) -> A2aContext<'_> {
        A2aContext {
            config: &self.config,
            base_url: Some("https://w.example"),
            tenant: "default",
            bundle_id: "support-bot",
            deployment_id: self.deployment_id,
            limiter: &self.limiter,
            turns: &self.turns,
            now_ms: 0,
            // The card is served before any authentication and runs no turn,
            // so there is nothing to meter on this path.
            metering: None,
        }
    }
}

fn request(body: &[u8]) -> A2aRequest<'_> {
    A2aRequest {
        version_header: None,
        query: None,
        if_none_match: None,
        body,
    }
}

async fn body_json(response: HttpResponse) -> Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

#[tokio::test]
async fn the_card_is_synthesized_from_the_staged_agent_with_an_etag() {
    let mut staged = config();
    staged.agent = AgentMeta {
        // Read by usage metering, never published on the card.
        id: None,
        name: Some("Support Bot".into()),
        description: Some("Answers support questions.".into()),
        version: None,
        skills: vec![AgentSkillMeta {
            id: "support".into(),
            name: "Support".into(),
            ..AgentSkillMeta::default()
        }],
    };
    let fixture = Fixture::new(staged);
    let response = card_response(&fixture.ctx(), &request(b""));
    assert_eq!(response.status(), StatusCode::OK);
    let etag = response
        .headers()
        .get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(etag.starts_with('"') && etag.len() > 2);
    assert!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .is_some_and(|v| v.to_str().is_ok_and(|v| v.contains("max-age")))
    );
    let card = body_json(response).await;
    assert_eq!(card["name"], "Support Bot");
    assert_eq!(card["skills"][0]["id"], "support");
    assert_eq!(
        card["skills"][0]["description"],
        "Answers support questions."
    );
    assert_eq!(
        card["supportedInterfaces"][0],
        json!({"url": "https://w.example/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"})
    );
    assert_eq!(
        card["capabilities"],
        json!({"streaming": false, "pushNotifications": false})
    );
    assert_eq!(
        card["securitySchemes"]["bearer"]["httpAuthSecurityScheme"]["bearerFormat"],
        "gtw"
    );
    // The requirement, in the proto's shape: a StringList message, not an
    // array. A scheme declared but not REQUIRED reads as "no authentication".
    assert_eq!(
        card["securityRequirements"],
        json!([{"schemes": {"bearer": {"list": []}}}])
    );

    let mut conditional = request(b"");
    conditional.if_none_match = Some(&etag);
    let not_modified = card_response(&fixture.ctx(), &conditional);
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
}

#[tokio::test]
async fn the_card_falls_back_to_the_bundle_and_a_converse_skill() {
    let fixture = Fixture::new(config());
    let card = body_json(card_response(&fixture.ctx(), &request(b""))).await;
    assert_eq!(card["name"], "support-bot");
    assert_eq!(card["skills"][0]["id"], "converse");
    assert_eq!(card["version"], "1.0.0");
}
