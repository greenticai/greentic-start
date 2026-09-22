//! The public agent card: `GET /.well-known/agent-card.json`.
//!
//! Unauthenticated by design (A2A §8.2 makes serving it the one explicit
//! MUST), cacheable, and synthesized from the unit's staged `agent` object
//! with the bundle id and a generic `converse` skill as the fallback.

use std::collections::BTreeMap;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Response, StatusCode, header};
use sha2::{Digest, Sha256};

use super::types::{
    AgentCapabilities, AgentCard, AgentInterface, AgentSkill, HttpAuthSecurityScheme,
    ProtocolVersion, SecurityScheme,
};
use super::{
    A2aContext, A2aRequest, ADAPTIVE_CARD_MEDIA_TYPE, CARD_CACHE_CONTROL, HttpResponse,
    JSONRPC_PATH, plain,
};

/// Synthesize the card from the staged `agent` object, falling back to the
/// bundle id and a generic `converse` skill.
pub(crate) fn build_card(ctx: &A2aContext<'_>, base_url: &str) -> AgentCard {
    let agent = &ctx.config.agent;
    let name = agent
        .name
        .clone()
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| ctx.bundle_id.to_string());
    let description = agent
        .description
        .clone()
        .filter(|d| !d.trim().is_empty())
        .unwrap_or_else(|| format!("{name}, a Greentic worker."));
    let mut skills: Vec<AgentSkill> = agent
        .skills
        .iter()
        .filter(|s| !s.id.trim().is_empty())
        .map(|s| AgentSkill {
            id: s.id.clone(),
            name: if s.name.trim().is_empty() {
                s.id.clone()
            } else {
                s.name.clone()
            },
            description: if s.description.trim().is_empty() {
                description.clone()
            } else {
                s.description.clone()
            },
            tags: s.tags.clone(),
            examples: s.examples.clone(),
            input_modes: Vec::new(),
            output_modes: Vec::new(),
        })
        .collect();
    if skills.is_empty() {
        skills.push(AgentSkill {
            id: "converse".into(),
            name: "Converse".into(),
            description: format!("Hold a conversation with {name}."),
            tags: vec!["conversation".into()],
            examples: Vec::new(),
            input_modes: Vec::new(),
            output_modes: Vec::new(),
        });
    }
    AgentCard {
        name,
        description,
        supported_interfaces: vec![AgentInterface {
            url: format!("{base_url}{JSONRPC_PATH}"),
            protocol_binding: "JSONRPC".into(),
            protocol_version: ProtocolVersion::SUPPORTED.to_string(),
            tenant: None,
        }],
        version: agent
            .version
            .clone()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "1.0.0".into()),
        capabilities: AgentCapabilities {
            streaming: Some(false),
            push_notifications: Some(false),
            extended_agent_card: None,
        },
        default_input_modes: vec!["text/plain".into(), "application/json".into()],
        default_output_modes: vec!["text/plain".into(), ADAPTIVE_CARD_MEDIA_TYPE.into()],
        skills,
        provider: None,
        documentation_url: None,
        icon_url: None,
        security_schemes: BTreeMap::from([(
            "bearer".to_string(),
            SecurityScheme::HttpAuth(HttpAuthSecurityScheme {
                description: Some("A worker interop token (gtw_…).".into()),
                scheme: "bearer".into(),
                bearer_format: Some("gtw".into()),
            }),
        )]),
    }
}

/// `GET /.well-known/agent-card.json`: unauthenticated, cacheable, with a
/// strong ETag over the exact bytes served.
pub(crate) fn card_response(ctx: &A2aContext<'_>, req: &A2aRequest<'_>) -> HttpResponse {
    let Some(base_url) = ctx.base_url else {
        crate::operator_log::warn(
            module_path!(),
            format!(
                "a2a: cannot serve the agent card for unit `{}`: the public base URL is unknown",
                ctx.bundle_id
            ),
        );
        return plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "the agent's public address is not known yet",
        );
    };
    let body = match serde_json::to_vec(&build_card(ctx, base_url)) {
        Ok(body) => body,
        Err(_) => {
            return plain(
                StatusCode::INTERNAL_SERVER_ERROR,
                "card serialization failed",
            );
        }
    };
    let digest: [u8; 32] = Sha256::digest(&body).into();
    let etag = format!(
        "\"{}\"",
        digest[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    if req.if_none_match.is_some_and(|inm| {
        inm.split(',')
            .any(|tag| tag.trim() == etag || tag.trim() == "*")
    }) {
        return Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(header::ETAG, &etag)
            .header(header::CACHE_CONTROL, CARD_CACHE_CONTROL)
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|_| plain(StatusCode::INTERNAL_SERVER_ERROR, "response"));
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ETAG, &etag)
        .header(header::CACHE_CONTROL, CARD_CACHE_CONTROL)
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| plain(StatusCode::INTERNAL_SERVER_ERROR, "response"))
}

#[cfg(test)]
#[path = "card_tests.rs"]
mod card_tests;
