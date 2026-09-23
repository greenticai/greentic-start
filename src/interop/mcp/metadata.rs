//! RFC 9728 protected-resource metadata — the discovery document an MCP
//! client fetches to learn which authorization server guards `POST /mcp`.
//!
//! Served at BOTH the bare path and the `/mcp`-suffixed form. RFC 9728 defines
//! both and clients differ over which they probe; a client probing the form we
//! do not serve sees a 404 and abandons discovery without ever reaching the
//! authorization server. That failure surfaces to the operator as "the
//! connector will not connect", with nothing pointing here.
//!
//! The document is PUBLIC by design and carries no secret: an issuer URL and a
//! resource identifier, both of which the client is about to be redirected to
//! anyway.

use serde_json::json;

use crate::interop::config::InteropConfig;

/// The resource identifier an accepted token's `aud` must equal.
///
/// The staged `mcp_resource` wins — the designer registers exactly that string
/// with the admin, so the token's audience is minted from it. Without one,
/// `<public base>/mcp` is the same value the designer will stage on the next
/// deploy, so the two agree in the meantime. `None` when neither is known, and
/// the caller then refuses rather than publishing an identifier no token will
/// match.
pub(crate) fn resource_identifier(
    config: &InteropConfig,
    base_url: Option<&str>,
) -> Option<String> {
    if let Some(resource) = config.mcp_resource.as_deref() {
        return Some(resource.to_string());
    }
    let base = base_url?.trim_end_matches('/');
    (!base.is_empty()).then(|| format!("{base}{}", super::MCP_PATH))
}

/// Where a `401` points a client that has not performed discovery, and where
/// the document below is served.
///
/// Derived from the public base when one is known, else from the resource
/// identifier with its `/mcp` suffix removed — so a deployment whose only
/// known address is the staged `mcp_resource` still advertises a reachable
/// metadata URL.
pub(crate) fn resource_metadata_url(base_url: Option<&str>, resource: &str) -> String {
    let origin = base_url
        .map(|base| base.trim_end_matches('/').to_string())
        .unwrap_or_else(|| {
            resource
                .strip_suffix(super::MCP_PATH)
                .unwrap_or(resource)
                .trim_end_matches('/')
                .to_string()
        });
    format!("{origin}{}", super::PROTECTED_RESOURCE_MCP_PATH)
}

/// The document itself. `None` when the unit has no issuer staged: a resource
/// that names no authorization server sends a client nowhere, and answering
/// with an empty list reads as "discovery succeeded" while being unusable.
pub(crate) fn document(config: &InteropConfig, resource: &str) -> Option<serde_json::Value> {
    let issuer = config.issuer.as_deref()?.trim_end_matches('/');
    Some(json!({
        "resource": resource,
        "authorization_servers": [issuer],
        "bearer_methods_supported": ["header"],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(resource: Option<&str>, issuer: Option<&str>) -> InteropConfig {
        InteropConfig {
            mcp: true,
            mcp_resource: resource.map(str::to_string),
            issuer: issuer.map(str::to_string),
            ..InteropConfig::default()
        }
    }

    #[test]
    fn the_staged_resource_wins_over_the_derived_one() {
        let staged = config(Some("https://staged.example/mcp"), None);
        assert_eq!(
            resource_identifier(&staged, Some("https://derived.example")),
            Some("https://staged.example/mcp".to_string())
        );
    }

    #[test]
    fn the_resource_is_derived_from_the_public_base_when_none_is_staged() {
        let bare = config(None, None);
        assert_eq!(
            resource_identifier(&bare, Some("https://w.example/")),
            Some("https://w.example/mcp".to_string()),
            "the trailing slash must not double"
        );
        assert_eq!(resource_identifier(&bare, None), None);
    }

    #[test]
    fn the_metadata_url_is_the_mcp_suffixed_form() {
        assert_eq!(
            resource_metadata_url(Some("https://w.example/"), "https://w.example/mcp"),
            "https://w.example/.well-known/oauth-protected-resource/mcp"
        );
        // With no known base, the origin comes back out of the resource.
        assert_eq!(
            resource_metadata_url(None, "https://staged.example/mcp"),
            "https://staged.example/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[test]
    fn the_document_names_the_issuer_and_the_header_method() {
        let with_issuer = config(None, Some("https://admin.example/"));
        assert_eq!(
            document(&with_issuer, "https://w.example/mcp"),
            Some(json!({
                "resource": "https://w.example/mcp",
                "authorization_servers": ["https://admin.example"],
                "bearer_methods_supported": ["header"],
            }))
        );
    }

    #[test]
    fn a_unit_with_no_issuer_publishes_no_document() {
        assert_eq!(document(&config(None, None), "https://w.example/mcp"), None);
    }
}
