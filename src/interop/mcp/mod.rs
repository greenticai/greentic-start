//! A deployed worker as an MCP server (worker-interop contract §3, Feature B
//! of the research spec).
//!
//! | path | method | auth |
//! |---|---|---|
//! | `/mcp` | POST (GET/DELETE → 405) | OAuth JWT, or the A2A bearer |
//! | `/.well-known/oauth-protected-resource` | GET | none |
//! | `/.well-known/oauth-protected-resource/mcp` | GET | none |
//!
//! Reserved only when the unit's staged config sets `mcp: true`; otherwise the
//! paths fall through to normal routing exactly as before.
//!
//! ONE tool, `ask` — never the worker's own bound tools (research §6.3). The
//! conversation is `mcp:<sub or credential id>:<conversation_id>`, namespaced
//! by the caller for the same reason the A2A one is.

pub(crate) mod auth;
pub(crate) mod jwks;
pub(crate) mod metadata;
pub(crate) mod server;

#[cfg(test)]
pub(crate) mod testkit;

/// The MCP endpoint.
pub(crate) const MCP_PATH: &str = "/mcp";
/// RFC 9728, bare form.
pub(crate) const PROTECTED_RESOURCE_PATH: &str = "/.well-known/oauth-protected-resource";
/// RFC 9728, path-suffixed form. Clients differ over which they probe, so both
/// are served — a client probing the one we do not serve sees a 404 and
/// abandons discovery without ever reaching the authorization server.
pub(crate) const PROTECTED_RESOURCE_MCP_PATH: &str = "/.well-known/oauth-protected-resource/mcp";

/// The header SEP-2243 requires an MCP client to send, naming the JSON-RPC
/// method. Read for rate limiting only, so the limiter never parses a body.
pub(crate) const MCP_METHOD_HEADER: &str = "mcp-method";

/// The methods charged the cheap rate. An ALLOW-LIST: an absent, misspelled
/// or unknown method falls into the expensive tier, which is the only shape
/// that fails closed — with a deny-list, a client could pay the cheap rate for
/// `tools/call` by omitting the header.
const CHEAP_METHODS: &[&str] = &[
    "initialize",
    "notifications/initialized",
    "ping",
    "tools/list",
    "prompts/list",
    "resources/list",
    "resources/templates/list",
    "completion/complete",
    "logging/setLevel",
];

/// Which MCP surface a path names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum McpRoute {
    /// The JSON-RPC endpoint.
    Endpoint,
    /// One of the two RFC 9728 discovery documents.
    Metadata,
}

/// Classify a request path. Exact matches only.
pub(crate) fn route_for(path: &str) -> Option<McpRoute> {
    match path {
        MCP_PATH => Some(McpRoute::Endpoint),
        PROTECTED_RESOURCE_PATH | PROTECTED_RESOURCE_MCP_PATH => Some(McpRoute::Metadata),
        _ => None,
    }
}

/// `/mcp` is never CORS-enabled — a browser page has no business driving an
/// authenticated turn runner, and `server::service`'s `allowed_origins`
/// opt-out rests on exactly that. The discovery documents are public and stay
/// CORS-open, which is how a browser-based client finds its issuer.
pub(crate) fn is_cors_excluded(path: &str) -> bool {
    path == MCP_PATH
}

/// What this request costs the caller's token bucket.
pub(crate) fn request_cost(mcp_method_header: Option<&str>) -> f64 {
    match mcp_method_header.map(str::trim) {
        Some(name) if CHEAP_METHODS.contains(&name) => super::limits::CHEAP_COST,
        _ => super::limits::TURN_COST,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_and_cors() {
        assert_eq!(route_for("/mcp"), Some(McpRoute::Endpoint));
        assert_eq!(
            route_for("/.well-known/oauth-protected-resource"),
            Some(McpRoute::Metadata)
        );
        assert_eq!(
            route_for("/.well-known/oauth-protected-resource/mcp"),
            Some(McpRoute::Metadata)
        );
        assert_eq!(route_for("/mcp/"), None);
        assert_eq!(route_for("/mcpx"), None);
        assert!(is_cors_excluded("/mcp"));
        assert!(!is_cors_excluded("/.well-known/oauth-protected-resource"));
    }

    /// The allow-list is what makes an omitted header expensive.
    #[test]
    fn the_expensive_tier_is_the_default() {
        assert_eq!(
            request_cost(Some("tools/list")),
            super::super::limits::CHEAP_COST
        );
        assert_eq!(
            request_cost(Some("initialize")),
            super::super::limits::CHEAP_COST
        );
        assert_eq!(
            request_cost(Some("tools/call")),
            super::super::limits::TURN_COST
        );
        assert_eq!(request_cost(None), super::super::limits::TURN_COST);
        assert_eq!(
            request_cost(Some("tools/CALL")),
            super::super::limits::TURN_COST
        );
        assert_eq!(request_cost(Some("")), super::super::limits::TURN_COST);
    }
}
