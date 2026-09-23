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
/// method. Read as a PRE-FILTER only — see [`request_cost`].
pub(crate) const MCP_METHOD_HEADER: &str = "mcp-method";

/// The methods charged the cheap rate up front. An ALLOW-LIST, so an absent,
/// misspelled or unknown method pays the expensive tier immediately.
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

/// What to charge this request BEFORE the body is parsed.
///
/// **The header is a pre-filter, never the final price.** It is supplied by
/// the caller, and the method actually executed comes from the body inside
/// `rmcp` — so a caller can send `Mcp-Method: tools/list` with a `tools/call`
/// body. Pricing a turn from that header alone would let it run turns at the
/// cheap rate, which is a rate limit a caller sets for itself.
///
/// Two halves, and BOTH are needed:
///
/// - here, an absent or unknown method pays the EXPENSIVE tier up front, so a
///   client that says nothing cannot be cheap;
/// - inside the `ask` tool ([`server::WorkerMcpServer::ask`]), the remainder
///   up to [`super::limits::TURN_COST`] is settled against the same bucket, so
///   a turn costs a turn however the request was announced.
///
/// What the header still buys is refusing an obvious flood before a body is
/// read, and charging a genuinely cheap request (`tools/list`) only once.
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
