//! Path classification and the CORS exclusion.

use super::*;

#[test]
fn routes_and_cors() {
    assert_eq!(
        route_for("/.well-known/agent-card.json"),
        Some(A2aRoute::Card)
    );
    assert_eq!(route_for("/a2a"), Some(A2aRoute::JsonRpc));
    assert_eq!(route_for("/a2a/message:send"), Some(A2aRoute::RestSend));
    assert_eq!(route_for("/a2a/"), None);
    assert_eq!(route_for("/a2ab"), None);
    assert!(is_cors_excluded("/a2a"));
    assert!(is_cors_excluded("/a2a/message:send"));
    assert!(!is_cors_excluded("/.well-known/agent-card.json"));
    assert!(!is_cors_excluded("/a2ab"));
}
