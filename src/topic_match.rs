//! Minimal topic glob matcher for event routing. Local to greentic-start
//! (the archived greentic-events `matches_pattern` is not a dependency).

/// `*` matches everything; `prefix.*` matches `prefix` followed by `.`+anything;
/// otherwise exact match.
pub fn topic_matches(pattern: &str, event_type: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix(".*") {
        return event_type == prefix
            || event_type
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('.'));
    }
    pattern == event_type
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_matches_exact_prefix_and_catchall() {
        assert!(topic_matches("subscription.created", "subscription.created"));
        assert!(!topic_matches("subscription.created", "subscription.updated"));
        assert!(topic_matches("subscription.*", "subscription.created"));
        assert!(topic_matches("subscription.*", "subscription.created.v2"));
        assert!(topic_matches("*", "anything.at.all"));
        assert!(!topic_matches("billing.*", "subscription.created"));
    }
}
