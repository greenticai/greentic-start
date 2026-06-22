//! Minimal topic glob matcher for event routing. Local to greentic-start
//! (the archived greentic-events `matches_pattern` is not a dependency).

/// `*` matches everything; `prefix.*` matches the bare `prefix` AND any
/// subtopic `prefix.<anything>` (so a flow subscribing to `subscription.*`
/// receives both `subscription` and `subscription.created`), but NOT a longer
/// stem with no dot (`subscriptionx`); otherwise exact match.
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
        // bare prefix matches `prefix.*` by design (prefix + all subtopics)
        assert!(topic_matches("subscription.*", "subscription"));
        // longer stem with no dot must NOT match
        assert!(!topic_matches("subscription.*", "subscriptionx"));
    }
}
