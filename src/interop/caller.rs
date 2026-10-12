//! Who an interop request authenticated as.
//!
//! One type for both surfaces, so the rate limiter, the session namespace and
//! usage metering cannot disagree about what a caller is.

use sha2::{Digest, Sha256};

/// An authenticated (or, on a public unit, anonymous) interop caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Caller {
    /// A staged `gtw_` credential, by id.
    Bearer(String),
    /// An OAuth access token, by caller key: the `sub` of a user token, or
    /// the mapped key of a service client (see
    /// [`crate::interop::mcp::auth::caller_key_for_sub`]).
    Oauth(String),
    /// No credential, on a public unit. Holds the namespace key derived from
    /// the client label, never the address itself.
    Anonymous(String),
}

impl Caller {
    /// An anonymous caller for the client `label` (an address, or a stand-in
    /// when none is known). The label is hashed: it becomes a session
    /// namespace and a rate-limit key, and an address has no business in
    /// either, nor in a log line that prints one.
    pub(crate) fn anonymous(label: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"greentic-interop-anonymous-v1\0");
        hasher.update(label.as_bytes());
        let digest = hasher.finalize();
        let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
        Caller::Anonymous(format!("anon_{hex}"))
    }

    /// The rate-limit key and conversation namespace. Always passes
    /// [`crate::interop::valid_caller_key`] or is `svc~…` (see the mapping).
    pub(crate) fn key(&self) -> &str {
        match self {
            Caller::Bearer(key) | Caller::Oauth(key) | Caller::Anonymous(key) => key,
        }
    }

    /// The staged credential id, when the caller used one. An OAuth subject
    /// and an anonymous caller are not credentials the designer issued, so a
    /// usage event may not name them as one.
    pub(crate) fn credential_id(&self) -> Option<&str> {
        match self {
            Caller::Bearer(id) => Some(id),
            Caller::Oauth(_) | Caller::Anonymous(_) => None,
        }
    }

    pub(crate) fn is_anonymous(&self) -> bool {
        matches!(self, Caller::Anonymous(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_anonymous_key_is_a_valid_caller_key_and_hides_the_label() {
        let caller = Caller::anonymous("203.0.113.7");
        assert!(crate::interop::valid_caller_key(caller.key()));
        assert!(!caller.key().contains("203"));
        assert_eq!(caller, Caller::anonymous("203.0.113.7"));
        assert_ne!(caller, Caller::anonymous("203.0.113.8"));
        assert_eq!(caller.credential_id(), None);
        assert!(caller.is_anonymous());
    }

    #[test]
    fn only_a_bearer_names_a_credential() {
        assert_eq!(Caller::Bearer("c1".into()).credential_id(), Some("c1"));
        assert_eq!(Caller::Oauth("u1".into()).credential_id(), None);
    }
}
