//! Who an interop request authenticated as.
//!
//! One type for both surfaces, so the rate limiter, the session namespace and
//! usage metering cannot disagree about what a caller is.

use sha2::{Digest, Sha256};

/// The prefix of every anonymous caller's key. Reserved: no OAuth subject may
/// start with it (see `caller_key_for_sub`), so a signed token can never land in
/// an anonymous caller's session namespace.
pub(crate) const ANONYMOUS_PREFIX: &str = "anon_";

/// An authenticated (or, on a public unit, anonymous) interop caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Caller {
    /// A staged `gtw_` credential, by id.
    Bearer(String),
    /// An OAuth access token, by caller key: the `sub` of a user token, or
    /// the mapped key of a service client (see
    /// [`crate::interop::mcp::auth::caller_key_for_sub`]).
    Oauth(String),
    /// No credential, on a public unit. `client` is a hash of the client
    /// label, or `None` when the client behind the request cannot be told
    /// apart from the others (behind a proxy that hides it).
    Anonymous { client: Option<String> },
}

impl Caller {
    /// An anonymous caller for the client `label` (an address), or for an
    /// unidentifiable one when `None`. The label is hashed: it becomes a
    /// session namespace and a rate-limit key, and an address has no business
    /// in either, nor in a log line that prints one.
    pub(crate) fn anonymous(label: Option<&str>) -> Self {
        Caller::Anonymous {
            client: label.map(|label| digest_hex("client", &[label])),
        }
    }

    /// The bucket key of a caller that has its own bucket. **None for an
    /// anonymous caller**, whose limits are the unit's ([`super::anonymous`]).
    pub(crate) fn bucket_key(&self) -> Option<&str> {
        match self {
            Caller::Bearer(key) | Caller::Oauth(key) => Some(key),
            Caller::Anonymous { .. } => None,
        }
    }

    /// The identifiable client of an anonymous caller, for its fairness bucket.
    /// `None` for everyone else AND for an anonymous caller nobody can tell
    /// apart from the rest: giving those a shared "unknown" bucket would make
    /// them one client.
    pub(crate) fn fairness_client(&self) -> Option<&str> {
        match self {
            Caller::Anonymous { client } => client.as_deref(),
            _ => None,
        }
    }

    /// The conversation namespace for a request in `context`, and the user
    /// string derived from it. **Never derived from the client label alone**,
    /// because the context id is the caller's own choice:
    ///
    /// - a staged credential or an OAuth subject is its own namespace;
    /// - an identifiable anonymous client is `hash(client, context)`, so two
    ///   clients choosing the same context id never share state;
    /// - an anonymous client nobody can tell apart gets a FRESH random
    ///   namespace on every request. Its conversation cannot be continued,
    ///   which is the point: with no identity there is nothing to stop one
    ///   caller naming another's context id.
    pub(crate) fn session_key(&self, context: &str) -> String {
        match self {
            Caller::Bearer(key) | Caller::Oauth(key) => key.clone(),
            Caller::Anonymous {
                client: Some(client),
            } => {
                format!(
                    "{ANONYMOUS_PREFIX}{}",
                    digest_hex("session", &[client, context])
                )
            }
            Caller::Anonymous { client: None } => {
                format!(
                    "{ANONYMOUS_PREFIX}{}",
                    ulid::Ulid::new().to_string().to_ascii_lowercase()
                )
            }
        }
    }

    /// The staged credential id, when the caller used one. An OAuth subject
    /// and an anonymous caller are not credentials the designer issued, so a
    /// usage event may not name them as one.
    pub(crate) fn credential_id(&self) -> Option<&str> {
        match self {
            Caller::Bearer(id) => Some(id),
            Caller::Oauth(_) | Caller::Anonymous { .. } => None,
        }
    }

    pub(crate) fn is_anonymous(&self) -> bool {
        matches!(self, Caller::Anonymous { .. })
    }
}

/// 16 hex characters of a domain-separated SHA-256 over `parts`.
fn digest_hex(domain: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"greentic-interop-anonymous-v2\0");
    hasher.update(domain.as_bytes());
    for part in parts {
        hasher.update(b"\0");
        hasher.update(part.as_bytes());
    }
    hasher.finalize()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identifiable_anonymous_namespace_is_per_client_and_per_context() {
        let a = Caller::anonymous(Some("203.0.113.7"));
        let b = Caller::anonymous(Some("203.0.113.8"));
        assert_eq!(a.session_key("ctx"), a.session_key("ctx"), "continuable");
        assert_ne!(a.session_key("ctx"), a.session_key("other"));
        assert_ne!(
            a.session_key("ctx"),
            b.session_key("ctx"),
            "two clients, same context id"
        );
        let key = a.session_key("ctx");
        assert!(crate::interop::valid_caller_key(&key));
        assert!(key.starts_with(ANONYMOUS_PREFIX));
        assert!(!key.contains("203"));
        assert_eq!(a.credential_id(), None);
        assert!(a.is_anonymous());
        assert!(a.fairness_client().is_some());
        assert_eq!(a.bucket_key(), None);
    }

    #[test]
    fn an_unidentifiable_anonymous_caller_never_shares_or_continues_a_namespace() {
        let a = Caller::anonymous(None);
        let b = Caller::anonymous(None);
        assert_eq!(a, b, "indistinguishable by construction");
        let first = a.session_key("ctx");
        assert_ne!(first, a.session_key("ctx"), "fresh on every request");
        assert_ne!(first, b.session_key("ctx"));
        assert!(crate::interop::valid_caller_key(&first));
        assert!(first.starts_with(ANONYMOUS_PREFIX));
        assert_eq!(a.fairness_client(), None);
    }

    #[test]
    fn only_a_bearer_names_a_credential() {
        assert_eq!(Caller::Bearer("c1".into()).credential_id(), Some("c1"));
        assert_eq!(Caller::Oauth("u1".into()).credential_id(), None);
        assert_eq!(Caller::Oauth("u1".into()).session_key("x"), "u1");
        assert_eq!(Caller::Bearer("c1".into()).bucket_key(), Some("c1"));
    }
}
