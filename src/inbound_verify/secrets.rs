//! Reads a channel's verification secret where the provider component reads
//! it, so the host and the provider can never disagree about which value
//! verifies a request.
//!
//! The provider op runs with team `None` in the route's tenant
//! (`RunnerHost::invoke_provider_for_revision` builds that `ExecCtx`), and its
//! secrets host tries the UNIT scope (`<pack>_unit_<bundle>`) before the bare
//! pack scope (`greentic_runner_host::secrets::read_pack_secret_blocking`).
//! This module tries the same two scopes in the same order, each through
//! [`crate::runner_host::secret_read_uris`] (raw, then canonical spelling), so
//! a value the designer staged under either spelling of the pack id resolves.
//!
//! `NotFound` or an empty value moves on to the next candidate. Any other read
//! error, or a value that is not UTF-8, is UNAVAILABLE and stops the walk: a
//! store that failed has not shown the secret is missing, so the request must
//! not be treated as "not configured", and a failure in the unit scope must not
//! fall through to the bare scope (the provider's read does not either).
//! Nothing here logs: a read error's text can name the store, and the URIs are
//! not worth a line on a path an unauthenticated caller reaches.

use crate::secrets_gate::DynSecretsManager;

/// A secret value. `Debug` never prints it; nothing else here formats it.
pub(crate) struct ChannelSecret(String);

impl ChannelSecret {
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The value, for the MAC / comparison that consumes it. Never format it.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ChannelSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChannelSecret(<redacted>)")
    }
}

#[derive(Debug)]
pub(crate) enum SecretRead {
    Found(ChannelSecret),
    /// Every candidate answered `NotFound` or an empty value.
    Absent,
    /// The store failed, or held a value that is not text.
    Unavailable,
}

/// Every URI tried for `names`, in order: the unit scope for each name, then
/// the bare pack scope for each name.
pub(crate) fn candidate_uris(
    env: &str,
    tenant: &str,
    pack_id: &str,
    unit_id: &str,
    names: &[&str],
) -> Vec<String> {
    let unit_segment = greentic_runner_host::secrets::unit_pack_segment(pack_id, unit_id);
    let mut uris = Vec::new();
    let mut push_scope = |segment: &str| {
        for name in names {
            for uri in crate::runner_host::secret_read_uris(env, tenant, None, segment, name) {
                if !uris.contains(&uri) {
                    uris.push(uri);
                }
            }
        }
    };
    if let Some(segment) = unit_segment.as_deref() {
        push_scope(segment);
    }
    push_scope(pack_id);
    uris
}

/// The first non-empty value among [`candidate_uris`].
pub(crate) async fn read_channel_secret(
    secrets: &DynSecretsManager,
    env: &str,
    tenant: &str,
    pack_id: &str,
    unit_id: &str,
    names: &[&str],
) -> SecretRead {
    for uri in candidate_uris(env, tenant, pack_id, unit_id, names) {
        let bytes = match secrets.read(&uri).await {
            Ok(bytes) => bytes,
            Err(err) if is_not_found(&err) => continue,
            Err(_) => return SecretRead::Unavailable,
        };
        let Ok(value) = String::from_utf8(bytes) else {
            return SecretRead::Unavailable;
        };
        let value = value.trim();
        if !value.is_empty() {
            return SecretRead::Found(ChannelSecret::new(value));
        }
    }
    SecretRead::Absent
}

/// `NotFound`, or a wrapped error saying so (the dev store and the runner
/// host phrase it in text: [`crate::runner_host::is_secret_not_found`]).
fn is_not_found(err: &greentic_secrets_lib::SecretError) -> bool {
    matches!(err, greentic_secrets_lib::SecretError::NotFound(_))
        || crate::runner_host::is_secret_not_found(err)
}
