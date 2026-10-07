//! Which door a unit's artifacts go to, derived from its staged metering
//! block, and the boot probe that decides whether a revision may serve.
//!
//! Fail closed: a door that cannot be derived, would carry the token in
//! cleartext off the host, cannot be reached, or rejects the token refuses
//! activation with a message naming the door. There is no in-memory or
//! "attachments off" fallback for those; the only way a unit with a metering
//! block runs without attachments is the door saying `403 purpose_not_granted`, i.e. its token
//! never carried the `artifacts` purpose (the unit did not opt in).

use crate::interop::metering::MeteringConfig;
use crate::interop::metering::run_outcome::{SiblingDoorError, sibling_door};

use super::store::{ARTIFACTS_SEGMENT, ArtifactStore, StoreError};

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SelectError {
    #[error(
        "the metering endpoint `{0}` does not end in `/worker-usage`, so the artifacts door \
         beside it cannot be derived; refusing to serve"
    )]
    Endpoint(String),
    #[error(
        "the artifacts door `{0}` is not https and not loopback http; refusing to send a token \
         and refusing to serve"
    )]
    UnsafeEndpoint(String),
}

/// The door and the token to present to it.
pub(crate) struct Door {
    pub url: String,
    pub token: String,
}

impl std::fmt::Debug for Door {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Door")
            .field("url", &self.url)
            .field("token", &"[redacted]")
            .finish()
    }
}

/// The artifacts door beside the unit's worker-usage endpoint, or `None` when
/// the unit stages no metering block (it does not use artifacts).
pub(crate) fn door_for(metering: Option<&MeteringConfig>) -> Result<Option<Door>, SelectError> {
    let Some(metering) = metering else {
        return Ok(None);
    };
    let url = sibling_door(&metering.endpoint, ARTIFACTS_SEGMENT).map_err(|e| match e {
        SiblingDoorError::Unparseable | SiblingDoorError::NotWorkerUsage => {
            SelectError::Endpoint(metering.endpoint.clone())
        }
    })?;
    let url = url.trim_end_matches('/').to_string();
    if !is_safe(&url) {
        return Err(SelectError::UnsafeEndpoint(url));
    }
    Ok(Some(Door {
        url,
        token: metering.token.expose().to_string(),
    }))
}

/// `https`, or `http` whose HOST is loopback. Judged on the parsed URL, never
/// on a string prefix: `http://127.0.0.1.evil.example` and
/// `http://localhost@evil.example` are not loopback.
fn is_safe(url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(url) else {
        return false;
    };
    match url.scheme() {
        "https" => true,
        "http" => matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")),
        _ => false,
    }
}

/// What the boot probe found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DoorProbe {
    /// The door is up and the token carries the `artifacts` purpose.
    Enabled,
    /// The door answered `403 purpose_not_granted`: the token has no
    /// `artifacts` purpose, so this unit never asked for attachments. It
    /// activates without them (warned once, here).
    NotGranted,
}

/// Probe the door once at activation. Anything but the door's own `404
/// not_found` or `403 purpose_not_granted` refuses
/// activation: an unreachable door, a `401` (a bad token is a
/// misconfiguration, not an opt-out), a `5xx`. The error names the door and
/// never the token.
pub(crate) async fn probe_door(
    store: &dyn ArtifactStore,
    door_url: &str,
) -> anyhow::Result<DoorProbe> {
    match store.probe().await {
        Ok(()) => Ok(DoorProbe::Enabled),
        Err(StoreError::NotGranted) => {
            tracing::warn!(
                "this unit's credential carries no artifacts purpose; inbound attachments are \
                 disabled and each one is reported to the agent as not received"
            );
            Ok(DoorProbe::NotGranted)
        }
        Err(err) => Err(anyhow::anyhow!(
            "the artifacts door `{door_url}` is not usable: {err}; refusing to serve, because \
             inbound files would otherwise be lost without a trace"
        )),
    }
}
