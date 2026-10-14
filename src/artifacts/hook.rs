//! The one call the inbound path makes, between the approval intercept and
//! the turn, inside the task that runs after the HTTP ack (a download or a
//! PDF worker never delays a webhook's answer).

use greentic_types::ChannelMessageEnvelope;

use super::off::refuse_all;
use super::origin::Origin;
use super::provenance::strip_reserved;
use super::quota_key::conversation_key;
use super::unit::{Off, UnitAttachments};

/// Prepares every envelope of one inbound request. Host-only fields a
/// provider wrote are always removed, whatever the unit's decision; `None`
/// (a revision with no recorded decision) is a unit without a door.
pub(crate) async fn prepare(
    unit: Option<&UnitAttachments>,
    envelopes: &mut [ChannelMessageEnvelope],
    origin: &Origin,
) {
    for envelope in envelopes.iter_mut() {
        strip_reserved(envelope);
        match unit {
            Some(UnitAttachments::Enabled { pipeline, .. }) => {
                let key = conversation_key(envelope, origin);
                pipeline.process(envelope, key.as_deref(), origin).await;
            }
            Some(UnitAttachments::Off(off)) => refuse_all(envelope, *off),
            None => refuse_all(envelope, Off::NoDoor),
        }
    }
}
