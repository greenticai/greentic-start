//! The legacy `--bundle` path does not serve inbound attachments: there is no
//! per-unit door there. It treats every file as a unit without a door would
//! ([`refuse_all`] with [`Off::NoDoor`]): host-only fields a provider wrote are
//! removed (the runner would trust them), no fetch reference and no inline
//! byte is passed on, and each file reaches the agent as a fixed
//! `door_unavailable` note. Warned once per request.

use greentic_types::ChannelMessageEnvelope;

use super::off::refuse_all;
use super::provenance::strip_reserved;
use super::unit::Off;

/// Returns how many envelopes carried attachments (for the warning and tests).
pub(crate) fn declare_unserved(envelopes: &mut [ChannelMessageEnvelope]) -> usize {
    let mut with_attachments = 0;
    for envelope in envelopes.iter_mut() {
        strip_reserved(envelope);
        if !envelope.attachments.is_empty() {
            with_attachments += 1;
        }
        refuse_all(envelope, Off::NoDoor);
        // A slot without a fetch reference may still carry the request's own
        // bytes: they never travel on either.
        for attachment in &mut envelope.attachments {
            attachment.content = None;
        }
    }
    if with_attachments > 0 {
        crate::operator_log::warn(
            module_path!(),
            "inbound attachments are not served on the legacy --bundle path; each file is \
             reported to the agent as not read",
        );
    }
    with_attachments
}
