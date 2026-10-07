//! The legacy `--bundle` path does not serve inbound attachments: there is no
//! per-unit door there. It still removes host-only fields a provider wrote
//! (the runner would trust them), and says once per request that attachments
//! pass through unchanged.

use greentic_types::ChannelMessageEnvelope;

use super::provenance::strip_reserved;

/// Returns how many envelopes carried attachments (for the warning and tests).
pub(crate) fn declare_unserved(envelopes: &mut [ChannelMessageEnvelope]) -> usize {
    let mut with_attachments = 0;
    for envelope in envelopes.iter_mut() {
        strip_reserved(envelope);
        if !envelope.attachments.is_empty() {
            with_attachments += 1;
        }
    }
    if with_attachments > 0 {
        crate::operator_log::warn(
            module_path!(),
            "inbound attachments are not served on the legacy --bundle path; they are passed \
             through unchanged",
        );
    }
    with_attachments
}
