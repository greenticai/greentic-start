//! Only the host may write what the runner reads as stored attachments.
//!
//! The runner treats `attachments[i].url = "artifact://…"`,
//! `extensions["artifacts"]` and `extensions["attachment_notes"]` as the
//! host's output: an `artifact://` url is read through the tenant-wide door,
//! and a note is shown to the agent. A provider writing any of them could
//! point the agent at another file of the tenant or put its own words in front
//! of the agent. So every one of them is removed BEFORE the pipeline runs;
//! whatever is there afterwards was written by this host.

use greentic_types::ChannelMessageEnvelope;
use reqwest::Url;

use super::ingest::{ARTIFACTS_KEY, NOTES_KEY};

const ARTIFACT_SCHEME: &str = "artifact";

/// Removes provider-written host fields. Returns how many attachment urls
/// were cleared (for a count-only log line). Leaves every other byte alone.
pub(crate) fn strip_reserved(envelope: &mut ChannelMessageEnvelope) -> usize {
    envelope.extensions.remove(ARTIFACTS_KEY);
    envelope.extensions.remove(NOTES_KEY);
    let mut cleared = 0;
    for attachment in &mut envelope.attachments {
        if attachment.url.as_deref().is_some_and(is_artifact_url) {
            attachment.url = None;
            cleared += 1;
        }
    }
    if cleared > 0 {
        tracing::warn!(
            cleared,
            "a provider sent artifact references the host did not create; they were removed"
        );
    }
    cleared
}

/// Any url whose scheme is `artifact`, however it is spelt: parsed as a URL
/// (which lowercases the scheme and drops leading control characters and
/// spaces), and by a case-insensitive prefix check after trimming, so no
/// spelling a lenient reader would accept gets through.
fn is_artifact_url(url: &str) -> bool {
    if Url::parse(url).is_ok_and(|u| u.scheme() == ARTIFACT_SCHEME) {
        return true;
    }
    let url = url.trim_start_matches(|c: char| c.is_whitespace() || c.is_control());
    url.get(..ARTIFACT_SCHEME.len() + 1)
        .is_some_and(|head| head.eq_ignore_ascii_case("artifact:"))
}
