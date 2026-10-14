//! Inbound attachment limits (master plan, Global Constraints).

/// Largest single attachment the host fetches or accepts inline.
pub(crate) const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
/// Attachments processed per message; any further slot gets a note.
pub(crate) const MAX_FILES: usize = 5;
/// Total bytes processed per message across all its attachments.
pub(crate) const MAX_MESSAGE_BYTES: u64 = 50 * 1024 * 1024;
/// Characters of extracted document text kept per document.
pub(crate) const MAX_TEXT_CHARS: usize = 200_000;
