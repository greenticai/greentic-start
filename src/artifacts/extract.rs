//! Text extraction for documents. Runs once at the host so every provider,
//! including one without vision, can read a document.
//!
//! Text formats are decoded here and capped at [`MAX_TEXT_CHARS`]. A PDF is
//! never parsed in this process: the parser is third-party code fed untrusted
//! bytes, and a 10 MiB PDF can inflate to gigabytes, so it runs in a separate,
//! resource-limited worker process (see [`super::pdf_isolation`]).

use super::limits::MAX_TEXT_CHARS;
use super::pdf_isolation;

/// `None` for anything that is not a document (images, unknown types);
/// `Some(text)`, possibly empty, for a document, at most [`MAX_TEXT_CHARS`]
/// characters long.
pub(crate) fn extract_text(bytes: &[u8], mime: &str) -> Option<String> {
    match mime {
        "text/plain" | "text/markdown" | "text/csv" | "application/json" => {
            Some(text_prefix(bytes, MAX_TEXT_CHARS))
        }
        "application/pdf" => Some(pdf_isolation::pdf_text(bytes)),
        _ => None,
    }
}

/// The first `max` characters of `bytes` as text, without leading byte-order
/// marks. Only the first `4 * max` bytes are decoded: a character is at most 4
/// bytes, so that prefix always holds `max` whole characters when the input
/// does, and a 10 MiB file is never turned into a 10 MiB string to keep 200k.
fn text_prefix(bytes: &[u8], max: usize) -> String {
    let mut bytes = bytes;
    while let Some(rest) = bytes.strip_prefix(b"\xEF\xBB\xBF") {
        bytes = rest;
    }
    let head = &bytes[..bytes.len().min(max.saturating_mul(4))];
    truncate_chars(&String::from_utf8_lossy(head), max)
}

/// `text` cut to at most `max` characters, on a character boundary.
pub(crate) fn truncate_chars(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((end, _)) => text[..end].to_string(),
        None => text.to_string(),
    }
}
