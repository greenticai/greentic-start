//! The file label sent to the door and quoted in notes.

/// Longest label, in bytes, sent to the door (its limit is 255; the derived
/// text adds `.txt`).
const MAX_LABEL_BYTES: usize = 200;

/// A label safe for the door and for a note: the last path component, without
/// control or invisible format characters or leading dots, at most
/// [`MAX_LABEL_BYTES`] bytes; `attachment <n>` when nothing usable is left.
/// Mirrors the admin's name rule so the door never refuses it.
pub(crate) fn display_label(name: Option<&str>, index: usize) -> String {
    let last = name
        .unwrap_or_default()
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default();
    let kept: String = last
        .chars()
        .filter(|c| !c.is_control() && !is_invisible_format(*c))
        .collect();
    let cleaned = kept.trim().trim_start_matches('.').trim_start();
    let mut end = cleaned.len().min(MAX_LABEL_BYTES);
    while !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    let cut = cleaned[..end].trim_end();
    if cut.is_empty() {
        format!("attachment {}", index + 1)
    } else {
        cut.to_string()
    }
}

/// Bidi controls, zero-width characters and the BOM (the admin's list).
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}
