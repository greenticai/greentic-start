use super::extract::extract_text;
use super::limits::MAX_TEXT_CHARS;

#[test]
fn images_have_no_text() {
    assert_eq!(extract_text(&[0x89, b'P', b'N', b'G'], "image/png"), None);
    assert_eq!(extract_text(b"GIF89a", "image/gif"), None);
}

#[test]
fn an_unknown_mime_has_no_text() {
    assert_eq!(extract_text(b"<svg/>", "image/svg+xml"), None);
    assert_eq!(extract_text(b"hello", "application/octet-stream"), None);
}

#[test]
fn plain_markdown_csv_json_pass_through() {
    assert_eq!(
        extract_text(b"hello", "text/plain").as_deref(),
        Some("hello")
    );
    assert_eq!(
        extract_text(b"# T", "text/markdown").as_deref(),
        Some("# T")
    );
    assert_eq!(
        extract_text(b"a,b\n1,2", "text/csv").as_deref(),
        Some("a,b\n1,2")
    );
    assert_eq!(
        extract_text(br#"{"a":1}"#, "application/json").as_deref(),
        Some(r#"{"a":1}"#)
    );
}

#[test]
fn text_is_truncated_on_a_char_boundary() {
    let big = "é".repeat(MAX_TEXT_CHARS + 10);
    let out = extract_text(big.as_bytes(), "text/plain").unwrap();
    assert_eq!(out.chars().count(), MAX_TEXT_CHARS);
}

#[test]
fn truncation_never_leaves_a_replacement_character() {
    // One ASCII byte shifts every 4-byte character off the 4-byte grid, so a
    // byte-level cut lands inside a character.
    let big = format!("a{}", "😀".repeat(MAX_TEXT_CHARS + 10));
    let out = extract_text(big.as_bytes(), "text/plain").unwrap();
    assert_eq!(out.chars().count(), MAX_TEXT_CHARS);
    assert!(!out.contains('\u{fffd}'));
}

#[test]
fn short_text_is_kept_whole() {
    let text = "x".repeat(MAX_TEXT_CHARS);
    let out = extract_text(text.as_bytes(), "text/plain").unwrap();
    assert_eq!(out.len(), MAX_TEXT_CHARS);
}

#[test]
fn a_bom_is_stripped() {
    assert_eq!(
        extract_text("\u{feff}hi".as_bytes(), "text/plain").as_deref(),
        Some("hi")
    );
    assert_eq!(
        extract_text("\u{feff}\u{feff}hi".as_bytes(), "text/csv").as_deref(),
        Some("hi")
    );
}

#[test]
fn a_pdf_is_never_parsed_in_process() {
    // Unit tests never enable the worker (only the binary's entry point
    // does), so even a perfectly readable PDF yields no text here: the parser
    // only ever runs in the isolated worker process.
    let pdf = super::pdf_fixture::text_pdf("Hello attachment", 1);
    assert_eq!(extract_text(&pdf, "application/pdf").as_deref(), Some(""));
}
