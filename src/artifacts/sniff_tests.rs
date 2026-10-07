use super::sniff::*;

const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0];

#[test]
fn png_is_an_image() {
    let d = detect(PNG).unwrap();
    assert_eq!(d.mime, "image/png");
    assert!(matches!(d.kind, Kind::Image));
}

#[test]
fn jpeg_gif_webp_are_images() {
    assert_eq!(
        detect(&[0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10]).unwrap().mime,
        "image/jpeg"
    );
    assert_eq!(detect(b"GIF89a\x01\x00\x01\x00").unwrap().mime, "image/gif");
    let mut webp = b"RIFF\x24\0\0\0WEBPVP8 ".to_vec();
    webp.extend_from_slice(&[0; 8]);
    assert_eq!(detect(&webp).unwrap().mime, "image/webp");
}

#[test]
fn pdf_is_a_document() {
    let d = detect(b"%PDF-1.7\n1 0 obj").unwrap();
    assert_eq!(d.mime, "application/pdf");
    assert!(matches!(d.kind, Kind::Document));
}

#[test]
fn svg_is_rejected_even_when_it_looks_like_text() {
    let svg = br#"<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>"#;
    assert!(matches!(detect(svg), Err(Rejection::Svg)));
    assert!(matches!(
        detect(b"<svg viewBox='0 0 1 1'/>"),
        Err(Rejection::Svg)
    ));
}

#[test]
fn html_is_rejected() {
    assert!(matches!(
        detect(b"<!DOCTYPE html><html></html>"),
        Err(Rejection::Unsupported)
    ));
}

#[test]
fn json_is_detected_by_parsing_not_by_name() {
    assert_eq!(
        detect(br#"{"a": [1, 2]}"#).unwrap().mime,
        "application/json"
    );
}

#[test]
fn csv_and_markdown_and_plain_text() {
    assert_eq!(detect(b"a,b,c\n1,2,3\n4,5,6\n").unwrap().mime, "text/csv");
    assert_eq!(
        detect(b"# Title\n\nSome *text*.\n").unwrap().mime,
        "text/markdown"
    );
    assert_eq!(detect(b"just a sentence.").unwrap().mime, "text/plain");
}

#[test]
fn binary_junk_and_empty_are_rejected() {
    assert!(matches!(detect(&[]), Err(Rejection::Empty)));
    assert!(matches!(
        detect(&[0, 1, 2, 3, 0xFE, 0xFF, 0x80]),
        Err(Rejection::Unsupported)
    ));
}

// --- Polyglots and evasions -------------------------------------------------

#[test]
fn markup_behind_a_bom_and_whitespace_is_rejected() {
    let html = "\u{feff} \r\n\t<html><body>x</body></html>";
    assert!(matches!(
        detect(html.as_bytes()),
        Err(Rejection::Unsupported)
    ));
    let svg = "\u{feff}\n\n   <svg onload=alert(1)>";
    assert!(matches!(detect(svg.as_bytes()), Err(Rejection::Svg)));
    // A BOM after the whitespace, and several BOMs, change nothing.
    let svg = " \u{feff}\u{feff} <svg/>";
    assert!(matches!(detect(svg.as_bytes()), Err(Rejection::Svg)));
}

#[test]
fn svg_behind_a_long_comment_is_still_svg() {
    let mut doc = String::from("<!--");
    doc.push_str(&"x".repeat(4096));
    doc.push_str("--><SVG xmlns='http://www.w3.org/2000/svg'></SVG>");
    assert!(matches!(detect(doc.as_bytes()), Err(Rejection::Svg)));
}

#[test]
fn any_text_opening_with_markup_is_rejected() {
    for doc in [
        "<?xml version='1.0'?><note/>",
        "<!-- a comment -->",
        "<script>alert(1)</script>",
        "<iframe src=x>",
        "<p>hi</p>",
        "<a href=x>",
        "<!doctype html>",
    ] {
        assert!(
            matches!(detect(doc.as_bytes()), Err(Rejection::Unsupported)),
            "accepted {doc:?}"
        );
    }
}

#[test]
fn text_mentioning_svg_later_is_still_text() {
    // Only a leading tag makes a file markup; prose about SVG is not an SVG.
    let md = b"# Icons\n\nWe draw them with an <svg> element.\n";
    assert_eq!(detect(md).unwrap().mime, "text/markdown");
}

#[test]
fn utf16_and_invalid_utf8_text_is_rejected() {
    let utf16 = [0xFF, 0xFE, b'<', 0, b's', 0, b'v', 0, b'g', 0];
    assert!(matches!(detect(&utf16), Err(Rejection::Unsupported)));
    assert!(matches!(detect(b"caf\xe9"), Err(Rejection::Unsupported)));
}

#[test]
fn text_with_a_nul_byte_is_rejected() {
    assert!(matches!(
        detect(b"hello\0world"),
        Err(Rejection::Unsupported)
    ));
}

#[test]
fn other_binary_formats_are_not_on_the_allow_list() {
    let zip = b"PK\x03\x04\x14\x00\x00\x00\x08\x00";
    assert!(matches!(detect(zip), Err(Rejection::Unsupported)));
    let elf = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    assert!(matches!(detect(elf), Err(Rejection::Unsupported)));
    let bmp = b"BM\x3a\0\0\0\0\0\0\0\x36\0\0\0\x28\0\0\0";
    assert!(matches!(detect(bmp), Err(Rejection::Unsupported)));
}

#[test]
fn a_json_lookalike_that_does_not_parse_is_plain_text() {
    assert_eq!(detect(b"{ not json").unwrap().mime, "text/plain");
}

#[test]
fn rejections_have_fixed_descriptions() {
    assert_eq!(Rejection::Svg.describe(), "SVG files are not accepted");
    assert_eq!(
        Rejection::Unsupported.describe(),
        "this file type is not supported"
    );
    assert_eq!(Rejection::Empty.describe(), "the file is empty");
}
