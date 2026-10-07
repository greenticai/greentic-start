//! Content sniffing for inbound attachments. The MIME type is decided from the
//! bytes alone; whatever the channel or the client declared is never an input.
//!
//! Allow-list (master plan, Global Constraints): PNG, JPEG, GIF, WebP, PDF,
//! plain text, Markdown, CSV and JSON. Everything else, SVG included, is
//! refused. A text file whose first meaningful character opens a tag (after any
//! mix of byte-order marks and whitespace) is markup — HTML, XML or SVG — and
//! is refused too, because that is exactly the prefix a browser sniffs.

use infer::MatcherType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Image,
    Document,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Detected {
    pub mime: &'static str,
    pub kind: Kind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rejection {
    Empty,
    Svg,
    Unsupported,
}

impl Rejection {
    /// Fixed, user-facing text; never derived from the file's content.
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Rejection::Empty => "the file is empty",
            Rejection::Svg => "SVG files are not accepted",
            Rejection::Unsupported => "this file type is not supported",
        }
    }
}

/// Classify `bytes` against the allow-list.
pub(crate) fn detect(bytes: &[u8]) -> Result<Detected, Rejection> {
    if bytes.is_empty() {
        return Err(Rejection::Empty);
    }
    if let Some(found) = infer::get(bytes) {
        // `infer`'s text matchers (HTML, XML, shell scripts) are decided by
        // the text rules below, so SVG is named as SVG and markup is refused
        // the same way whichever matcher saw it first.
        if found.matcher_type() == MatcherType::Text {
            return detect_text(bytes);
        }
        let image = |mime| {
            Ok(Detected {
                mime,
                kind: Kind::Image,
            })
        };
        return match found.mime_type() {
            "image/png" => image("image/png"),
            "image/jpeg" => image("image/jpeg"),
            "image/gif" => image("image/gif"),
            "image/webp" => image("image/webp"),
            "application/pdf" => Ok(Detected {
                mime: "application/pdf",
                kind: Kind::Document,
            }),
            _ => Err(Rejection::Unsupported),
        };
    }
    detect_text(bytes)
}

fn detect_text(bytes: &[u8]) -> Result<Detected, Rejection> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Err(Rejection::Unsupported);
    };
    if text.contains('\0') {
        return Err(Rejection::Unsupported);
    }
    let body = text.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    if body.starts_with('<') {
        return Err(if contains_ignore_ascii_case(body, "<svg") {
            Rejection::Svg
        } else {
            Rejection::Unsupported
        });
    }
    let doc = |mime| {
        Ok(Detected {
            mime,
            kind: Kind::Document,
        })
    };
    if (body.starts_with('{') || body.starts_with('['))
        && serde_json::from_str::<serde::de::IgnoredAny>(body).is_ok()
    {
        return doc("application/json");
    }
    if looks_like_csv(body) {
        return doc("text/csv");
    }
    if looks_like_markdown(body) {
        return doc("text/markdown");
    }
    doc("text/plain")
}

fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn looks_like_csv(text: &str) -> bool {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty()).take(5);
    let Some(first) = lines.next() else {
        return false;
    };
    let cols = first.matches(',').count();
    let rest: Vec<&str> = lines.collect();
    cols >= 1 && !rest.is_empty() && rest.iter().all(|l| l.matches(',').count() == cols)
}

fn looks_like_markdown(text: &str) -> bool {
    text.lines().take(50).any(|l| {
        let l = l.trim_start();
        l.starts_with("# ") || l.starts_with("## ") || l.starts_with("- ") || l.starts_with("```")
    })
}
