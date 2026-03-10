#![allow(dead_code)]

use std::{backtrace::Backtrace, env};

#[inline]
fn should_trace() -> bool {
    env::var("GREENTIC_SECRETS_TRACE").as_deref() == Ok("1")
}

fn trace_if_needed(raw: &str, canonical: &str) {
    if !should_trace() {
        return;
    }
    if raw != canonical {
        eprintln!(
            "GREENTIC_SECRETS_TRACE: canonicalizing secret name raw={raw} canonical={canonical}"
        );
        eprintln!("backtrace:\n{:?}", Backtrace::capture());
    }
}

#[inline]
fn normalize_char(ch: char) -> Option<char> {
    match ch {
        'A'..='Z' => Some(ch.to_ascii_lowercase()),
        'a'..='z' | '0'..='9' | '_' => Some(ch),
        '-' | '.' | ' ' | '/' => Some('_'),
        _ => None,
    }
}

/// Convert a raw secret name (e.g. TELEGRAM_BOT_TOKEN) into the store-friendly canonical form.
pub fn canonical_secret_name(raw: &str) -> String {
    let mut result = String::with_capacity(raw.len());
    let mut prev_underscore = false;

    for ch in raw.chars() {
        if let Some(normalized) = normalize_char(ch) {
            if normalized == '_' {
                if prev_underscore {
                    continue;
                }
                prev_underscore = true;
            } else {
                prev_underscore = false;
            }
            result.push(normalized);
        }
    }

    let trimmed = result.trim_matches('_').to_string();
    let canonical = if trimmed.is_empty() {
        "secret".to_string()
    } else {
        trimmed
    };
    trace_if_needed(raw, &canonical);
    canonical
}

/// Apply [`canonical_secret_name`] to each segment of a slash-delimited key path.
pub fn canonical_secret_key_path(raw: &str) -> String {
    raw.split('/')
        .filter(|segment| !segment.trim().is_empty())
        .map(canonical_secret_name)
        .collect::<Vec<_>>()
        .join("/")
}
