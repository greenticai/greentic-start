//! Operator-chosen "allowed embedder origins" for the served WebChat page.
//!
//! The webchat pack (`messaging-webchat-gui`) declares an optional, non-secret
//! setup answer `allowed_embed_origins`. When an operator sets it, the chat
//! HTML page is served with `Content-Security-Policy: frame-ancestors 'self'
//! <origins>` and WITHOUT `X-Frame-Options` (browsers ignore the latter when
//! `frame-ancestors` is present, and an old `SAMEORIGIN` would only confuse
//! operators reading the headers). When the answer is absent or blank the
//! response is left exactly as it was: no framing header at all.
//!
//! Parsing is strict because the value is spliced into a header: an entry must
//! be a bare origin (`https://host[:port]`, or `http://localhost[:port]` for
//! local development) and anything else is dropped. A configured value with no
//! valid entry fails closed to `frame-ancestors 'self'` rather than silently
//! reverting to "anyone may frame".

use std::path::Path;

use http_body_util::Full;
use hyper::{
    Response,
    body::Bytes,
    header::{CONTENT_SECURITY_POLICY, CONTENT_TYPE, HeaderValue, X_FRAME_OPTIONS},
};
use serde_json::Value as JsonValue;

use crate::operator_log;
use crate::provider_config_envelope::read_provider_config_envelope;

/// Setup answer key declared by the webchat pack.
pub(crate) const ANSWER_KEY: &str = "allowed_embed_origins";

/// At most this many origins are honoured; extra entries are dropped.
const MAX_ORIGINS: usize = 20;

/// Outcome of reading the answer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AllowedOrigins {
    /// Normalised, valid origins in the order given, de-duplicated.
    pub(crate) origins: Vec<String>,
}

/// Parse the raw answer value (a string split on commas/whitespace, or an
/// array of strings). Returns `None` when nothing was configured (absent,
/// null, blank) so the caller leaves the response untouched. Returns `Some`
/// with possibly zero origins when something was configured but none of it was
/// valid.
pub(crate) fn parse_answer(value: &JsonValue) -> Option<AllowedOrigins> {
    let raw: Vec<String> = match value {
        JsonValue::String(text) => text
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|part| !part.is_empty())
            .map(str::to_string)
            .collect(),
        JsonValue::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => return None,
    };
    if raw.is_empty() {
        return None;
    }
    let mut origins: Vec<String> = Vec::new();
    for entry in &raw {
        match normalise_origin(entry) {
            Some(origin) => {
                if !origins.contains(&origin) && origins.len() < MAX_ORIGINS {
                    origins.push(origin);
                }
            }
            None => operator_log::warn(
                module_path!(),
                format!(
                    "[embed] ignoring invalid {ANSWER_KEY} entry ({} chars)",
                    entry.len()
                ),
            ),
        }
    }
    Some(AllowedOrigins { origins })
}

/// Validate one origin and return its canonical (lowercase) form.
///
/// Accepts `https://<dns-name>[:port]` and `http://localhost[:port]`. Rejects
/// wildcards, paths, queries, fragments, userinfo, IP literals, trailing
/// slashes and anything that is not plain ASCII host characters.
pub(crate) fn normalise_origin(input: &str) -> Option<String> {
    let lowered = input.trim().to_ascii_lowercase();
    let (scheme, rest) = if let Some(rest) = lowered.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = lowered.strip_prefix("http://") {
        ("http", rest)
    } else {
        return None;
    };
    let (host, port) = match rest.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (rest, None),
    };
    if let Some(port) = port {
        let digits_only = !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit());
        let value: u32 = port.parse().ok().filter(|_| digits_only)?;
        if value == 0 || value > 65535 || port.len() > 5 {
            return None;
        }
    }
    if scheme == "http" && host != "localhost" {
        return None;
    }
    if !valid_dns_name(host) {
        return None;
    }
    Some(match port {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    })
}

fn valid_dns_name(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    // An all-numeric final label would make this an IPv4 literal.
    if labels
        .last()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

impl AllowedOrigins {
    /// The `Content-Security-Policy` value for these origins.
    pub(crate) fn csp_value(&self) -> String {
        let mut value = String::from("frame-ancestors 'self'");
        for origin in &self.origins {
            value.push(' ');
            value.push_str(origin);
        }
        value
    }
}

/// Read the answer for `pack_id` from the revision's provider config envelope,
/// falling back to the wizard's `setup-answers.json` (the same two sources the
/// per-tenant webchat config is synthesised from).
pub(crate) fn read_for_pack(bundle_root: &Path, pack_id: &str) -> Option<AllowedOrigins> {
    let providers_root = bundle_root.join(".providers");
    let config = read_provider_config_envelope(&providers_root, pack_id)
        .ok()
        .flatten()
        .map(|envelope| envelope.config)
        .or_else(|| {
            let path = bundle_root
                .join("state")
                .join("config")
                .join(pack_id)
                .join("setup-answers.json");
            let bytes = std::fs::read(path).ok()?;
            serde_json::from_slice::<JsonValue>(&bytes).ok()
        })?;
    parse_answer(config.get(ANSWER_KEY)?)
}

/// Apply the framing policy to an HTML response. Non-HTML responses (scripts,
/// JSON, images) and non-success statuses are returned unchanged.
pub(crate) fn apply(
    mut response: Response<Full<Bytes>>,
    allowed: &AllowedOrigins,
) -> Response<Full<Bytes>> {
    let is_html = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().starts_with("text/html"));
    if !is_html || !response.status().is_success() {
        return response;
    }
    if let Ok(value) = HeaderValue::from_str(&allowed.csp_value()) {
        response
            .headers_mut()
            .insert(CONTENT_SECURITY_POLICY, value);
        response.headers_mut().remove(X_FRAME_OPTIONS);
    }
    response
}

#[cfg(test)]
#[path = "embed_origins_tests.rs"]
mod tests;
