//! Host checklist 6: an envelope, an event, an `HttpIn`/`HttpOut` or a raw
//! request body is never written to a log line, at any level.
//!
//! An inbound envelope can carry inline file bytes (`attachments[i].content`,
//! `data_base64`) until the attachment pipeline clears them, and fetch
//! references whose `public` URL is a bearer-equivalent secret. A provider's
//! HTTP input carries raw upload bodies and headers. None of that may reach
//! `system.log`, stderr or the OTLP exporter, so this test reads the files on
//! the inbound path and refuses any log statement that formats one of those
//! values with `{:?}`, as a `tracing` `?field`, or through `serde_json`.
//! A log line names ids, counts and fixed codes only.

/// Every source file on the inbound path, from the HTTP listener to the turn.
const FILES: &[(&str, &str)] = &[
    ("revision_serve.rs", include_str!("../revision_serve.rs")),
    (
        "revision_serve/client_caller.rs",
        include_str!("../revision_serve/client_caller.rs"),
    ),
    (
        "revision_serve/fast2flow_hook.rs",
        include_str!("../revision_serve/fast2flow_hook.rs"),
    ),
    (
        "ingress_dispatch.rs",
        include_str!("../ingress_dispatch.rs"),
    ),
    (
        "http_ingress/mod.rs",
        include_str!("../http_ingress/mod.rs"),
    ),
    (
        "http_ingress/messaging.rs",
        include_str!("../http_ingress/messaging.rs"),
    ),
    (
        "http_ingress/messaging_turn.rs",
        include_str!("../http_ingress/messaging_turn.rs"),
    ),
    (
        "http_ingress/helpers.rs",
        include_str!("../http_ingress/helpers.rs"),
    ),
    (
        "http_ingress/limits.rs",
        include_str!("../http_ingress/limits.rs"),
    ),
    (
        "http_ingress/admin_relay.rs",
        include_str!("../http_ingress/admin_relay.rs"),
    ),
    (
        "http_ingress/flow_owner.rs",
        include_str!("../http_ingress/flow_owner.rs"),
    ),
    (
        "http_ingress/setup_gate.rs",
        include_str!("../http_ingress/setup_gate.rs"),
    ),
    (
        "approval_rail/mod.rs",
        include_str!("../approval_rail/mod.rs"),
    ),
    ("artifacts/activate.rs", include_str!("activate.rs")),
    ("artifacts/boot.rs", include_str!("boot.rs")),
    ("artifacts/client.rs", include_str!("client.rs")),
    ("artifacts/dns.rs", include_str!("dns.rs")),
    ("artifacts/drops.rs", include_str!("drops.rs")),
    ("artifacts/extract.rs", include_str!("extract.rs")),
    ("artifacts/fetch.rs", include_str!("fetch.rs")),
    ("artifacts/fetch_ref.rs", include_str!("fetch_ref.rs")),
    ("artifacts/hook.rs", include_str!("hook.rs")),
    ("artifacts/host_access.rs", include_str!("host_access.rs")),
    ("artifacts/host_policy.rs", include_str!("host_policy.rs")),
    ("artifacts/ingest.rs", include_str!("ingest.rs")),
    (
        "artifacts/instance_check.rs",
        include_str!("instance_check.rs"),
    ),
    ("artifacts/label.rs", include_str!("label.rs")),
    ("artifacts/legacy.rs", include_str!("legacy.rs")),
    ("artifacts/link.rs", include_str!("link.rs")),
    ("artifacts/link_base.rs", include_str!("link_base.rs")),
    ("artifacts/link_table.rs", include_str!("link_table.rs")),
    ("artifacts/off.rs", include_str!("off.rs")),
    ("artifacts/origin.rs", include_str!("origin.rs")),
    ("artifacts/outbound.rs", include_str!("outbound.rs")),
    (
        "artifacts/outbound_shape.rs",
        include_str!("outbound_shape.rs"),
    ),
    (
        "artifacts/pdf_isolation.rs",
        include_str!("pdf_isolation.rs"),
    ),
    ("artifacts/port.rs", include_str!("port.rs")),
    ("artifacts/provenance.rs", include_str!("provenance.rs")),
    ("artifacts/quota_key.rs", include_str!("quota_key.rs")),
    ("artifacts/recent_puts.rs", include_str!("recent_puts.rs")),
    ("artifacts/recovery.rs", include_str!("recovery.rs")),
    ("artifacts/secrets.rs", include_str!("secrets.rs")),
    ("artifacts/serve_link.rs", include_str!("serve_link.rs")),
    (
        "artifacts/serve_link_limits.rs",
        include_str!("serve_link_limits.rs"),
    ),
    ("artifacts/store.rs", include_str!("store.rs")),
    ("artifacts/unit.rs", include_str!("unit.rs")),
    ("artifacts/unserved.rs", include_str!("unserved.rs")),
    ("artifacts/wire.rs", include_str!("wire.rs")),
];

/// Values that carry message content, file bytes, access URLs or raw HTTP.
const PAYLOAD_NAMES: &[&str] = &[
    "envelope",
    "envelopes",
    "ingress",
    "ingress_envelopes",
    "event",
    "events",
    "http_in",
    "http_out",
    "entry",
    "payload",
    "body",
    "attachment",
    "attachments",
    "content",
    "activity",
    "output",
    "input_json",
    "request",
    "req",
];

const LOG_CALLS: &[&str] = &[
    "operator_log::trace(",
    "operator_log::debug(",
    "operator_log::info(",
    "operator_log::warn(",
    "operator_log::error(",
    "tracing::trace!(",
    "tracing::debug!(",
    "tracing::info!(",
    "tracing::warn!(",
    "tracing::error!(",
    "eprintln!(",
    "println!(",
];

/// The text of one call starting at `start`, up to its closing parenthesis.
/// String literals are skipped so a `(` inside a message does not count.
fn call_text(source: &str, start: usize) -> &str {
    let bytes = source.as_bytes();
    let mut depth = 0i32;
    let mut i = start;
    let mut in_str = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_str = false;
            }
        } else if b == b'"' {
            in_str = true;
        } else if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth -= 1;
            if depth == 0 {
                return &source[start..=i];
            }
        }
        i += 1;
    }
    &source[start..]
}

/// Top-level comma-separated arguments after the last string literal.
fn trailing_args(call: &str) -> Vec<String> {
    let after = call.rfind('"').map_or(call, |i| &call[i + 1..]);
    after
        .trim_end_matches(')')
        .split(',')
        .map(|arg| {
            arg.trim()
                .trim_start_matches('&')
                .trim_end_matches(".clone(")
                .to_string()
        })
        .filter(|arg| !arg.is_empty())
        .collect()
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// `?name` used as a `tracing` field value (`?envelope`, `x = ?envelope`).
fn has_debug_field(call: &str, name: &str) -> bool {
    let needle = format!("?{name}");
    call.match_indices(&needle).any(|(i, _)| {
        let before = call[..i].chars().next_back();
        let after = call[i + needle.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

/// Every offending log statement in `source`, as a short description.
fn offences(file: &str, source: &str) -> Vec<String> {
    let mut found = Vec::new();
    for marker in LOG_CALLS {
        for (start, _) in source.match_indices(marker) {
            let call = call_text(source, start);
            let line = source[..start].lines().count() + 1;
            let here = format!("{file}:{line}");
            if call.contains("serde_json::to_") {
                found.push(format!("{here}: serialises a value into a log line"));
            }
            let positional_debug = call.contains("{:?}") || call.contains("{:#?}");
            let args = trailing_args(call);
            for name in PAYLOAD_NAMES {
                if call.contains(&format!("{{{name}:?}}"))
                    || call.contains(&format!("{{{name}:#?}}"))
                {
                    found.push(format!("{here}: formats `{name}` with Debug"));
                }
                if has_debug_field(call, name) {
                    found.push(format!("{here}: records `{name}` as a Debug field"));
                }
                if positional_debug && args.iter().any(|arg| arg == name) {
                    found.push(format!("{here}: formats `{name}` with Debug"));
                }
            }
        }
    }
    found
}

#[test]
fn no_log_line_on_the_inbound_path_prints_an_envelope_or_an_http_payload() {
    let found: Vec<String> = FILES
        .iter()
        .flat_map(|(file, source)| offences(file, source))
        .collect();
    assert!(
        found.is_empty(),
        "log ids, counts and codes only:\n{}",
        found.join("\n")
    );
}

/// The ratchet itself must be able to fail: each shape it refuses is caught.
#[test]
fn the_ratchet_recognises_each_forbidden_shape() {
    for bad in [
        r#"operator_log::warn(module_path!(), format!("x {}", serde_json::to_string(entry).unwrap_or_default()));"#,
        r#"tracing::debug!(?envelope, "got one");"#,
        r#"tracing::info!(e = ?http_in, "in");"#,
        r#"operator_log::debug(module_path!(), format!("in {envelope:?}"));"#,
        r#"operator_log::debug(module_path!(), format!("out {:?}", &http_out));"#,
        r#"eprintln!("{:#?}", payload.clone());"#,
    ] {
        assert!(!offences("t.rs", bad).is_empty(), "not caught: {bad}");
    }
    for fine in [
        r#"operator_log::warn(module_path!(), format!("envelopes={}", envelopes.len()));"#,
        r#"tracing::info!(attachments = count, "inbound attachments ingested");"#,
        r#"operator_log::debug(module_path!(), format!("from={:?} id={}", env.from, env.id));"#,
        r#"tracing::warn!(?reason, "x");"#,
    ] {
        assert!(offences("t.rs", fine).is_empty(), "false positive: {fine}");
    }
}

/// The outbound link files: a log call there may not carry the request path,
/// the link, its MAC, a URL, the token or the artifact id, in any form.
const LINK_FILES: &[(&str, &str)] = &[
    ("artifacts/link.rs", include_str!("link.rs")),
    ("artifacts/link_base.rs", include_str!("link_base.rs")),
    ("artifacts/link_table.rs", include_str!("link_table.rs")),
    ("artifacts/serve_link.rs", include_str!("serve_link.rs")),
    ("artifacts/outbound.rs", include_str!("outbound.rs")),
    (
        "artifacts/outbound_shape.rs",
        include_str!("outbound_shape.rs"),
    ),
];

const LINK_SECRET_NAMES: &[&str] = &[
    "path",
    "link",
    "mac",
    "mac_hex",
    "url",
    "token",
    "artifact_id",
    "artifact_hex",
    "key",
];

fn link_offences(file: &str, source: &str) -> Vec<String> {
    let mut found = Vec::new();
    for marker in LOG_CALLS {
        for (start, _) in source.match_indices(marker) {
            let call = call_text(source, start);
            let line = source[..start].lines().count() + 1;
            let args = trailing_args(call);
            for name in LINK_SECRET_NAMES {
                let shapes = [
                    format!("{{{name}}}"),
                    format!("{{{name}:?}}"),
                    format!("%{name}"),
                    format!("?{name}"),
                    format!("{name}.to_path()"),
                ];
                let in_shape = shapes.iter().any(|shape| {
                    call.match_indices(shape.as_str()).any(|(i, _)| {
                        let after = call[i + shape.len()..].chars().next();
                        shape.ends_with('}') || shape.ends_with(')') || !after.is_some_and(is_ident)
                    })
                });
                if in_shape || args.iter().any(|arg| arg == name) {
                    found.push(format!("{file}:{line}: logs `{name}`"));
                }
            }
        }
    }
    found
}

#[test]
fn no_log_line_on_the_link_path_carries_a_link_or_a_secret() {
    let found: Vec<String> = LINK_FILES
        .iter()
        .flat_map(|(file, source)| link_offences(file, source))
        .collect();
    assert!(
        found.is_empty(),
        "ids, counts and codes only:\n{}",
        found.join("\n")
    );
}

#[test]
fn the_link_ratchet_recognises_each_forbidden_shape() {
    for bad in [
        r#"tracing::debug!(%path, "x");"#,
        r#"tracing::debug!(link = ?link, "x");"#,
        r#"operator_log::warn(module_path!(), format!("bad {mac_hex}"));"#,
        r#"operator_log::warn(module_path!(), format!("bad {}", url));"#,
        r#"tracing::warn!("{}", link.to_path());"#,
        r#"tracing::info!(id = %artifact_id, "x");"#,
    ] {
        assert!(!link_offences("t.rs", bad).is_empty(), "not caught: {bad}");
    }
    for fine in [
        r#"tracing::debug!(deployment = %unit.deployment, outcome = "served", "artifact link");"#,
        r#"tracing::warn!(deployment = %deployment, code, "refused");"#,
    ] {
        assert!(
            link_offences("t.rs", fine).is_empty(),
            "false positive: {fine}"
        );
    }
}
