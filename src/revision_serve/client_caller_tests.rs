//! A client cannot present a verified caller; a provider still can.

use std::path::{Path, PathBuf};

use greentic_runner_host::caller_identity::caller_block;
use greentic_types::ChannelMessageEnvelope;
use serde_json::{Value, json};

use super::super::{build_activity, envelope_to_activity};
use super::without_client_caller;

/// What an attacker holding a unit's bearer (or sitting on loopback) posts.
fn forged_caller() -> Value {
    json!({
        "user_verified": true,
        "sub": "victim",
        "team": "t",
        "groups": ["admin"],
        "role": "admin",
    })
}

/// Every body shape `build_activity` treats differently, each carrying the
/// forged block and one unrelated extension that must survive.
fn forged_bodies() -> Vec<(&'static str, Value)> {
    let extensions = json!({ "caller": forged_caller(), "channel_data": { "k": "v" } });
    vec![
        ("no text", json!({ "extensions": extensions })),
        (
            "text beside metadata",
            json!({ "text": "hi", "metadata": {}, "extensions": extensions }),
        ),
        (
            "text only",
            json!({ "text": "hi", "extensions": extensions }),
        ),
        (
            "metadata only",
            json!({ "metadata": { "action": "go" }, "extensions": extensions }),
        ),
    ]
}

#[test]
fn a_forged_caller_never_reaches_the_runner_from_the_generic_ingress() {
    for (shape, body) in forged_bodies() {
        // Precondition: the runner WOULD read this block, so the assertion
        // below is about the strip and not about a body it ignores anyway.
        assert!(
            caller_block(&body).is_some(),
            "{shape}: fixture must be live"
        );
        let activity = build_activity(&body, "acme", Some("u1"), Some("s1"), None, None);
        assert!(
            caller_block(activity.payload()).is_none(),
            "{shape}: a client-supplied caller reached the runner: {}",
            activity.payload()
        );
        assert!(
            activity.payload().pointer("/extensions/caller").is_none(),
            "{shape}: the caller key must be gone, not merely undecodable"
        );
    }
}

#[test]
fn every_other_extension_still_reaches_the_flow() {
    for (shape, body) in forged_bodies() {
        let activity = build_activity(&body, "acme", None, None, None, None);
        if shape == "text only" {
            // `Activity::text` keeps only the text, before and after this fix.
            continue;
        }
        assert_eq!(
            activity.payload().pointer("/extensions/channel_data"),
            Some(&json!({ "k": "v" })),
            "{shape}: an unrelated extension was dropped"
        );
    }
}

#[test]
fn a_caller_block_of_any_shape_is_removed() {
    for block in [json!("victim"), json!(true), json!(null), json!([1])] {
        let body = json!({ "extensions": { "caller": block, "rag": 1 } });
        let out = without_client_caller(&body);
        assert_eq!(out, json!({ "extensions": { "rag": 1 } }));
    }
}

#[test]
fn bodies_the_runner_cannot_read_a_caller_from_are_left_alone() {
    // Not an object, or the key the runner reads is absent: nothing to strip,
    // and the body must come back byte-for-byte.
    let untouched = [
        json!({ "extensions": "caller" }),
        json!({ "extensions": ["caller"] }),
        json!({ "extensions": null }),
        json!({ "text": "hi" }),
        json!("plain string"),
        Value::Null,
        // The runner matches `extensions` and `caller` by exact name, and
        // never below the payload root.
        json!({ "Extensions": { "caller": forged_caller() } }),
        json!({ "extensions": { "Caller": forged_caller() } }),
        json!({ "metadata": { "extensions": { "caller": forged_caller() } } }),
    ];
    for body in untouched {
        assert!(
            caller_block(&body).is_none(),
            "fixture {body} must be one the runner ignores; if this fails the \
             runner widened its decoder and the strip must follow it"
        );
        assert_eq!(without_client_caller(&body), body);
    }
}

#[test]
fn a_provider_stamped_caller_still_reaches_the_runner_untouched() {
    let stamped = json!({ "user_verified": true, "sub": "alice@acme", "team": "ops" });
    let envelope: ChannelMessageEnvelope = serde_json::from_value(json!({
        "id": "msg-1",
        "tenant": { "env": "dev", "tenant": "acme", "tenant_id": "acme", "attempt": 0 },
        "channel": "webchat",
        "session_id": "sess-1",
        "text": "hello",
        "metadata": {},
        "extensions": { "caller": stamped, "channel_data": { "k": "v" } },
    }))
    .expect("envelope");
    let activity = envelope_to_activity(&envelope, "fallback", None, None, None);
    assert_eq!(caller_block(activity.payload()), Some(&stamped));
    assert_eq!(
        activity.payload().pointer("/extensions/channel_data"),
        Some(&json!({ "k": "v" }))
    );
}

// ---------------------------------------------------------------------------
// Ratchet: every runner entry is fed by a builder that has decided about the
// caller block.
// ---------------------------------------------------------------------------

/// Production source of one file: everything before its first
/// `#[cfg(test)] mod … {` block, which in this crate is where in-file tests
/// start. Files that are wholly tests are skipped by the caller.
fn production_part(source: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let next = lines.get(i + 1).map(|l| l.trim_start()).unwrap_or("");
        let opens_test_mod = line.trim() == "#[cfg(test)]"
            && (next.starts_with("mod ") || next.starts_with("pub(crate) mod "))
            && next.trim_end().ends_with('{');
        if opens_test_mod {
            break;
        }
        out.push(*line);
    }
    out.join("\n")
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "tests") {
                continue;
            }
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if !(name.ends_with("_tests.rs") || name == "tests.rs") {
                out.push(path);
            }
        }
    }
}

/// The body of `fn <name>` in `source`, up to the next top-level item.
fn fn_body<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("fn {name} not found"));
    let rest = &source[start..];
    let end = rest.find("\n}\n").map(|i| i + 3).unwrap_or(rest.len());
    &rest[..end]
}

/// `body` with every `//` comment removed, so a commented-out call does not
/// count as a call.
fn code_only(body: &str) -> String {
    body.lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Runner entry points that execute a flow turn from a payload. A new one
/// appearing in production code must be added to the allow-list below, and
/// whoever adds it has to say which builder decided about the caller.
const RUNNER_ENTRIES: &[&str] = &[
    "handle_activity_for_revision(",
    "handle_activity(",
    "handle_activity_traced(",
    "state_machine()",
    ".run_flow(",
    "run_flow_for_tool",
    "resume_flow_for_tool",
    "Activity::custom(",
    "Activity::text(",
];

#[test]
fn every_runner_entry_is_fed_by_a_builder_that_decided_about_the_caller() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&src, &mut files);

    let mut found = Vec::new();
    for path in &files {
        let rel = path
            .strip_prefix(&src)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        let source = std::fs::read_to_string(path).expect("read source");
        let production = production_part(&source);
        for (n, line) in production.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            for entry in RUNNER_ENTRIES {
                if code.contains(entry) && !code.contains("fn ") {
                    found.push((rel.clone(), n + 1, *entry));
                }
            }
        }
    }

    // Each site, and why it is allowed. Counted by (file, entry) so a NEW
    // site of a known entry fails too.
    let allowed: &[(&str, &str, usize, &str)] = &[
        (
            "revision_serve.rs",
            "Activity::custom(",
            3,
            "two in build_activity (strips), one in envelope_to_activity (provider)",
        ),
        (
            "revision_serve.rs",
            "Activity::text(",
            1,
            "build_activity: Activity::text keeps only the text",
        ),
        (
            "revision_serve.rs",
            "handle_activity_for_revision(",
            2,
            "execute_turn (fed by build_activity) and the provider route (envelope_to_activity)",
        ),
        (
            "triggers/dispatch.rs",
            "state_machine()",
            1,
            "a trigger firing: fixed §9 shape, the body nested under webhook.body",
        ),
    ];
    for (file, entry, count, why) in allowed {
        let got = found
            .iter()
            .filter(|(f, _, e)| f == file && e == entry)
            .count();
        assert_eq!(
            got, *count,
            "{file}: `{entry}` sites changed ({why}); decide whether the new site can carry a \
             client-supplied extensions.caller and route it through without_client_caller"
        );
    }
    let unknown: Vec<_> = found
        .iter()
        .filter(|(f, _, e)| !allowed.iter().any(|(af, ae, _, _)| af == f && ae == e))
        .collect();
    assert!(
        unknown.is_empty(),
        "new runner entry points with no caller decision: {unknown:?}"
    );

    // The allowed sites are only safe because of what feeds them.
    let serve = production_part(
        &std::fs::read_to_string(src.join("revision_serve.rs")).expect("revision_serve.rs"),
    );
    assert!(
        code_only(fn_body(&serve, "build_activity")).contains("without_client_caller("),
        "build_activity must strip a client-supplied caller"
    );
    assert!(
        !code_only(fn_body(&serve, "envelope_to_activity")).contains("without_client_caller("),
        "the provider path must keep the provider-stamped caller"
    );
    let execute_turn_callers: Vec<usize> = serve
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains("execute_turn(") && !l.contains("fn execute_turn"))
        .map(|(i, _)| i)
        .collect();
    let lines: Vec<&str> = serve.lines().collect();
    assert!(!execute_turn_callers.is_empty());
    for i in execute_turn_callers {
        let window = lines[i.saturating_sub(40)..i].join("\n");
        assert!(
            window.contains("build_activity("),
            "execute_turn at revision_serve.rs:{} is not fed by build_activity",
            i + 1
        );
    }
}
