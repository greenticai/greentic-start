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
            "GREENTIC_SECRETS_TRACE: canonicalized secret name raw_len={} canonical_len={}",
            raw.len(),
            canonical.len()
        );
        eprintln!("backtrace:\n{:?}", Backtrace::capture());
    }
}

/// Convert a raw secret name (e.g. TELEGRAM_BOT_TOKEN) into the store-friendly
/// canonical form.
///
/// The normalization itself lives in `greentic-secrets`
/// ([`greentic_secrets_lib::canonical_secret_name`]) — the single
/// ecosystem-wide definition shared by start/setup/deployer so a producer and a
/// reader can never derive a name differently. This wrapper only adds the
/// opt-in `GREENTIC_SECRETS_TRACE` diagnostic around it.
pub fn canonical_secret_name(raw: &str) -> String {
    let canonical = greentic_secrets_lib::canonical_secret_name(raw);
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
