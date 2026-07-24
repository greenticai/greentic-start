//! Discovery of `greentic.triggers.v1` trigger definitions from pack manifests.
//!
//! `parse_trigger_defs` is wired into the boot path in a later slice task
//! (wallclock trigger scheduler boot wiring); until then nothing outside this
//! module's tests calls these `pub` functions, so silence the resulting
//! dead-code lint the same way `timer_scheduler.rs` does for its own
//! pre-wiring functions.
#![allow(dead_code)]

use std::io::Read;

use anyhow::Context;
use greentic_triggers::{TriggerDef, validate_trigger};
use serde_json::Value as JsonValue;
use zip::ZipArchive;

use crate::discovery::DiscoveryResult;
use crate::operator_log;

/// Parse valid `TriggerDef`s from a decoded pack manifest's
/// `extensions."greentic.triggers.v1".triggers` array. Invalid defs are dropped
/// with an error log (fail-soft: one bad trigger never blocks the others).
pub fn trigger_defs_from_manifest(manifest: &JsonValue) -> Vec<TriggerDef> {
    let Some(array) = manifest
        .pointer("/extensions/greentic.triggers.v1/triggers")
        .and_then(JsonValue::as_array)
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in array {
        match serde_json::from_value::<TriggerDef>(entry.clone()) {
            Ok(def) => match validate_trigger(&def) {
                Ok(()) => out.push(def),
                Err(errs) => operator_log::error(
                    module_path!(),
                    format!("skipping invalid trigger '{}': {}", def.id, errs.join("; ")),
                ),
            },
            Err(err) => operator_log::error(
                module_path!(),
                format!("skipping unparseable trigger entry: {err}"),
            ),
        }
    }
    out
}

/// Walk discovered `events`-domain packs, decode each `manifest.cbor`, and
/// collect all declared `TriggerDef`s.
pub fn parse_trigger_defs(discovery: &DiscoveryResult) -> anyhow::Result<Vec<TriggerDef>> {
    let mut out = Vec::new();
    for provider in &discovery.providers {
        if provider.domain != "events" {
            continue;
        }
        let file = std::fs::File::open(&provider.pack_path)
            .with_context(|| format!("open pack {}", provider.pack_path.display()))?;
        let mut archive = ZipArchive::new(file).context("open pack zip")?;
        let mut bytes = Vec::new();
        archive
            .by_name("manifest.cbor")
            .context("manifest.cbor")?
            .read_to_end(&mut bytes)?;
        let manifest: JsonValue = serde_cbor::from_slice(&bytes).context("decode manifest.cbor")?;
        out.extend(trigger_defs_from_manifest(&manifest));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_trigger_defs_from_manifest_extension() {
        let manifest = serde_json::json!({
            "extensions": {
                "greentic.triggers.v1": {
                    "triggers": [
                        { "id": "daily_rent", "schedule": { "kind": "daily", "at": { "hour": 6, "minute": 0 } },
                          "emits": "cap://greentic/events/tenancy/rent",
                          "payload_template": { "at": "{{fire_time}}" } }
                    ]
                }
            }
        });
        let defs = trigger_defs_from_manifest(&manifest);
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].id, "daily_rent");
    }

    #[test]
    fn skips_invalid_trigger_defs() {
        let manifest = serde_json::json!({
            "extensions": { "greentic.triggers.v1": { "triggers": [
                { "id": "", "schedule": { "kind": "hourly", "minute": 99 }, "emits": "bad" }
            ] } }
        });
        assert!(
            trigger_defs_from_manifest(&manifest).is_empty(),
            "invalid trigger must be dropped"
        );
    }

    #[test]
    fn empty_when_no_extension() {
        assert!(trigger_defs_from_manifest(&serde_json::json!({})).is_empty());
    }
}
