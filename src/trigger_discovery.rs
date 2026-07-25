//! Discovery of `greentic.triggers.v1` trigger definitions from pack manifests.

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

    // Focused seam test for the boot-path glue (open pack zip -> decode
    // manifest.cbor -> delegate to `trigger_defs_from_manifest`, mirroring
    // `timer_scheduler::discover_timer_handlers`). A full live-runner smoke
    // (real `WallClockScheduler` thread firing a trigger and delivering it via
    // `event_router::route_event_to_subscribers` to a subscribed flow) is
    // deferred: it would need a real flow execution through the runner
    // engine, which is exactly the flaky, slow surface Tasks 1-10 already
    // isolated behind unit-tested deterministic seams (`envelope_for`,
    // `trigger_defs_from_manifest`, `SorxAppendClient::events_url`, the
    // `event_router` subscriber-selection tests). This test covers the one
    // seam those tasks could not: the zip/CBOR discovery glue itself.
    #[test]
    fn parse_trigger_defs_reads_manifest_cbor_from_pack_zip() {
        use std::io::Write;

        use tempfile::tempdir;
        use zip::write::FileOptions;

        use crate::discovery::{
            DetectedDomains, DetectedProvider, DiscoveryResult, ProviderIdSource,
        };

        let dir = tempdir().expect("tempdir");
        let pack_path = dir.path().join("events-tick.gtpack");
        let manifest = serde_json::json!({
            "extensions": {
                "greentic.triggers.v1": {
                    "triggers": [
                        { "id": "every_minute_tick", "schedule": { "kind": "every_minute" },
                          "emits": "cap://greentic/events/tenancy/tick",
                          "payload_template": {} }
                    ]
                }
            }
        });
        let manifest_cbor = serde_cbor::to_vec(&manifest).expect("encode manifest.cbor");
        let file = std::fs::File::create(&pack_path).expect("create pack");
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file("manifest.cbor", FileOptions::<()>::default())
            .expect("start manifest.cbor entry");
        zip.write_all(&manifest_cbor).expect("write manifest.cbor");
        zip.finish().expect("finish pack");

        let discovery = DiscoveryResult {
            domains: DetectedDomains {
                messaging: false,
                events: true,
                oauth: false,
            },
            providers: vec![DetectedProvider {
                provider_id: "events-tick".to_string(),
                domain: "events".to_string(),
                pack_path,
                id_source: ProviderIdSource::Manifest,
            }],
        };

        let defs = parse_trigger_defs(&discovery).expect("parse trigger defs");
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].id, "every_minute_tick");
    }
}
