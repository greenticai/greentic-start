//! The pack's own routing settings: `assets/fast2flow.json`.
//!
//! A pack that opts into Fast2Flow may ship this file beside its
//! `assets/intent-index.json` (the designer writes both for a channel router):
//!
//! ```json
//! { "schema": "greentic.fast2flow-config.v1", "strategy": "bm25", "min_confidence": 0.2 }
//! ```
//!
//! Only `min_confidence` is applied. The routing host reads its threshold from
//! the process environment (`FAST2FLOW_MIN_CONFIDENCE`, default 0.5), which a
//! container deployment cannot set per pack, so without this the value a pack
//! author chose was never seen and every score between the author's threshold
//! and 0.5 was a routing miss. `strategy` is left alone: the embedded LLM tier
//! is configured elsewhere (`llm:` in the bundle config).
//!
//! Precedence: an operator who sets `FAST2FLOW_MIN_CONFIDENCE` on the process
//! keeps it — that is an explicit override for the whole deployment — and the
//! pack value fills the gap only when the variable is unset or empty.

use std::path::Path;

/// The pack entry the settings are read from.
const PACK_CONFIG_ENTRY: &str = "assets/fast2flow.json";

/// The only schema this reader understands.
const SCHEMA: &str = "greentic.fast2flow-config.v1";

/// The routing host's threshold variable (`fast2flow-routing-gtpack` config).
pub(crate) const ENV_MIN_CONFIDENCE: &str = "FAST2FLOW_MIN_CONFIDENCE";

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct PackRouting {
    pub min_confidence: Option<f32>,
}

#[derive(serde::Deserialize)]
struct Raw {
    schema: Option<String>,
    min_confidence: Option<f64>,
}

/// The pack's settings. `Ok(None)`: no pack file or no settings entry, which is
/// every pack that never shipped one. `Err`: the entry exists and cannot be
/// used — reported by the caller, and the host then runs on its own defaults.
pub(crate) fn read(pack_path: &Path) -> Result<Option<PackRouting>, String> {
    let Ok(file) = std::fs::File::open(pack_path) else {
        return Ok(None);
    };
    let Ok(mut archive) = zip::ZipArchive::new(file) else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    match archive.by_name(PACK_CONFIG_ENTRY) {
        Ok(mut entry) => std::io::Read::read_to_end(&mut entry, &mut bytes)
            .map_err(|e| format!("read {PACK_CONFIG_ENTRY}: {e}"))?,
        Err(_) => return Ok(None),
    };
    parse(&bytes).map(Some)
}

fn parse(bytes: &[u8]) -> Result<PackRouting, String> {
    let raw: Raw = serde_json::from_slice(bytes)
        .map_err(|e| format!("{PACK_CONFIG_ENTRY} is not valid JSON: {e}"))?;
    if let Some(schema) = raw.schema.as_deref()
        && schema != SCHEMA
    {
        return Err(format!(
            "{PACK_CONFIG_ENTRY} declares schema `{schema}`, expected `{SCHEMA}`"
        ));
    }
    let min_confidence = match raw.min_confidence {
        None => None,
        Some(v) if v.is_finite() && (0.0..=1.0).contains(&v) => Some(v as f32),
        Some(v) => {
            return Err(format!(
                "{PACK_CONFIG_ENTRY} min_confidence {v} is outside 0..=1"
            ));
        }
    };
    Ok(PackRouting { min_confidence })
}

/// Extra environment for the routing host spawned for `pack_path`.
///
/// Empty when the operator already pinned the threshold on the process (their
/// value reaches the host through the inherited environment) or when the pack
/// carries none.
pub(crate) fn host_env(
    routing: Option<PackRouting>,
    operator_value: Option<&str>,
) -> Vec<(String, String)> {
    if operator_value.is_some_and(|v| !v.trim().is_empty()) {
        return Vec::new();
    }
    routing
        .and_then(|r| r.min_confidence)
        .map(|v| vec![(ENV_MIN_CONFIDENCE.to_string(), v.to_string())])
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn pack_with(entries: &[(&str, &str)]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("p.gtpack");
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&path).expect("create"));
        for (name, body) in entries {
            zip.start_file(*name, zip::write::SimpleFileOptions::default())
                .expect("start");
            zip.write_all(body.as_bytes()).expect("write");
        }
        zip.finish().expect("finish");
        (dir, path)
    }

    #[test]
    fn a_pack_threshold_is_read() {
        let (_d, p) = pack_with(&[(
            "assets/fast2flow.json",
            r#"{"schema":"greentic.fast2flow-config.v1","strategy":"bm25","min_confidence":0.2}"#,
        )]);
        let got = read(&p).expect("ok").expect("some");
        assert_eq!(got.min_confidence, Some(0.2));
    }

    #[test]
    fn a_pack_without_the_entry_or_a_pack_that_is_not_a_zip_has_no_settings() {
        let (_d, p) = pack_with(&[("assets/intent-index.json", "{}")]);
        assert_eq!(read(&p), Ok(None));
        assert_eq!(read(Path::new("/definitely/not/a/pack")), Ok(None));
    }

    #[test]
    fn an_unusable_entry_is_an_error_not_a_silent_default() {
        for body in [
            "not json",
            r#"{"schema":"other.v9","min_confidence":0.2}"#,
            r#"{"min_confidence":1.5}"#,
            r#"{"min_confidence":-0.1}"#,
        ] {
            let (_d, p) = pack_with(&[("assets/fast2flow.json", body)]);
            assert!(read(&p).is_err(), "{body}");
        }
    }

    #[test]
    fn a_file_without_a_threshold_leaves_the_host_default() {
        let (_d, p) = pack_with(&[("assets/fast2flow.json", r#"{"strategy":"bm25"}"#)]);
        let got = read(&p).expect("ok");
        assert_eq!(host_env(got, None), Vec::<(String, String)>::new());
    }

    #[test]
    fn the_pack_value_fills_the_gap_and_an_operator_value_wins() {
        let routing = Some(PackRouting {
            min_confidence: Some(0.2),
        });
        assert_eq!(
            host_env(routing, None),
            vec![(ENV_MIN_CONFIDENCE.to_string(), "0.2".to_string())]
        );
        assert_eq!(
            host_env(routing, Some("  ")),
            vec![(ENV_MIN_CONFIDENCE.to_string(), "0.2".to_string())],
            "an empty variable is not an operator choice"
        );
        assert!(host_env(routing, Some("0.6")).is_empty());
    }
}
