//! Watch config model + bundle loader for the threshold watcher.
//!
//! A bundle declares zero or more watches in `threshold-watchers.yaml` at the
//! bundle root, under a top-level `watches:` list. [`load_watches`] reads and
//! validates that file; a missing file or a parse error yields an empty
//! `Vec` (never panics), and any individual watch that fails [`validate`] is
//! skipped (with a `warn` log) so one bad entry doesn't drop the rest.

use std::path::Path;

use serde::Deserialize;

use super::eval::{Comparator, EdgeDirection};

/// Where to fetch the metric from and how to extract the numeric value.
#[derive(Debug, Clone, Deserialize)]
pub struct MetricSource {
    pub url: String,
    pub json_path: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

/// A single threshold watch: poll `source` on `interval_seconds`, compare
/// the extracted value against `threshold` using `comparator`, and fire on
/// an edge crossing matching `direction`.
#[derive(Debug, Clone, Deserialize)]
pub struct ThresholdWatchConfig {
    pub name: String,
    pub tenant: String,
    #[serde(default)]
    pub team: Option<String>,
    pub source: MetricSource,
    pub comparator: Comparator,
    pub threshold: f64,
    pub direction: EdgeDirection,
    pub interval_seconds: u64,
    /// The emitted event's `event_type`. This is the user contract: a flow fires
    /// on a crossing iff its pack-manifest `subscribes_to` matches this string
    /// (exact or glob, e.g. `metric.inventory_low.crossed` / `metric.*`).
    pub topic: String,
}

#[derive(Debug, Deserialize)]
struct ThresholdWatchersFile {
    #[serde(default)]
    watches: Vec<ThresholdWatchConfig>,
}

impl ThresholdWatchConfig {
    /// Validate the watch's static configuration.
    ///
    /// Checks: `name`/`tenant`/`source.url`/`source.json_path`/`topic` are
    /// non-empty, `name`/`tenant` are free of path separators/traversal (they
    /// compose the state-file path), `interval_seconds >= 1`, and `threshold`
    /// is finite (not NaN/infinite).
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("name must not be empty".to_string());
        }
        if self.tenant.trim().is_empty() {
            return Err("tenant must not be empty".to_string());
        }
        // `tenant` and `name` compose the durable state path
        // (`{state_dir}/threshold/{tenant}/{name}.json`); reject path separators
        // and traversal so a watch cannot escape the state directory.
        for (field, value) in [("name", &self.name), ("tenant", &self.tenant)] {
            if value.contains('/') || value.contains('\\') || value.contains("..") {
                return Err(format!("{field} must not contain '/', '\\', or '..'"));
            }
        }
        if self.source.url.trim().is_empty() {
            return Err("source.url must not be empty".to_string());
        }
        if self.source.json_path.trim().is_empty() {
            return Err("source.json_path must not be empty".to_string());
        }
        if self.topic.trim().is_empty() {
            return Err("topic must not be empty".to_string());
        }
        if self.interval_seconds < 1 {
            return Err("interval_seconds must be >= 1".to_string());
        }
        if !self.threshold.is_finite() {
            return Err("threshold must be a finite number".to_string());
        }
        Ok(())
    }
}

/// Load and validate the watches declared in `{bundle_root}/threshold-watchers.yaml`.
///
/// - Missing file -> empty `Vec` (the watcher simply doesn't start; this is
///   the expected shape for bundles that don't use this feature).
/// - Parse error -> logs a `warn` and returns an empty `Vec`.
/// - Any individual watch failing [`ThresholdWatchConfig::validate`] is
///   skipped (with a `warn`) so one bad entry doesn't drop the rest.
pub fn load_watches(bundle_root: &Path) -> Vec<ThresholdWatchConfig> {
    let path = bundle_root.join("threshold-watchers.yaml");
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(_) => return Vec::new(),
    };
    let parsed: ThresholdWatchersFile = match serde_yaml_bw::from_str(&contents) {
        Ok(parsed) => parsed,
        Err(err) => {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "failed to parse threshold-watchers.yaml; no watches loaded"
            );
            return Vec::new();
        }
    };
    parsed
        .watches
        .into_iter()
        .filter(|watch| match watch.validate() {
            Ok(()) => true,
            Err(reason) => {
                tracing::warn!(
                    name = %watch.name,
                    tenant = %watch.tenant,
                    reason = %reason,
                    "skipping invalid threshold watch"
                );
                false
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_yaml() -> &'static str {
        r#"watches:
  - name: cpu-high
    tenant: acme
    team: ops
    source:
      url: https://example.com/metrics
      json_path: $.cpu.percent
      headers:
        - [Authorization, Bearer abc]
    comparator: gt
    threshold: 90.0
    direction: rising
    interval_seconds: 30
    topic: alerts.cpu
"#
    }

    #[test]
    fn load_watches_parses_valid_yaml() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp.path().join("threshold-watchers.yaml"), valid_yaml())
            .expect("write watchers yaml");

        let watches = load_watches(temp.path());

        assert_eq!(watches.len(), 1);
        let watch = &watches[0];
        assert_eq!(watch.name, "cpu-high");
        assert_eq!(watch.tenant, "acme");
        assert_eq!(watch.team.as_deref(), Some("ops"));
        assert_eq!(watch.source.url, "https://example.com/metrics");
        assert_eq!(watch.source.json_path, "$.cpu.percent");
        assert_eq!(
            watch.source.headers,
            vec![("Authorization".to_string(), "Bearer abc".to_string())]
        );
        assert_eq!(watch.comparator, Comparator::Gt);
        assert_eq!(watch.threshold, 90.0);
        assert_eq!(watch.direction, EdgeDirection::Rising);
        assert_eq!(watch.interval_seconds, 30);
        assert_eq!(watch.topic, "alerts.cpu");
    }

    #[test]
    fn load_watches_missing_file_returns_empty() {
        let temp = tempfile::tempdir().expect("tempdir");

        let watches = load_watches(temp.path());

        assert!(watches.is_empty());
    }

    #[test]
    fn load_watches_parse_error_returns_empty() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            temp.path().join("threshold-watchers.yaml"),
            "not: [valid, yaml: structure\n",
        )
        .expect("write malformed yaml");

        let watches = load_watches(temp.path());

        assert!(watches.is_empty());
    }

    #[test]
    fn load_watches_skips_invalid_entry_keeps_valid_ones() {
        let temp = tempfile::tempdir().expect("tempdir");
        let yaml = format!(
            r#"watches:
  - name: ''
    tenant: acme
    source:
      url: https://example.com/metrics
      json_path: $.cpu.percent
    comparator: gt
    threshold: 90.0
    direction: rising
    interval_seconds: 30
    topic: alerts.cpu
{}"#,
            valid_yaml().strip_prefix("watches:\n").expect("prefix")
        );
        std::fs::write(temp.path().join("threshold-watchers.yaml"), yaml)
            .expect("write watchers yaml");

        let watches = load_watches(temp.path());

        assert_eq!(watches.len(), 1);
        assert_eq!(watches[0].name, "cpu-high");
    }

    fn base_watch() -> ThresholdWatchConfig {
        ThresholdWatchConfig {
            name: "cpu-high".to_string(),
            tenant: "acme".to_string(),
            team: None,
            source: MetricSource {
                url: "https://example.com/metrics".to_string(),
                json_path: "$.cpu.percent".to_string(),
                headers: Vec::new(),
            },
            comparator: Comparator::Gt,
            threshold: 90.0,
            direction: EdgeDirection::Rising,
            interval_seconds: 30,
            topic: "alerts.cpu".to_string(),
        }
    }

    #[test]
    fn validate_accepts_well_formed_watch() {
        assert!(base_watch().validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_url() {
        let mut watch = base_watch();
        watch.source.url = String::new();
        assert!(watch.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_interval() {
        let mut watch = base_watch();
        watch.interval_seconds = 0;
        assert!(watch.validate().is_err());
    }

    #[test]
    fn validate_rejects_non_finite_threshold() {
        let mut watch = base_watch();
        watch.threshold = f64::NAN;
        assert!(watch.validate().is_err());

        let mut watch = base_watch();
        watch.threshold = f64::INFINITY;
        assert!(watch.validate().is_err());
    }

    #[test]
    fn validate_rejects_path_traversal_in_name_or_tenant() {
        for bad in ["../etc", "a/b", "a\\b", ".."] {
            let mut watch = base_watch();
            watch.name = bad.to_string();
            assert!(watch.validate().is_err(), "name {bad:?} must be rejected");
            let mut watch = base_watch();
            watch.tenant = bad.to_string();
            assert!(watch.validate().is_err(), "tenant {bad:?} must be rejected");
        }
    }

    #[test]
    fn validate_rejects_empty_name_tenant_json_path_topic() {
        let mut watch = base_watch();
        watch.name = String::new();
        assert!(watch.validate().is_err());

        let mut watch = base_watch();
        watch.tenant = String::new();
        assert!(watch.validate().is_err());

        let mut watch = base_watch();
        watch.source.json_path = String::new();
        assert!(watch.validate().is_err());

        let mut watch = base_watch();
        watch.topic = String::new();
        assert!(watch.validate().is_err());
    }
}
