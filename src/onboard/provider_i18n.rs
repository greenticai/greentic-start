use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Find the provider i18n locale files directory.
///
/// Precedence:
/// 1. `GREENTIC_PROVIDER_I18N_DIR` environment variable
/// 2. Sibling `greentic-i18n/i18n/providers/` relative to ancestors (up to 4 levels)
/// 3. `{bundle_root}/i18n/providers/`
pub fn resolve_i18n_dir(bundle_root: &Path) -> Option<PathBuf> {
    // 1. Env override
    if let Ok(dir) = std::env::var("GREENTIC_PROVIDER_I18N_DIR") {
        let p = PathBuf::from(dir);
        if p.is_dir() {
            return Some(p);
        }
    }

    // 2. Sibling greentic-i18n repo (walk up ancestors)
    //    bundle_root may be nested (e.g. greentic-operator/demo-bundle/),
    //    so check parent, grandparent, etc. up to 4 levels.
    let mut ancestor = bundle_root.parent();
    for _ in 0..4 {
        let Some(dir) = ancestor else { break };
        let sibling = dir.join("greentic-i18n").join("i18n").join("providers");
        if sibling.is_dir() {
            return Some(sibling);
        }
        ancestor = dir.parent();
    }

    // 3. Inside bundle
    let inside = bundle_root.join("i18n").join("providers");
    if inside.is_dir() {
        return Some(inside);
    }

    None
}

/// Read `{dir}/{locale}.json` into a flat key→value map.
///
/// Returns an empty map if the file is missing or unparseable.
pub fn load_locale_file(dir: &Path, locale: &str) -> BTreeMap<String, String> {
    let path = dir.join(format!("{locale}.json"));
    let Ok(data) = std::fs::read_to_string(&path) else {
        return BTreeMap::new();
    };
    let Ok(obj) = serde_json::from_str::<serde_json::Value>(&data) else {
        return BTreeMap::new();
    };
    obj.as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

/// Load disk files and merge with WASM english.
pub fn load_and_merge(
    wasm_english: &BTreeMap<String, String>,
    locale: &str,
    dir: Option<&Path>,
) -> BTreeMap<String, String> {
    let Some(dir) = dir else {
        return wasm_english.clone();
    };

    let disk_base = load_locale_file(dir, "en");
    let locale_map = if locale != "en" {
        Some(load_locale_file(dir, locale))
    } else {
        None
    };

    merge_i18n_layers_local(disk_base, wasm_english, locale_map.as_ref())
}

fn merge_i18n_layers_local(
    mut disk_base: BTreeMap<String, String>,
    wasm_english: &BTreeMap<String, String>,
    locale_map: Option<&BTreeMap<String, String>>,
) -> BTreeMap<String, String> {
    for (key, value) in wasm_english {
        disk_base.insert(key.clone(), value.clone());
    }
    if let Some(locale) = locale_map {
        for (key, value) in locale {
            if disk_base.contains_key(key) {
                disk_base.insert(key.clone(), value.clone());
            }
        }
    }
    disk_base
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn load_and_merge_overlays_locale() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        fs::write(
            dir.join("en.json"),
            r#"{"telegram.qa.setup.bot_token":"Bot token","telegram.qa.setup.enabled":"Enable provider"}"#,
        )
        .unwrap();
        fs::write(
            dir.join("id.json"),
            r#"{"telegram.qa.setup.bot_token":"Token bot","unknown.key":"ignored"}"#,
        )
        .unwrap();

        let wasm_english = BTreeMap::new(); // simulate WASM failure
        let merged = load_and_merge(&wasm_english, "id", Some(dir));

        assert_eq!(merged["telegram.qa.setup.bot_token"], "Token bot");
        assert_eq!(merged["telegram.qa.setup.enabled"], "Enable provider");
        assert!(!merged.contains_key("unknown.key"));
    }

    #[test]
    fn load_and_merge_uses_disk_en_when_wasm_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        fs::write(dir.join("en.json"), r#"{"key":"disk value"}"#).unwrap();

        let merged = load_and_merge(&BTreeMap::new(), "en", Some(dir));
        assert_eq!(merged["key"], "disk value");
    }

    #[test]
    fn load_and_merge_wasm_overrides_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        fs::write(dir.join("en.json"), r#"{"key":"from disk"}"#).unwrap();

        let mut wasm = BTreeMap::new();
        wasm.insert("key".into(), "from WASM".into());
        let merged = load_and_merge(&wasm, "en", Some(dir));
        assert_eq!(merged["key"], "from WASM");
    }

    #[test]
    fn load_and_merge_returns_wasm_when_no_dir() {
        let mut wasm = BTreeMap::new();
        wasm.insert("key".into(), "value".into());
        let merged = load_and_merge(&wasm, "id", None);
        assert_eq!(merged, wasm);
    }

    #[test]
    fn resolve_i18n_dir_from_env() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        // SAFETY: test-only, single-threaded access to this env var
        unsafe { std::env::set_var("GREENTIC_PROVIDER_I18N_DIR", &dir) };
        let result = resolve_i18n_dir(Path::new("/nonexistent"));
        unsafe { std::env::remove_var("GREENTIC_PROVIDER_I18N_DIR") };
        assert_eq!(result, Some(dir));
    }
}
