use anyhow::Context;
use include_dir::{Dir, include_dir};
use once_cell::sync::Lazy;
use std::collections::BTreeMap;
use std::sync::RwLock;
use unic_langid::LanguageIdentifier;

pub type Map = BTreeMap<String, String>;

static OPERATOR_CLI_I18N: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/i18n/operator_cli");
static CURRENT_LOCALE: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(select_locale(None)));

pub fn select_locale(cli_locale: Option<&str>) -> String {
    let supported = supported_locales();

    if let Some(cli) = cli_locale
        && let Some(found) = resolve_supported(cli, &supported)
    {
        return found;
    }

    for env_key in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(raw) = std::env::var(env_key)
            && let Some(found) = resolve_supported(&raw, &supported)
        {
            return found;
        }
    }

    if let Some(raw) = sys_locale::get_locale()
        && let Some(found) = resolve_supported(&raw, &supported)
    {
        return found;
    }

    "en".to_string()
}

pub fn set_locale(locale: impl Into<String>) {
    let normalized = greentic_i18n::normalize_locale(&locale.into());
    if let Ok(mut guard) = CURRENT_LOCALE.write() {
        *guard = normalized;
    }
}

pub fn current_locale() -> String {
    CURRENT_LOCALE
        .read()
        .map(|value| value.clone())
        .unwrap_or_else(|_| select_locale(None))
}

pub fn tr(key: &str, fallback: &str) -> String {
    tr_for_locale(key, fallback, &current_locale())
}

pub fn trf(key: &str, fallback: &str, args: &[&str]) -> String {
    let mut rendered = tr(key, fallback);
    for value in args {
        rendered = rendered.replacen("{}", value, 1);
    }
    rendered
}

pub fn tr_for_locale(key: &str, fallback: &str, locale: &str) -> String {
    match load_cli(locale) {
        Ok(map) => map
            .get(key)
            .cloned()
            .unwrap_or_else(|| fallback.to_string()),
        Err(_) => fallback.to_string(),
    }
}

pub fn load_cli(locale: &str) -> anyhow::Result<Map> {
    for candidate in locale_candidates(locale) {
        if let Some(file) = OPERATOR_CLI_I18N.get_file(&candidate) {
            let raw = file.contents_utf8().ok_or_else(|| {
                anyhow::anyhow!("operator cli i18n file is not valid UTF-8: {candidate}")
            })?;
            return serde_json::from_str(raw)
                .with_context(|| format!("parse embedded operator cli i18n map {candidate}"));
        }
    }
    Ok(Map::new())
}

fn locale_candidates(locale: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut push_candidate = |candidate: String| {
        if !out.iter().any(|existing| existing == &candidate) {
            out.push(candidate);
        }
    };
    let trimmed = locale.trim();
    if !trimmed.is_empty() {
        push_candidate(format!("{}.json", trimmed));
        let primary = greentic_i18n::normalize_locale(trimmed);
        push_candidate(format!("{}.json", primary));
    }
    push_candidate("en.json".to_string());
    out
}

fn normalize_locale_tag(raw: &str) -> Option<String> {
    let mut cleaned = raw.trim();
    if cleaned.is_empty() {
        return None;
    }
    if cleaned.eq_ignore_ascii_case("c") || cleaned.eq_ignore_ascii_case("posix") {
        return None;
    }
    if let Some((head, _)) = cleaned.split_once('.') {
        cleaned = head;
    }
    if let Some((head, _)) = cleaned.split_once('@') {
        cleaned = head;
    }
    if cleaned.eq_ignore_ascii_case("c") || cleaned.eq_ignore_ascii_case("posix") {
        return None;
    }
    let normalized = cleaned.replace('_', "-");
    normalized
        .parse::<LanguageIdentifier>()
        .ok()
        .map(|value| value.to_string())
}

fn base_language(tag: &str) -> Option<String> {
    tag.split('-')
        .next()
        .map(|value| value.to_ascii_lowercase())
}

fn resolve_supported(candidate: &str, supported: &[String]) -> Option<String> {
    let normalized = normalize_locale_tag(candidate)?;
    if supported.iter().any(|value| value == &normalized) {
        return Some(normalized);
    }
    let base = base_language(&normalized)?;
    if supported.iter().any(|value| value == &base) {
        return Some(base);
    }
    None
}

fn supported_locales() -> Vec<String> {
    let mut out = OPERATOR_CLI_I18N
        .files()
        .filter_map(|file| {
            file.path()
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix(".json"))
                .map(|name| name.to_string())
        })
        .collect::<Vec<_>>();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_requested_locale_before_english() {
        let map = load_cli("de-DE").expect("load de locale");
        assert_eq!(
            map.get("cli.common.answer_yes_no").map(String::as_str),
            Some("bitte mit y oder n antworten")
        );
    }

    #[test]
    fn normalize_locale_tag_handles_common_system_forms() {
        assert_eq!(
            normalize_locale_tag("en_US.UTF-8").as_deref(),
            Some("en-US")
        );
        assert_eq!(normalize_locale_tag("de_DE@euro").as_deref(), Some("de-DE"));
        assert_eq!(normalize_locale_tag("es").as_deref(), Some("es"));
    }

    #[test]
    fn normalize_locale_tag_rejects_c_posix() {
        assert_eq!(normalize_locale_tag("C"), None);
        assert_eq!(normalize_locale_tag("POSIX"), None);
        assert_eq!(normalize_locale_tag("C.UTF-8"), None);
    }
}
