//! Runtime resolution of `ext://<path>[/<instance>]` references (`Path 3`).
//!
//! An extension is an open-namespace capability binding
//! ([`ExtensionBinding`](greentic_deploy_spec::ExtensionBinding)) that a
//! workload reaches **by name** rather than through a typed host interface. At
//! provider config-injection time
//! ([`crate::ingress_dispatch::build_injected_config`]) any config value that
//! is an `ext://` reference is replaced with the bound extension's resolved
//! config/answers blob — the exact analogue of the `secrets://` resolution that
//! sits beside it.
//!
//! Resolution is **fail-closed**: a reference that names no bound extension
//! (e.g. after `op extensions remove`) is an error, never a silent
//! pass-through. A stale `ext://` string must not reach the component as opaque
//! config it cannot interpret.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use greentic_deploy_spec::{Environment, ExtensionRef};
use serde_json::{Map as JsonMap, Value as JsonValue};

/// `ext://` scheme prefix. The authoritative grammar lives in
/// [`ExtensionRef`]; this is only the cheap "is this even a reference?" probe.
const EXTENSION_SCHEME: &str = "ext://";

/// Borrow `value` as an `ext://` reference string, if it is one.
fn as_ext_ref(value: &JsonValue) -> Option<&str> {
    value.as_str().filter(|s| s.starts_with(EXTENSION_SCHEME))
}

/// True when any top-level value in `map` is an `ext://` reference. Used as a
/// cheap pre-scan so the environment store is only read when a reference is
/// actually present — the common ingress carries none.
pub(crate) fn map_has_ext_ref(map: &JsonMap<String, JsonValue>) -> bool {
    map.values().any(|v| as_ext_ref(v).is_some())
}

/// Resolve one `ext://<path>[/<instance>]` reference against `env`, returning
/// the bound extension's config/answers blob.
///
/// `env_root` is the environment directory (`<store-root>/<env-id>`); the
/// binding's [`answers_ref`](greentic_deploy_spec::ExtensionBinding::answers_ref)
/// is resolved relative to it. A binding with no `answers_ref` resolves to an
/// empty object (it is bound but carries no config). Fail-closed on an
/// unparseable ref, an unbound ref, or an unreadable/invalid answers blob.
pub(crate) fn resolve_extension_ref(
    env: &Environment,
    env_root: &Path,
    raw: &str,
) -> Result<JsonValue> {
    let reference = ExtensionRef::try_new(raw)
        .map_err(|err| anyhow!("invalid extension reference `{raw}`: {err}"))?;
    let binding = env
        .extension_for_ref(&reference)
        .with_context(|| format!("extension `{raw}` is not bound in this environment"))?;
    let Some(answers_ref) = binding.answers_ref.as_ref() else {
        return Ok(JsonValue::Object(JsonMap::new()));
    };
    let path = env_root.join(answers_ref);
    let bytes = std::fs::read(&path)
        .with_context(|| format!("reading extension answers blob `{}`", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing extension answers blob `{}`", path.display()))
}

/// Replace every top-level `ext://` string value in `map` with its resolved
/// extension config. Errors propagate (fail-closed) so a stale reference fails
/// the ingress rather than reaching the component unresolved.
///
/// `resolved` memoizes by raw reference string so a ref that appears under
/// several keys — or in both config sources of one ingress (envelope AND
/// setup-answers commonly carry the same value) — reads its answers blob from
/// disk once. The caller shares one memo across all sources of a request.
pub(crate) fn rewrite_ext_refs(
    map: &mut JsonMap<String, JsonValue>,
    env: &Environment,
    env_root: &Path,
    resolved: &mut HashMap<String, JsonValue>,
) -> Result<()> {
    for value in map.values_mut() {
        let Some(raw) = as_ext_ref(value).map(str::to_string) else {
            continue;
        };
        *value = match resolved.get(&raw) {
            Some(cached) => cached.clone(),
            None => {
                let fresh = resolve_extension_ref(env, env_root, &raw)?;
                resolved.insert(raw, fresh.clone());
                fresh
            }
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_deploy_spec::{ExtensionBinding, PackDescriptor, PackId};
    use serde_json::json;
    use std::path::PathBuf;

    fn binding(
        kind: &str,
        instance_id: Option<&str>,
        answers_ref: Option<&str>,
    ) -> ExtensionBinding {
        ExtensionBinding {
            kind: PackDescriptor::try_new(kind).unwrap(),
            pack_ref: PackId::new(kind),
            instance_id: instance_id.map(str::to_string),
            answers_ref: answers_ref.map(PathBuf::from),
            generation: 1,
            previous_binding_ref: None,
        }
    }

    /// Shared minimal env from `test_fixtures`, parameterized on the one field
    /// these tests consult — keeps this module off the per-field fixture drift
    /// the shared module exists to prevent.
    fn env_with(extensions: Vec<ExtensionBinding>) -> Environment {
        let mut env = crate::test_fixtures::env_with(Vec::new());
        env.extensions = extensions;
        env
    }

    #[test]
    fn resolves_default_instance_to_answers_blob() {
        let dir = tempfile::tempdir().unwrap();
        let answers_dir = dir.path().join("extensions/acme.crm");
        std::fs::create_dir_all(&answers_dir).unwrap();
        std::fs::write(
            answers_dir.join("answers.json"),
            br#"{"url":"https://crm.example","scopes":["read"]}"#,
        )
        .unwrap();

        let env = env_with(vec![binding(
            "acme.crm@1.0.0",
            None,
            Some("extensions/acme.crm/answers.json"),
        )]);

        let resolved = resolve_extension_ref(&env, dir.path(), "ext://acme.crm").unwrap();
        assert_eq!(
            resolved,
            json!({"url":"https://crm.example","scopes":["read"]})
        );
    }

    #[test]
    fn named_and_default_instances_resolve_independently() {
        let dir = tempfile::tempdir().unwrap();
        for (sub, body) in [
            ("extensions/acme.crm", br#"{"who":"default"}"#.as_slice()),
            (
                "extensions/acme.crm-primary",
                br#"{"who":"primary"}"#.as_slice(),
            ),
        ] {
            let d = dir.path().join(sub);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("answers.json"), body).unwrap();
        }
        let env = env_with(vec![
            binding(
                "acme.crm@1.0.0",
                None,
                Some("extensions/acme.crm/answers.json"),
            ),
            binding(
                "acme.crm@1.0.0",
                Some("primary"),
                Some("extensions/acme.crm-primary/answers.json"),
            ),
        ]);

        assert_eq!(
            resolve_extension_ref(&env, dir.path(), "ext://acme.crm").unwrap(),
            json!({"who":"default"})
        );
        assert_eq!(
            resolve_extension_ref(&env, dir.path(), "ext://acme.crm/primary").unwrap(),
            json!({"who":"primary"})
        );
    }

    #[test]
    fn binding_without_answers_resolves_to_empty_object() {
        let dir = tempfile::tempdir().unwrap();
        let env = env_with(vec![binding("acme.crm@1.0.0", None, None)]);
        assert_eq!(
            resolve_extension_ref(&env, dir.path(), "ext://acme.crm").unwrap(),
            json!({})
        );
    }

    #[test]
    fn unbound_reference_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let env = env_with(vec![binding(
            "acme.crm@1.0.0",
            None,
            Some("extensions/acme.crm/answers.json"),
        )]);
        // A path that is not bound, and the wrong instance of a bound path.
        let err = resolve_extension_ref(&env, dir.path(), "ext://other.thing").unwrap_err();
        assert!(err.to_string().contains("not bound"), "{err}");
        let err = resolve_extension_ref(&env, dir.path(), "ext://acme.crm/primary").unwrap_err();
        assert!(err.to_string().contains("not bound"), "{err}");
    }

    #[test]
    fn invalid_reference_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let env = env_with(vec![]);
        let err = resolve_extension_ref(&env, dir.path(), "ext://no-dot").unwrap_err();
        assert!(
            err.to_string().contains("invalid extension reference"),
            "{err}"
        );
    }

    #[test]
    fn missing_answers_blob_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let env = env_with(vec![binding(
            "acme.crm@1.0.0",
            None,
            Some("extensions/acme.crm/answers.json"),
        )]);
        let err = resolve_extension_ref(&env, dir.path(), "ext://acme.crm").unwrap_err();
        assert!(
            err.to_string().contains("reading extension answers blob"),
            "{err}"
        );
    }

    #[test]
    fn rewrite_substitutes_only_ext_values() {
        let dir = tempfile::tempdir().unwrap();
        let answers_dir = dir.path().join("extensions/acme.crm");
        std::fs::create_dir_all(&answers_dir).unwrap();
        std::fs::write(answers_dir.join("answers.json"), br#"{"k":"v"}"#).unwrap();
        let env = env_with(vec![binding(
            "acme.crm@1.0.0",
            None,
            Some("extensions/acme.crm/answers.json"),
        )]);

        let mut map = json!({
            "endpoint": "ext://acme.crm",
            "plain": "literal",
            "number": 7
        })
        .as_object()
        .unwrap()
        .clone();

        assert!(map_has_ext_ref(&map));
        rewrite_ext_refs(&mut map, &env, dir.path(), &mut HashMap::new()).unwrap();
        assert_eq!(map.get("endpoint").unwrap(), &json!({"k":"v"}));
        assert_eq!(map.get("plain").unwrap(), &json!("literal"));
        assert_eq!(map.get("number").unwrap(), &json!(7));
        assert!(!map_has_ext_ref(&map));
    }

    #[test]
    fn duplicate_refs_resolve_once_via_shared_memo() {
        let dir = tempfile::tempdir().unwrap();
        let answers_dir = dir.path().join("extensions/acme.crm");
        std::fs::create_dir_all(&answers_dir).unwrap();
        std::fs::write(answers_dir.join("answers.json"), br#"{"k":"v"}"#).unwrap();
        let env = env_with(vec![binding(
            "acme.crm@1.0.0",
            None,
            Some("extensions/acme.crm/answers.json"),
        )]);

        // Same ref under two keys in one map, and again in a second map fed
        // the SAME memo (the cross-source shape `build_injected_config` uses).
        let mut first = json!({ "a": "ext://acme.crm", "b": "ext://acme.crm" })
            .as_object()
            .unwrap()
            .clone();
        let mut second = json!({ "c": "ext://acme.crm" })
            .as_object()
            .unwrap()
            .clone();

        let mut resolved = HashMap::new();
        rewrite_ext_refs(&mut first, &env, dir.path(), &mut resolved).unwrap();
        // Delete the blob: a memo hit must NOT touch the filesystem again.
        std::fs::remove_file(dir.path().join("extensions/acme.crm/answers.json")).unwrap();
        rewrite_ext_refs(&mut second, &env, dir.path(), &mut resolved).unwrap();

        for (map, key) in [(&first, "a"), (&first, "b"), (&second, "c")] {
            assert_eq!(map.get(key).unwrap(), &json!({"k":"v"}));
        }
        assert_eq!(resolved.len(), 1, "one memo entry per unique ref");
    }
}
