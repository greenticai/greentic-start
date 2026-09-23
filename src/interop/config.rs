//! The staged per-unit interop config (worker-interop contract §2).
//!
//! The designer writes ONE secret per unit into the environment's dev-store,
//! `secrets://<env>/<runtime tenant>/_/ingress/<canonical(bundle id)>`, whose
//! value is this document. The runtime only ever READS it:
//!
//! - `credentials[]` are SHA-256 hashes of `gtw_` bearer tokens. The plaintext
//!   is never staged, because the dev-store ships whole into the container.
//! - `a2a` / `mcp` decide whether the interop paths are reserved at all.
//! - `agent` feeds the A2A agent card.
//!
//! The document is versioned (`v`). An unknown version is treated as ABSENT
//! (plus a `warn`), never as a partial parse: a future shape this build cannot
//! read must not be half-trusted. Unknown fields inside a known version are
//! ignored, so the designer can add fields ahead of this runtime.

use serde::Deserialize;
use serde_json::Value;

use crate::operator_log;

/// The only document version this build understands.
pub(crate) const CONFIG_VERSION: u64 = 1;

/// One accepted bearer credential.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Credential {
    /// Never secret: it is the rate-limit key and the session namespace.
    pub id: String,
    /// `sha256(token)`.
    pub sha256: [u8; 32],
    /// A rotated-out credential stays valid until this instant (ms since the
    /// Unix epoch). `None` = no expiry.
    pub expires_at_ms: Option<u64>,
}

impl std::fmt::Debug for Credential {
    // The hash is not the token, but there is no reason to print it either.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("id", &self.id)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

/// One A2A skill as the designer stages it. Mirrors `AgentSkill` minus the
/// fields the card fills in itself.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct AgentSkillMeta {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub examples: Vec<String>,
}

/// The `agent` object: what the A2A card says about the worker.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct AgentMeta {
    /// The worker's own agent id, when the designer stages one.
    ///
    /// Read by usage metering alone — the A2A card publishes a NAME, not an
    /// id. It exists because nothing else in this runtime knows one: the
    /// `dw.agent` node output carries `reply`/`trail`/`terminated_by`/`usage`
    /// and the reply `Activity` carries a pack id, so an absent value falls
    /// back to the unit's bundle id rather than being invented. See
    /// [`crate::interop::metering::TurnMetering::for_unit`].
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub skills: Vec<AgentSkillMeta>,
}

/// A parsed, validated interop config.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct InteropConfig {
    pub a2a: bool,
    pub mcp: bool,
    pub credentials: Vec<Credential>,
    pub tenant_slug: Option<String>,
    pub issuer: Option<String>,
    pub mcp_resource: Option<String>,
    pub agent: AgentMeta,
    /// Where to record what a turn spent (§8.1). **Absent means metering is
    /// off**, which is every deployment staged before it existed.
    pub metering: Option<super::metering::MeteringConfig>,
}

/// Wire form of one credential, before validation.
#[derive(Deserialize)]
struct RawCredential {
    #[serde(default)]
    id: String,
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    expires_at_ms: Option<u64>,
}

/// Wire form of the document, before validation. Unknown fields are ignored.
#[derive(Deserialize)]
struct RawConfig {
    #[serde(default)]
    a2a: bool,
    #[serde(default)]
    mcp: bool,
    #[serde(default)]
    credentials: Vec<Value>,
    #[serde(default)]
    tenant_slug: Option<String>,
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    mcp_resource: Option<String>,
    #[serde(default)]
    agent: Option<Value>,
    #[serde(default)]
    metering: Option<Value>,
}

/// Parse the staged bytes. `None` means "treat as absent": the document is not
/// JSON, carries no or an unknown `v`, or has a malformed top level. Each case
/// is logged at `warn`, because a unit that staged a config and got none is a
/// deploy that silently answers 401 to every caller.
///
/// A malformed ENTRY (a credential with a bad hash, a skill that is not an
/// object) is dropped on its own with a `warn` rather than voiding the whole
/// document: dropping a credential can only refuse a caller, never admit one.
pub(crate) fn parse(bytes: &[u8], unit: &str) -> Option<InteropConfig> {
    let value: Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(err) => {
            warn(unit, &format!("config is not JSON ({err}); ignoring it"));
            return None;
        }
    };
    match value.get("v").and_then(Value::as_u64) {
        Some(CONFIG_VERSION) => {}
        Some(other) => {
            warn(
                unit,
                &format!("config version {other} is not understood by this build; ignoring it"),
            );
            return None;
        }
        None => {
            warn(unit, "config carries no numeric `v`; ignoring it");
            return None;
        }
    }
    let raw: RawConfig = match serde_json::from_value(value) {
        Ok(raw) => raw,
        Err(err) => {
            warn(unit, &format!("config is malformed ({err}); ignoring it"));
            return None;
        }
    };
    let credentials = raw
        .credentials
        .into_iter()
        .filter_map(|entry| parse_credential(entry, unit))
        .collect();
    let agent = raw
        .agent
        .and_then(|value| match serde_json::from_value::<AgentMeta>(value) {
            Ok(agent) => Some(agent),
            Err(err) => {
                warn(
                    unit,
                    &format!("config `agent` is malformed ({err}); using defaults"),
                );
                None
            }
        })
        .unwrap_or_default();
    // A malformed or unsafe `metering` block switches METERING off and
    // nothing else, for the same reason a malformed credential is dropped
    // alone: losing a usage row must never cost a unit its interop surface.
    let metering = raw
        .metering
        .and_then(|value| super::metering::parse_metering(value, unit));
    Some(InteropConfig {
        a2a: raw.a2a,
        mcp: raw.mcp,
        credentials,
        tenant_slug: non_empty(raw.tenant_slug),
        issuer: non_empty(raw.issuer),
        mcp_resource: non_empty(raw.mcp_resource),
        agent,
        metering,
    })
}

fn parse_credential(entry: Value, unit: &str) -> Option<Credential> {
    let raw: RawCredential = match serde_json::from_value(entry) {
        Ok(raw) => raw,
        Err(err) => {
            warn(unit, &format!("dropping a malformed credential ({err})"));
            return None;
        }
    };
    if !valid_credential_id(&raw.id) {
        warn(
            unit,
            "dropping a credential whose id is empty, too long, or not [A-Za-z0-9_-]",
        );
        return None;
    }
    let Some(sha256) = decode_sha256_hex(&raw.sha256) else {
        warn(
            unit,
            &format!(
                "dropping credential `{}`: `sha256` is not 64 hex characters",
                raw.id
            ),
        );
        return None;
    };
    Some(Credential {
        id: raw.id,
        sha256,
        expires_at_ms: raw.expires_at_ms,
    })
}

/// The id becomes the CALLER segment of a session hint, so it obeys the one
/// shared rule — see [`crate::interop::valid_caller_key`] for why a colon in
/// it would let two callers share a namespace.
fn valid_credential_id(id: &str) -> bool {
    crate::interop::valid_caller_key(id)
}

fn decode_sha256_hex(raw: &str) -> Option<[u8; 32]> {
    let raw = raw.trim();
    if raw.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, chunk) in raw.as_bytes().chunks(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        out[index] = (high << 4) | low;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn warn(unit: &str, message: &str) {
    operator_log::warn(
        module_path!(),
        format!("interop config for unit `{unit}`: {message}"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HASH: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    #[test]
    fn a_full_v1_document_parses() {
        let doc = json!({
            "v": 1,
            "a2a": true,
            "mcp": true,
            "credentials": [
                {"id": "c_01J", "sha256": HASH},
                {"id": "c_01H", "sha256": HASH.to_uppercase(), "expires_at_ms": 1_790_000_000_000u64}
            ],
            "tenant_slug": "acme",
            "issuer": "https://admin.demo.greentic.cloud",
            "mcp_resource": "https://gtc-svc.run.app/mcp",
            "agent": {
                "name": "Support Bot",
                "description": "Answers support questions.",
                "skills": [{"id": "converse", "name": "Converse", "description": "d", "tags": [], "examples": []}]
            }
        });
        let config = parse(doc.to_string().as_bytes(), "unit").expect("parses");
        assert!(config.a2a && config.mcp);
        assert_eq!(config.credentials.len(), 2);
        assert_eq!(config.credentials[0].id, "c_01J");
        assert_eq!(config.credentials[0].sha256[0], 0x9f);
        assert_eq!(config.credentials[1].expires_at_ms, Some(1_790_000_000_000));
        assert_eq!(config.credentials[0].sha256, config.credentials[1].sha256);
        assert_eq!(config.tenant_slug.as_deref(), Some("acme"));
        assert_eq!(config.agent.name.as_deref(), Some("Support Bot"));
        assert_eq!(config.agent.skills[0].id, "converse");
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let doc = json!({"v": 1, "a2a": true, "future": {"x": 1}, "credentials": []});
        let config = parse(doc.to_string().as_bytes(), "unit").expect("parses");
        assert!(config.a2a);
        assert!(!config.mcp);
    }

    #[test]
    fn an_unknown_or_missing_version_is_absent() {
        for doc in [
            json!({"v": 2, "a2a": true}),
            json!({"a2a": true}),
            json!({"v": "1"}),
        ] {
            assert!(parse(doc.to_string().as_bytes(), "unit").is_none(), "{doc}");
        }
        assert!(parse(b"not json", "unit").is_none());
    }

    #[test]
    fn a_malformed_credential_is_dropped_alone() {
        let doc = json!({
            "v": 1,
            "credentials": [
                {"id": "ok", "sha256": HASH},
                {"id": "short", "sha256": "abcd"},
                {"id": "not hex", "sha256": HASH},
                {"id": "a:b", "sha256": HASH},
                {"id": "", "sha256": HASH},
                {"id": "zz", "sha256": "g".repeat(64)},
                "not an object"
            ]
        });
        let config = parse(doc.to_string().as_bytes(), "unit").expect("parses");
        let ids: Vec<_> = config.credentials.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["ok"]);
    }

    #[test]
    fn a_malformed_agent_falls_back_to_defaults() {
        let doc = json!({"v": 1, "a2a": true, "agent": "nope"});
        let config = parse(doc.to_string().as_bytes(), "unit").expect("parses");
        assert_eq!(config.agent, AgentMeta::default());
    }

    #[test]
    fn debug_never_prints_the_hash() {
        let doc = json!({"v": 1, "credentials": [{"id": "c1", "sha256": HASH}]});
        let config = parse(doc.to_string().as_bytes(), "unit").expect("parses");
        assert!(!format!("{config:?}").contains("9f86"));
    }
}
