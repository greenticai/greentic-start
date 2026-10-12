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

/// Who may call the unit's interop surfaces (access-policy spec §4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Visibility {
    /// Every caller must present a credential. The default, and what any
    /// unreadable `access` block degrades to.
    #[default]
    Private,
    /// A caller with no credential is served as anonymous, within the limits.
    Public,
}

/// A credential mechanism the admin allows on a private unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mechanism {
    /// The staged `gtw_` bearer.
    ApiKey,
    /// An RS256 access token from the unit's authorization server.
    Oauth,
}

/// Limits on anonymous callers of a public unit (spec §6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PublicLimits {
    /// Sustained turns per minute, per unit.
    pub rate_per_min: u32,
    /// Turns that may arrive at once.
    pub burst: u32,
    /// Anonymous turns per UTC day, per unit. `None` = no daily cap.
    pub daily_turn_cap: Option<u32>,
}

impl Default for PublicLimits {
    fn default() -> Self {
        Self {
            rate_per_min: 60,
            burst: 20,
            daily_turn_cap: None,
        }
    }
}

/// The staged access policy. **Every failure mode of reading it is
/// [`AccessPolicy::default`]**: private, both mechanisms. Never public.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AccessPolicy {
    pub visibility: Visibility,
    /// Never empty: an empty or absent list reads as both.
    pub mechanisms: Vec<Mechanism>,
    /// Meaningful only when `visibility` is `Public`.
    pub public: PublicLimits,
    pub generation: u64,
}

impl Default for AccessPolicy {
    fn default() -> Self {
        Self {
            visibility: Visibility::Private,
            mechanisms: vec![Mechanism::ApiKey, Mechanism::Oauth],
            public: PublicLimits::default(),
            generation: 0,
        }
    }
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
    /// The unit's deployed secrets live in the admin, not the shipped dev
    /// store: activation hydrates them through the secrets door (see
    /// `crate::secrets_door`). **Absent means off**, which is every document
    /// staged before the field existed; a build that predates the field
    /// ignores it (unknown fields are not rejected).
    pub secrets_door: bool,
    /// Private (default) or public, and which mechanisms protect a private
    /// unit. See [`AccessPolicy`].
    pub access: AccessPolicy,
    /// The audience an OAuth token must carry on `/a2a`. **Absent means
    /// `/a2a` accepts the staged bearer alone**, whatever `access` says.
    pub a2a_resource: Option<String>,
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
    #[serde(default)]
    secrets_door: bool,
    #[serde(default)]
    access: Option<Value>,
    #[serde(default)]
    a2a_resource: Option<String>,
}

/// Wire form of the `access` block, before validation.
#[derive(Deserialize)]
struct RawAccess {
    #[serde(default)]
    visibility: Option<String>,
    #[serde(default)]
    mechanisms: Option<Vec<String>>,
    #[serde(default)]
    public: Option<RawPublicLimits>,
    #[serde(default)]
    generation: Option<u64>,
}

#[derive(Deserialize)]
struct RawPublicLimits {
    rate_per_min: u32,
    burst: u32,
    #[serde(default)]
    daily_turn_cap: Option<u32>,
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
    let tenant_slug = non_empty(raw.tenant_slug);
    // A malformed, unsafe or slug-less `metering` block switches METERING off
    // and nothing else, for the same reason a malformed credential is dropped
    // alone: losing a usage row must never cost a unit its interop surface.
    // The slug is threaded in because the usage ingest requires it — see
    // `metering::MeteringRefusal::NoTenantSlug`.
    let metering = raw
        .metering
        .and_then(|value| super::metering::parse_metering(value, tenant_slug.as_deref(), unit));
    Some(InteropConfig {
        a2a: raw.a2a,
        mcp: raw.mcp,
        credentials,
        tenant_slug,
        issuer: non_empty(raw.issuer),
        mcp_resource: non_empty(raw.mcp_resource),
        agent,
        metering,
        secrets_door: raw.secrets_door,
        access: raw
            .access
            .map(|value| parse_access(value, unit))
            .unwrap_or_default(),
        a2a_resource: raw
            .a2a_resource
            .and_then(|value| valid_a2a_resource(&value, unit)),
    })
}

/// Read the `access` block alone, like `metering`. **Any problem returns the
/// default (private), never a partly-read public policy**: a block this build
/// cannot fully understand must not open a unit to the internet. Callers that
/// want to know why read the `warn`.
fn parse_access(value: Value, unit: &str) -> AccessPolicy {
    // serde reads a JSON ARRAY into a struct field by field, so `["public"]`
    // would otherwise parse as `visibility: "public"`.
    if !value.is_object() {
        warn(
            unit,
            "`access` is not an object; treating the unit as private",
        );
        return AccessPolicy::default();
    }
    let raw: RawAccess = match serde_json::from_value(value) {
        Ok(raw) => raw,
        Err(err) => {
            warn(
                unit,
                &format!("`access` is malformed ({err}); treating the unit as private"),
            );
            return AccessPolicy::default();
        }
    };
    let visibility = match raw.visibility.as_deref() {
        None | Some("private") => Visibility::Private,
        Some("public") => Visibility::Public,
        Some(other) => {
            warn(
                unit,
                &format!(
                    "`access.visibility` `{other}` is not understood; treating the unit as private"
                ),
            );
            Visibility::Private
        }
    };
    let mechanisms = match raw.mechanisms {
        None => AccessPolicy::default().mechanisms,
        Some(names) => {
            let mut parsed = Vec::new();
            for name in &names {
                let mechanism = match name.as_str() {
                    "api_key" => Mechanism::ApiKey,
                    "oauth" => Mechanism::Oauth,
                    // An unknown mechanism is dropped alone: it can only
                    // narrow what a caller may present.
                    _ => continue,
                };
                if !parsed.contains(&mechanism) {
                    parsed.push(mechanism);
                }
            }
            if parsed.is_empty() {
                AccessPolicy::default().mechanisms
            } else {
                parsed
            }
        }
    };
    // Limits are read only for a public unit, and a public unit with limits
    // that cannot work (zero) is not public at all.
    let public = if visibility == Visibility::Public {
        match raw.public {
            None => PublicLimits::default(),
            Some(limits) if limits.rate_per_min > 0 && limits.burst > 0 => PublicLimits {
                rate_per_min: limits.rate_per_min,
                burst: limits.burst,
                daily_turn_cap: limits.daily_turn_cap.filter(|cap| *cap > 0),
            },
            Some(_) => {
                warn(
                    unit,
                    "`access.public` limits must be positive; treating the unit as private",
                );
                return AccessPolicy::default();
            }
        }
    } else {
        PublicLimits::default()
    };
    AccessPolicy {
        visibility,
        mechanisms,
        public,
        generation: raw.generation.unwrap_or(0),
    }
}

/// `https://…`, or `http://` to a loopback host (local development). Anything
/// else is dropped: the value is the audience a token is checked against, and
/// an audience that is not an address this unit can serve is not one.
fn valid_a2a_resource(value: &str, unit: &str) -> Option<String> {
    let value = value.trim();
    let loopback = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
        .iter()
        .any(|prefix| {
            value
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/']))
        });
    let https = value
        .strip_prefix("https://")
        .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'));
    if https || loopback {
        Some(value.to_string())
    } else {
        if !value.is_empty() {
            warn(
                unit,
                "ignoring `a2a_resource`: not an https:// (or loopback) URL",
            );
        }
        None
    }
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

    fn parse_doc(extra: Value) -> InteropConfig {
        let mut doc = json!({"v": 1, "a2a": true, "credentials": []});
        if let (Value::Object(base), Value::Object(more)) = (&mut doc, extra) {
            base.extend(more);
        }
        parse(doc.to_string().as_bytes(), "unit").expect("parses")
    }

    #[test]
    fn absent_access_block_is_private_with_both_mechanisms() {
        let c = parse_doc(json!({}));
        assert_eq!(c.access.visibility, Visibility::Private);
        assert_eq!(
            c.access.mechanisms,
            vec![Mechanism::ApiKey, Mechanism::Oauth]
        );
        assert_eq!(c.access, AccessPolicy::default());
        assert_eq!(c.a2a_resource, None);
    }

    #[test]
    fn a_full_access_block_parses() {
        let c = parse_doc(json!({
            "access": {
                "visibility": "public",
                "mechanisms": ["oauth"],
                "public": {"rate_per_min": 30, "burst": 5, "daily_turn_cap": 100},
                "generation": 7
            },
            "a2a_resource": "https://w.example/a2a"
        }));
        assert_eq!(c.access.visibility, Visibility::Public);
        assert_eq!(c.access.mechanisms, vec![Mechanism::Oauth]);
        assert_eq!(
            c.access.public,
            PublicLimits {
                rate_per_min: 30,
                burst: 5,
                daily_turn_cap: Some(100)
            }
        );
        assert_eq!(c.access.generation, 7);
        assert_eq!(c.a2a_resource.as_deref(), Some("https://w.example/a2a"));
    }

    #[test]
    fn unparseable_access_degrades_to_private_never_public() {
        for access in [
            json!({"visibility": "public", "mechanisms": "nope"}),
            json!({"visibility": "public", "public": "nope"}),
            json!({"visibility": "public", "public": {"rate_per_min": 0, "burst": 5}}),
            json!({"visibility": "public", "public": {"rate_per_min": 5, "burst": 0}}),
            json!({"visibility": "public", "public": {"rate_per_min": -1, "burst": 5}}),
            json!({"visibility": true}),
            json!("public"),
            json!(["public"]),
        ] {
            let c = parse_doc(json!({"access": access.clone()}));
            assert_eq!(c.access.visibility, Visibility::Private, "{access}");
            assert_ne!(c.access.visibility, Visibility::Public, "{access}");
        }
    }

    #[test]
    fn unknown_visibility_value_is_private() {
        for value in ["world", "PUBLIC", "", "anyone"] {
            let c = parse_doc(json!({"access": {"visibility": value}}));
            assert_eq!(c.access.visibility, Visibility::Private, "{value}");
        }
    }

    #[test]
    fn empty_or_unknown_mechanisms_read_as_both() {
        for mechanisms in [json!([]), json!(["saml"])] {
            let c = parse_doc(json!({"access": {"mechanisms": mechanisms}}));
            assert_eq!(
                c.access.mechanisms,
                vec![Mechanism::ApiKey, Mechanism::Oauth]
            );
        }
        let c = parse_doc(json!({"access": {"mechanisms": ["saml", "api_key", "api_key"]}}));
        assert_eq!(c.access.mechanisms, vec![Mechanism::ApiKey]);
    }

    #[test]
    fn public_limits_are_read_only_when_public() {
        let c = parse_doc(json!({"access": {
            "visibility": "private",
            "public": {"rate_per_min": 1, "burst": 1, "daily_turn_cap": 1}
        }}));
        assert_eq!(c.access.public, PublicLimits::default());
        // Even malformed limits on a private unit change nothing.
        let c = parse_doc(json!({"access": {"visibility": "private", "public": "junk"}}));
        assert_eq!(c.access.visibility, Visibility::Private);
    }

    #[test]
    fn public_without_limits_gets_the_defaults() {
        let c = parse_doc(json!({"access": {"visibility": "public"}}));
        assert_eq!(
            c.access.public,
            PublicLimits {
                rate_per_min: 60,
                burst: 20,
                daily_turn_cap: None
            }
        );
    }

    #[test]
    fn a2a_resource_must_be_https_or_loopback_http() {
        for (value, kept) in [
            ("https://w.example/a2a", true),
            ("http://127.0.0.1:8080/a2a", true),
            ("http://localhost/a2a", true),
            ("http://w.example/a2a", false),
            ("http://127.0.0.1.evil.example/a2a", false),
            ("ftp://w.example", false),
            ("https://", false),
            ("", false),
        ] {
            let c = parse_doc(json!({"a2a_resource": value}));
            assert_eq!(c.a2a_resource.is_some(), kept, "{value}");
        }
    }

    #[test]
    fn debug_never_prints_the_hash() {
        let doc = json!({"v": 1, "credentials": [{"id": "c1", "sha256": HASH}]});
        let config = parse(doc.to_string().as_bytes(), "unit").expect("parses");
        assert!(!format!("{config:?}").contains("9f86"));
    }
}
