//! Parse and validate an `assets/triggers.json` document (contract
//! `greentic.triggers.v1`, `docs/trigger-contract-v1.md` in greentic-designer).
//!
//! Two failure granularities, both from the contract:
//!
//! - **Whole file** (§6.1, §7.1): a wrong `schema`, a `pack_id` that is not the
//!   containing pack's, a duplicated `trigger_id`, or a malformed entry of a
//!   kind this host knows. Nothing from the pack starts, and one line says why.
//!   A half-understood file is not served.
//! - **One entry** (§11): an unknown `kind`, `verify.scheme` or
//!   `challenge.scheme`. That entry is skipped with a warning and the rest
//!   start, so an older host keeps serving what it understands when a newer
//!   designer adds a kind.
//!
//! Unknown FIELDS are ignored everywhere (no `deny_unknown_fields`): that is
//! the additive-growth promise of §11.

use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

use super::field_ref::FieldRef;

pub(crate) const SCHEMA_V1: &str = "greentic.triggers.v1";

const DEFAULT_MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_MAX_BODY_BYTES: usize = 5 * 1024 * 1024;
const DEFAULT_IDEMPOTENCY_TTL_S: u64 = 86_400;
const MAX_IDEMPOTENCY_TTL_S: u64 = 604_800;
const DEFAULT_CRON_CONCURRENCY: u32 = 1;
const DEFAULT_WEBHOOK_CONCURRENCY: u32 = 8;

/// One accepted trigger, typed.
#[derive(Clone, Debug)]
pub(crate) struct TriggerSpec {
    pub trigger_id: String,
    pub flow_id: String,
    pub entry_node: String,
    pub enabled: bool,
    pub session: SessionSpec,
    pub max_concurrency: u32,
    pub max_firings_per_hour: Option<u32>,
    pub extension_id: String,
    pub node_id: String,
    pub kind: TriggerKind,
}

#[derive(Clone, Debug)]
pub(crate) enum TriggerKind {
    Cron(CronSpec),
    Webhook(WebhookSpec),
}

impl TriggerKind {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            TriggerKind::Cron(_) => "cron",
            TriggerKind::Webhook(_) => "webhook",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CronSpec {
    /// The expression as declared, for logs and the flow payload.
    pub expr: String,
    pub schedule: cron::Schedule,
    pub timezone: chrono_tz::Tz,
}

#[derive(Clone, Debug)]
pub(crate) struct WebhookSpec {
    /// Upper-case HTTP methods that fire the trigger.
    pub methods: Vec<String>,
    pub verify: Verify,
    pub challenge: Option<Challenge>,
    pub idempotency: Option<Idempotency>,
    pub max_body_bytes: usize,
    pub allowed_sources: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HmacAlgo {
    Sha256,
    Sha1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SignatureEncoding {
    Hex,
    Base64,
}

#[derive(Clone, Debug)]
pub(crate) enum Verify {
    None,
    Hmac {
        algo: HmacAlgo,
        header: String,
        prefix: String,
        encoding: SignatureEncoding,
        secret_ref: String,
    },
    Bearer {
        header: String,
        secret_ref: String,
    },
}

#[derive(Clone, Debug)]
pub(crate) enum Challenge {
    MetaHub { verify_token_ref: String },
}

#[derive(Clone, Debug)]
pub(crate) struct Idempotency {
    pub key: FieldRef,
    pub ttl_s: u64,
}

#[derive(Clone, Debug)]
pub(crate) enum SessionSpec {
    PerRun,
    PerKey(FieldRef),
}

/// The outcome of parsing one file: the accepted triggers, plus one warning per
/// entry that was skipped for being newer than this host (§11).
#[derive(Debug, Default)]
pub(crate) struct ParsedTriggers {
    pub triggers: Vec<TriggerSpec>,
    pub skipped: Vec<String>,
}

/// Parse `bytes` as the `assets/triggers.json` of the pack whose manifest id is
/// `pack_id`.
pub(crate) fn parse(bytes: &[u8], pack_id: &str) -> Result<ParsedTriggers> {
    let doc: Value = serde_json::from_slice(bytes).context("triggers.json is not valid JSON")?;
    let schema = str_field(&doc, "schema")?;
    if schema != SCHEMA_V1 {
        bail!("unsupported schema `{schema}` (this host reads `{SCHEMA_V1}`)");
    }
    let declared_pack = str_field(&doc, "pack_id")?;
    if declared_pack != pack_id {
        bail!("pack_id `{declared_pack}` does not match the containing pack `{pack_id}`");
    }
    let entries = doc
        .get("triggers")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("`triggers` must be an array"))?;

    let mut parsed = ParsedTriggers::default();
    let mut seen = std::collections::HashSet::new();
    for entry in entries {
        let trigger_id = str_field(entry, "trigger_id")?;
        if !is_valid_trigger_id(trigger_id) {
            bail!("trigger_id `{trigger_id}` does not match [a-z0-9][a-z0-9_-]{{0,62}}");
        }
        if !seen.insert(trigger_id.to_string()) {
            bail!("trigger_id `{trigger_id}` is declared twice");
        }
        match parse_entry(entry, trigger_id).with_context(|| format!("trigger `{trigger_id}`"))? {
            EntryOutcome::Accepted(spec) => parsed.triggers.push(*spec),
            EntryOutcome::Skipped(reason) => parsed
                .skipped
                .push(format!("trigger `{trigger_id}` skipped: {reason}")),
        }
    }
    Ok(parsed)
}

enum EntryOutcome {
    Accepted(Box<TriggerSpec>),
    Skipped(String),
}

fn parse_entry(entry: &Value, trigger_id: &str) -> Result<EntryOutcome> {
    let kind_name = str_field(entry, "kind")?;
    let kind = match kind_name {
        "cron" => TriggerKind::Cron(parse_cron(block(entry, "cron")?)?),
        "webhook" => match parse_webhook(block(entry, "webhook")?)? {
            Some(spec) => TriggerKind::Webhook(spec),
            None => return Ok(EntryOutcome::Skipped(unknown_scheme_reason(entry))),
        },
        other => return Ok(EntryOutcome::Skipped(format!("unknown kind `{other}`"))),
    };
    let default_concurrency = match kind {
        TriggerKind::Cron(_) => DEFAULT_CRON_CONCURRENCY,
        TriggerKind::Webhook(_) => DEFAULT_WEBHOOK_CONCURRENCY,
    };
    let limits = entry.get("limits");
    let max_concurrency = match limits.and_then(|l| l.get("max_concurrency")) {
        None | Some(Value::Null) => default_concurrency,
        Some(v) => positive_u32(v, "limits.max_concurrency")?,
    };
    let max_firings_per_hour = match limits.and_then(|l| l.get("max_firings_per_hour")) {
        None | Some(Value::Null) => None,
        Some(v) => Some(positive_u32(v, "limits.max_firings_per_hour")?),
    };
    let source = block(entry, "source")?;
    Ok(EntryOutcome::Accepted(Box::new(TriggerSpec {
        trigger_id: trigger_id.to_string(),
        flow_id: non_empty(entry, "flow_id")?,
        entry_node: non_empty(entry, "entry_node")?,
        enabled: entry
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        session: parse_session(entry.get("session"))?,
        max_concurrency,
        max_firings_per_hour,
        extension_id: non_empty(source, "extension_id")?,
        node_id: non_empty(source, "node_id")?,
        kind,
    })))
}

fn parse_cron(block: &Value) -> Result<CronSpec> {
    let expr = non_empty(block, "expr")?;
    let schedule = cron::Schedule::from_str(&normalize_cron(&expr))
        .with_context(|| format!("cron.expr `{expr}` does not parse"))?;
    let timezone = match block.get("timezone").and_then(Value::as_str) {
        None => chrono_tz::UTC,
        Some(name) => chrono_tz::Tz::from_str(name)
            .map_err(|_| anyhow!("cron.timezone `{name}` is not an IANA zone name"))?,
    };
    Ok(CronSpec {
        expr,
        schedule,
        timezone,
    })
}

/// The runner's own rule (`adapt_timer::normalize_cron`): a 5-field expression
/// gains a leading seconds field of `0`, so the two dialects agree on meaning.
pub(crate) fn normalize_cron(expr: &str) -> String {
    let trimmed = expr.trim();
    if trimmed.split_whitespace().count() == 5 {
        format!("0 {trimmed}")
    } else {
        trimmed.to_string()
    }
}

/// `Ok(None)` when the verify or challenge scheme is newer than this host.
fn parse_webhook(block: &Value) -> Result<Option<WebhookSpec>> {
    let methods = match block.get("methods") {
        None | Some(Value::Null) => vec!["POST".to_string()],
        Some(Value::Array(items)) => items
            .iter()
            .map(|m| {
                m.as_str()
                    .map(str::to_ascii_uppercase)
                    .ok_or_else(|| anyhow!("webhook.methods must be strings"))
            })
            .collect::<Result<Vec<_>>>()?,
        Some(_) => bail!("webhook.methods must be an array"),
    };
    let Some(verify) = parse_verify(block.get("verify"))? else {
        return Ok(None);
    };
    let challenge = match block.get("challenge") {
        None | Some(Value::Null) => None,
        Some(c) => match str_field(c, "scheme")? {
            "meta_hub" => Some(Challenge::MetaHub {
                verify_token_ref: secret_ref(c, "verify_token_ref")?,
            }),
            _ => return Ok(None),
        },
    };
    if challenge.is_some() && methods.iter().any(|m| m == "GET") {
        bail!("GET cannot fire a trigger that declares a challenge (§6.3.2)");
    }
    let idempotency = match block.get("idempotency") {
        None | Some(Value::Null) => None,
        Some(i) => {
            let ttl_s = match i.get("ttl_s") {
                None | Some(Value::Null) => DEFAULT_IDEMPOTENCY_TTL_S,
                Some(v) => {
                    let ttl = v
                        .as_u64()
                        .ok_or_else(|| anyhow!("idempotency.ttl_s must be an integer"))?;
                    if ttl == 0 || ttl > MAX_IDEMPOTENCY_TTL_S {
                        bail!("idempotency.ttl_s must be 1..={MAX_IDEMPOTENCY_TTL_S}");
                    }
                    ttl
                }
            };
            Some(Idempotency {
                key: FieldRef::parse(&non_empty(i, "key")?)?,
                ttl_s,
            })
        }
    };
    let max_body_bytes = match block.get("max_body_bytes") {
        None | Some(Value::Null) => DEFAULT_MAX_BODY_BYTES,
        Some(v) => {
            let n = v
                .as_u64()
                .ok_or_else(|| anyhow!("webhook.max_body_bytes must be an integer"))?
                as usize;
            if n == 0 || n > MAX_MAX_BODY_BYTES {
                bail!("webhook.max_body_bytes must be 1..={MAX_MAX_BODY_BYTES}");
            }
            n
        }
    };
    let allowed_sources = match block.get("allowed_sources") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|s| {
                s.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow!("webhook.allowed_sources must be strings"))
            })
            .collect::<Result<Vec<_>>>()?,
        Some(_) => bail!("webhook.allowed_sources must be an array"),
    };
    Ok(Some(WebhookSpec {
        methods,
        verify,
        challenge,
        idempotency,
        max_body_bytes,
        allowed_sources,
    }))
}

/// `Ok(None)` for a scheme newer than this host. `verify` itself is required:
/// there is deliberately no default, so an unverified public endpoint is always
/// something an author wrote down (§6.3.2).
fn parse_verify(verify: Option<&Value>) -> Result<Option<Verify>> {
    let verify = verify.ok_or_else(|| anyhow!("webhook.verify is required"))?;
    let scheme = str_field(verify, "scheme")?;
    let parsed = match scheme {
        "none" => Verify::None,
        "hmac-sha256" | "hmac-sha1" => Verify::Hmac {
            algo: if scheme == "hmac-sha256" {
                HmacAlgo::Sha256
            } else {
                HmacAlgo::Sha1
            },
            header: non_empty(verify, "header")?,
            prefix: verify
                .get("prefix")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            encoding: match verify.get("encoding").and_then(Value::as_str) {
                None | Some("hex") => SignatureEncoding::Hex,
                Some("base64") => SignatureEncoding::Base64,
                Some(other) => bail!("verify.encoding `{other}` must be `hex` or `base64`"),
            },
            secret_ref: secret_ref(verify, "secret_ref")?,
        },
        "bearer" => Verify::Bearer {
            header: verify
                .get("header")
                .and_then(Value::as_str)
                .unwrap_or("Authorization")
                .to_string(),
            secret_ref: secret_ref(verify, "secret_ref")?,
        },
        _ => return Ok(None),
    };
    Ok(Some(parsed))
}

fn unknown_scheme_reason(entry: &Value) -> String {
    let verify = entry
        .pointer("/webhook/verify/scheme")
        .and_then(Value::as_str);
    let challenge = entry
        .pointer("/webhook/challenge/scheme")
        .and_then(Value::as_str);
    format!(
        "verify scheme {:?} / challenge scheme {:?} not supported by this host",
        verify, challenge
    )
}

fn parse_session(session: Option<&Value>) -> Result<SessionSpec> {
    let Some(session) = session.filter(|s| !s.is_null()) else {
        return Ok(SessionSpec::PerRun);
    };
    match session
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("per_run")
    {
        "per_run" => Ok(SessionSpec::PerRun),
        "per_key" => Ok(SessionSpec::PerKey(FieldRef::parse(&non_empty(
            session, "key",
        )?)?)),
        other => bail!("session.mode `{other}` must be `per_run` or `per_key`"),
    }
}

/// `[a-z0-9][a-z0-9_-]{0,62}`: it becomes a URL segment and a store key.
pub(crate) fn is_valid_trigger_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

/// A secret REFERENCE: `<provider>/<key>`, never a value (§5). A pasted token
/// has no `/` and is refused here as well as by the designer, so a file built
/// by anything else cannot smuggle a credential into a public verify path.
pub(crate) fn is_valid_secret_ref(value: &str) -> bool {
    fn segment_ok(s: &str) -> bool {
        let bytes = s.as_bytes();
        !bytes.is_empty()
            && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
            && bytes.iter().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
            })
    }
    match value.split_once('/') {
        Some((provider, key)) => !key.contains('/') && segment_ok(provider) && segment_ok(key),
        None => false,
    }
}

fn secret_ref(block: &Value, field: &str) -> Result<String> {
    let value = non_empty(block, field)?;
    if !is_valid_secret_ref(&value) {
        // Never echo the value: if this is a pasted credential, a log line is
        // exactly where it must not end up.
        bail!("`{field}` is not a <provider>/<key> secret reference");
    }
    Ok(value)
}

fn block<'a>(v: &'a Value, field: &str) -> Result<&'a Value> {
    v.get(field)
        .filter(|b| b.is_object())
        .ok_or_else(|| anyhow!("`{field}` block is required"))
}

fn str_field<'a>(v: &'a Value, field: &str) -> Result<&'a str> {
    v.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("`{field}` must be a string"))
}

fn non_empty(v: &Value, field: &str) -> Result<String> {
    let s = str_field(v, field)?.trim();
    if s.is_empty() {
        bail!("`{field}` must not be empty");
    }
    Ok(s.to_string())
}

fn positive_u32(v: &Value, field: &str) -> Result<u32> {
    v.as_u64()
        .filter(|n| *n >= 1 && *n <= u64::from(u32::MAX))
        .map(|n| n as u32)
        .ok_or_else(|| anyhow!("`{field}` must be a positive integer"))
}

#[cfg(test)]
#[path = "schema_tests.rs"]
mod tests;
