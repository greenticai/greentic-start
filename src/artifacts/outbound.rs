//! Files an agent created reach the user (docs/outbound-artifacts.md).
//!
//! A `dw.agent` reply carries its tool results in `trail`; a result that
//! names an `artifact://` id (master contract C5) is collected here, OUT OF
//! BAND (an [`OutboundSide`] keyed by envelope id, never a field of the
//! envelope), resolved against what THIS unit's extension port created
//! ([`super::recent_puts`]), signed ([`super::link`]) and shaped per channel
//! ([`super::outbound_shape`]):
//!
//! - WebChat: a typed attachment whose `url` is the signed link;
//! - every other channel: the link in the message text (in a follow-up
//!   message when a card would hide the text).
//!
//! A flow-authored full envelope cannot ask for a link, and any raw
//! `artifact://` url left in an outgoing envelope is removed before egress:
//! no provider validates an outbound url. Nothing here logs a link or an id.

use std::sync::{Arc, Mutex};

use greentic_types::ChannelMessageEnvelope;
use serde_json::Value;

use super::link::{self, mint};
use super::link_base::{LinkBase, link_url};
use super::link_table::LinkUnit;
use super::provenance::Occurrences;
use super::wire::is_artifact_id;

/// At most this many files per reply (master contract).
pub(crate) const MAX_OUTBOUND: usize = 5;

pub(crate) const NOT_FROM_THIS_WORKER: &str = "A file could not be sent.";
pub(crate) const NO_PUBLIC_ADDRESS: &str = "A file was created but cannot be sent on this \
     channel because this worker has no public https address.";
pub(crate) const LINKS_OFF: &str =
    "A file was created but file delivery is turned off for this worker.";
/// The legacy `--bundle` lane has no door, no signer and no route.
pub(crate) const LEGACY_UNSENT: &str = "A file was created but this host cannot send files.";

/// One file a reply names. Only the id is used: a tool's claim about the
/// name or type is untrusted (the door's record at put time is used).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct C5Ref {
    pub id: String,
}

fn artifact_id_of(value: &Value) -> Option<String> {
    value
        .get("artifact")?
        .get("id")?
        .as_str()
        .filter(|id| is_artifact_id(id))
        .map(str::to_string)
}

/// A trail step's result, as a JSON object (a tool may answer with the JSON
/// as a string).
fn result_object(step: &Value) -> Option<Value> {
    match step.get("result")? {
        Value::String(raw) => serde_json::from_str::<Value>(raw).ok(),
        other => Some(other.clone()),
    }
}

/// The files a reply payload names, in order, deduplicated, at most
/// [`MAX_OUTBOUND`]: every `tool_call` trail step whose result is `ok: true`
/// with a well-formed `artifact.id`, then a top-level `artifact` or
/// `response.artifact`. A payload that is itself a full envelope (a flow
/// emitting one) names nothing: it cannot ask for a link.
pub(crate) fn collect(payload: &Value) -> Vec<C5Ref> {
    if serde_json::from_value::<ChannelMessageEnvelope>(payload.clone()).is_ok() {
        return Vec::new();
    }
    let mut ids: Vec<String> = Vec::new();
    let steps = payload
        .get("trail")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for step in steps {
        if step.get("kind").and_then(Value::as_str) != Some("tool_call") {
            continue;
        }
        let Some(result) = result_object(step) else {
            continue;
        };
        if result.get("ok").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        ids.extend(artifact_id_of(&result));
    }
    ids.extend(artifact_id_of(payload));
    ids.extend(payload.get("response").and_then(artifact_id_of));
    let mut refs: Vec<C5Ref> = Vec::new();
    for id in ids {
        if refs.len() == MAX_OUTBOUND {
            break;
        }
        if !refs.iter().any(|known| known.id == id) {
            refs.push(C5Ref { id });
        }
    }
    refs
}

/// Why a named file was not delivered. Each becomes a fixed sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Undeliverable {
    NotFromThisWorker,
    NoPublicAddress,
    LinksOff,
}

impl Undeliverable {
    pub(crate) fn sentence(self) -> &'static str {
        match self {
            Undeliverable::NotFromThisWorker => NOT_FROM_THIS_WORKER,
            Undeliverable::NoPublicAddress => NO_PUBLIC_ADDRESS,
            Undeliverable::LinksOff => LINKS_OFF,
        }
    }
}

/// A file ready to send: the door's own type and size, the port's name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutboundFile {
    pub name: String,
    pub mime_type: String,
    pub size_bytes: u64,
    /// The signed link (a bearer secret for one file until it expires).
    pub url: String,
}

#[derive(Debug, Default)]
pub(crate) struct Resolved {
    pub files: Vec<OutboundFile>,
    pub refused: Vec<Undeliverable>,
}

impl Resolved {
    pub(crate) fn is_empty(&self) -> bool {
        self.files.is_empty() && self.refused.is_empty()
    }
}

/// What one reply batch may link with: the unit's signer (if any), the
/// public base, and the kill switch.
pub(crate) struct OutboundCtx {
    pub unit: Option<Arc<LinkUnit>>,
    pub base: LinkBase,
    pub enabled: bool,
}

impl OutboundCtx {
    /// The kill switch is read HERE, never left to a caller.
    pub(crate) fn new(unit: Option<Arc<LinkUnit>>, base: LinkBase) -> Self {
        Self {
            unit,
            base,
            enabled: link::links_enabled(),
        }
    }
}

/// Signs each named file this unit created within the link TTL; everything
/// else is refused with its reason.
pub(crate) fn resolve(
    refs: &[C5Ref],
    ctx: &OutboundCtx,
    is_webchat: bool,
    now: u64,
    ttl: u64,
) -> Resolved {
    let mut resolved = Resolved::default();
    let unit = ctx.unit.as_deref().filter(|_| ctx.enabled);
    for reference in refs {
        let Some(unit) = unit else {
            resolved.refused.push(Undeliverable::LinksOff);
            continue;
        };
        let Some(record) = unit.recent.lookup(&reference.id, now, ttl) else {
            resolved.refused.push(Undeliverable::NotFromThisWorker);
            continue;
        };
        if ctx.base == LinkBase::RelativeOnly && !is_webchat {
            resolved.refused.push(Undeliverable::NoPublicAddress);
            continue;
        }
        let Some(path) = mint(&unit.key, &unit.deployment, &reference.id, now, ttl) else {
            resolved.refused.push(Undeliverable::NotFromThisWorker);
            continue;
        };
        resolved.files.push(OutboundFile {
            name: record.name,
            mime_type: record.mime_type,
            size_bytes: record.size_bytes,
            url: link_url(&ctx.base, &path),
        });
    }
    resolved
}

/// The out-of-band carrier: filled by the reply-shaping closure, drained by
/// the egress loop. Keyed by the reply envelope's id (a fresh UUID).
#[derive(Default)]
pub(crate) struct OutboundSide(Mutex<Vec<(Option<String>, Vec<C5Ref>)>>);

impl OutboundSide {
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<(Option<String>, Vec<C5Ref>)>> {
        match self.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Attaches `refs` to the FIRST of `envelopes`, or, when the reply
    /// produced none (a file-only turn), to no envelope: the egress loop
    /// then builds one.
    pub(crate) fn record(&self, envelopes: &[ChannelMessageEnvelope], refs: Vec<C5Ref>) {
        if refs.is_empty() {
            return;
        }
        let key = envelopes.first().map(|envelope| envelope.id.clone());
        self.lock().push((key, refs));
    }

    pub(crate) fn take(&self, envelope_id: &str) -> Vec<C5Ref> {
        self.take_where(|key| key.as_deref() == Some(envelope_id))
    }

    pub(crate) fn take_orphans(&self) -> Vec<C5Ref> {
        self.take_where(Option::is_none)
    }

    fn take_where(&self, wanted: impl Fn(&Option<String>) -> bool) -> Vec<C5Ref> {
        let mut entries = self.lock();
        let mut taken: Vec<C5Ref> = Vec::new();
        entries.retain(|(key, refs)| {
            if wanted(key) {
                for reference in refs {
                    if taken.len() < MAX_OUTBOUND && !taken.contains(reference) {
                        taken.push(reference.clone());
                    }
                }
                false
            } else {
                true
            }
        });
        taken
    }
}

static STRIPPED: Occurrences = Occurrences::new();

fn log_stripped(stripped: usize) {
    if STRIPPED.record(stripped) {
        tracing::warn!(
            stripped,
            "a reply carried raw artifact references; they were removed before egress \
             (later occurrences are counted at debug)"
        );
    } else if stripped > 0 {
        tracing::debug!(
            stripped,
            total = STRIPPED.total(),
            "raw artifact references removed"
        );
    }
}

/// [`super::outbound_shape::strip_raw_artifact_urls`] with the count-only log.
pub(crate) fn strip_logged(envelope: &mut ChannelMessageEnvelope) -> usize {
    let stripped = super::outbound_shape::strip_raw_artifact_urls(envelope);
    log_stripped(stripped);
    stripped
}

/// The legacy `--bundle` lane: a reply whose flow output names a file gets
/// [`LEGACY_UNSENT`] on its first envelope. Returns whether it did.
pub(crate) fn declare_legacy_unsent(
    payload: &Value,
    envelopes: &mut [ChannelMessageEnvelope],
) -> bool {
    let Some(first) = envelopes.first_mut() else {
        return false;
    };
    if collect(payload).is_empty() {
        return false;
    }
    let text = first.text.as_deref().map(str::trim).unwrap_or_default();
    first.text = Some(if text.is_empty() {
        LEGACY_UNSENT.to_string()
    } else {
        format!("{text}\n\n{LEGACY_UNSENT}")
    });
    true
}

/// The egress hook: strips raw `artifact://` urls from every reply, then
/// shapes each reply that carries files (and synthesises one from `ingress`
/// for a file-only turn). Counts only are logged.
pub(crate) fn prepare_replies(
    replies: Vec<ChannelMessageEnvelope>,
    side: &OutboundSide,
    ingress: &ChannelMessageEnvelope,
    provider_type: &str,
    ctx: &OutboundCtx,
    now: u64,
) -> Vec<ChannelMessageEnvelope> {
    let is_webchat = super::outbound_shape::is_webchat(provider_type);
    let ttl = link::ttl_secs();
    let (mut linked, mut refused, mut stripped) = (0usize, 0usize, 0usize);
    let mut out = Vec::with_capacity(replies.len());
    let mut shape_one = |mut envelope: ChannelMessageEnvelope, refs: Vec<C5Ref>| {
        stripped += super::outbound_shape::strip_raw_artifact_urls(&mut envelope);
        let resolved = resolve(&refs, ctx, is_webchat, now, ttl);
        linked += resolved.files.len();
        refused += resolved.refused.len();
        out.extend(super::outbound_shape::shape(
            envelope,
            provider_type,
            &resolved,
        ));
    };
    for envelope in replies {
        let refs = side.take(&envelope.id);
        shape_one(envelope, refs);
    }
    let orphans = side.take_orphans();
    if !orphans.is_empty() {
        shape_one(crate::messaging_app::base_reply_envelope(ingress), orphans);
    }
    log_stripped(stripped);
    if linked + refused + stripped > 0 {
        tracing::info!(
            artifacts_linked = linked,
            refused,
            stripped,
            "outbound files shaped"
        );
    }
    out
}
