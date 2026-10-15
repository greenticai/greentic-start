//! The Jev routing tier: classify a free-text turn with Jev (TypeSafe AI's
//! typed-decision API) when the host router (BM25) found nothing.
//!
//! Order of a turn: host router -> **Jev** -> embedded LLM fallback -> the
//! pack's miss policy. A route from an earlier tier wins; `Deny`/`Respond`
//! stop routing before this tier is reached (see `turn::probe_turn`).
//!
//! * **Off unless configured** ([`config`]). With no `jev` block anywhere
//!   nothing here runs: no secret is read, no request is made, no log line is
//!   written.
//! * **Fails open.** Every failure — secret missing or unreadable, timeout,
//!   transport error, non-2xx, garbage, low confidence, an option that is not
//!   one of ours — is `None`, so the next tier (and finally the existing miss
//!   behaviour) gets the turn exactly as it would have without this tier. The
//!   first occurrence of each failure class is a `warn`, the rest `debug`.
//! * **The key is a NAME.** It is read from the secrets store at call time (a
//!   rotated key applies on the next turn), held in a value whose `Debug`
//!   prints nothing, and sent only as the bearer header. It is never in
//!   config, an error, or a log line; neither is the message text.
//!
//! Blocking, like the rest of the probe: callers run it on a blocking thread.

pub(crate) mod client;
pub(crate) mod config;

use greentic_types::ChannelMessageEnvelope;

use self::client::{JevChoice, NONE_OPTION};
use self::config::{JevBlock, JevSettings};
use super::FAST2FLOW_CAPABILITY;
use super::contracts::RoutingDirective;
use super::dispatch::{self, RouteDecision};
use super::index_refresh::WarnOnce;
use super::llm_router::{Candidate, candidates_from_index};
use super::mapper::map_directive_to_control;
use super::probe::ProbeInputs;
use super::turn::RouteSource;
use crate::inbound_verify::secrets::SecretRead;
use crate::operator_log;

/// Where a turn reads the Jev key NAME from the secrets store.
pub(crate) trait JevKeys: Send + Sync {
    fn read(&self, name: &str) -> SecretRead;
}

/// What the probe needs to run the tier. `None` on [`ProbeInputs`] = no way to
/// read a key = the tier cannot run.
pub(crate) struct JevInputs<'a> {
    /// The bundle's `jev:` block (legacy ingress); `None` when it has none.
    pub(crate) operator: Option<&'a JevBlock>,
    pub(crate) keys: &'a dyn JevKeys,
}

/// Reads the key through a secrets manager, in the scopes a channel secret of
/// this pack is read from (`inbound_verify::secrets::candidate_uris`).
pub(crate) struct ManagerKeys {
    pub(crate) secrets: crate::secrets_gate::DynSecretsManager,
    pub(crate) env: String,
    pub(crate) tenant: String,
    pub(crate) pack_id: String,
    pub(crate) unit_id: String,
}

impl JevKeys for ManagerKeys {
    fn read(&self, name: &str) -> SecretRead {
        let names = [name];
        let read = crate::inbound_verify::secrets::read_channel_secret(
            &self.secrets,
            &self.env,
            &self.tenant,
            &self.pack_id,
            &self.unit_id,
            &names,
        );
        crate::llm::block_on(read).unwrap_or(SecretRead::Unavailable)
    }
}

/// Failure classes already reported, so a condition that holds on every turn is
/// one `warn`, not one per message.
static REPORTED: std::sync::LazyLock<WarnOnce<&'static str>> =
    std::sync::LazyLock::new(Default::default);

fn report(seen: &WarnOnce<&'static str>, class: &'static str, line: String) {
    if seen.first(class) {
        operator_log::warn(
            module_path!(),
            format!("[fast2flow:jev] {line} - falling through (reported once per cause)"),
        );
    } else {
        operator_log::debug(module_path!(), format!("[fast2flow:jev] {line}"));
    }
}

/// Route `original` with Jev, or `None` to fall through.
pub(crate) fn route(
    i: &ProbeInputs<'_>,
    original: &ChannelMessageEnvelope,
) -> Option<RouteDecision> {
    route_reporting(i, original, &REPORTED)
}

fn route_reporting(
    i: &ProbeInputs<'_>,
    original: &ChannelMessageEnvelope,
    seen: &WarnOnce<&'static str>,
) -> Option<RouteDecision> {
    let jev = i.jev.as_ref()?;
    // Cheap gates first, in the LLM fallback's order, so a turn that would not
    // be routed anyway never opens the pack or the secrets store.
    if !i
        .pack
        .capabilities
        .iter()
        .any(|c| c == FAST2FLOW_CAPABILITY)
    {
        return None;
    }
    let text = original
        .text
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())?;
    let settings = settings_for(i, jev, seen)?;
    let index_path = super::resolve_index_path(i.cfg, i.ctx, i.pack_path, i.index_scope)?;
    let bytes = std::fs::read(&index_path).ok()?;
    let candidates = candidates_from_index(&bytes);
    if candidates.is_empty() {
        return None;
    }

    let key = match jev.keys.read(&settings.secret_name) {
        SecretRead::Found(secret) => secret,
        SecretRead::Absent => {
            report(
                seen,
                "secret_missing",
                format!("secret `{}` is not set", settings.secret_name),
            );
            return None;
        }
        SecretRead::Unavailable => {
            report(
                seen,
                "secret_unavailable",
                format!("secret `{}` could not be read", settings.secret_name),
            );
            return None;
        }
    };

    let body = client::build_body(text, &candidates, settings.model.as_deref());
    let choice = match client::decide(&settings.endpoint, key.expose(), settings.timeout, &body) {
        Ok(choice) => choice,
        Err(err) => {
            report(seen, err.class(), format!("Jev {}", err.describe()));
            return None;
        }
    };
    accept(i, original, &settings, &candidates, choice)
}

/// The operator's block combined with the pack's. A pack block that cannot be
/// used leaves the tier off for the turn, reported once.
fn settings_for(
    i: &ProbeInputs<'_>,
    jev: &JevInputs<'_>,
    seen: &WarnOnce<&'static str>,
) -> Option<JevSettings> {
    let pack = match config::read_pack_block(i.pack_path) {
        Ok(pack) => pack,
        Err(why) => {
            report(seen, "bad_config", why);
            return None;
        }
    };
    match config::effective(jev.operator, pack.as_ref()) {
        Ok(settings) => settings,
        Err(why) => {
            report(seen, "bad_config", why);
            None
        }
    }
}

/// Turn Jev's choice into a route, or `None` when it is not one we can trust.
fn accept(
    i: &ProbeInputs<'_>,
    original: &ChannelMessageEnvelope,
    settings: &JevSettings,
    candidates: &[Candidate],
    choice: JevChoice,
) -> Option<RouteDecision> {
    if choice.option == NONE_OPTION {
        operator_log::info(
            module_path!(),
            "[fast2flow:jev] abstained: no destination fits",
        );
        return None;
    }
    if choice.confidence < settings.min_confidence {
        operator_log::info(
            module_path!(),
            format!(
                "[fast2flow:jev] abstain confidence={:.3} < threshold={:.3}",
                choice.confidence, settings.min_confidence
            ),
        );
        return None;
    }
    let ids = client::option_ids(candidates);
    let Some(candidate) = ids
        .iter()
        .position(|id| *id == choice.option)
        .and_then(|n| candidates.get(n))
    else {
        // Not one of the ids we offered: the answer is not about our options.
        operator_log::warn(
            module_path!(),
            "[fast2flow:jev] rejected an option that was not offered",
        );
        return None;
    };
    operator_log::info(
        module_path!(),
        format!(
            "[fast2flow] dispatch target={} confidence={:.3} reason=jev",
            candidate.target, choice.confidence
        ),
    );
    match map_directive_to_control(
        RoutingDirective::Dispatch {
            target: candidate.target.clone(),
            confidence: choice.confidence,
            reason: "jev".to_string(),
            entities: Vec::new(),
        },
        i.ctx,
    ) {
        crate::ingress::control_directive::ControlDirective::Continue => None,
        directive => dispatch::apply_dispatch(directive, i.pack, original, RouteSource::Jev).ok(),
    }
}

#[cfg(all(test, unix))]
mod mock_server;
#[cfg(all(test, unix))]
#[path = "route_tests.rs"]
mod tests;
