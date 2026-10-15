//! The Jev (TypeSafe AI System One) call: request shaping, transport, and
//! response mapping.
//!
//! The wire contract is the one `greentic.jev`'s `decide` tool already speaks
//! (component-jev-ext `input.rs` / `output.rs`): `POST /v1/systemone` with
//! `{ state, model, questions }`, `Authorization: Bearer <key>`, answered by
//! `{ model, answers: { <id>: { choice, confidence, probabilities } } }`. Router
//! asks exactly one `choice` question.
//!
//! Nothing here logs, and [`JevError`] carries only a class and a status code:
//! neither the key, the message text nor a response body can reach a log line
//! through it.

use std::time::Duration;

use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::super::llm_router::Candidate;

/// Model asked for when the settings name none (same default as the tool).
pub(crate) const DEFAULT_MODEL: &str = "jev-latest";
/// The id the single routing question is asked and answered under.
pub(crate) const QUESTION_ID: &str = "route";
/// The option that means "none of the destinations fit".
pub(crate) const NONE_OPTION: &str = "none";
/// Message text sent as `state` is cut here: a routing decision needs the gist,
/// and an unbounded user message is not ours to forward.
const MAX_STATE_CHARS: usize = 2_000;
const MAX_DESCRIPTION_CHARS: usize = 400;
const MAX_RESPONSE_BYTES: u64 = 256 * 1024;

/// Why a Jev call produced no answer. A class, never a payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JevError {
    Timeout,
    Transport,
    Status(u16),
    Decode,
    NoAnswer,
}

impl JevError {
    /// A short, payload-free description for operator logs.
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::Timeout => "timed out".to_string(),
            Self::Transport => "could not be reached".to_string(),
            Self::Status(code) => format!("answered HTTP {code}"),
            Self::Decode => "answered something unreadable".to_string(),
            Self::NoAnswer => "returned no usable answer".to_string(),
        }
    }

    /// The key the warn-once memo uses (a status class, not the exact code).
    pub(crate) fn class(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Transport => "transport",
            Self::Status(401 | 403) => "auth",
            Self::Status(429) => "rate_limited",
            Self::Status(500..=599) => "server_error",
            Self::Status(_) => "rejected",
            Self::Decode => "decode",
            Self::NoAnswer => "no_answer",
        }
    }
}

/// What Jev picked.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct JevChoice {
    pub option: String,
    pub confidence: f32,
}

/// One option id per candidate (`opt_1`, ...), kept in order so the answer maps
/// back. Ids rather than the targets themselves: a target is a path the model
/// might reformat, an id it can only echo.
pub(crate) fn option_ids(candidates: &[Candidate]) -> Vec<String> {
    (1..=candidates.len()).map(|n| format!("opt_{n}")).collect()
}

fn describe(candidate: &Candidate) -> String {
    let mut text = candidate.title.trim().to_string();
    if !candidate.hints.is_empty() {
        if !text.is_empty() {
            text.push_str(" - ");
        }
        text.push_str("e.g. ");
        text.push_str(&candidate.hints.join("; "));
    }
    if text.is_empty() {
        text = candidate.target.clone();
    }
    text.chars().take(MAX_DESCRIPTION_CHARS).collect()
}

/// The request body for one routing question.
pub(crate) fn build_body(text: &str, candidates: &[Candidate], model: Option<&str>) -> Value {
    let mut criteria = Map::new();
    for (id, candidate) in option_ids(candidates).into_iter().zip(candidates) {
        criteria.insert(id, Value::String(describe(candidate)));
    }
    criteria.insert(
        NONE_OPTION.to_string(),
        Value::String("None of the other options fits this message".to_string()),
    );
    let state: String = text.chars().take(MAX_STATE_CHARS).collect();
    json!({
        "state": state,
        "model": model.map(str::trim).filter(|m| !m.is_empty()).unwrap_or(DEFAULT_MODEL),
        "questions": {
            QUESTION_ID: {
                "type": "choice",
                "instructions": "Choose the destination that should handle this customer message. Choose 'none' when no destination fits.",
                "criteria": Value::Object(criteria),
            }
        }
    })
}

#[derive(Debug, Deserialize)]
struct Response {
    #[serde(default)]
    answers: Option<Map<String, Value>>,
}

/// Map a reply body to the choice made for [`QUESTION_ID`]. The confidence is
/// the answer's own `confidence`, else the probability of the chosen option;
/// with neither the answer cannot be trusted and is refused.
pub(crate) fn map_response(body: &[u8]) -> Result<JevChoice, JevError> {
    let parsed: Response = serde_json::from_slice(body).map_err(|_| JevError::Decode)?;
    let answer = parsed
        .answers
        .and_then(|mut answers| answers.remove(QUESTION_ID))
        .ok_or(JevError::NoAnswer)?;
    let option = answer
        .get("choice")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .ok_or(JevError::NoAnswer)?
        .to_string();
    let confidence = answer
        .get("confidence")
        .and_then(Value::as_f64)
        .or_else(|| {
            answer
                .get("probabilities")
                .and_then(|p| p.get(&option))
                .and_then(Value::as_f64)
        })
        .filter(|c| c.is_finite() && (0.0..=1.0).contains(c))
        .ok_or(JevError::NoAnswer)? as f32;
    Ok(JevChoice { option, confidence })
}

/// POST `body` and map the answer. Blocking; bounded by `timeout` for the whole
/// exchange. A non-2xx status is an error, never read as an answer.
pub(crate) fn decide(
    endpoint: &str,
    api_key: &str,
    timeout: Duration,
    body: &Value,
) -> Result<JevChoice, JevError> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .build()
        .new_agent();
    let mut response = agent
        .post(endpoint)
        .header("authorization", &format!("Bearer {api_key}"))
        .send_json(body)
        .map_err(|err| match err {
            ureq::Error::Timeout(_) => JevError::Timeout,
            _ => JevError::Transport,
        })?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(JevError::Status(status));
    }
    let bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_to_vec()
        .map_err(|err| match err {
            ureq::Error::Timeout(_) => JevError::Timeout,
            _ => JevError::Transport,
        })?;
    map_response(&bytes)
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
