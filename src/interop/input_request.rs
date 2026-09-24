//! What a parked turn asks an AGENT caller for (worker-interop contract §9.2).
//!
//! A flow that parks is asking a question. To a person it asks it with an
//! Adaptive Card; to a program that card is an unlabelled UI artefact it has
//! to reverse-engineer into a form. This module derives the question the card
//! is really asking — named, typed fields — from the card's own `Input.*`
//! elements, with no new authoring surface: the same card serves both
//! audiences.
//!
//! The emitted document rides as ONE `data` part of media type
//! [`INPUT_REQUEST_MEDIA_TYPE`], beside a `text` part carrying the same
//! question in prose:
//!
//! ```json
//! {"prompt": "Which plan?",
//!  "fields": [{"id": "plan", "label": "Plan", "type": "choice",
//!              "required": true, "multiSelect": false,
//!              "choices": [{"value": "pro", "label": "Pro"}]}],
//!  "actions": [{"id": "confirm", "label": "Confirm"}]}
//! ```
//!
//! All three keys are always present. `fields: []` is a real answer — a
//! display-only card the flow waits on asks for no named value and still has
//! to be answered to continue — and is not the same as not parking.
//!
//! # Answering one
//!
//! The caller replies with a message whose `data` part is
//! `{"<field id>": value, …}`. `a2a::rpc::message_payload`
//! lifts such a part to `{"metadata": …}`, which is the shape a card submit
//! travels in on this runtime — the same shape
//! `revision_serve::normalize_worker_payload` builds for `/workers/invoke`,
//! and the one greentic-runner-host's `submitted_fields` reads back out of
//! `entry.input.metadata.*` when it resumes the parked node.
//!
//! Two consequences of that, both measured against the pinned runner-host
//! rather than assumed:
//!
//! - **`action` is the route discriminator, not a field.** `submitted_fields`
//!   skips a metadata key called `action`, and a routing condition tests it
//!   as `response.action`. That is why an `actions` entry's `id` is taken
//!   from the card button's own submit `data.action` when it has one:
//!   sending `{"action": "<that id>"}` is how a caller presses the button,
//!   and a made-up id would route nowhere.
//! - **A text part no longer beats a data part.** It did until 2026-09-24,
//!   and an answer sent beside a sentence lost its fields without a word.
//!   `message_payload` now carries both — the answer under `metadata` and the
//!   joined text beside it — so a caller may say something about what it is
//!   submitting. A message with text and no usable data part, or a data part
//!   and no text, produces exactly the payload it always did.

use serde_json::{Map, Value, json};

/// Media type of the `data` part carrying an [`input_request`] (contract
/// D11).
pub(crate) const INPUT_REQUEST_MEDIA_TYPE: &str = "application/vnd.greentic.input-request+json";

/// Build the input request for a parked turn.
///
/// `prompt` is the question in prose — `reply::card_fallback_text` for a
/// parked card, the turn's own text otherwise. `card` is the Adaptive Card
/// the turn parked on, absent for a `session.wait` that rendered none.
pub(crate) fn input_request(prompt: &str, card: Option<&Value>) -> Value {
    let mut fields = Vec::new();
    let mut actions = Vec::new();
    if let Some(card) = card {
        collect_fields(card, &mut fields);
        collect_actions(card, &mut actions);
    }
    json!({"prompt": prompt, "fields": fields, "actions": actions})
}

/// Build the flow payload that ANSWERS an [`input_request`].
///
/// The ONE builder both interop surfaces use, so an MCP `answer` and an
/// agent-to-agent `data` part cannot reach the runtime in different shapes.
/// `answer` is field id → value exactly as the caller sent it; `text` is the
/// caller's own sentence when it sent one beside the answer — an MCP
/// `message` alongside an `answer`, or an agent-to-agent message carrying
/// both a text part and a data part.
///
/// The field ids are NOT checked against the card the turn parked on. This
/// server does not hold that card here, and a wrong id already fails the way
/// a wrong id fails from webchat — the flow does not route. A second, weaker
/// copy of the runner's own routing check would only refuse valid submits
/// (contract §9.4).
pub(crate) fn answer_payload(answer: &Map<String, Value>, text: Option<&str>) -> Value {
    let mut payload = Map::new();
    // `text` first so the envelope reads the way the messaging ingress
    // builds one; key order is cosmetic to serde_json's default map, and the
    // runner reads both by name.
    if let Some(text) = text {
        payload.insert("text".into(), Value::String(text.to_string()));
    }
    payload.insert("metadata".into(), Value::Object(answer.clone()));
    Value::Object(payload)
}

/// Every `Input.*` element in the card, in the order it is written.
///
/// A plain recursive descent rather than a walk of the container keys
/// Adaptive Cards happens to define today (`body`, `items`, `columns`,
/// `rows`, …): a card element this runtime has never heard of must not be
/// able to hide an input inside it. Order is the card's own; identity is the
/// `id`, so a reordering is cosmetic.
fn collect_fields(value: &Value, out: &mut Vec<Value>) {
    match value {
        Value::Object(map) => {
            if let Some(field) = field_from(map) {
                out.push(field);
            }
            for child in map.values() {
                collect_fields(child, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_fields(item, out)),
        _ => {}
    }
}

/// One field, or `None` when this object is not an input this runtime can
/// describe — including an input with no `id`, which no answer could name.
fn field_from(map: &Map<String, Value>) -> Option<Value> {
    let element = string_of(map, "type")?;
    let id = string_of(map, "id").filter(|id| !id.is_empty())?;
    let mut extras = Map::new();
    let kind = match element.as_str() {
        "Input.Text" => {
            carry_bool(map, "isMultiline", "multiline", &mut extras);
            carry_number(map, "maxLength", "maxLength", &mut extras);
            "text"
        }
        "Input.Number" => {
            carry_number(map, "min", "min", &mut extras);
            carry_number(map, "max", "max", &mut extras);
            "number"
        }
        "Input.Date" => "date",
        "Input.Time" => "time",
        "Input.Toggle" => {
            carry_string(map, "valueOn", "valueOn", &mut extras);
            carry_string(map, "valueOff", "valueOff", &mut extras);
            "boolean"
        }
        "Input.ChoiceSet" => {
            // Both are always emitted for a choice: a caller has to know
            // whether it may send one value or several, and an absent
            // `choices` reads as "any value will do", which is never true of
            // a choice set.
            extras.insert(
                "multiSelect".into(),
                Value::Bool(map.get("isMultiSelect").and_then(Value::as_bool) == Some(true)),
            );
            extras.insert("choices".into(), Value::Array(choices_of(map)));
            "choice"
        }
        _ => return None,
    };
    let mut field = Map::new();
    field.insert("id".into(), Value::String(id.clone()));
    field.insert("label".into(), Value::String(label_of(map, &id)));
    field.insert("type".into(), Value::String(kind.into()));
    field.insert(
        "required".into(),
        Value::Bool(map.get("isRequired").and_then(Value::as_bool) == Some(true)),
    );
    field.extend(extras);
    Some(Value::Object(field))
}

/// The card's own `label` (1.3+), else the `title` an `Input.Toggle` carries
/// its text in, else the `placeholder` a text or number input shows, else the
/// id — a field a caller cannot name in prose is still a field it must fill.
fn label_of(map: &Map<String, Value>, id: &str) -> String {
    for key in ["label", "title", "placeholder"] {
        if let Some(text) = string_of(map, key).filter(|text| !text.is_empty()) {
            return text;
        }
    }
    id.to_string()
}

/// `{"value","label"}` per declared choice. A choice with no `value` is
/// dropped: it names nothing a caller could send back.
fn choices_of(map: &Map<String, Value>) -> Vec<Value> {
    let Some(choices) = map.get("choices").and_then(Value::as_array) else {
        return Vec::new();
    };
    choices
        .iter()
        .filter_map(|choice| {
            let choice = choice.as_object()?;
            let value = string_of(choice, "value").filter(|value| !value.is_empty())?;
            let label = string_of(choice, "title")
                .filter(|title| !title.is_empty())
                .unwrap_or_else(|| value.clone());
            Some(json!({"value": value, "label": label}))
        })
        .collect()
}

/// Every `Action.Submit` in the card, as `{"id","label"}`.
///
/// Only `Action.Submit`: the others navigate, open a URL or expand a card,
/// none of which answers the question. See the module doc for why the id
/// prefers the button's own `data.action`.
fn collect_actions(value: &Value, out: &mut Vec<Value>) {
    match value {
        Value::Object(map) => {
            if string_of(map, "type").as_deref() == Some("Action.Submit")
                && let Some(action) = action_from(map)
            {
                out.push(action);
            }
            for child in map.values() {
                collect_actions(child, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_actions(item, out)),
        _ => {}
    }
}

fn action_from(map: &Map<String, Value>) -> Option<Value> {
    let title = string_of(map, "title").filter(|title| !title.is_empty());
    let id = map
        .get("data")
        .and_then(Value::as_object)
        .and_then(|data| string_of(data, "action"))
        .filter(|action| !action.is_empty())
        .or_else(|| string_of(map, "id").filter(|id| !id.is_empty()))
        .or_else(|| title.as_deref().map(slug))
        .filter(|id| !id.is_empty())?;
    let label = title.unwrap_or_else(|| id.clone());
    Some(json!({"id": id, "label": label}))
}

/// A last-resort id for a button that declares none: its title, lowercased,
/// with every run of non-alphanumeric bytes collapsed to one `_`.
fn slug(title: &str) -> String {
    let mut out = String::with_capacity(title.len());
    for ch in title.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

fn string_of(map: &Map<String, Value>, key: &str) -> Option<String> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .map(str::to_string)
}

fn carry_string(map: &Map<String, Value>, from: &str, to: &str, out: &mut Map<String, Value>) {
    if let Some(value) = map.get(from).and_then(Value::as_str) {
        out.insert(to.into(), Value::String(value.to_string()));
    }
}

/// Carried as the number the card declared, never through `f64`: an integer
/// bound must not come back out as `1.0`.
fn carry_number(map: &Map<String, Value>, from: &str, to: &str, out: &mut Map<String, Value>) {
    match map.get(from) {
        Some(Value::Number(number)) => {
            out.insert(to.into(), Value::Number(number.clone()));
        }
        // Adaptive Cards routinely carry these as strings ("1"), which a
        // caller still has to be told about.
        Some(Value::String(raw)) => {
            if let Ok(number) = raw.trim().parse::<serde_json::Number>() {
                out.insert(to.into(), Value::Number(number));
            }
        }
        _ => {}
    }
}

fn carry_bool(map: &Map<String, Value>, from: &str, to: &str, out: &mut Map<String, Value>) {
    if let Some(value) = map.get(from).and_then(Value::as_bool) {
        out.insert(to.into(), Value::Bool(value));
    }
}

#[cfg(test)]
#[path = "input_request_tests.rs"]
mod input_request_tests;
