//! Deriving the §9.2 input request from a card's own `Input.*` elements.

use super::*;
use serde_json::json;

/// The card a support flow really parks on: a required choice, an optional
/// number with bounds, a multiline text box, a toggle, and a submit button.
fn plan_card() -> Value {
    json!({
        "type": "AdaptiveCard",
        "version": "1.6",
        "fallbackText": "Which plan should I set up?",
        "body": [
            {"type": "TextBlock", "text": "Which plan should I set up?"},
            {"type": "Input.ChoiceSet", "id": "plan", "label": "Plan",
             "isRequired": true, "isMultiSelect": false,
             "choices": [{"title": "Basic", "value": "basic"},
                         {"title": "Pro", "value": "pro"}]},
            {"type": "Container", "items": [
                {"type": "Input.Number", "id": "seats", "label": "Seats",
                 "min": 1, "max": 100},
                {"type": "Input.Text", "id": "notes", "label": "Notes",
                 "isMultiline": true, "maxLength": 500},
                {"type": "Input.Toggle", "id": "trial", "title": "Start a trial",
                 "valueOn": "yes", "valueOff": "no"}
            ]}
        ],
        "actions": [
            {"type": "Action.Submit", "title": "Confirm", "data": {"action": "confirm"}},
            {"type": "Action.OpenUrl", "title": "Pricing", "url": "https://example.test"}
        ]
    })
}

#[test]
fn a_real_card_becomes_named_typed_fields() {
    let request = input_request("Which plan should I set up?", Some(&plan_card()));
    assert_eq!(
        request,
        json!({
            "prompt": "Which plan should I set up?",
            "fields": [
                {"id": "plan", "label": "Plan", "type": "choice", "required": true,
                 "multiSelect": false,
                 "choices": [{"value": "basic", "label": "Basic"},
                             {"value": "pro", "label": "Pro"}]},
                {"id": "seats", "label": "Seats", "type": "number", "required": false,
                 "min": 1, "max": 100},
                {"id": "notes", "label": "Notes", "type": "text", "required": false,
                 "multiline": true, "maxLength": 500},
                {"id": "trial", "label": "Start a trial", "type": "boolean",
                 "required": false, "valueOn": "yes", "valueOff": "no"}
            ],
            "actions": [{"id": "confirm", "label": "Confirm"}]
        }),
        "the derived request must match the contract's shape exactly"
    );
}

/// Bounds must survive as the numbers the card declared. An integer `min`
/// that comes back as `1.0` reads to a strict consumer as a different type.
#[test]
fn numeric_bounds_keep_their_declared_form() {
    let request = input_request("", Some(&plan_card()));
    let seats = &request["fields"][1];
    assert_eq!(seats["min"], json!(1));
    assert_eq!(seats["max"], json!(100));
    assert!(seats["min"].is_i64(), "an integer bound stays an integer");
}

/// A display-only card the flow waits on. It asks for no named value and
/// still has to be answered — `fields: []`, not "not parking".
#[test]
fn a_parked_card_with_no_inputs_emits_an_empty_field_list() {
    let card = json!({
        "type": "AdaptiveCard",
        "body": [{"type": "TextBlock", "text": "Press continue when ready"}],
        "actions": [{"type": "Action.Submit", "title": "Continue"}]
    });
    let request = input_request("Press continue when ready", Some(&card));
    assert_eq!(request["fields"], json!([]));
    assert_eq!(
        request["actions"],
        json!([{"id": "continue", "label": "Continue"}]),
        "a button with no data and no id is still nameable by its title"
    );
}

/// A `session.wait` that rendered no card at all.
#[test]
fn no_card_still_produces_a_question() {
    let request = input_request("What is the order number?", None);
    assert_eq!(
        request,
        json!({"prompt": "What is the order number?", "fields": [], "actions": []})
    );
}

/// The three keys are ALWAYS present, whatever the card carried: a consumer
/// must not have to tell "no fields" apart from "this server does not report
/// fields".
#[test]
fn the_key_set_is_closed_and_constant() {
    for card in [None, Some(&plan_card())] {
        let request = input_request("q", card);
        let mut keys: Vec<&str> = request
            .as_object()
            .map(|map| map.keys().map(String::as_str).collect())
            .unwrap_or_default();
        keys.sort_unstable();
        assert_eq!(keys, vec!["actions", "fields", "prompt"]);
    }
}

#[test]
fn every_input_type_maps_and_unknown_elements_are_left_alone() {
    let card = json!({"type": "AdaptiveCard", "body": [
        {"type": "Input.Text", "id": "t"},
        {"type": "Input.Number", "id": "n"},
        {"type": "Input.Date", "id": "d"},
        {"type": "Input.Time", "id": "h"},
        {"type": "Input.Toggle", "id": "b"},
        {"type": "Input.ChoiceSet", "id": "c"},
        {"type": "Input.Rating", "id": "future"},
        {"type": "Image", "id": "pic", "url": "https://example.test/x.png"}
    ]});
    let request = input_request("", Some(&card));
    let kinds: Vec<&Value> = request["fields"]
        .as_array()
        .map(|fields| fields.iter().map(|field| &field["type"]).collect())
        .unwrap_or_default();
    assert_eq!(
        kinds,
        vec!["text", "number", "date", "time", "boolean", "choice"],
        "an element this runtime cannot describe is omitted, never guessed"
    );
    // A choice set with no declared choices still says it is a choice set.
    assert_eq!(request["fields"][5]["choices"], json!([]));
    assert_eq!(request["fields"][5]["multiSelect"], json!(false));
}

/// An input a caller could not name in an answer is not offered to it.
#[test]
fn an_input_with_no_id_is_dropped() {
    let card = json!({"type": "AdaptiveCard", "body": [
        {"type": "Input.Text", "label": "Anonymous"},
        {"type": "Input.Text", "id": "  ", "label": "Blank"},
        {"type": "Input.Text", "id": "real", "label": "Real"}
    ]});
    let request = input_request("", Some(&card));
    assert_eq!(request["fields"].as_array().map(Vec::len), Some(1));
    assert_eq!(request["fields"][0]["id"], "real");
}

#[test]
fn the_label_falls_back_through_title_then_placeholder_then_the_id() {
    let card = json!({"type": "AdaptiveCard", "body": [
        {"type": "Input.Text", "id": "a", "label": "Label", "placeholder": "Hint"},
        {"type": "Input.Toggle", "id": "b", "title": "Toggle text"},
        {"type": "Input.Text", "id": "c", "placeholder": "Hint only"},
        {"type": "Input.Text", "id": "d"}
    ]});
    let request = input_request("", Some(&card));
    let labels: Vec<&Value> = request["fields"]
        .as_array()
        .map(|fields| fields.iter().map(|field| &field["label"]).collect())
        .unwrap_or_default();
    assert_eq!(labels, vec!["Label", "Toggle text", "Hint only", "d"]);
}

/// A choice nothing can be sent back for is dropped; a choice with no title
/// is named by its own value.
#[test]
fn choices_need_a_value_and_fall_back_to_it_for_a_label() {
    let card = json!({"type": "AdaptiveCard", "body": [
        {"type": "Input.ChoiceSet", "id": "c", "isMultiSelect": true, "choices": [
            {"title": "Titled", "value": "v1"},
            {"value": "v2"},
            {"title": "No value"}
        ]}
    ]});
    let request = input_request("", Some(&card));
    assert_eq!(
        request["fields"][0]["choices"],
        json!([{"value": "v1", "label": "Titled"}, {"value": "v2", "label": "v2"}])
    );
    assert_eq!(request["fields"][0]["multiSelect"], json!(true));
}

/// **The id a caller has to send back.** `submitted_fields` in
/// greentic-runner-host treats a metadata key called `action` as the route
/// discriminator, so the button's own `data.action` is the only string that
/// routes. An id invented from the title would look right and go nowhere.
#[test]
fn an_action_id_prefers_the_submit_data_the_flow_routes_on() {
    let card = json!({"type": "AdaptiveCard", "actions": [
        {"type": "Action.Submit", "id": "btn1", "title": "Approve",
         "data": {"action": "approve_it"}},
        {"type": "Action.Submit", "id": "btn2", "title": "Reject"},
        {"type": "Action.Submit", "title": "Ask a question"},
        {"type": "Action.Submit", "data": {"other": "x"}}
    ]});
    let request = input_request("", Some(&card));
    assert_eq!(
        request["actions"],
        json!([
            {"id": "approve_it", "label": "Approve"},
            {"id": "btn2", "label": "Reject"},
            {"id": "ask_a_question", "label": "Ask a question"},
        ]),
        "a submit with neither an action, an id nor a title names nothing"
    );
}

/// A card element this runtime has never heard of must not be able to hide
/// an input inside it — the walk is by descent, not by a list of the
/// container keys Adaptive Cards defines today.
#[test]
fn inputs_nested_under_unknown_containers_are_still_found() {
    let card = json!({"type": "AdaptiveCard", "body": [
        {"type": "ColumnSet", "columns": [
            {"type": "Column", "items": [{"type": "Input.Text", "id": "in_column"}]}
        ]},
        {"type": "Greentic.FutureLayout", "panes": [
            {"contents": [{"type": "Input.Text", "id": "in_future_layout"}]}
        ]}
    ]});
    let request = input_request("", Some(&card));
    let ids: Vec<&Value> = request["fields"]
        .as_array()
        .map(|fields| fields.iter().map(|field| &field["id"]).collect())
        .unwrap_or_default();
    assert_eq!(ids, vec!["in_column", "in_future_layout"]);
}

/// Adaptive Cards routinely carry a bound as a string. A caller still has to
/// be told about it, and told as a number.
#[test]
fn a_string_bound_is_carried_as_a_number() {
    let card = json!({"type": "AdaptiveCard", "body": [
        {"type": "Input.Number", "id": "n", "min": "1", "max": "not a number"}
    ]});
    let field = &input_request("", Some(&card))["fields"][0];
    assert_eq!(field["min"], json!(1));
    assert!(
        field.get("max").is_none(),
        "an unparseable bound is no bound"
    );
}

#[test]
fn the_media_type_is_the_contracts_own() {
    assert_eq!(
        INPUT_REQUEST_MEDIA_TYPE,
        "application/vnd.greentic.input-request+json"
    );
}
