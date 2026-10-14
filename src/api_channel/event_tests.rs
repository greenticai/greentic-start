//! The shared fixtures are asserted byte for byte: parse, re-serialize, and the
//! bytes must equal the file (with no trailing newline either).

use super::event::*;
use serde::Serialize;
use serde::de::DeserializeOwned;

fn fixture(name: &str) -> String {
    let path = format!(
        "{}/docs/fixtures/api-channel/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {path}: {err}"))
}

fn assert_round_trips<T: Serialize + DeserializeOwned>(name: &str) -> T {
    let raw = fixture(name);
    let expected = raw.as_str();
    assert!(
        !expected.ends_with('\n'),
        "{name} must have no trailing newline"
    );
    let parsed: T = serde_json::from_str(expected).expect("fixture parses");
    let out = serde_json::to_string(&parsed).expect("serializes");
    assert_eq!(out, expected, "{name} drifted from the typed schema");
    parsed
}

#[test]
fn event_fixtures_round_trip_byte_for_byte() {
    for name in [
        "message.json",
        "input_required.json",
        "error.json",
        "done.json",
        "delivery_failed.json",
    ] {
        assert_round_trips::<ApiEvent>(name);
    }
}

#[test]
fn event_fixtures_carry_the_expected_types() {
    let message = assert_round_trips::<ApiEvent>("message.json");
    assert_eq!(message.cursor, 7);
    assert_eq!(message.kind, EventType::Message);
    let error = assert_round_trips::<ApiEvent>("error.json");
    assert_eq!(error.code.as_deref(), Some("flow_failed"));
    let card = assert_round_trips::<ApiEvent>("input_required.json");
    assert!(matches!(card.items[0], Item::Card { .. }));
}

#[test]
fn poll_events_fixtures_round_trip_byte_for_byte() {
    let request = assert_round_trips::<PollEventsRequest>("poll_events_request.json");
    assert_eq!(request.since, 7);
    let response = assert_round_trips::<PollEventsResponse>("poll_events_response.json");
    assert_eq!(response.next_cursor, 8);
    assert_eq!(response.events[0].cursor, 7);
}
