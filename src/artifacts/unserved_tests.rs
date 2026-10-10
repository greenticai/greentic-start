use super::unserved::{activation_lines, unserved_channel_classes, verified_on_request_classes};

fn ep(provider_type: &str, has_secret: bool) -> (String, bool) {
    (provider_type.to_string(), has_secret)
}

/// Only Telegram without a `webhook_secret_ref` is unserved outright: this
/// host verifies WhatsApp, Webex and Teams itself (`crate::inbound_verify`)
/// once their input is configured, which activation cannot see.
#[test]
fn only_telegram_without_a_webhook_secret_is_unserved() {
    let endpoints = [
        ep("messaging.whatsapp", false),
        ep("messaging.webex.bot", true),
        ep("messaging.teams.bot", false),
        ep("messaging.telegram.bot", false),
        ep("messaging.slack.api", false),
        ep("messaging.webchat-gui", false),
    ];
    assert_eq!(
        unserved_channel_classes(&endpoints)
            .into_iter()
            .collect::<Vec<_>>(),
        ["Telegram"]
    );
}

#[test]
fn telegram_with_a_webhook_secret_and_slack_are_served() {
    let endpoints = [
        ep("messaging.telegram.bot", true),
        ep("messaging.slack.api", false),
        ep("messaging.webchat-gui", false),
    ];
    assert!(unserved_channel_classes(&endpoints).is_empty());
}

#[test]
fn whatsapp_webex_and_teams_are_named_once_each_as_verified_on_request() {
    let endpoints = [
        ep("messaging.whatsapp", false),
        ep("messaging.whatsapp", true),
        ep("messaging.webex.bot", true),
        ep("messaging.teams.bot", false),
        ep("messaging.telegram.bot", false),
        ep("messaging.slack.api", false),
    ];
    assert_eq!(
        verified_on_request_classes(&endpoints)
            .into_iter()
            .collect::<Vec<_>>(),
        ["Microsoft Teams", "Webex", "WhatsApp"]
    );
}

#[test]
fn the_pointer_line_is_said_once_and_only_when_such_a_channel_is_declared() {
    let none = activation_lines(&[ep("messaging.slack.api", false)]);
    assert!(none.is_empty(), "{none:?}");

    let lines = activation_lines(&[
        ep("messaging.whatsapp", false),
        ep("messaging.teams.bot", false),
        ep("messaging.webex.bot", false),
    ]);
    assert_eq!(lines.len(), 1, "{lines:?}");
    let line = &lines[0];
    assert!(
        line.contains(
            "inbound files from WhatsApp, Webex and Microsoft Teams are read only from \
             requests this host verifies"
        ),
        "{line}"
    );
    assert!(line.contains("per-channel warning"), "{line}");
    assert!(!line.contains("not supported"), "{line}");
}

#[test]
fn telegram_without_a_secret_keeps_its_own_warning() {
    let lines = activation_lines(&[
        ep("messaging.telegram.bot", false),
        ep("messaging.whatsapp", false),
    ]);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines
            .iter()
            .any(|l| l.contains("Telegram") && l.contains("webhook secret")),
        "{lines:?}"
    );
    assert!(
        lines.iter().all(|l| !l.contains("not supported")),
        "{lines:?}"
    );
}
