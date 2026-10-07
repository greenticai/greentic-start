use super::unserved::unserved_channel_classes;

fn ep(provider_type: &str, has_secret: bool) -> (String, bool) {
    (provider_type.to_string(), has_secret)
}

#[test]
fn channels_whose_requests_this_host_cannot_verify_are_named_once_each() {
    let endpoints = [
        ep("messaging.whatsapp", false),
        ep("messaging.whatsapp", false),
        ep("messaging.webex.bot", true),
        ep("messaging.teams.bot", false),
        ep("messaging.telegram.bot", false),
        ep("messaging.slack.api", false),
        ep("messaging.webchat-gui", false),
    ];
    let classes = unserved_channel_classes(&endpoints);
    assert_eq!(
        classes.into_iter().collect::<Vec<_>>(),
        ["Microsoft Teams", "Telegram", "Webex", "WhatsApp"]
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
