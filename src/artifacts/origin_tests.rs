use super::fetch_ref::FetchRef;
use super::origin::{Channel, Origin};

fn bearer(name: &str) -> FetchRef {
    FetchRef::Bearer {
        url: "https://files.slack.com/x".into(),
        secret_key: name.into(),
    }
}

#[test]
fn the_channel_comes_from_the_provider_type() {
    for (provider_type, want) in [
        ("messaging.slack.api", Channel::Slack),
        ("messaging.slack", Channel::Slack),
        ("messaging.webex.bot", Channel::Webex),
        ("messaging.telegram.bot", Channel::Telegram),
        ("messaging.whatsapp.cloud", Channel::Whatsapp),
        ("messaging.teams.graph", Channel::Teams),
        ("messaging.webchat-gui", Channel::WebChat),
        ("messaging.webchat", Channel::WebChat),
        ("messaging.slackish", Channel::Other),
        ("messaging.email", Channel::Other),
        ("", Channel::Other),
    ] {
        assert_eq!(
            Channel::from_provider_type(provider_type),
            want,
            "{provider_type}"
        );
    }
}

#[test]
fn a_channel_may_only_name_its_own_credential() {
    assert!(Channel::Slack.allows(&bearer("SLACK_BOT_TOKEN")));
    assert!(Channel::Webex.allows(&bearer("WEBEX_BOT_TOKEN")));
    // Confused deputy: a Slack envelope asking the host to spend another
    // channel's token, and every other channel asking for Slack's.
    for name in [
        "WEBEX_BOT_TOKEN",
        "WHATSAPP_TOKEN",
        "TELEGRAM_BOT_TOKEN",
        "slack_bot_token",
    ] {
        assert!(!Channel::Slack.allows(&bearer(name)), "{name}");
    }
    for channel in [
        Channel::Webex,
        Channel::Telegram,
        Channel::Whatsapp,
        Channel::Teams,
        Channel::WebChat,
        Channel::Other,
    ] {
        assert!(!channel.allows(&bearer("SLACK_BOT_TOKEN")), "{channel:?}");
    }
}

#[test]
fn id_kinds_belong_to_their_own_channel() {
    let telegram = FetchRef::TelegramFile {
        file_id: "f".into(),
    };
    let whatsapp = FetchRef::WhatsappMedia {
        media_id: "m".into(),
    };
    assert!(Channel::Telegram.allows(&telegram));
    assert!(Channel::Whatsapp.allows(&whatsapp));
    for channel in [
        Channel::Slack,
        Channel::Teams,
        Channel::WebChat,
        Channel::Other,
    ] {
        assert!(!channel.allows(&telegram), "{channel:?}");
        assert!(!channel.allows(&whatsapp), "{channel:?}");
    }
    assert!(!Channel::Telegram.allows(&whatsapp));
    assert!(!Channel::Whatsapp.allows(&telegram));
}

#[test]
fn credential_less_kinds_are_open_to_every_channel() {
    let public = FetchRef::Public {
        url: "https://a.sharepoint.com/x".into(),
    };
    for channel in [
        Channel::Slack,
        Channel::Teams,
        Channel::WebChat,
        Channel::Other,
    ] {
        assert!(channel.allows(&public), "{channel:?}");
        assert!(channel.allows(&FetchRef::Inline), "{channel:?}");
    }
}

#[test]
fn the_secret_scope_is_the_receiving_pack_never_the_envelope() {
    let origin = Origin::new(
        "messaging.slack.api",
        "messaging-provider-slack",
        "acme",
        Some("ops"),
    );
    assert_eq!(origin.channel(), Channel::Slack);
    assert_eq!(origin.scope().pack_id, "messaging-provider-slack");
    assert_eq!(origin.scope().tenant, "acme");
    assert_eq!(origin.scope().team.as_deref(), Some("ops"));
}
