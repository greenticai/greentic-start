use super::ingest_testkit::bare_envelope;
use super::origin::Origin;
use super::quota_key::conversation_key;

fn whatsapp() -> Origin {
    Origin::new(
        "messaging.whatsapp",
        "messaging-provider-whatsapp",
        "acme",
        None,
    )
}

fn from(env: &mut greentic_types::ChannelMessageEnvelope, id: &str) {
    env.from = Some(greentic_types::messaging::Actor {
        id: id.into(),
        kind: None,
    });
}

#[test]
fn two_whatsapp_users_on_the_constant_session_get_different_keys() {
    let mut a = bare_envelope();
    a.session_id = "whatsapp".into();
    a.channel = "whatsapp".into();
    from(&mut a, "4911111");
    let mut b = a.clone();
    from(&mut b, "4922222");
    let (ka, kb) = (
        conversation_key(&a, &whatsapp()),
        conversation_key(&b, &whatsapp()),
    );
    assert!(ka.is_some() && kb.is_some());
    assert_ne!(ka, kb);
    assert_eq!(
        ka,
        conversation_key(&a.clone(), &whatsapp()),
        "stable for one user"
    );
}

#[test]
fn telegram_without_a_session_still_gets_a_key_from_the_chat() {
    let telegram = Origin::new(
        "messaging.telegram.bot",
        "messaging-provider-telegram",
        "acme",
        None,
    );
    let mut env = bare_envelope();
    env.session_id.clear();
    env.channel = "123456".into();
    let key = conversation_key(&env, &telegram).expect("a key");
    assert!(key.contains("123456"));
}

#[test]
fn the_same_ids_on_two_channels_or_packs_never_share_a_key() {
    let env = bare_envelope();
    let slack = Origin::new(
        "messaging.slack.api",
        "messaging-provider-slack",
        "acme",
        None,
    );
    let other_pack = Origin::new("messaging.slack.api", "other-slack-pack", "acme", None);
    assert_ne!(
        conversation_key(&env, &slack),
        conversation_key(&env, &whatsapp())
    );
    assert_ne!(
        conversation_key(&env, &slack),
        conversation_key(&env, &other_pack)
    );
}

#[test]
fn nothing_that_identifies_a_conversation_means_no_key() {
    let mut env = bare_envelope();
    env.session_id.clear();
    env.channel.clear();
    env.from = None;
    assert_eq!(conversation_key(&env, &whatsapp()), None);
}

/// A part carrying the separator cannot impersonate another split of the
/// parts: the separator (and the escape itself) is escaped.
#[test]
fn a_separator_inside_a_part_cannot_shift_the_parts() {
    let mut a = bare_envelope();
    a.channel = "c\u{1f}alice".into();
    from(&mut a, "s1");
    a.session_id = "x".into();
    let mut b = bare_envelope();
    b.channel = "c".into();
    from(&mut b, "alice\u{1f}s1");
    b.session_id = "x".into();
    assert_ne!(
        conversation_key(&a, &whatsapp()),
        conversation_key(&b, &whatsapp())
    );
    let mut c = bare_envelope();
    c.channel = "c\\u001falice".into();
    from(&mut c, "s1");
    c.session_id = "x".into();
    assert_ne!(
        conversation_key(&a, &whatsapp()),
        conversation_key(&c, &whatsapp()),
        "the escape itself is escaped"
    );
}
