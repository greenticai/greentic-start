use std::collections::HashMap;
use std::sync::Arc;

use greentic_types::{EnvId, TenantCtx, TenantId};

use super::secrets::{ChannelSecret, SecretRead, candidate_uris, read_channel_secret};
use crate::secrets_gate::DynSecretsManager;
use crate::test_fixtures::FakeSecrets;

const NAMES: &[&str] = &["WHATSAPP_APP_SECRET", "whatsapp_app_secret"];
const PACK: &str = "messaging-whatsapp";
const UNIT: &str = "support-bot";

fn manager(entries: &[(&str, &str)]) -> DynSecretsManager {
    Arc::new(FakeSecrets(
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
            .collect::<HashMap<_, _>>(),
    ))
}

async fn read(manager: &DynSecretsManager) -> SecretRead {
    read_channel_secret(manager, "local", "default", PACK, UNIT, NAMES).await
}

fn found(read: &SecretRead) -> Option<String> {
    match read {
        SecretRead::Found(value) => Some(value.expose().to_string()),
        SecretRead::Absent | SecretRead::Unavailable => None,
    }
}

#[tokio::test]
async fn reads_the_first_name_that_resolves_in_the_provider_ops_scope() {
    let canonical =
        crate::runner_host::secret_read_uris("local", "default", None, PACK, "WHATSAPP_APP_SECRET")
            .last()
            .cloned()
            .expect("a candidate");
    let manager = manager(&[(&canonical, " app-secret\n")]);
    assert_eq!(found(&read(&manager).await).as_deref(), Some("app-secret"));
}

#[tokio::test]
async fn an_empty_or_whitespace_value_is_absent() {
    let canonical = "secrets://local/default/_/messaging_whatsapp/whatsapp_app_secret";
    let manager = manager(&[(canonical, "  \n")]);
    assert!(matches!(read(&manager).await, SecretRead::Absent));
}

#[tokio::test]
async fn a_value_under_another_pack_or_a_team_scope_is_not_read() {
    let manager = manager(&[
        (
            "secrets://local/default/sales/messaging-whatsapp/WHATSAPP_APP_SECRET",
            "team-scoped",
        ),
        (
            "secrets://local/default/sales/messaging_whatsapp/whatsapp_app_secret",
            "team-scoped",
        ),
        (
            "secrets://local/default/_/messaging_webex/whatsapp_app_secret",
            "other-pack",
        ),
        (
            "secrets://local/other/_/messaging_whatsapp/whatsapp_app_secret",
            "other-tenant",
        ),
    ]);
    assert!(matches!(read(&manager).await, SecretRead::Absent));
}

#[tokio::test]
async fn the_designer_staged_spellings_are_read() {
    // `ext_stage::channel` writes the question id under the provider id, in
    // the hyphen AND the underscore spelling of the pack segment.
    for staged in [
        "secrets://local/default/_/messaging_whatsapp/whatsapp_app_secret",
        "secrets://local/default/_/messaging-whatsapp/whatsapp_app_secret",
    ] {
        let manager = manager(&[(staged, "staged")]);
        assert_eq!(
            found(&read(&manager).await).as_deref(),
            Some("staged"),
            "{staged}"
        );
    }
}

/// Drift guard: every address the provider component itself reads for this
/// pack (runner-host's own bare and unit-scoped paths) is one this host tries,
/// and the unit scope is tried first, as the provider does.
#[test]
fn the_candidates_cover_every_address_the_provider_reads_unit_first() {
    let ctx = TenantCtx::new(
        EnvId::new("local").expect("env"),
        TenantId::new("default").expect("tenant"),
    );
    let candidates = candidate_uris("local", "default", PACK, UNIT, NAMES);
    let bare = greentic_runner_host::secrets::scoped_secret_path_for_pack(
        &ctx,
        PACK,
        "WHATSAPP_APP_SECRET",
    )
    .expect("bare");
    let unit = greentic_runner_host::secrets::scoped_secret_path_for_unit(
        &ctx,
        PACK,
        UNIT,
        "WHATSAPP_APP_SECRET",
    )
    .expect("unit")
    .expect("a unit scope");
    let bare_at = candidates.iter().position(|c| *c == bare);
    let unit_at = candidates.iter().position(|c| *c == unit);
    assert!(bare_at.is_some(), "{bare} not in {candidates:?}");
    assert!(unit_at.is_some(), "{unit} not in {candidates:?}");
    assert!(unit_at < bare_at, "the unit scope is read first");
}

#[tokio::test]
async fn a_unit_scoped_value_wins_over_the_shared_one() {
    let ctx = TenantCtx::new(
        EnvId::new("local").expect("env"),
        TenantId::new("default").expect("tenant"),
    );
    let unit = greentic_runner_host::secrets::scoped_secret_path_for_unit(
        &ctx,
        PACK,
        UNIT,
        "whatsapp_app_secret",
    )
    .expect("unit")
    .expect("a unit scope");
    let manager = manager(&[
        (&unit, "unit"),
        (
            "secrets://local/default/_/messaging_whatsapp/whatsapp_app_secret",
            "shared",
        ),
    ]);
    assert_eq!(found(&read(&manager).await).as_deref(), Some("unit"));
}

#[test]
fn debug_output_never_contains_the_value() {
    let read = SecretRead::Found(ChannelSecret::new("super-secret-value"));
    let printed = format!("{read:?}");
    assert!(!printed.contains("super-secret-value"), "{printed}");
    assert!(printed.contains("redacted"), "{printed}");
}
