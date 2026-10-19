//! A secret NAME that carries a `/` (the Jev key, `jev/api_key`) against a REAL
//! dev store, the one an operator's `op secrets put` writes.
//!
//! The fake stores in `secrets_tests.rs` answer `NotFound` for any URI they do
//! not hold, which hid this: the real store refuses a six-segment path with an
//! error that is not `NotFound`, so the raw spelling ended the walk as
//! `Unavailable` and the canonical spelling it was staged under (`jev_api_key`)
//! was never asked for.

use std::sync::Arc;

use greentic_secrets_lib::SecretsManager;

use super::secrets::{SecretRead, read_channel_secret};
use crate::secrets_client::SecretsClient;
use crate::secrets_gate::DynSecretsManager;

const PACK: &str = "greentic.router.demo";
const UNIT: &str = "router-demo";
const NAME: &str = "jev/api_key";

fn store() -> (tempfile::TempDir, Arc<SecretsClient>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let client =
        SecretsClient::open_with_path(dir.path().join(".dev.secrets.env")).expect("open dev store");
    (dir, Arc::new(client))
}

async fn read(store: &Arc<SecretsClient>) -> SecretRead {
    let manager: DynSecretsManager = store.clone();
    read_channel_secret(&manager, "local", "default", PACK, UNIT, &[NAME]).await
}

#[tokio::test]
async fn a_slash_name_staged_under_its_canonical_spelling_is_found() {
    let (_dir, store) = store();
    let unit = greentic_runner_host::secrets::unit_pack_segment(PACK, UNIT).expect("unit segment");
    let canonical = format!("secrets://local/default/_/{unit}/jev_api_key");
    store
        .write(&canonical, b"the-key")
        .await
        .expect("stage the canonical entry");
    match read(&store).await {
        SecretRead::Found(value) => assert_eq!(value.expose(), "the-key"),
        SecretRead::Absent => panic!("the staged key was reported absent"),
        SecretRead::Unavailable => panic!("the staged key was reported unavailable"),
    }
}

#[tokio::test]
async fn a_slash_name_with_nothing_staged_is_absent_not_unavailable() {
    let (_dir, store) = store();
    assert!(matches!(read(&store).await, SecretRead::Absent));
}

#[test]
fn a_slash_name_is_asked_for_only_in_its_canonical_spelling() {
    let uris = crate::runner_host::secret_read_uris(
        "local",
        "default",
        None,
        "greentic_router_demo_unit_router_demo",
        NAME,
    );
    assert_eq!(
        uris,
        vec!["secrets://local/default/_/greentic_router_demo_unit_router_demo/jev_api_key"]
    );
}

#[test]
fn a_plain_name_is_still_asked_for_raw_then_canonical() {
    let uris = crate::runner_host::secret_read_uris(
        "local",
        "default",
        None,
        "messaging-whatsapp",
        "WHATSAPP_APP_SECRET",
    );
    assert_eq!(uris.len(), 2, "{uris:?}");
    assert!(uris[0].ends_with("/WHATSAPP_APP_SECRET"), "{uris:?}");
}
