//! Review G4 #4: a store that FAILS is not a store that has no secret.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use greentic_deploy_spec::DeploymentId;
use greentic_secrets_lib::{SecretError, SecretsManager};

use super::mod_tests::{deps, inbound};
use super::notices::Notices;
use super::secrets::{SecretRead, candidate_uris, read_channel_secret};
use super::{Verdict, verify_with};
use crate::secrets_gate::DynSecretsManager;

const NAMES: &[&str] = &["WHATSAPP_APP_SECRET", "whatsapp_app_secret"];

/// Answers `NotFound` everywhere except the URIs in `fail` (a backend error)
/// and `values`, and records every read.
struct Store {
    fail: Vec<String>,
    values: HashMap<String, String>,
    reads: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl SecretsManager for Store {
    async fn read(&self, path: &str) -> greentic_secrets_lib::Result<Vec<u8>> {
        self.reads.lock().unwrap().push(path.to_string());
        if self.fail.iter().any(|f| f == path) {
            return Err(SecretError::Backend("store unreachable".into()));
        }
        self.values
            .get(path)
            .map(|v| v.as_bytes().to_vec())
            .ok_or_else(|| SecretError::NotFound(path.to_string()))
    }
    async fn write(&self, _: &str, _: &[u8]) -> greentic_secrets_lib::Result<()> {
        Err(SecretError::Permission("read-only".into()))
    }
    async fn delete(&self, _: &str) -> greentic_secrets_lib::Result<()> {
        Err(SecretError::Permission("read-only".into()))
    }
}

fn candidates() -> Vec<String> {
    candidate_uris("local", "default", "messaging-pack", "unit-a", NAMES)
}

fn store(fail: Vec<String>, values: &[(String, &str)]) -> Arc<Store> {
    Arc::new(Store {
        fail,
        values: values
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string()))
            .collect(),
        reads: Mutex::new(Vec::new()),
    })
}

async fn read(store: &Arc<Store>) -> SecretRead {
    let manager: DynSecretsManager = store.clone();
    read_channel_secret(
        &manager,
        "local",
        "default",
        "messaging-pack",
        "unit-a",
        NAMES,
    )
    .await
}

#[tokio::test]
async fn a_backend_error_in_the_unit_scope_is_unavailable_and_stops_the_walk() {
    let all = candidates();
    let bare = all.last().unwrap().clone();
    let store = store(vec![all[0].clone()], &[(bare, "shared-secret")]);
    assert!(matches!(read(&store).await, SecretRead::Unavailable));
    assert_eq!(
        store.reads.lock().unwrap().len(),
        1,
        "the bare scope was read after a unit-scope failure"
    );
}

#[tokio::test]
async fn not_found_and_empty_values_move_on_to_the_next_candidate() {
    let all = candidates();
    let store = store(
        Vec::new(),
        &[
            (all[0].clone(), "   "),
            (all.last().unwrap().clone(), "found"),
        ],
    );
    assert!(matches!(read(&store).await, SecretRead::Found(_)));
}

#[tokio::test]
async fn a_non_utf8_value_is_unavailable_not_absent() {
    struct Binary;
    #[async_trait::async_trait]
    impl SecretsManager for Binary {
        async fn read(&self, _: &str) -> greentic_secrets_lib::Result<Vec<u8>> {
            Ok(vec![0xff, 0xfe])
        }
        async fn write(&self, _: &str, _: &[u8]) -> greentic_secrets_lib::Result<()> {
            Ok(())
        }
        async fn delete(&self, _: &str) -> greentic_secrets_lib::Result<()> {
            Ok(())
        }
    }
    let manager: DynSecretsManager = Arc::new(Binary);
    assert!(matches!(
        read_channel_secret(&manager, "local", "default", "p", "u", NAMES).await,
        SecretRead::Unavailable
    ));
}

/// The dispatcher admits the request unverified and says verification is
/// UNAVAILABLE, never that the channel is not configured.
#[tokio::test]
async fn a_failing_store_admits_unverified_with_the_right_notice() {
    let all = candidates();
    let failing = store(vec![all[0].clone()], &[]);
    let manager: DynSecretsManager = failing;
    let (notices, said) = Notices::recording();
    let verdict = verify_with(
        inbound(
            "messaging.whatsapp",
            "POST",
            &[],
            b"{}",
            DeploymentId::new(),
        ),
        &deps(&manager, &notices),
    )
    .await
    .expect("a store failure never refuses");
    assert_eq!(verdict, Verdict::Unavailable);
    let lines = said.lock().unwrap().clone();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("could not be read"), "{lines:?}");
    assert!(!lines[0].contains("set the app secret"), "{lines:?}");
    assert!(
        !lines[0].contains("unreachable"),
        "store text leaked: {lines:?}"
    );
}
