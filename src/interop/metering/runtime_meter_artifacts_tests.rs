//! The per-unit artifact access a revision's runtime is loaded with: the
//! agent's reader and the extensions' port (split from
//! `runtime_meter_tests.rs` for the file-size cap).

use std::sync::Arc;
use std::time::Duration;

use greentic_deploy_spec::ids::{DeploymentId, RevisionId};

use super::runtime_meter_tests::{BUNDLE, TOKEN, installs_a_meter, metering};
use super::*;

/// Whether the options would hand the runtime the agent's artifact reader /
/// the extensions' artifact port. Same `Debug` trick as above.
fn installs_artifacts(options: &RevisionHostOptions) -> (bool, bool) {
    let rendered = format!("{options:?}");
    assert!(
        rendered.contains("artifact_reader") && rendered.contains("ext_artifact_port"),
        "RevisionHostOptions' Debug does not report the artifact reader/port — \
         greentic-runner-host lost its `agentic-worker` feature, or the Debug changed: {rendered}"
    );
    (
        rendered.contains("artifact_reader: true"),
        rendered.contains("ext_artifact_port: true"),
    )
}

fn artifact_access(token: &str) -> crate::artifacts::host_access::HostArtifactAccess {
    let door = "https://admin.example/api/v1/ingest/artifacts".to_string();
    let store = crate::artifacts::store::HttpArtifactStore::new(
        door.clone(),
        token.into(),
        Duration::from_secs(2),
    )
    .expect("client");
    crate::artifacts::host_access::HostArtifactAccess::new(
        Arc::new(store),
        crate::artifacts::boot::Door {
            url: door,
            token: token.into(),
        },
    )
}

#[test]
fn a_unit_with_attachments_gets_the_agent_reader_and_the_extension_port() {
    let access = artifact_access(TOKEN);
    let unit = host_options_for_unit(
        Some(&metering()),
        DeploymentId::new(),
        BUNDLE,
        RevisionId::new(),
        Some(&access),
    );
    assert_eq!(installs_artifacts(&unit.options), (true, true));
    assert!(
        !format!("{:?}", unit.options).contains(TOKEN),
        "the options never print the token"
    );
}

#[test]
fn a_unit_without_attachments_gets_neither() {
    for metering in [Some(metering()), None] {
        let unit = host_options_for_unit(
            metering.as_ref(),
            DeploymentId::new(),
            BUNDLE,
            RevisionId::new(),
            None,
        );
        assert_eq!(installs_artifacts(&unit.options), (false, false));
    }
}

#[test]
fn a_reader_that_cannot_be_built_leaves_the_port_and_the_revision_alone() {
    let access = artifact_access("tok\nen");
    let unit = host_options_for_unit(
        Some(&metering()),
        DeploymentId::new(),
        BUNDLE,
        RevisionId::new(),
        Some(&access),
    );
    assert_eq!(installs_artifacts(&unit.options), (false, true));
    assert!(installs_a_meter(&unit.options), "the rest still installs");
}
