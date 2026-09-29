use std::time::{Duration, Instant};

use greentic_deploy_spec::ids::DeploymentId;

use super::*;
use crate::interop::a2a::types::{Part, TaskState, TaskStatus};

fn task(id: &str, state: TaskState) -> Task {
    Task {
        id: id.to_string(),
        context_id: id.to_string(),
        status: TaskStatus {
            state,
            message: None,
            timestamp: None,
        },
        artifacts: Vec::new(),
        history: Vec::new(),
        metadata: None,
    }
}

#[test]
fn a_recorded_task_is_answered_to_the_credential_that_created_it() {
    let store = TaskStore::default();
    let dep = DeploymentId::new();
    let now = Instant::now();
    let recorded = task("ctx-1", TaskState::InputRequired);
    assert_eq!(store.put("default", dep, "c1", &recorded, now), Ok(()));
    assert_eq!(
        store.get("default", dep, "c1", "ctx-1", now),
        Some(recorded)
    );
}

#[test]
fn no_other_credential_tenant_or_deployment_can_read_it() {
    let store = TaskStore::default();
    let dep = DeploymentId::new();
    let now = Instant::now();
    assert_eq!(
        store.put(
            "default",
            dep,
            "c1",
            &task("ctx-1", TaskState::Completed),
            now
        ),
        Ok(())
    );
    assert_eq!(store.get("default", dep, "c2", "ctx-1", now), None);
    assert_eq!(store.get("other", dep, "c1", "ctx-1", now), None);
    assert_eq!(
        store.get("default", DeploymentId::new(), "c1", "ctx-1", now),
        None
    );
    assert_eq!(store.get("default", dep, "c1", "ctx-2", now), None);
}

#[test]
fn a_later_turn_in_the_same_conversation_replaces_the_snapshot() {
    let store = TaskStore::default();
    let dep = DeploymentId::new();
    let now = Instant::now();
    let _ = store.put("t", dep, "c1", &task("ctx", TaskState::InputRequired), now);
    let _ = store.put("t", dep, "c1", &task("ctx", TaskState::Completed), now);
    assert_eq!(store.len(), 1);
    assert_eq!(
        store
            .get("t", dep, "c1", "ctx", now)
            .map(|t| t.status.state),
        Some(TaskState::Completed)
    );
}

#[test]
fn an_idle_entry_expires_and_a_read_keeps_it_alive() {
    let store = TaskStore::default();
    let dep = DeploymentId::new();
    let start = Instant::now();
    let _ = store.put("t", dep, "c1", &task("kept", TaskState::Completed), start);
    let _ = store.put("t", dep, "c1", &task("idle", TaskState::Completed), start);
    let half = start + IDLE_TTL / 2;
    assert!(store.get("t", dep, "c1", "kept", half).is_some());
    let later = start + IDLE_TTL + Duration::from_secs(1);
    assert!(store.get("t", dep, "c1", "idle", later).is_none());
    assert!(store.get("t", dep, "c1", "kept", later).is_some());
}

#[test]
fn one_credential_over_its_share_evicts_only_its_own_oldest() {
    let store = TaskStore::default();
    let dep = DeploymentId::new();
    let start = Instant::now();
    let _ = store.put(
        "t",
        dep,
        "victim",
        &task("mine", TaskState::Completed),
        start,
    );
    for i in 0..=MAX_ENTRIES_PER_CREDENTIAL {
        let at = start + Duration::from_millis(1 + i as u64);
        let _ = store.put(
            "t",
            dep,
            "flood",
            &task(&format!("f{i}"), TaskState::Completed),
            at,
        );
    }
    let now = start + Duration::from_secs(1);
    assert!(store.get("t", dep, "victim", "mine", now).is_some());
    assert!(
        store.get("t", dep, "flood", "f0", now).is_none(),
        "own oldest evicted"
    );
    assert!(
        store
            .get(
                "t",
                dep,
                "flood",
                &format!("f{MAX_ENTRIES_PER_CREDENTIAL}"),
                now
            )
            .is_some()
    );
    assert_eq!(store.len(), MAX_ENTRIES_PER_CREDENTIAL + 1);
}

#[test]
fn the_total_entry_cap_evicts_the_least_recently_touched() {
    let store = TaskStore::default();
    let dep = DeploymentId::new();
    let start = Instant::now();
    let per = MAX_ENTRIES_PER_CREDENTIAL;
    let creds = MAX_ENTRIES / per + 1;
    for c in 0..creds {
        for i in 0..per {
            let at = start + Duration::from_millis((c * per + i) as u64);
            let _ = store.put(
                "t",
                dep,
                &format!("c{c}"),
                &task(&format!("t{i}"), TaskState::Completed),
                at,
            );
        }
    }
    assert_eq!(store.len(), MAX_ENTRIES);
    let now = start + Duration::from_secs(60);
    assert!(store.get("t", dep, "c0", "t0", now).is_none());
    assert!(
        store
            .get(
                "t",
                dep,
                &format!("c{}", creds - 1),
                &format!("t{}", per - 1),
                now
            )
            .is_some()
    );
}

#[test]
fn an_oversized_snapshot_is_refused_rather_than_stored() {
    let store = TaskStore::default();
    let mut big = task("big", TaskState::Completed);
    big.status.message = Some(crate::interop::a2a::types::Message {
        message_id: "m".into(),
        context_id: None,
        task_id: None,
        role: crate::interop::a2a::types::Role::Agent,
        parts: vec![Part::text("x".repeat(MAX_ENTRY_BYTES))],
        metadata: None,
        extensions: Vec::new(),
        reference_task_ids: Vec::new(),
    });
    let dep = DeploymentId::new();
    let now = Instant::now();
    assert_eq!(
        store.put("t", dep, "c1", &big, now),
        Err(NotStored::TooLarge)
    );
    assert_eq!(store.len(), 0);
}
