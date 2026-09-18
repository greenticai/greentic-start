//! Which flow owns a messaging conversation (greentic-start#590, option A).
//!
//! Fast2Flow can dispatch a turn to a named flow (`pack/flow`) rather than the
//! pack's default one. A flow that parks on a card must get the NEXT turn too:
//! its parked snapshot is keyed `{pack}:{flow}:{session}`, so a turn routed
//! through the default flow again would never resume it and the user's card
//! submit would land in the wrong flow.
//!
//! So a conversation stays with the flow it was dispatched to until that flow
//! completes. The record is one small JSON file per conversation, written next
//! to the parked snapshots it describes:
//!
//! `state/sessions/{tenant}/{team}/{pack}/@flow-owner/{session}.json`
//!
//! It is tenant- and team-scoped by the same path segments as the snapshots,
//! and survives exactly the restarts they do.
//!
//! **The snapshot is the authority, the record only names which one to look
//! at.** An owner is honoured only while its flow's snapshot still exists, and
//! a record found without one is deleted on read. The runner deletes the
//! snapshot when the flow completes, so "the flow completed" and "the parked
//! state was removed by any other means" both release the conversation the
//! same way — there is no second expiry policy to keep in step, and a record
//! can never pin a conversation to a flow that has nothing left to resume.
//!
//! Every write is best-effort. Losing a record degrades to routing the turn
//! afresh (the pre-#590 behaviour), which is why a failure only warns.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::messaging_app::{AppFlowInfo, AppPackInfo};
use crate::operator_log;
use crate::runner_exec;
use crate::runner_host::OperatorContext;

/// Directory name for owner records inside a pack's session directory. The
/// `@` keeps it out of the namespace of flow ids, which name the sibling
/// snapshot directories.
const OWNER_DIR: &str = "@flow-owner";

#[derive(Debug, Serialize, Deserialize)]
struct OwnerRecord {
    flow: String,
    recorded_at_unix_ms: u64,
}

fn owner_path(root: &Path, ctx: &OperatorContext, pack_id: &str, session: &str) -> PathBuf {
    let safe: String = session
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':') {
                c
            } else {
                '_'
            }
        })
        .collect();
    runner_exec::session_state_dir(root, &ctx.tenant, ctx.team.as_deref(), pack_id, OWNER_DIR)
        .join(format!("{safe}.json"))
}

fn is_parked(
    root: &Path,
    ctx: &OperatorContext,
    pack_id: &str,
    flow_id: &str,
    session: &str,
) -> bool {
    runner_exec::session_snapshot_path(
        root,
        &ctx.tenant,
        ctx.team.as_deref(),
        pack_id,
        flow_id,
        session,
    )
    .is_file()
}

/// The flow that owns this conversation, if one is parked on it.
///
/// `None` when the conversation carries no session id, no record exists, the
/// recorded flow is no longer a messaging flow of this pack, or the flow has
/// nothing parked any more. The last two remove the stale record.
pub(super) fn sticky_flow<'p>(
    root: &Path,
    ctx: &OperatorContext,
    pack_info: &'p AppPackInfo,
    session: &str,
) -> Option<&'p AppFlowInfo> {
    if session.trim().is_empty() {
        return None;
    }
    let path = owner_path(root, ctx, &pack_info.pack_id, session);
    let bytes = std::fs::read(&path).ok()?;
    let Ok(record) = serde_json::from_slice::<OwnerRecord>(&bytes) else {
        release(&path, "unreadable record");
        return None;
    };
    let Some(flow) = pack_info
        .flows
        .iter()
        .find(|f| f.id == record.flow && f.kind.eq_ignore_ascii_case("messaging"))
    else {
        release(&path, "owning flow is not in the pack");
        return None;
    };
    if !is_parked(root, ctx, &pack_info.pack_id, &flow.id, session) {
        release(&path, "owning flow has nothing parked");
        return None;
    }
    Some(flow)
}

/// Record or release ownership after `flow_id` ran a turn of this
/// conversation: it keeps the conversation while it is parked on it, and
/// gives it up once it has completed.
pub(super) fn settle(
    root: &Path,
    ctx: &OperatorContext,
    pack_id: &str,
    flow_id: &str,
    session: &str,
) {
    if session.trim().is_empty() {
        return;
    }
    let path = owner_path(root, ctx, pack_id, session);
    if !is_parked(root, ctx, pack_id, flow_id, session) {
        release(&path, "flow completed");
        return;
    }
    let record = OwnerRecord {
        flow: flow_id.to_string(),
        recorded_at_unix_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
    };
    if let Err(err) = write_record(&path, &record) {
        operator_log::warn(
            module_path!(),
            format!(
                "[fast2flow] could not record flow={flow_id} as owner of the conversation \
                 (the next turn will be routed afresh): {err}"
            ),
        );
    }
}

fn write_record(path: &Path, record: &OwnerRecord) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("owner record path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    // Write-then-rename so a concurrent reader never sees a half-written
    // record (which it would treat as unreadable and delete).
    let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    std::fs::write(&tmp, serde_json::to_vec(record)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn release(path: &Path, why: &str) {
    match std::fs::remove_file(path) {
        Ok(()) => operator_log::info(
            module_path!(),
            format!(
                "[fast2flow] conversation released by its flow ({why}): {}",
                path.display()
            ),
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => operator_log::warn(
            module_path!(),
            format!(
                "[fast2flow] could not release flow ownership ({why}) at {}: {err}",
                path.display()
            ),
        ),
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use super::*;

    /// Simulate the runner parking `flow_id` on `session`.
    pub(in crate::http_ingress) fn park(
        root: &Path,
        ctx: &OperatorContext,
        pack_id: &str,
        flow_id: &str,
        session: &str,
    ) {
        let path = runner_exec::session_snapshot_path(
            root,
            &ctx.tenant,
            ctx.team.as_deref(),
            pack_id,
            flow_id,
            session,
        );
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, b"{}").expect("write snapshot");
    }

    /// Simulate the runner completing `flow_id` on `session`.
    pub(in crate::http_ingress) fn complete(
        root: &Path,
        ctx: &OperatorContext,
        pack_id: &str,
        flow_id: &str,
        session: &str,
    ) {
        let path = runner_exec::session_snapshot_path(
            root,
            &ctx.tenant,
            ctx.team.as_deref(),
            pack_id,
            flow_id,
            session,
        );
        std::fs::remove_file(path).expect("remove snapshot");
    }

    pub(in crate::http_ingress) fn has_record(
        root: &Path,
        ctx: &OperatorContext,
        pack_id: &str,
        session: &str,
    ) -> bool {
        owner_path(root, ctx, pack_id, session).is_file()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{complete, has_record, park};
    use super::*;
    use tempfile::tempdir;

    fn ctx(tenant: &str, team: &str) -> OperatorContext {
        OperatorContext {
            tenant: tenant.into(),
            team: Some(team.into()),
            correlation_id: None,
        }
    }

    fn flow(id: &str, kind: &str) -> AppFlowInfo {
        AppFlowInfo {
            id: id.into(),
            kind: kind.into(),
            subscribes_to: vec![],
            node_ids: vec![],
        }
    }

    fn pack() -> AppPackInfo {
        AppPackInfo {
            pack_id: "support".into(),
            flows: vec![
                flow("default", "messaging"),
                flow("refund", "messaging"),
                flow("on_event", "events"),
            ],
            capabilities: vec![],
        }
    }

    #[test]
    fn a_parked_flow_keeps_the_conversation_and_releases_it_on_completion() {
        let dir = tempdir().expect("tempdir");
        let (root, c, p) = (dir.path(), ctx("acme", "sales"), pack());

        assert!(sticky_flow(root, &c, &p, "conv-1").is_none());

        park(root, &c, "support", "refund", "conv-1");
        settle(root, &c, "support", "refund", "conv-1");
        assert_eq!(
            sticky_flow(root, &c, &p, "conv-1").map(|f| f.id.as_str()),
            Some("refund")
        );

        complete(root, &c, "support", "refund", "conv-1");
        settle(root, &c, "support", "refund", "conv-1");
        assert!(!has_record(root, &c, "support", "conv-1"));
        assert!(sticky_flow(root, &c, &p, "conv-1").is_none());
    }

    #[test]
    fn a_flow_that_completes_in_one_turn_never_takes_ownership() {
        let dir = tempdir().expect("tempdir");
        let (root, c) = (dir.path(), ctx("acme", "sales"));
        settle(root, &c, "support", "refund", "conv-1");
        assert!(!has_record(root, &c, "support", "conv-1"));
    }

    #[test]
    fn a_record_whose_snapshot_is_gone_is_released_on_read() {
        let dir = tempdir().expect("tempdir");
        let (root, c, p) = (dir.path(), ctx("acme", "sales"), pack());
        park(root, &c, "support", "refund", "conv-1");
        settle(root, &c, "support", "refund", "conv-1");
        // Removed by something other than a turn we saw complete.
        complete(root, &c, "support", "refund", "conv-1");

        assert!(sticky_flow(root, &c, &p, "conv-1").is_none());
        assert!(!has_record(root, &c, "support", "conv-1"));
    }

    #[test]
    fn a_record_naming_a_flow_the_pack_no_longer_has_is_released() {
        let dir = tempdir().expect("tempdir");
        let (root, c) = (dir.path(), ctx("acme", "sales"));
        for gone in ["retired", "on_event"] {
            park(root, &c, "support", gone, "conv-1");
            settle(root, &c, "support", gone, "conv-1");
            assert!(has_record(root, &c, "support", "conv-1"));
            assert!(sticky_flow(root, &c, &pack(), "conv-1").is_none(), "{gone}");
            assert!(!has_record(root, &c, "support", "conv-1"), "{gone}");
        }
    }

    #[test]
    fn ownership_is_per_conversation() {
        let dir = tempdir().expect("tempdir");
        let (root, c, p) = (dir.path(), ctx("acme", "sales"), pack());
        park(root, &c, "support", "refund", "conv-1");
        settle(root, &c, "support", "refund", "conv-1");

        assert!(sticky_flow(root, &c, &p, "conv-2").is_none());
        assert_eq!(
            sticky_flow(root, &c, &p, "conv-1").map(|f| f.id.as_str()),
            Some("refund")
        );
    }

    #[test]
    fn ownership_is_tenant_and_team_scoped() {
        let dir = tempdir().expect("tempdir");
        let (root, p) = (dir.path(), pack());
        let owner = ctx("acme", "sales");
        park(root, &owner, "support", "refund", "conv-1");
        settle(root, &owner, "support", "refund", "conv-1");

        assert!(sticky_flow(root, &ctx("globex", "sales"), &p, "conv-1").is_none());
        assert!(sticky_flow(root, &ctx("acme", "legal"), &p, "conv-1").is_none());
        assert!(sticky_flow(root, &owner, &p, "conv-1").is_some());
    }

    #[test]
    fn a_conversation_without_a_session_id_is_never_sticky() {
        let dir = tempdir().expect("tempdir");
        let (root, c, p) = (dir.path(), ctx("acme", "sales"), pack());
        park(root, &c, "support", "refund", "");
        settle(root, &c, "support", "refund", "");
        assert!(sticky_flow(root, &c, &p, "").is_none());
        assert!(!has_record(root, &c, "support", ""));
    }

    #[test]
    fn the_record_sits_beside_the_snapshots_it_describes() {
        let dir = tempdir().expect("tempdir");
        let c = ctx("acme", "sales");
        let record = owner_path(dir.path(), &c, "support", "conv/1");
        let snapshot = runner_exec::session_snapshot_path(
            dir.path(),
            "acme",
            Some("sales"),
            "support",
            "refund",
            "conv/1",
        );
        assert_eq!(
            record.parent().and_then(Path::parent),
            snapshot.parent().and_then(Path::parent),
        );
        assert!(record.ends_with("@flow-owner/conv_1.json"));
        assert!(snapshot.ends_with("refund/support:refund:conv_1.snapshot.json"));
    }
}
