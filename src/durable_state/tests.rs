//! Tests for [`crate::durable_state`].
//!
//! Everything above the `live` divider is pure. Below it, one test needs a real
//! Redis and is `#[ignore]`d; the other deliberately is NOT, because what it
//! proves is that a Redis which is *not* there fails loudly — and that needs
//! nothing listening.

use super::*;
use greentic_runner_host::engine::runtime::IngressEnvelope;
use greentic_runner_host::runner::engine::{ExecutionState, FlowSnapshot, FlowWait};
use greentic_runner_host::storage::config::ENV_REDIS_URL;

/// The default must stay byte-for-byte the pre-existing behaviour: naming no
/// backend resolves to memory, even when a Redis URL is sitting in the
/// environment for some other reason (the pin store's, say).
#[test]
fn naming_no_backend_resolves_to_memory_even_with_a_url_present() {
    let config = StorageConfig::from_vars(
        None,
        None,
        Some("redis://127.0.0.1:6379"),
        None,
        Some("local"),
        None,
    )
    .expect("no backend named is not an error");
    let storage = DurableStorage { config };
    assert!(
        !storage.is_durable(),
        "a URL alone must not switch a deployment onto Redis"
    );
}

/// A named-but-unbuildable backend is a refusal, not a fall back. This is the
/// whole difference from `resolve_pin_store`.
#[test]
fn a_named_redis_session_backend_without_a_url_is_a_refusal() {
    let err = StorageConfig::from_vars(Some("redis"), None, None, None, Some("local"), None)
        .expect_err("redis with no URL must refuse");
    let rendered = err.to_string();
    assert!(
        rendered.contains(ENV_REDIS_URL),
        "the refusal must name the variable to set; got: {rendered}"
    );
    assert!(
        rendered.contains("refusing"),
        "the refusal must say it is refusing, not describe a degrade; got: {rendered}"
    );
}

/// The keyspace an operator gets when they name only the backend and the URL.
#[test]
fn the_namespace_is_derived_from_the_resolved_env_not_the_process_var() {
    let config = StorageConfig::from_vars(
        Some("redis"),
        None,
        Some("redis://127.0.0.1:6379"),
        None,
        // `DurableStorage::resolve` passes the env this boot RESOLVED here, so
        // a `--env prod` boot with no GREENTIC_ENV set still gets `prod`.
        Some("prod"),
        None,
    )
    .expect("resolves");
    let SessionBackend::Redis { namespace, .. } = &config.session else {
        panic!("expected a redis session backend");
    };
    assert_eq!(namespace, "greentic:session:prod");
}

/// MUTATION PROOF: drop any field from `revision_namespace_suffix`'s input and
/// this fails. Two revisions that differ in ONE field of the isolation identity
/// must land in different keyspaces — a merged keyspace is the cross-revision
/// resume `revision_boot` exists to prevent, and it would appear only on the
/// deployment that configured durability.
#[test]
fn every_isolation_field_changes_the_namespace() {
    let base = ["rev", "dep", "tenant", "team", "customer", "bundle"];
    let baseline = isolation_suffix(&base);
    for index in 0..base.len() {
        let mut altered = base;
        altered[index] = "different";
        assert_ne!(
            isolation_suffix(&altered),
            baseline,
            "changing field {index} must change the keyspace"
        );
    }
}

/// Length-prefixing, not concatenation: `("ab","c")` and `("a","bc")` name two
/// different revisions and must not digest the same.
#[test]
fn adjacent_fields_cannot_be_confused_for_one_another() {
    assert_ne!(
        isolation_suffix(&["ab", "c"]),
        isolation_suffix(&["a", "bc"])
    );
}

/// The suffix is stable across calls — it is a pure digest of on-disk identity,
/// which is the only reason a restarted process can find what it parked.
#[test]
fn the_suffix_is_stable_across_calls() {
    let fields = ["rev-01", "dep-01", "acme", "general", "cust", "bundle"];
    assert_eq!(isolation_suffix(&fields), isolation_suffix(&fields));
    assert!(
        isolation_suffix(&fields).starts_with("rev-01-"),
        "the revision id leads so SCAN output stays readable"
    );
}

/// The per-revision keyspace extends the operator's, it does not replace it —
/// so an operator who set `GREENTIC_RUNNER_SESSION_NAMESPACE` still owns the
/// prefix every key of this deployment is written under.
#[test]
fn the_revision_keyspace_extends_the_operators_prefix() {
    assert_eq!(
        revision_namespace("greentic:session:prod", "rev-abc"),
        "greentic:session:prod:rev-abc"
    );
    assert_eq!(
        revision_namespace("greentic:session:prod:", "rev-abc"),
        "greentic:session:prod:rev-abc",
        "a trailing colon must not produce an empty keyspace segment"
    );
}

/// An in-memory `DurableStorage` hands out fresh, unshared stores and never
/// touches the network — the path every existing test and every desktop run
/// takes.
#[tokio::test]
async fn in_memory_storage_mints_independent_stores() {
    let storage = DurableStorage::in_memory();
    let (session_a, _) = storage.stores_for("rev-a").await.expect("in-memory");
    let (session_b, _) = storage.stores_for("rev-b").await.expect("in-memory");
    assert!(
        !std::sync::Arc::ptr_eq(&session_a, &session_b),
        "two revisions must not share one in-memory store"
    );
}

/// A zero wait TTL means "no expiry", not "expire immediately" — a zero would
/// drop the snapshot before the turn that wrote it could be resumed, which
/// reads as "durable storage does not work".
#[test]
fn a_zero_wait_ttl_disables_expiry_rather_than_expiring_at_once() {
    let config = StorageConfig::from_vars(
        Some("redis"),
        None,
        Some("redis://127.0.0.1:6379"),
        Some("greentic:session:test"),
        None,
        Some("0"),
    )
    .expect("resolves");
    assert_eq!(config.session.wait_ttl(), None);
}

/// The documented default, asserted rather than described: 24 hours.
#[test]
fn the_default_wait_ttl_is_twenty_four_hours() {
    let config = StorageConfig::from_vars(
        Some("redis"),
        None,
        Some("redis://127.0.0.1:6379"),
        Some("greentic:session:test"),
        None,
        None,
    )
    .expect("resolves");
    assert_eq!(
        config.session.wait_ttl(),
        Some(std::time::Duration::from_secs(24 * 60 * 60))
    );
}

/// Durable sessions without revision affinity is half a configuration, and the
/// half that is missing produces an INTERMITTENT version of the failure the
/// operator just configured Redis to remove. The boot has to say so.
#[test]
fn the_affinity_warning_fires_only_when_it_is_the_missing_half() {
    let durable = DurableStorage {
        config: StorageConfig::redis("redis://127.0.0.1:6379", "greentic:session:prod")
            .expect("resolves"),
    };

    let warning = durable
        .revision_affinity_warning(None)
        .expect("durable sessions with no pin store must warn");
    assert!(
        warning.contains(PIN_REDIS_URL_ENV),
        "the warning must name the variable to set; got: {warning}"
    );
    assert!(
        warning.contains("greentic:session:prod"),
        "the warning must name what is already configured; got: {warning}"
    );

    assert!(
        durable
            .revision_affinity_warning(Some("redis://127.0.0.1:6379"))
            .is_none(),
        "a configured pin store is the other half; warning then is noise"
    );
    assert!(
        durable.revision_affinity_warning(Some("   ")).is_some(),
        "a blank pin URL configures nothing and must not silence the warning"
    );

    assert!(
        DurableStorage::in_memory()
            .revision_affinity_warning(None)
            .is_none(),
        "in-memory sessions do not survive a restart at all, so affinity is moot"
    );
}

/// The boot probe is what makes an unreachable backend a STARTUP failure rather
/// than a first-deploy failure — an environment with no revision attached opens
/// no per-revision store, so nothing else would notice.
#[test]
fn the_boot_probe_refuses_an_unreachable_backend() {
    let durable = DurableStorage {
        // Port 1 is privileged and unbound; the connect is refused at once.
        config: StorageConfig::redis("redis://127.0.0.1:1", "greentic:session:probe-test")
            .expect("resolves"),
    };
    let err = durable
        .ensure_reachable()
        .expect_err("an unreachable backend must not boot");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("unreachable"),
        "the boot failure must say the backend is unreachable; got: {rendered}"
    );
    assert!(
        DurableStorage::in_memory().ensure_reachable().is_ok(),
        "the in-memory default must open no socket at all"
    );
}

// ---------------------------------------------------------------------------
// live: needs a real Redis
// ---------------------------------------------------------------------------
//
// ```bash
// docker run -d --name start-durable-redis -p 127.0.0.1:6398:6379 redis:7-alpine
// GREENTIC_DURABLE_TEST_REDIS_URL=redis://127.0.0.1:6398 \
//   cargo test -p greentic-start --lib durable_state::tests::live -- --ignored --nocapture
// ```

/// The same shape `revision_serve`'s resume tests use. Duplicated rather than
/// shared: those live inside that module's `mod tests`, and widening their
/// visibility to reach them from here would put a test fixture on the crate's
/// internal surface for no gain.
fn envelope_for(user: &str, conversation: &str) -> IngressEnvelope {
    IngressEnvelope {
        entry_node: None,
        tenant: "acme".into(),
        env: Some("local".into()),
        pack_id: Some("pack.demo".into()),
        flow_id: "flow.main".into(),
        flow_type: Some("messaging".into()),
        action: Some("messaging".into()),
        session_hint: Some(format!("acme:provider:{conversation}:{user}")),
        provider: Some("provider".into()),
        messaging_endpoint_id: None,
        channel: Some(conversation.into()),
        conversation: Some(conversation.into()),
        user: Some(user.into()),
        activity_id: Some(format!("activity-{conversation}")),
        timestamp: None,
        payload: serde_json::json!({ "text": "hi" }),
        metadata: None,
        reply_scope: Some(greentic_types::ReplyScope {
            conversation: conversation.into(),
            thread: None,
            reply_to: None,
            correlation: None,
        }),
    }
    .canonicalize()
}

fn wait_for(next_node: &str) -> FlowWait {
    let state: ExecutionState = serde_json::from_value(serde_json::json!({
        "input": { "text": "hi" },
        "nodes": {},
        "egress": []
    }))
    .expect("state");
    FlowWait {
        reason: Some("await-user".into()),
        snapshot: FlowSnapshot {
            pack_id: "pack.demo".into(),
            flow_id: "flow.main".into(),
            next_flow: None,
            next_node: next_node.into(),
            awaiting_submit: false,
            state,
        },
    }
}

const LIVE_REDIS_ENV: &str = "GREENTIC_DURABLE_TEST_REDIS_URL";

/// Panics with the recipe rather than skipping: an `#[ignore]`d test that is
/// RUN and then silently passes reports green for work it did not do.
fn live_redis_url() -> String {
    std::env::var(LIVE_REDIS_ENV).unwrap_or_else(|_| {
        panic!("{LIVE_REDIS_ENV} is unset; see this module's `live` section for the recipe")
    })
}

fn live_storage(url: &str) -> DurableStorage {
    let config = StorageConfig::from_vars(
        Some("redis"),
        Some("redis"),
        Some(url),
        Some(&format!(
            "greentic:session:durable-test:{}",
            ulid::Ulid::new()
        )),
        None,
        None,
    )
    .expect("live storage resolves");
    DurableStorage { config }
}

/// A backend that was NAMED and cannot be reached fails at construction, in
/// front of the operator, rather than minutes later in front of a user.
///
/// No `#[ignore]` and no Redis: the point is that nothing is listening.
#[tokio::test]
async fn an_unreachable_configured_redis_fails_at_store_construction() {
    // Port 1 is privileged and unbound; the connect is refused immediately.
    let storage = live_storage("redis://127.0.0.1:1");
    // `expect_err` is unavailable: the Ok side is a pair of `Arc<dyn …>` and
    // neither store trait is `Debug`.
    let Err(err) = storage.stores_for("rev-unreachable").await else {
        panic!("an unreachable Redis must not yield a working-looking store");
    };
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("session store") || rendered.contains("unreachable"),
        "the failure must say which store could not be opened; got: {rendered}"
    );
    assert!(
        !rendered.contains("127.0.0.1:1@") && !rendered.contains("password"),
        "a failure message must never carry the URL's credential; got: {rendered}"
    );
}

/// THE durability check: park a conversation, throw the process away, resume it.
///
/// "Throw the process away" is modelled by building a SECOND, independent pair
/// of stores from the same `DurableStorage` and the same revision identity —
/// which is exactly what a restarted `greentic-start` does, since every input
/// to the keyspace comes from `runtime-config.json` and `environment.json` on
/// disk rather than from anything a process mints. Nothing is shared between
/// the two `FlowResumeStore`s but Redis.
///
/// MUTATION PROOF: make `revision_namespace` ignore its suffix, or make
/// `isolation_suffix` return a per-process value, and the isolation half fails;
/// take the session store back to in-memory and the resume half fails.
#[tokio::test]
#[ignore = "needs a real Redis; see this module's `live` section"]
async fn a_parked_conversation_survives_a_restart() {
    use greentic_runner_host::engine::runtime::FlowResumeStore;

    let url = live_redis_url();
    let storage = live_storage(&url);
    let suffix = isolation_suffix(&["rev-01", "dep-01", "acme", "general", "cust", "bundle"]);
    let other = isolation_suffix(&["rev-02", "dep-01", "acme", "general", "cust", "bundle"]);

    let envelope = envelope_for("user-1", "conv-1");

    // --- process lifetime 1: park ---
    let (session, _state) = storage.stores_for(&suffix).await.expect("open");
    FlowResumeStore::new(session)
        .save(&envelope, &wait_for("node-a"))
        .await
        .expect("park");

    // --- process lifetime 2: a brand-new store over the same keyspace ---
    let (session_after_restart, _) = storage.stores_for(&suffix).await.expect("reopen");
    let resumed = FlowResumeStore::new(session_after_restart)
        .fetch(&envelope)
        .await
        .expect("fetch")
        .expect("the parked snapshot must survive the process that wrote it");
    assert_eq!(
        resumed.next_node, "node-a",
        "a resumed conversation must land where it parked, not at the entry card"
    );

    // --- and a DIFFERENT revision, on the same Redis, still sees nothing ---
    let (other_revision, _) = storage.stores_for(&other).await.expect("open other");
    assert!(
        FlowResumeStore::new(other_revision)
            .fetch(&envelope)
            .await
            .expect("fetch other")
            .is_none(),
        "durability must not cost the per-revision isolation revision_boot provides"
    );

    // Leave the keyspace clean for the next run.
    let (session, _) = storage.stores_for(&suffix).await.expect("reopen to clear");
    FlowResumeStore::new(session)
        .clear(&envelope)
        .await
        .expect("clear");
}
