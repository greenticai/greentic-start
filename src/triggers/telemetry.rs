//! Trigger counters and the per-firing log line (contract §10). Safe to call
//! unconditionally: with no meter installed the global meter is a no-op.

use std::sync::OnceLock;

use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::metrics::Counter;

use super::table::LoadedTrigger;

static OUTCOMES: OnceLock<Counter<u64>> = OnceLock::new();

fn outcomes() -> &'static Counter<u64> {
    OUTCOMES.get_or_init(|| {
        global::meter("greentic-start")
            .u64_counter("greentic.trigger.outcomes")
            .with_description(
                "Trigger firings by outcome: fired, rejected, deduplicated, skipped, failed",
            )
            .build()
    })
}

/// Record one outcome. `reason` narrows `rejected` and `skipped`
/// (`verification`, `overlap`, `budget`, `disabled`, …); it is a closed
/// vocabulary of this module's own strings, never request data.
pub(crate) fn record(loaded: &LoadedTrigger, outcome: &'static str, reason: &'static str) {
    outcomes().add(
        1,
        &[
            KeyValue::new("trigger_id", loaded.spec.trigger_id.clone()),
            KeyValue::new("kind", loaded.spec.kind.name()),
            KeyValue::new("outcome", outcome),
            KeyValue::new("reason", reason),
            KeyValue::new("deployment_id", loaded.scope.deployment_id.to_string()),
        ],
    );
    tracing::info!(
        target: "greentic.trigger",
        trigger_id = %loaded.spec.trigger_id,
        kind = loaded.spec.kind.name(),
        deployment_id = %loaded.scope.deployment_id,
        revision_id = %loaded.scope.revision_id,
        source_extension = %loaded.spec.extension_id,
        source_node = %loaded.spec.node_id,
        outcome,
        reason,
        "trigger outcome"
    );
}

/// A rejected webhook, as an audit event: which trigger, why. Never the body
/// and never a header value — a rejected request is by definition untrusted
/// input, and an audit log that stores it becomes the injection surface.
pub(crate) fn audit_rejection(loaded: &LoadedTrigger, reason: &'static str) {
    tracing::warn!(
        target: "greentic.trigger.audit",
        trigger_id = %loaded.spec.trigger_id,
        deployment_id = %loaded.scope.deployment_id,
        revision_id = %loaded.scope.revision_id,
        reason,
        "trigger request rejected"
    );
    record(loaded, "rejected", reason);
}
