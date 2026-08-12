//! The `correlation_id -> delivered message` map.
//!
//! A WASM provider component holds no state between invocations, so the
//! `message_ts` of the message that carries an outstanding approval request has
//! to live here. Without it a quorum republish — the designer mints a fresh
//! token and republishes on the same correlation id every time a vote lands
//! while `min_approvals` is unmet (contract §4) — would `chat.postMessage` a
//! SECOND approval message rather than `chat.update` the outstanding one, and
//! one gate would read as several approvals.
//!
//! ## What happens when this process restarts
//!
//! The ledger is in-memory and is deliberately **not** persisted. A restart
//! loses it, and the next republish for a gate delivered before the restart
//! posts a new message; every republish after that updates *that* message,
//! because the new delivery re-enters the ledger. So the degradation is
//! bounded — at most one extra message per outstanding gate per restart — and
//! it is logged (see [`crate::approval_rail::listener`]), never silent.
//!
//! Persisting it to `state/runtime/` would not fix the general case and would
//! read as if it had. The rail is consumed under a NATS **queue group**, so in
//! a multi-instance deployment a republish is delivered to exactly one
//! instance, and not necessarily the one that made the first delivery. A map
//! local to a process is therefore already incomplete before any restart
//! happens. Closing that properly needs either shared state or a channel-side
//! lookup of the outstanding message (Slack stamps `event_payload.correlation_id`
//! into the delivered message's metadata precisely so such a lookup is
//! possible), and both are larger than this bridge.

use std::collections::{HashMap, VecDeque};

/// Where an outstanding approval request was delivered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    /// The channel/conversation id the request was delivered to.
    pub channel: String,
    /// The provider's id for the delivered message (Slack's `ts`).
    pub message_ts: String,
}

/// Default number of outstanding gates tracked before the oldest is evicted.
///
/// Correlation ids arrive from a shared subject, so the key space is not ours
/// to bound; a cap is what keeps a long-lived process from growing without
/// limit. An evicted gate degrades exactly like a restart does.
pub const DEFAULT_CAPACITY: usize = 1024;

/// Bounded, insertion-ordered `correlation_id -> Delivery` map.
///
/// Nothing here is a credential: a correlation id is
/// `<tenant>::run=<run_id>::node=<node_id>` and a `message_ts` is a Slack
/// message id, so both are safe to log. The `decision_token` is deliberately
/// NOT held — it is delivered into the channel's own per-message state and
/// comes back on the click, so this process never has to keep one at rest.
pub struct DeliveryLedger {
    capacity: usize,
    order: VecDeque<String>,
    entries: HashMap<String, Delivery>,
}

impl DeliveryLedger {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::new(),
            entries: HashMap::new(),
        }
    }

    /// Record (or refresh) where a gate's outstanding message lives.
    ///
    /// Returns the correlation id evicted to make room, if any, so the caller
    /// can say so out loud rather than silently forgetting a gate.
    pub fn record(&mut self, correlation_id: &str, delivery: Delivery) -> Option<String> {
        if self
            .entries
            .insert(correlation_id.to_string(), delivery)
            .is_some()
        {
            // Already tracked: refresh the value, keep its position. Re-queuing
            // it would let one chatty gate hold several slots in `order` and
            // evict others long before `capacity` entries actually exist.
            return None;
        }
        self.order.push_back(correlation_id.to_string());
        if self.order.len() <= self.capacity {
            return None;
        }
        let evicted = self.order.pop_front()?;
        self.entries.remove(&evicted);
        Some(evicted)
    }

    pub fn lookup(&self, correlation_id: &str) -> Option<&Delivery> {
        self.entries.get(correlation_id)
    }

    /// How many gates are currently tracked.
    ///
    /// Deliberately not called `len`: this is not a collection anybody
    /// iterates, and the `len`/`is_empty` pair would imply it is.
    #[cfg(test)]
    pub fn tracked_gates(&self) -> usize {
        self.entries.len()
    }
}

impl Default for DeliveryLedger {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delivery(ts: &str) -> Delivery {
        Delivery {
            channel: "C123".to_string(),
            message_ts: ts.to_string(),
        }
    }

    #[test]
    fn a_recorded_gate_is_found_again() {
        let mut ledger = DeliveryLedger::default();
        assert_eq!(
            ledger.record("default::run=R::node=n", delivery("1.1")),
            None
        );
        assert_eq!(
            ledger.lookup("default::run=R::node=n"),
            Some(&delivery("1.1"))
        );
        assert_eq!(ledger.lookup("default::run=OTHER::node=n"), None);
    }

    #[test]
    fn re_recording_a_gate_refreshes_it_without_consuming_a_second_slot() {
        // A quorum gate is re-delivered on every vote. If each re-delivery
        // pushed another entry onto `order`, a two-approver gate would evict
        // two other gates for one slot's worth of state.
        let mut ledger = DeliveryLedger::new(2);
        ledger.record("gate-a", delivery("1.1"));
        ledger.record("gate-a", delivery("2.2"));
        ledger.record("gate-b", delivery("3.3"));

        assert_eq!(ledger.tracked_gates(), 2);
        assert_eq!(ledger.lookup("gate-a"), Some(&delivery("2.2")));
        assert_eq!(ledger.lookup("gate-b"), Some(&delivery("3.3")));
    }

    #[test]
    fn the_oldest_gate_is_evicted_and_named_when_capacity_is_reached() {
        let mut ledger = DeliveryLedger::new(2);
        assert_eq!(ledger.record("gate-a", delivery("1.1")), None);
        assert_eq!(ledger.record("gate-b", delivery("2.2")), None);
        assert_eq!(
            ledger.record("gate-c", delivery("3.3")).as_deref(),
            Some("gate-a"),
            "the evicted gate must be reported so it can be logged"
        );

        assert_eq!(ledger.tracked_gates(), 2);
        assert_eq!(ledger.lookup("gate-a"), None);
        assert_eq!(ledger.lookup("gate-c"), Some(&delivery("3.3")));
    }

    #[test]
    fn a_zero_capacity_ledger_still_holds_one_gate() {
        // A misconfigured capacity must not turn the ledger into a no-op that
        // silently republishes a new message on every vote.
        let mut ledger = DeliveryLedger::new(0);
        ledger.record("gate-a", delivery("1.1"));
        assert_eq!(ledger.lookup("gate-a"), Some(&delivery("1.1")));
    }
}
