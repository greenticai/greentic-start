//! Feeds `websocket::Pump` from the provider's `poll_events` op.
//!
//! `Pump` itself is transport-neutral (it only talks to an `ActivitySource`
//! and an `ActivityNotifier`), but its live loop de-duplicates by reading
//! `channelData.watermark` off each activity, a Direct Line convention. An
//! activity without it always passes the filter, so a source that did not
//! stamp it would replay the last event on every wake-up. [`PollEventsSource`]
//! stamps it, so `Pump` needs no change.

use super::event::{ApiEvent, PollEventsResponse};
use crate::notifier::{ActivityNotifier, EventStream, NotifierError, NotifyEvent};
use crate::websocket::pump::ActivitySource;
use async_trait::async_trait;
use futures_util::StreamExt;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

/// Why a backend call failed. Carries no provider text: it can reach a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum BackendError {
    #[error("the credential was refused")]
    Unauthorized,
    #[error("the conversation does not exist")]
    NotFound,
    #[error("the provider could not be asked")]
    Unavailable,
}

/// What the SSE route needs from the deployed provider. One value is built per
/// request, so it carries that request's credential and revision.
#[async_trait]
pub(crate) trait ApiChannelBackend: Send + Sync + 'static {
    /// Verify the caller's credential. `Unauthorized` becomes a bare `401`
    /// before anything streams.
    async fn authorize(&self) -> Result<(), BackendError>;

    /// The `poll_events` provider op.
    async fn poll_events(
        &self,
        conversation_id: &str,
        since: u64,
    ) -> Result<PollEventsResponse, BackendError>;
}

/// `ActivitySource` over [`ApiChannelBackend::poll_events`].
pub(crate) struct PollEventsSource {
    pub backend: Arc<dyn ApiChannelBackend>,
}

/// An event as `Pump` sees it: the event plus the watermark stamp.
pub(crate) fn event_to_activity(event: &ApiEvent) -> Result<Value, String> {
    let mut activity = serde_json::to_value(event).map_err(|err| err.to_string())?;
    if let Some(map) = activity.as_object_mut() {
        map.insert("channelData".into(), json!({ "watermark": event.cursor }));
    }
    Ok(activity)
}

/// The inverse of [`event_to_activity`]; the stamp is dropped.
pub(crate) fn activity_to_event(activity: Value) -> Result<ApiEvent, String> {
    serde_json::from_value(activity).map_err(|err| err.to_string())
}

#[async_trait]
impl ActivitySource for PollEventsSource {
    async fn fetch_since(
        &self,
        _tenant_id: &str,
        conversation_id: &str,
        since_watermark: u64,
    ) -> Result<(Vec<Value>, u64), String> {
        let response = self
            .backend
            .poll_events(conversation_id, since_watermark)
            .await
            .map_err(|err| err.to_string())?;
        let mut activities = Vec::with_capacity(response.events.len());
        // The op promises `cursor >= since`; a provider that over-returns must
        // not make the client see an event twice.
        for event in response
            .events
            .iter()
            .filter(|e| e.cursor >= since_watermark)
        {
            activities.push(event_to_activity(event)?);
        }
        Ok((activities, response.next_cursor))
    }
}

/// Wraps a notifier so every subscription also wakes up on a timer.
///
/// The provider appends to the log; nothing tells the notifier unless the host
/// publishes after `send`. The tick bounds the latency of a missed or
/// cross-replica wake-up without any shared state: each stream polls for itself.
pub(crate) struct TickingNotifier {
    pub inner: Arc<dyn ActivityNotifier>,
    pub period: Duration,
}

#[async_trait]
impl ActivityNotifier for TickingNotifier {
    async fn publish(&self, event: NotifyEvent) {
        self.inner.publish(event).await;
    }

    async fn subscribe(
        &self,
        tenant_id: &str,
        conversation_id: &str,
    ) -> Result<EventStream, NotifierError> {
        let inner = self.inner.subscribe(tenant_id, conversation_id).await?;
        let tenant = tenant_id.to_string();
        let conv = conversation_id.to_string();
        let mut interval = tokio::time::interval(self.period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let ticks = futures_util::stream::unfold(interval, move |mut interval| {
            let tenant = tenant.clone();
            let conv = conv.clone();
            async move {
                interval.tick().await;
                // `u64::MAX` never reads as "behind the cursor", so `Pump`
                // always fetches; an empty fetch sends nothing.
                Some((
                    NotifyEvent {
                        tenant_id: tenant,
                        conversation_id: conv,
                        new_watermark: u64::MAX,
                    },
                    interval,
                ))
            }
        });
        Ok(futures_util::stream::select(inner, ticks.boxed()).boxed())
    }
}
