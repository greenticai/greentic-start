//! Push pump: replays activities since the client's watermark, then streams
//! live activities published via the notifier.

// These types are consumed by the upgrade handler in Task 11.
#![allow(dead_code)]

use crate::notifier::{ActivityNotifier, EventStream};
use async_trait::async_trait;
use futures_util::StreamExt;
use serde_json::Value;
use std::sync::Arc;

/// Abstract over how the pump reads activities from the conversation store.
/// Implementing this lets unit tests substitute an in-memory fake.
#[async_trait]
pub trait ActivitySource: Send + Sync + 'static {
    /// Fetch activities with `watermark >= since_watermark`, in order.
    /// Returns (activities_json_array, current_next_watermark).
    async fn fetch_since(
        &self,
        tenant_id: &str,
        conversation_id: &str,
        since_watermark: u64,
    ) -> Result<(Vec<Value>, u64), String>;
}

#[derive(Debug, thiserror::Error)]
pub enum PumpError {
    #[error("replay too large: {count} > {max}")]
    ReplayTooLarge { count: usize, max: usize },
    #[error("activity source error: {0}")]
    Source(String),
    #[error("notifier error: {0}")]
    Notifier(String),
}

#[derive(Debug)]
pub enum PumpFrame {
    Activities {
        activities: Vec<Value>,
        next_watermark: u64,
    },
    Error(String),
}

pub struct Pump {
    source: Arc<dyn ActivitySource>,
    notifier: Arc<dyn ActivityNotifier>,
    max_replay_size: usize,
}

impl Pump {
    pub fn new(
        source: Arc<dyn ActivitySource>,
        notifier: Arc<dyn ActivityNotifier>,
        max_replay_size: usize,
    ) -> Self {
        Self {
            source,
            notifier,
            max_replay_size,
        }
    }

    /// Run the pump and emit frames into `tx`. Returns when `tx` is closed
    /// (client disconnect) or on unrecoverable error.
    pub async fn run(
        &self,
        tenant_id: String,
        conversation_id: String,
        initial_watermark: u64,
        tx: tokio::sync::mpsc::Sender<PumpFrame>,
    ) -> Result<(), PumpError> {
        // 1. Subscribe FIRST so we don't miss events that fire during replay.
        let mut events: EventStream = self
            .notifier
            .subscribe(&tenant_id, &conversation_id)
            .await
            .map_err(|e| PumpError::Notifier(e.to_string()))?;

        // 2. Replay.
        let (replay_activities, mut cursor) = self
            .source
            .fetch_since(&tenant_id, &conversation_id, initial_watermark)
            .await
            .map_err(PumpError::Source)?;

        if replay_activities.len() > self.max_replay_size {
            return Err(PumpError::ReplayTooLarge {
                count: replay_activities.len(),
                max: self.max_replay_size,
            });
        }

        if !replay_activities.is_empty()
            && tx
                .send(PumpFrame::Activities {
                    activities: replay_activities,
                    next_watermark: cursor,
                })
                .await
                .is_err()
        {
            return Ok(()); // client gone
        }

        // 3. Live loop.
        while let Some(event) = events.next().await {
            // Only act on events that advance the cursor.
            if event.new_watermark < cursor {
                continue;
            }
            match self
                .source
                .fetch_since(
                    &event.tenant_id,
                    &event.conversation_id,
                    cursor.saturating_sub(1),
                )
                .await
            {
                Ok((activities, new_cursor)) => {
                    let to_send: Vec<Value> = activities
                        .into_iter()
                        .filter(|a| {
                            a.get("channelData")
                                .and_then(|cd| cd.get("watermark"))
                                .and_then(|w| w.as_u64())
                                .map(|w| w >= cursor)
                                .unwrap_or(true)
                        })
                        .collect();
                    if !to_send.is_empty() {
                        cursor = new_cursor;
                        if tx
                            .send(PumpFrame::Activities {
                                activities: to_send,
                                next_watermark: new_cursor,
                            })
                            .await
                            .is_err()
                        {
                            return Ok(());
                        }
                    }
                }
                Err(err) => {
                    let _ = tx.send(PumpFrame::Error(err)).await;
                    // Transient: keep the session alive; next event retries.
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notifier::{InMemoryNotifier, NotifyEvent};
    use serde_json::json;
    use std::sync::Mutex;

    struct FakeSource {
        activities: Mutex<Vec<Value>>,
        next_watermark: Mutex<u64>,
    }

    impl FakeSource {
        fn new() -> Self {
            Self {
                activities: Mutex::new(vec![]),
                next_watermark: Mutex::new(0),
            }
        }

        fn append(&self, text: &str) -> u64 {
            let mut wm = self.next_watermark.lock().unwrap();
            let watermark = *wm;
            *wm += 1;
            self.activities.lock().unwrap().push(json!({
                "type": "message",
                "text": text,
                "channelData": {"watermark": watermark}
            }));
            watermark
        }
    }

    #[async_trait]
    impl ActivitySource for FakeSource {
        async fn fetch_since(
            &self,
            _tenant: &str,
            _conv: &str,
            since: u64,
        ) -> Result<(Vec<Value>, u64), String> {
            let acts = self.activities.lock().unwrap();
            let next = *self.next_watermark.lock().unwrap();
            let filtered: Vec<Value> = acts
                .iter()
                .filter(|a| {
                    a.get("channelData")
                        .and_then(|cd| cd.get("watermark"))
                        .and_then(|w| w.as_u64())
                        .map(|w| w >= since)
                        .unwrap_or(false)
                })
                .cloned()
                .collect();
            Ok((filtered, next))
        }
    }

    #[tokio::test]
    async fn replay_returns_activities_above_initial_watermark() {
        let source = Arc::new(FakeSource::new());
        source.append("a");
        source.append("b");
        source.append("c");

        let notifier = Arc::new(InMemoryNotifier::new(8));
        let pump = Pump::new(source.clone(), notifier, 1000);

        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let handle = tokio::spawn(async move { pump.run("t1".into(), "c1".into(), 0, tx).await });

        let frame = rx.recv().await.expect("frame");
        match frame {
            PumpFrame::Activities {
                activities,
                next_watermark,
            } => {
                assert_eq!(activities.len(), 3);
                assert_eq!(next_watermark, 3);
            }
            _ => panic!("unexpected frame"),
        }
        drop(rx);
        handle.abort();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn replay_too_large_returns_error() {
        let source = Arc::new(FakeSource::new());
        for i in 0..5 {
            source.append(&format!("msg-{i}"));
        }
        let notifier = Arc::new(InMemoryNotifier::new(8));
        let pump = Pump::new(source, notifier, 3);

        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let result = pump.run("t1".into(), "c1".into(), 0, tx).await;
        assert!(matches!(
            result,
            Err(PumpError::ReplayTooLarge { count: 5, max: 3 })
        ));
    }

    #[tokio::test]
    async fn live_event_triggers_fetch_and_send() {
        let source = Arc::new(FakeSource::new());
        let notifier: Arc<dyn ActivityNotifier> = Arc::new(InMemoryNotifier::new(8));
        let pump = Pump::new(source.clone(), notifier.clone(), 1000);

        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let handle = tokio::spawn(async move { pump.run("t1".into(), "c1".into(), 0, tx).await });

        // Wait for replay (empty) — pump should now be in live loop.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let wm = source.append("hello-live");
        notifier
            .publish(NotifyEvent {
                tenant_id: "t1".into(),
                conversation_id: "c1".into(),
                new_watermark: wm + 1,
            })
            .await;

        let frame = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
            .await
            .expect("timed out")
            .expect("no frame");
        match frame {
            PumpFrame::Activities { activities, .. } => {
                assert_eq!(activities.len(), 1);
                assert_eq!(activities[0]["text"], "hello-live");
            }
            _ => panic!("unexpected"),
        }
        drop(rx);
        handle.abort();
        let _ = handle.await;
    }
}
