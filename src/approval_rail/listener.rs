//! The NATS half of the bridge: subscribe to requests, publish answers.
//!
//! Shape is deliberately [`crate::business_event_listener`]'s, down to the
//! comments' reasoning. `gtc start` (`run_start_request -> run_start ->
//! demo_up_services`) is fully synchronous — there is no ambient Tokio runtime
//! — so the thread spawned here builds its own `current_thread` runtime and
//! does the `async_nats::connect`, the `queue_subscribe` and the whole loop
//! inside `rt.block_on(...)`. A connect failure warns and exits this thread; it
//! can never panic ("there is no reactor running") or fail boot.
//!
//! Delivery itself is synchronous (it instantiates a WASM component), so each
//! request is handed to `spawn_blocking` — otherwise one slow Slack call would
//! head-of-line block every other gate on the subscription.

use std::sync::{Arc, Mutex};
use std::thread;

use futures_util::StreamExt;
use tokio::sync::{mpsc, oneshot};

use crate::operator_log;

use super::delivery::ApprovalDelivery;
use super::ledger::{DEFAULT_CAPACITY, DeliveryLedger};
use super::request::{self, RailRequest};
use super::response::ResponsePublication;
use super::{
    CORRELATION_ID_HEADER, REQUEST_QUEUE_GROUP, REQUEST_SUBJECT, RESPONSE_QUEUE_CAPACITY,
    RESPONSE_SUBJECT,
};

/// Everything one running bridge needs.
pub struct ApprovalRailListenerConfig {
    /// Broker carrying the approval rail. Connecting happens inside the
    /// listener's own thread — see the module docs.
    pub nats_url: String,
    /// How an approval request reaches a human.
    pub delivery: Arc<dyn ApprovalDelivery>,
}

/// Handle to the background subscribe/publish thread.
pub struct ApprovalRailListener {
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl ApprovalRailListener {
    /// Spawn the bridge and install the process-wide handle the ingress seams
    /// publish through.
    ///
    /// A thread-spawn failure (an exceptional OS-level condition) is logged and
    /// yields a no-op handle rather than panicking the caller — mirrors
    /// [`crate::business_event_listener::BusinessEventListener::start`]. So does
    /// a poisoned handle slot; either way boot continues without the bridge.
    pub fn start(config: ApprovalRailListenerConfig) -> Self {
        let ledger = Arc::new(Mutex::new(DeliveryLedger::new(DEFAULT_CAPACITY)));
        let (responses_tx, responses_rx) = mpsc::channel(RESPONSE_QUEUE_CAPACITY);
        if !super::install(responses_tx, Arc::clone(&ledger)) {
            return Self {
                shutdown: None,
                handle: None,
            };
        }

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        match thread::Builder::new()
            .name("approval-rail-bridge".to_string())
            .spawn(move || run_listener_thread(config, ledger, responses_rx, shutdown_rx))
        {
            Ok(handle) => Self {
                shutdown: Some(shutdown_tx),
                handle: Some(handle),
            },
            Err(err) => {
                operator_log::error(
                    module_path!(),
                    format!("failed to spawn approval bridge thread: {err}"),
                );
                super::uninstall();
                Self {
                    shutdown: None,
                    handle: None,
                }
            }
        }
    }

    /// Signal the loop to stop, wait for the thread to exit, and remove the
    /// process-wide handle.
    ///
    /// Uninstalling matters: an ingress seam that kept publishing into the
    /// stopped listener's queue would fill it and then log a dropped answer per
    /// click, when the honest state is simply "no bridge is running".
    pub fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take()
            && let Err(err) = handle.join()
        {
            operator_log::error(
                module_path!(),
                format!("approval bridge thread panicked: {err:?}"),
            );
        }
        super::uninstall();
    }
}

fn run_listener_thread(
    config: ApprovalRailListenerConfig,
    ledger: Arc<Mutex<DeliveryLedger>>,
    responses_rx: mpsc::Receiver<ResponsePublication>,
    shutdown_rx: oneshot::Receiver<()>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            operator_log::error(
                module_path!(),
                format!("failed to build tokio runtime for the approval bridge: {err}"),
            );
            return;
        }
    };
    runtime.block_on(run_listener_loop(config, ledger, responses_rx, shutdown_rx));
}

async fn run_listener_loop(
    config: ApprovalRailListenerConfig,
    ledger: Arc<Mutex<DeliveryLedger>>,
    mut responses_rx: mpsc::Receiver<ResponsePublication>,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let client = match async_nats::connect(&config.nats_url).await {
        Ok(client) => client,
        Err(err) => {
            operator_log::warn(
                module_path!(),
                format!(
                    "approval bridge failed to connect to {}: {err}",
                    config.nats_url
                ),
            );
            return;
        }
    };

    let mut subscriber = match client
        .queue_subscribe(REQUEST_SUBJECT, REQUEST_QUEUE_GROUP.to_string())
        .await
    {
        Ok(subscriber) => subscriber,
        Err(err) => {
            operator_log::warn(
                module_path!(),
                format!("approval bridge failed to subscribe to {REQUEST_SUBJECT}: {err}"),
            );
            return;
        }
    };

    operator_log::info(
        module_path!(),
        format!(
            "approval bridge subscribed subject={REQUEST_SUBJECT} \
             queue_group={REQUEST_QUEUE_GROUP} response_subject={RESPONSE_SUBJECT}"
        ),
    );

    loop {
        tokio::select! {
            maybe_message = subscriber.next() => {
                match maybe_message {
                    Some(message) => dispatch_request(message, &config.delivery, &ledger),
                    None => {
                        operator_log::warn(
                            module_path!(),
                            "approval bridge subscription ended (NATS connection closed)",
                        );
                        break;
                    }
                }
            }
            maybe_response = responses_rx.recv() => {
                match maybe_response {
                    Some(publication) => publish_response(&client, publication).await,
                    None => {
                        operator_log::warn(
                            module_path!(),
                            "approval bridge response queue closed",
                        );
                        break;
                    }
                }
            }
            _ = &mut shutdown_rx => {
                operator_log::info(module_path!(), "approval bridge stopping (shutdown signal)");
                break;
            }
        }
    }
}

/// Offload one request's delivery onto the blocking pool.
///
/// Fire-and-forget, exactly like `business_event_listener::dispatch_message`: a
/// join failure is logged and never re-panicked, so one bad gate cannot take
/// the bridge down.
fn dispatch_request(
    message: async_nats::Message,
    delivery: &Arc<dyn ApprovalDelivery>,
    ledger: &Arc<Mutex<DeliveryLedger>>,
) {
    let correlation_header = message.headers.as_ref().and_then(|headers| {
        headers
            .get(CORRELATION_ID_HEADER)
            .map(|value| value.as_str().to_string())
    });
    let payload = message.payload.to_vec();
    let delivery = Arc::clone(delivery);
    let ledger = Arc::clone(ledger);

    let blocking = tokio::task::spawn_blocking(move || {
        handle_request(correlation_header.as_deref(), &payload, &delivery, &ledger);
    });

    tokio::spawn(async move {
        if let Err(err) = blocking.await {
            operator_log::error(
                module_path!(),
                format!("approval bridge delivery task failed: {err}"),
            );
        }
    });
}

/// Parse one request off the rail and deliver it.
///
/// The payload is never logged, at any level: it carries a `decision_token`
/// (contract §4) and the approver emails §6 warns about. Failures name the
/// correlation id and a stable reason token instead — both safe to print.
pub fn handle_request(
    correlation_header: Option<&str>,
    payload: &[u8],
    delivery: &Arc<dyn ApprovalDelivery>,
    ledger: &Arc<Mutex<DeliveryLedger>>,
) {
    let request = match request::parse(correlation_header, payload) {
        Ok(request) => request,
        Err(reason) => {
            // Traffic that is not an approval request is expected on a shared
            // subject; a decode failure of one that is, is not.
            operator_log::debug(
                module_path!(),
                format!(
                    "approval bridge skipped a message on {REQUEST_SUBJECT}: {}",
                    reason.as_str()
                ),
            );
            return;
        }
    };

    let known = lookup(ledger, &request.correlation_id);
    if known.is_none() {
        warn_on_untracked_repeat(&request);
    }

    match delivery.deliver(&request, known.as_ref()) {
        Ok(Some(recorded)) => record(ledger, &request.correlation_id, recorded),
        Ok(None) => {}
        Err(err) => operator_log::error(
            module_path!(),
            format!(
                "approval bridge failed to deliver gate {}: {err:#}",
                request.correlation_id
            ),
        ),
    }
}

/// A gate the ledger has never seen may still be a republish — the first vote
/// on a quorum gate, an escalation, or a delivery made before a restart. Say so
/// rather than letting a second message appear in the channel unexplained.
fn warn_on_untracked_repeat(request: &RailRequest) {
    operator_log::debug(
        module_path!(),
        format!(
            "approval bridge delivering gate {} as a new message (no outstanding message \
             is tracked for it in this process)",
            request.correlation_id
        ),
    );
}

fn lookup(
    ledger: &Arc<Mutex<DeliveryLedger>>,
    correlation_id: &str,
) -> Option<super::ledger::Delivery> {
    ledger.lock().ok()?.lookup(correlation_id).cloned().or(None)
}

fn record(
    ledger: &Arc<Mutex<DeliveryLedger>>,
    correlation_id: &str,
    delivery: super::ledger::Delivery,
) {
    let Ok(mut ledger) = ledger.lock() else {
        operator_log::error(
            module_path!(),
            "approval bridge delivery ledger is poisoned; republishes will post new messages",
        );
        return;
    };
    if let Some(evicted) = ledger.record(correlation_id, delivery) {
        operator_log::warn(
            module_path!(),
            format!(
                "approval bridge evicted gate {evicted} from the delivery ledger (capacity \
                 reached); a republish for it will post a new message"
            ),
        );
    }
}

/// Publish one answer, echoing the request's correlation id.
///
/// Without that header the designer cannot route the response at all — it
/// routes on the header alone (contract §1), so an answer published without one
/// is silently discarded and the gate stays pending forever.
async fn publish_response(client: &async_nats::Client, publication: ResponsePublication) {
    let payload = match publication.body.to_wire_bytes() {
        Ok(payload) => payload,
        Err(err) => {
            operator_log::error(
                module_path!(),
                format!(
                    "approval bridge could not encode the answer for gate {}: {err}",
                    publication.correlation_id
                ),
            );
            return;
        }
    };

    let mut headers = async_nats::HeaderMap::new();
    headers.insert(CORRELATION_ID_HEADER, publication.correlation_id.as_str());

    if let Err(err) = client
        .publish_with_headers(RESPONSE_SUBJECT, headers, payload.into())
        .await
    {
        operator_log::error(
            module_path!(),
            format!(
                "approval bridge failed to publish the answer for gate {} on \
                 {RESPONSE_SUBJECT}: {err}. The gate stays pending.",
                publication.correlation_id
            ),
        );
        return;
    }

    // Flushing matters here: the bridge may be the only thing keeping the
    // connection busy, and an un-flushed publish sitting in the client buffer
    // at shutdown is a decision that never reached the designer.
    if let Err(err) = client.flush().await {
        operator_log::warn(
            module_path!(),
            format!(
                "approval bridge published the answer for gate {} but could not flush: {err}",
                publication.correlation_id
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval_rail::ledger::Delivery;
    use serde_json::json;
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct RecordingDelivery {
        seen: StdMutex<Vec<(String, Option<Delivery>, serde_json::Value)>>,
        fail: bool,
    }

    impl ApprovalDelivery for RecordingDelivery {
        fn deliver(
            &self,
            request: &RailRequest,
            known: Option<&Delivery>,
        ) -> anyhow::Result<Option<Delivery>> {
            self.seen.lock().expect("lock").push((
                request.correlation_id.clone(),
                known.cloned(),
                request.body.expose().clone(),
            ));
            if self.fail {
                anyhow::bail!("simulated delivery failure");
            }
            Ok(None)
        }
    }

    fn request_bytes(correlation: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "target": correlation,
            "operation": "request",
            "input": {"title": "Refund 1200 USD"},
            "routing": {"channels": ["slack"], "decision_token": "s3cr3t-token-value"},
        }))
        .expect("serialize")
    }

    #[test]
    fn a_request_reaches_delivery_with_its_body_intact() {
        let recording = Arc::new(RecordingDelivery::default());
        let delivery: Arc<dyn ApprovalDelivery> =
            Arc::clone(&recording) as Arc<dyn ApprovalDelivery>;
        let ledger = Arc::new(Mutex::new(DeliveryLedger::default()));

        handle_request(
            Some("default::run=RUN-1::node=gate"),
            &request_bytes("default::run=RUN-1::node=gate"),
            &delivery,
            &ledger,
        );

        let seen = recording.seen.lock().expect("lock");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "default::run=RUN-1::node=gate");
        assert_eq!(seen[0].1, None, "a first delivery knows of no message");
        assert_eq!(
            seen[0].2["routing"]["decision_token"], "s3cr3t-token-value",
            "the body must reach delivery verbatim"
        );
    }

    #[test]
    fn a_republish_for_a_tracked_gate_is_handed_the_outstanding_message() {
        // This is the rule the whole ledger exists for: a quorum republish
        // (contract §4) must update the outstanding message, not post a second
        // approval into the channel.
        let recording = Arc::new(RecordingDelivery::default());
        let delivery: Arc<dyn ApprovalDelivery> =
            Arc::clone(&recording) as Arc<dyn ApprovalDelivery>;
        let ledger = Arc::new(Mutex::new(DeliveryLedger::default()));
        ledger.lock().expect("lock").record(
            "default::run=RUN-1::node=gate",
            Delivery {
                channel: "C123".to_string(),
                message_ts: "1700000000.000100".to_string(),
            },
        );

        handle_request(
            Some("default::run=RUN-1::node=gate"),
            &request_bytes("default::run=RUN-1::node=gate"),
            &delivery,
            &ledger,
        );

        let seen = recording.seen.lock().expect("lock");
        assert_eq!(
            seen[0].1,
            Some(Delivery {
                channel: "C123".to_string(),
                message_ts: "1700000000.000100".to_string(),
            }),
            "a republish for a tracked gate must carry the outstanding message id, or the \
             delivery posts a SECOND approval message"
        );
    }

    #[test]
    fn a_message_that_is_not_an_approval_request_is_skipped_without_delivering() {
        let recording = Arc::new(RecordingDelivery::default());
        let delivery: Arc<dyn ApprovalDelivery> =
            Arc::clone(&recording) as Arc<dyn ApprovalDelivery>;
        let ledger = Arc::new(Mutex::new(DeliveryLedger::default()));

        handle_request(None, b"{ not json", &delivery, &ledger);
        handle_request(
            None,
            &serde_json::to_vec(&json!({"target": "t", "operation": "response"})).expect("json"),
            &delivery,
            &ledger,
        );

        assert!(recording.seen.lock().expect("lock").is_empty());
    }

    #[test]
    fn a_delivery_failure_is_logged_and_never_panics() {
        let delivery: Arc<dyn ApprovalDelivery> = Arc::new(RecordingDelivery {
            seen: StdMutex::new(Vec::new()),
            fail: true,
        });
        let ledger = Arc::new(Mutex::new(DeliveryLedger::default()));
        handle_request(
            Some("default::run=RUN-1::node=gate"),
            &request_bytes("default::run=RUN-1::node=gate"),
            &delivery,
            &ledger,
        );
    }
}
