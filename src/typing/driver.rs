//! The typing drivers. Both send once, refresh on the pure schedule, stop when the
//! turn finishes, and never touch the turn's output.
//!
//! Both paths run the typing loop on its OWN detached thread, never in the turn's
//! task: the deployed turn (`handle_activity_for_revision`) and the deployed send
//! (`invoke_provider_for_revision`) each run sync WASM on a joined thread inside ONE
//! poll, so anything sharing a task (or a `select!`) with either is starved until it
//! returns — the e2e run against the first release showed exactly that: one send at
//! +0.02 s and no refresh during a 6–12 s turn. A dedicated thread with std timers is
//! also independent of how many runtime workers there are.
//!
//! Stop rule (both paths): once the turn is done no NEW send starts, and an in-flight
//! send is awaited for at most `STOP_GRACE` before the driver returns — so a refresh
//! cannot land after the reply unless the provider call outlives the grace, in which
//! case it is abandoned (it keeps running detached and may land late).

use std::future::Future;
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError, TryRecvError};
use std::time::Duration;

use tokio::sync::oneshot;

use super::schedule::{Next, SendOutcome, plan_next};
use super::{STOP_GRACE, SendTypingInV1, SendTypingOutV1};

#[async_trait::async_trait]
pub(crate) trait TypingSender: Send + Sync + 'static {
    async fn send_typing(&self, input: &SendTypingInV1) -> anyhow::Result<SendTypingOutV1>;
}

/// Blocking twin of [`TypingSender`]. `'static` because the loop runs it on a
/// DETACHED thread, which is what lets a hung call be abandoned after `STOP_GRACE`.
pub(crate) trait BlockingTypingSender: Send + Sync + 'static {
    fn send_typing(&self, input: &SendTypingInV1) -> anyhow::Result<SendTypingOutV1>;
}

/// Drives an async sender from the typing thread through the caller's runtime handle.
/// The typing thread is not a runtime thread, so `block_on` is allowed there.
struct AsyncBridge {
    sender: Arc<dyn TypingSender>,
    handle: tokio::runtime::Handle,
}

impl BlockingTypingSender for AsyncBridge {
    fn send_typing(&self, input: &SendTypingInV1) -> anyhow::Result<SendTypingOutV1> {
        self.handle.block_on(self.sender.send_typing(input))
    }
}

fn classify(result: anyhow::Result<SendTypingOutV1>, provider: &str) -> SendOutcome {
    match result {
        Ok(out) if out.ok => {
            crate::operator_log::debug(
                module_path!(),
                format!(
                    "send_typing ok provider={provider} refresh_after_ms={:?}",
                    out.refresh_after_ms
                ),
            );
            SendOutcome::Sent {
                refresh_after_ms: out.refresh_after_ms,
            }
        }
        Ok(out) => {
            crate::operator_log::debug(
                module_path!(),
                format!(
                    "send_typing ok=false provider={provider} error={}; not refreshing this turn",
                    out.error.as_deref().unwrap_or("")
                ),
            );
            SendOutcome::Failed
        }
        Err(err) => {
            crate::operator_log::warn(
                module_path!(),
                format!("send_typing failed provider={provider}: {err:#}"),
            );
            SendOutcome::Failed
        }
    }
}

/// A running typing loop. Dropping `stop` is the stop signal; `Done` fires on every
/// exit of the loop thread, panics included.
struct TypingLoop {
    stop: Option<mpsc::Sender<()>>,
    done_sync: mpsc::Receiver<()>,
    done_async: oneshot::Receiver<()>,
    started: bool,
    provider: String,
}

struct Done {
    sync: mpsc::Sender<()>,
    notify: Option<oneshot::Sender<()>>,
}

impl Drop for Done {
    fn drop(&mut self) {
        let _ = self.sync.send(());
        if let Some(notify) = self.notify.take() {
            let _ = notify.send(());
        }
    }
}

fn start_loop(sender: Arc<dyn BlockingTypingSender>, input: SendTypingInV1) -> TypingLoop {
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let (done_sync_tx, done_sync) = mpsc::channel::<()>();
    let (done_async_tx, done_async) = oneshot::channel::<()>();
    let provider = input.provider_type.clone();
    // Keep the caller's span (e.g. `messaging.turn`) on the typing thread's logs.
    let span = tracing::Span::current();
    let spawned = std::thread::Builder::new()
        .name("typing-signal".to_string())
        .spawn(move || {
            let _span = span.enter();
            let _done = Done {
                sync: done_sync_tx,
                notify: Some(done_async_tx),
            };
            let started = std::time::Instant::now();
            loop {
                if matches!(stop_rx.try_recv(), Err(TryRecvError::Disconnected)) {
                    return;
                }
                crate::operator_log::debug(
                    module_path!(),
                    format!(
                        "send_typing sending provider={} at +{}ms",
                        input.provider_type,
                        started.elapsed().as_millis()
                    ),
                );
                let outcome = classify(sender.send_typing(&input), &input.provider_type);
                match plan_next(started.elapsed(), outcome) {
                    Next::Stop(reason) => {
                        tracing::debug!(?reason, "typing signal stopped");
                        return;
                    }
                    Next::Refresh(wait) => match stop_rx.recv_timeout(wait) {
                        Err(RecvTimeoutError::Timeout) => continue,
                        _ => return,
                    },
                }
            }
        });
    if let Err(err) = &spawned {
        crate::operator_log::warn(
            module_path!(),
            format!("typing signal thread could not start provider={provider}: {err}"),
        );
    }
    TypingLoop {
        stop: Some(stop_tx),
        done_sync,
        done_async,
        started: spawned.is_ok(),
        provider,
    }
}

impl TypingLoop {
    fn abandoned(&self, grace: Duration) {
        crate::operator_log::debug(
            module_path!(),
            format!(
                "send_typing still in flight {grace:?} after the turn; abandoned, may land late \
                 provider={}",
                self.provider
            ),
        );
    }

    fn finish_blocking(mut self, grace: Duration) {
        drop(self.stop.take());
        if self.started && self.done_sync.recv_timeout(grace) == Err(RecvTimeoutError::Timeout) {
            self.abandoned(grace);
        }
    }

    async fn finish(mut self, grace: Duration) {
        drop(self.stop.take());
        if self.started
            && tokio::time::timeout(grace, &mut self.done_async)
                .await
                .is_err()
        {
            self.abandoned(grace);
        }
    }
}

/// Async driver (deployed path). The caller awaits `turn` directly; the typing loop
/// runs on its own thread and is stopped (≤ `STOP_GRACE`) before this returns.
pub(crate) async fn keep_typing_while<F: Future>(
    sender: Arc<dyn TypingSender>,
    input: SendTypingInV1,
    turn: F,
) -> F::Output {
    keep_typing_while_with(sender, input, turn, STOP_GRACE).await
}

async fn keep_typing_while_with<F: Future>(
    sender: Arc<dyn TypingSender>,
    input: SendTypingInV1,
    turn: F,
    grace: Duration,
) -> F::Output {
    let bridge = Arc::new(AsyncBridge {
        sender,
        handle: tokio::runtime::Handle::current(),
    });
    let typing = start_loop(bridge, input);
    let output = turn.await;
    typing.finish(grace).await;
    output
}

/// Blocking driver (legacy synchronous path). Same loop; the caller's thread waits at
/// most `STOP_GRACE` for an in-flight send after `turn` returns.
pub(crate) fn keep_typing_blocking<R>(
    sender: Arc<dyn BlockingTypingSender>,
    input: SendTypingInV1,
    turn: impl FnOnce() -> R,
) -> R {
    keep_typing_blocking_with_grace(sender, input, turn, STOP_GRACE)
}

fn keep_typing_blocking_with_grace<R>(
    sender: Arc<dyn BlockingTypingSender>,
    input: SendTypingInV1,
    turn: impl FnOnce() -> R,
    grace: Duration,
) -> R {
    let typing = start_loop(sender, input);
    let out = turn();
    typing.finish_blocking(grace);
    out
}

#[cfg(test)]
#[path = "driver_tests.rs"]
mod tests;
