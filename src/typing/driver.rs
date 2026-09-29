//! The two typing drivers. Both send once, refresh on the pure schedule, stop when the
//! turn finishes, and never touch the turn's output.
//!
//! Stop rule (both paths): once the turn is done no NEW send starts, and an in-flight
//! send is awaited for at most `STOP_GRACE` before the driver returns — so a refresh
//! cannot land after the reply unless the provider call outlives the grace, in which
//! case it is abandoned and logged.

use std::future::Future;
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError, TryRecvError};
use std::time::Duration;

use tokio::sync::watch;

use super::schedule::{Next, SendOutcome, plan_next};
use super::{STOP_GRACE, SendTypingInV1, SendTypingOutV1};

#[async_trait::async_trait]
pub(crate) trait TypingSender: Send + Sync {
    async fn send_typing(&self, input: &SendTypingInV1) -> anyhow::Result<SendTypingOutV1>;
}

/// Blocking twin of [`TypingSender`]. `'static` because the legacy driver runs it on a
/// DETACHED thread, which is what lets it abandon a hung call after `STOP_GRACE`.
pub(crate) trait BlockingTypingSender: Send + Sync + 'static {
    fn send_typing(&self, input: &SendTypingInV1) -> anyhow::Result<SendTypingOutV1>;
}

fn classify(result: anyhow::Result<SendTypingOutV1>, provider: &str) -> SendOutcome {
    match result {
        Ok(out) if out.ok => SendOutcome::Sent {
            refresh_after_ms: out.refresh_after_ms,
        },
        Ok(out) => {
            tracing::debug!(
                provider,
                error = out.error.as_deref().unwrap_or(""),
                "send_typing returned ok=false; not refreshing this turn"
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

async fn drive(sender: &dyn TypingSender, input: &SendTypingInV1, mut stop: watch::Receiver<bool>) {
    let started = tokio::time::Instant::now();
    loop {
        if *stop.borrow() {
            return;
        }
        // Deliberately NOT raced against `stop`: an in-flight send completes (or is
        // dropped by the caller's STOP_GRACE timeout), so it cannot land after the reply.
        let outcome = classify(sender.send_typing(input).await, &input.provider_type);
        match plan_next(started.elapsed(), outcome) {
            Next::Stop(reason) => {
                tracing::debug!(?reason, "typing signal stopped");
                return;
            }
            Next::Refresh(wait) => tokio::select! {
                () = tokio::time::sleep(wait) => {}
                _ = stop.changed() => return,
            },
        }
    }
}

/// Runs `turn` and the typing loop in the CALLER's task (no spawn, so no `'static`
/// bound and the caller's span is kept). Returns the turn's output untouched.
pub(crate) async fn keep_typing_while<F: Future>(
    sender: &dyn TypingSender,
    input: &SendTypingInV1,
    turn: F,
) -> F::Output {
    let (stop_tx, stop_rx) = watch::channel(false);
    let typing = drive(sender, input, stop_rx);
    tokio::pin!(turn);
    tokio::pin!(typing);
    let mut typing_done = false;
    let output = loop {
        tokio::select! {
            out = &mut turn => break out,
            () = &mut typing, if !typing_done => typing_done = true,
        }
    };
    if !typing_done {
        let _ = stop_tx.send(true);
        if tokio::time::timeout(STOP_GRACE, &mut typing).await.is_err() {
            crate::operator_log::warn(
                module_path!(),
                format!(
                    "send_typing still in flight {STOP_GRACE:?} after the turn; abandoned provider={}",
                    input.provider_type
                ),
            );
        }
    }
    output
}

/// Blocking driver for the legacy (synchronous) ingress path. The typing loop runs on
/// a detached thread; when `turn` returns the stop channel is dropped and the caller
/// waits at most `STOP_GRACE` for the thread to finish its in-flight send. A hung
/// provider call is abandoned after the grace (the thread exits on its own once the
/// call returns, sending nothing more).
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
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let provider = input.provider_type.clone();
    let spawned = std::thread::Builder::new()
        .name("typing-signal".to_string())
        .spawn(move || {
            // Signals the waiter on every exit path, panics included.
            struct Done(mpsc::Sender<()>);
            impl Drop for Done {
                fn drop(&mut self) {
                    let _ = self.0.send(());
                }
            }
            let _done = Done(done_tx);
            let started = std::time::Instant::now();
            loop {
                if matches!(stop_rx.try_recv(), Err(TryRecvError::Disconnected)) {
                    return;
                }
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
    let out = turn();
    drop(stop_tx);
    if spawned.is_ok() && done_rx.recv_timeout(grace) == Err(RecvTimeoutError::Timeout) {
        crate::operator_log::warn(
            module_path!(),
            format!(
                "send_typing still in flight {grace:?} after the turn; abandoned provider={provider}"
            ),
        );
    }
    out
}

#[cfg(test)]
#[path = "driver_tests.rs"]
mod tests;
