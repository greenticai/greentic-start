//! Mirror `tracing` WARN/ERROR events to stderr in a container.
//!
//! `init_trace_log` writes the tracing subscriber to `system.log` and, when
//! configured, to OTLP. In a container neither is readable: Cloud Run and
//! `kubectl logs` collect stdout/stderr only, and `system.log` lives on the
//! container's own filesystem, gone when the instance scales to zero. So a
//! `tracing::warn!` from an embedded crate never surfaced anywhere an operator
//! could look — most visibly greentic-runner-host's `DwAgent step failed`,
//! which carries the ONLY record of why an agent answered the fixed
//! "Something went wrong. Please try again." reply.
//!
//! The layer follows `operator_log`'s rule for when to mirror (stderr is not a
//! terminal), so an interactive session keeps a quiet terminal exactly as
//! before. It passes WARN and ERROR only: the file keeps every level, and the
//! container log gains the failures without the per-request INFO volume.
//! Records forwarded from `operator_log` are dropped here because
//! `operator_log` already mirrors them to stderr itself.

use tracing::{Level, Metadata};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::FilterFn;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::registry::LookupSpan;

use crate::operator_log::OTLP_BRIDGE_TARGET;

/// Whether an event is mirrored to stderr: WARN or ERROR, and not an
/// `operator_log` record (those reach stderr through `operator_log`).
fn reaches_stderr(meta: &Metadata<'_>) -> bool {
    // `tracing` orders levels by verbosity, so `<= WARN` is WARN or ERROR.
    *meta.level() <= Level::WARN && meta.target() != OTLP_BRIDGE_TARGET
}

/// The stderr layer, or `None` when stderr is a terminal.
pub(crate) fn layer<S>() -> Option<impl Layer<S>>
where
    S: tracing::Subscriber + for<'span> LookupSpan<'span>,
{
    crate::operator_log::mirror_to_stderr().then(|| layer_to(std::io::stderr))
}

/// The layer itself, over any writer, so the filter can be tested without
/// capturing the process's real stderr.
fn layer_to<S, W>(writer: W) -> impl Layer<S>
where
    S: tracing::Subscriber + for<'span> LookupSpan<'span>,
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .with_ansi(false)
        .with_target(true)
        .with_filter(FilterFn::new(reaches_stderr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Captured {
        fn text(&self) -> String {
            let bytes = self.0.lock().map(|b| b.clone()).unwrap_or_default();
            String::from_utf8_lossy(&bytes).into_owned()
        }
    }

    impl io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if let Ok(mut inner) = self.0.lock() {
                inner.extend_from_slice(buf);
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn capture(emit: impl FnOnce()) -> String {
        let out = Captured::default();
        let subscriber = tracing_subscriber::registry().with(layer_to(out.clone()));
        tracing::subscriber::with_default(subscriber, emit);
        out.text()
    }

    #[test]
    fn a_failed_agent_step_reaches_stderr_with_its_cause() {
        let text = capture(|| {
            tracing::warn!(
                target: "greentic_runner_host::runner::agent_node",
                error = "config error: agent_id helpdesk not found for tenant",
                "DwAgent step failed"
            );
        });
        assert!(text.contains("DwAgent step failed"), "{text}");
        assert!(text.contains("agent_id helpdesk not found"), "{text}");
    }

    #[test]
    fn errors_pass_and_info_and_debug_do_not() {
        let text = capture(|| {
            tracing::error!("an error line");
            tracing::info!("an info line");
            tracing::debug!("a debug line");
        });
        assert!(text.contains("an error line"), "{text}");
        assert!(!text.contains("an info line"), "{text}");
        assert!(!text.contains("a debug line"), "{text}");
    }

    #[test]
    fn operator_log_records_are_not_printed_twice() {
        let text = capture(|| {
            tracing::warn!(target: "greentic.operator", "already mirrored by operator_log");
        });
        assert!(text.is_empty(), "{text}");
    }
}
