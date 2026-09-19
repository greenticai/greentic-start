//! Optional OTLP wire-up used by `init_trace_log` when a bundle's
//! `telemetry:` block (or `TELEMETRY_EXPORT` / `OTLP_ENDPOINT` env vars)
//! requests OpenTelemetry export.
//!
//! Backwards-compatible: callers pass `None` to opt out and behavior is
//! identical to the pre-existing file-appender-only subscriber.

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use opentelemetry::global;
use opentelemetry::logs::Severity;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{LogExporter, MetricExporter, Protocol, SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::logs::LogExporter as SdkLogExporter;
use opentelemetry_sdk::logs::{LogBatch, SdkLoggerProvider};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::metrics::Temporality;
use opentelemetry_sdk::metrics::data::ResourceMetrics;
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::trace::{SdkTracerProvider, SpanData, SpanExporter as SdkSpanExporter};
use tokio::runtime::Handle;

use crate::bundle_config::BundleTelemetryConfig;
use crate::otlp_status::{self, Signal};

/// Resolved telemetry settings after merging bundle.yaml with env-var overrides.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedTelemetry {
    pub exporter: ExporterKind,
    pub endpoint: String,
    pub service_name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExporterKind {
    OtlpGrpc,
    OtlpHttp,
}

/// Merge bundle config + env-var overrides into a `ResolvedTelemetry`.
///
/// Env vars `TELEMETRY_EXPORT` and `OTLP_ENDPOINT` (matching the legacy
/// `apply_otlp_hook` knobs) take precedence over the bundle values so
/// operators can flip exporters without re-running setup. Returns `None`
/// when neither the bundle nor the env vars opt into OTLP.
pub(crate) fn resolve(
    bundle: Option<&BundleTelemetryConfig>,
    fallback_service_name: &str,
) -> Option<ResolvedTelemetry> {
    let env_exporter = std::env::var("TELEMETRY_EXPORT").ok();
    let env_endpoint = std::env::var("OTLP_ENDPOINT")
        .ok()
        .or_else(|| std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok());

    let bundle_enabled = bundle.map(|t| t.enabled).unwrap_or(false);
    let bundle_exporter = bundle.map(|t| t.exporter.as_str()).unwrap_or("none");
    let bundle_endpoint = bundle.and_then(|t| t.endpoint.as_deref());

    let exporter_raw = env_exporter.as_deref().unwrap_or(if bundle_enabled {
        bundle_exporter
    } else {
        "none"
    });
    let exporter = match exporter_raw {
        "otlp-grpc" | "otlp_grpc" | "otlp" => ExporterKind::OtlpGrpc,
        "otlp-http" | "otlp_http" => ExporterKind::OtlpHttp,
        _ => return None,
    };

    let endpoint = env_endpoint
        .or_else(|| bundle_endpoint.map(str::to_string))
        .unwrap_or_else(|| match exporter {
            ExporterKind::OtlpGrpc => "http://localhost:4317".to_string(),
            ExporterKind::OtlpHttp => "http://localhost:4318".to_string(),
        });

    let service_name = bundle
        .and_then(|t| t.service_name.clone())
        .or_else(|| std::env::var("OTEL_SERVICE_NAME").ok())
        .unwrap_or_else(|| fallback_service_name.to_string());

    Some(ResolvedTelemetry {
        exporter,
        endpoint,
        service_name,
    })
}

/// The three OTel provider handles `install_layer` builds, handed back to the
/// caller so it can flush/shut them down on graceful shutdown (Task 3). Each
/// field is a cheap `Arc`-backed clone, and dropping this struct alone never
/// shuts a provider down, because each provider already has a SEPARATE
/// strong reference rooted in something that outlives it:
/// - `tracer`: `install_layer` calls `global::set_tracer_provider(providers.tracer.clone())`
///   before returning — `opentelemetry::global`'s tracer slot is a
///   process-lifetime static, so that clone survives independently of this
///   struct.
/// - `logger`: `OpenTelemetryTracingBridge::new(&providers.logger)` calls
///   `provider.logger("")` internally, which clones the provider into the
///   `SdkLogger` the bridge stores (`SdkLogger::new(scope, self.clone())` in
///   `opentelemetry_sdk`). That bridge is boxed into the layer returned from
///   `install_layer`, which the caller installs as the process's global
///   default `tracing` subscriber — itself a process-lifetime static.
/// - `meter`: cloned into `global::set_meter_provider(meter_provider.clone())`
///   the same way as the tracer, into the same kind of process-lifetime
///   global slot.
///
/// Each provider's `Drop` only runs its real shutdown when the STRONG
/// refcount hits zero (see `TracerProviderInner`/`LoggerProviderInner`/
/// `MeterProviderInner`'s `Drop` impls in `opentelemetry_sdk`), so as long as
/// one of these two references is outstanding, dropping the other is a
/// no-op. That is why flushing on shutdown (`TraceGuard::drop` in `lib.rs`,
/// Task 3) goes through the explicit `shutdown()` method below rather than
/// relying on this struct going out of scope — an explicit
/// `shutdown_with_timeout` call runs regardless of how many clones of a
/// provider are still alive elsewhere.
pub(crate) struct OtlpProviders {
    pub tracer: SdkTracerProvider,
    pub logger: SdkLoggerProvider,
    pub meter: SdkMeterProvider,
}

impl OtlpProviders {
    /// Shuts down all three providers, bounding each to `timeout`. A failure
    /// is logged (redacted) but never propagated — shutdown must not block or
    /// fail process exit.
    pub(crate) fn shutdown(&self, timeout: Duration) {
        if let Err(e) = self.tracer.shutdown_with_timeout(timeout) {
            tracing::warn!(
                "OTLP tracer shutdown error: {}",
                otlp_status::redact(&e.to_string())
            );
        }
        if let Err(e) = self.logger.shutdown_with_timeout(timeout) {
            tracing::warn!(
                "OTLP logger shutdown error: {}",
                otlp_status::redact(&e.to_string())
            );
        }
        if let Err(e) = self.meter.shutdown_with_timeout(timeout) {
            tracing::warn!(
                "OTLP meter shutdown error: {}",
                otlp_status::redact(&e.to_string())
            );
        }
    }
}

/// Install the global OTel tracer + meter + logger providers for the given
/// config and return a combined `tracing-subscriber` layer that fans events
/// to BOTH the span tracer and the OTLP log exporter, plus the provider
/// handles themselves so the caller can flush/shut them down later.
///
/// Tonic transports require a running Tokio runtime; this function spins up a
/// dedicated multi-thread runtime when none is current and intentionally leaks
/// it so the batch span/log exporters keep draining for the process lifetime.
///
/// The metric exporter is wrapped in [`TokioMetricExporter`] so the periodic
/// reader (which runs on its own `std::thread` and drives exports via
/// `futures_executor::block_on` — without any Tokio runtime in scope) can
/// reach the tonic client via a captured runtime handle.
pub(crate) fn install_layer<S>(
    resolved: &ResolvedTelemetry,
) -> Result<(
    Box<dyn tracing_subscriber::Layer<S> + Send + Sync + 'static>,
    OtlpProviders,
)>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a> + Send + Sync,
{
    use tracing_subscriber::Layer;

    let resource = Resource::builder()
        .with_service_name(resolved.service_name.clone())
        .build();

    let providers = if let Ok(handle) = Handle::try_current() {
        build_providers(resolved, resource, handle)?
    } else {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .context("failed to build tokio runtime for OTLP exporter")?;
        let handle = rt.handle().clone();
        let providers = {
            let _enter = rt.enter();
            build_providers(resolved, resource, handle)?
        };
        std::mem::forget(rt);
        providers
    };

    global::set_tracer_provider(providers.tracer.clone());
    let tracer = providers.tracer.tracer("greentic-start");
    let tracer_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let logger_layer = OpenTelemetryTracingBridge::new(&providers.logger);

    Ok((tracer_layer.and_then(logger_layer).boxed(), providers))
}

/// The three OTLP/HTTP default per-signal paths, per the OTLP/HTTP spec.
/// `signal_endpoint` strips exactly one of these from the end of a
/// configured base URL before re-appending the requested signal's path, so
/// that pointing `OTLP_ENDPOINT` at the DEFAULT traces path (the shape
/// `OTEL_EXPORTER_OTLP_ENDPOINT` is commonly copy-pasted with) does not
/// leave logs/metrics exports carrying `/v1/traces` too.
const SIGNAL_PATH_SUFFIXES: [&str; 3] = ["/v1/traces", "/v1/logs", "/v1/metrics"];

/// Rewrites a base OTLP/HTTP endpoint to carry the requested signal's path.
///
/// gRPC endpoints are returned unchanged: gRPC has no per-signal path, only
/// a service/method on the one channel.
///
/// For OtlpHttp: the base is trimmed of a trailing `/`, then — if what
/// remains ends with one of [`SIGNAL_PATH_SUFFIXES`] (any of the three, not
/// just the one being requested) — that suffix is stripped to recover the
/// collector's true root before `path` is appended. A base with no matching
/// suffix (root, or an operator's own custom sub-path such as `/otlp`) is
/// kept as-is and `path` is simply appended to it. This mirrors the OTel
/// base-endpoint convention: `http://c:4318` and `http://c:4318/custom/v1/traces`
/// both normalise to a root the requested signal path can be appended to,
/// the former trivially (nothing to strip) and the latter by first removing
/// the default traces suffix it happens to carry.
fn signal_endpoint(base: &str, exporter: ExporterKind, path: &str) -> String {
    if exporter != ExporterKind::OtlpHttp {
        return base.to_string();
    }
    let trimmed = base.trim_end_matches('/');
    let root = SIGNAL_PATH_SUFFIXES
        .iter()
        .find_map(|suffix| trimmed.strip_suffix(suffix))
        .unwrap_or(trimmed);
    format!("{root}{path}")
}

fn build_providers(
    resolved: &ResolvedTelemetry,
    resource: Resource,
    runtime_handle: Handle,
) -> Result<OtlpProviders> {
    let span_exporter: SpanExporter = match resolved.exporter {
        ExporterKind::OtlpGrpc => SpanExporter::builder()
            .with_tonic()
            .with_endpoint(resolved.endpoint.clone())
            .with_protocol(Protocol::Grpc)
            .build()
            .map_err(|e| anyhow!("build OTLP gRPC span exporter: {e}"))?,
        ExporterKind::OtlpHttp => SpanExporter::builder()
            .with_http()
            .with_endpoint(signal_endpoint(
                &resolved.endpoint,
                ExporterKind::OtlpHttp,
                "/v1/traces",
            ))
            .with_protocol(Protocol::HttpBinary)
            .build()
            .map_err(|e| anyhow!("build OTLP HTTP span exporter: {e}"))?,
    };

    let metric_exporter: MetricExporter = match resolved.exporter {
        ExporterKind::OtlpGrpc => MetricExporter::builder()
            .with_tonic()
            .with_endpoint(resolved.endpoint.clone())
            .with_protocol(Protocol::Grpc)
            .build()
            .map_err(|e| anyhow!("build OTLP gRPC metric exporter: {e}"))?,
        ExporterKind::OtlpHttp => MetricExporter::builder()
            .with_http()
            .with_endpoint(signal_endpoint(
                &resolved.endpoint,
                ExporterKind::OtlpHttp,
                "/v1/metrics",
            ))
            .with_protocol(Protocol::HttpBinary)
            .build()
            .map_err(|e| anyhow!("build OTLP HTTP metric exporter: {e}"))?,
    };

    let log_exporter: LogExporter = match resolved.exporter {
        ExporterKind::OtlpGrpc => LogExporter::builder()
            .with_tonic()
            .with_endpoint(resolved.endpoint.clone())
            .with_protocol(Protocol::Grpc)
            .build()
            .map_err(|e| anyhow!("build OTLP gRPC log exporter: {e}"))?,
        ExporterKind::OtlpHttp => LogExporter::builder()
            .with_http()
            .with_endpoint(signal_endpoint(
                &resolved.endpoint,
                ExporterKind::OtlpHttp,
                "/v1/logs",
            ))
            .with_protocol(Protocol::HttpBinary)
            .build()
            .map_err(|e| anyhow!("build OTLP HTTP log exporter: {e}"))?,
    };

    let wrapped_metric_exporter = TokioMetricExporter {
        inner: metric_exporter,
        // Only gRPC (tonic) needs the captured runtime entered for it — see
        // the doc comment on `TokioMetricExporter` for why the HTTP exporter
        // must never be driven from inside a Tokio runtime context.
        runtime: match resolved.exporter {
            ExporterKind::OtlpGrpc => Some(runtime_handle),
            ExporterKind::OtlpHttp => None,
        },
    };

    let meter_provider = SdkMeterProvider::builder()
        .with_resource(resource.clone())
        .with_periodic_exporter(wrapped_metric_exporter)
        .build();
    global::set_meter_provider(meter_provider.clone());

    let logger_provider = SdkLoggerProvider::builder()
        .with_resource(resource.clone())
        .with_batch_exporter(RecordingLogExporter {
            inner: log_exporter,
        })
        .build();

    let tracer_provider = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(RecordingSpanExporter {
            inner: span_exporter,
        })
        .build();

    Ok(OtlpProviders {
        tracer: tracer_provider,
        logger: logger_provider,
        meter: meter_provider,
    })
}

/// Wraps a `SpanExporter` so every `export` outcome is stamped into
/// `otlp_status` (spec §3.4) — forwards every other trait method unchanged,
/// `set_resource` included (dropping that would silently lose
/// `service.name` and friends on the wrapped exporter).
#[derive(Debug)]
struct RecordingSpanExporter<E> {
    inner: E,
}

impl<E: SdkSpanExporter> SdkSpanExporter for RecordingSpanExporter<E> {
    fn export(
        &self,
        batch: Vec<SpanData>,
    ) -> impl std::future::Future<Output = OTelSdkResult> + Send {
        let fut = self.inner.export(batch);
        async move {
            let r = fut.await;
            otlp_status::record_export(
                Signal::Traces,
                r.as_ref().map(|_| ()).map_err(|e| e.to_string()),
            );
            r
        }
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }

    fn shutdown(&self) -> OTelSdkResult {
        self.inner.shutdown()
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}

/// Wraps a `LogExporter` so every `export` outcome is stamped into
/// `otlp_status` (spec §3.4) — forwards every other trait method unchanged,
/// `event_enabled` and `set_resource` included.
#[derive(Debug)]
struct RecordingLogExporter<E> {
    inner: E,
}

impl<E: SdkLogExporter> SdkLogExporter for RecordingLogExporter<E> {
    fn export(
        &self,
        batch: LogBatch<'_>,
    ) -> impl std::future::Future<Output = OTelSdkResult> + Send {
        let fut = self.inner.export(batch);
        async move {
            let r = fut.await;
            otlp_status::record_export(
                Signal::Logs,
                r.as_ref().map(|_| ()).map_err(|e| e.to_string()),
            );
            r
        }
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }

    fn shutdown(&self) -> OTelSdkResult {
        self.inner.shutdown()
    }

    fn event_enabled(&self, level: Severity, target: &str, name: Option<&str>) -> bool {
        self.inner.event_enabled(level, target, name)
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}

/// Wraps an OTLP `MetricExporter` so gRPC (tonic) can be driven from the
/// `PeriodicReader` background `std::thread` (which has no Tokio runtime
/// scope) by entering a captured runtime handle on every export.
///
/// `runtime` is `Some` for gRPC and `None` for HTTP — HTTP must NOT be
/// entered into any Tokio runtime, captured or ambient. The HTTP exporter
/// (built with `.with_http()` / the `reqwest-blocking-client` feature)
/// delegates to `reqwest::blocking::Client::send_bytes`, which is `async fn`
/// in name only: its body calls the genuinely-blocking `Client::execute`
/// directly, and that call's internal wait (`reqwest`'s
/// `blocking::wait::enter()`) does a debug-only sanity check — "are we
/// already inside a Tokio runtime?" — by building and dropping a throwaway
/// `current_thread` runtime. If the calling thread already HAS a runtime
/// entered (which `Handle::block_on` does, for the duration of the call),
/// that throwaway runtime's drop panics with "Cannot drop a runtime in a
/// context where blocking is not allowed". Driving the HTTP exporter WITHOUT
/// entering any runtime first (i.e. straight off the `PeriodicReader`'s bare
/// background thread, exactly as `futures_executor::block_on` does) avoids
/// the nested-runtime condition entirely, since `reqwest`'s sanity check then
/// finds no runtime to conflict with.
#[derive(Debug)]
struct TokioMetricExporter {
    inner: MetricExporter,
    runtime: Option<Handle>,
}

impl PushMetricExporter for TokioMetricExporter {
    fn export(
        &self,
        metrics: &ResourceMetrics,
    ) -> impl std::future::Future<Output = OTelSdkResult> + Send {
        let runtime = self.runtime.clone();
        Box::pin(async move {
            let result = match runtime {
                Some(handle) => handle.block_on(self.inner.export(metrics)),
                None => self.inner.export(metrics).await,
            };
            otlp_status::record_export(
                Signal::Metrics,
                result.as_ref().map(|_| ()).map_err(|e| e.to_string()),
            );
            result
        })
    }

    fn force_flush(&self) -> OTelSdkResult {
        match &self.runtime {
            Some(handle) => handle.block_on(async { self.inner.force_flush() }),
            None => self.inner.force_flush(),
        }
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        match &self.runtime {
            Some(handle) => handle.block_on(async { self.inner.shutdown_with_timeout(timeout) }),
            None => self.inner.shutdown_with_timeout(timeout),
        }
    }

    fn temporality(&self) -> Temporality {
        self.inner.temporality()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    struct EnvGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            unsafe {
                std::env::remove_var(key);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.previous {
                    Some(value) => std::env::set_var(self.key, value),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    fn clear_env() -> Vec<EnvGuard> {
        vec![
            EnvGuard::remove("TELEMETRY_EXPORT"),
            EnvGuard::remove("OTLP_ENDPOINT"),
            EnvGuard::remove("OTEL_EXPORTER_OTLP_ENDPOINT"),
            EnvGuard::remove("OTEL_SERVICE_NAME"),
        ]
    }

    #[test]
    fn resolve_returns_none_without_opt_in() {
        let _lock = env_lock();
        let _env = clear_env();
        assert!(resolve(None, "fallback-service").is_none());
        assert!(
            resolve(
                Some(&BundleTelemetryConfig {
                    enabled: false,
                    exporter: "otlp-grpc".to_string(),
                    ..Default::default()
                }),
                "fallback-service"
            )
            .is_none()
        );
    }

    #[test]
    fn resolve_uses_bundle_grpc_defaults() {
        let _lock = env_lock();
        let _env = clear_env();
        let resolved = resolve(
            Some(&BundleTelemetryConfig {
                enabled: true,
                exporter: "otlp".to_string(),
                service_name: Some("bundle-service".to_string()),
                ..Default::default()
            }),
            "fallback-service",
        )
        .expect("resolved telemetry");

        assert_eq!(resolved.exporter, ExporterKind::OtlpGrpc);
        assert_eq!(resolved.endpoint, "http://localhost:4317");
        assert_eq!(resolved.service_name, "bundle-service");
    }

    #[test]
    fn resolve_uses_env_overrides_and_http_default() {
        let _lock = env_lock();
        let _env = clear_env();
        let _export = EnvGuard::set("TELEMETRY_EXPORT", "otlp-http");
        let _service = EnvGuard::set("OTEL_SERVICE_NAME", "env-service");

        let resolved = resolve(None, "fallback-service").expect("env opt-in");
        assert_eq!(resolved.exporter, ExporterKind::OtlpHttp);
        assert_eq!(resolved.endpoint, "http://localhost:4318");
        assert_eq!(resolved.service_name, "env-service");
    }

    #[test]
    fn resolve_prefers_env_endpoint_over_bundle_endpoint() {
        let _lock = env_lock();
        let _env = clear_env();
        let _endpoint = EnvGuard::set("OTLP_ENDPOINT", "http://collector:9999");

        let resolved = resolve(
            Some(&BundleTelemetryConfig {
                enabled: true,
                exporter: "otlp-grpc".to_string(),
                endpoint: Some("http://bundle:4317".to_string()),
                ..Default::default()
            }),
            "fallback-service",
        )
        .expect("resolved telemetry");

        assert_eq!(resolved.endpoint, "http://collector:9999");
    }

    #[test]
    fn http_endpoints_get_per_signal_paths_grpc_does_not() {
        assert_eq!(
            signal_endpoint("http://c:4318", ExporterKind::OtlpHttp, "/v1/traces"),
            "http://c:4318/v1/traces"
        );
        assert_eq!(
            signal_endpoint("http://c:4318/", ExporterKind::OtlpHttp, "/v1/logs"),
            "http://c:4318/v1/logs"
        );
        assert_eq!(
            signal_endpoint(
                "http://c:4318/custom/v1/traces",
                ExporterKind::OtlpHttp,
                "/v1/traces"
            ),
            "http://c:4318/custom/v1/traces"
        );
        assert_eq!(
            signal_endpoint("http://c:4317", ExporterKind::OtlpGrpc, "/v1/traces"),
            "http://c:4317"
        );
        // A custom collector path with no default per-signal suffix is kept
        // and the requested signal path appended to it verbatim.
        assert_eq!(
            signal_endpoint(
                "https://gw.example/otlp",
                ExporterKind::OtlpHttp,
                "/v1/traces"
            ),
            "https://gw.example/otlp/v1/traces"
        );
        // A base already carrying a DIFFERENT signal's default suffix has
        // that suffix stripped before the requested one is appended, so a
        // generic `OTLP_ENDPOINT` copy-pasted with the traces path does not
        // leak into a logs export.
        assert_eq!(
            signal_endpoint(
                "http://c:4318/custom/v1/traces",
                ExporterKind::OtlpHttp,
                "/v1/logs"
            ),
            "http://c:4318/custom/v1/logs"
        );
    }

    /// Drives a future to completion on the CURRENT thread with no ambient
    /// Tokio runtime whatsoever — deliberately not `#[tokio::test]` (which
    /// would itself enter a runtime on this thread) and not
    /// `Handle::block_on` (same reason). This is what lets
    /// `http_metric_export_never_panics_and_records_an_error` faithfully
    /// reproduce the real `PeriodicReader` calling context (its own bare
    /// `std::thread`, driven via `futures_executor::block_on` — see the
    /// `TokioMetricExporter` doc comment) instead of accidentally recreating
    /// the very nested-runtime precondition the fix removes.
    fn poll_to_completion<F: std::future::Future>(fut: F) -> F::Output {
        let mut fut = std::pin::pin!(fut);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        loop {
            match fut.as_mut().poll(&mut cx) {
                std::task::Poll::Ready(v) => return v,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn the_recording_span_exporter_stamps_ok_and_errors() {
        use opentelemetry_sdk::trace::{InMemorySpanExporter, SpanExporter as _};
        // Held across the whole export+snapshot: this is a plain sync #[test]
        // (no `.await` in this function), so clippy::await_holding_lock does
        // not apply, and `otlp_status`'s state can't be touched by a
        // concurrently-running test in either file while this runs.
        let _lock = crate::otlp_status::test_lock();
        crate::otlp_status::reset_for_test();
        let rec = RecordingSpanExporter {
            inner: InMemorySpanExporter::default(),
        };
        poll_to_completion(rec.export(vec![])).unwrap();
        let s = crate::otlp_status::snapshot_json();
        assert!(s["signals"]["traces"]["last_ok_at"].is_string());
    }

    #[test]
    fn http_metric_export_never_panics_and_records_an_error() {
        let _lock = crate::otlp_status::test_lock();
        crate::otlp_status::reset_for_test();

        // Bind an ephemeral port, then drop the listener so nothing answers
        // there — a reliable, fast connection-refused without depending on
        // network access or a fixed "probably free" port number.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = listener.local_addr().expect("read local addr");
        drop(listener);

        let dead_endpoint = signal_endpoint(
            &format!("http://{addr}"),
            ExporterKind::OtlpHttp,
            "/v1/metrics",
        );
        let metric_exporter = MetricExporter::builder()
            .with_http()
            .with_endpoint(dead_endpoint)
            .with_protocol(Protocol::HttpBinary)
            .build()
            .expect("build http metric exporter");

        let wrapped = TokioMetricExporter {
            inner: metric_exporter,
            runtime: None,
        };

        let metrics = ResourceMetrics::default();
        // Pre-fix, driving the OtlpHttp-built exporter through a captured
        // runtime handle here panicked under debug_assertions (nested Tokio
        // runtime — see the `TokioMetricExporter` doc comment). This must
        // not panic, and the refused connection must surface as a recorded
        // error rather than silently vanishing.
        let _ = poll_to_completion(wrapped.export(&metrics));

        let s = crate::otlp_status::snapshot_json();
        assert!(s["signals"]["metrics"]["last_error_at"].is_string());
    }
}
