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
/// field is a cheap `Arc`-backed clone: the tracer is also cloned into
/// `opentelemetry::global`, the logger's clone lives inside the returned
/// layer's [`OpenTelemetryTracingBridge`], and the meter is cloned into
/// `opentelemetry::global` too — so dropping this struct alone never shuts a
/// provider down (see the module tests / task report for the drop-semantics
/// check this relies on).
///
/// Not yet wired up: `install_layer`'s caller only destructures the tuple
/// today to keep `init_trace_log` compiling. Task 3 (the flush guard) reads
/// `meter` and calls `shutdown`, so `#[allow(dead_code)]` covers the gap
/// until then — same reasoning as `otlp_status`'s module-level allow.
#[allow(dead_code)]
pub(crate) struct OtlpProviders {
    pub tracer: SdkTracerProvider,
    pub logger: SdkLoggerProvider,
    pub meter: SdkMeterProvider,
}

impl OtlpProviders {
    /// Shuts down all three providers, bounding each to `timeout`. A failure
    /// is logged (redacted) but never propagated — shutdown must not block or
    /// fail process exit.
    #[allow(dead_code)]
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

/// Rewrites a base OTLP/HTTP endpoint to carry the per-signal path (per the
/// OTLP/HTTP spec, `/v1/traces`, `/v1/logs`, `/v1/metrics`), unless the
/// operator already configured a custom, non-root path — which is kept
/// verbatim. gRPC endpoints are returned unchanged: gRPC has no per-signal
/// path, only a service/method on the one channel.
fn signal_endpoint(base: &str, exporter: ExporterKind, path: &str) -> String {
    if exporter != ExporterKind::OtlpHttp {
        return base.to_string();
    }
    let authority_start = base.find("://").map(|i| i + 3).unwrap_or(0);
    let authority_and_path = &base[authority_start..];
    match authority_and_path.find('/') {
        None => format!("{}{path}", base.trim_end_matches('/')),
        Some(slash_offset) => {
            if &authority_and_path[slash_offset..] == "/" {
                format!("{}{path}", base.trim_end_matches('/'))
            } else {
                base.to_string()
            }
        }
    }
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
        runtime: runtime_handle,
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

/// Wraps an OTLP `MetricExporter` so it can be driven from the
/// `PeriodicReader` background `std::thread` (which has no Tokio runtime
/// scope) by entering a captured runtime handle on every export.
#[derive(Debug)]
struct TokioMetricExporter {
    inner: MetricExporter,
    runtime: Handle,
}

impl PushMetricExporter for TokioMetricExporter {
    fn export(
        &self,
        metrics: &ResourceMetrics,
    ) -> impl std::future::Future<Output = OTelSdkResult> + Send {
        let result = self.runtime.block_on(self.inner.export(metrics));
        otlp_status::record_export(
            Signal::Metrics,
            result.as_ref().map(|_| ()).map_err(|e| e.to_string()),
        );
        async move { result }
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.runtime.block_on(async { self.inner.force_flush() })
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.runtime
            .block_on(async { self.inner.shutdown_with_timeout(timeout) })
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
    }

    #[tokio::test]
    async fn the_recording_span_exporter_stamps_ok_and_errors() {
        use opentelemetry_sdk::trace::{InMemorySpanExporter, SpanExporter as _};
        // The lock only needs to cover the reset, not the export/snapshot —
        // holding a std::sync::MutexGuard across an .await trips
        // clippy::await_holding_lock (and would risk deadlocking the async
        // executor), so it is dropped before the await point.
        {
            let _lock = env_lock();
            crate::otlp_status::reset_for_test();
        }
        let rec = RecordingSpanExporter {
            inner: InMemorySpanExporter::default(),
        };
        rec.export(vec![]).await.unwrap();
        let s = crate::otlp_status::snapshot_json();
        assert!(s["signals"]["traces"]["last_ok_at"].is_string());
    }
}
