//! Optional OTLP wire-up used by `init_trace_log` when a bundle's
//! `telemetry:` block (or `TELEMETRY_EXPORT` / `OTLP_ENDPOINT` env vars)
//! requests OpenTelemetry export.
//!
//! Backwards-compatible: callers pass `None` to opt out and behavior is
//! identical to the pre-existing file-appender-only subscriber.

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{
    LogExporter, MetricExporter, Protocol, SpanExporter, WithExportConfig,
};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::metrics::Temporality;
use opentelemetry_sdk::metrics::data::ResourceMetrics;
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tokio::runtime::Handle;

use crate::bundle_config::BundleTelemetryConfig;

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

/// Install the global OTel tracer + meter + logger providers for the given
/// config and return a single combined `tracing-subscriber` layer that fans
/// events to BOTH the span tracer and the OTLP log exporter.
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
) -> Result<Box<dyn tracing_subscriber::Layer<S> + Send + Sync + 'static>>
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

    Ok(tracer_layer.and_then(logger_layer).boxed())
}

struct Providers {
    tracer: SdkTracerProvider,
    logger: SdkLoggerProvider,
}

fn build_providers(
    resolved: &ResolvedTelemetry,
    resource: Resource,
    runtime_handle: Handle,
) -> Result<Providers> {
    let span_exporter: SpanExporter = match resolved.exporter {
        ExporterKind::OtlpGrpc => SpanExporter::builder()
            .with_tonic()
            .with_endpoint(resolved.endpoint.clone())
            .with_protocol(Protocol::Grpc)
            .build()
            .map_err(|e| anyhow!("build OTLP gRPC span exporter: {e}"))?,
        ExporterKind::OtlpHttp => SpanExporter::builder()
            .with_tonic()
            .with_endpoint(resolved.endpoint.clone())
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
            .with_tonic()
            .with_endpoint(resolved.endpoint.clone())
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
            .with_tonic()
            .with_endpoint(resolved.endpoint.clone())
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
    global::set_meter_provider(meter_provider);

    let logger_provider = SdkLoggerProvider::builder()
        .with_resource(resource.clone())
        .with_batch_exporter(log_exporter)
        .build();

    let tracer_provider = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(span_exporter)
        .build();

    Ok(Providers {
        tracer: tracer_provider,
        logger: logger_provider,
    })
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
