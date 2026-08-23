from __future__ import annotations

import json
import logging
import os
import sys
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI
from opentelemetry import metrics, trace
from opentelemetry._logs import set_logger_provider
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from verigence_security.config import Settings
from verigence_security.core.correlation import correlation_id_ctx

_APP_LOGGER_NAME = "verigence_security"
_HANDLER_MARKER = "_verigence_observability_handler"


class StructuredJsonFormatter(logging.Formatter):
    """Small, privacy-safe formatter for Security application logs.

    It deliberately serializes only the controlled fields supplied by Security plus trace/correlation
    context. Request/response bodies, authentication headers and arbitrary object dictionaries are
    never copied into the event payload.
    """

    def __init__(self, *, service_name: str, service_version: str, environment: str) -> None:
        super().__init__()
        self._service_name = service_name
        self._service_version = service_version
        self._environment = environment

    def format(self, record: logging.LogRecord) -> str:
        span_context = trace.get_current_span().get_span_context()
        payload: dict[str, Any] = {
            "timestamp_utc": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "severity": record.levelname,
            "event_name": getattr(record, "event_name", record.getMessage()),
            "service_name": self._service_name,
            "service_version": self._service_version,
            "environment": self._environment,
        }
        correlation_id = correlation_id_ctx.get()
        if correlation_id:
            payload["correlation_id"] = correlation_id
        if span_context.is_valid:
            payload["trace_id"] = format(span_context.trace_id, "032x")
            payload["span_id"] = format(span_context.span_id, "016x")

        for key in (
            "outcome",
            "failure_stage",
            "error_code",
            "error_category",
            "retryable",
            "http_method",
            "http_route",
            "http_status_code",
            "dependency_name",
            "dependency_type",
        ):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value

        if record.exc_info:
            payload["exception_type"] = record.exc_info[0].__name__ if record.exc_info[0] else "Exception"

        return json.dumps(payload, separators=(",", ":"), default=str)


def attach_trusted_user_id(user_id: str) -> None:
    """Attach an already-authenticated opaque Verigence user ID to the current trace."""

    span = trace.get_current_span()
    if span.is_recording():
        span.set_attribute("verigence.user.id", user_id)


def _service_version() -> str:
    return (
        os.getenv("VERIGENCE_GIT_SHA")
        or os.getenv("RAILWAY_GIT_COMMIT_SHA")
        or os.getenv("VERIGENCE_RELEASE")
        or "unknown"
    )


def _configure_application_logging(settings: Settings, *, logger_provider: LoggerProvider | None) -> None:
    logger = logging.getLogger(_APP_LOGGER_NAME)
    logger.setLevel(settings.log_level.upper())
    logger.propagate = False

    if not any(getattr(handler, _HANDLER_MARKER, False) for handler in logger.handlers):
        stdout_handler = logging.StreamHandler(sys.stdout)
        setattr(stdout_handler, _HANDLER_MARKER, True)
        stdout_handler.setFormatter(
            StructuredJsonFormatter(
                service_name=settings.app_name,
                service_version=_service_version(),
                environment=settings.app_env.value,
            )
        )
        logger.addHandler(stdout_handler)

    if logger_provider is not None and not any(
        isinstance(handler, LoggingHandler) for handler in logger.handlers
    ):
        logger.addHandler(LoggingHandler(level=logging.INFO, logger_provider=logger_provider))


def configure_observability(app: FastAPI, settings: Settings) -> bool:
    """Configure Phase-1 Security telemetry.

    The feature is disabled by default. When enabled, all remote export uses OpenTelemetry batch
    processors/readers. No request handler performs a synchronous telemetry network call or flush.
    Standard OTLP environment variables configure signal-specific endpoints/headers, keeping this
    service vendor-neutral and secrets out of source code.
    """

    if not settings.observability_enabled:
        return False

    resource = Resource.create(
        {
            "service.namespace": "verigence",
            "service.name": settings.app_name,
            "service.version": _service_version(),
            "deployment.environment.name": settings.app_env.value,
        }
    )

    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(
        BatchSpanProcessor(
            OTLPSpanExporter(timeout=settings.observability_export_timeout_seconds),
            max_queue_size=settings.observability_max_queue_size,
            max_export_batch_size=settings.observability_max_export_batch_size,
            schedule_delay_millis=settings.observability_batch_delay_ms,
            export_timeout_millis=int(settings.observability_export_timeout_seconds * 1000),
        )
    )
    trace.set_tracer_provider(tracer_provider)

    metric_reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(timeout=settings.observability_export_timeout_seconds),
        export_interval_millis=settings.observability_metric_export_interval_ms,
        export_timeout_millis=int(settings.observability_export_timeout_seconds * 1000),
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
    metrics.set_meter_provider(meter_provider)

    logger_provider = LoggerProvider(resource=resource)
    logger_provider.add_log_record_processor(
        BatchLogRecordProcessor(
            OTLPLogExporter(timeout=settings.observability_export_timeout_seconds),
            max_queue_size=settings.observability_max_queue_size,
            max_export_batch_size=settings.observability_max_export_batch_size,
            schedule_delay_millis=settings.observability_batch_delay_ms,
            export_timeout_millis=int(settings.observability_export_timeout_seconds * 1000),
        )
    )
    set_logger_provider(logger_provider)
    _configure_application_logging(settings, logger_provider=logger_provider)

    FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=tracer_provider,
        meter_provider=meter_provider,
        excluded_urls="/health/live,/health/ready",
    )
    HTTPXClientInstrumentor().instrument(tracer_provider=tracer_provider, meter_provider=meter_provider)
    return True
