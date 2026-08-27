from __future__ import annotations

import json
import logging

import pytest
from fastapi import FastAPI
from pydantic import ValidationError

import verigence_security.core.observability as observability
from verigence_security.config import Settings
from verigence_security.core.correlation import correlation_id_ctx
from verigence_security.core.observability import StructuredJsonFormatter, configure_observability
from verigence_security.core.types import AppEnvironment


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "app_env": AppEnvironment.CI,
        "network_risk_mode": "unknown",
        "observability_enabled": False,
    }
    values.update(overrides)
    return Settings(**values)


def test_observability_is_disabled_by_default():
    settings = _settings()
    assert settings.observability_enabled is False


def test_disabled_observability_does_not_modify_application_logger():
    logger = logging.getLogger("verigence_security")
    handlers_before = tuple(logger.handlers)

    enabled = configure_observability(FastAPI(), _settings())

    assert enabled is False
    assert tuple(logger.handlers) == handlers_before


def test_observability_queue_must_bound_export_batch():
    with pytest.raises(ValidationError, match="export batch size cannot exceed queue size"):
        _settings(
            observability_max_queue_size=128,
            observability_max_export_batch_size=129,
        )


def test_structured_formatter_includes_correlation_without_business_values():
    formatter = StructuredJsonFormatter(
        service_name="verigence-security",
        service_version="test-sha",
        environment="ci",
    )
    record = logging.LogRecord(
        name="verigence_security.test",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="authorization_denied",
        args=(),
        exc_info=None,
    )
    record.event_name = "authorization_denied"  # type: ignore[attr-defined]
    record.outcome = "DENIED"  # type: ignore[attr-defined]
    record.error_code = "SEC-RBAC-002"  # type: ignore[attr-defined]

    token = correlation_id_ctx.set("security-observability-test")
    try:
        payload = json.loads(formatter.format(record))
    finally:
        correlation_id_ctx.reset(token)

    assert payload["event_name"] == "authorization_denied"
    assert payload["correlation_id"] == "security-observability-test"
    assert payload["outcome"] == "DENIED"
    assert payload["error_code"] == "SEC-RBAC-002"
    assert "trace_id" not in payload
    assert "span_id" not in payload


def test_structured_formatter_emits_only_safe_uc001_diagnostic_fields():
    formatter = StructuredJsonFormatter(
        service_name="verigence-security",
        service_version="test-sha",
        environment="ci",
    )
    record = logging.LogRecord(
        name="verigence_security.api.routes.global_users",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="uc001_onboarding_clerk_failure",
        args=(),
        exc_info=None,
    )
    record.event_name = "uc001_onboarding_clerk_failure"  # type: ignore[attr-defined]
    record.provider_status_code = 422  # type: ignore[attr-defined]
    record.provider_error_code = "form_param_missing"  # type: ignore[attr-defined]
    record.provider_operation = "Clerk Backend API returned HTTP 422 for POST /users"  # type: ignore[attr-defined]
    record.validation_issues = "header.X-Onboarding-Key:string_too_short"  # type: ignore[attr-defined]
    # Arbitrary log-record data must remain excluded by the formatter allow-list.
    record.password = "NeverLogThisPassword"  # type: ignore[attr-defined]
    record.onboarding_key = "NeverLogThisKey"  # type: ignore[attr-defined]
    record.provider_detail = "NeverLogProviderDetail"  # type: ignore[attr-defined]

    payload = json.loads(formatter.format(record))

    assert payload["provider_status_code"] == 422
    assert payload["provider_error_code"] == "form_param_missing"
    assert payload["provider_operation"] == "Clerk Backend API returned HTTP 422 for POST /users"
    assert payload["validation_issues"] == "header.X-Onboarding-Key:string_too_short"
    assert "password" not in payload
    assert "onboarding_key" not in payload
    assert "provider_detail" not in payload
    serialized = json.dumps(payload)
    assert "NeverLogThisPassword" not in serialized
    assert "NeverLogThisKey" not in serialized
    assert "NeverLogProviderDetail" not in serialized


def test_trusted_user_id_is_added_only_to_recording_trace(monkeypatch: pytest.MonkeyPatch):
    attributes: dict[str, str] = {}

    class RecordingSpan:
        @staticmethod
        def is_recording() -> bool:
            return True

        @staticmethod
        def set_attribute(key: str, value: str) -> None:
            attributes[key] = value

    monkeypatch.setattr(observability.trace, "get_current_span", lambda: RecordingSpan())

    observability.attach_trusted_user_id("00000000-0000-4000-8000-000000000001")

    assert attributes == {
        "verigence.user.id": "00000000-0000-4000-8000-000000000001"
    }
