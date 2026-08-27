import logging

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field
from starlette.requests import Request

from verigence_security.adapters.clerk_backend import ClerkBackendError
from verigence_security.api.routes.global_users import _log_onboarding_clerk_failure
from verigence_security.core.correlation import CorrelationIdMiddleware
from verigence_security.core.problem import request_validation_error_handler


class DiagnosticBody(BaseModel):
    password: str = Field(max_length=3)


def test_request_validation_log_records_field_and_type_without_request_value(caplog):
    app = FastAPI()
    app.add_middleware(CorrelationIdMiddleware)
    app.add_exception_handler(RequestValidationError, request_validation_error_handler)

    @app.post("/validate")
    def validate(body: DiagnosticBody) -> dict[str, bool]:
        _ = body
        return {"ok": True}

    with caplog.at_level(logging.WARNING, logger="verigence_security.core.problem"):
        response = TestClient(app).post(
            "/validate",
            json={"password": "do-not-log-this-secret"},
            headers={"X-Correlation-ID": "uc001-validation-diag"},
        )

    assert response.status_code == 422
    assert response.headers["X-Correlation-ID"] == "uc001-validation-diag"
    assert "security_request_validation_failed" in caplog.text
    assert "body.password:string_too_long" in caplog.text
    assert "do-not-log-this-secret" not in caplog.text


def test_clerk_onboarding_log_records_code_status_and_operation_without_provider_detail(caplog):
    request = Request({"type": "http", "method": "POST", "path": "/security/v1/onboarding/users"})
    request.state.correlation_id = "uc001-clerk-diag"
    exc = ClerkBackendError(
        "Clerk Backend API returned HTTP 422 for POST /users",
        status_code=422,
        provider_code="form_param_invalid",
        provider_detail="sensitive@example.com must not appear in logs",
    )

    with caplog.at_level(logging.WARNING, logger="verigence_security.api.routes.global_users"):
        _log_onboarding_clerk_failure(request, exc)

    assert "uc001_onboarding_clerk_failure" in caplog.text
    assert "provider_status=422" in caplog.text
    assert "provider_code=form_param_invalid" in caplog.text
    assert "POST /users" in caplog.text
    assert "sensitive@example.com" not in caplog.text
