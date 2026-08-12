from fastapi import FastAPI
from fastapi.testclient import TestClient

from verigence_security.core.correlation import CorrelationIdMiddleware
from verigence_security.core.problem import unexpected_error_handler
from verigence_security.main import app

client = TestClient(app)


def test_health_has_correlation_id():
    response = client.get("/health/live")
    assert response.status_code == 200
    assert "X-Correlation-ID" in response.headers


def test_health_echoes_supplied_correlation_id():
    response = client.get("/health/live", headers={"X-Correlation-ID": "test-123"})
    assert response.headers["X-Correlation-ID"] == "test-123"


def test_invalid_correlation_id_is_rejected_with_traceable_server_id():
    response = client.get("/health/live", headers={"X-Correlation-ID": " bad value "})
    assert response.status_code == 400
    assert response.json()["code"] == "CORRELATION_ID_INVALID"
    assert response.headers["X-Correlation-ID"] == response.json()["correlationId"]
    assert response.headers["X-Correlation-ID"] != " bad value "


def test_unexpected_500_still_returns_correlation_id():
    error_app = FastAPI()
    error_app.add_middleware(CorrelationIdMiddleware)
    error_app.add_exception_handler(Exception, unexpected_error_handler)

    @error_app.get("/boom")
    def boom():
        raise RuntimeError("test failure")

    response = TestClient(error_app, raise_server_exceptions=False).get(
        "/boom",
        headers={"X-Correlation-ID": "end-to-end-500"},
    )
    assert response.status_code == 500
    assert response.headers["X-Correlation-ID"] == "end-to-end-500"


def test_readiness_fails_closed_when_dependencies_are_not_configured():
    response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    assert "X-Correlation-ID" in response.headers
