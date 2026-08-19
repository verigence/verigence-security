from __future__ import annotations

from fastapi.testclient import TestClient

from verigence_security.main import app

client = TestClient(app)


def test_legacy_human_and_oauth_token_routes_are_not_active() -> None:
    assert client.post("/oauth/token").status_code == 404
    assert client.post("/security/v1/auth/login", json={}).status_code == 404
    assert client.post("/security/v1/access-sessions", json={}).status_code == 404
    assert client.post("/security/v1/platform/auth/login", json={}).status_code == 404
    assert client.post("/security/v1/platform/bootstrap/claim", json={}).status_code == 404
    assert client.get("/security/v1/platform/me").status_code == 404
