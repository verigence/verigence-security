from __future__ import annotations

import hashlib
import json
from dataclasses import replace

from fastapi.testclient import TestClient

from verigence_security.app import ACCESS_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT, create_app
from verigence_security.settings import Settings


def test_from_env_accepts_hashed_confidential_client(monkeypatch, settings):
    verifier = hashlib.sha256(b"managed-client-secret").hexdigest()
    monkeypatch.setenv("SECURITY_JWT_PRIVATE_KEY_PEM", settings.private_key_pem)
    monkeypatch.setenv(
        "SECURITY_INTEGRATION_CLIENTS_JSON",
        json.dumps(
            {
                "audit-core": {
                    "secret_sha256": verifier,
                    "permissions": ["di.document.read", "di.document.upload"],
                    "public": False,
                }
            }
        ),
    )

    resolved = Settings.from_env()
    client = resolved.integration_clients["audit-core"]

    assert client.secret == ""
    assert client.secret_sha256 == verifier
    assert client.permissions == frozenset({"di.document.read", "di.document.upload"})


def test_hashed_confidential_client_authenticates_service_and_delegated(settings):
    raw_secret = "audit-core-secret"
    configured = replace(
        settings.integration_clients["audit-core"],
        secret="",
        secret_sha256=hashlib.sha256(raw_secret.encode()).hexdigest(),
    )
    hashed_settings = replace(
        settings,
        integration_clients={**settings.integration_clients, "audit-core": configured},
    )
    app = create_app(hashed_settings)
    app.state.auth_service.ensure_tenant("tenant-1")
    client = TestClient(app)

    service = client.post(
        "/oauth/token",
        auth=("audit-core", raw_secret),
        data={
            "grant_type": "client_credentials",
            "tenant_id": "tenant-1",
            "scope": "di.document.read",
        },
    )
    assert service.status_code == 200, service.text
    service_claims = app.state.token_service.decode(service.json()["access_token"])
    assert service_claims["sub"] == "audit-core"
    assert service_claims["actor_type"] == "SERVICE"
    assert service_claims["permissions"] == ["di.document.read"]

    user = app.state.token_service.issue_user_access_token(
        subject="pc-1", tenant_id="tenant-1", roles=["PC"]
    )
    delegated = client.post(
        "/oauth/token",
        auth=("audit-core", raw_secret),
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "subject_token": user.access_token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "scope": "di.document.upload",
        },
    )
    assert delegated.status_code == 200, delegated.text
    delegated_claims = app.state.token_service.decode(delegated.json()["access_token"])
    assert delegated_claims["sub"] == "pc-1"
    assert delegated_claims["tenant_id"] == "tenant-1"
    assert delegated_claims["actor_type"] == "USER"
    assert delegated_claims["permissions"] == ["di.document.upload"]
    assert delegated_claims["act"] == {"sub": "audit-core"}

    wrong_secret = client.post(
        "/oauth/token",
        auth=("audit-core", "wrong-secret"),
        data={
            "grant_type": "client_credentials",
            "tenant_id": "tenant-1",
            "scope": "di.document.read",
        },
    )
    assert wrong_secret.status_code == 401
    assert wrong_secret.json() == {"error": "invalid_client"}
