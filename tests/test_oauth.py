from __future__ import annotations

import base64

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from verigence_security.app import ACCESS_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT, create_app
from verigence_security.settings import IntegrationClient, Settings


@pytest.fixture
def settings() -> Settings:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return Settings(
        private_key_pem=private_key,
        key_id="test-key",
        issuer="verigence-security",
        audience="verigence-platform",
        token_ttl_seconds=300,
        role_permission_bundles={
            "PC": frozenset(
                {
                    "audit.booking.create",
                    "audit.evidence.upload",
                    "di.document.upload",
                    "di.document.read",
                }
            ),
            "TL": frozenset(
                {
                    "audit.review.write",
                    "di.document.read",
                    "di.verification.write",
                }
            ),
        },
        integration_clients={
            "audit-core": IntegrationClient(
                secret="audit-core-secret",
                permissions=frozenset(
                    {
                        "di.document.upload",
                        "di.document.read",
                    }
                ),
            )
        },
    )


@pytest.fixture
def app(settings: Settings):
    return create_app(settings)


@pytest.fixture
def client(app) -> TestClient:
    return TestClient(app)


def _basic(client_id: str = "audit-core", secret: str = "audit-core-secret") -> dict[str, str]:
    encoded = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


def _decode(app, token: str) -> dict:
    return app.state.token_service.decode(token)


def test_user_token_contains_cross_module_platform_permissions(app):
    issued = app.state.token_service.issue_user_access_token(
        subject="pc-1", tenant_id="tenant-1", roles=["PC"]
    )
    claims = _decode(app, issued.access_token)

    assert claims["roles"] == ["PC"]
    assert set(claims["permissions"]) == {
        "audit.booking.create",
        "audit.evidence.upload",
        "di.document.upload",
        "di.document.read",
    }


def test_service_flow_is_limited_to_integration_permissions(client, app):
    response = client.post(
        "/oauth/token",
        headers=_basic(),
        data={
            "grant_type": "client_credentials",
            "tenant_id": "tenant-1",
            "scope": "di.document.upload",
        },
    )
    assert response.status_code == 200
    claims = _decode(app, response.json()["access_token"])
    assert claims["sub"] == "audit-core"
    assert claims["tenant_id"] == "tenant-1"
    assert claims["actor_type"] == "SERVICE"
    assert claims["permissions"] == ["di.document.upload"]

    denied = client.post(
        "/oauth/token",
        headers=_basic(),
        data={
            "grant_type": "client_credentials",
            "tenant_id": "tenant-1",
            "scope": "di.verification.write",
        },
    )
    assert denied.status_code == 400
    assert denied.json()["error"] == "invalid_scope"
    assert "access_token" not in denied.json()


def test_delegated_exchange_preserves_user_and_narrows_authority(client, app):
    user = app.state.token_service.issue_user_access_token(
        subject="pc-1", tenant_id="tenant-1", roles=["PC"]
    )
    response = client.post(
        "/oauth/token",
        headers=_basic(),
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "subject_token": user.access_token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "scope": "di.document.upload",
        },
    )
    assert response.status_code == 200
    claims = _decode(app, response.json()["access_token"])
    assert claims["sub"] == "pc-1"
    assert claims["tenant_id"] == "tenant-1"
    assert claims["actor_type"] == "USER"
    assert claims["permissions"] == ["di.document.upload"]
    assert claims["act"] == {"sub": "audit-core"}


def test_delegated_exchange_denies_permission_outside_intersection(client, app):
    user = app.state.token_service.issue_user_access_token(
        subject="tl-1", tenant_id="tenant-1", roles=["TL"]
    )
    response = client.post(
        "/oauth/token",
        headers=_basic(),
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "subject_token": user.access_token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "scope": "di.verification.write",
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_scope"
    assert "access_token" not in response.json()


def test_invalid_client_is_rejected(client):
    response = client.post(
        "/oauth/token",
        headers=_basic(secret="wrong"),
        data={
            "grant_type": "client_credentials",
            "tenant_id": "tenant-1",
            "scope": "di.document.upload",
        },
    )
    assert response.status_code == 401
    assert response.json() == {"error": "invalid_client"}


def test_jwks_validates_delegated_token_and_matches_di_contract(client, app, settings):
    user = app.state.token_service.issue_user_access_token(
        subject="pc-1", tenant_id="tenant-1", roles=["PC"]
    )
    response = client.post(
        "/oauth/token",
        headers=_basic(),
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "subject_token": user.access_token,
            "scope": "di.document.read",
        },
    )
    token = response.json()["access_token"]
    jwk = client.get("/.well-known/jwks.json").json()["keys"][0]
    public_key = jwt.PyJWK.from_dict(jwk).key
    claims = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience=settings.audience,
        issuer=settings.issuer,
    )

    assert claims["iss"] == "verigence-security"
    assert claims["aud"] == "verigence-platform"
    assert claims["sub"] == "pc-1"
    assert claims["tenant_id"] == "tenant-1"
    assert claims["actor_type"] == "USER"
    assert claims["permissions"] == ["di.document.read"]
