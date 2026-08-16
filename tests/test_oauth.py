from __future__ import annotations

import base64

import jwt
from fastapi.testclient import TestClient

from verigence_security.app import ACCESS_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT, create_app


def _basic(client_id: str = "audit-core", secret: str = "audit-core-secret") -> dict[str, str]:
    encoded = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


def _decode(app, token: str) -> dict:
    return app.state.token_service.decode(token)


def _decode_with_jwks(client: TestClient, settings, token: str) -> dict:
    jwk = client.get("/.well-known/jwks.json").json()["keys"][0]
    public_key = jwt.PyJWK.from_dict(jwk).key
    return jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience=settings.audience,
        issuer=settings.issuer,
    )


def test_user_token_contains_default_cross_module_pc_permissions(settings):
    app = create_app(settings)
    issued = app.state.token_service.issue_user_access_token(
        subject="pc-1", tenant_id="tenant-1", roles=["PC"]
    )
    claims = _decode(app, issued.access_token)

    assert claims["roles"] == ["PC"]
    assert "audit.evidence.upload" in claims["permissions"]
    assert "di.document.upload" in claims["permissions"]
    assert "di.document.read" in claims["permissions"]
    assert "di.verification.write" not in claims["permissions"]


def test_service_flow_is_limited_to_integration_permissions_and_validates_via_jwks(settings):
    app = create_app(settings)
    app.state.auth_service.ensure_tenant("tenant-1")
    client = TestClient(app)
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
    claims = _decode_with_jwks(client, settings, response.json()["access_token"])
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
            "scope": "di.platform.whatsapp.admin",
        },
    )
    assert denied.status_code == 400
    assert denied.json()["error"] == "invalid_scope"
    assert "access_token" not in denied.json()


def test_delegated_exchange_preserves_user_and_narrows_authority(settings):
    app = create_app(settings)
    client = TestClient(app)
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


def test_pc_cannot_exchange_for_verification_write(settings):
    app = create_app(settings)
    client = TestClient(app)
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
            "scope": "di.verification.write",
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_scope"


def test_tl_can_exchange_for_verification_write(settings):
    app = create_app(settings)
    client = TestClient(app)
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
    assert response.status_code == 200
    claims = _decode(app, response.json()["access_token"])
    assert claims["permissions"] == ["di.verification.write"]


def test_invalid_client_is_rejected(settings):
    app = create_app(settings)
    client = TestClient(app)
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


def test_jwks_validates_delegated_token_and_matches_di_contract(settings):
    app = create_app(settings)
    client = TestClient(app)
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
    claims = _decode_with_jwks(client, settings, response.json()["access_token"])

    assert claims["iss"] == "verigence-security"
    assert claims["aud"] == "verigence-platform"
    assert claims["sub"] == "pc-1"
    assert claims["tenant_id"] == "tenant-1"
    assert claims["actor_type"] == "USER"
    assert claims["permissions"] == ["di.document.read"]
