from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from verigence_security.api.dependencies import repository, source_ip, token_service
from verigence_security.api.routes import access
from verigence_security.core.errors import SecurityError
from verigence_security.core.types import ActorType
from verigence_security.repositories.security_repository import (
    MachineCredential,
    TenantPolicy,
)
from verigence_security.services.access_service import MachineAccessService


class FakeRepo:
    def __init__(self, secret: str = "audit-core-secret") -> None:
        self.credential = MachineCredential(
            principal_id="principal-audit-core",
            actor_type=ActorType.SERVICE_INTEGRATION,
            credential_id="credential-audit-core",
            client_id="audit-core",
            secret_hash=hashlib.sha256(secret.encode()).hexdigest(),
        )
        self.permissions = ["di.document.read", "di.document.upload"]
        self.committed = False
        self.rolled_back = False
        self.session = None
        self.evaluation = None
        self.credential_used = None

    def machine_credential(self, client_id: str, now: datetime) -> MachineCredential:
        assert client_id == "audit-core"
        assert now.tzinfo is not None
        return self.credential

    def tenant_status(self, tenant_id: str) -> str:
        assert tenant_id == "tenant-1"
        return "ACTIVE"

    def get_tenant_policy(self, tenant_id: str) -> TenantPolicy:
        assert tenant_id == "tenant-1"
        return TenantPolicy(
            max_active_devices_per_user=2,
            max_geo_accuracy_meters=50,
            max_geo_age_seconds=300,
            geo_revalidation_interval_seconds=300,
            access_token_ttl_minutes=15,
            machine_token_ttl_minutes=5,
            session_idle_timeout_minutes=30,
            session_max_duration_minutes=60,
            vpn_detected_action="DENY",
            vpn_unknown_action="DENY",
            status="ACTIVE",
        )

    def machine_permissions(self, principal_id: str, tenant_id: str, now: datetime) -> list[str]:
        assert principal_id == "principal-audit-core"
        assert tenant_id == "tenant-1"
        assert now.tzinfo is not None
        return self.permissions

    def create_machine_session(self, **kwargs):
        self.session = kwargs
        return "machine-session-1"

    def record_evaluation(self, payload):
        self.evaluation = payload

    def mark_machine_credential_used(self, credential_id: str, now: datetime) -> None:
        self.credential_used = (credential_id, now)

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True


class FakeTokens:
    def __init__(self) -> None:
        self.claims = None
        self.subject_claims = None

    def issue(self, claims):
        self.claims = claims
        return "signed-token"

    def verify(self, token: str):
        assert token == "subject-token"
        assert self.subject_claims is not None
        return self.subject_claims


def _subject_claims(*, permissions: list[str]) -> dict[str, object]:
    expiry = datetime.now(UTC) + timedelta(minutes=4)
    return {
        "sub": "user-1",
        "actor_type": "USER",
        "tenant_id": "tenant-1",
        "access_session_id": "user-session-1",
        "roles": ["PC"],
        "device_id": "device-1",
        "location_id": "location-1",
        "permissions": permissions,
        "exp": expiry.timestamp(),
    }


def test_client_credentials_uses_service_integration_and_requested_grants_only() -> None:
    repo = FakeRepo()
    tokens = FakeTokens()
    result = MachineAccessService(repo, tokens).issue_machine_token(
        client_id="audit-core",
        client_secret="audit-core-secret",
        tenant_id="tenant-1",
        requested_permissions=["di.document.read"],
        source_ip="203.0.113.10",
        correlation_id="corr-1",
    )

    assert result["accessToken"] == "signed-token"
    assert result["permissions"] == ["di.document.read"]
    assert tokens.claims is not None
    assert tokens.claims.principal_id == "principal-audit-core"
    assert tokens.claims.subject == "audit-core"
    assert tokens.claims.actor_type == ActorType.SERVICE_INTEGRATION
    assert tokens.claims.permissions == ("di.document.read",)
    assert tokens.claims.roles == ()
    assert repo.session is not None
    assert repo.session["actor_type"] == ActorType.SERVICE_INTEGRATION
    assert repo.evaluation is not None
    assert repo.evaluation["correlation_id"] == "corr-1"
    assert repo.committed
    assert not repo.rolled_back


def test_wrong_machine_secret_fails_closed() -> None:
    repo = FakeRepo()
    tokens = FakeTokens()

    with pytest.raises(SecurityError) as exc:
        MachineAccessService(repo, tokens).issue_machine_token(
            client_id="audit-core",
            client_secret="wrong-secret",
            tenant_id="tenant-1",
            requested_permissions=["di.document.read"],
            source_ip="203.0.113.10",
            correlation_id="corr-1",
        )

    assert exc.value.code == "MACHINE_CREDENTIAL_INVALID"
    assert repo.rolled_back
    assert not repo.committed


def test_machine_scope_cannot_exceed_registered_tenant_grants() -> None:
    repo = FakeRepo()
    tokens = FakeTokens()

    with pytest.raises(SecurityError) as exc:
        MachineAccessService(repo, tokens).issue_machine_token(
            client_id="audit-core",
            client_secret="audit-core-secret",
            tenant_id="tenant-1",
            requested_permissions=["di.verification.write"],
            source_ip="203.0.113.10",
            correlation_id="corr-1",
        )

    assert exc.value.code == "PERMISSION_DENIED"
    assert repo.rolled_back


def test_delegated_token_preserves_user_and_adds_audit_core_actor() -> None:
    repo = FakeRepo()
    tokens = FakeTokens()
    tokens.subject_claims = _subject_claims(
        permissions=["di.document.read", "di.document.upload"]
    )

    result = MachineAccessService(repo, tokens).exchange_user_token(
        client_id="audit-core",
        client_secret="audit-core-secret",
        subject_token="subject-token",
        requested_permissions=["di.document.upload"],
    )

    assert result["permissions"] == ["di.document.upload"]
    assert tokens.claims is not None
    assert tokens.claims.principal_id == "user-1"
    assert tokens.claims.subject is None
    assert tokens.claims.actor_type == ActorType.USER
    assert tokens.claims.tenant_id == "tenant-1"
    assert tokens.claims.access_session_id == "user-session-1"
    assert tokens.claims.permissions == ("di.document.upload",)
    assert tokens.claims.delegated_actor_id == "audit-core"
    assert repo.committed


def test_delegated_scope_is_intersection_of_user_and_client_authority() -> None:
    repo = FakeRepo()
    tokens = FakeTokens()
    tokens.subject_claims = _subject_claims(permissions=["di.document.read"])

    with pytest.raises(SecurityError) as exc:
        MachineAccessService(repo, tokens).exchange_user_token(
            client_id="audit-core",
            client_secret="audit-core-secret",
            subject_token="subject-token",
            requested_permissions=["di.document.upload"],
        )

    assert exc.value.code == "PERMISSION_DENIED"
    assert repo.rolled_back


def _oauth_test_app(repo: FakeRepo, tokens: FakeTokens) -> FastAPI:
    app = FastAPI()

    @app.middleware("http")
    async def correlation(request: Request, call_next):
        request.state.correlation_id = "corr-http"
        return await call_next(request)

    app.include_router(access.oauth_router)
    app.dependency_overrides[repository] = lambda: repo
    app.dependency_overrides[token_service] = lambda: tokens
    app.dependency_overrides[source_ip] = lambda: "203.0.113.10"
    return app


def test_oauth_wrong_secret_returns_invalid_client() -> None:
    repo = FakeRepo()
    tokens = FakeTokens()
    client = TestClient(_oauth_test_app(repo, tokens))

    response = client.post(
        "/oauth/token",
        auth=("audit-core", "wrong-secret"),
        data={
            "grant_type": "client_credentials",
            "tenant_id": "tenant-1",
            "scope": "di.document.read",
        },
    )

    assert response.status_code == 401
    assert response.json() == {"error": "invalid_client"}
    assert response.headers["www-authenticate"] == "Basic"


def test_oauth_client_credentials_response_shape() -> None:
    repo = FakeRepo()
    tokens = FakeTokens()
    client = TestClient(_oauth_test_app(repo, tokens))

    response = client.post(
        "/oauth/token",
        auth=("audit-core", "audit-core-secret"),
        data={
            "grant_type": "client_credentials",
            "tenant_id": "tenant-1",
            "scope": "di.document.read",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["access_token"] == "signed-token"
    assert body["issued_token_type"] == access.ACCESS_TOKEN_TYPE
    assert body["token_type"] == "Bearer"
    assert body["scope"] == "di.document.read"
    assert 0 < body["expires_in"] <= 300