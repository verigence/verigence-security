from __future__ import annotations

import re
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.routes import platform_admin
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.main import app
from verigence_security.services.v2_human_actor import AdminScope, HumanActorContext

client = TestClient(app)
ACTOR = "00000000-0000-4000-8000-000000000001"
TENANT = "00000000-0000-4000-8000-000000000010"


class _FakeSession:
    pass


@pytest.fixture(autouse=True)
def _dependencies() -> None:
    app.dependency_overrides.clear()
    app.dependency_overrides[platform_session] = lambda: _FakeSession()
    app.dependency_overrides[security_human_actor] = lambda: HumanActorContext(
        user_id=ACTOR,
        clerk_subject="user_super_admin",
        admin_scopes=(AdminScope("SuperAdmin", "PLATFORM", None),),
    )
    yield
    app.dependency_overrides.clear()


def test_uc02_tenant_create_generates_internal_code_server_side(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class _TenantService:
        def __init__(self, session: object) -> None:
            assert isinstance(session, _FakeSession)

        def create_tenant(self, **kwargs: object) -> dict[str, object]:
            observed.update(kwargs)
            now = datetime.now(UTC)
            return {
                "tenant_id": TENANT,
                "tenant_code": kwargs["tenant_code"],
                "tenant_name": kwargs["tenant_name"],
                "status": "CONFIGURING",
                "created_at_utc": now,
                "updated_at_utc": now,
            }

    monkeypatch.setattr(platform_admin, "PlatformTenantService", _TenantService)

    response = client.post(
        "/security/v1/platform/tenants",
        headers={"Idempotency-Key": "uc02-create-001"},
        json={"tenantName": "Hyundai West Audit Project"},
    )

    assert response.status_code == 201
    assert observed["tenant_name"] == "Hyundai West Audit Project"
    assert observed["idempotency_key"] == "uc02-create-001"
    generated = str(observed["tenant_code"])
    assert re.fullmatch(r"tenant-[0-9a-f]{32}", generated)
    assert response.json()["tenantCode"] == generated
    assert response.json()["status"] == "CONFIGURING"


def test_uc02_caller_cannot_control_internal_tenant_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class _TenantService:
        def __init__(self, session: object) -> None:
            assert isinstance(session, _FakeSession)

        def create_tenant(self, **kwargs: object) -> dict[str, object]:
            observed.update(kwargs)
            now = datetime.now(UTC)
            return {
                "tenant_id": TENANT,
                "tenant_code": kwargs["tenant_code"],
                "tenant_name": kwargs["tenant_name"],
                "status": "CONFIGURING",
                "created_at_utc": now,
                "updated_at_utc": now,
            }

    monkeypatch.setattr(platform_admin, "PlatformTenantService", _TenantService)

    response = client.post(
        "/security/v1/platform/tenants",
        headers={"Idempotency-Key": "uc02-create-002"},
        json={
            "tenantName": "Hyundai West Audit Project",
            "tenantCode": "caller-controlled-code",
        },
    )

    assert response.status_code == 201
    assert observed["tenant_code"] != "caller-controlled-code"
    assert response.json()["tenantCode"] == observed["tenant_code"]


def test_uc02_tenant_create_requires_idempotency_key() -> None:
    response = client.post(
        "/security/v1/platform/tenants",
        json={"tenantName": "Hyundai West Audit Project"},
    )

    assert response.status_code == 422
