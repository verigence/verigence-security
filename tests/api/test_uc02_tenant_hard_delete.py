from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.routes import platform_admin
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.main import app
from verigence_security.services.platform_admin import TenantHardDeleteResult
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


def test_uc02_superadmin_can_hard_delete_tenant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    deleted_at = datetime(2026, 8, 21, 8, 0, tzinfo=UTC)

    class _TenantService:
        def __init__(self, session: object) -> None:
            assert isinstance(session, _FakeSession)

        def hard_delete_tenant(self, **kwargs: object) -> TenantHardDeleteResult:
            observed.update(kwargs)
            return TenantHardDeleteResult(
                tenant_id=TENANT,
                deleted_at_utc=deleted_at,
                already_deleted=False,
            )

    monkeypatch.setattr(platform_admin, "PlatformTenantService", _TenantService)

    response = client.delete(
        f"/security/v1/platform/tenants/{TENANT}",
        headers={"X-Correlation-ID": "uc02-delete-tenant"},
    )

    assert response.status_code == 200
    assert response.json()["tenantId"] == TENANT
    assert response.json()["status"] == "DELETED"
    assert response.json()["alreadyDeleted"] is False
    assert observed["actor_user_id"] == ACTOR
    assert observed["tenant_id"] == TENANT
    assert observed["correlation_id"] == "uc02-delete-tenant"


def test_uc02_tenantadmin_cannot_hard_delete_tenant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app.dependency_overrides[security_human_actor] = lambda: HumanActorContext(
        user_id=ACTOR,
        clerk_subject="user_tenant_admin",
        admin_scopes=(AdminScope("TenantAdmin", "TENANT", TENANT),),
    )

    class _TenantService:
        def __init__(self, session: object) -> None:
            _ = session

        def hard_delete_tenant(self, **kwargs: object) -> TenantHardDeleteResult:
            raise AssertionError(f"service must not be called: {kwargs}")

    monkeypatch.setattr(platform_admin, "PlatformTenantService", _TenantService)

    response = client.delete(f"/security/v1/platform/tenants/{TENANT}")

    assert response.status_code == 403
    assert response.json()["code"] == "PERMISSION_DENIED"


def test_uc02_hard_delete_is_retry_safe_after_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deleted_at = datetime(2026, 8, 21, 8, 0, tzinfo=UTC)

    class _TenantService:
        def __init__(self, session: object) -> None:
            assert isinstance(session, _FakeSession)

        def hard_delete_tenant(self, **kwargs: object) -> TenantHardDeleteResult:
            assert kwargs["tenant_id"] == TENANT
            return TenantHardDeleteResult(
                tenant_id=TENANT,
                deleted_at_utc=deleted_at,
                already_deleted=True,
            )

    monkeypatch.setattr(platform_admin, "PlatformTenantService", _TenantService)

    response = client.delete(f"/security/v1/platform/tenants/{TENANT}")

    assert response.status_code == 200
    assert response.json()["status"] == "DELETED"
    assert response.json()["alreadyDeleted"] is True


def test_uc02_hard_delete_unknown_tenant_is_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _TenantService:
        def __init__(self, session: object) -> None:
            _ = session

        def hard_delete_tenant(self, **kwargs: object) -> None:
            _ = kwargs
            return None

    monkeypatch.setattr(platform_admin, "PlatformTenantService", _TenantService)

    response = client.delete(f"/security/v1/platform/tenants/{TENANT}")

    assert response.status_code == 404
