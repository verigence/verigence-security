from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from verigence_security.config import Settings
from verigence_security.core.errors import SecurityError
from verigence_security.core.types import ActorType
from verigence_security.services.token_service import (
    AccessTokenClaims,
    ServiceTokenClaims,
    TokenService,
)
from verigence_security.services.v2_authorization import (
    AuthorizationCheckService,
    HumanAuthorizationResolver,
)

USER_ID = "00000000-0000-4000-8000-000000000101"
TENANT_A = "00000000-0000-4000-8000-000000000201"
TENANT_B = "00000000-0000-4000-8000-000000000202"
TEST_TENANT = "00000000-0000-4000-8000-000000000299"


class FakeAuthorizationRepository:
    def __init__(self) -> None:
        self.service_active = True
        self.human: dict[str, Any] | None = {
            "user_id": USER_ID,
            "identity_status": "ACTIVE",
            "user_status": "ACTIVE",
            "principal_actor_type": "USER",
            "principal_status": "ACTIVE",
        }
        self.permissions: dict[str, str] = {
            "audit.project.read": "audit",
            "audit.master.publish": "audit",
            "audit.journey.update": "audit",
            "di.tenant_config.write": "di",
            "di.document.read": "di",
        }
        self.tenants = {TENANT_A: "ACTIVE", TENANT_B: "ACTIVE", TEST_TENANT: "ACTIVE"}
        self.admin_assignments: list[dict[str, Any]] = []
        self.operating_roles: dict[str, str] = {}
        self.role_permissions: set[tuple[str, str, str]] = set()
        self.test_tenant: str | None = None

    def active_service_integration(self, integration_key: str) -> bool:
        return self.service_active and integration_key == "audit-core"

    def human_for_user_id(self, user_id: str) -> dict[str, Any] | None:
        if user_id != USER_ID:
            return None
        return self.human

    def active_permission(self, permission_key: str) -> dict[str, Any] | None:
        module = self.permissions.get(permission_key)
        if module is None:
            return None
        return {
            "permission_key": permission_key,
            "module_key": module,
            "resource_key": "test",
            "action_key": "test",
            "status": "ACTIVE",
        }

    def tenant_status(self, tenant_id: str) -> str | None:
        return self.tenants.get(tenant_id)

    def active_admin_assignments(self, user_id: str) -> list[dict[str, Any]]:
        assert user_id == USER_ID
        return list(self.admin_assignments)

    def active_operating_role(self, *, user_id: str, tenant_id: str) -> str | None:
        assert user_id == USER_ID
        return self.operating_roles.get(tenant_id)

    def tenant_role_has_permission(
        self,
        *,
        tenant_id: str,
        role_key: str,
        permission_key: str,
    ) -> bool:
        return (tenant_id, role_key, permission_key) in self.role_permissions

    def active_test_identity_for_user(self, user_id: str) -> str | None:
        assert user_id == USER_ID
        return self.test_tenant


def _token_service() -> TokenService:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return TokenService(
        Settings(
            app_env="ci",
            security_key_id="authz-test-key",
            security_private_key_pem=private_pem,
            security_public_key_pem=public_pem,
        )
    )


def test_operating_role_uses_only_tenant_bundle() -> None:
    repo = FakeAuthorizationRepository()
    repo.operating_roles[TENANT_A] = "PC"
    repo.role_permissions.add((TENANT_A, "PC", "audit.project.read"))
    resolver = HumanAuthorizationResolver(repo)

    allowed = resolver.check(
        user_id=USER_ID,
        tenant_id=TENANT_A,
        permission_key="audit.project.read",
    )
    denied = resolver.check(
        user_id=USER_ID,
        tenant_id=TENANT_A,
        permission_key="audit.journey.update",
    )

    assert allowed.allowed is True
    assert allowed.reason_code == "ALLOW_OPERATING_ROLE"
    assert allowed.role_key == "PC"
    assert denied.allowed is False
    assert denied.reason_code == "ROLE_PERMISSION_DENIED"


def test_test_user_is_pc_only_in_canonical_test_tenant() -> None:
    repo = FakeAuthorizationRepository()
    repo.test_tenant = TEST_TENANT
    repo.role_permissions.add((TEST_TENANT, "PC", "di.document.read"))
    resolver = HumanAuthorizationResolver(repo)

    allowed = resolver.check(
        user_id=USER_ID,
        tenant_id=TEST_TENANT,
        permission_key="di.document.read",
    )
    production = resolver.check(
        user_id=USER_ID,
        tenant_id=TENANT_A,
        permission_key="di.document.read",
    )

    assert allowed.allowed is True
    assert allowed.reason_code == "ALLOW_TEST_USER_PC"
    assert allowed.classification == "TestUser"
    assert production.allowed is False
    assert production.reason_code == "TEST_TENANT_REQUIRED"


def test_super_admin_gets_every_active_registered_permission() -> None:
    repo = FakeAuthorizationRepository()
    repo.admin_assignments = [
        {"role_key": "SuperAdmin", "scope_type": "PLATFORM", "scope_id": None}
    ]
    resolver = HumanAuthorizationResolver(repo)

    decision = resolver.check(
        user_id=USER_ID,
        tenant_id=TENANT_A,
        permission_key="di.document.read",
    )
    inactive_permission = resolver.check(
        user_id=USER_ID,
        tenant_id=TENANT_A,
        permission_key="di.nonexistent.write",
    )

    assert decision.allowed is True
    assert decision.reason_code == "ALLOW_SUPER_ADMIN"
    assert inactive_permission.allowed is False
    assert inactive_permission.reason_code == "PERMISSION_NOT_ACTIVE"


def test_tenant_admin_is_all_approved_modules_for_one_tenant() -> None:
    repo = FakeAuthorizationRepository()
    repo.admin_assignments = [
        {"role_key": "TenantAdmin", "scope_type": "TENANT", "scope_id": TENANT_A}
    ]
    resolver = HumanAuthorizationResolver(repo)

    audit = resolver.check(
        user_id=USER_ID,
        tenant_id=TENANT_A,
        permission_key="audit.master.publish",
    )
    di = resolver.check(
        user_id=USER_ID,
        tenant_id=TENANT_A,
        permission_key="di.tenant_config.write",
    )
    wrong_tenant = resolver.check(
        user_id=USER_ID,
        tenant_id=TENANT_B,
        permission_key="audit.master.publish",
    )
    operating_permission = resolver.check(
        user_id=USER_ID,
        tenant_id=TENANT_A,
        permission_key="audit.journey.update",
    )

    assert audit.allowed is True and audit.reason_code == "ALLOW_TENANT_ADMIN"
    assert di.allowed is True and di.reason_code == "ALLOW_TENANT_ADMIN"
    assert wrong_tenant.allowed is False
    assert operating_permission.allowed is False
    assert operating_permission.reason_code == "ADMIN_SCOPE_OR_PERMISSION_DENIED"


def test_module_admin_is_one_module_across_tenants() -> None:
    repo = FakeAuthorizationRepository()
    repo.admin_assignments = [
        {"role_key": "ModuleAdmin", "scope_type": "MODULE", "scope_id": "audit"}
    ]
    resolver = HumanAuthorizationResolver(repo)

    tenant_a = resolver.check(
        user_id=USER_ID,
        tenant_id=TENANT_A,
        permission_key="audit.master.publish",
    )
    tenant_b = resolver.check(
        user_id=USER_ID,
        tenant_id=TENANT_B,
        permission_key="audit.master.publish",
    )
    di = resolver.check(
        user_id=USER_ID,
        tenant_id=TENANT_A,
        permission_key="di.tenant_config.write",
    )
    audit_operating = resolver.check(
        user_id=USER_ID,
        tenant_id=TENANT_A,
        permission_key="audit.journey.update",
    )

    assert tenant_a.allowed is True and tenant_a.reason_code == "ALLOW_MODULE_ADMIN"
    assert tenant_b.allowed is True and tenant_b.reason_code == "ALLOW_MODULE_ADMIN"
    assert di.allowed is False
    assert audit_operating.allowed is False


def test_inactive_user_and_inactive_tenant_fail_closed() -> None:
    repo = FakeAuthorizationRepository()
    resolver = HumanAuthorizationResolver(repo)
    assert repo.human is not None
    repo.human["user_status"] = "SUSPENDED"

    inactive_user = resolver.check(
        user_id=USER_ID,
        tenant_id=TENANT_A,
        permission_key="audit.project.read",
    )
    assert inactive_user.allowed is False
    assert inactive_user.reason_code == "USER_NOT_ACTIVE"

    repo.human["user_status"] = "ACTIVE"
    repo.tenants[TENANT_A] = "OFFBOARDED"
    inactive_tenant = resolver.check(
        user_id=USER_ID,
        tenant_id=TENANT_A,
        permission_key="audit.project.read",
    )
    assert inactive_tenant.allowed is False
    assert inactive_tenant.reason_code == "TENANT_NOT_ACTIVE"


def test_authorization_check_requires_registered_service_token_with_security_audience() -> None:
    repo = FakeAuthorizationRepository()
    repo.operating_roles[TENANT_A] = "PC"
    repo.role_permissions.add((TENANT_A, "PC", "audit.project.read"))
    tokens = _token_service()
    service = AuthorizationCheckService(repo, tokens)

    security_token = tokens.issue_service_token(
        ServiceTokenClaims(
            subject="audit-core",
            audience="security",
            expires_at=datetime.now(UTC) + timedelta(hours=4),
        )
    )
    decision = service.check(
        service_token=security_token,
        user_id=USER_ID,
        tenant_id=TENANT_A,
        permission_key="audit.project.read",
    )
    assert decision.allowed is True

    wrong_audience_token = tokens.issue_service_token(
        ServiceTokenClaims(
            subject="audit-core",
            audience="di",
            expires_at=datetime.now(UTC) + timedelta(hours=4),
        )
    )
    with pytest.raises(SecurityError) as wrong_audience:
        service.check(
            service_token=wrong_audience_token,
            user_id=USER_ID,
            tenant_id=TENANT_A,
            permission_key="audit.project.read",
        )
    assert wrong_audience.value.code == "AUTH_TOKEN_INVALID"

    browser_like_token = tokens.issue(
        AccessTokenClaims(
            principal_id=USER_ID,
            actor_type=ActorType.USER,
            tenant_id=TENANT_A,
            access_session_id="00000000-0000-4000-8000-000000000301",
            permissions=("audit.project.read",),
            roles=("PC",),
            device_id="00000000-0000-4000-8000-000000000401",
            location_id="00000000-0000-4000-8000-000000000501",
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
    )
    with pytest.raises(SecurityError) as browser_denied:
        service.check(
            service_token=browser_like_token,
            user_id=USER_ID,
            tenant_id=TENANT_A,
            permission_key="audit.project.read",
        )
    assert browser_denied.value.code == "AUTH_TOKEN_INVALID"

    repo.service_active = False
    with pytest.raises(SecurityError) as unregistered:
        service.check(
            service_token=security_token,
            user_id=USER_ID,
            tenant_id=TENANT_A,
            permission_key="audit.project.read",
        )
    assert unregistered.value.code == "AUTH_TOKEN_INVALID"
