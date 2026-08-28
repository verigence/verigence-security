from __future__ import annotations

from typing import Any

from verigence_security.services.v2_authorization import HumanAuthorizationResolver

USER_ID = "00000000-0000-4000-8000-000000000101"
TENANT_ID = "00000000-0000-4000-8000-000000000201"


class AttendanceAuthorizationRepository:
    def human_for_user_id(self, user_id: str) -> dict[str, Any] | None:
        if user_id != USER_ID:
            return None
        return {
            "user_id": USER_ID,
            "identity_status": "ACTIVE",
            "user_status": "ACTIVE",
            "principal_actor_type": "USER",
            "principal_status": "ACTIVE",
        }

    def active_permission(self, permission_key: str) -> dict[str, Any] | None:
        permissions = {
            "attendance.all.read": "attendance",
            "attendance.policy.manage": "attendance",
            "audit.journey.read": "audit",
        }
        module = permissions.get(permission_key)
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
        return "ACTIVE" if tenant_id == TENANT_ID else None

    def active_admin_assignments(self, user_id: str) -> list[dict[str, Any]]:
        if user_id != USER_ID:
            return []
        return [
            {
                "role_key": "HRAdmin",
                "scope_type": "TENANT",
                "scope_id": TENANT_ID,
            }
        ]

    def active_operating_role(self, *, user_id: str, tenant_id: str) -> str | None:
        if user_id == USER_ID and tenant_id == TENANT_ID:
            return "TL"
        return None

    def tenant_role_has_permission(
        self,
        *,
        tenant_id: str,
        role_key: str,
        permission_key: str,
    ) -> bool:
        if tenant_id != TENANT_ID:
            return False
        if role_key == "HRAdmin":
            return permission_key.startswith("attendance.")
        return role_key == "TL" and permission_key == "audit.journey.read"

    def active_test_identity_for_user(self, user_id: str) -> str | None:
        return None


def test_hradmin_grants_attendance_without_replacing_operating_role() -> None:
    resolver = HumanAuthorizationResolver(AttendanceAuthorizationRepository())

    attendance = resolver.check(
        user_id=USER_ID,
        tenant_id=TENANT_ID,
        permission_key="attendance.policy.manage",
    )
    audit = resolver.check(
        user_id=USER_ID,
        tenant_id=TENANT_ID,
        permission_key="audit.journey.read",
    )

    assert attendance.allowed is True
    assert attendance.reason_code == "ALLOW_HR_ADMIN"
    assert attendance.classification == "Admin"
    assert attendance.role_key == "HRAdmin"

    assert audit.allowed is True
    assert audit.reason_code == "ALLOW_OPERATING_ROLE"
    assert audit.classification == "Operating"
    assert audit.role_key == "TL"


def test_hradmin_scope_is_tenant_specific() -> None:
    resolver = HumanAuthorizationResolver(AttendanceAuthorizationRepository())
    other_tenant = "00000000-0000-4000-8000-000000000202"

    decision = resolver.check(
        user_id=USER_ID,
        tenant_id=other_tenant,
        permission_key="attendance.all.read",
    )

    assert decision.allowed is False
