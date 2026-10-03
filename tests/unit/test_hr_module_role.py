from __future__ import annotations

from typing import Any

import pytest

from verigence_security.services.v2_authorization import HumanAuthorizationResolver

USER_ID = "00000000-0000-4000-8000-000000000101"
TENANT_ID = "00000000-0000-4000-8000-000000000201"

HR_GRANTS = {
    "HRADMIN": {"hr.employee.read", "hr.employee.manage", "hr.sensitive.read", "hr.audit.read", "hr.settings.manage"},
    "FINANCEADMIN": {"hr.employee.read"},
    "CEO": {"hr.employee.read", "hr.employee.manage", "hr.sensitive.read", "hr.audit.read", "hr.settings.manage"},
}


class HrRepo:
    def __init__(self, roles: list[str]) -> None:
        self.roles = roles

    def human_for_user_id(self, user_id: str) -> dict[str, Any] | None:
        if user_id != USER_ID:
            return None
        return {"user_id": USER_ID, "identity_status": "ACTIVE", "user_status": "ACTIVE",
                "principal_actor_type": "USER", "principal_status": "ACTIVE"}

    def active_permission(self, permission_key: str) -> dict[str, Any] | None:
        module = permission_key.split(".")[0]
        if module not in {"hr", "audit"}:
            return None
        return {"permission_key": permission_key, "module_key": module, "resource_key": "t",
                "action_key": "t", "status": "ACTIVE"}

    def tenant_status(self, tenant_id: str) -> str | None:
        return "ACTIVE" if tenant_id == TENANT_ID else None

    def active_admin_assignments(self, user_id: str) -> list[dict[str, Any]]:
        return []

    def active_module_roles(self, *, user_id: str, module_key: str) -> list[str]:
        return list(self.roles) if module_key == "hr" and user_id == USER_ID else []

    def module_role_has_permission(self, *, module_key: str, role_key: str, permission_key: str) -> bool:
        return module_key == "hr" and permission_key in HR_GRANTS.get(role_key, set())

    def active_operating_role(self, *, user_id: str, tenant_id: str) -> str | None:
        return None

    def tenant_role_has_permission(self, *, tenant_id: str, role_key: str, permission_key: str) -> bool:
        return False

    def active_test_identity_for_user(self, user_id: str) -> str | None:
        return None


def _check(roles: list[str], permission: str, tenant: str | None = None):
    return HumanAuthorizationResolver(HrRepo(roles)).check(
        user_id=USER_ID, tenant_id=tenant, permission_key=permission
    )


@pytest.mark.parametrize("permission", sorted(HR_GRANTS["HRADMIN"]))
def test_hradmin_has_every_hr_permission_with_no_project(permission: str) -> None:
    decision = _check(["HRADMIN"], permission)
    assert decision.allowed and decision.reason_code == "ALLOW_MODULE_ROLE"
    assert decision.role_key == "HRADMIN" and decision.tenant_id is None


def test_financeadmin_can_read_employees_but_not_manage_or_see_identity_numbers() -> None:
    assert _check(["FINANCEADMIN"], "hr.employee.read").allowed
    for permission in ("hr.employee.manage", "hr.sensitive.read", "hr.settings.manage"):
        assert not _check(["FINANCEADMIN"], permission).allowed


def test_ceo_holds_every_hr_permission() -> None:
    for permission in HR_GRANTS["CEO"]:
        assert _check(["CEO"], permission).allowed


def test_a_person_with_two_hr_roles_gets_the_union() -> None:
    assert _check(["FINANCEADMIN", "HRADMIN"], "hr.employee.manage").allowed


def test_no_hr_role_means_no_hr_access_and_a_tenant_does_not_help() -> None:
    for tenant in (None, TENANT_ID):
        decision = _check([], "hr.employee.read", tenant)
        assert not decision.allowed
    assert _check([], "hr.employee.read").reason_code == "TENANT_CONTEXT_REQUIRED"


def test_hr_role_does_not_leak_into_other_modules() -> None:
    assert not _check(["CEO"], "audit.journey.read", TENANT_ID).allowed
