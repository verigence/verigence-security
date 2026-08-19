from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Iterable
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from verigence_security.repositories.v2_rbac_repository import V2RbacRepository

OPERATING_ROLE_KEYS = frozenset({"PC", "TL", "PM", "CRM", "Executive"})
ADMIN_ROLE_SCOPES = {
    "SuperAdmin": "PLATFORM",
    "TenantAdmin": "TENANT",
    "ModuleAdmin": "MODULE",
}


@dataclass(frozen=True, slots=True)
class RoleMutationResult:
    changed: bool
    assignment_id: str | None
    role_key: str | None


class RoleDefinitionService:
    def __init__(self, session: Session) -> None:
        self.repository = V2RbacRepository(session)

    def list_roles(self) -> list[dict[str, Any]]:
        return self.repository.role_definitions()

    def get_role(self, role_key: str) -> dict[str, Any] | None:
        return self.repository.role_definition(role_key)


class TenantRoleBundleService:
    """Read/write the v2 operating-role permission bundles.

    Authorization for who may call mutation methods is intentionally left to the
    later human-admin/API batch. This service only enforces v2 data invariants.
    """

    def __init__(self, session: Session) -> None:
        self.repository = V2RbacRepository(session)

    def platform_default(self, role_key: str) -> list[str]:
        self._require_operating_role(role_key)
        return self.repository.platform_default_permissions(role_key)

    def tenant_bundle(self, tenant_id: str, role_key: str) -> list[str]:
        self._require_operating_role(role_key)
        return self.repository.tenant_role_permissions(tenant_id, role_key)

    def replace_tenant_bundle(
        self,
        *,
        tenant_id: str,
        role_key: str,
        permission_keys: Iterable[str],
        actor_user_id: str,
    ) -> list[str]:
        self._require_operating_role(role_key)
        requested = set(permission_keys)
        now = datetime.now(UTC)
        try:
            if not self.repository.lock_tenant(tenant_id):
                raise ValueError("Tenant not found")
            if not self.repository.lock_user(actor_user_id):
                raise ValueError("Actor USER not found")
            active = self.repository.active_permission_keys(requested)
            missing = sorted(requested - active)
            if missing:
                raise ValueError(
                    "Permissions must exist and be ACTIVE: " + ", ".join(missing)
                )
            self.repository.replace_tenant_role_permissions(
                tenant_id=tenant_id,
                role_key=role_key,
                permission_keys=requested,
                actor_user_id=actor_user_id,
                now=now,
            )
            self.repository.commit()
        except Exception:
            self.repository.rollback()
            raise
        return self.repository.tenant_role_permissions(tenant_id, role_key)

    def _require_operating_role(self, role_key: str) -> dict[str, Any]:
        role = self.repository.role_definition(role_key)
        if (
            role is None
            or role["status"] != "ACTIVE"
            or role["role_class"] != "OPERATING"
            or role_key not in OPERATING_ROLE_KEYS
        ):
            raise ValueError("Role must be an ACTIVE Phase-1 operating role")
        return role


class OperatingRoleAssignmentService:
    """Set/replace one Phase-1 operating role for a USER in a Tenant."""

    def __init__(self, session: Session) -> None:
        self.repository = V2RbacRepository(session)

    def set_role(
        self,
        *,
        tenant_id: str,
        user_id: str,
        role_key: str,
        actor_user_id: str,
    ) -> RoleMutationResult:
        self._require_operating_role(role_key)
        now = datetime.now(UTC)
        assignment_id = str(uuid4())
        try:
            # The global USER row is the serialization point for the cross-table
            # admin-vs-operating exclusivity invariant.
            if not self.repository.lock_user(user_id):
                raise ValueError("USER not found")
            user_status = self.repository.s.execute(
                text("SELECT status FROM security.users WHERE user_id=:user_id"),
                {"user_id": user_id},
            ).scalar_one()
            if str(user_status) != "ACTIVE":
                raise ValueError("USER must be ACTIVE for an operating-role assignment")
            if not self.repository.lock_tenant(tenant_id):
                raise ValueError("Tenant not found")
            if not self.repository.lock_user(actor_user_id):
                raise ValueError("Actor USER not found")

            if self.repository.active_admin_assignments(user_id):
                raise ValueError(
                    "Administrative and operating roles are mutually exclusive"
                )

            current = self.repository.active_operating_role(
                user_id=user_id,
                tenant_id=tenant_id,
                for_update=True,
            )
            if current is not None and current["role_key"] == role_key:
                self.repository.rollback()
                return RoleMutationResult(
                    changed=False,
                    assignment_id=str(current["assignment_id"]),
                    role_key=role_key,
                )

            if role_key == "PM":
                existing_pm = self.repository.active_pm(
                    tenant_id,
                    exclude_user_id=user_id,
                )
                if existing_pm is not None:
                    raise ValueError("Tenant already has an ACTIVE PM")

            if current is not None:
                self.repository.end_active_operating_role(
                    user_id=user_id,
                    tenant_id=tenant_id,
                    now=now,
                )

            self.repository.insert_operating_role(
                assignment_id=assignment_id,
                user_id=user_id,
                tenant_id=tenant_id,
                role_key=role_key,
                actor_user_id=actor_user_id,
                now=now,
            )
            self.repository.commit()
        except IntegrityError as exc:
            self.repository.rollback()
            raise ValueError(
                "Operating role assignment violates Phase-1 cardinality"
            ) from exc
        except Exception:
            self.repository.rollback()
            raise

        return RoleMutationResult(
            changed=True,
            assignment_id=assignment_id,
            role_key=role_key,
        )

    def remove_role(self, *, tenant_id: str, user_id: str) -> RoleMutationResult:
        now = datetime.now(UTC)
        try:
            if not self.repository.lock_user(user_id):
                raise ValueError("USER not found")
            if not self.repository.lock_tenant(tenant_id):
                raise ValueError("Tenant not found")
            current = self.repository.active_operating_role(
                user_id=user_id,
                tenant_id=tenant_id,
                for_update=True,
            )
            if current is None:
                self.repository.rollback()
                return RoleMutationResult(False, None, None)
            self.repository.end_active_operating_role(
                user_id=user_id,
                tenant_id=tenant_id,
                now=now,
            )
            self.repository.commit()
        except Exception:
            self.repository.rollback()
            raise
        return RoleMutationResult(
            changed=True,
            assignment_id=str(current["assignment_id"]),
            role_key=str(current["role_key"]),
        )

    def _require_operating_role(self, role_key: str) -> None:
        role = self.repository.role_definition(role_key)
        if (
            role is None
            or role["status"] != "ACTIVE"
            or role["role_class"] != "OPERATING"
            or role_key not in OPERATING_ROLE_KEYS
        ):
            raise ValueError("Role must be an ACTIVE Phase-1 operating role")


class AdminRoleAssignmentService:
    """Assign scoped Phase-1 administrative classifications.

    Admin roles may stack with other admin roles. Any ACTIVE operating role for the
    same global USER blocks an admin assignment, and any ACTIVE admin assignment
    blocks an operating role assignment.
    """

    def __init__(self, session: Session) -> None:
        self.repository = V2RbacRepository(session)

    def assign(
        self,
        *,
        user_id: str,
        role_key: str,
        scope_id: str | None,
        actor_user_id: str | None,
    ) -> RoleMutationResult:
        scope_type = self._scope_for(role_key, scope_id)
        now = datetime.now(UTC)
        assignment_id = str(uuid4())
        try:
            if not self.repository.lock_user(user_id):
                raise ValueError("USER not found")
            if actor_user_id is not None and not self.repository.lock_user(actor_user_id):
                raise ValueError("Actor USER not found")

            if self.repository.active_operating_roles_for_user(user_id):
                raise ValueError(
                    "Administrative and operating roles are mutually exclusive"
                )

            if role_key == "TenantAdmin":
                assert scope_id is not None
                if not self.repository.lock_tenant(scope_id):
                    raise ValueError("Tenant scope not found")
            elif role_key == "ModuleAdmin":
                assert scope_id is not None
                if not self.repository.module_exists(scope_id):
                    raise ValueError("Module scope is not ACTIVE")
            elif role_key == "SuperAdmin":
                existing_super_admin = self.repository.active_super_admin_user_id()
                if existing_super_admin is not None and existing_super_admin != user_id:
                    raise ValueError("Phase 1 allows exactly one ACTIVE SuperAdmin")

            existing = self.repository.active_admin_assignment(
                user_id=user_id,
                role_key=role_key,
                scope_type=scope_type,
                scope_id=scope_id,
            )
            if existing is not None:
                self.repository.rollback()
                return RoleMutationResult(
                    changed=False,
                    assignment_id=str(existing["assignment_id"]),
                    role_key=role_key,
                )

            self.repository.insert_admin_assignment(
                assignment_id=assignment_id,
                user_id=user_id,
                role_key=role_key,
                scope_type=scope_type,
                scope_id=scope_id,
                actor_user_id=actor_user_id,
                now=now,
            )
            self.repository.commit()
        except IntegrityError as exc:
            self.repository.rollback()
            raise ValueError("Administrative role assignment conflicts with Phase-1 rules") from exc
        except Exception:
            self.repository.rollback()
            raise

        return RoleMutationResult(True, assignment_id, role_key)

    def remove(
        self,
        *,
        user_id: str,
        role_key: str,
        scope_id: str | None,
    ) -> RoleMutationResult:
        if role_key == "SuperAdmin":
            raise ValueError("SuperAdmin removal is not part of the Phase-1 admin assignment flow")
        scope_type = self._scope_for(role_key, scope_id)
        now = datetime.now(UTC)
        try:
            if not self.repository.lock_user(user_id):
                raise ValueError("USER not found")
            current = self.repository.active_admin_assignment(
                user_id=user_id,
                role_key=role_key,
                scope_type=scope_type,
                scope_id=scope_id,
            )
            if current is None:
                self.repository.rollback()
                return RoleMutationResult(False, None, role_key)
            self.repository.end_admin_assignment(
                user_id=user_id,
                role_key=role_key,
                scope_type=scope_type,
                scope_id=scope_id,
                now=now,
            )
            self.repository.commit()
        except Exception:
            self.repository.rollback()
            raise
        return RoleMutationResult(
            True,
            str(current["assignment_id"]),
            role_key,
        )

    def _scope_for(self, role_key: str, scope_id: str | None) -> str:
        role = self.repository.role_definition(role_key)
        if role is None or role["status"] != "ACTIVE" or role["role_class"] != "ADMIN":
            raise ValueError("Role must be an ACTIVE Phase-1 administrative role")
        expected = ADMIN_ROLE_SCOPES.get(role_key)
        if expected is None:
            raise ValueError("Unsupported Phase-1 administrative role")
        if role_key == "SuperAdmin" and scope_id is not None:
            raise ValueError("SuperAdmin is platform-scoped and has no scope ID")
        if role_key in {"TenantAdmin", "ModuleAdmin"} and not scope_id:
            raise ValueError(f"{role_key} requires a scope ID")
        return expected
