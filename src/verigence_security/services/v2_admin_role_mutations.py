from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from verigence_security.repositories.v2_rbac_repository import V2RbacRepository
from verigence_security.services.v2_rbac import ADMIN_ROLE_SCOPES, RoleMutationResult


class AuditedAdminRoleAssignmentService:
    """Scoped Phase-1 admin assignments with mutation + audit in one transaction."""

    def __init__(self, session: Session) -> None:
        self.repository = V2RbacRepository(session)

    def assign(
        self,
        *,
        user_id: str,
        role_key: str,
        scope_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> RoleMutationResult:
        scope_type = self._scope_for(role_key, scope_id)
        now = datetime.now(UTC)
        assignment_id = str(uuid4())
        try:
            if not self.repository.lock_user(user_id):
                raise ValueError("USER not found")
            if not self.repository.lock_user(actor_user_id):
                raise ValueError("Actor USER not found")
            if self.repository.active_operating_roles_for_user(user_id):
                raise ValueError("Administrative and operating roles are mutually exclusive")

            if role_key == "TenantAdmin":
                if not self.repository.lock_tenant(scope_id):
                    raise ValueError("Tenant scope not found")
            elif role_key == "ModuleAdmin" and not self.repository.module_exists(scope_id):
                raise ValueError("Module scope is not ACTIVE")

            existing = self.repository.active_admin_assignment(
                user_id=user_id,
                role_key=role_key,
                scope_type=scope_type,
                scope_id=scope_id,
            )
            if existing is not None:
                self.repository.rollback()
                return RoleMutationResult(
                    False,
                    str(existing["assignment_id"]),
                    role_key,
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
            self._audit(
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
                role_key=role_key,
                scope_type=scope_type,
                scope_id=scope_id,
                user_id=user_id,
                before=None,
                after={"roleKey": role_key, "scopeType": scope_type, "scopeId": scope_id},
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
        scope_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> RoleMutationResult:
        if role_key == "SuperAdmin":
            raise ValueError("SuperAdmin removal is not part of the Phase-1 admin assignment flow")
        scope_type = self._scope_for(role_key, scope_id)
        now = datetime.now(UTC)
        try:
            if not self.repository.lock_user(user_id):
                raise ValueError("USER not found")
            if not self.repository.lock_user(actor_user_id):
                raise ValueError("Actor USER not found")
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
            self._audit(
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
                role_key=role_key,
                scope_type=scope_type,
                scope_id=scope_id,
                user_id=user_id,
                before={"roleKey": role_key, "scopeType": scope_type, "scopeId": scope_id},
                after=None,
                now=now,
            )
            self.repository.commit()
        except Exception:
            self.repository.rollback()
            raise
        return RoleMutationResult(True, str(current["assignment_id"]), role_key)

    def _scope_for(self, role_key: str, scope_id: str) -> str:
        role = self.repository.role_definition(role_key)
        if role is None or role["status"] != "ACTIVE" or role["role_class"] != "ADMIN":
            raise ValueError("Role must be an ACTIVE Phase-1 administrative role")
        expected = ADMIN_ROLE_SCOPES.get(role_key)
        if role_key not in {"TenantAdmin", "ModuleAdmin"} or expected is None:
            raise ValueError("Unsupported Phase-1 scoped administrative role")
        if not scope_id:
            raise ValueError(f"{role_key} requires a scope ID")
        return expected

    def _audit(
        self,
        *,
        actor_user_id: str,
        correlation_id: str,
        role_key: str,
        scope_type: str,
        scope_id: str,
        user_id: str,
        before: dict[str, object] | None,
        after: dict[str, object] | None,
        now: datetime,
    ) -> None:
        tenant_id = scope_id if scope_type == "TENANT" else None
        audit_scope = "TENANT" if tenant_id is not None else "PLATFORM"
        self.repository.s.execute(
            text(
                """
                INSERT INTO security.admin_change_records
                (admin_change_id,correlation_id,scope_type,tenant_id,actor_user_id,
                 operation_key,resource_type,resource_id,outcome,before_state_json,
                 after_state_json,occurred_at_utc)
                VALUES (:id,:correlation_id,:scope_type,CAST(:tenant_id AS uuid),:actor,
                        'security.role.assign','USER_ADMIN_ROLE',:resource_id,'SUCCESS',
                        CAST(:before AS jsonb),CAST(:after AS jsonb),:now)
                """
            ),
            {
                "id": str(uuid4()),
                "correlation_id": correlation_id,
                "scope_type": audit_scope,
                "tenant_id": tenant_id,
                "actor": actor_user_id,
                "resource_id": user_id,
                "before": json.dumps(before) if before is not None else None,
                "after": json.dumps(after) if after is not None else None,
                "now": now,
            },
        )
