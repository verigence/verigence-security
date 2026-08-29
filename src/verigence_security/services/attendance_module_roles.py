from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session


class AttendanceModuleRoleService:
    """Manage the global secondary Attendance HRADMIN role.

    HRADMIN is intentionally independent of Tenant/Project membership and never
    changes the user's normal operating role.
    """

    MODULE_KEY = "attendance"
    ROLE_KEY = "HRADMIN"

    def __init__(self, session: Session) -> None:
        self.session = session

    def assign(
        self,
        *,
        user_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> tuple[bool, str]:
        now = datetime.now(UTC)
        assignment_id = str(uuid4())
        try:
            self._require_subject(user_id=user_id)
            self._require_module_role()
            existing = self._active_assignment(user_id=user_id)
            if existing is not None:
                self.session.rollback()
                return False, str(existing)

            self.session.execute(
                text(
                    """
                    INSERT INTO security.user_global_module_role_assignments (
                        assignment_id,user_id,module_key,role_key,status,
                        valid_from_utc,assigned_by_user_id,assigned_at_utc
                    ) VALUES (
                        CAST(:assignment_id AS uuid),CAST(:user_id AS uuid),
                        'attendance','HRADMIN','ACTIVE',
                        :now,CAST(:actor_user_id AS uuid),:now
                    )
                    """
                ),
                {
                    "assignment_id": assignment_id,
                    "user_id": user_id,
                    "actor_user_id": actor_user_id,
                    "now": now,
                },
            )
            self._audit(
                user_id=user_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
                before=None,
                after={"moduleKey": self.MODULE_KEY, "roleKey": self.ROLE_KEY},
                now=now,
            )
            self.session.commit()
        except IntegrityError as exc:
            self.session.rollback()
            raise ValueError("Attendance HRADMIN assignment conflicts with current Security state") from exc
        except Exception:
            self.session.rollback()
            raise
        return True, assignment_id

    def remove(
        self,
        *,
        user_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> tuple[bool, str | None]:
        now = datetime.now(UTC)
        try:
            existing = self._active_assignment(user_id=user_id)
            if existing is None:
                self.session.rollback()
                return False, None
            self.session.execute(
                text(
                    """
                    UPDATE security.user_global_module_role_assignments
                    SET status='ENDED',ended_at_utc=:now,
                        valid_to_utc=COALESCE(valid_to_utc,:now)
                    WHERE assignment_id=CAST(:assignment_id AS uuid)
                      AND status='ACTIVE'
                    """
                ),
                {"assignment_id": existing, "now": now},
            )
            self._audit(
                user_id=user_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
                before={"moduleKey": self.MODULE_KEY, "roleKey": self.ROLE_KEY},
                after=None,
                now=now,
            )
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise
        return True, str(existing)

    def _require_subject(self, *, user_id: str) -> None:
        row = self.session.execute(
            text(
                """
                SELECT u.user_id
                FROM security.users u
                JOIN security.security_principals p ON p.principal_id=u.user_id
                WHERE u.user_id=CAST(:user_id AS uuid)
                  AND u.status='ACTIVE'
                  AND p.actor_type='USER'
                  AND p.status='ACTIVE'
                FOR UPDATE OF u
                """
            ),
            {"user_id": user_id},
        ).first()
        if row is None:
            raise ValueError("HRADMIN subject must be an active Verigence USER")

    def _require_module_role(self) -> None:
        row = self.session.execute(
            text(
                """
                SELECT 1
                FROM security.module_roles
                WHERE module_key='attendance'
                  AND role_key='HRADMIN'
                  AND status='ACTIVE'
                """
            )
        ).first()
        if row is None:
            raise ValueError("Attendance HRADMIN role is not active")

    def _active_assignment(self, *, user_id: str) -> str | None:
        value = self.session.execute(
            text(
                """
                SELECT assignment_id
                FROM security.user_global_module_role_assignments
                WHERE user_id=CAST(:user_id AS uuid)
                  AND module_key='attendance'
                  AND role_key='HRADMIN'
                  AND status='ACTIVE'
                  AND (valid_from_utc IS NULL OR valid_from_utc<=CURRENT_TIMESTAMP)
                  AND (valid_to_utc IS NULL OR valid_to_utc>CURRENT_TIMESTAMP)
                """
            ),
            {"user_id": user_id},
        ).scalar_one_or_none()
        return str(value) if value is not None else None

    def _audit(
        self,
        *,
        user_id: str,
        actor_user_id: str,
        correlation_id: str,
        before: dict[str, str] | None,
        after: dict[str, str] | None,
        now: datetime,
    ) -> None:
        self.session.execute(
            text(
                """
                INSERT INTO security.admin_change_records (
                    admin_change_id,correlation_id,scope_type,tenant_id,actor_user_id,
                    operation_key,resource_type,resource_id,outcome,
                    before_state_json,after_state_json,occurred_at_utc
                ) VALUES (
                    CAST(:admin_change_id AS uuid),:correlation_id,'PLATFORM',
                    NULL,CAST(:actor_user_id AS uuid),
                    'security.attendance_hradmin.manage','USER_GLOBAL_MODULE_ROLE',:resource_id,
                    'SUCCESS',CAST(:before_json AS jsonb),CAST(:after_json AS jsonb),:now
                )
                """
            ),
            {
                "admin_change_id": str(uuid4()),
                "correlation_id": correlation_id,
                "actor_user_id": actor_user_id,
                "resource_id": user_id,
                "before_json": json.dumps(before) if before is not None else None,
                "after_json": json.dumps(after) if after is not None else None,
                "now": now,
            },
        )
