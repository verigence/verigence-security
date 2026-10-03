from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

HR_MODULE_KEY = "hr"
HR_ROLE_KEYS = ("HRADMIN", "FINANCEADMIN", "CEO")


class HrModuleRoleService:
    """Manage the company-wide HR module roles (HRADMIN, FINANCEADMIN, CEO).

    These are global secondary roles: independent of Tenant/Project membership, and they never
    change the user's normal operating role. A person may hold more than one HR role.
    """

    def __init__(self, session: Session) -> None:
        self.session = session

    def assign(
        self, *, user_id: str, role_key: str, actor_user_id: str, correlation_id: str
    ) -> tuple[bool, str]:
        self._require_known_role(role_key)
        now = datetime.now(UTC)
        assignment_id = str(uuid4())
        try:
            self._require_subject(user_id=user_id)
            self._require_module_role(role_key)
            existing = self._active_assignment(user_id=user_id, role_key=role_key)
            if existing is not None:
                self.session.rollback()
                return False, existing
            self.session.execute(
                text(
                    """
                    INSERT INTO security.user_global_module_role_assignments (
                        assignment_id,user_id,module_key,role_key,status,
                        valid_from_utc,assigned_by_user_id,assigned_at_utc
                    ) VALUES (
                        CAST(:assignment_id AS uuid),CAST(:user_id AS uuid),
                        'hr',:role_key,'ACTIVE',
                        CURRENT_TIMESTAMP,CAST(:actor_user_id AS uuid),CURRENT_TIMESTAMP
                    )
                    """
                ),
                {
                    "assignment_id": assignment_id,
                    "user_id": user_id,
                    "role_key": role_key,
                    "actor_user_id": actor_user_id,
                },
            )
            self._audit(
                user_id=user_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
                before=None,
                after={"moduleKey": HR_MODULE_KEY, "roleKey": role_key},
                now=now,
            )
            self.session.commit()
        except IntegrityError as exc:
            self.session.rollback()
            raise ValueError("HR role assignment conflicts with current Security state") from exc
        except Exception:
            self.session.rollback()
            raise
        return True, assignment_id

    def remove(
        self, *, user_id: str, role_key: str, actor_user_id: str, correlation_id: str
    ) -> tuple[bool, str | None]:
        self._require_known_role(role_key)
        now = datetime.now(UTC)
        try:
            existing = self._active_assignment(user_id=user_id, role_key=role_key)
            if existing is None:
                self.session.rollback()
                return False, None
            self.session.execute(
                text(
                    """
                    UPDATE security.user_global_module_role_assignments
                    SET status='ENDED',ended_at_utc=clock_timestamp(),
                        valid_to_utc=COALESCE(valid_to_utc,clock_timestamp())
                    WHERE assignment_id=CAST(:assignment_id AS uuid)
                      AND status='ACTIVE'
                    """
                ),
                {"assignment_id": existing},
            )
            self._audit(
                user_id=user_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
                before={"moduleKey": HR_MODULE_KEY, "roleKey": role_key},
                after=None,
                now=now,
            )
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise
        return True, existing

    @staticmethod
    def _require_known_role(role_key: str) -> None:
        if role_key not in HR_ROLE_KEYS:
            raise ValueError("Unknown HR role")

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
            raise ValueError("The HR role subject must be an active Verigence USER")

    def _require_module_role(self, role_key: str) -> None:
        row = self.session.execute(
            text(
                """
                SELECT 1 FROM security.module_roles
                WHERE module_key='hr' AND role_key=:role_key AND status='ACTIVE'
                """
            ),
            {"role_key": role_key},
        ).first()
        if row is None:
            raise ValueError("The HR role is not active")

    def _active_assignment(self, *, user_id: str, role_key: str) -> str | None:
        value = self.session.execute(
            text(
                """
                SELECT assignment_id
                FROM security.user_global_module_role_assignments
                WHERE user_id=CAST(:user_id AS uuid)
                  AND module_key='hr'
                  AND role_key=:role_key
                  AND status='ACTIVE'
                  AND (valid_from_utc IS NULL OR valid_from_utc<=CURRENT_TIMESTAMP)
                  AND (valid_to_utc IS NULL OR valid_to_utc>CURRENT_TIMESTAMP)
                """
            ),
            {"user_id": user_id, "role_key": role_key},
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
                    'security.hr_module_role.manage','USER_GLOBAL_MODULE_ROLE',:resource_id,
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
