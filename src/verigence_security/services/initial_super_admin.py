from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session


@dataclass(frozen=True, slots=True)
class InitialSuperAdminProvisioningResult:
    user_id: str
    created: bool


class InitialSuperAdminProvisioningService:
    """One-time operator-controlled provisioning of the first Platform Super Admin."""

    _LOCK_KEY = "verigence.platform.initial.super_admin.provision"
    _OPERATION_KEY = "platform.super_admin.system_provision"

    def __init__(self, session: Session) -> None:
        self.s = session

    def provision(
        self,
        *,
        clerk_user_id: str,
        display_name: str = "superadmin",
    ) -> InitialSuperAdminProvisioningResult:
        subject = clerk_user_id.strip()
        name = display_name.strip() or "superadmin"
        if not subject.startswith("user_") or len(subject) > 240:
            raise ValueError(
                "Initial Super Admin Clerk user ID must be an immutable Clerk user_ identifier"
            )

        try:
            self.s.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
                {"key": self._LOCK_KEY},
            )

            existing = self._user_for_clerk_subject(subject)
            if existing is not None:
                user_id = str(existing["user_id"])
                if self._active_super_admin_for_user(user_id):
                    self.s.commit()
                    return InitialSuperAdminProvisioningResult(user_id=user_id, created=False)
                raise RuntimeError(
                    "The configured Clerk identity is already mapped to Security but is not "
                    "an active Platform Super Admin"
                )

            if self._active_super_admin_exists():
                raise RuntimeError(
                    "A different active Platform Super Admin already exists; initial provisioning "
                    "will not replace it"
                )

            now = datetime.now(UTC)
            user_id = str(uuid4())
            principal_name = f"clerk:{subject}"

            self.s.execute(
                text(
                    """
                    INSERT INTO security.security_principals
                    (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                    VALUES (:user_id,'USER',:principal_name,'ACTIVE',:now,:now)
                    """
                ),
                {"user_id": user_id, "principal_name": principal_name, "now": now},
            )
            self.s.execute(
                text(
                    """
                    INSERT INTO security.users
                    (user_id,display_name,status,created_at_utc,updated_at_utc)
                    VALUES (:user_id,:display_name,'ACTIVE',:now,:now)
                    """
                ),
                {"user_id": user_id, "display_name": name, "now": now},
            )
            self.s.execute(
                text(
                    """
                    INSERT INTO security.external_identities
                    (external_identity_id,user_id,provider,provider_subject,status,linked_at_utc)
                    VALUES (:external_identity_id,:user_id,'CLERK',:subject,'ACTIVE',:now)
                    """
                ),
                {
                    "external_identity_id": str(uuid4()),
                    "user_id": user_id,
                    "subject": subject,
                    "now": now,
                },
            )
            self.s.execute(
                text(
                    """
                    INSERT INTO security.platform_user_role_assignments
                    (assignment_id,user_id,role_key,status,assignment_source,assigned_at_utc)
                    VALUES (:assignment_id,:user_id,'platform.super_admin','ACTIVE','BOOTSTRAP',:now)
                    """
                ),
                {"assignment_id": str(uuid4()), "user_id": user_id, "now": now},
            )
            self.s.execute(
                text(
                    """
                    INSERT INTO security.admin_change_records
                    (admin_change_id,correlation_id,scope_type,tenant_id,actor_user_id,
                     operation_key,resource_type,resource_id,outcome,before_state_json,
                     after_state_json,occurred_at_utc)
                    VALUES (:change_id,:correlation_id,'PLATFORM',NULL,:user_id,
                            :operation_key,'platform_user',:user_id,'SUCCESS',NULL,
                            CAST(:after_state AS jsonb),:now)
                    """
                ),
                {
                    "change_id": str(uuid4()),
                    "correlation_id": str(uuid4()),
                    "user_id": user_id,
                    "operation_key": self._OPERATION_KEY,
                    "after_state": json.dumps(
                        {
                            "identityProvider": "CLERK",
                            "providerSubject": subject,
                            "platformRole": "platform.super_admin",
                            "provisioningMode": "SYSTEM_INITIAL_ADMIN",
                        }
                    ),
                    "now": now,
                },
            )
            self.s.commit()
            return InitialSuperAdminProvisioningResult(user_id=user_id, created=True)
        except Exception:
            self.s.rollback()
            raise

    def _user_for_clerk_subject(self, subject: str) -> dict[str, object] | None:
        row = self.s.execute(
            text(
                """
                SELECT e.user_id
                FROM security.external_identities e
                WHERE e.provider='CLERK' AND e.provider_subject=:subject
                """
            ),
            {"subject": subject},
        ).mappings().first()
        return dict(row) if row else None

    def _active_super_admin_for_user(self, user_id: str) -> bool:
        return (
            self.s.execute(
                text(
                    """
                    SELECT 1
                    FROM security.platform_user_role_assignments
                    WHERE user_id=:user_id
                      AND role_key='platform.super_admin'
                      AND status='ACTIVE'
                    LIMIT 1
                    """
                ),
                {"user_id": user_id},
            ).first()
            is not None
        )

    def _active_super_admin_exists(self) -> bool:
        return (
            self.s.execute(
                text(
                    """
                    SELECT 1
                    FROM security.platform_user_role_assignments
                    WHERE role_key='platform.super_admin' AND status='ACTIVE'
                    LIMIT 1
                    """
                )
            ).first()
            is not None
        )
