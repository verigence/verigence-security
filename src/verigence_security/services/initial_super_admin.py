from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

PHASE1_SUPER_ADMIN_CLERK_USER_ID = "user_3I7HFuZZiFC9K2muiweXFRoeoud"


@dataclass(frozen=True, slots=True)
class InitialSuperAdminProvisioningResult:
    user_id: str
    created: bool


class InitialSuperAdminProvisioningService:
    """Provision/reconcile the one approved Phase-1 SuperAdmin identity."""

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
        if subject != PHASE1_SUPER_ADMIN_CLERK_USER_ID:
            raise ValueError(
                "Initial Super Admin Clerk user ID must match the approved Phase-1 identity"
            )

        try:
            self.s.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
                {"key": self._LOCK_KEY},
            )

            existing = self._user_for_clerk_subject(subject)
            existing_user_id = str(existing["user_id"]) if existing is not None else None
            self._reject_conflicting_super_admin(existing_user_id)

            if existing is not None:
                user_id = str(existing["user_id"])
                if existing["identity_status"] != "ACTIVE":
                    raise RuntimeError("Approved SuperAdmin Clerk identity is not ACTIVE")
                if (
                    existing["user_status"] != "ACTIVE"
                    or existing["principal_status"] != "ACTIVE"
                ):
                    raise RuntimeError("Approved SuperAdmin USER/principal must be ACTIVE")
                if self._has_active_operating_role(user_id):
                    raise RuntimeError(
                        "Approved SuperAdmin USER cannot have an ACTIVE operating role"
                    )

                now = datetime.now(UTC)
                changed = self._ensure_super_admin_assignments(user_id=user_id, now=now)
                if changed:
                    self._insert_audit(
                        user_id=user_id,
                        subject=subject,
                        provisioning_mode="SYSTEM_RECONCILIATION",
                        now=now,
                    )
                self.s.commit()
                return InitialSuperAdminProvisioningResult(user_id=user_id, created=False)

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
            self._ensure_super_admin_assignments(user_id=user_id, now=now)
            self._insert_audit(
                user_id=user_id,
                subject=subject,
                provisioning_mode="SYSTEM_INITIAL_ADMIN",
                now=now,
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
                SELECT e.user_id,
                       e.status AS identity_status,
                       u.status AS user_status,
                       sp.status AS principal_status
                FROM security.external_identities e
                JOIN security.users u ON u.user_id=e.user_id
                JOIN security.security_principals sp ON sp.principal_id=u.user_id
                WHERE e.provider='CLERK' AND e.provider_subject=:subject
                """
            ),
            {"subject": subject},
        ).mappings().first()
        return dict(row) if row else None

    def _reject_conflicting_super_admin(self, approved_user_id: str | None) -> None:
        params = {"approved_user_id": approved_user_id}
        legacy_conflict = self.s.execute(
            text(
                """
                SELECT 1
                FROM security.platform_user_role_assignments
                WHERE role_key='platform.super_admin'
                  AND status='ACTIVE'
                  AND (
                    :approved_user_id IS NULL
                    OR user_id<>CAST(:approved_user_id AS uuid)
                  )
                LIMIT 1
                """
            ),
            params,
        ).first()
        if legacy_conflict is not None:
            raise RuntimeError(
                "A different active Platform Super Admin already exists; provisioning will not replace it"
            )

        v2_conflict = self.s.execute(
            text(
                """
                SELECT 1
                FROM security.user_admin_role_assignments
                WHERE role_key='SuperAdmin'
                  AND status='ACTIVE'
                  AND (
                    :approved_user_id IS NULL
                    OR user_id<>CAST(:approved_user_id AS uuid)
                  )
                LIMIT 1
                """
            ),
            params,
        ).first()
        if v2_conflict is not None:
            raise RuntimeError(
                "A different active v2 SuperAdmin already exists; provisioning will not replace it"
            )

    def _has_active_operating_role(self, user_id: str) -> bool:
        return (
            self.s.execute(
                text(
                    """
                    SELECT 1
                    FROM security.user_tenant_operating_roles
                    WHERE user_id=:user_id AND status='ACTIVE'
                    LIMIT 1
                    """
                ),
                {"user_id": user_id},
            ).first()
            is not None
        )

    def _ensure_super_admin_assignments(self, *, user_id: str, now: datetime) -> bool:
        changed = False
        if not self._active_legacy_super_admin_for_user(user_id):
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
            changed = True

        if not self._active_v2_super_admin_for_user(user_id):
            self.s.execute(
                text(
                    """
                    INSERT INTO security.user_admin_role_assignments
                    (assignment_id,user_id,role_key,scope_type,scope_id,status,
                     assigned_by_user_id,assigned_at_utc)
                    VALUES (:assignment_id,:user_id,'SuperAdmin','PLATFORM',NULL,'ACTIVE',NULL,:now)
                    """
                ),
                {"assignment_id": str(uuid4()), "user_id": user_id, "now": now},
            )
            changed = True
        return changed

    def _active_legacy_super_admin_for_user(self, user_id: str) -> bool:
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

    def _active_v2_super_admin_for_user(self, user_id: str) -> bool:
        return (
            self.s.execute(
                text(
                    """
                    SELECT 1
                    FROM security.user_admin_role_assignments
                    WHERE user_id=:user_id
                      AND role_key='SuperAdmin'
                      AND status='ACTIVE'
                    LIMIT 1
                    """
                ),
                {"user_id": user_id},
            ).first()
            is not None
        )

    def _insert_audit(
        self,
        *,
        user_id: str,
        subject: str,
        provisioning_mode: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.admin_change_records
                (admin_change_id,correlation_id,scope_type,tenant_id,actor_user_id,
                 operation_key,resource_type,resource_id,outcome,before_state_json,
                 after_state_json,occurred_at_utc)
                VALUES (:change_id,:correlation_id,'PLATFORM',NULL,:user_id,
                        :operation_key,'platform_user',:resource_id,'SUCCESS',NULL,
                        CAST(:after_state AS jsonb),:now)
                """
            ),
            {
                "change_id": str(uuid4()),
                "correlation_id": str(uuid4()),
                "user_id": user_id,
                "resource_id": user_id,
                "operation_key": self._OPERATION_KEY,
                "after_state": json.dumps(
                    {
                        "identityProvider": "CLERK",
                        "providerSubject": subject,
                        "legacyPlatformRole": "platform.super_admin",
                        "v2AdminRole": "SuperAdmin",
                        "scopeType": "PLATFORM",
                        "provisioningMode": provisioning_mode,
                    }
                ),
                "now": now,
            },
        )
