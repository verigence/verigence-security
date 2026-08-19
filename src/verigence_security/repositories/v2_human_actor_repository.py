from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


class V2HumanActorRepository:
    """Persistence for Phase-1 human actor resolution.

    Active v2 routes resolve the global USER identified by a Security-issued human token.
    The Clerk mapping is read only from Security-owned state so lifecycle operations can still
    call Clerk through Security when required. Legacy external-identity lookup is retained for
    compatibility code and tests; it is not the active v2 route trust boundary.
    """

    def __init__(self, session: Session) -> None:
        self.s = session

    def human_for_user_id(self, user_id: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT u.user_id,
                       u.status AS user_status,
                       sp.actor_type AS principal_actor_type,
                       sp.status AS principal_status,
                       ei.provider_subject AS clerk_subject,
                       ei.status AS identity_status
                FROM security.users u
                JOIN security.security_principals sp ON sp.principal_id=u.user_id
                JOIN security.external_identities ei
                  ON ei.user_id=u.user_id AND ei.provider='CLERK'
                WHERE u.user_id=:user_id
                """
            ),
            {"user_id": user_id},
        ).mappings().first()
        return dict(row) if row else None

    def human_for_external_identity(
        self,
        *,
        provider: str,
        provider_subject: str,
    ) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT ei.status AS identity_status,
                       u.user_id,
                       u.status AS user_status,
                       sp.actor_type AS principal_actor_type,
                       sp.status AS principal_status
                FROM security.external_identities ei
                JOIN security.users u ON u.user_id=ei.user_id
                JOIN security.security_principals sp ON sp.principal_id=u.user_id
                WHERE ei.provider=:provider
                  AND ei.provider_subject=:provider_subject
                """
            ),
            {"provider": provider, "provider_subject": provider_subject},
        ).mappings().first()
        return dict(row) if row else None

    def active_admin_assignments(self, user_id: str) -> list[dict[str, Any]]:
        rows = self.s.execute(
            text(
                """
                SELECT assignment_id,role_key,scope_type,scope_id
                FROM security.user_admin_role_assignments
                WHERE user_id=:user_id AND status='ACTIVE'
                ORDER BY role_key,scope_id NULLS FIRST
                """
            ),
            {"user_id": user_id},
        ).mappings()
        return [dict(row) for row in rows]
