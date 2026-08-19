from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


class V2HumanActorRepository:
    """Persistence for Clerk-authenticated Phase-1 human actor resolution.

    This repository reads the global USER/external identity registry and the new v2
    administrative assignments. It does not consult legacy Platform/Tenant role
    assignments or Group-derived authorization.
    """

    def __init__(self, session: Session) -> None:
        self.s = session

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
