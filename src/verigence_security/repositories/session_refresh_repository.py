from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


class SessionRefreshRepository:
    """PostgreSQL persistence used by the approved USER refresh lifecycle."""

    def __init__(self, session: Session) -> None:
        self.s = session

    def user_session(
        self,
        *,
        access_session_id: str,
        tenant_id: str,
        user_id: str,
    ) -> dict[str, Any] | None:
        """Read session identity/context before entering the canonical device→session lock order."""
        row = self.s.execute(
            text(
                """
                SELECT *
                FROM security.access_sessions
                WHERE access_session_id=:access_session_id
                  AND tenant_id=:tenant_id
                  AND principal_id=:user_id
                  AND actor_type='USER'
                """
            ),
            {
                "access_session_id": access_session_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
            },
        ).mappings().first()
        return dict(row) if row else None

    def user_session_for_update(
        self,
        *,
        access_session_id: str,
        tenant_id: str,
        user_id: str,
    ) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT *
                FROM security.access_sessions
                WHERE access_session_id=:access_session_id
                  AND tenant_id=:tenant_id
                  AND principal_id=:user_id
                  AND actor_type='USER'
                FOR UPDATE
                """
            ),
            {
                "access_session_id": access_session_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
            },
        ).mappings().first()
        return dict(row) if row else None

    def update_active_session_context(
        self,
        *,
        access_session_id: str,
        tenant_id: str,
        user_id: str,
        location_id: str,
        source_ip: str,
        vpn_status: str,
        authorization_version: int,
        expires_at: datetime,
        now: datetime,
    ) -> bool:
        row = self.s.execute(
            text(
                """
                UPDATE security.access_sessions
                SET location_id=:location_id,
                    source_ip=:source_ip,
                    vpn_status=:vpn_status,
                    authorization_version=:authorization_version,
                    expires_at_utc=:expires_at,
                    last_activity_at_utc=:now,
                    last_geo_validated_at_utc=:now
                WHERE access_session_id=:access_session_id
                  AND tenant_id=:tenant_id
                  AND principal_id=:user_id
                  AND actor_type='USER'
                  AND status='ACTIVE'
                RETURNING access_session_id
                """
            ),
            {
                "access_session_id": access_session_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "location_id": location_id,
                "source_ip": source_ip,
                "vpn_status": vpn_status,
                "authorization_version": authorization_version,
                "expires_at": expires_at,
                "now": now,
            },
        ).first()
        return row is not None

    def record_evaluation(self, payload: dict[str, Any]) -> None:
        columns = ",".join(payload)
        values = ",".join(f":{key}" for key in payload)
        self.s.execute(
            text(f"INSERT INTO security.access_context_evaluations ({columns}) VALUES ({values})"),
            payload,
        )

    def commit(self) -> None:
        self.s.commit()

    def rollback(self) -> None:
        self.s.rollback()
