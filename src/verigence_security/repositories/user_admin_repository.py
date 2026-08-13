from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


class UserAdminRepository:
    def __init__(self, session: Session) -> None:
        self.s = session

    def principal(self, principal_id: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT * FROM security.security_principals
                WHERE principal_id=:principal_id
                """
            ),
            {"principal_id": principal_id},
        ).mappings().first()
        return dict(row) if row else None

    def create_user_principal_if_absent(
        self,
        *,
        user_id: str,
        principal_name: str,
        principal_status: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.security_principals
                (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                VALUES (:user_id,'USER',:principal_name,:principal_status,:now,:now)
                ON CONFLICT (principal_id) DO NOTHING
                """
            ),
            {
                "user_id": user_id,
                "principal_name": principal_name,
                "principal_status": principal_status,
                "now": now,
            },
        )

    def update_user_principal(
        self,
        *,
        user_id: str,
        principal_name: str,
        principal_status: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                UPDATE security.security_principals
                SET principal_name=:principal_name,status=:principal_status,
                    updated_at_utc=:now
                WHERE principal_id=:user_id AND actor_type='USER'
                """
            ),
            {
                "user_id": user_id,
                "principal_name": principal_name,
                "principal_status": principal_status,
                "now": now,
            },
        )

    def upsert_user(
        self,
        *,
        user_id: str,
        display_name: str,
        primary_email: str | None,
        primary_mobile: str | None,
        user_status: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.users
                (user_id,display_name,primary_email,primary_mobile,status,
                 created_at_utc,updated_at_utc)
                VALUES
                (:user_id,:display_name,:primary_email,:primary_mobile,:user_status,:now,:now)
                ON CONFLICT (user_id) DO UPDATE SET
                  display_name=EXCLUDED.display_name,
                  primary_email=EXCLUDED.primary_email,
                  primary_mobile=EXCLUDED.primary_mobile,
                  status=EXCLUDED.status,
                  updated_at_utc=EXCLUDED.updated_at_utc
                """
            ),
            {
                "user_id": user_id,
                "display_name": display_name,
                "primary_email": primary_email,
                "primary_mobile": primary_mobile,
                "user_status": user_status,
                "now": now,
            },
        )

    def external_identity(
        self,
        *,
        provider: str,
        provider_subject: str,
    ) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT * FROM security.external_identities
                WHERE provider=:provider AND provider_subject=:provider_subject
                """
            ),
            {"provider": provider, "provider_subject": provider_subject},
        ).mappings().first()
        return dict(row) if row else None

    def upsert_external_identity(
        self,
        *,
        external_identity_id: str,
        user_id: str,
        provider: str,
        provider_subject: str,
        status: str,
        linked_at: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.external_identities
                (external_identity_id,user_id,provider,provider_subject,status,linked_at_utc)
                VALUES
                (:external_identity_id,:user_id,:provider,:provider_subject,:status,:linked_at)
                ON CONFLICT (provider,provider_subject) DO UPDATE SET
                  status=EXCLUDED.status
                WHERE security.external_identities.user_id=EXCLUDED.user_id
                """
            ),
            {
                "external_identity_id": external_identity_id,
                "user_id": user_id,
                "provider": provider,
                "provider_subject": provider_subject,
                "status": status,
                "linked_at": linked_at,
            },
        )

    def commit(self) -> None:
        self.s.commit()

    def rollback(self) -> None:
        self.s.rollback()
