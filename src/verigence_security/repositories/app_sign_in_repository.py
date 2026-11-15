from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


class AppSignInRepository:
    """One-time codes that sign a person in to another Verigence app from the Verigence app.

    Only the code's hash is stored; a code is taken once, atomically.
    """

    def __init__(self, session: Session) -> None:
        self.s = session

    def create(
        self,
        *,
        code_hash: str,
        user_id: str,
        client_key: str,
        redirect_uri: str,
        code_challenge: str,
        from_session_id: str | None,
        from_device_id: str | None,
        now: datetime,
        expires_at: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.app_sign_in_codes
                  (code_hash,user_id,client_key,redirect_uri,code_challenge,from_session_id,from_device_id,
                   created_at_utc,expires_at_utc,used_at_utc)
                VALUES
                  (:code_hash,:user_id,:client_key,:redirect_uri,:code_challenge,:from_session_id,:from_device_id,
                   :now,:expires_at,NULL)
                """
            ),
            {
                "code_hash": code_hash,
                "user_id": user_id,
                "client_key": client_key,
                "redirect_uri": redirect_uri,
                "code_challenge": code_challenge,
                "from_session_id": from_session_id,
                "from_device_id": from_device_id,
                "now": now,
                "expires_at": expires_at,
            },
        )
        # Codes older than a day are of no use to anyone.
        self.s.execute(
            text("DELETE FROM security.app_sign_in_codes WHERE user_id=:user_id AND created_at_utc < :before"),
            {"user_id": user_id, "before": now - timedelta(days=1)},
        )

    def take(self, *, code_hash: str, now: datetime) -> dict[str, Any] | None:
        """Marks the code used and returns it; None when it is unknown, used or expired."""
        row = (
            self.s.execute(
                text(
                    """
                    UPDATE security.app_sign_in_codes
                    SET used_at_utc=:now
                    WHERE code_hash=:code_hash AND used_at_utc IS NULL AND expires_at_utc > :now
                    RETURNING user_id,client_key,redirect_uri,code_challenge
                    """
                ),
                {"code_hash": code_hash, "now": now},
            )
            .mappings()
            .first()
        )
        return dict(row) if row else None

    def email_of(self, user_id: str) -> str | None:
        row = self.s.execute(
            text("SELECT primary_email FROM security.users WHERE user_id=:user_id"),
            {"user_id": user_id},
        ).first()
        return str(row[0]) if row and row[0] else None
