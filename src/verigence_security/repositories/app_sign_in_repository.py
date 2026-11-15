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


class AppRememberRepository:
    """Long-lived sign-ins another Verigence app's server keeps for a person (hash only, bound to the app)."""

    def __init__(self, session: Session) -> None:
        self.s = session

    def create(
        self,
        *,
        credential_hash: str,
        user_id: str,
        client_key: str,
        session_id: str,
        device_id: str,
        now: datetime,
        expires_at: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.app_remember_sessions
                  (credential_hash,user_id,client_key,session_id,device_id,created_at_utc,expires_at_utc,
                   last_used_at_utc,revoked_at_utc)
                VALUES (:credential_hash,:user_id,:client_key,:session_id,:device_id,:now,:expires_at,:now,NULL)
                """
            ),
            {
                "credential_hash": credential_hash,
                "user_id": user_id,
                "client_key": client_key,
                "session_id": session_id,
                "device_id": device_id,
                "now": now,
                "expires_at": expires_at,
            },
        )
        # Ended ones are of no use: kept a week for the record, then gone.
        self.s.execute(
            text(
                "DELETE FROM security.app_remember_sessions WHERE user_id=:user_id "
                "AND (expires_at_utc < :before OR revoked_at_utc < :before)"
            ),
            {"user_id": user_id, "before": now - timedelta(days=7)},
        )

    def use(self, *, credential_hash: str, client_key: str, now: datetime) -> dict[str, Any] | None:
        """The live credential (not ended, not revoked, this app's), marked used; None otherwise."""
        row = (
            self.s.execute(
                text(
                    """
                    UPDATE security.app_remember_sessions
                    SET last_used_at_utc=:now
                    WHERE credential_hash=:credential_hash AND client_key=:client_key
                      AND revoked_at_utc IS NULL AND expires_at_utc > :now
                    RETURNING user_id,session_id,device_id,expires_at_utc
                    """
                ),
                {"credential_hash": credential_hash, "client_key": client_key, "now": now},
            )
            .mappings()
            .first()
        )
        return dict(row) if row else None

    def revoke(self, *, credential_hash: str, client_key: str, now: datetime) -> None:
        self.s.execute(
            text(
                "UPDATE security.app_remember_sessions SET revoked_at_utc=:now "
                "WHERE credential_hash=:credential_hash AND client_key=:client_key AND revoked_at_utc IS NULL"
            ),
            {"credential_hash": credential_hash, "client_key": client_key, "now": now},
        )
