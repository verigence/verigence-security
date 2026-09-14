from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


class HumanRememberRepository:
    """Persistence for long-lived, opaque human resume credentials.

    Only token hashes are stored. A single previous hash is retained so immediate replay of a
    rotated credential can be detected and the token family revoked without keeping raw secrets.
    """

    def __init__(self, session: Session) -> None:
        self.s = session

    def replace_for_login(
        self,
        *,
        user_id: str,
        session_id: str,
        device_id: str,
        token_hash: str,
        expires_at: datetime,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                UPDATE security.human_remember_sessions
                SET status='REVOKED',revoked_at_utc=:now
                WHERE user_id=:user_id AND status='ACTIVE'
                """
            ),
            {"user_id": user_id, "now": now},
        )
        self.s.execute(
            text(
                """
                INSERT INTO security.human_remember_sessions
                  (access_session_id,user_id,device_id,token_hash,previous_token_hash,status,
                   created_at_utc,expires_at_utc,last_used_at_utc,revoked_at_utc)
                VALUES
                  (:session_id,:user_id,:device_id,:token_hash,NULL,'ACTIVE',
                   :now,:expires_at,:now,NULL)
                """
            ),
            {
                "session_id": session_id,
                "user_id": user_id,
                "device_id": device_id,
                "token_hash": token_hash,
                "now": now,
                "expires_at": expires_at,
            },
        )
        self.s.commit()

    def revoke_active_for_user(self, *, user_id: str, now: datetime) -> None:
        self.s.execute(
            text(
                """
                UPDATE security.human_remember_sessions
                SET status='REVOKED',revoked_at_utc=:now
                WHERE user_id=:user_id AND status='ACTIVE'
                """
            ),
            {"user_id": user_id, "now": now},
        )
        self.s.commit()

    def lock_by_hash(self, *, token_hash: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT access_session_id,user_id,device_id,token_hash,previous_token_hash,status,
                       created_at_utc,expires_at_utc,last_used_at_utc
                FROM security.human_remember_sessions
                WHERE token_hash=:token_hash OR previous_token_hash=:token_hash
                FOR UPDATE
                """
            ),
            {"token_hash": token_hash},
        ).mappings().first()
        return dict(row) if row is not None else None

    def rotate(
        self,
        *,
        session_id: str,
        new_token_hash: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                UPDATE security.human_remember_sessions
                SET previous_token_hash=token_hash,
                    token_hash=:new_token_hash,
                    last_used_at_utc=:now
                WHERE access_session_id=:session_id AND status='ACTIVE'
                """
            ),
            {
                "session_id": session_id,
                "new_token_hash": new_token_hash,
                "now": now,
            },
        )
        self.s.commit()

    def revoke_session(self, *, session_id: str, now: datetime) -> None:
        self.s.execute(
            text(
                """
                UPDATE security.human_remember_sessions
                SET status='REVOKED',revoked_at_utc=:now
                WHERE access_session_id=:session_id AND status='ACTIVE'
                """
            ),
            {"session_id": session_id, "now": now},
        )
        self.s.commit()

    def revoke_by_hash(self, *, token_hash: str, now: datetime) -> None:
        self.s.execute(
            text(
                """
                UPDATE security.human_remember_sessions
                SET status='REVOKED',revoked_at_utc=:now
                WHERE status='ACTIVE'
                  AND (token_hash=:token_hash OR previous_token_hash=:token_hash)
                """
            ),
            {"token_hash": token_hash, "now": now},
        )
        self.s.commit()
