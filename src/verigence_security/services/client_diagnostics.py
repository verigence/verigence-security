from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

from sqlalchemy import CursorResult, text
from sqlalchemy.orm import Session

KEEP_DAYS = 14
MIN_SECONDS_BETWEEN_UPLOADS = 60
MAX_ENTRIES = 100
MAX_BYTES = 40_000


class ClientDiagnosticsService:
    """Optional device logs: a SuperAdmin switch (off by default), a place for signed-in apps to send
    their on-device log while it is on, and a list for SuperAdmin to read. Nothing is stored while off."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def enabled(self) -> bool:
        value = self.session.execute(
            text("SELECT enabled FROM security.client_diagnostics_settings WHERE singleton")
        ).scalar_one_or_none()
        return bool(value)

    def set_enabled(self, *, enabled: bool, actor_user_id: str, correlation_id: str) -> None:
        now = datetime.now(UTC)
        before = self.enabled()
        try:
            self.session.execute(
                text(
                    "INSERT INTO security.client_diagnostics_settings (singleton,enabled,updated_by_user_id)"
                    " VALUES (true,:e,CAST(:a AS uuid))"
                    " ON CONFLICT (singleton) DO UPDATE SET enabled=EXCLUDED.enabled,"
                    " updated_by_user_id=EXCLUDED.updated_by_user_id, updated_at_utc=CURRENT_TIMESTAMP"
                ),
                {"e": enabled, "a": actor_user_id},
            )
            self._audit({"enabled": before}, {"enabled": enabled}, actor_user_id, correlation_id, now)
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise

    def accept(
        self,
        *,
        user_id: str,
        device_id: str,
        platform: str | None,
        app_version: str | None,
        entries: list[dict[str, Any]],
    ) -> bool:
        """Stores one upload and returns True; returns False, storing nothing, when diagnostics are off,
        the device sent a moment ago, or there is nothing to keep."""
        if not entries or len(entries) > MAX_ENTRIES or not self.enabled():
            return False
        payload = json.dumps(entries, default=str)
        if len(payload.encode()) > MAX_BYTES:
            return False
        try:
            recent = self.session.execute(
                text(
                    "SELECT 1 FROM security.client_diagnostic_logs WHERE device_id=:d"
                    " AND received_at_utc > now() - make_interval(secs => :s)"
                ),
                {"d": device_id, "s": MIN_SECONDS_BETWEEN_UPLOADS},
            ).first()
            if recent is not None:
                self.session.rollback()
                return False
            self.session.execute(
                text(
                    "INSERT INTO security.client_diagnostic_logs"
                    " (log_id,user_id,device_id,platform,app_version,entry_count,entries)"
                    " VALUES (CAST(:id AS uuid),CAST(:u AS uuid),:d,:p,:v,:n,CAST(:e AS jsonb))"
                ),
                {
                    "id": str(uuid4()),
                    "u": user_id,
                    "d": device_id,
                    "p": platform,
                    "v": app_version,
                    "n": len(entries),
                    "e": payload,
                },
            )
            self.session.execute(
                text(
                    "DELETE FROM security.client_diagnostic_logs"
                    " WHERE received_at_utc < now() - make_interval(days => :k)"
                ),
                {"k": KEEP_DAYS},
            )
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise
        return True

    def listing(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.session.execute(
            text(
                "SELECT l.log_id, l.device_id, l.platform, l.app_version, l.entry_count, l.entries,"
                " l.received_at_utc, u.display_name, u.primary_email"
                " FROM security.client_diagnostic_logs l JOIN security.users u ON u.user_id = l.user_id"
                " ORDER BY l.received_at_utc DESC LIMIT :n"
            ),
            {"n": max(1, min(limit, 200))},
        ).all()
        return [
            {
                "logId": str(r[0]),
                "deviceId": r[1],
                "platform": r[2],
                "appVersion": r[3],
                "entryCount": int(r[4]),
                "entries": r[5],
                "receivedAt": r[6].isoformat(),
                "person": r[7] or r[8],
            }
            for r in rows
        ]

    def clear(self, *, actor_user_id: str, correlation_id: str) -> int:
        now = datetime.now(UTC)
        try:
            result = cast(CursorResult[Any], self.session.execute(text("DELETE FROM security.client_diagnostic_logs")))
            removed = result.rowcount or 0
            self._audit({"logs": int(removed)}, {"logs": 0}, actor_user_id, correlation_id, now)
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise
        return int(removed)

    def _audit(
        self, before: dict[str, Any], after: dict[str, Any], actor_user_id: str, correlation_id: str, now: datetime
    ) -> None:
        self.session.execute(
            text(
                """
                INSERT INTO security.admin_change_records (
                    admin_change_id,correlation_id,scope_type,tenant_id,actor_user_id,
                    operation_key,resource_type,resource_id,outcome,
                    before_state_json,after_state_json,occurred_at_utc
                ) VALUES (
                    CAST(:id AS uuid),:corr,'PLATFORM',NULL,CAST(:actor AS uuid),
                    'security.client_diagnostics.manage','CLIENT_DIAGNOSTICS','device-diagnostics',
                    'SUCCESS',CAST(:before AS jsonb),CAST(:after AS jsonb),:now
                )
                """
            ),
            {
                "id": str(uuid4()),
                "corr": correlation_id,
                "actor": actor_user_id,
                "before": json.dumps(before),
                "after": json.dumps(after),
                "now": now,
            },
        )
