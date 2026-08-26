from __future__ import annotations

import json
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

from sqlalchemy.orm import Session

from verigence_security.repositories.platform_admin_repository import PlatformAdminRepository
from verigence_security.repositories.security_housekeeping_repository import SecurityHousekeepingRepository


class SecurityHousekeepingService:
    def __init__(self, session: Session) -> None:
        self.repository = SecurityHousekeepingRepository(session)
        self.admin_repository = PlatformAdminRepository(session)

    @staticmethod
    def _cutoff_exclusive_utc(cutoff_date: date) -> datetime:
        return datetime.combine(cutoff_date + timedelta(days=1), time.min, tzinfo=UTC)

    @staticmethod
    def _validate_cutoff(cutoff_date: date) -> None:
        if cutoff_date > datetime.now(UTC).date():
            raise ValueError("Cutoff date cannot be in the future")

    def preview(self, *, tenant_id: str, cutoff_date: date) -> dict[str, Any] | None:
        self._validate_cutoff(cutoff_date)
        cutoff_exclusive_utc = self._cutoff_exclusive_utc(cutoff_date)
        row = self.repository.preview(
            tenant_id=tenant_id,
            cutoff_exclusive_utc=cutoff_exclusive_utc,
        )
        if row is None:
            return None
        return self._preview_response(
            row=row,
            cutoff_date=cutoff_date,
            cutoff_exclusive_utc=cutoff_exclusive_utc,
        )

    def purge(
        self,
        *,
        actor_user_id: str,
        tenant_id: str,
        cutoff_date: date,
        correlation_id: str,
    ) -> dict[str, Any] | None:
        self._validate_cutoff(cutoff_date)
        cutoff_exclusive_utc = self._cutoff_exclusive_utc(cutoff_date)
        before = self.repository.preview(
            tenant_id=tenant_id,
            cutoff_exclusive_utc=cutoff_exclusive_utc,
        )
        if before is None:
            return None

        now = datetime.now(UTC)
        try:
            deleted = self.repository.purge(
                tenant_id=tenant_id,
                cutoff_exclusive_utc=cutoff_exclusive_utc,
            )
            self.repository.insert_purge_event(
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
                cutoff_date=cutoff_date.isoformat(),
                deleted=deleted,
                now=now,
            )
            self.admin_repository.insert_admin_change(
                correlation_id=correlation_id,
                actor_user_id=actor_user_id,
                operation_key="platform.security_housekeeping.manual_cutoff",
                resource_type="security_operational_history",
                resource_id=tenant_id,
                outcome="SUCCESS",
                tenant_id=tenant_id,
                before_state_json=json.dumps(
                    {
                        "cutoffDate": cutoff_date.isoformat(),
                        "eligible": {
                            "accessContextEvaluations": int(before["eligible_access_contexts"]),
                            "accessSessions": int(before["eligible_access_sessions"]),
                            "securityEvents": int(before["eligible_security_events"]),
                        },
                    }
                ),
                after_state_json=json.dumps(
                    {
                        "cutoffDate": cutoff_date.isoformat(),
                        "deleted": {
                            "accessContextEvaluations": deleted["access_context_evaluations"],
                            "accessSessions": deleted["access_sessions"],
                            "securityEvents": deleted["security_events"],
                        },
                    }
                ),
                now=now,
            )
            self.repository.commit()
        except Exception:
            self.repository.rollback()
            raise

        return {
            "tenantId": tenant_id,
            "cutoffDate": cutoff_date,
            "deleted": {
                "accessContextEvaluations": deleted["access_context_evaluations"],
                "accessSessions": deleted["access_sessions"],
                "securityEvents": deleted["security_events"],
            },
            "completedAtUtc": now,
        }

    @staticmethod
    def _preview_response(
        *,
        row: dict[str, Any],
        cutoff_date: date,
        cutoff_exclusive_utc: datetime,
    ) -> dict[str, Any]:
        return {
            "tenantId": str(row["tenant_id"]),
            "cutoffDate": cutoff_date,
            "cutoffExclusiveUtc": cutoff_exclusive_utc,
            "total": {
                "accessContextEvaluations": int(row["total_access_contexts"]),
                "accessSessions": int(row["total_access_sessions"]),
                "securityEvents": int(row["total_security_events"]),
            },
            "eligible": {
                "accessContextEvaluations": int(row["eligible_access_contexts"]),
                "accessSessions": int(row["eligible_access_sessions"]),
                "securityEvents": int(row["eligible_security_events"]),
            },
            "retentionPolicy": {
                "status": row["retention_status"],
                "accessContextRetentionDays": row["access_context_retention_days"],
                "accessSessionRetentionDays": row["access_session_retention_days"],
                "securityEventRetentionDays": row["security_event_retention_days"],
            },
        }
