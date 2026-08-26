from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session


class SecurityHousekeepingRepository:
    def __init__(self, session: Session) -> None:
        self.s = session

    def preview(self, *, tenant_id: str, cutoff_exclusive_utc: datetime) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT
                    t.tenant_id,
                    rp.status AS retention_status,
                    rp.access_context_retention_days,
                    rp.access_session_retention_days,
                    rp.security_event_retention_days,
                    (SELECT count(*) FROM security.access_context_evaluations e
                     WHERE e.tenant_id=t.tenant_id) AS total_access_contexts,
                    (SELECT count(*) FROM security.access_context_evaluations e
                     WHERE e.tenant_id=t.tenant_id
                       AND e.evaluated_at_utc < :cutoff_exclusive_utc) AS eligible_access_contexts,
                    (SELECT count(*) FROM security.access_sessions s
                     WHERE s.tenant_id=t.tenant_id) AS total_access_sessions,
                    (SELECT count(*) FROM security.access_sessions s
                     WHERE s.tenant_id=t.tenant_id
                       AND s.last_activity_at_utc < :cutoff_exclusive_utc) AS eligible_access_sessions,
                    (SELECT count(*) FROM security.security_events se
                     WHERE se.tenant_id=t.tenant_id) AS total_security_events,
                    (SELECT count(*) FROM security.security_events se
                     WHERE se.tenant_id=t.tenant_id
                       AND se.occurred_at_utc < :cutoff_exclusive_utc) AS eligible_security_events
                FROM security.tenants t
                LEFT JOIN security.security_retention_policies rp
                  ON rp.tenant_id=t.tenant_id
                WHERE t.tenant_id=CAST(:tenant_id AS uuid)
                """
            ),
            {
                "tenant_id": tenant_id,
                "cutoff_exclusive_utc": cutoff_exclusive_utc,
            },
        ).mappings().first()
        return dict(row) if row else None

    def purge(self, *, tenant_id: str, cutoff_exclusive_utc: datetime) -> dict[str, int]:
        params = {
            "tenant_id": tenant_id,
            "cutoff_exclusive_utc": cutoff_exclusive_utc,
        }

        access_context_result = self.s.execute(
            text(
                """
                DELETE FROM security.access_context_evaluations
                WHERE tenant_id=CAST(:tenant_id AS uuid)
                  AND evaluated_at_utc < :cutoff_exclusive_utc
                """
            ),
            params,
        )
        access_session_result = self.s.execute(
            text(
                """
                DELETE FROM security.access_sessions
                WHERE tenant_id=CAST(:tenant_id AS uuid)
                  AND last_activity_at_utc < :cutoff_exclusive_utc
                """
            ),
            params,
        )
        security_event_result = self.s.execute(
            text(
                """
                DELETE FROM security.security_events
                WHERE tenant_id=CAST(:tenant_id AS uuid)
                  AND occurred_at_utc < :cutoff_exclusive_utc
                """
            ),
            params,
        )

        return {
            "access_context_evaluations": int(access_context_result.rowcount or 0),
            "access_sessions": int(access_session_result.rowcount or 0),
            "security_events": int(security_event_result.rowcount or 0),
        }

    def insert_purge_event(
        self,
        *,
        tenant_id: str,
        actor_user_id: str,
        correlation_id: str,
        cutoff_date: str,
        deleted: dict[str, int],
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.security_events
                (security_event_id,tenant_id,principal_id,actor_type,event_type,
                 entity_type,entity_id,outcome,reason_code,correlation_id,payload_json,
                 occurred_at_utc)
                VALUES
                (:security_event_id,CAST(:tenant_id AS uuid),CAST(:actor_user_id AS uuid),'USER',
                 'SECURITY_MANUAL_HOUSEKEEPING_PURGE','TENANT',:tenant_id,'SUCCESS',
                 'SUPER_ADMIN_MANUAL_CUTOFF',:correlation_id,CAST(:payload_json AS jsonb),:now)
                """
            ),
            {
                "security_event_id": str(uuid4()),
                "tenant_id": tenant_id,
                "actor_user_id": actor_user_id,
                "correlation_id": correlation_id,
                "payload_json": json.dumps(
                    {
                        "cutoffDate": cutoff_date,
                        "deletedAccessContextEvaluations": deleted["access_context_evaluations"],
                        "deletedAccessSessions": deleted["access_sessions"],
                        "deletedSecurityEvents": deleted["security_events"],
                        "mode": "SUPER_ADMIN_MANUAL_CUTOFF",
                    }
                ),
                "now": now,
            },
        )

    def commit(self) -> None:
        self.s.commit()

    def rollback(self) -> None:
        self.s.rollback()
