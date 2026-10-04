from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

FeatureKey = Literal["AUDIT", "ANALYTICS"]
FEATURE_KEYS: tuple[FeatureKey, ...] = ("AUDIT", "ANALYTICS")


class FeatureAccessService:
    """Which sections of the apps a person may see. A section is hidden until it is switched on
    for everyone or for that person; a person's own setting wins over the setting for everyone."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def resolve(self, *, user_id: str, is_super_admin: bool) -> dict[str, bool]:
        if is_super_admin:
            return {key: True for key in FEATURE_KEYS}
        rows = self.session.execute(
            text(
                """
                SELECT feature_key, user_id IS NOT NULL AS personal, enabled
                FROM security.feature_access
                WHERE user_id IS NULL OR user_id=CAST(:user_id AS uuid)
                """
            ),
            {"user_id": user_id},
        ).all()
        everyone: dict[str, bool] = {}
        own: dict[str, bool] = {}
        for key, personal, enabled in rows:
            (own if personal else everyone)[str(key)] = bool(enabled)
        return {key: own.get(key, everyone.get(key, False)) for key in FEATURE_KEYS}

    def overview(self) -> list[dict[str, object]]:
        rows = self.session.execute(
            text(
                """
                SELECT f.feature_key, f.user_id, f.enabled, u.display_name, u.primary_email
                FROM security.feature_access f
                LEFT JOIN security.users u ON u.user_id=f.user_id
                ORDER BY f.feature_key, u.display_name
                """
            )
        ).all()
        out: list[dict[str, object]] = []
        for key in FEATURE_KEYS:
            mine = [r for r in rows if r[0] == key]
            everyone = next((bool(r[2]) for r in mine if r[1] is None), False)
            out.append(
                {
                    "featureKey": key,
                    "everyone": everyone,
                    "people": [
                        {
                            "userId": str(r[1]),
                            "displayName": r[3],
                            "email": r[4],
                            "enabled": bool(r[2]),
                        }
                        for r in mine
                        if r[1] is not None
                    ],
                }
            )
        return out

    def set_everyone(self, *, feature_key: str, enabled: bool, actor_user_id: str, correlation_id: str) -> None:
        self._require_known(feature_key)
        self._write(feature_key, None, enabled, actor_user_id, correlation_id)

    def set_person(
        self,
        *,
        feature_key: str,
        user_id: str,
        enabled: bool | None,
        actor_user_id: str,
        correlation_id: str,
    ) -> None:
        """enabled True or False sets this person's own choice; None removes it, so the setting
        for everyone applies again."""
        self._require_known(feature_key)
        known = self.session.execute(
            text("SELECT 1 FROM security.users WHERE user_id=CAST(:u AS uuid) AND status='ACTIVE'"),
            {"u": user_id},
        ).first()
        if known is None:
            raise ValueError("The person must be an active Verigence user")
        self._write(feature_key, user_id, enabled, actor_user_id, correlation_id)

    @staticmethod
    def _require_known(feature_key: str) -> None:
        if feature_key not in FEATURE_KEYS:
            raise ValueError("Unknown feature")

    def _write(
        self,
        feature_key: str,
        user_id: str | None,
        enabled: bool | None,
        actor_user_id: str,
        correlation_id: str,
    ) -> None:
        now = datetime.now(UTC)
        params = {"k": feature_key, "u": user_id, "a": actor_user_id, "now": now}
        try:
            before = self.session.execute(
                text(
                    "SELECT enabled FROM security.feature_access WHERE feature_key=:k"
                    " AND user_id IS NOT DISTINCT FROM CAST(:u AS uuid)"
                ),
                params,
            ).scalar_one_or_none()
            if enabled is None:
                self.session.execute(
                    text(
                        "DELETE FROM security.feature_access WHERE feature_key=:k"
                        " AND user_id IS NOT DISTINCT FROM CAST(:u AS uuid)"
                    ),
                    params,
                )
            else:
                self.session.execute(
                    text(
                        """
                        INSERT INTO security.feature_access
                            (feature_key,user_id,enabled,updated_by_user_id,updated_at_utc)
                        VALUES (:k,CAST(:u AS uuid),:e,CAST(:a AS uuid),:now)
                        ON CONFLICT (feature_key,
                            COALESCE(user_id,'00000000-0000-0000-0000-000000000000'::uuid))
                        DO UPDATE SET enabled=EXCLUDED.enabled,
                            updated_by_user_id=EXCLUDED.updated_by_user_id,
                            updated_at_utc=EXCLUDED.updated_at_utc
                        """
                    ),
                    {**params, "e": enabled},
                )
            self._audit(feature_key, user_id, before, enabled, actor_user_id, correlation_id, now)
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise

    def _audit(
        self,
        feature_key: str,
        user_id: str | None,
        before: bool | None,
        after: bool | None,
        actor_user_id: str,
        correlation_id: str,
        now: datetime,
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
                    'security.feature_access.manage','FEATURE_ACCESS',:resource,
                    'SUCCESS',CAST(:before AS jsonb),CAST(:after AS jsonb),:now
                )
                """
            ),
            {
                "id": str(uuid4()),
                "corr": correlation_id,
                "actor": actor_user_id,
                "resource": f"{feature_key}:{user_id or 'everyone'}",
                "before": json.dumps({"enabled": before}) if before is not None else None,
                "after": json.dumps({"enabled": after}) if after is not None else None,
                "now": now,
            },
        )
