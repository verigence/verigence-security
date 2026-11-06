"""Night control (product owner, 6 Nov 2026).

From 20:00 to 08:30 IST nobody may open Journey 360 or download any Verigence file, unless SuperAdmin
has given them access. It is on for everyone by default and kept feature by feature, so more features
can be added later. SuperAdmin and Executive are never blocked. A grant is for one feature or for all of
them and stays until SuperAdmin removes it.

Security decides; each service asks before serving a night-controlled request (POST
/security/v1/service/night-control/check) and the apps ask for the signed-in person's own state
(GET /security/v1/me/night-control) to show "Night Mode On"."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, time
from typing import Any
from uuid import uuid4
from zoneinfo import ZoneInfo

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

IST = ZoneInfo("Asia/Kolkata")
MESSAGE = "Night Mode On"


def in_window(now: datetime, starts: time, ends: time) -> bool:
    """Whether `now` (any time zone) falls in the India-time window; a window that starts later than it
    ends runs over midnight (20:00 to 08:30)."""
    local = now.astimezone(IST).time()
    if starts < ends:
        return starts <= local < ends
    return local >= starts or local < ends


@dataclass(frozen=True)
class Feature:
    key: str
    label: str
    enabled: bool
    starts: time
    ends: time

    def view(self) -> dict[str, Any]:
        return {
            "featureKey": self.key,
            "label": self.label,
            "enabled": self.enabled,
            "startsAt": self.starts.strftime("%H:%M"),
            "endsAt": self.ends.strftime("%H:%M"),
        }


class NightControlService:
    def __init__(self, session: Session) -> None:
        self.session = session

    # ---- reads ---------------------------------------------------------------------------------

    def features(self) -> list[Feature]:
        rows = self.session.execute(
            text(
                "SELECT feature_key, label, enabled, starts_local, ends_local"
                " FROM security.night_control_features ORDER BY feature_key"
            )
        ).all()
        return [Feature(r[0], r[1], bool(r[2]), r[3], r[4]) for r in rows]

    def exempt_reason(self, user_id: str, *, is_super_admin: bool | None = None) -> str | None:
        """SUPER_ADMIN or EXECUTIVE when the person is never blocked."""
        if is_super_admin is None:
            is_super_admin = (
                self.session.execute(
                    text(
                        "SELECT 1 FROM security.user_admin_role_assignments WHERE user_id = CAST(:u AS uuid)"
                        " AND role_key = 'SuperAdmin' AND status = 'ACTIVE' LIMIT 1"
                    ),
                    {"u": user_id},
                ).first()
                is not None
            )
        if is_super_admin:
            return "SUPER_ADMIN"
        executive = self.session.execute(
            text(
                "SELECT 1 FROM security.user_tenant_operating_roles WHERE user_id = CAST(:u AS uuid)"
                " AND role_key = 'Executive' AND status = 'ACTIVE' LIMIT 1"
            ),
            {"u": user_id},
        ).first()
        return "EXECUTIVE" if executive is not None else None

    def granted_features(self, user_id: str) -> set[str | None]:
        """The features this person has access to at night; None means all of them."""
        rows = self.session.execute(
            text(
                "SELECT feature_key FROM security.night_access_grants"
                " WHERE user_id = CAST(:u AS uuid) AND revoked_at_utc IS NULL"
            ),
            {"u": user_id},
        ).all()
        return {r[0] for r in rows}

    def state(self, user_id: str, *, is_super_admin: bool | None = None, now: datetime | None = None) -> dict[str, Any]:
        """Every night-controlled feature and whether it is blocked for this person right now."""
        now = now or datetime.now(UTC)
        exempt = self.exempt_reason(user_id, is_super_admin=is_super_admin)
        granted = self.granted_features(user_id) if exempt is None else set()
        out = []
        for f in self.features():
            active = f.enabled and in_window(now, f.starts, f.ends)
            allowed_by = exempt or ("GRANT" if (None in granted or f.key in granted) else None)
            out.append(
                {**f.view(), "active": active, "blocked": active and allowed_by is None, "allowedBy": allowed_by}
            )
        return {
            "nightModeOn": any(f["blocked"] for f in out),
            "message": MESSAGE,
            "exempt": exempt,
            "features": out,
            "checkedAt": now.isoformat(),
        }

    def check(self, user_id: str, feature_key: str, now: datetime | None = None) -> dict[str, Any]:
        state = self.state(user_id, now=now)
        found = next((f for f in state["features"] if f["featureKey"] == feature_key), None)
        if found is None:
            # A feature Security does not know is never blocked: the control is opt-in per feature.
            return {"featureKey": feature_key, "blocked": False, "reasonCode": None, "message": None}
        return {
            "featureKey": feature_key,
            "blocked": found["blocked"],
            "reasonCode": "NIGHT_MODE" if found["blocked"] else None,
            "message": MESSAGE if found["blocked"] else None,
            "startsAt": found["startsAt"],
            "endsAt": found["endsAt"],
            "allowedBy": found["allowedBy"],
        }

    def overview(self, now: datetime | None = None) -> dict[str, Any]:
        now = now or datetime.now(UTC)
        rows = self.session.execute(
            text(
                """
                SELECT g.grant_id, g.user_id, g.feature_key, g.note, g.granted_at_utc,
                       u.display_name, u.primary_email, b.display_name
                FROM security.night_access_grants g
                LEFT JOIN security.users u ON u.user_id = g.user_id
                LEFT JOIN security.users b ON b.user_id = g.granted_by_user_id
                WHERE g.revoked_at_utc IS NULL
                ORDER BY g.granted_at_utc DESC
                """
            )
        ).all()
        return {
            "message": MESSAGE,
            "features": [
                {**f.view(), "active": f.enabled and in_window(now, f.starts, f.ends)} for f in self.features()
            ],
            "grants": [
                {
                    "grantId": str(r[0]),
                    "userId": str(r[1]),
                    "featureKey": r[2],
                    "note": r[3],
                    "grantedAt": r[4].isoformat(),
                    "displayName": r[5],
                    "email": r[6],
                    "grantedBy": r[7],
                }
                for r in rows
            ],
            "exemptRoles": ["SuperAdmin", "Executive"],
        }

    # ---- SuperAdmin changes (each recorded) ----------------------------------------------------

    def set_feature(
        self,
        *,
        feature_key: str,
        enabled: bool,
        starts: time,
        ends: time,
        actor_user_id: str,
        correlation_id: str,
    ) -> dict[str, Any]:
        if starts == ends:
            raise ValueError("The night must start and end at different times")
        before = next((f for f in self.features() if f.key == feature_key), None)
        if before is None:
            raise LookupError(feature_key)
        try:
            self.session.execute(
                text(
                    "UPDATE security.night_control_features SET enabled = :e, starts_local = :s, ends_local = :n,"
                    " updated_by_user_id = CAST(:a AS uuid), updated_at_utc = CURRENT_TIMESTAMP"
                    " WHERE feature_key = :k"
                ),
                {"e": enabled, "s": starts, "n": ends, "a": actor_user_id, "k": feature_key},
            )
            after = next(f for f in self.features() if f.key == feature_key)
            self._record(
                actor_user_id,
                correlation_id,
                "security.night_control.feature",
                "NIGHT_CONTROL_FEATURE",
                feature_key,
                before.view(),
                after.view(),
            )
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise
        return after.view()

    def grant(
        self, *, user_id: str, feature_key: str | None, note: str, actor_user_id: str, correlation_id: str
    ) -> dict[str, Any]:
        if feature_key is not None and feature_key not in {f.key for f in self.features()}:
            raise LookupError(feature_key)
        exists = self.session.execute(
            text("SELECT 1 FROM security.users WHERE user_id = CAST(:u AS uuid)"), {"u": user_id}
        ).first()
        if exists is None:
            raise LookupError(user_id)
        try:
            row = self.session.execute(
                text(
                    "INSERT INTO security.night_access_grants (user_id, feature_key, note, granted_by_user_id)"
                    " VALUES (CAST(:u AS uuid), :k, :n, CAST(:a AS uuid))"
                    " ON CONFLICT (user_id, coalesce(feature_key, '*')) WHERE revoked_at_utc IS NULL DO NOTHING"
                    " RETURNING grant_id"
                ),
                {"u": user_id, "k": feature_key, "n": note.strip(), "a": actor_user_id},
            ).first()
            if row is None:
                self.session.rollback()
                raise FileExistsError("This person already has this access")
            view = {"grantId": str(row[0]), "userId": user_id, "featureKey": feature_key, "note": note.strip()}
            self._record(
                actor_user_id,
                correlation_id,
                "security.night_control.grant",
                "NIGHT_ACCESS_GRANT",
                str(row[0]),
                None,
                view,
            )
            self.session.commit()
        except FileExistsError:
            raise
        except Exception:
            self.session.rollback()
            raise
        return view

    def revoke(self, *, grant_id: str, note: str, actor_user_id: str, correlation_id: str) -> bool:
        try:
            row = self.session.execute(
                text(
                    "UPDATE security.night_access_grants SET revoked_at_utc = CURRENT_TIMESTAMP,"
                    " revoked_by_user_id = CAST(:a AS uuid), revoke_note = :n"
                    " WHERE grant_id = CAST(:g AS uuid) AND revoked_at_utc IS NULL"
                    " RETURNING user_id, feature_key, note"
                ),
                {"a": actor_user_id, "n": note.strip(), "g": grant_id},
            ).first()
            if row is None:
                self.session.rollback()
                return False
            before = {"grantId": grant_id, "userId": str(row[0]), "featureKey": row[1], "note": row[2]}
            self._record(
                actor_user_id,
                correlation_id,
                "security.night_control.revoke",
                "NIGHT_ACCESS_GRANT",
                grant_id,
                before,
                {"revoked": True, "note": note.strip()},
            )
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise
        return True

    def _record(
        self,
        actor: str,
        correlation_id: str,
        operation: str,
        resource_type: str,
        resource_id: str,
        before: dict[str, Any] | None,
        after: dict[str, Any] | None,
    ) -> None:
        self.session.execute(
            text(
                """
                INSERT INTO security.admin_change_records (
                    admin_change_id, correlation_id, scope_type, tenant_id, actor_user_id,
                    operation_key, resource_type, resource_id, outcome,
                    before_state_json, after_state_json, occurred_at_utc
                ) VALUES (
                    CAST(:id AS uuid), :corr, 'PLATFORM', NULL, CAST(:actor AS uuid),
                    :op, :rt, :rid, 'SUCCESS', CAST(:before AS jsonb), CAST(:after AS jsonb), :now
                )
                """
            ),
            {
                "id": str(uuid4()),
                "corr": correlation_id,
                "actor": actor,
                "op": operation,
                "rt": resource_type,
                "rid": resource_id,
                "before": json.dumps(before) if before is not None else None,
                "after": json.dumps(after) if after is not None else None,
                "now": datetime.now(UTC),
            },
        )
