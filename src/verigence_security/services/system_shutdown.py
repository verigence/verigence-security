"""The shutdown switch as it is kept: one row of security.system_shutdown (core/system_shutdown.py
holds it in memory and explains it). Read at start-up, written when a Super Admin or Executive changes
it from the System shutdown tab."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from verigence_security.core import system_shutdown
from verigence_security.core.system_shutdown import Switch


def load(session: Session) -> Switch | None:
    """The stored state; None when the table has no row (the clock then stands)."""
    row = session.execute(
        text(
            "SELECT hours_enabled, hours_from, hours_to, manual_state, manual_until_utc,"
            " changed_by_user_id, changed_at_utc FROM security.system_shutdown WHERE singleton"
        )
    ).first()
    if row is None:
        return None
    until = row[4].astimezone(UTC) if row[4] is not None else None
    return Switch(
        hours=(row[1], row[2]) if row[0] else None,
        manual=row[3],
        manual_until=until,
        changed_by=str(row[5]) if row[5] else None,
        changed_at=row[6].astimezone(UTC) if row[6] is not None else None,
        stored=True,
    )


def save(session: Session, state: Switch, *, action: str) -> None:
    hours = state.hours
    session.execute(
        text(
            "INSERT INTO security.system_shutdown (singleton, hours_enabled, hours_from, hours_to,"
            " manual_state, manual_until_utc, changed_by_user_id, changed_at_utc, last_action)"
            " VALUES (true, :enabled, :start, :end, :manual, :until, CAST(:by AS uuid), :at, :action)"
            " ON CONFLICT (singleton) DO UPDATE SET hours_enabled = excluded.hours_enabled,"
            " hours_from = excluded.hours_from, hours_to = excluded.hours_to,"
            " manual_state = excluded.manual_state, manual_until_utc = excluded.manual_until_utc,"
            " changed_by_user_id = excluded.changed_by_user_id, changed_at_utc = excluded.changed_at_utc,"
            " last_action = excluded.last_action"
        ),
        {
            "enabled": hours is not None,
            "start": hours[0] if hours else "00:30",
            "end": hours[1] if hours else "08:00",
            "manual": state.manual if state.manual_until is not None else None,
            "until": state.manual_until if state.manual is not None else None,
            "by": state.changed_by,
            "at": state.changed_at or datetime.now(UTC),
            "action": action,
        },
    )


def people(session: Session) -> list[dict[str, Any]]:
    """Every active Super Admin and Executive, and whether each is on the configured list of people
    who may sign in while Verigence is shut (someone not on it cannot start it)."""
    rows = session.execute(
        text(
            "SELECT u.user_id, u.display_name, bool_or(x.kind = 'SuperAdmin') AS super_admin,"
            " bool_or(x.kind = 'Executive') AS executive"
            " FROM security.users u JOIN ("
            "   SELECT user_id, 'SuperAdmin' AS kind FROM security.user_admin_role_assignments"
            "    WHERE role_key = 'SuperAdmin' AND status = 'ACTIVE'"
            "   UNION ALL"
            "   SELECT user_id, 'Executive' FROM security.user_tenant_operating_roles"
            "    WHERE role_key = 'Executive' AND status = 'ACTIVE'"
            " ) x USING (user_id) WHERE u.status = 'ACTIVE'"
            " GROUP BY u.user_id, u.display_name ORDER BY lower(u.display_name)"
        )
    ).all()
    listed = system_shutdown.OPENERS.user_ids
    return [
        {
            "userId": str(r[0]),
            "name": r[1],
            "role": "Super Admin" if r[2] else "Executive",
            "mayStart": str(r[0]).lower() in listed,
        }
        for r in rows
    ]


def last_change(session: Session) -> dict[str, Any] | None:
    row = session.execute(
        text(
            "SELECT s.last_action, s.changed_at_utc, u.display_name FROM security.system_shutdown s"
            " LEFT JOIN security.users u ON u.user_id = s.changed_by_user_id"
            " WHERE s.singleton AND s.changed_at_utc IS NOT NULL"
        )
    ).first()
    if row is None:
        return None
    return {"action": row[0], "atUtc": row[1].astimezone(UTC).isoformat().replace("+00:00", "Z"), "by": row[2]}
