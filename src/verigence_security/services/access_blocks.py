"""A person's whole Verigence access paused, and restored (product owner, 4 Nov 2026).

The HR service pauses a Team Lead who missed the Monday 09:00 deadline for the week's approvals;
SuperAdmin restores access from myHR Settings. While a pause is active Security refuses sign-in,
"keep me signed in" and session renewal. SuperAdmin is never paused."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import text

from verigence_security.core.errors import security_error

logger = logging.getLogger(__name__)

_MESSAGE = (
    "Your Verigence access is paused because approvals waiting with you passed the Monday 09:00 "
    "deadline. Ask SuperAdmin to restore it."
)


def active_block(session: Any, user_id: str) -> dict[str, Any] | None:
    row = session.execute(
        text(
            "SELECT block_id, reason, source, blocked_at_utc FROM security.user_access_blocks"
            " WHERE user_id = CAST(:u AS uuid) AND restored_at_utc IS NULL"
        ),
        {"u": user_id},
    ).first()
    if row is None:
        return None
    return {
        "blockId": str(row[0]),
        "reason": row[1],
        "source": row[2],
        "blockedAt": row[3].isoformat(),
    }


def require_not_blocked(session: Any, *, user_id: str, is_super_admin: bool) -> None:
    """Refuses a paused person. If the pauses cannot be read the request goes through: a database
    problem must not lock everyone out."""
    if is_super_admin:
        return
    try:
        block = active_block(session, user_id)
    except Exception:  # noqa: BLE001
        logger.warning("access_block_unreadable")
        return
    if block is not None:
        raise security_error("ACCESS_BLOCKED", _MESSAGE)


def block(session: Any, *, user_id: str, reason: str, source: str) -> tuple[dict[str, Any], bool]:
    """Pauses the person; returns (the active pause, whether it is new). Idempotent."""
    existing = active_block(session, user_id)
    if existing is not None:
        return existing, False
    session.execute(
        text(
            "INSERT INTO security.user_access_blocks (user_id, reason, source)"
            " VALUES (CAST(:u AS uuid), :r, :s) ON CONFLICT DO NOTHING"
        ),
        {"u": user_id, "r": reason, "s": source},
    )
    created = active_block(session, user_id)
    assert created is not None
    return created, True


def restore(session: Any, *, user_id: str, restored_by: str, note: str) -> bool:
    """Ends the active pause; returns whether there was one."""
    row = session.execute(
        text(
            "UPDATE security.user_access_blocks SET restored_at_utc = now(),"
            " restored_by_user_id = CAST(:by AS uuid), restore_note = :n"
            " WHERE user_id = CAST(:u AS uuid) AND restored_at_utc IS NULL RETURNING block_id"
        ),
        {"u": user_id, "by": restored_by, "n": note},
    ).first()
    return row is not None


def active_blocks(session: Any) -> list[dict[str, Any]]:
    return [
        {"userId": str(r[0]), "reason": r[1], "source": r[2], "blockedAt": r[3].isoformat()}
        for r in session.execute(
            text(
                "SELECT user_id, reason, source, blocked_at_utc FROM security.user_access_blocks"
                " WHERE restored_at_utc IS NULL ORDER BY blocked_at_utc"
            )
        )
    ]
