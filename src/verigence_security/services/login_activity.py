from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from verigence_security.config import Settings
from verigence_security.db.session import build_session_factory

logger = logging.getLogger(__name__)

# What the app reports on its own: native app = MOBILE + ANDROID.
_APP_LOGIN = "device_type='MOBILE' AND platform='ANDROID'"


def record_login_attempt(
    settings: Settings,
    *,
    identifier: str,
    user_id: str | None,
    outcome: str,
    reason: str | None,
    device_type: str | None,
    platform: str | None,
    app_version: str | None,
    source_ip: str | None,
) -> None:
    """Writes one row about a sign-in attempt, in its own transaction so a refused sign-in is still
    recorded. It never raises and never delays the sign-in result: a failure here is only logged."""
    try:
        factory = build_session_factory(settings)
        if factory is None:
            return
        # Only an e-mail address is kept as "who tried"; anything else typed in that box (a password
        # pasted by mistake, say) is not stored.
        typed = identifier.strip().lower()
        who = typed if "@" in typed and len(typed) <= 320 else None
        session = factory()
        try:
            session.execute(
                text(
                    "INSERT INTO security.login_attempts (identifier,user_id,outcome,reason,device_type,"
                    "platform,app_version,source_ip) VALUES (:i,CAST(:u AS uuid),:o,:r,:dt,:p,:v,:ip)"
                ),
                {
                    "i": who,
                    "u": user_id,
                    "o": outcome,
                    "r": (reason or None) and reason[:80],
                    "dt": device_type,
                    "p": platform,
                    "v": app_version and app_version[:30],
                    "ip": source_ip and source_ip[:64],
                },
            )
            session.commit()
        finally:
            session.close()
    except Exception:  # noqa: BLE001 - recording must never block a sign-in
        logger.warning("login_attempt_not_recorded")


class LoginActivityService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def record_download(self, *, user_id: str, app_version: str | None, source_ip: str | None) -> None:
        try:
            self.session.execute(
                text(
                    "INSERT INTO security.app_downloads (user_id,app_version,source_ip)"
                    " VALUES (CAST(:u AS uuid),:v,:ip)"
                ),
                {"u": user_id, "v": app_version and app_version[:30], "ip": source_ip and source_ip[:64]},
            )
            self.session.commit()
        except Exception:  # noqa: BLE001 - recording a download must never break it
            self.session.rollback()
            logger.warning("app_download_not_recorded")

    def report(self) -> dict[str, Any]:
        people = (
            self.session.execute(
                text(
                    f"""
                WITH attempts AS (
                  SELECT a.*, COALESCE(a.user_id,
                    (SELECT u.user_id FROM security.users u WHERE lower(u.primary_email)=a.identifier LIMIT 1)
                  ) AS uid
                  FROM security.login_attempts a
                ),
                att AS (
                  SELECT uid,
                    count(*) FILTER (WHERE outcome='SUCCESS') AS ok,
                    count(*) FILTER (WHERE outcome='FAILED') AS failed,
                    count(*) FILTER (WHERE outcome='SUCCESS' AND {_APP_LOGIN}) AS app_ok,
                    count(*) FILTER (WHERE outcome='SUCCESS' AND NOT ({_APP_LOGIN})) AS web_ok,
                    min(attempted_at_utc) FILTER (WHERE outcome='SUCCESS') AS first_ok,
                    max(attempted_at_utc) FILTER (WHERE outcome='SUCCESS') AS last_ok,
                    max(attempted_at_utc) AS last_at
                  FROM attempts WHERE uid IS NOT NULL GROUP BY uid
                ),
                last_try AS (
                  SELECT DISTINCT ON (uid) uid, outcome, reason
                  FROM attempts WHERE uid IS NOT NULL ORDER BY uid, attempted_at_utc DESC
                ),
                last_app AS (
                  SELECT DISTINCT ON (uid) uid, app_version
                  FROM attempts WHERE uid IS NOT NULL AND outcome='SUCCESS' AND {_APP_LOGIN}
                  ORDER BY uid, attempted_at_utc DESC
                ),
                dl AS (
                  SELECT user_id AS uid, count(*) AS downloads, min(downloaded_at_utc) AS first_dl,
                         max(downloaded_at_utc) AS last_dl
                  FROM security.app_downloads GROUP BY user_id
                )
                SELECT u.user_id::text AS user_id, u.display_name, u.primary_email, u.status,
                       COALESCE(u.is_employee,false) AS is_employee,
                       COALESCE(att.ok,0) AS ok, COALESCE(att.failed,0) AS failed,
                       COALESCE(att.app_ok,0) AS app_ok, COALESCE(att.web_ok,0) AS web_ok,
                       att.first_ok, att.last_ok, att.last_at,
                       last_try.outcome AS last_outcome, last_try.reason AS last_reason,
                       last_app.app_version,
                       COALESCE(dl.downloads,0) AS downloads, dl.first_dl, dl.last_dl
                FROM security.users u
                LEFT JOIN att ON att.uid=u.user_id
                LEFT JOIN last_try ON last_try.uid=u.user_id
                LEFT JOIN last_app ON last_app.uid=u.user_id
                LEFT JOIN dl ON dl.uid=u.user_id
                WHERE u.primary_email IS NOT NULL
                ORDER BY lower(u.display_name)
                """
                )
            )
            .mappings()
            .all()
        )
        unknown = (
            self.session.execute(
                text(
                    """
                SELECT a.identifier, count(*) AS attempts, max(a.attempted_at_utc) AS last_at
                FROM security.login_attempts a
                WHERE a.user_id IS NULL AND a.identifier IS NOT NULL
                  AND NOT EXISTS (SELECT 1 FROM security.users u WHERE lower(u.primary_email)=a.identifier)
                GROUP BY a.identifier ORDER BY max(a.attempted_at_utc) DESC LIMIT 100
                """
                )
            )
            .mappings()
            .all()
        )
        return {
            "people": [_person(r) for r in people],
            "unknown": [
                {"identifier": r["identifier"], "attempts": int(r["attempts"]), "lastAt": _iso(r["last_at"])}
                for r in unknown
            ],
        }


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _state(row: Any) -> str:
    if row["app_ok"]:
        return "APP_SIGNED_IN"
    if row["downloads"]:
        return "DOWNLOADED"
    if row["ok"]:
        return "WEB_ONLY"
    if row["failed"]:
        return "TRIED_FAILED"
    return "NOT_TRIED"


def _person(row: Any) -> dict[str, Any]:
    return {
        "userId": row["user_id"],
        "name": row["display_name"],
        "email": row["primary_email"],
        "userStatus": row["status"],
        "isEmployee": bool(row["is_employee"]),
        "state": _state(row),
        "loginsOk": int(row["ok"]),
        "loginsFailed": int(row["failed"]),
        "appLogins": int(row["app_ok"]),
        "webLogins": int(row["web_ok"]),
        "firstLoginAt": _iso(row["first_ok"]),
        "lastLoginAt": _iso(row["last_ok"]),
        "lastAttemptAt": _iso(row["last_at"]),
        "lastOutcome": row["last_outcome"],
        "lastReason": row["last_reason"],
        "appVersion": row["app_version"],
        "downloads": int(row["downloads"]),
        "firstDownloadAt": _iso(row["first_dl"]),
        "lastDownloadAt": _iso(row["last_dl"]),
    }
