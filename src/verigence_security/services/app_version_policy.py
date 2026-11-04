"""The oldest Verigence app version still allowed (product owner, 4 Nov 2026).

SuperAdmin sets a minimum Android app version and, optionally, the moment it takes effect. From
then on an app older than the minimum, or one too old to report its version at all, is refused at
sign-in, at "keep me signed in" and at every session renewal, so it cannot be used; the app is told
to download the latest version. Web browsers are never affected: they load the current screens.

An app is the native Android app when its device context says the Capacitor WebView, or when it
reports an app version (only the native app does)."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

from verigence_security.core.errors import security_error

logger = logging.getLogger(__name__)

NATIVE_BROWSER = "Capacitor WebView"
_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def parse_version(value: str | None) -> tuple[int, int, int] | None:
    match = _VERSION.match((value or "").strip())
    return (int(match[1]), int(match[2]), int(match[3])) if match else None


def is_native_app(*, browser_name: str | None, app_version: str | None) -> bool:
    return (browser_name or "").strip() == NATIVE_BROWSER or bool((app_version or "").strip())


@dataclass(frozen=True)
class Policy:
    minimum_version: str | None
    effective_from: datetime | None
    download_url: str

    def in_force(self, now: datetime) -> bool:
        return bool(self.minimum_version) and (self.effective_from is None or now >= self.effective_from)

    def too_old(self, app_version: str | None) -> bool:
        """A version below the minimum, or none that can be read, is too old."""
        minimum = parse_version(self.minimum_version)
        if minimum is None:
            return False
        found = parse_version(app_version)
        return found is None or found < minimum

    def view(self, now: datetime) -> dict[str, Any]:
        return {
            "minimumVersion": self.minimum_version,
            "effectiveFrom": self.effective_from.isoformat() if self.effective_from else None,
            "inForce": self.in_force(now),
            "downloadUrl": self.download_url,
        }


class AppVersionPolicyService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def policy(self) -> Policy:
        row = self.session.execute(
            text(
                "SELECT minimum_version, effective_from_utc, download_url"
                " FROM security.app_version_policy WHERE singleton"
            )
        ).first()
        if row is None:
            return Policy(None, None, "")
        return Policy(row[0], row[1], row[2])

    def set_policy(
        self,
        *,
        minimum_version: str | None,
        effective_from: datetime | None,
        download_url: str | None,
        actor_user_id: str,
        correlation_id: str,
    ) -> Policy:
        if minimum_version is not None and parse_version(minimum_version) is None:
            raise ValueError("The version must look like 1.5.0")
        before = self.policy()
        now = datetime.now(UTC)
        try:
            self.session.execute(
                text(
                    "INSERT INTO security.app_version_policy (singleton, minimum_version,"
                    " effective_from_utc, download_url, updated_by_user_id)"
                    " VALUES (true, :v, :f, COALESCE(:u, :default_url), CAST(:a AS uuid))"
                    " ON CONFLICT (singleton) DO UPDATE SET minimum_version = EXCLUDED.minimum_version,"
                    " effective_from_utc = EXCLUDED.effective_from_utc,"
                    " download_url = COALESCE(:u, security.app_version_policy.download_url),"
                    " updated_by_user_id = EXCLUDED.updated_by_user_id, updated_at_utc = CURRENT_TIMESTAMP"
                ),
                {
                    "v": minimum_version,
                    "f": effective_from,
                    "u": download_url,
                    "default_url": before.download_url or "",
                    "a": actor_user_id,
                },
            )
            after = self.policy()
            self.session.execute(
                text(
                    """
                    INSERT INTO security.admin_change_records (
                        admin_change_id,correlation_id,scope_type,tenant_id,actor_user_id,
                        operation_key,resource_type,resource_id,outcome,
                        before_state_json,after_state_json,occurred_at_utc
                    ) VALUES (
                        CAST(:id AS uuid),:corr,'PLATFORM',NULL,CAST(:actor AS uuid),
                        'security.app_version_policy.manage','APP_VERSION_POLICY','android',
                        'SUCCESS',CAST(:before AS jsonb),CAST(:after AS jsonb),:now
                    )
                    """
                ),
                {
                    "id": str(uuid4()),
                    "corr": correlation_id,
                    "actor": actor_user_id,
                    "before": json.dumps(before.view(now)),
                    "after": json.dumps(after.view(now)),
                    "now": now,
                },
            )
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise
        return after

    def devices_below(self, minimum_version: str | None, days: int = 30) -> list[dict[str, Any]]:
        """Native app installations seen in the last `days`, per version, that are below the
        minimum (or too old to say their version): who still has to update."""
        minimum = parse_version(minimum_version)
        if minimum is None:
            return []
        rows = self.session.execute(
            text(
                "SELECT app_version, count(*), count(DISTINCT user_id) FROM security.human_devices"
                " WHERE (browser_name = :b OR app_version IS NOT NULL)"
                " AND last_seen_at_utc > now() - make_interval(days => :d)"
                " GROUP BY app_version"
            ),
            {"b": NATIVE_BROWSER, "d": days},
        ).all()
        out = []
        for version, devices, people in rows:
            found = parse_version(version)
            if found is None or found < minimum:
                out.append({"appVersion": version, "devices": int(devices), "people": int(people)})
        out.sort(key=lambda r: parse_version(r["appVersion"]) or (-1, -1, -1))
        return out

    def stored_device(self, *, user_id: str, device_id: str) -> tuple[str | None, str | None] | None:
        row = self.session.execute(
            text(
                "SELECT browser_name, app_version FROM security.human_devices"
                " WHERE user_id = CAST(:u AS uuid) AND device_id = CAST(:d AS uuid)"
            ),
            {"u": user_id, "d": device_id},
        ).first()
        return (row[0], row[1]) if row else None


def require_supported_app(
    session: Any, *, browser_name: str | None, app_version: str | None, now: datetime | None = None
) -> None:
    """Refuses an app older than the minimum in force. A web browser always passes. If the policy
    cannot be read the check lets the request through (sign-in then fails or succeeds on its own)."""
    if not is_native_app(browser_name=browser_name, app_version=app_version):
        return
    try:
        policy = AppVersionPolicyService(session).policy()
    except Exception:  # noqa: BLE001 - the policy must never be the reason sign-in breaks
        logger.warning("app_version_policy_unreadable")
        return
    if policy.in_force(now or datetime.now(UTC)) and policy.too_old(app_version):
        raise security_error(
            "APP_UPDATE_REQUIRED",
            f"This version of the Verigence app ({app_version or 'unknown'}) is no longer supported. "
            f"Download the latest version ({policy.minimum_version} or newer) from {policy.download_url}",
        )


def require_supported_device(session: Any, *, user_id: str, device_id: str) -> None:
    """At session renewal the request carries no device context: use what was stored at sign-in."""
    try:
        stored = AppVersionPolicyService(session).stored_device(user_id=user_id, device_id=device_id)
    except Exception:  # noqa: BLE001
        logger.warning("app_version_device_unreadable")
        return
    if stored is None:
        return
    require_supported_app(session, browser_name=stored[0], app_version=stored[1])
