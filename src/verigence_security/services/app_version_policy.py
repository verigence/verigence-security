"""The oldest Verigence app version still allowed (product owner, 4 Nov 2026).

SuperAdmin sets a minimum Android app version and, optionally, the moment it takes effect. From
then on an app older than the minimum, or one too old to report its version at all, is refused at
sign-in, at "keep me signed in" and at every session renewal, so it cannot be used; the app is told
to download the latest version. Web browsers are never affected: they load the current screens.

An app is the native Android app when its device context says the Capacitor WebView, or when it
reports an app version (only the native app does).

A Project can have a minimum of its own (product owner, 19 Nov 2026: "can you enforce it for mahindra
team selectively"). It holds for the people who work in that Project (an ACTIVE operating role there)
and for nobody else. The app asks the public status before anyone is known, so that status cannot
carry a Project's minimum; it is enforced where the person is known: at sign-in, at "keep me signed
in" and at session renewal, where an app below it is refused with where to download the latest."""

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


@dataclass(frozen=True)
class ProjectPolicy:
    """The minimum app version of one Project, for the people who work in it."""

    tenant_id: str
    tenant_name: str
    minimum_version: str
    effective_from: datetime | None

    def in_force(self, now: datetime) -> bool:
        return self.effective_from is None or now >= self.effective_from

    def too_old(self, app_version: str | None) -> bool:
        minimum = parse_version(self.minimum_version)
        if minimum is None:
            return False
        found = parse_version(app_version)
        return found is None or found < minimum

    def view(self, now: datetime) -> dict[str, Any]:
        return {
            "tenantId": self.tenant_id,
            "tenantName": self.tenant_name,
            "minimumVersion": self.minimum_version,
            "effectiveFrom": self.effective_from.isoformat() if self.effective_from else None,
            "inForce": self.in_force(now),
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

    # ---- a minimum for one Project ------------------------------------------------------------

    def project_policies(self) -> list[ProjectPolicy]:
        rows = self.session.execute(
            text(
                "SELECT p.tenant_id, t.tenant_name, p.minimum_version, p.effective_from_utc"
                " FROM security.app_version_project_policies p"
                " JOIN security.tenants t ON t.tenant_id = p.tenant_id"
                " ORDER BY lower(t.tenant_name)"
            )
        ).all()
        return [ProjectPolicy(str(r[0]), r[1], r[2], r[3]) for r in rows]

    def project_choices(self) -> list[dict[str, Any]]:
        """The Projects a minimum can be set for: those with people working in them."""
        rows = self.session.execute(
            text(
                "SELECT t.tenant_id, t.tenant_name, count(DISTINCT r.user_id)"
                " FROM security.tenants t"
                " JOIN security.user_tenant_operating_roles r ON r.tenant_id = t.tenant_id AND r.status = 'ACTIVE'"
                "   AND (r.valid_to_utc IS NULL OR r.valid_to_utc > now())"
                " GROUP BY t.tenant_id, t.tenant_name ORDER BY lower(t.tenant_name), t.tenant_id"
            )
        ).all()
        return [{"tenantId": str(r[0]), "tenantName": r[1], "people": int(r[2])} for r in rows]

    def project_policy_for_user(self, user_id: str, now: datetime) -> ProjectPolicy | None:
        """The highest Project minimum in force among the Projects the person works in."""
        rows = self.session.execute(
            text(
                "SELECT p.tenant_id, t.tenant_name, p.minimum_version, p.effective_from_utc"
                " FROM security.app_version_project_policies p"
                " JOIN security.tenants t ON t.tenant_id = p.tenant_id"
                " WHERE EXISTS (SELECT 1 FROM security.user_tenant_operating_roles r"
                "   WHERE r.tenant_id = p.tenant_id AND r.user_id = CAST(:u AS uuid) AND r.status = 'ACTIVE'"
                "   AND (r.valid_from_utc IS NULL OR r.valid_from_utc <= :now)"
                "   AND (r.valid_to_utc IS NULL OR r.valid_to_utc > :now))"
            ),
            {"u": user_id, "now": now},
        ).all()
        in_force = [p for p in (ProjectPolicy(str(r[0]), r[1], r[2], r[3]) for r in rows) if p.in_force(now)]
        if not in_force:
            return None
        return max(in_force, key=lambda p: parse_version(p.minimum_version) or (0, 0, 0))

    def set_project_policy(
        self,
        *,
        tenant_id: str,
        minimum_version: str | None,
        effective_from: datetime | None,
        actor_user_id: str,
        correlation_id: str,
    ) -> list[ProjectPolicy]:
        """Sets the Project's minimum, or removes it (``minimum_version`` None)."""
        if minimum_version is not None and parse_version(minimum_version) is None:
            raise ValueError("The version must look like 1.5.0")
        now = datetime.now(UTC)
        try:
            known = self.session.execute(
                text("SELECT 1 FROM security.tenants WHERE tenant_id = CAST(:t AS uuid)"), {"t": tenant_id}
            ).first()
            if known is None:
                raise LookupError("Project not found")
            before = next((p for p in self.project_policies() if p.tenant_id == tenant_id), None)
            if minimum_version is None:
                self.session.execute(
                    text("DELETE FROM security.app_version_project_policies WHERE tenant_id = CAST(:t AS uuid)"),
                    {"t": tenant_id},
                )
            else:
                self.session.execute(
                    text(
                        "INSERT INTO security.app_version_project_policies (tenant_id, minimum_version,"
                        " effective_from_utc, updated_by_user_id)"
                        " VALUES (CAST(:t AS uuid), :v, :f, CAST(:a AS uuid))"
                        " ON CONFLICT (tenant_id) DO UPDATE SET minimum_version = EXCLUDED.minimum_version,"
                        " effective_from_utc = EXCLUDED.effective_from_utc,"
                        " updated_by_user_id = EXCLUDED.updated_by_user_id, updated_at_utc = CURRENT_TIMESTAMP"
                    ),
                    {"t": tenant_id, "v": minimum_version, "f": effective_from, "a": actor_user_id},
                )
            policies = self.project_policies()
            after = next((p for p in policies if p.tenant_id == tenant_id), None)
            self.session.execute(
                text(
                    """
                    INSERT INTO security.admin_change_records (
                        admin_change_id,correlation_id,scope_type,tenant_id,actor_user_id,
                        operation_key,resource_type,resource_id,outcome,
                        before_state_json,after_state_json,occurred_at_utc
                    ) VALUES (
                        CAST(:id AS uuid),:corr,'TENANT',CAST(:tenant AS uuid),CAST(:actor AS uuid),
                        'security.app_version_policy.manage','APP_VERSION_PROJECT_POLICY','android',
                        'SUCCESS',CAST(:before AS jsonb),CAST(:after AS jsonb),:now
                    )
                    """
                ),
                {
                    "id": str(uuid4()),
                    "corr": correlation_id,
                    "tenant": tenant_id,
                    "actor": actor_user_id,
                    "before": json.dumps(before.view(now) if before else None),
                    "after": json.dumps(after.view(now) if after else None),
                    "now": now,
                },
            )
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise
        return policies

    def project_devices_below(
        self, tenant_id: str, minimum_version: str | None, days: int = 30
    ) -> list[dict[str, Any]]:
        """As devices_below, for the people who work in one Project."""
        minimum = parse_version(minimum_version)
        if minimum is None:
            return []
        rows = self.session.execute(
            text(
                "SELECT d.app_version, count(*), count(DISTINCT d.user_id) FROM security.human_devices d"
                " WHERE (d.browser_name = :b OR d.app_version IS NOT NULL)"
                " AND d.last_seen_at_utc > now() - make_interval(days => :d)"
                " AND EXISTS (SELECT 1 FROM security.user_tenant_operating_roles r"
                "   WHERE r.user_id = d.user_id AND r.tenant_id = CAST(:t AS uuid) AND r.status = 'ACTIVE'"
                "   AND (r.valid_to_utc IS NULL OR r.valid_to_utc > now()))"
                " GROUP BY d.app_version"
            ),
            {"b": NATIVE_BROWSER, "d": days, "t": tenant_id},
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


# Every released app from 1.1.0 has the full-screen notice page (it asks /status/maintenance before and
# after sign-in). Such an app below the minimum may sign in -- so the person can be shown "Update the
# Verigence app" and where to download it -- and the page then replaces the whole app. An app older
# than this, or one that does not report its version, cannot show any message: it is refused.
CAN_SHOW_UPDATE_PAGE = (1, 1, 0)

# The origins the Android app's WebView sends (Capacitor serves the app from localhost).
NATIVE_ORIGINS = {"https://localhost", "http://localhost", "capacitor://localhost"}


def can_show_update_page(app_version: str | None) -> bool:
    found = parse_version(app_version)
    return found is not None and found >= CAN_SHOW_UPDATE_PAGE


def update_notice(policy: Policy, app_version: str | None, now: datetime) -> dict[str, Any] | None:
    """For an app asking the public status: the "Update the Verigence app" notice when the app is below
    the minimum in force, in the shape of a maintenance notice so every released app since 1.1.0
    shows it (on the sign-in page, and in place of the whole app after sign-in)."""
    if not policy.in_force(now) or not policy.too_old(app_version):
        return None
    return {
        "announcementId": "00000000-0000-0000-0000-00000000a99e",
        "kind": "MAINTENANCE",
        "title": "Update the Verigence app to continue",
        "body": (
            f"This version of the app can no longer be used. Open {policy.download_url} in your phone's "
            f"browser (Chrome), sign in there and install version {policy.minimum_version} or newer. "
            "Then open the new app."
        ),
        "backAt": None,
        "startsAt": (policy.effective_from or now).isoformat(),
        "endsAt": None,
        "audience": "EVERYONE",
        "active": True,
    }


def require_supported_app(
    session: Any, *, browser_name: str | None, app_version: str | None, now: datetime | None = None
) -> None:
    """Refuses an app older than the minimum in force that cannot show the update page itself. A web
    browser always passes; so does an outdated app from 1.1.0, which is shown "Update the Verigence app"
    instead (see update_notice). If the policy cannot be read the check lets the request through."""
    if not is_native_app(browser_name=browser_name, app_version=app_version):
        return
    if can_show_update_page(app_version):
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


def _read_apart(session: Any, read: Any) -> Any:
    """Runs a read inside a savepoint where the session has them, so that a failed read (the table
    not there yet, a lost connection) does not leave the caller's own transaction unusable."""
    nested = getattr(session, "begin_nested", None)
    if nested is None:
        return read()
    with nested():
        return read()


def require_project_app(
    session: Any,
    *,
    user_id: str,
    browser_name: str | None,
    app_version: str | None,
    now: datetime | None = None,
) -> None:
    """Refuses the Android app of a person who works in a Project whose own minimum is in force, when
    the app is below it. Unlike the minimum for everyone, nothing lets such an app in to be shown an
    update page: the page comes from the public status, which does not know the person. The refusal
    says which version is needed and where to get it; the app shows it on its sign-in page. A web
    browser always passes, and so does everyone when the policy cannot be read."""
    if not is_native_app(browser_name=browser_name, app_version=app_version):
        return
    service = AppVersionPolicyService(session)
    current = now or datetime.now(UTC)
    try:
        required = _read_apart(session, lambda: service.project_policy_for_user(user_id, current))
        download_url = _read_apart(session, lambda: service.policy().download_url) if required else ""
    except Exception:  # noqa: BLE001 - the policy must never be the reason sign-in breaks
        logger.warning("app_version_project_policy_unreadable")
        return
    if required is not None and required.too_old(app_version):
        raise security_error(
            "APP_UPDATE_REQUIRED",
            f"This version of the Verigence app ({app_version or 'unknown'}) can no longer be used for "
            f"{required.tenant_name}. Open {download_url} in your phone's browser (Chrome), sign in there "
            f"and install version {required.minimum_version} or newer. Then open the new app.",
        )


def require_project_device(session: Any, *, user_id: str, device_id: str, now: datetime | None = None) -> None:
    """At session renewal the request carries no device context: use what was stored for the device.
    A stored version can be behind the app (the device is recorded after sign-in): a person who has
    the new app and is refused here is let in by "keep me signed in", which the app tries next and
    which carries the app's own version."""
    try:
        stored = _read_apart(
            session, lambda: AppVersionPolicyService(session).stored_device(user_id=user_id, device_id=device_id)
        )
    except Exception:  # noqa: BLE001
        logger.warning("app_version_device_unreadable")
        return
    if stored is None:
        return
    require_project_app(session, user_id=user_id, browser_name=stored[0], app_version=stored[1], now=now)
