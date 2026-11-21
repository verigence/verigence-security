"""Verigence shut for the night: nobody signs in but the people who may start it.

Product owner, 21 Nov 2026: "lets have a tab in the verigence to have a full shutdown of DB",
"let have superadmin and Executive only the privilege to start the database", and, on how those
two get in once it is stopped: "superadmin id and executive id are going to be constant and wont
change.. lets put it in some configuration file locally and use to read from that".

Why. The database is billed for every hour it runs, stops by itself five minutes after the last
query and starts by itself on the next one. On the night of 20 Nov the worker, Document
Intelligence and myHR all slept in the 12:30 am - 8:00 am window and the database still ran all
night, because people's sessions did not: every tab left open renewed its sign-in here every 13
minutes (405 renewals in nine hours), and each renewal is a read and a write. So "shut" has to mean
that this service, the one door every person comes through, asks the database nothing.

What it does. While Verigence is shut (the night's sleep, VERIGENCE_SLEEP_WINDOW_IST, the same
clock the heartbeat and Audit Core's worker go by), a request from a person is answered 403
SYSTEM_CLOSED from memory, with the time Verigence opens: no session, no connection. The exceptions
are the people on the configured list, SECURITY_SHUTDOWN_OPENERS: the Super Admins and Executives.
Their sign-in and their renewals are served as by day, which is also what starts the database.

The list is a setting of this service, not a file in this (public) repository, and it holds no
readable sign-in id: each entry is a user id and the SHA-256 of the email the person signs in with.
It only decides whose request may reach the database while shut. Password, status and role are
checked there as always, so a stale entry lets nobody in who could not sign in by day; someone
newly made an Executive cannot start Verigence until they are added to it.

Services are not people: a request carrying a ServiceIntegration token, and the two machine-token
endpoints, pass as by day. The services rest by the same clock, and what is left of their traffic
at night is the consequence of a person on the list being at work. (One path is a person behind a
service: SevaSutra's phone app resuming its remembered sign-in. It is left open here: SevaSutra
ends a remembered sign-in on any refusal, so refusing it would sign every phone out; it costs one
start of the database when someone opens that app at night.)

403, not 401 or 503, on purpose. The Verigence apps treat 401 on a resume as "this remembered
sign-in is no good" and delete it, and 5xx as trouble to retry; 403 is "refused for now": the
session in the tab ends, "Keep me signed in" is kept, and the next opening of the app resumes.

With no list configured the gate does nothing at all: a deployment cannot shut everyone out by
accident. SECURITY_SHUTDOWN_GATE=off switches it off without removing the list.

The switch. Whether Verigence is shut is one piece of state, held here (``Switch``): the daily hours
and, while it lasts, a Super Admin's or Executive's own "Shut down now" or "Start now" from the
System shutdown tab. It is kept in security.system_shutdown, read once when this service starts and
again only when one of them changes it (this service runs as one process), so answering "open or
shut, until when" never needs the database. GET /security/v1/system/status gives that answer to
anyone: the sign-in pages, and every Verigence service, which rests and runs by it.

    Shut down now   shut from this moment to the next daily opening time.
    Start now       running from this moment. Pressed during the daily hours, Verigence is open
                    until that day's opening time; the next night is shut as every night.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from datetime import time as clock_time
from typing import Any

import jwt
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from verigence_security import platform_heartbeat
from verigence_security.config import get_settings
from verigence_security.core.correlation import HEADER
from verigence_security.core.errors import SecurityError, security_error
from verigence_security.core.types import ActorType

logger = logging.getLogger(__name__)

CODE = "SYSTEM_CLOSED"
LOGIN_PATH = "/security/v1/auth/login"
STATUS_PATH = "/security/v1/system/status"
# Asked by services with their own client credentials; the answer is a service's token.
MACHINE_TOKEN_PATHS = frozenset({"/security/v1/service/token", "/oauth/token"})
# Answered without the database at any hour.
_ALWAYS_OPEN = frozenset({STATUS_PATH, "/.well-known/jwks.json", "/openapi.json", "/docs", "/redoc"})


@dataclass(frozen=True)
class Openers:
    """The people who may sign in while Verigence is shut."""

    user_ids: frozenset[str] = frozenset()
    email_hashes: frozenset[str] = frozenset()

    def __bool__(self) -> bool:
        return bool(self.user_ids)


def email_hash(identifier: str) -> str:
    """The form a sign-in email is listed in: SHA-256 of it as sign-in compares it (trimmed, lower case)."""
    return hashlib.sha256(identifier.strip().lower().encode("utf-8")).hexdigest()


def parse_openers(raw: str | None) -> Openers:
    """``[{"userId": "...", "emailSha256": "..."}, ...]``. Anything unreadable is no list at all (the
    gate then does nothing) and says so in the log; an entry without a user id is left out."""
    text = (raw or "").strip()
    if not text:
        return Openers()
    try:
        entries = json.loads(text)
        if not isinstance(entries, list):
            raise ValueError("not a list")
    except ValueError:
        logger.error("system_shutdown_openers_unreadable", extra={"event_name": "system_shutdown_openers_unreadable"})
        return Openers()
    user_ids: set[str] = set()
    hashes: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        user_id = str(entry.get("userId") or "").strip().lower()
        if not user_id:
            continue
        user_ids.add(user_id)
        digest = str(entry.get("emailSha256") or "").strip().lower()
        if len(digest) == 64 and all(c in "0123456789abcdef" for c in digest):
            hashes.add(digest)
    return Openers(frozenset(user_ids), frozenset(hashes))


def _gate_on() -> bool:
    return os.environ.get("SECURITY_SHUTDOWN_GATE", "on").strip().lower() not in {"off", "false", "0", "no"}


OPENERS = parse_openers(os.environ.get("SECURITY_SHUTDOWN_OPENERS"))
GATE_ON = _gate_on()


SHUT = "SHUT"
OPEN = "OPEN"


@dataclass(frozen=True)
class Switch:
    """The daily hours (India time; None for no daily shutdown) and a manual Shut down / Start, if one
    is in force: ``manual`` is SHUT or OPEN until ``manual_until``."""

    hours: tuple[clock_time, clock_time] | None
    manual: str | None = None
    manual_until: datetime | None = None
    changed_by: str | None = None
    changed_at: datetime | None = None
    # False until the state has been read from security.system_shutdown or set from the tab: the
    # hours are then those of VERIGENCE_SLEEP_WINDOW_IST, the clock every service started with.
    stored: bool = False

    def manual_now(self, now: datetime) -> str | None:
        if self.manual in {SHUT, OPEN} and self.manual_until is not None and now < self.manual_until:
            return self.manual
        return None

    def in_hours(self, now: datetime) -> bool:
        if self.hours is None:
            return False
        start, end = self.hours
        local = now.astimezone(platform_heartbeat._IST).time()
        return start <= local < end if start < end else (local >= start or local < end)

    def next_opening(self, now: datetime) -> datetime | None:
        """The next daily opening time after ``now``."""
        if self.hours is None:
            return None
        end = self.hours[1]
        local = now.astimezone(platform_heartbeat._IST)
        opening = local.replace(hour=end.hour, minute=end.minute, second=0, microsecond=0)
        if opening <= local:
            opening += timedelta(days=1)
        return opening.astimezone(UTC)

    def resting(self, now: datetime) -> bool:
        manual = self.manual_now(now)
        return manual == SHUT if manual is not None else self.in_hours(now)

    def rest_ends(self, now: datetime) -> datetime | None:
        """When the shutdown in progress ends; None when Verigence is running."""
        if not self.resting(now):
            return None
        until = self.manual_until if self.manual_now(now) == SHUT else self.next_opening(now)
        # A manual shutdown that runs out inside the daily hours goes on to that day's opening.
        if until is not None and self.manual_now(now) == SHUT and replace(self, manual=None).in_hours(until):
            return replace(self, manual=None).next_opening(until)
        return until


_lock = threading.Lock()
_switch = Switch(hours=platform_heartbeat.SLEEP_WINDOW)


def switch() -> Switch:
    """The state in force. Until one is loaded or set, the daily hours of VERIGENCE_SLEEP_WINDOW_IST."""
    with _lock:
        if not _switch.stored:
            return replace(_switch, hours=platform_heartbeat.SLEEP_WINDOW)
        return _switch


def set_switch(state: Switch) -> None:
    """Called when the state is read at start-up and after each change from the tab."""
    global _switch
    with _lock:
        _switch = state


def reset_switch() -> None:
    """Back to the clock alone (tests)."""
    set_switch(Switch(hours=platform_heartbeat.SLEEP_WINDOW))


def resting(now: datetime | None = None) -> bool:
    """Whether Verigence is shut at this moment: the services rest, and the heartbeat here."""
    return switch().resting(now or datetime.now(UTC))


def closed(now: datetime | None = None) -> bool:
    """Whether people are refused at this moment: shut, with a list of who may still sign in."""
    return GATE_ON and bool(OPENERS) and resting(now)


def opens_at(now: datetime | None = None) -> datetime | None:
    """When the shutdown in progress ends (UTC); None when people are not being refused."""
    moment = now or datetime.now(UTC)
    return switch().rest_ends(moment) if closed(moment) else None


def shut_now(by: str, now: datetime | None = None) -> Switch:
    """Shut from this moment to the next daily opening time (with no daily hours: 8:00 am India time)."""
    moment = now or datetime.now(UTC)
    current = switch()
    hours = current.hours or (clock_time(0, 30), clock_time(8, 0))
    until = replace(current, hours=hours, manual=None).next_opening(moment)
    return replace(current, manual=SHUT, manual_until=until, changed_by=by, changed_at=moment, stored=True)


def start_now(by: str, now: datetime | None = None) -> Switch:
    """Running from this moment. A shutdown by hand is cleared; inside the daily hours Verigence is
    open until that day's opening time, after which the hours hold again as every day."""
    moment = now or datetime.now(UTC)
    daily = replace(switch(), manual=None, manual_until=None, changed_by=by, changed_at=moment, stored=True)
    if daily.in_hours(moment):
        return replace(daily, manual=OPEN, manual_until=daily.next_opening(moment))
    return daily


def with_hours(start: clock_time, end: clock_time, by: str, now: datetime | None = None) -> Switch:
    """New daily hours. A manual Shut down or Start in force stays as it is."""
    if start == end:
        raise ValueError("The shutdown must start and end at different times")
    return replace(switch(), hours=(start, end), changed_by=by, changed_at=now or datetime.now(UTC), stored=True)


def closed_message(now: datetime | None = None) -> str:
    opening = opens_at(now)
    if opening is None:
        return "Verigence is closed."
    local = opening.astimezone(platform_heartbeat._IST)
    hour = local.hour % 12 or 12
    half = "am" if local.hour < 12 else "pm"
    return f"Verigence is closed until {hour}:{local.minute:02d} {half}. It opens by itself at that time."


def may_sign_in(identifier: str, now: datetime | None = None) -> bool:
    """Whether this sign-in may go to the database: always when open, the listed people when shut."""
    return not closed(now) or email_hash(identifier) in OPENERS.email_hashes


def require_may_sign_in(identifier: str, now: datetime | None = None) -> None:
    """Called first thing by the sign-in endpoint, before anything is read or recorded."""
    if not may_sign_in(identifier, now):
        raise closed_error(now)


def closed_error(now: datetime | None = None) -> SecurityError:
    return security_error(CODE, closed_message(now))


def _z(moment: datetime | None) -> str | None:
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z") if moment else None


def status(now: datetime | None = None) -> dict[str, Any]:
    """Open or shut, and until when. No database. ``closed`` is for a sign-in page (people are being
    refused); ``resting`` is for a service (Verigence is shut, rest until ``restUntilUtc``), with the
    daily hours so a service that cannot reach this one for a while still knows them."""
    moment = now or datetime.now(UTC)
    state = switch()
    opening = opens_at(moment)
    rest_ends = state.rest_ends(moment)
    return {
        "closed": opening is not None,
        "opensAtUtc": _z(opening),
        "message": closed_message(moment) if opening else None,
        "resting": rest_ends is not None,
        "restUntilUtc": _z(rest_ends),
        "hoursFromIst": state.hours[0].strftime("%H:%M") if state.hours else None,
        "hoursToIst": state.hours[1].strftime("%H:%M") if state.hours else None,
        "manual": state.manual_now(moment),
        "manualSinceUtc": _z(state.changed_at) if state.manual_now(moment) else None,
        "manualUntilUtc": _z(state.manual_until) if state.manual_now(moment) else None,
    }


def _claims(token: str) -> dict[str, Any] | None:
    """A token this service issued and that still holds, by its signature alone (no database, and no
    audience check: this only tells a service from a person, the endpoint checks the rest)."""
    settings = get_settings()
    if not token or not settings.security_public_key_pem:
        return None
    try:
        payload = jwt.decode(
            token,
            settings.security_public_key_pem,
            algorithms=["RS256"],
            issuer=settings.security_token_issuer,
            options={"verify_aud": False, "require": ["exp", "sub", "actor_type"]},
        )
    except jwt.PyJWTError:
        return None
    return payload if isinstance(payload, dict) else None


def _passes(method: str, path: str, authorization: str) -> bool:
    if method == "OPTIONS" or path in _ALWAYS_OPEN or path.startswith("/health"):
        return True
    if path in MACHINE_TOKEN_PATHS:
        return True
    if path == LOGIN_PATH and method == "POST":
        return True  # the endpoint decides, from the email typed (require_may_sign_in)
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return False
    claims = _claims(token.strip())
    if claims is None:
        return False
    if claims.get("actor_type") == ActorType.USER.value:
        return str(claims.get("sub") or "").strip().lower() in OPENERS.user_ids
    return True  # a service


class SystemShutdownMiddleware:
    """Answers a person's request from memory while Verigence is shut. Plain ASGI: nothing of the
    request is read but its method, path and Authorization header."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not closed():
            await self.app(scope, receive, send)
            return
        headers = {name: value for name, value in scope.get("headers") or []}
        authorization = headers.get(b"authorization", b"").decode("latin-1")
        if _passes(str(scope.get("method", "")).upper(), str(scope.get("path", "")), authorization):
            await self.app(scope, receive, send)
            return
        state = scope.get("state")
        cid = state.get("correlation_id") if isinstance(state, dict) else getattr(state, "correlation_id", None)
        error = closed_error()
        opening = opens_at()
        response = JSONResponse(
            status_code=error.status_code,
            content={
                "code": error.code,
                "title": error.title,
                "status": error.status_code,
                "detail": error.detail,
                "correlationId": cid,
                "opensAtUtc": _z(opening),
            },
            media_type="application/problem+json",
        )
        if cid:
            response.headers[HEADER] = str(cid)
        await response(scope, receive, send)
