"""The System shutdown tab (product owner, 21 Nov 2026): a Super Admin or an Executive sees whether
Verigence is shut, sets the daily hours, shuts it down now and starts it now. Nobody else may.

The state itself, and why changing it here is all it takes, is in core/system_shutdown.py."""
from __future__ import annotations

import logging
from datetime import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.core import system_shutdown as switchboard
from verigence_security.core.errors import security_error
from verigence_security.services import system_shutdown as store
from verigence_security.services.night_control import NightControlService
from verigence_security.services.v2_human_actor import HumanActorContext

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/security/v1/admin/system-shutdown", tags=["System shutdown"])

_HHMM = r"^([01]\d|2[0-3]):[0-5]\d$"


class HoursIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fromIst: str = Field(pattern=_HHMM)
    toIst: str = Field(pattern=_HHMM)


def _require_super_admin_or_executive(actor: HumanActorContext, session: Session) -> None:
    reason = NightControlService(session).exempt_reason(actor.user_id, is_super_admin=actor.is_super_admin)
    if reason not in {"SUPER_ADMIN", "EXECUTIVE"}:
        raise security_error("PERMISSION_DENIED")


def _hhmm(value: str) -> time:
    hours, minutes = value.split(":")
    return time(int(hours), int(minutes))


def _view(session: Session) -> dict[str, Any]:
    return {
        **switchboard.status(),
        "gate": switchboard.GATE_ON and bool(switchboard.OPENERS),
        "people": store.people(session),
        "lastChange": store.last_change(session),
    }


def _apply(session: Session, state: switchboard.Switch, *, action: str, actor: HumanActorContext) -> dict[str, Any]:
    """Stored first, then in force: a change that could not be kept is not acted on."""
    store.save(session, state, action=action)
    session.commit()
    switchboard.set_switch(state)
    logger.info(
        "system_shutdown_changed action=%s",
        action,
        extra={"event_name": "system_shutdown_changed", "action": action, "actor_user_id": actor.user_id},
    )
    return _view(session)


@router.get("")
def overview(
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, Any]:
    _require_super_admin_or_executive(actor, session)
    return _view(session)


@router.put("/hours")
def set_hours(
    body: HoursIn,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, Any]:
    _require_super_admin_or_executive(actor, session)
    try:
        state = switchboard.with_hours(_hhmm(body.fromIst), _hhmm(body.toIst), actor.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _apply(session, state, action=f"HOURS {body.fromIst}-{body.toIst}", actor=actor)


@router.post("/shut-now")
def shut_now(
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, Any]:
    _require_super_admin_or_executive(actor, session)
    return _apply(session, switchboard.shut_now(actor.user_id), action="SHUT_NOW", actor=actor)


@router.post("/start-now")
def start_now(
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, Any]:
    _require_super_admin_or_executive(actor, session)
    return _apply(session, switchboard.start_now(actor.user_id), action="START_NOW", actor=actor)
