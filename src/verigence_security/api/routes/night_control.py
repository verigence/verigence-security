"""Night control (product owner, 6 Nov 2026): from 20:00 to 08:30 IST Journey 360 and file downloads are
closed to everyone except SuperAdmin, Executive and the people SuperAdmin has given access."""

from __future__ import annotations

from datetime import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.routes.authorization import service_integration_token
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.config import Settings, get_settings
from verigence_security.core.errors import security_error
from verigence_security.services.night_control import NightControlService
from verigence_security.services.token_service import TokenService
from verigence_security.services.v2_human_actor import HumanActorContext

router = APIRouter(prefix="/security/v1", tags=["Night control"])

_KEY = r"^[A-Z][A-Z0-9_]{1,40}$"
_HHMM = r"^([01]\d|2[0-3]):[0-5]\d$"


def _require_super_admin(actor: HumanActorContext) -> None:
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")


def _require_service(service_token: str, settings: Settings, session: Session) -> None:
    """Any active Verigence service may ask: Audit Core, myHR and the services that come later."""
    claims = TokenService(settings).verify_service_token(service_token, audience="security")
    subject = str(claims.get("sub") or "").strip()
    row = session.execute(
        text(
            "SELECT 1 FROM security.service_integrations si"
            " JOIN security.security_principals p ON p.principal_id = si.principal_id"
            " WHERE si.integration_key = :k AND p.actor_type = 'SERVICE_INTEGRATION' AND p.status = 'ACTIVE'"
        ),
        {"k": subject},
    ).first()
    if not subject or row is None:
        raise security_error("AUTH_TOKEN_INVALID")


def _hhmm(value: str) -> time:
    hours, minutes = value.split(":")
    return time(int(hours), int(minutes))


class CheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    userId: str = Field(min_length=36, max_length=36)
    featureKey: str = Field(pattern=_KEY)


class FeatureIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool
    startsAt: str = Field(pattern=_HHMM)
    endsAt: str = Field(pattern=_HHMM)


class GrantIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    userId: str = Field(min_length=36, max_length=36)
    # None: every night-controlled feature.
    featureKey: str | None = Field(default=None, pattern=_KEY)
    note: str = Field(min_length=3, max_length=500)


class RevokeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: str = Field(min_length=3, max_length=500)


@router.get("/me/night-control")
def my_night_control(
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, Any]:
    """The signed-in person's own night state, for the apps to show "Night Mode On". The services
    enforce it on their own requests."""
    return NightControlService(session).state(actor.user_id, is_super_admin=actor.is_super_admin)


@router.post("/service/night-control/check")
def service_check(
    body: CheckIn,
    service_token: str = Depends(service_integration_token),
    session: Session = Depends(platform_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    _require_service(service_token, settings, session)
    return NightControlService(session).check(body.userId, body.featureKey)


@router.get("/admin/night-control")
def overview(
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, Any]:
    _require_super_admin(actor)
    return NightControlService(session).overview()


@router.put("/admin/night-control/features/{featureKey}")
def set_feature(
    featureKey: str,
    body: FeatureIn,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, Any]:
    _require_super_admin(actor)
    try:
        return NightControlService(session).set_feature(
            feature_key=featureKey,
            enabled=body.enabled,
            starts=_hhmm(body.startsAt),
            ends=_hhmm(body.endsAt),
            actor_user_id=actor.user_id,
            correlation_id=getattr(request.state, "correlation_id", ""),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="No such night-controlled feature") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/admin/night-control/grants", status_code=201)
def grant(
    body: GrantIn,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, Any]:
    _require_super_admin(actor)
    try:
        return NightControlService(session).grant(
            user_id=body.userId,
            feature_key=body.featureKey,
            note=body.note,
            actor_user_id=actor.user_id,
            correlation_id=getattr(request.state, "correlation_id", ""),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="No such person or feature") from exc
    except FileExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/admin/night-control/grants/{grantId}/revoke")
def revoke(
    grantId: str,
    body: RevokeIn,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, Any]:
    _require_super_admin(actor)
    done = NightControlService(session).revoke(
        grant_id=grantId,
        note=body.note,
        actor_user_id=actor.user_id,
        correlation_id=getattr(request.state, "correlation_id", ""),
    )
    if not done:
        raise HTTPException(status_code=404, detail="No such access, or it was already removed")
    return {"revoked": True}
