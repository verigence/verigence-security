from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.core.errors import security_error
from verigence_security.services.announcements import AnnouncementService
from verigence_security.services.v2_human_actor import HumanActorContext

router = APIRouter(prefix="/security/v1", tags=["Announcements"])


class AnnouncementIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["NOTICE", "WELCOME", "MAINTENANCE"]
    title: str = Field(min_length=1, max_length=120)
    body: str = Field(min_length=1, max_length=1000)
    backAt: datetime | None = None
    startsAt: datetime | None = None
    endsAt: datetime | None = None
    audience: Literal["EVERYONE", "PEOPLE"] = "EVERYONE"
    people: list[str] = Field(default_factory=list, max_length=500)


class AnnouncementPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str | None = Field(default=None, min_length=1, max_length=120)
    body: str | None = Field(default=None, min_length=1, max_length=1000)
    backAt: datetime | None = None
    endsAt: datetime | None = None
    active: bool | None = None
    people: list[str] | None = Field(default=None, max_length=500)


class SettingsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    quietHours: int = Field(ge=0, le=720)


def _require_super_admin(actor: HumanActorContext) -> None:
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")


@router.get("/status/maintenance")
def maintenance_status(session: Session = Depends(platform_session)) -> dict[str, Any]:
    """Whether the apps are paused for maintenance. Needs no sign-in, so a person sees it first."""
    notice = AnnouncementService(session).maintenance()
    return {"maintenance": notice}


@router.get("/me/announcements")
def my_announcement(
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, Any]:
    """The one greeting or notice this person should see now (none most of the time)."""
    notice = AnnouncementService(session).next_for(user_id=actor.user_id)
    return {"announcement": notice}


@router.post("/me/announcements/{announcementId}/seen")
def mark_seen(
    announcementId: str,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, bool]:
    AnnouncementService(session).mark_seen(announcement_id=announcementId, user_id=actor.user_id)
    return {"seen": True}


@router.get("/admin/announcements/settings")
def announcement_settings(
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, int]:
    """How many hours must pass before a person is shown another notice or greeting (0 = no wait)."""
    _require_super_admin(actor)
    return {"quietHours": AnnouncementService(session).quiet_hours()}


@router.put("/admin/announcements/settings")
def set_announcement_settings(
    body: SettingsIn,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, int]:
    _require_super_admin(actor)
    AnnouncementService(session).set_quiet_hours(
        hours=body.quietHours, actor_user_id=actor.user_id, correlation_id=request.state.correlation_id
    )
    return {"quietHours": body.quietHours}


@router.get("/admin/announcements")
def list_announcements(
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, Any]:
    _require_super_admin(actor)
    service = AnnouncementService(session)
    items = service.listing()
    for item in items:
        item["people"] = service.people_of(item["announcementId"]) if item["audience"] == "PEOPLE" else []
    return {"announcements": items}


@router.post("/admin/announcements", status_code=201)
def create_announcement(
    body: AnnouncementIn,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, str]:
    _require_super_admin(actor)
    try:
        announcement_id = AnnouncementService(session).create(
            kind=body.kind,
            title=body.title.strip(),
            body=body.body.strip(),
            back_at=body.backAt,
            starts_at=body.startsAt,
            ends_at=body.endsAt,
            audience=body.audience,
            people=body.people,
            actor_user_id=actor.user_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # a second maintenance notice, an end before the start, a bad person id
        raise HTTPException(status_code=409, detail="This announcement conflicts with what is already set") from exc
    return {"announcementId": announcement_id}


@router.patch("/admin/announcements/{announcementId}")
def update_announcement(
    announcementId: str,
    body: AnnouncementPatch,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, str]:
    _require_super_admin(actor)
    try:
        AnnouncementService(session).update(
            announcement_id=announcementId,
            title=body.title.strip() if body.title else None,
            body=body.body.strip() if body.body else None,
            back_at=body.backAt,
            ends_at=body.endsAt,
            active=body.active,
            people=body.people,
            actor_user_id=actor.user_id,
            correlation_id=request.state.correlation_id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=409, detail="This change conflicts with what is already set") from exc
    return {"announcementId": announcementId}
