from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.core.errors import security_error
from verigence_security.services.announcements import MAX_IMAGE_BYTES, AnnouncementService
from verigence_security.services.app_version_policy import (
    NATIVE_ORIGINS,
    AppVersionPolicyService,
    update_notice,
)
from verigence_security.services.v2_human_actor import HumanActorContext

router = APIRouter(prefix="/security/v1", tags=["Announcements"])


class AnnouncementIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["NOTICE", "WELCOME", "MAINTENANCE"]
    title: str = Field(min_length=1, max_length=120)
    # May be empty when the announcement is a picture (a poster or a graphic) added after creating it.
    body: str = Field(default="", max_length=1000)
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


class ImageIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # The picture as base64 (no data: prefix). The apps shrink it before sending; at most 2 MB.
    data: str = Field(min_length=8, max_length=(MAX_IMAGE_BYTES * 4) // 3 + 8)
    width: int | None = Field(default=None, ge=1, le=10000)
    height: int | None = Field(default=None, ge=1, le=10000)


class SettingsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    quietHours: int = Field(ge=0, le=720)


def _require_super_admin(actor: HumanActorContext) -> None:
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")


@router.get("/status/maintenance")
def maintenance_status(
    request: Request,
    appVersion: str | None = Query(default=None, max_length=30),
    session: Session = Depends(platform_session),
) -> dict[str, Any]:
    """Whether the apps are paused for maintenance. Needs no sign-in, so a person sees it first.

    The Android app below the minimum version gets "Update the Verigence app" here instead: released
    apps before 1.5.1 do not send their version, and are known by their WebView origin."""
    notice = AnnouncementService(session).maintenance()
    if notice is None and (request.headers.get("origin") or "").rstrip("/") in NATIVE_ORIGINS:
        try:
            policy = AppVersionPolicyService(session).policy()
            notice = update_notice(policy, appVersion, datetime.now(UTC))
        except Exception:  # noqa: BLE001 - never let the policy break the maintenance check
            notice = None
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


@router.get("/announcements/{announcementId}/image")
def announcement_image(
    announcementId: str,
    request: Request,
    session: Session = Depends(platform_session),
) -> Response:
    """The announcement's picture. Needs no sign-in, like the maintenance notice it can belong to:
    the id is not guessable, and announcements are messages meant to be shown."""
    try:
        found = AnnouncementService(session).image(announcementId)
    except Exception:  # noqa: BLE001 - a malformed id is simply not found
        found = None
    if found is None:
        raise HTTPException(status_code=404, detail="No image")
    content_type, data, digest = found
    etag = f'"{digest[:32]}"'
    headers = {
        "ETag": etag,
        "Cache-Control": "public, max-age=86400, immutable",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'",
    }
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers=headers)
    return Response(content=data, media_type=content_type, headers=headers)


@router.put("/admin/announcements/{announcementId}/image")
def put_announcement_image(
    announcementId: str,
    body: ImageIn,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, str]:
    _require_super_admin(actor)
    try:
        data = base64.b64decode(body.data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=422, detail="The image could not be read") from exc
    try:
        version = AnnouncementService(session).set_image(
            announcement_id=announcementId,
            data=data,
            width=body.width,
            height=body.height,
            actor_user_id=actor.user_id,
            correlation_id=request.state.correlation_id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"announcementId": announcementId, "imageVersion": version}


@router.delete("/admin/announcements/{announcementId}/image")
def delete_announcement_image(
    announcementId: str,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, str]:
    _require_super_admin(actor)
    try:
        AnnouncementService(session).remove_image(
            announcement_id=announcementId,
            actor_user_id=actor.user_id,
            correlation_id=request.state.correlation_id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"announcementId": announcementId}
