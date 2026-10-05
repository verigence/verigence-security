from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from verigence_security.api.dependencies import source_ip
from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.core.errors import security_error
from verigence_security.services.login_activity import LoginActivityService
from verigence_security.services.v2_human_actor import HumanActorContext

router = APIRouter(prefix="/security/v1", tags=["Login activity"])


class AppDownloadIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    appVersion: str | None = Field(default=None, max_length=30)


@router.post("/me/app-download")
def record_app_download(
    body: AppDownloadIn,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
    ip: str = Depends(source_ip),
) -> dict[str, bool]:
    """The App Portal tells Security that this signed-in person started the Android download."""
    LoginActivityService(session).record_download(user_id=actor.user_id, app_version=body.appVersion, source_ip=ip)
    return {"recorded": True}


@router.get("/admin/login-activity")
def admin_login_activity(
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, Any]:
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")
    return LoginActivityService(session).report()
