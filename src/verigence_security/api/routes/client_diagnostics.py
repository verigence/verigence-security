from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.core.errors import security_error
from verigence_security.services.client_diagnostics import ClientDiagnosticsService
from verigence_security.services.v2_human_actor import HumanActorContext

router = APIRouter(prefix="/security/v1", tags=["Device diagnostics"])


class LogEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    time: str = Field(max_length=40)
    step: str = Field(max_length=120)
    detail: dict[str, Any] = Field(default_factory=dict)


class LogsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deviceId: str = Field(min_length=8, max_length=64)
    platform: str | None = Field(default=None, max_length=20)
    appVersion: str | None = Field(default=None, max_length=30)
    entries: list[LogEntry] = Field(max_length=100)


class EnabledIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


def _require_super_admin(actor: HumanActorContext) -> None:
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")


@router.get("/me/client-diagnostics")
def my_client_diagnostics(
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, bool]:
    """Whether this app should keep and send its on-device log (off unless SuperAdmin switched it on)."""
    _ = actor
    return {"enabled": ClientDiagnosticsService(session).enabled()}


@router.post("/me/client-diagnostics/logs")
def send_client_diagnostics(
    body: LogsIn,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, bool]:
    stored = ClientDiagnosticsService(session).accept(
        user_id=actor.user_id,
        device_id=body.deviceId,
        platform=body.platform,
        app_version=body.appVersion,
        entries=[entry.model_dump() for entry in body.entries],
    )
    return {"accepted": stored}


@router.get("/admin/client-diagnostics")
def admin_client_diagnostics(
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, Any]:
    _require_super_admin(actor)
    service = ClientDiagnosticsService(session)
    return {"enabled": service.enabled(), "logs": service.listing()}


@router.put("/admin/client-diagnostics")
def set_client_diagnostics(
    body: EnabledIn,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, bool]:
    _require_super_admin(actor)
    ClientDiagnosticsService(session).set_enabled(
        enabled=body.enabled, actor_user_id=actor.user_id, correlation_id=request.state.correlation_id
    )
    return {"enabled": body.enabled}


@router.delete("/admin/client-diagnostics/logs")
def clear_client_diagnostics(
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, int]:
    _require_super_admin(actor)
    removed = ClientDiagnosticsService(session).clear(
        actor_user_id=actor.user_id, correlation_id=request.state.correlation_id
    )
    return {"removed": removed}
