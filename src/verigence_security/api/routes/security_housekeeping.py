from __future__ import annotations

from datetime import date
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.security_housekeeping_schemas import (
    SecurityHousekeepingPreviewResponse,
    SecurityHousekeepingPurgeRequest,
    SecurityHousekeepingPurgeResponse,
)
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.core.errors import security_error
from verigence_security.services.security_housekeeping import SecurityHousekeepingService
from verigence_security.services.v2_human_actor import HumanActorContext

router = APIRouter(
    prefix="/security/v1/platform/tenants/{tenantId}/housekeeping/security",
    tags=["Platform Administration"],
)


def _require_super_admin(actor: HumanActorContext) -> None:
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")


@router.get("", response_model=SecurityHousekeepingPreviewResponse)
def preview_security_housekeeping(
    tenantId: str,
    cutoff_date: Annotated[date, Query(alias="cutoffDate")],
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    _require_super_admin(actor)
    try:
        result = SecurityHousekeepingService(session).preview(
            tenant_id=tenantId,
            cutoff_date=cutoff_date,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return result


@router.post("/purge", response_model=SecurityHousekeepingPurgeResponse)
def purge_security_housekeeping(
    tenantId: str,
    body: SecurityHousekeepingPurgeRequest,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    _require_super_admin(actor)
    try:
        result = SecurityHousekeepingService(session).purge(
            actor_user_id=actor.user_id,
            tenant_id=tenantId,
            cutoff_date=body.cutoffDate,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return result
