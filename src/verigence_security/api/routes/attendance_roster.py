from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from verigence_security.api.attendance_roster_schemas import (
    AttendanceRosterMember,
    AttendanceRosterResponse,
)
from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.routes.authorization import service_integration_token
from verigence_security.config import Settings, get_settings
from verigence_security.core.errors import security_error
from verigence_security.repositories.attendance_roster_repository import AttendanceRosterRepository
from verigence_security.repositories.v2_authorization_repository import V2AuthorizationRepository
from verigence_security.services.token_service import TokenService

router = APIRouter(prefix="/security/v1/internal/attendance", tags=["Attendance Internal"])


def _require_service_integration(
    *,
    service_token: str,
    session: Session,
    settings: Settings,
) -> None:
    claims = TokenService(settings).verify_service_token(service_token, audience="security")
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise security_error("AUTH_TOKEN_INVALID")
    if not V2AuthorizationRepository(session).active_service_integration(subject):
        raise security_error("AUTH_TOKEN_INVALID")


@router.get("/tenants/{tenant_id}/roster", response_model=AttendanceRosterResponse)
def attendance_roster(
    tenant_id: UUID,
    service_token: str = Depends(service_integration_token),
    session: Session = Depends(platform_session),
    settings: Settings = Depends(get_settings),
) -> AttendanceRosterResponse:
    """Return active employee identity needed only for Attendance reporting.

    This endpoint is service-to-service only. It is not used by human login,
    onboarding, authorization resolution, or any existing business flow.
    """

    _require_service_integration(
        service_token=service_token,
        session=session,
        settings=settings,
    )
    rows = AttendanceRosterRepository(session).active_members(str(tenant_id))
    return AttendanceRosterResponse(
        tenantId=tenant_id,
        items=[
            AttendanceRosterMember(
                userId=UUID(str(row["user_id"])),
                displayName=str(row["display_name"]),
                primaryEmail=(str(row["primary_email"]) if row.get("primary_email") else None),
                operatingRole=(str(row["operating_role"]) if row.get("operating_role") else None),
            )
            for row in rows
        ],
    )
