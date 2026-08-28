from __future__ import annotations

from datetime import date
from functools import lru_cache
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from verigence_security.attendance.audit_core import AuditCoreAttendanceClient
from verigence_security.attendance.config import AttendanceSettings, get_attendance_settings
from verigence_security.attendance.db import attendance_session
from verigence_security.attendance.repository import AttendanceRepository
from verigence_security.attendance.runtime_service import RuntimeAttendanceService as AttendanceService
from verigence_security.attendance.schemas import (
    AttendanceActionRequest,
    AttendanceActionResponse,
    AttendanceListResponse,
    AttendancePolicyResponse,
    AttendancePolicyUpdate,
    AttendanceRecord,
    CorrectionRequest,
    TodayResponse,
)
from verigence_security.attendance.security import (
    AttendanceAuthenticationError,
    SecurityAuthorizationClient,
    VerifiedHuman,
    verify_human_token,
)

router = APIRouter(prefix="/attendance/v1", tags=["Attendance"])
_human_bearer = HTTPBearer(auto_error=False, scheme_name="VerigenceHumanToken", bearerFormat="JWT")


class AttendanceRequestContext:
    def __init__(self, *, human: VerifiedHuman, bearer_token: str) -> None:
        self.human = human
        self.bearer_token = bearer_token


def attendance_request_context(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(_human_bearer)],
    settings: Annotated[AttendanceSettings, Depends(get_attendance_settings)],
) -> AttendanceRequestContext:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise AttendanceAuthenticationError("Missing Security human token")
    bearer_token = credentials.credentials.strip()
    if not bearer_token:
        raise AttendanceAuthenticationError("Missing Security human token")
    return AttendanceRequestContext(
        human=verify_human_token(bearer_token, settings),
        bearer_token=bearer_token,
    )


@lru_cache
def security_client() -> SecurityAuthorizationClient:
    return SecurityAuthorizationClient(get_attendance_settings())


@lru_cache
def audit_core_client() -> AuditCoreAttendanceClient:
    return AuditCoreAttendanceClient(get_attendance_settings())


def attendance_service(
    session: Annotated[Session, Depends(attendance_session)],
    settings: Annotated[AttendanceSettings, Depends(get_attendance_settings)],
) -> AttendanceService:
    return AttendanceService(
        repository=AttendanceRepository(session),
        settings=settings,
        security=security_client(),
        audit_core=audit_core_client(),
    )


@router.get("/tenants/{tenant_id}/me/today", response_model=TodayResponse)
def today(
    tenant_id: UUID,
    context: Annotated[AttendanceRequestContext, Depends(attendance_request_context)],
    service: Annotated[AttendanceService, Depends(attendance_service)],
) -> TodayResponse:
    return service.today(tenant_id=tenant_id, user_id=context.human.user_id)


@router.post("/tenants/{tenant_id}/me/check-in", response_model=AttendanceActionResponse)
def check_in(
    tenant_id: UUID,
    body: AttendanceActionRequest,
    context: Annotated[AttendanceRequestContext, Depends(attendance_request_context)],
    service: Annotated[AttendanceService, Depends(attendance_service)],
) -> AttendanceActionResponse:
    return service.check_in(
        tenant_id=tenant_id,
        user_id=context.human.user_id,
        human_bearer_token=context.bearer_token,
        request=body,
    )


@router.post("/tenants/{tenant_id}/me/check-out", response_model=AttendanceActionResponse)
def check_out(
    tenant_id: UUID,
    body: AttendanceActionRequest,
    context: Annotated[AttendanceRequestContext, Depends(attendance_request_context)],
    service: Annotated[AttendanceService, Depends(attendance_service)],
) -> AttendanceActionResponse:
    return service.check_out(
        tenant_id=tenant_id,
        user_id=context.human.user_id,
        human_bearer_token=context.bearer_token,
        request=body,
    )


@router.get("/tenants/{tenant_id}/me/history", response_model=AttendanceListResponse)
def history(
    tenant_id: UUID,
    context: Annotated[AttendanceRequestContext, Depends(attendance_request_context)],
    service: Annotated[AttendanceService, Depends(attendance_service)],
    limit: Annotated[int, Query(ge=1, le=366)] = 31,
) -> AttendanceListResponse:
    return service.history(tenant_id=tenant_id, user_id=context.human.user_id, limit=limit)


@router.get("/tenants/{tenant_id}/records", response_model=AttendanceListResponse)
def tenant_day(
    tenant_id: UUID,
    attendance_date: Annotated[date, Query(alias="attendanceDate")],
    context: Annotated[AttendanceRequestContext, Depends(attendance_request_context)],
    service: Annotated[AttendanceService, Depends(attendance_service)],
) -> AttendanceListResponse:
    return service.tenant_day(
        tenant_id=tenant_id,
        user_id=context.human.user_id,
        attendance_date=attendance_date,
    )


@router.get("/tenants/{tenant_id}/policy", response_model=AttendancePolicyResponse)
def get_policy(
    tenant_id: UUID,
    context: Annotated[AttendanceRequestContext, Depends(attendance_request_context)],
    service: Annotated[AttendanceService, Depends(attendance_service)],
) -> AttendancePolicyResponse:
    return service.policy(tenant_id=tenant_id, user_id=context.human.user_id)


@router.put("/tenants/{tenant_id}/policy", response_model=AttendancePolicyResponse)
def update_policy(
    tenant_id: UUID,
    body: AttendancePolicyUpdate,
    context: Annotated[AttendanceRequestContext, Depends(attendance_request_context)],
    service: Annotated[AttendanceService, Depends(attendance_service)],
) -> AttendancePolicyResponse:
    return service.update_policy(
        tenant_id=tenant_id,
        user_id=context.human.user_id,
        update=body,
    )


@router.patch(
    "/tenants/{tenant_id}/records/{attendance_id}",
    response_model=AttendanceRecord,
)
def correct_attendance(
    tenant_id: UUID,
    attendance_id: UUID,
    body: CorrectionRequest,
    context: Annotated[AttendanceRequestContext, Depends(attendance_request_context)],
    service: Annotated[AttendanceService, Depends(attendance_service)],
) -> AttendanceRecord:
    return service.correct(
        tenant_id=tenant_id,
        user_id=context.human.user_id,
        attendance_id=attendance_id,
        request=body,
    )
