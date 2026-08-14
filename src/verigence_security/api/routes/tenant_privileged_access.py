from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from verigence_security.api.dependencies import bearer_token, identity_from_token, repository
from verigence_security.config import Settings, get_settings
from verigence_security.repositories.security_repository import SecurityRepository
from verigence_security.services.privileged_access import PrivilegedAccessService

router = APIRouter(
    prefix="/security/v1/admin/tenants/{tenantId}",
    tags=["Privileged Access"],
)


class PrivilegedDecisionRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=1000)


def _service(repo: SecurityRepository) -> PrivilegedAccessService:
    return PrivilegedAccessService(repo.s)


def _approver_user(
    token: str,
    settings: Settings,
    repo: SecurityRepository,
    tenant_id: str,
) -> str:
    identity = identity_from_token(token, settings)
    user_id = repo.resolve_identity_user(identity.provider, identity.provider_subject)
    _service(repo).authorize_user(
        tenant_id=tenant_id,
        user_id=user_id,
        permission_key="security.privileged_access.approve",
    )
    return user_id


@router.get("/privileged-access-requests")
def list_privileged_access_requests(
    tenantId: str,
    status: Literal["PENDING", "APPROVED", "REJECTED", "CANCELLED", "EXPIRED"] | None = None,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> list[dict[str, object]]:
    _approver_user(token, settings, repo, tenantId)
    return _service(repo).list_requests(tenantId, status)


@router.post("/privileged-access-requests/{requestId}/approve")
def approve_privileged_access_request(
    tenantId: str,
    requestId: str,
    body: PrivilegedDecisionRequest,
    request: Request,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> dict[str, object]:
    approver_id = _approver_user(token, settings, repo, tenantId)
    try:
        return _service(repo).approve(
            tenant_id=tenantId,
            request_id=requestId,
            approver_user_id=approver_id,
            correlation_id=request.state.correlation_id,
            reason=body.reason,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/privileged-access-requests/{requestId}/reject")
def reject_privileged_access_request(
    tenantId: str,
    requestId: str,
    body: PrivilegedDecisionRequest,
    request: Request,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> dict[str, object]:
    approver_id = _approver_user(token, settings, repo, tenantId)
    try:
        return _service(repo).reject(
            tenant_id=tenantId,
            request_id=requestId,
            approver_user_id=approver_id,
            correlation_id=request.state.correlation_id,
            reason=body.reason,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
