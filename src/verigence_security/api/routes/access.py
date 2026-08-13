from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.orm import Session

from verigence_security.adapters.network_risk import NetworkRiskAdapter
from verigence_security.api.dependencies import (
    bearer_token,
    identity_from_token,
    network_adapter,
    repository,
    source_ip,
    token_service,
)
from verigence_security.api.platform_dependencies import (
    platform_session,
    require_platform_permission,
)
from verigence_security.api.schemas import AccessSessionRequest, AccessTokenResponse
from verigence_security.config import Settings, get_settings
from verigence_security.repositories.security_repository import SecurityRepository
from verigence_security.services.access_service import UserAccessService
from verigence_security.services.geo import GeoSample
from verigence_security.services.onboarding import OnboardingService
from verigence_security.services.permissions import effective_user_permissions
from verigence_security.services.tenant_rbac_gate import TenantRbacGateService
from verigence_security.services.token_service import TokenService

router = APIRouter(prefix="/security/v1", tags=["Runtime Access"])


class GroupAwareSecurityRepository(SecurityRepository):
    def effective_user_permissions(
        self,
        tenant_id: str,
        user_id: str,
        now: datetime,
    ) -> tuple[list[str], list[str]]:
        return effective_user_permissions(self.s, tenant_id, user_id, now)


class LocationAssignmentRequest(BaseModel):
    locationId: str = Field(min_length=1)
    scheduleId: str = Field(min_length=1)


class InvitationCreateRequest(BaseModel):
    displayName: str = Field(min_length=1, max_length=240)
    email: str | None = Field(default=None, max_length=320)
    mobile: str | None = Field(default=None, max_length=40)
    employeeCode: str | None = Field(default=None, max_length=120)
    roleIds: list[str] = Field(default_factory=list)
    groupIds: list[str] = Field(default_factory=list)
    locationAssignments: list[LocationAssignmentRequest] = Field(default_factory=list)
    expiresAtUtc: datetime

    @model_validator(mode="after")
    def validate_invitation(self) -> InvitationCreateRequest:
        self.displayName = self.displayName.strip()
        self.email = self.email.strip() if self.email else None
        self.mobile = self.mobile.strip() if self.mobile else None
        if not self.displayName:
            raise ValueError("Display name cannot be blank")
        if not self.email and not self.mobile:
            raise ValueError("At least one contact channel is required")
        if self.expiresAtUtc.tzinfo is None:
            raise ValueError("expiresAtUtc must include timezone information")
        self.expiresAtUtc = self.expiresAtUtc.astimezone(UTC)
        return self


class OwnerInvitationRequest(BaseModel):
    displayName: str = Field(min_length=1, max_length=240)
    email: str | None = Field(default=None, max_length=320)
    mobile: str | None = Field(default=None, max_length=40)
    employeeCode: str | None = Field(default=None, max_length=120)
    expiresAtUtc: datetime

    @model_validator(mode="after")
    def validate_owner_invitation(self) -> OwnerInvitationRequest:
        self.displayName = self.displayName.strip()
        self.email = self.email.strip() if self.email else None
        self.mobile = self.mobile.strip() if self.mobile else None
        if not self.displayName:
            raise ValueError("Display name cannot be blank")
        if not self.email and not self.mobile:
            raise ValueError("At least one contact channel is required")
        if self.expiresAtUtc.tzinfo is None:
            raise ValueError("expiresAtUtc must include timezone information")
        self.expiresAtUtc = self.expiresAtUtc.astimezone(UTC)
        return self


class SelfRegistrationRequest(BaseModel):
    displayName: str = Field(min_length=1, max_length=240)


class SelfOnboardingApprovalRequest(BaseModel):
    roleIds: list[str] = Field(default_factory=list)
    groupIds: list[str] = Field(default_factory=list)
    locationAssignments: list[LocationAssignmentRequest] = Field(default_factory=list)


class RejectionRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=1000)


def _tenant_admin_user(
    token: str,
    settings: Settings,
    repo: SecurityRepository,
    tenant_id: str,
    permission_key: str,
) -> str:
    identity = identity_from_token(token, settings)
    user_id = repo.resolve_identity_user(identity.provider, identity.provider_subject)
    TenantRbacGateService(repo.s).authorize_user(
        tenant_id=tenant_id,
        user_id=user_id,
        permission_key=permission_key,
    )
    return user_id


def _locations(values: list[LocationAssignmentRequest]) -> list[dict[str, str]]:
    return [
        {"locationId": value.locationId, "scheduleId": value.scheduleId}
        for value in values
    ]


@router.post("/access-sessions", response_model=AccessTokenResponse)
def create_access_session(
    body: AccessSessionRequest,
    request: Request,
    authorization_token: str = Depends(bearer_token),
    idempotency_key: str = Header(..., alias="Idempotency-Key", max_length=200),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
    network: NetworkRiskAdapter = Depends(network_adapter),
    tokens: TokenService = Depends(token_service),
    ip: str = Depends(source_ip),
) -> dict[str, object]:
    # Persistent same-key replay across stateless replicas still requires the approved
    # idempotency store tracked in IMPLEMENTATION_STATUS.
    _ = idempotency_key
    identity = identity_from_token(authorization_token, settings)
    geo = GeoSample(
        latitude=body.geo.latitude,
        longitude=body.geo.longitude,
        accuracy_meters=body.geo.accuracyMeters,
        captured_at=body.geo.capturedAt,
        source=body.geo.source,
        integrity_status=body.geo.integrityStatus,
        integrity_reason=body.geo.integrityReason,
    )
    runtime_repo = GroupAwareSecurityRepository(repo.s)
    return UserAccessService(runtime_repo, network, tokens).create_or_reuse(
        identity=identity,
        tenant_id=str(body.tenantId),
        device_id=str(body.deviceId),
        geo=geo,
        source_ip=ip,
        correlation_id=request.state.correlation_id,
    )


@router.post(
    "/platform/tenants/{tenantId}/owner-invitations",
    status_code=status.HTTP_201_CREATED,
    tags=["Platform Administration"],
)
def create_owner_invitation(
    tenantId: str,
    body: OwnerInvitationRequest,
    request: Request,
    claims: dict[str, Any] = Depends(
        require_platform_permission("security.tenant.bootstrap_admin")
    ),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    service = OnboardingService(session)
    try:
        owner_role_id = service.role_id_by_key(
            tenant_id=tenantId,
            role_key="tenant.owner",
        )
        invitation, acceptance_value = service.create_invitation(
            tenant_id=tenantId,
            actor_user_id=str(claims["sub"]),
            display_name=body.displayName,
            email=body.email,
            mobile=body.mobile,
            employee_code=body.employeeCode,
            role_ids=[owner_role_id],
            group_ids=[],
            location_assignments=[],
            expires_at_utc=body.expiresAtUtc,
            correlation_id=request.state.correlation_id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {**invitation, "acceptanceToken": acceptance_value}


@router.post(
    "/admin/tenants/{tenantId}/invitations",
    status_code=status.HTTP_201_CREATED,
    tags=["Tenant Onboarding"],
)
def create_invitation(
    tenantId: str,
    body: InvitationCreateRequest,
    request: Request,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> dict[str, object]:
    actor_id = _tenant_admin_user(
        token,
        settings,
        repo,
        tenantId,
        "security.member.invite",
    )
    try:
        invitation, acceptance_value = OnboardingService(repo.s).create_invitation(
            tenant_id=tenantId,
            actor_user_id=actor_id,
            display_name=body.displayName,
            email=body.email,
            mobile=body.mobile,
            employee_code=body.employeeCode,
            role_ids=body.roleIds,
            group_ids=body.groupIds,
            location_assignments=_locations(body.locationAssignments),
            expires_at_utc=body.expiresAtUtc,
            correlation_id=request.state.correlation_id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {**invitation, "acceptanceToken": acceptance_value}


@router.get(
    "/admin/tenants/{tenantId}/invitations",
    tags=["Tenant Onboarding"],
)
def list_invitations(
    tenantId: str,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> list[dict[str, object]]:
    _tenant_admin_user(token, settings, repo, tenantId, "security.member.read")
    return OnboardingService(repo.s).list_invitations(tenantId)


@router.post(
    "/admin/tenants/{tenantId}/invitations/{invitationId}/cancel",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Tenant Onboarding"],
)
def cancel_invitation(
    tenantId: str,
    invitationId: str,
    request: Request,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> Response:
    actor_id = _tenant_admin_user(
        token,
        settings,
        repo,
        tenantId,
        "security.member.update",
    )
    try:
        changed = OnboardingService(repo.s).cancel_invitation(
            tenant_id=tenantId,
            invitation_id=invitationId,
            actor_user_id=actor_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if not changed:
        raise HTTPException(status_code=404, detail="Invitation not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/onboarding/invitations/{invitationId}/accept",
    tags=["Onboarding"],
)
def accept_invitation(
    invitationId: str,
    request: Request,
    invitation_token: str = Header(min_length=1, alias="X-Invitation-Token"),
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> dict[str, object]:
    identity = identity_from_token(token, settings)
    try:
        return OnboardingService(repo.s).accept_invitation(
            invitation_id=invitationId,
            acceptance_token=invitation_token,
            identity_provider=identity.provider,
            identity_subject=identity.provider_subject,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/onboarding/tenants/{tenantCode}/self-registrations",
    tags=["Onboarding"],
)
def submit_self_registration(
    tenantCode: str,
    body: SelfRegistrationRequest,
    request: Request,
    onboarding_token: str = Header(min_length=1, alias="X-Onboarding-Token"),
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    client_ip: str = Depends(source_ip),
    repo: SecurityRepository = Depends(repository),
) -> dict[str, object]:
    identity = identity_from_token(token, settings)
    try:
        return OnboardingService(repo.s).submit_self_registration(
            tenant_code=tenantCode,
            onboarding_token=onboarding_token,
            identity_provider=identity.provider,
            identity_subject=identity.provider_subject,
            display_name=body.displayName.strip(),
            source_ip=client_ip,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/admin/tenants/{tenantId}/self-onboarding-requests",
    tags=["Tenant Onboarding"],
)
def list_self_onboarding_requests(
    tenantId: str,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> list[dict[str, object]]:
    _tenant_admin_user(token, settings, repo, tenantId, "security.member.read")
    return OnboardingService(repo.s).list_self_onboarding_requests(tenantId)


@router.get(
    "/admin/tenants/{tenantId}/self-onboarding-requests/{requestId}",
    tags=["Tenant Onboarding"],
)
def get_self_onboarding_request(
    tenantId: str,
    requestId: str,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> dict[str, object]:
    _tenant_admin_user(token, settings, repo, tenantId, "security.member.read")
    row = OnboardingService(repo.s).get_self_onboarding_request(
        tenant_id=tenantId,
        request_id=requestId,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Self-onboarding request not found")
    return row


@router.post(
    "/admin/tenants/{tenantId}/self-onboarding-requests/{requestId}/approve",
    tags=["Tenant Onboarding"],
)
def approve_self_onboarding_request(
    tenantId: str,
    requestId: str,
    body: SelfOnboardingApprovalRequest,
    request: Request,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> dict[str, object]:
    actor_id = _tenant_admin_user(
        token,
        settings,
        repo,
        tenantId,
        "security.member.approve",
    )
    try:
        return OnboardingService(repo.s).approve_self_onboarding_request(
            tenant_id=tenantId,
            request_id=requestId,
            actor_user_id=actor_id,
            role_ids=body.roleIds,
            group_ids=body.groupIds,
            location_assignments=_locations(body.locationAssignments),
            correlation_id=request.state.correlation_id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/admin/tenants/{tenantId}/self-onboarding-requests/{requestId}/reject",
    tags=["Tenant Onboarding"],
)
def reject_self_onboarding_request(
    tenantId: str,
    requestId: str,
    body: RejectionRequest,
    request: Request,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> dict[str, object]:
    actor_id = _tenant_admin_user(
        token,
        settings,
        repo,
        tenantId,
        "security.member.approve",
    )
    try:
        return OnboardingService(repo.s).reject_self_onboarding_request(
            tenant_id=tenantId,
            request_id=requestId,
            actor_user_id=actor_id,
            reason=body.reason,
            correlation_id=request.state.correlation_id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
