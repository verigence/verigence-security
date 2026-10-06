from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from verigence_security.api.authorization_schemas import (
    AuthorizationBatchCheckRequest,
    AuthorizationBatchCheckResponse,
    AuthorizationCheckRequest,
    AuthorizationCheckResponse,
)
from verigence_security.api.platform_dependencies import platform_session
from verigence_security.config import Settings, get_settings
from verigence_security.core.errors import security_error
from verigence_security.repositories.v2_authorization_repository import (
    V2AuthorizationRepository,
)
from verigence_security.services.token_service import TokenService
from verigence_security.services.v2_authorization import (
    AuthorizationCheckService,
    AuthorizationDecision,
)

router = APIRouter(prefix="/security/v1", tags=["Authorization"])

service_bearer = HTTPBearer(
    auto_error=False,
    scheme_name="ServiceIntegrationToken",
    bearerFormat="JWT",
    description="Security-issued SERVICE_INTEGRATION JWT with aud=security.",
)


def service_integration_token(
    credentials: HTTPAuthorizationCredentials | None = Security(service_bearer),
) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise security_error("AUTH_TOKEN_INVALID")
    token = credentials.credentials.strip()
    if not token:
        raise security_error("AUTH_TOKEN_INVALID")
    return token


def _response(decision: AuthorizationDecision) -> AuthorizationCheckResponse:
    return AuthorizationCheckResponse(
        allowed=decision.allowed,
        decision="ALLOW" if decision.allowed else "DENY",
        reasonCode=decision.reason_code,
        userId=UUID(decision.user_id) if decision.user_id is not None else None,
        tenantId=UUID(decision.tenant_id) if decision.tenant_id is not None else None,
        permissionKey=decision.permission_key,
        moduleKey=decision.module_key,
        classification=decision.classification,
        roleKey=decision.role_key,
    )


@router.post("/authorization/check-batch", response_model=AuthorizationBatchCheckResponse)
def authorization_check_batch(
    body: AuthorizationBatchCheckRequest,
    service_token: str = Depends(service_integration_token),
    session: Session = Depends(platform_session),
    settings: Settings = Depends(get_settings),
) -> AuthorizationBatchCheckResponse:
    """Up to 64 permission questions about one user in one call. Each answer is exactly what the
    single check gives; the caller is authenticated once and the user is read once."""
    decisions = AuthorizationCheckService(
        V2AuthorizationRepository(session),
        TokenService(settings),
    ).check_many(
        service_token=service_token,
        user_id=str(body.userId),
        tenant_id=str(body.tenantId) if body.tenantId is not None else None,
        permission_keys=body.permissionKeys,
    )
    return AuthorizationBatchCheckResponse(decisions=[_response(d) for d in decisions])


@router.post("/authorization/check", response_model=AuthorizationCheckResponse)
def authorization_check(
    body: AuthorizationCheckRequest,
    service_token: str = Depends(service_integration_token),
    session: Session = Depends(platform_session),
    settings: Settings = Depends(get_settings),
) -> AuthorizationCheckResponse:
    decision = AuthorizationCheckService(
        V2AuthorizationRepository(session),
        TokenService(settings),
    ).check(
        service_token=service_token,
        user_id=str(body.userId),
        tenant_id=str(body.tenantId) if body.tenantId is not None else None,
        permission_key=body.permissionKey,
    )
    return _response(decision)
