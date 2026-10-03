from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from verigence_security.adapters.clerk_backend import ClerkBackendClient, ClerkBackendError
from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.routes.authorization import service_integration_token
from verigence_security.api.routes.v2_user_admin import _clerk_create_failure, _user_response
from verigence_security.api.v2_user_directory_schemas import (
    GlobalUserDirectoryResponse,
    PlatformUserCreateRequest,
)
from verigence_security.config import Settings, get_settings
from verigence_security.core.errors import security_error
from verigence_security.services.token_service import TokenService
from verigence_security.services.v2_platform_user_create import (
    InvalidUserInput,
    V2PlatformUserCreateService,
)
from verigence_security.services.v2_user_directory import V2UserDirectoryService

router = APIRouter(prefix="/security/v1/service", tags=["ServiceIntegration"])


def _allowed_integrations(settings: Settings) -> frozenset[str]:
    return frozenset(
        key.strip() for key in settings.service_user_create_integrations.split(",") if key.strip()
    )


@router.post("/users", response_model=GlobalUserDirectoryResponse, status_code=201)
def create_user_for_service(
    body: PlatformUserCreateRequest,
    request: Request,
    service_token: str = Depends(service_integration_token),
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> GlobalUserDirectoryResponse:
    """An allowed ServiceIntegration (the HR service) creates an ACTIVE user with a verified email
    and the given password, with no OTP step. Narrow by design: only integrations named in
    SERVICE_USER_CREATE_INTEGRATIONS may call it; every other service token is refused."""
    claims = TokenService(settings).verify_service_token(service_token, audience="security")
    subject = str(claims.get("sub") or "").strip()
    if not subject:
        raise security_error("AUTH_TOKEN_INVALID")
    row = session.execute(
        text(
            """
            SELECT si.principal_id
            FROM security.service_integrations si
            JOIN security.security_principals p ON p.principal_id = si.principal_id
            WHERE si.integration_key = :key
              AND p.actor_type = 'SERVICE_INTEGRATION' AND p.status = 'ACTIVE'
            """
        ),
        {"key": subject},
    ).first()
    if row is None:
        raise security_error("AUTH_TOKEN_INVALID")
    if subject not in _allowed_integrations(settings):
        raise security_error("PERMISSION_DENIED")

    try:
        clerk = ClerkBackendClient(settings)
    except ClerkBackendError as exc:
        raise HTTPException(
            status_code=503, detail="Identity provider integration is not configured"
        ) from exc
    try:
        created = V2PlatformUserCreateService(session).create_for_service(
            first_name=body.firstName,
            last_name=body.lastName,
            email=body.email,
            mobile=body.mobile,
            password=body.password.get_secret_value(),
            service_principal_id=str(row[0]),
            service_integration_key=subject,
            correlation_id=request.state.correlation_id,
            clerk=clerk,
        )
    except InvalidUserInput as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ClerkBackendError as exc:
        raise _clerk_create_failure(exc) from exc
    user = V2UserDirectoryService(session).get_user(created.user_id)
    if user is None:
        raise HTTPException(status_code=500, detail="Created USER could not be read back")
    return _user_response(user)
