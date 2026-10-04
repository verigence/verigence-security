from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy import text
from sqlalchemy.orm import Session

from verigence_security.adapters.clerk_backend import ClerkBackendClient, ClerkBackendError
from verigence_security.adapters.clerk_password_recovery import update_password
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


def _authorize_service(service_token: str, settings: Settings, session: Session) -> tuple[str, str]:
    """Returns (service principal id, integration key) for an allowed ServiceIntegration, else raises."""
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
    return str(row[0]), subject


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
    principal_id, subject = _authorize_service(service_token, settings, session)
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
            service_principal_id=principal_id,
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


class ServiceUserLookupResponse(BaseModel):
    userId: str
    displayName: str | None
    status: str


@router.get("/users/lookup", response_model=ServiceUserLookupResponse)
def lookup_user_for_service(
    email: str,
    service_token: str = Depends(service_integration_token),
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> ServiceUserLookupResponse:
    """An allowed ServiceIntegration (the HR service) finds the existing Verigence user with this
    email so an employee record can be linked to it. Same guard as user creation; read-only; it
    returns only the user id, display name and status."""
    _authorize_service(service_token, settings, session)
    wanted = email.strip().lower()
    if not wanted or len(wanted) > 254:
        raise HTTPException(status_code=422, detail="A valid email is required")
    row = session.execute(
        text(
            """
            SELECT user_id::text, display_name, status
            FROM security.users
            WHERE lower(primary_email) = :email
            ORDER BY (status = 'ACTIVE') DESC, created_at_utc
            LIMIT 1
            """
        ),
        {"email": wanted},
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="No Verigence user has this email")
    return ServiceUserLookupResponse(userId=row[0], displayName=row[1], status=str(row[2]))


class ServiceUserEmployeeResponse(BaseModel):
    userId: str
    isEmployee: bool


@router.post("/users/{userId}/employee", response_model=ServiceUserEmployeeResponse)
def mark_user_as_employee_for_service(
    userId: str,
    service_token: str = Depends(service_integration_token),
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> ServiceUserEmployeeResponse:
    """The HR service ticks "Is Employee" on an existing user it has just linked to an employee
    record. Same guard as user creation; it can only set the flag, never clear it or change
    anything else."""
    _authorize_service(service_token, settings, session)
    try:
        updated = session.execute(
            text(
                "UPDATE security.users SET is_employee=true, updated_at_utc=now()"
                " WHERE user_id=CAST(:user_id AS uuid) RETURNING 1"
            ),
            {"user_id": userId},
        ).first()
    except Exception as exc:  # a malformed id must read as not found, not as a server error
        session.rollback()
        raise HTTPException(status_code=404, detail="User not found") from exc
    if updated is None:
        session.rollback()
        raise HTTPException(status_code=404, detail="User not found")
    session.commit()
    return ServiceUserEmployeeResponse(userId=userId, isEmployee=True)


class ServicePasswordRequest(BaseModel):
    password: SecretStr = Field(min_length=8, max_length=256)


class ServicePasswordResponse(BaseModel):
    userId: str
    primaryEmail: str | None


@router.post("/users/{userId}/password", response_model=ServicePasswordResponse)
def set_password_for_service(
    userId: str,
    body: ServicePasswordRequest,
    service_token: str = Depends(service_integration_token),
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> ServicePasswordResponse:
    """The HR service sets a temporary password for an ACTIVE user it is about to email. Same guard
    as user creation. A user who is still PENDING (SuperAdmin has not allowed them yet), suspended
    or disabled is refused, so a password is never handed out for an account that cannot sign in.
    The password is never stored, logged or returned by Security."""
    _authorize_service(service_token, settings, session)
    try:
        row = session.execute(
            text(
                """
                SELECT u.status, u.primary_email, e.provider_subject
                FROM security.users u
                LEFT JOIN security.external_identities e
                  ON e.user_id=u.user_id AND e.provider='CLERK' AND e.status='ACTIVE'
                WHERE u.user_id=CAST(:user_id AS uuid)
                """
            ),
            {"user_id": userId},
        ).first()
    except Exception as exc:  # a malformed id must read as not found, not as a server error
        session.rollback()
        raise HTTPException(status_code=404, detail="User not found") from exc
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")
    status, email, clerk_subject = str(row[0]), row[1], row[2]
    if status != "ACTIVE":
        raise HTTPException(
            status_code=409, detail=f"The user is {status.lower()}, not active; allow them first"
        )
    if not clerk_subject:
        raise HTTPException(status_code=409, detail="The user has no sign-in identity")
    try:
        clerk = ClerkBackendClient(settings)
    except ClerkBackendError as exc:
        raise HTTPException(
            status_code=503, detail="Identity provider integration is not configured"
        ) from exc
    try:
        update_password(
            clerk, clerk_user_id=str(clerk_subject), password=body.password.get_secret_value()
        )
    except ClerkBackendError as exc:
        raise HTTPException(status_code=502, detail="The password could not be set") from exc
    return ServicePasswordResponse(userId=userId, primaryEmail=str(email) if email else None)
