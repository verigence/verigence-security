from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from verigence_security.adapters.clerk_backend import ClerkBackendClient, ClerkBackendError
from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.api.v2_user_directory_schemas import (
    GlobalUserDirectoryResponse,
    PlatformUserCreateRequest,
)
from verigence_security.config import Settings, get_settings
from verigence_security.core.errors import security_error
from verigence_security.services.v2_human_actor import HumanActorContext
from verigence_security.services.v2_platform_user_create import (
    InvalidUserInput,
    V2PlatformUserCreateService,
)
from verigence_security.services.v2_user_directory import V2UserDirectoryService

router = APIRouter(prefix="/security/v1/platform", tags=["Security v2 USER Administration"])


def _require_super_admin(actor: HumanActorContext) -> None:
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")


def _user_response(row: dict[str, object]) -> GlobalUserDirectoryResponse:
    return GlobalUserDirectoryResponse(
        userId=str(row["user_id"]),
        displayName=str(row["display_name"]),
        primaryEmail=(str(row["primary_email"]) if row["primary_email"] is not None else None),
        primaryMobile=(str(row["primary_mobile"]) if row["primary_mobile"] is not None else None),
        status=str(row["status"]),
        clerkSubject=(str(row["clerk_subject"]) if row["clerk_subject"] is not None else None),
        onboardingStatus=(
            str(row["onboarding_status"]) if row["onboarding_status"] is not None else None
        ),
        createdAtUtc=row["created_at_utc"],  # type: ignore[arg-type]
        updatedAtUtc=row["updated_at_utc"],  # type: ignore[arg-type]
    )


@router.get("/users", response_model=list[GlobalUserDirectoryResponse])
def list_global_users(
    userStatus: str | None = Query(default=None, max_length=20),
    search: str | None = Query(default=None, max_length=320),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> list[GlobalUserDirectoryResponse]:
    _require_super_admin(actor)
    try:
        rows = V2UserDirectoryService(session).list_users(
            status=userStatus,
            search=search,
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return [_user_response(row) for row in rows]


@router.get("/users/{userId}", response_model=GlobalUserDirectoryResponse)
def get_global_user(
    userId: str,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> GlobalUserDirectoryResponse:
    _require_super_admin(actor)
    row = V2UserDirectoryService(session).get_user(userId)
    if row is None:
        raise HTTPException(status_code=404, detail="USER not found")
    return _user_response(row)


def _clerk_create_failure(exc: ClerkBackendError) -> HTTPException:
    # provider_detail is shown only for form validation errors, which describe the submitted
    # values (e.g. a breached password) and never carry other users' data.
    code = exc.provider_code
    if code == "form_identifier_exists":
        return HTTPException(status_code=409, detail="This email address already exists in the identity provider.")
    if code in {"form_password_pwned", "form_password_validation_failed", "form_password_length_too_short"}:
        return HTTPException(
            status_code=422,
            detail=exc.provider_detail or "Password does not meet the identity provider security requirements.",
        )
    if exc.status_code in {400, 409, 422}:
        suffix = f" ({code})" if code else ""
        return HTTPException(status_code=422, detail=f"Identity provider rejected the new user{suffix}.")
    return HTTPException(status_code=503, detail="Identity provider is temporarily unavailable")


@router.post("/users", response_model=GlobalUserDirectoryResponse, status_code=201)
def create_global_user(
    body: PlatformUserCreateRequest,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> GlobalUserDirectoryResponse:
    """SuperAdmin creates an ACTIVE user directly; no self-registration or email OTP."""
    _require_super_admin(actor)
    try:
        clerk = ClerkBackendClient(settings)
    except ClerkBackendError as exc:
        raise HTTPException(status_code=503, detail="Identity provider integration is not configured") from exc
    try:
        created = V2PlatformUserCreateService(session).create(
            first_name=body.firstName,
            last_name=body.lastName,
            email=body.email,
            mobile=body.mobile,
            password=body.password.get_secret_value(),
            actor=actor,
            correlation_id=request.state.correlation_id,
            clerk=clerk,
        )
    except PermissionError as exc:
        raise security_error("PERMISSION_DENIED") from exc
    except InvalidUserInput as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ClerkBackendError as exc:
        raise _clerk_create_failure(exc) from exc
    row = V2UserDirectoryService(session).get_user(created.user_id)
    if row is None:
        raise HTTPException(status_code=500, detail="Created USER could not be read back")
    return _user_response(row)
