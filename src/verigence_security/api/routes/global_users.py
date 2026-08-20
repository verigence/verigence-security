from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy.orm import Session

from verigence_security.adapters.clerk_backend import ClerkBackendClient, ClerkBackendError
from verigence_security.api.dependencies import source_ip
from verigence_security.api.platform_dependencies import (
    platform_session,
    require_platform_permission,
)
from verigence_security.config import Settings, get_settings
from verigence_security.core.errors import security_error
from verigence_security.services.global_user_onboarding import GlobalUserOnboardingService
from verigence_security.services.onboarding_key import require_onboarding_key_shape
from verigence_security.services.phase1_self_onboarding import Phase1SelfOnboardingService
from verigence_security.services.uc001_self_onboarding import UC001SelfOnboardingService

router = APIRouter(prefix="/security/v1", tags=["Global User Onboarding"])


class GlobalUserOnboardingRequest(BaseModel):
    firstName: str = Field(min_length=1, max_length=120)
    lastName: str = Field(min_length=1, max_length=120)
    email: str = Field(min_length=3, max_length=320)
    mobile: str = Field(min_length=10, max_length=40)
    password: SecretStr


class EmailOtpRequest(BaseModel):
    code: SecretStr


class GlobalUserStatusRequest(BaseModel):
    status: Literal["ACTIVE", "SUSPENDED", "DISABLED", "EXITED"]
    reason: str | None = Field(default=None, max_length=1000)


class AuthenticationPrecheckRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)


def _clerk(settings: Settings) -> ClerkBackendClient:
    try:
        return ClerkBackendClient(settings)
    except ClerkBackendError as exc:
        raise HTTPException(status_code=503, detail="Identity provider integration is not configured") from exc


def _clerk_failure(exc: ClerkBackendError) -> HTTPException:
    """Translate Clerk failures without hiding actionable DEV onboarding problems."""

    code = exc.provider_code
    detail = exc.provider_detail

    if code == "form_identifier_exists":
        return HTTPException(
            status_code=409,
            detail="This email address already exists in the identity provider.",
        )
    if code in {"form_password_pwned", "form_password_validation_failed"}:
        return HTTPException(
            status_code=422,
            detail=detail or "Password does not meet the identity provider security requirements.",
        )
    if code == "dev_monthly_email_limit_exceeded":
        return HTTPException(
            status_code=429,
            detail="The Clerk DEV email verification limit has been reached.",
        )
    if code == "form_param_unknown":
        return HTTPException(
            status_code=502,
            detail="Identity provider rejected the Security signup request format (form_param_unknown).",
        )
    if exc.status_code in {400, 409, 422}:
        provider_suffix = f" ({code})" if code else ""
        return HTTPException(
            status_code=422,
            detail=detail or f"Identity provider rejected the signup request{provider_suffix}.",
        )
    return HTTPException(status_code=503, detail="Identity provider is temporarily unavailable")


@router.post("/onboarding/users", status_code=status.HTTP_202_ACCEPTED)
def start_global_user_onboarding(
    body: GlobalUserOnboardingRequest,
    request: Request,
    onboarding_key: str = Header(min_length=11, max_length=11, alias="X-Onboarding-Key"),
    settings: Settings = Depends(get_settings),
    client_ip: str = Depends(source_ip),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    # Cheap structural rejection before any Clerk network call or Argon2 verification. The prefix
    # is intentionally public; the complete key remains authoritative only in Security storage.
    try:
        normalized_key = require_onboarding_key_shape(onboarding_key)
    except ValueError as exc:
        raise security_error("PERMISSION_DENIED") from exc

    try:
        return UC001SelfOnboardingService(session).start(
            first_name=body.firstName,
            last_name=body.lastName,
            email=body.email,
            mobile=body.mobile,
            password=body.password.get_secret_value(),
            onboarding_key=normalized_key,
            source_ip=client_ip,
            correlation_id=request.state.correlation_id,
            clerk=_clerk(settings),
        )
    except ClerkBackendError as exc:
        raise _clerk_failure(exc) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/onboarding/users/{signupAttemptId}/resend-email-code")
def resend_global_user_email_code(
    signupAttemptId: str,
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    try:
        return Phase1SelfOnboardingService(session).resend_email_code(
            signup_attempt_id=signupAttemptId,
            clerk=_clerk(settings),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ClerkBackendError as exc:
        raise _clerk_failure(exc) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/onboarding/users/{signupAttemptId}/verify-email",
    status_code=status.HTTP_201_CREATED,
)
def verify_global_user_email(
    signupAttemptId: str,
    body: EmailOtpRequest,
    request: Request,
    settings: Settings = Depends(get_settings),
    client_ip: str = Depends(source_ip),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    try:
        return Phase1SelfOnboardingService(session).verify_email_code(
            signup_attempt_id=signupAttemptId,
            code=body.code.get_secret_value(),
            source_ip=client_ip,
            correlation_id=request.state.correlation_id,
            clerk=_clerk(settings),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ClerkBackendError as exc:
        raise _clerk_failure(exc) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/platform/users")
def list_global_users(
    status_filter: str | None = None,
    claims: dict[str, Any] = Depends(require_platform_permission("security.user.read")),
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> list[dict[str, object]]:
    _ = claims
    normalized = status_filter.upper() if status_filter else None
    return GlobalUserOnboardingService(session, settings).list_users(normalized)


@router.patch("/platform/users/{userId}/status")
def change_global_user_status(
    userId: str,
    body: GlobalUserStatusRequest,
    request: Request,
    claims: dict[str, Any] = Depends(require_platform_permission("security.user.manage")),
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    try:
        return GlobalUserOnboardingService(session, settings).set_user_status(
            user_id=userId,
            new_status=body.status,
            actor_user_id=str(claims["sub"]),
            reason=body.reason,
            correlation_id=request.state.correlation_id,
            clerk=_clerk(settings),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ClerkBackendError as exc:
        raise HTTPException(status_code=502, detail="Identity-provider lifecycle synchronization failed") from exc


@router.post("/auth/precheck")
def authentication_precheck(
    body: AuthenticationPrecheckRequest,
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> dict[str, bool]:
    # Deliberately returns only allow/deny so callers cannot enumerate Security lifecycle detail.
    return {"allowed": GlobalUserOnboardingService(session, settings).precheck(body.email)}
