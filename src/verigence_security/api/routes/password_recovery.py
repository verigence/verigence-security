from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy.orm import Session

from verigence_security.adapters.clerk_backend import ClerkBackendClient, ClerkBackendError
from verigence_security.api.dependencies import source_ip
from verigence_security.api.platform_dependencies import platform_session
from verigence_security.config import Settings, get_settings
from verigence_security.services.password_recovery import PasswordRecoveryService

router = APIRouter(prefix="/security/v1/auth/password-reset", tags=["Password Recovery"])


class PasswordResetStartRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)


class PasswordResetCompleteRequest(BaseModel):
    code: SecretStr
    newPassword: SecretStr


def _clerk(settings: Settings) -> ClerkBackendClient:
    try:
        return ClerkBackendClient(settings)
    except ClerkBackendError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Password recovery is temporarily unavailable.",
        ) from exc


def _provider_failure(exc: ClerkBackendError) -> HTTPException:
    if exc.provider_code in {"form_password_pwned", "form_password_validation_failed"}:
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=exc.provider_detail or "The new password does not meet security requirements.",
        )
    if exc.provider_code == "dev_monthly_email_limit_exceeded":
        return HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="The DEV email verification limit has been reached. Please try again later.",
        )
    if exc.status_code in {400, 409, 422}:
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=exc.provider_detail or "Password recovery could not be completed.",
        )
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Password recovery is temporarily unavailable.",
    )


@router.post("", status_code=status.HTTP_202_ACCEPTED)
def start_password_reset(
    body: PasswordResetStartRequest,
    request: Request,
    settings: Settings = Depends(get_settings),
    client_ip: str = Depends(source_ip),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    try:
        return PasswordRecoveryService(session).start(
            email=body.email,
            source_ip=client_ip,
            correlation_id=request.state.correlation_id,
            clerk=_clerk(settings),
        )
    except ClerkBackendError as exc:
        raise _provider_failure(exc) from exc
    except ValueError as exc:
        status_code = (
            status.HTTP_429_TOO_MANY_REQUESTS
            if str(exc).startswith("Too many password reset requests")
            else status.HTTP_400_BAD_REQUEST
        )
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc


@router.post("/{passwordResetAttemptId}/resend")
def resend_password_reset_code(
    passwordResetAttemptId: str,
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    try:
        return PasswordRecoveryService(session).resend(
            attempt_id=passwordResetAttemptId,
            clerk=_clerk(settings),
        )
    except (LookupError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset request is invalid or expired.",
        ) from exc
    except ClerkBackendError as exc:
        raise _provider_failure(exc) from exc


@router.post("/{passwordResetAttemptId}/cancel")
def cancel_password_reset(
    passwordResetAttemptId: str,
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> dict[str, str]:
    try:
        return PasswordRecoveryService(session).cancel(
            attempt_id=passwordResetAttemptId,
            clerk=_clerk(settings),
        )
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset request is invalid or expired.",
        ) from exc
    except ClerkBackendError as exc:
        raise _provider_failure(exc) from exc


@router.post("/{passwordResetAttemptId}/complete")
def complete_password_reset(
    passwordResetAttemptId: str,
    body: PasswordResetCompleteRequest,
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> dict[str, str]:
    try:
        return PasswordRecoveryService(session).complete(
            attempt_id=passwordResetAttemptId,
            code=body.code.get_secret_value(),
            new_password=body.newPassword.get_secret_value(),
            clerk=_clerk(settings),
        )
    except (LookupError, ValueError) as exc:
        detail = str(exc)
        if "password" not in detail.lower() and "verification" not in detail.lower():
            detail = "Password reset request is invalid or expired."
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc
    except ClerkBackendError as exc:
        raise _provider_failure(exc) from exc
