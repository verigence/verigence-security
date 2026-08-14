from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from verigence_security.adapters.clerk_backend import ClerkBackendClient, ClerkBackendError
from verigence_security.adapters.identity import ClerkJwtIdentityProvider
from verigence_security.api.dependencies import bearer_token, source_ip
from verigence_security.api.platform_dependencies import platform_session, require_platform_permission
from verigence_security.config import Settings, get_settings
from verigence_security.services.global_user_onboarding import GlobalUserOnboardingService

router = APIRouter(prefix="/security/v1", tags=["Global User Onboarding"])


class OnboardingKeyRequest(BaseModel):
    onboardingKey: str = Field(min_length=8, max_length=64)
    enabled: bool = True


class GlobalUserOnboardingRequest(BaseModel):
    displayName: str = Field(min_length=1, max_length=240)
    email: str = Field(min_length=3, max_length=320)


class GlobalUserStatusRequest(BaseModel):
    status: Literal["ACTIVE", "SUSPENDED", "DISABLED", "EXITED"]
    reason: str | None = Field(default=None, max_length=1000)


class AuthenticationPrecheckRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)


def _clerk(settings: Settings) -> ClerkBackendClient:
    try:
        return ClerkBackendClient(settings)
    except ClerkBackendError as exc:
        raise HTTPException(status_code=503, detail="Clerk lifecycle integration is not configured") from exc


@router.get("/platform/user-onboarding/key")
def get_global_onboarding_key(
    claims: dict[str, Any] = Depends(
        require_platform_permission("security.user_onboarding.read")
    ),
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    _ = claims
    try:
        return GlobalUserOnboardingService(session, settings).get_onboarding_key()
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.put("/platform/user-onboarding/key")
def set_global_onboarding_key(
    body: OnboardingKeyRequest,
    request: Request,
    claims: dict[str, Any] = Depends(
        require_platform_permission("security.user_onboarding.manage")
    ),
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    try:
        return GlobalUserOnboardingService(session, settings).set_onboarding_key(
            actor_user_id=str(claims["sub"]),
            onboarding_key=body.onboardingKey,
            enabled=body.enabled,
            correlation_id=request.state.correlation_id,
        )
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/platform/user-onboarding/key/rotate")
def rotate_global_onboarding_key(
    request: Request,
    claims: dict[str, Any] = Depends(
        require_platform_permission("security.user_onboarding.manage")
    ),
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    try:
        return GlobalUserOnboardingService(session, settings).rotate_onboarding_key(
            actor_user_id=str(claims["sub"]),
            correlation_id=request.state.correlation_id,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.delete(
    "/platform/user-onboarding/key",
    status_code=status.HTTP_204_NO_CONTENT,
)
def disable_global_onboarding_key(
    request: Request,
    claims: dict[str, Any] = Depends(
        require_platform_permission("security.user_onboarding.manage")
    ),
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> Response:
    changed = GlobalUserOnboardingService(session, settings).disable_onboarding_key(
        actor_user_id=str(claims["sub"]),
        correlation_id=request.state.correlation_id,
    )
    if not changed:
        raise HTTPException(status_code=404, detail="Global user onboarding key is not configured")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/onboarding/users", status_code=status.HTTP_201_CREATED)
def submit_global_user_onboarding(
    body: GlobalUserOnboardingRequest,
    request: Request,
    onboarding_key: str = Header(min_length=8, max_length=64, alias="X-Onboarding-Key"),
    settings: Settings = Depends(get_settings),
    client_ip: str = Depends(source_ip),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    service = GlobalUserOnboardingService(session, settings)
    try:
        return service.submit(
            email=body.email,
            display_name=body.displayName,
            onboarding_key=onboarding_key,
            source_ip=client_ip,
            correlation_id=request.state.correlation_id,
            clerk=_clerk(settings),
        )
    except ClerkBackendError as exc:
        raise HTTPException(status_code=502, detail="Clerk invitation could not be created") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/onboarding/users/{requestId}/bind")
def bind_global_user_clerk_identity(
    requestId: str,
    request: Request,
    authorization_token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    client_ip: str = Depends(source_ip),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    identity = ClerkJwtIdentityProvider(settings).verify(authorization_token)
    try:
        return GlobalUserOnboardingService(session, settings).bind_authenticated_clerk_user(
            onboarding_request_id=requestId,
            identity=identity,
            source_ip=client_ip,
            correlation_id=request.state.correlation_id,
            clerk=_clerk(settings),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ClerkBackendError as exc:
        raise HTTPException(status_code=502, detail="Clerk identity lifecycle synchronization failed") from exc


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
        raise HTTPException(status_code=502, detail="Clerk lifecycle synchronization failed") from exc


@router.post("/auth/precheck")
def authentication_precheck(
    body: AuthenticationPrecheckRequest,
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> dict[str, bool]:
    # Deliberately returns only an allow/deny boolean so the UI can gate Clerk sign-in without
    # exposing detailed Security lifecycle state through the public endpoint.
    return {"allowed": GlobalUserOnboardingService(session, settings).precheck(body.email)}
