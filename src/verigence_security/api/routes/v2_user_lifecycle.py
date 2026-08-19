from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from verigence_security.adapters.clerk_backend import ClerkBackendClient, ClerkBackendError
from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.api.v2_user_lifecycle_schemas import (
    UserHardDeleteResponse,
    UserStatusTransitionRequest,
    UserStatusTransitionResponse,
)
from verigence_security.config import Settings, get_settings
from verigence_security.core.errors import security_error
from verigence_security.services.v2_human_actor import HumanActorContext
from verigence_security.services.v2_user_lifecycle import V2UserLifecycleService

router = APIRouter(prefix="/security/v1", tags=["Security v2 USER Lifecycle"])


def _clerk(settings: Settings) -> ClerkBackendClient:
    try:
        return ClerkBackendClient(settings)
    except ClerkBackendError as exc:
        raise HTTPException(
            status_code=503,
            detail="Identity provider integration is not configured",
        ) from exc


@router.patch(
    "/users/{userId}/status",
    response_model=UserStatusTransitionResponse,
)
def change_user_status(
    userId: str,
    body: UserStatusTransitionRequest,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> UserStatusTransitionResponse:
    try:
        result = V2UserLifecycleService(session).transition(
            user_id=userId,
            requested_status=body.status,
            actor=actor,
            reason_code=body.reasonCode,
            reason=body.reason,
            correlation_id=request.state.correlation_id,
            clerk=_clerk(settings),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise security_error("PERMISSION_DENIED") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ClerkBackendError as exc:
        raise HTTPException(
            status_code=502,
            detail="Identity-provider lifecycle synchronization failed",
        ) from exc

    return UserStatusTransitionResponse(
        userId=result.user_id,
        status=result.status,
        previousStatus=result.previous_status,
        changed=result.changed,
        deletionRequestId=result.deletion_request_id,
    )


@router.delete(
    "/platform/users/{userId}",
    response_model=UserHardDeleteResponse,
)
def hard_delete_user(
    userId: str,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> UserHardDeleteResponse:
    try:
        result = V2UserLifecycleService(session).hard_delete(
            user_id=userId,
            actor=actor,
            correlation_id=request.state.correlation_id,
            clerk=_clerk(settings),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise security_error("PERMISSION_DENIED") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ClerkBackendError as exc:
        raise HTTPException(
            status_code=502,
            detail="Identity-provider deletion failed",
        ) from exc

    return UserHardDeleteResponse(
        userId=result.user_id,
        deletionRequestId=result.deletion_request_id,
        tombstoneId=result.tombstone_id,
        deletedAtUtc=result.deleted_at_utc.isoformat(),
        retainUntilUtc=result.retain_until_utc.isoformat(),
    )
