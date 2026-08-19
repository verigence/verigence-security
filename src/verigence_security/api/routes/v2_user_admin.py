from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.v2_human_dependencies import clerk_human_actor
from verigence_security.api.v2_user_directory_schemas import GlobalUserDirectoryResponse
from verigence_security.core.errors import security_error
from verigence_security.services.v2_human_actor import HumanActorContext
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
    actor: HumanActorContext = Depends(clerk_human_actor),
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
    actor: HumanActorContext = Depends(clerk_human_actor),
    session: Session = Depends(platform_session),
) -> GlobalUserDirectoryResponse:
    _require_super_admin(actor)
    row = V2UserDirectoryService(session).get_user(userId)
    if row is None:
        raise HTTPException(status_code=404, detail="USER not found")
    return _user_response(row)
