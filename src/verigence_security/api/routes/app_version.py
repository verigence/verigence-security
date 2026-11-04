"""The minimum Verigence app version (product owner, 4 Nov 2026). The app asks the public status at
start to show "Update required" before anyone types a password; SuperAdmin sets the policy."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.core.errors import security_error
from verigence_security.services.app_version_policy import AppVersionPolicyService
from verigence_security.services.v2_human_actor import HumanActorContext

router = APIRouter(prefix="/security/v1", tags=["App version"])


class PolicyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # None removes the minimum: every app version may be used.
    minimumVersion: str | None = Field(default=None, pattern=r"^\d+\.\d+\.\d+$")
    # None means at once.
    effectiveFrom: datetime | None = None
    downloadUrl: str | None = Field(default=None, min_length=8, max_length=300, pattern=r"^https://")


@router.get("/status/app-version")
def app_version_status(session: Session = Depends(platform_session)) -> dict[str, Any]:
    """Needs no sign-in: the oldest app version allowed, from when, and where to get the latest."""
    return AppVersionPolicyService(session).policy().view(datetime.now(UTC))


@router.get("/admin/app-version-policy")
def get_policy(
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, Any]:
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")
    service = AppVersionPolicyService(session)
    policy = service.policy()
    return {
        **policy.view(datetime.now(UTC)),
        "devicesBelow": service.devices_below(policy.minimum_version),
    }


@router.get("/admin/app-version-policy/impact")
def policy_impact(
    minimumVersion: str = Query(pattern=r"^\d+\.\d+\.\d+$"),
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, Any]:
    """Before saving: the app installations seen in the last 30 days that a minimum would stop."""
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")
    return {"devicesBelow": AppVersionPolicyService(session).devices_below(minimumVersion)}


@router.put("/admin/app-version-policy")
def set_policy(
    body: PolicyIn,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, Any]:
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")
    service = AppVersionPolicyService(session)
    policy = service.set_policy(
        minimum_version=body.minimumVersion,
        effective_from=body.effectiveFrom,
        download_url=body.downloadUrl,
        actor_user_id=actor.user_id,
        correlation_id=getattr(request.state, "correlation_id", ""),
    )
    return {
        **policy.view(datetime.now(UTC)),
        "devicesBelow": service.devices_below(policy.minimum_version),
    }
