"""The minimum Verigence app version (product owner, 4 Nov 2026). The app asks the public status at
start to show "Update required" before anyone types a password; SuperAdmin sets the policy."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
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


class ProjectPolicyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # None removes the Project's own minimum.
    minimumVersion: str | None = Field(default=None, pattern=r"^\d+\.\d+\.\d+$")
    # None means at once.
    effectiveFrom: datetime | None = None


def _admin_view(service: AppVersionPolicyService) -> dict[str, Any]:
    now = datetime.now(UTC)
    policy = service.policy()
    return {
        **policy.view(now),
        "devicesBelow": service.devices_below(policy.minimum_version),
        # A minimum of its own for the people of one Project (product owner, 19 Nov 2026).
        "projects": [
            {**p.view(now), "devicesBelow": service.project_devices_below(p.tenant_id, p.minimum_version)}
            for p in service.project_policies()
        ],
        "projectChoices": service.project_choices(),
    }


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
    return _admin_view(AppVersionPolicyService(session))


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
    service.set_policy(
        minimum_version=body.minimumVersion,
        effective_from=body.effectiveFrom,
        download_url=body.downloadUrl,
        actor_user_id=actor.user_id,
        correlation_id=getattr(request.state, "correlation_id", ""),
    )
    return _admin_view(service)


@router.get("/admin/app-version-policy/projects/{tenantId}/impact")
def project_policy_impact(
    tenantId: UUID,
    minimumVersion: str = Query(pattern=r"^\d+\.\d+\.\d+$"),
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, Any]:
    """Before saving: the app installations of the Project's people that a minimum would stop."""
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")
    return {"devicesBelow": AppVersionPolicyService(session).project_devices_below(str(tenantId), minimumVersion)}


@router.put("/admin/app-version-policy/projects/{tenantId}")
def set_project_policy(
    tenantId: UUID,
    body: ProjectPolicyIn,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, Any]:
    """The minimum app version for the people who work in one Project; no version removes it."""
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")
    service = AppVersionPolicyService(session)
    try:
        service.set_project_policy(
            tenant_id=str(tenantId),
            minimum_version=body.minimumVersion,
            effective_from=body.effectiveFrom,
            actor_user_id=actor.user_id,
            correlation_id=getattr(request.state, "correlation_id", ""),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc
    return _admin_view(service)
