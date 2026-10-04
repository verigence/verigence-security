from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.core.errors import security_error
from verigence_security.services.feature_access import FeatureAccessService
from verigence_security.services.v2_human_actor import HumanActorContext

router = APIRouter(prefix="/security/v1", tags=["Feature access"])

FeatureKeyPath = Literal["AUDIT", "ANALYTICS"]


class MyFeaturesResponse(BaseModel):
    features: dict[str, bool]


class EveryoneBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


class PersonBody(BaseModel):
    """enabled true or false is this person's own choice; null removes it."""

    model_config = ConfigDict(extra="forbid")
    enabled: bool | None


def _require_super_admin(actor: HumanActorContext) -> None:
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")


@router.get("/me/features", response_model=MyFeaturesResponse)
def my_features(
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> MyFeaturesResponse:
    """Which sections of the apps this person may see. Controls navigation only."""
    return MyFeaturesResponse(
        features=FeatureAccessService(session).resolve(user_id=actor.user_id, is_super_admin=actor.is_super_admin)
    )


@router.get("/admin/features")
def feature_overview(
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    """Every feature with its setting for everyone and the people set on their own. SuperAdmin."""
    _require_super_admin(actor)
    return {"features": FeatureAccessService(session).overview()}


@router.put("/admin/features/{featureKey}/everyone")
def set_for_everyone(
    featureKey: FeatureKeyPath,
    body: EveryoneBody,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    _require_super_admin(actor)
    FeatureAccessService(session).set_everyone(
        feature_key=featureKey,
        enabled=body.enabled,
        actor_user_id=actor.user_id,
        correlation_id=request.state.correlation_id,
    )
    return {"featureKey": featureKey, "everyone": body.enabled}


@router.put("/admin/features/{featureKey}/users/{userId}")
def set_for_person(
    featureKey: FeatureKeyPath,
    userId: str,
    body: PersonBody,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    _require_super_admin(actor)
    try:
        FeatureAccessService(session).set_person(
            feature_key=featureKey,
            user_id=userId,
            enabled=body.enabled,
            actor_user_id=actor.user_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"featureKey": featureKey, "userId": userId, "enabled": body.enabled}
