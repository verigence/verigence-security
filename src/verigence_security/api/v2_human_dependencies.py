from __future__ import annotations

from collections.abc import Generator

from fastapi import Depends

from verigence_security.adapters.identity import ClerkJwtIdentityProvider
from verigence_security.api.dependencies import bearer_token
from verigence_security.config import Settings, get_settings
from verigence_security.core.errors import security_error
from verigence_security.db.session import build_session_factory
from verigence_security.services.v2_human_actor import (
    HumanActorAuthenticationService,
    HumanActorContext,
)


def clerk_human_identity_token(
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
):
    """Validate a first-party Clerk session JWT for a human Security caller.

    This dependency intentionally bypasses the generic DEV-mock/legacy token chooser.
    Security-issued SERVICE_INTEGRATION JWTs therefore cannot enter human-admin routes.
    """

    return ClerkJwtIdentityProvider(settings).verify(token)


def clerk_human_actor(
    identity=Depends(clerk_human_identity_token),
    settings: Settings = Depends(get_settings),
) -> Generator[HumanActorContext, None, None]:
    factory = build_session_factory(settings)
    if factory is None:
        raise security_error("DATABASE_UNAVAILABLE")
    session = factory()
    try:
        yield HumanActorAuthenticationService(session).authenticate(identity)
    finally:
        session.close()
