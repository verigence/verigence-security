from __future__ import annotations

from inspect import signature

from verigence_security.services.phase1_self_onboarding import Phase1SelfOnboardingService


def test_v145_backend_create_registration_is_retired() -> None:
    """v1.4.6 supersedes the Security-proxied password/backend Clerk create-user path."""

    assert not hasattr(Phase1SelfOnboardingService, "register")
    assert "password" not in signature(Phase1SelfOnboardingService.start).parameters
    assert "clerk" not in signature(Phase1SelfOnboardingService.start).parameters
    assert "identity" in signature(Phase1SelfOnboardingService.complete).parameters
