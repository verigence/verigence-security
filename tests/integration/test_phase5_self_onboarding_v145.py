from __future__ import annotations

from inspect import signature

from verigence_security.services.phase1_self_onboarding import Phase1SelfOnboardingService


def test_v148_backend_auth_replaces_client_clerk_completion_contract() -> None:
    """v1.4.8 accepts transient credentials in Security and retires Clerk-session completion."""

    assert not hasattr(Phase1SelfOnboardingService, "register")
    start_parameters = signature(Phase1SelfOnboardingService.start).parameters
    assert "password" in start_parameters
    assert "clerk" in start_parameters
    assert not hasattr(Phase1SelfOnboardingService, "complete")

    verify_parameters = signature(Phase1SelfOnboardingService.verify_email_code).parameters
    assert "code" in verify_parameters
    assert "clerk" in verify_parameters
