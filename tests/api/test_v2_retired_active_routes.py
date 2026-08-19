from __future__ import annotations

from verigence_security.main import app


def test_target_human_routes_remain_active_and_duplicate_platformadmin_routes_are_retired() -> None:
    paths = set(app.openapi().get("paths", {}))

    # Security is the Verigence-facing human authentication/onboarding boundary.
    assert "/security/v1/auth/login" in paths
    assert "/security/v1/onboarding/users" in paths
    assert "/security/v1/onboarding/users/{signupAttemptId}/verify-email" in paths
    assert "/security/v1/onboarding/users/{signupAttemptId}/resend-email-code" in paths

    # Current Audit Core dev still uses the old OAuth endpoint. The access-session bridge remains
    # deprecated compatibility; neither is a target Phase-1 route.
    assert "/oauth/token" in paths
    assert "/security/v1/access-sessions" in paths

    # Human admins use the canonical Security login; no separate PlatformAdmin JWT surface remains.
    assert "/security/v1/platform/auth/login" not in paths
    assert "/security/v1/platform/bootstrap/claim" not in paths
    assert "/security/v1/platform/me" not in paths
