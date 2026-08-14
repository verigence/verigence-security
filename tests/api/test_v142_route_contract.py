from verigence_security.main import app


def test_v142_global_user_routes_are_active_and_tenant_identity_routes_are_retired() -> None:
    paths = {
        path
        for route in app.routes
        if isinstance((path := getattr(route, "path", None)), str)
    }

    assert "/security/v1/onboarding/users" in paths
    assert "/security/v1/onboarding/users/{requestId}/bind" in paths
    assert "/security/v1/auth/precheck" in paths
    assert "/security/v1/platform/users" in paths
    assert "/security/v1/platform/users/{userId}/status" in paths

    assert not any("self-registrations" in path for path in paths)
    assert not any("owner-invitations" in path for path in paths)
    assert not any("self-onboarding-token" in path for path in paths)
    assert not any("/onboarding/invitations/" in path for path in paths)
