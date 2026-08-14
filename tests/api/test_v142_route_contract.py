import importlib

import verigence_security.main as main_module


def test_v142_global_user_routes_are_active_and_tenant_identity_routes_are_retired() -> None:
    # Other API tests intentionally exercise/mutate the module-level FastAPI app. Reload main so
    # this route-contract assertion is order-independent and validates a freshly composed runtime.
    app = importlib.reload(main_module).app
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
