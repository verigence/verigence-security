from verigence_security.main import app

paths = {
    path
    for route in app.routes
    if isinstance((path := getattr(route, "path", None)), str)
}

required = {
    "/security/v1/onboarding/users",
    "/security/v1/onboarding/users/{requestId}/bind",
    "/security/v1/auth/precheck",
    "/security/v1/platform/users",
    "/security/v1/platform/users/{userId}/status",
}
missing = sorted(required - paths)
if missing:
    raise SystemExit(f"Missing v1.4.2 runtime routes: {missing}")

retired_markers = (
    "self-registrations",
    "owner-invitations",
    "self-onboarding-token",
    "/onboarding/invitations/",
)
active_retired = sorted(
    path for path in paths if any(marker in path for marker in retired_markers)
)
if active_retired:
    raise SystemExit(f"Retired Tenant identity routes are still active: {active_retired}")

print("v1.4.2 runtime route contract PASSED")
