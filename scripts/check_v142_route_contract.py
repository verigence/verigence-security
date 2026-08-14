from verigence_security.main import app

schema = app.openapi()
paths = set(schema.get("paths", {}))

required = {
    "/security/v1/onboarding/users",
    "/security/v1/auth/precheck",
    "/security/v1/platform/users",
    "/security/v1/platform/users/{userId}/status",
}
missing = sorted(required - paths)
if missing:
    raise SystemExit(f"Missing global USER runtime routes: {missing}")

retired_markers = (
    "self-registrations",
    "owner-invitations",
    "self-onboarding-token",
    "/onboarding/invitations/",
    "/onboarding/users/{requestId}/bind",
)
active_retired = sorted(
    path for path in paths if any(marker in path for marker in retired_markers)
)
if active_retired:
    raise SystemExit(f"Retired identity routes are still active: {active_retired}")

print("v1.4.5 Phase 1 self-onboarding runtime route contract PASSED")
