from __future__ import annotations

from fastapi import APIRouter, status

from verigence_security.api.routes import global_users

router = APIRouter(tags=["Deprecated Onboarding Compatibility"])

# Temporary compatibility only. The approved target is Clerk first-party signup plus an
# authenticated bind operation. These routes stay isolated until the bind URL/contract is
# explicitly fixed; no PlatformAdmin USER-list/status operation from global_users is registered.
router.add_api_route(
    "/security/v1/onboarding/users",
    global_users.start_global_user_onboarding,
    methods=["POST"],
    status_code=status.HTTP_202_ACCEPTED,
    deprecated=True,
)
router.add_api_route(
    "/security/v1/onboarding/users/{signupAttemptId}/resend-email-code",
    global_users.resend_global_user_email_code,
    methods=["POST"],
    deprecated=True,
)
router.add_api_route(
    "/security/v1/onboarding/users/{signupAttemptId}/verify-email",
    global_users.verify_global_user_email,
    methods=["POST"],
    status_code=status.HTTP_201_CREATED,
    deprecated=True,
)
router.add_api_route(
    "/security/v1/auth/precheck",
    global_users.authentication_precheck,
    methods=["POST"],
    deprecated=True,
)
