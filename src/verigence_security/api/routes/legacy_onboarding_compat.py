from __future__ import annotations

from fastapi import APIRouter, status

from verigence_security.api.routes import global_users

router = APIRouter(tags=["Global USER Onboarding"])

# Phase-1 target facade. Web/Mobile calls Security; Security alone integrates with the
# Clerk Backend API for user creation and email verification. There is no client-driven
# Clerk session or authenticated-bind route in the target flow.
router.add_api_route(
    "/security/v1/onboarding/users",
    global_users.start_global_user_onboarding,
    methods=["POST"],
    status_code=status.HTTP_202_ACCEPTED,
)
router.add_api_route(
    "/security/v1/onboarding/users/{signupAttemptId}/resend-email-code",
    global_users.resend_global_user_email_code,
    methods=["POST"],
)
router.add_api_route(
    "/security/v1/onboarding/users/{signupAttemptId}/verify-email",
    global_users.verify_global_user_email,
    methods=["POST"],
    status_code=status.HTTP_201_CREATED,
)
router.add_api_route(
    "/security/v1/auth/precheck",
    global_users.authentication_precheck,
    methods=["POST"],
)
