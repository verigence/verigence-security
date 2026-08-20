from __future__ import annotations

from typing import Any

from sqlalchemy import text

from verigence_security.adapters.clerk_backend import ClerkBackendClient, ClerkBackendError
from verigence_security.services.phase1_self_onboarding import Phase1SelfOnboardingService


class UC001SelfOnboardingService(Phase1SelfOnboardingService):
    """UC-001 signup restart semantics layered on the Phase-1 onboarding service.

    A fresh, valid onboarding request supersedes any unfinished signup attempt that uses the same
    email address or mobile number. Superseded attempts are cancelled before their banned Clerk
    placeholder identities are deleted. CANCELLED/EXPIRED attempts are also retried for provider
    cleanup so a previous transient Clerk deletion failure cannot reserve the email forever.
    """

    def start(
        self,
        *,
        first_name: str,
        last_name: str,
        email: str,
        mobile: str,
        password: str,
        onboarding_key: str,
        source_ip: str,
        correlation_id: str,
        clerk: ClerkBackendClient,
    ) -> dict[str, Any]:
        clean_email = self._email(email)
        clean_mobile = self._indian_mobile(mobile)

        # Do not let an unauthorised caller cancel somebody else's in-flight attempt. Security
        # validates the complete onboarding key before any replacement/cleanup side effect.
        self._require_valid_onboarding_key(onboarding_key)
        self._release_prior_attempts(email=clean_email, mobile=clean_mobile, clerk=clerk)

        # The canonical implementation still performs all normal validation and validates the key
        # again. The duplicate Argon2 verification is intentional here: this small compatibility
        # layer changes only restart semantics and does not fork the canonical onboarding flow.
        return super().start(
            first_name=first_name,
            last_name=last_name,
            email=clean_email,
            mobile=clean_mobile,
            password=password,
            onboarding_key=onboarding_key,
            source_ip=source_ip,
            correlation_id=correlation_id,
            clerk=clerk,
        )

    def _release_prior_attempts(
        self,
        *,
        email: str,
        mobile: str,
        clerk: ClerkBackendClient,
    ) -> None:
        # Cancel first and commit before calling Clerk. Once an attempt is CANCELLED, a concurrent
        # OTP verification cannot complete it while its provider placeholder is being removed.
        released = list(
            self.s.execute(
                text(
                    """
                    UPDATE security.platform_user_signup_attempts
                    SET status='CANCELLED'
                    WHERE status='AUTHORIZED_FOR_CLERK'
                      AND (lower(email)=:email OR mobile=:mobile)
                    RETURNING signup_attempt_id,clerk_user_id
                    """
                ),
                {"email": email, "mobile": mobile},
            ).mappings()
        )

        # Include earlier cancelled/expired attempts so a prior transient Clerk cleanup failure is
        # repaired on the next registration instead of leaving the email reserved at the provider.
        cleanup_rows = list(
            self.s.execute(
                text(
                    """
                    SELECT signup_attempt_id,clerk_user_id
                    FROM security.platform_user_signup_attempts
                    WHERE status IN ('CANCELLED','EXPIRED')
                      AND clerk_user_id IS NOT NULL
                      AND (lower(email)=:email OR mobile=:mobile)
                    """
                ),
                {"email": email, "mobile": mobile},
            ).mappings()
        )
        self.s.commit()

        clerk_user_ids = {
            str(row["clerk_user_id"])
            for row in [*released, *cleanup_rows]
            if row.get("clerk_user_id")
        }
        for clerk_user_id in clerk_user_ids:
            try:
                clerk.delete_user(clerk_user_id)
            except ClerkBackendError as exc:
                if exc.status_code != 404:
                    # The attempt is already CANCELLED. A later retry will revisit cancelled rows
                    # and retry provider cleanup before creating a replacement Clerk identity.
                    raise
