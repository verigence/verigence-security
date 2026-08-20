from __future__ import annotations

from typing import Any

from sqlalchemy import text

from verigence_security.adapters.clerk_backend import ClerkBackendClient, ClerkBackendError
from verigence_security.services.phase1_self_onboarding import Phase1SelfOnboardingService


class UC001SelfOnboardingService(Phase1SelfOnboardingService):
    """UC-001 signup restart semantics layered on the Phase-1 onboarding service.

    A fresh, valid onboarding request supersedes unfinished signup attempts and prior USER records
    that no longer own their contact details. Only ACTIVE or SUSPENDED USERs retain ownership of
    email/mobile. PENDING, INVITED, DISABLED and EXITED records are retired from Clerk before a
    replacement signup is created so Clerk's own email uniqueness cannot permanently reserve the
    address after a failed, abandoned or otherwise non-owning registration lifecycle.
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

        # Do not let an unauthorised caller cancel somebody else's in-flight attempt or retire a
        # non-owning USER identity. Security validates the complete onboarding key first.
        self._require_valid_onboarding_key(onboarding_key)
        self._release_prior_attempts(email=clean_email, mobile=clean_mobile, clerk=clerk)
        self._release_nonowning_users(email=clean_email, mobile=clean_mobile, clerk=clerk)

        # The canonical implementation still performs all normal validation and validates the key
        # again. The duplicate Argon2 verification is intentional here: this compatibility layer
        # changes only restart/contact-reclamation semantics and does not fork the canonical flow.
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
        self._delete_clerk_users(clerk_user_ids, clerk)

    def _release_nonowning_users(
        self,
        *,
        email: str,
        mobile: str,
        clerk: ClerkBackendClient,
    ) -> None:
        """Retire prior non-owning Security USER identities before creating a fresh Clerk user.

        The database uniqueness rule already limits contact ownership to ACTIVE/SUSPENDED users,
        but Clerk enforces email uniqueness independently. Without retiring the old Clerk identity,
        a PENDING/DISABLED/EXITED Security record can still make a legitimate retry fail with
        form_identifier_exists. Preserve the historical USER/request rows, revoke their external
        identity, disable their principal, cancel any open onboarding request, then delete the Clerk
        identity. ACTIVE/SUSPENDED users are intentionally excluded and remain authoritative owners.
        """

        rows = list(
            self.s.execute(
                text(
                    """
                    SELECT DISTINCT u.user_id,e.provider_subject AS clerk_user_id
                    FROM security.users u
                    LEFT JOIN security.external_identities e
                      ON e.user_id=u.user_id
                     AND e.provider='CLERK'
                    WHERE u.status NOT IN ('ACTIVE','SUSPENDED')
                      AND (
                        lower(u.primary_email)=:email
                        OR (
                          u.primary_mobile IS NOT NULL
                          AND regexp_replace(u.primary_mobile, '[^0-9]', '', 'g')=:mobile_digits
                        )
                      )
                    """
                ),
                {"email": email, "mobile_digits": mobile.removeprefix("+")},
            ).mappings()
        )
        if not rows:
            return

        user_ids = {str(row["user_id"]) for row in rows}
        clerk_user_ids = {
            str(row["clerk_user_id"])
            for row in rows
            if row.get("clerk_user_id")
        }

        for user_id in user_ids:
            self.s.execute(
                text(
                    """
                    UPDATE security.platform_user_onboarding_requests
                    SET status='CANCELLED',
                        review_reason=COALESCE(
                          review_reason,
                          'Superseded by a fresh UC-001 registration using a reusable contact'
                        )
                    WHERE user_id=:user_id
                      AND status IN (
                        'PENDING_CLERK',
                        'CLERK_INVITED',
                        'PENDING_ADMIN_APPROVAL',
                        'CLERK_PROVISIONING_FAILED'
                      )
                    """
                ),
                {"user_id": user_id},
            )
            self.s.execute(
                text(
                    """
                    UPDATE security.external_identities
                    SET status='REVOKED'
                    WHERE user_id=:user_id
                      AND provider='CLERK'
                      AND status='ACTIVE'
                    """
                ),
                {"user_id": user_id},
            )
            self.s.execute(
                text(
                    """
                    UPDATE security.security_principals
                    SET status='DISABLED',updated_at_utc=CURRENT_TIMESTAMP
                    WHERE principal_id=:user_id
                      AND actor_type='USER'
                      AND status IN ('ACTIVE','SUSPENDED')
                    """
                ),
                {"user_id": user_id},
            )
        self.s.commit()

        self._delete_clerk_users(clerk_user_ids, clerk)

    @staticmethod
    def _delete_clerk_users(clerk_user_ids: set[str], clerk: ClerkBackendClient) -> None:
        for clerk_user_id in clerk_user_ids:
            try:
                clerk.delete_user(clerk_user_id)
            except ClerkBackendError as exc:
                if exc.status_code != 404:
                    # Database state has already been made non-owning/non-authenticatable. A later
                    # retry revisits the historical row and retries provider deletion safely.
                    raise
