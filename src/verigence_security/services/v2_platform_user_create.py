from __future__ import annotations

import json
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from verigence_security.adapters.clerk_backend import ClerkBackendClient, ClerkBackendError
from verigence_security.services.phase1_self_onboarding import Phase1SelfOnboardingService
from verigence_security.services.v2_human_actor import HumanActorContext


class InvalidUserInput(ValueError):
    """The submitted name, email, mobile or password is not acceptable."""


@dataclass(frozen=True, slots=True)
class CreatedUser:
    user_id: str
    clerk_subject: str


class V2PlatformUserCreateService:
    """SuperAdmin creation of an ACTIVE USER, without self-registration or email OTP.

    The SuperAdmin vouches for the contact details, so the user is created ACTIVE with a Clerk
    identity whose email is verified by the Backend API and whose password is the one supplied.
    The password is a transient call argument only; it is never written to Security storage,
    audit or logs. Contact ownership follows the self-registration rules: an ACTIVE/SUSPENDED
    user, a live signup attempt or a PENDING registration for the same email or mobile blocks
    creation.
    """

    def __init__(self, session: Session) -> None:
        self.s = session

    def create(
        self,
        *,
        first_name: str,
        last_name: str,
        email: str,
        mobile: str,
        password: str,
        actor: HumanActorContext,
        correlation_id: str,
        clerk: ClerkBackendClient,
    ) -> CreatedUser:
        if not actor.is_super_admin:
            raise PermissionError("SuperAdmin authority is required")
        onboarding = Phase1SelfOnboardingService(self.s)
        try:
            clean_first = onboarding._name(first_name, "First name")
            clean_email = onboarding._email(email)
            clean_mobile = onboarding._indian_mobile(mobile)
        except ValueError as exc:
            raise InvalidUserInput(str(exc)) from exc
        clean_last = " ".join(last_name.strip().split())
        if not password:
            raise InvalidUserInput("Password is required")

        now = datetime.now(UTC)
        onboarding._expire_stale_identity_attempts(
            email=clean_email, mobile=clean_mobile, now=now, clerk=clerk
        )
        onboarding._require_identity_not_registered(clean_email, clean_mobile)
        onboarding._require_no_live_attempt(clean_email, clean_mobile)
        self._require_no_pending_registration(clean_email, clean_mobile)

        # Never hold a database transaction open across the Clerk call.
        self.s.rollback()
        clerk_subject = clerk.create_user(
            first_name=clean_first,
            last_name=clean_last,
            email=clean_email,
            password=password,
        )

        user_id = str(uuid4())
        display_name = f"{clean_first} {clean_last}".strip()
        now = datetime.now(UTC)
        try:
            self._insert_user(
                user_id=user_id,
                clerk_subject=clerk_subject,
                display_name=display_name,
                first_name=clean_first,
                last_name=clean_last,
                email=clean_email,
                mobile=clean_mobile,
                now=now,
            )
            self._audit(
                actor_user_id=actor.user_id,
                correlation_id=correlation_id,
                user_id=user_id,
                after={"status": "ACTIVE", "displayName": display_name, "source": "SUPER_ADMIN_CREATE"},
                now=now,
            )
            self.s.commit()
        except IntegrityError as exc:
            self.s.rollback()
            self._discard_clerk_user(clerk, clerk_subject)
            raise ValueError("Email or mobile number is already registered") from exc
        except Exception:
            self.s.rollback()
            self._discard_clerk_user(clerk, clerk_subject)
            raise
        return CreatedUser(user_id=user_id, clerk_subject=clerk_subject)

    def _require_no_pending_registration(self, email: str, mobile: str) -> None:
        row = self.s.execute(
            text(
                """
                SELECT 1 FROM security.users
                WHERE status='PENDING'
                  AND (lower(primary_email)=:email
                       OR regexp_replace(coalesce(primary_mobile,''), '[^0-9]', '', 'g')=:mobile_digits)
                LIMIT 1
                """
            ),
            {"email": email, "mobile_digits": mobile.removeprefix("+")},
        ).first()
        if row is not None:
            raise ValueError(
                "Email or mobile number has a pending registration; approve it from Pending Approvals"
            )

    def _insert_user(
        self,
        *,
        user_id: str,
        clerk_subject: str,
        display_name: str,
        first_name: str,
        last_name: str,
        email: str,
        mobile: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.security_principals
                (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                VALUES (:user_id,'USER',:email,'ACTIVE',:now,:now)
                """
            ),
            {"user_id": user_id, "email": email, "now": now},
        )
        self.s.execute(
            text(
                """
                INSERT INTO security.users
                (user_id,display_name,first_name,last_name,primary_email,primary_mobile,status,
                 created_at_utc,updated_at_utc)
                VALUES (:user_id,:display_name,:first_name,:last_name,:email,:mobile,'ACTIVE',
                        :now,:now)
                """
            ),
            {
                "user_id": user_id,
                "display_name": display_name,
                "first_name": first_name,
                "last_name": last_name,
                "email": email,
                "mobile": mobile,
                "now": now,
            },
        )
        self.s.execute(
            text(
                """
                INSERT INTO security.external_identities
                (external_identity_id,user_id,provider,provider_subject,status,linked_at_utc)
                VALUES (:external_identity_id,:user_id,'CLERK',:clerk_subject,'ACTIVE',:now)
                """
            ),
            {
                "external_identity_id": str(uuid4()),
                "user_id": user_id,
                "clerk_subject": clerk_subject,
                "now": now,
            },
        )

    def _audit(
        self,
        *,
        actor_user_id: str,
        correlation_id: str,
        user_id: str,
        after: dict[str, object],
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.admin_change_records
                (admin_change_id,correlation_id,scope_type,actor_user_id,operation_key,
                 resource_type,resource_id,outcome,before_state_json,after_state_json,
                 occurred_at_utc)
                VALUES (:id,:correlation_id,'PLATFORM',:actor,'security.user.create',
                        'USER',:resource_id,'SUCCESS',CAST(:before AS jsonb),
                        CAST(:after AS jsonb),:now)
                """
            ),
            {
                "id": str(uuid4()),
                "correlation_id": correlation_id,
                "actor": actor_user_id,
                "resource_id": user_id,
                "before": json.dumps({}),
                "after": json.dumps(after),
                "now": now,
            },
        )

    @staticmethod
    def _discard_clerk_user(clerk: ClerkBackendClient, clerk_subject: str) -> None:
        # Compensate the provider identity so a failed Security write leaves no orphan login.
        with suppress(ClerkBackendError):
            clerk.delete_user(clerk_subject)
