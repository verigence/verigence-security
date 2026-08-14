from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from verigence_security.adapters.clerk_backend import ClerkBackendClient
from verigence_security.adapters.identity import AuthenticatedIdentity
from verigence_security.core.errors import security_error

_HASHER = PasswordHasher()
_ATTEMPT_TTL = timedelta(minutes=30)


class Phase1SelfOnboardingService:
    """Phase 1 onboarding with Security pre-authorization and Clerk-owned email OTP."""

    def __init__(self, session: Session) -> None:
        self.s = session

    def start(
        self,
        *,
        first_name: str,
        last_name: str,
        email: str,
        mobile: str,
        onboarding_key: str,
        source_ip: str,
        correlation_id: str,
    ) -> dict[str, Any]:
        clean_first = self._name(first_name, "First name")
        clean_last = self._name(last_name, "Last name")
        clean_email = self._email(email)
        clean_mobile = self._indian_mobile(mobile)
        now = datetime.now(UTC)

        self._require_valid_onboarding_key(onboarding_key)
        self._expire_stale_attempts(now)
        self._require_identity_not_registered(clean_email, clean_mobile)
        self._require_no_live_attempt(clean_email, clean_mobile)

        attempt_id = str(uuid4())
        expires_at = now + _ATTEMPT_TTL
        try:
            self.s.execute(
                text(
                    """
                    INSERT INTO security.platform_user_signup_attempts
                    (signup_attempt_id,first_name,last_name,email,mobile,status,
                     submitted_source_ip,correlation_id,created_at_utc,expires_at_utc)
                    VALUES
                    (:attempt_id,:first_name,:last_name,:email,:mobile,'AUTHORIZED_FOR_CLERK',
                     CAST(:source_ip AS inet),:correlation_id,:now,:expires_at)
                    """
                ),
                {
                    "attempt_id": attempt_id,
                    "first_name": clean_first,
                    "last_name": clean_last,
                    "email": clean_email,
                    "mobile": clean_mobile,
                    "source_ip": source_ip,
                    "correlation_id": correlation_id,
                    "now": now,
                    "expires_at": expires_at,
                },
            )
            self.s.commit()
        except IntegrityError as exc:
            self.s.rollback()
            raise ValueError("Email or mobile number already has an active signup attempt") from exc

        return {
            "signupAttemptId": attempt_id,
            "status": "CLERK_EMAIL_VERIFICATION_REQUIRED",
            "expiresAt": expires_at.isoformat(),
        }

    def complete(
        self,
        *,
        signup_attempt_id: str,
        identity: AuthenticatedIdentity,
        source_ip: str,
        correlation_id: str,
        clerk: ClerkBackendClient,
    ) -> dict[str, Any]:
        if identity.provider != "CLERK" or not identity.provider_subject.startswith("user_"):
            raise security_error("AUTH_TOKEN_INVALID")

        attempt = self._load_attempt(signup_attempt_id)
        self._require_completable(attempt)
        expected_email = str(attempt["email"])
        first_name = str(attempt["first_name"])
        last_name = str(attempt["last_name"])
        mobile = str(attempt["mobile"])

        # Do not hold a database row lock while calling Clerk. Re-acquire and re-check the
        # signup attempt before committing the Security USER to make completion idempotent.
        self.s.rollback()
        if not clerk.is_email_verified(identity.provider_subject, expected_email):
            raise ValueError("Clerk email is not verified or does not match the signup email")
        clerk.update_user_profile(
            identity.provider_subject,
            first_name=first_name,
            last_name=last_name,
        )

        now = datetime.now(UTC)
        locked_attempt = self._load_attempt(signup_attempt_id, for_update=True)
        self._require_completable(locked_attempt, now=now)
        self._require_identity_not_registered(expected_email, mobile)
        self._require_clerk_identity_not_registered(identity.provider_subject)

        user_id = str(uuid4())
        request_id = str(uuid4())
        display_name = f"{first_name} {last_name}".strip()
        try:
            self.s.execute(
                text(
                    """
                    INSERT INTO security.security_principals
                    (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                    VALUES (:user_id,'USER',:principal_name,'ACTIVE',:now,:now)
                    """
                ),
                {
                    "user_id": user_id,
                    "principal_name": expected_email,
                    "now": now,
                },
            )
            self.s.execute(
                text(
                    """
                    INSERT INTO security.users
                    (user_id,display_name,first_name,last_name,primary_email,primary_mobile,status,
                     created_at_utc,updated_at_utc)
                    VALUES (:user_id,:display_name,:first_name,:last_name,:email,:mobile,'PENDING',
                            :now,:now)
                    """
                ),
                {
                    "user_id": user_id,
                    "display_name": display_name,
                    "first_name": first_name,
                    "last_name": last_name,
                    "email": expected_email,
                    "mobile": mobile,
                    "now": now,
                },
            )
            self.s.execute(
                text(
                    """
                    INSERT INTO security.external_identities
                    (external_identity_id,user_id,provider,provider_subject,status,linked_at_utc)
                    VALUES (:external_identity_id,:user_id,'CLERK',:clerk_user_id,'ACTIVE',:now)
                    """
                ),
                {
                    "external_identity_id": str(uuid4()),
                    "user_id": user_id,
                    "clerk_user_id": identity.provider_subject,
                    "now": now,
                },
            )
            self.s.execute(
                text(
                    """
                    INSERT INTO security.platform_user_onboarding_requests
                    (onboarding_request_id,user_id,email,clerk_user_id,status,submitted_source_ip,
                     submitted_at_utc,correlation_id)
                    VALUES (:request_id,:user_id,:email,:clerk_user_id,'PENDING_ADMIN_APPROVAL',
                            CAST(:source_ip AS inet),:now,:correlation_id)
                    """
                ),
                {
                    "request_id": request_id,
                    "user_id": user_id,
                    "email": expected_email,
                    "clerk_user_id": identity.provider_subject,
                    "source_ip": source_ip,
                    "now": now,
                    "correlation_id": correlation_id,
                },
            )
            self.s.execute(
                text(
                    """
                    UPDATE security.platform_user_signup_attempts
                    SET status='COMPLETED',clerk_user_id=:clerk_user_id,completed_at_utc=:now
                    WHERE signup_attempt_id=:attempt_id
                    """
                ),
                {
                    "attempt_id": signup_attempt_id,
                    "clerk_user_id": identity.provider_subject,
                    "now": now,
                },
            )
            self._security_event(
                user_id=user_id,
                source_ip=source_ip,
                correlation_id=correlation_id,
                now=now,
            )
            self.s.commit()
        except IntegrityError as exc:
            self.s.rollback()
            raise ValueError("Email, mobile, or Clerk identity is already registered") from exc
        except Exception:
            self.s.rollback()
            raise

        return {
            "onboardingRequestId": request_id,
            "status": "PENDING_ADMIN_APPROVAL",
            "message": "Registration successful. Pending administrator approval.",
        }

    def _load_attempt(self, signup_attempt_id: str, *, for_update: bool = False) -> dict[str, Any]:
        suffix = " FOR UPDATE" if for_update else ""
        row = self.s.execute(
            text(
                """
                SELECT signup_attempt_id,first_name,last_name,email,mobile,status,
                       created_at_utc,expires_at_utc,clerk_user_id,completed_at_utc
                FROM security.platform_user_signup_attempts
                WHERE signup_attempt_id=:attempt_id
                """
                + suffix
            ),
            {"attempt_id": signup_attempt_id},
        ).mappings().first()
        if row is None:
            raise LookupError("Signup attempt was not found")
        return dict(row)

    def _require_completable(
        self,
        attempt: dict[str, Any],
        *,
        now: datetime | None = None,
    ) -> None:
        current = now or datetime.now(UTC)
        if str(attempt["status"]) != "AUTHORIZED_FOR_CLERK":
            raise ValueError("Signup attempt is no longer available for completion")
        if attempt["expires_at_utc"] <= current:
            self.s.execute(
                text(
                    """
                    UPDATE security.platform_user_signup_attempts
                    SET status='EXPIRED'
                    WHERE signup_attempt_id=:attempt_id
                      AND status='AUTHORIZED_FOR_CLERK'
                    """
                ),
                {"attempt_id": str(attempt["signup_attempt_id"])},
            )
            self.s.commit()
            raise ValueError("Signup attempt has expired")

    def _expire_stale_attempts(self, now: datetime) -> None:
        self.s.execute(
            text(
                """
                UPDATE security.platform_user_signup_attempts
                SET status='EXPIRED'
                WHERE status='AUTHORIZED_FOR_CLERK'
                  AND expires_at_utc<=:now
                """
            ),
            {"now": now},
        )

    def _require_valid_onboarding_key(self, supplied: str) -> None:
        row = self.s.execute(
            text(
                """
                SELECT key_hash,status
                FROM security.platform_user_onboarding_settings
                WHERE singleton_id=1
                """
            )
        ).mappings().first()
        if row is None or row["status"] != "ACTIVE":
            raise security_error("PERMISSION_DENIED")
        try:
            _HASHER.verify(str(row["key_hash"]), supplied.strip())
        except (VerifyMismatchError, VerificationError, InvalidHashError) as exc:
            raise security_error("PERMISSION_DENIED") from exc

    def _require_identity_not_registered(self, email: str, mobile: str) -> None:
        email_row = self.s.execute(
            text(
                """
                SELECT 1 FROM security.users
                WHERE lower(primary_email)=:email
                LIMIT 1
                """
            ),
            {"email": email},
        ).first()
        if email_row is not None:
            raise ValueError("Email address is already registered")

        mobile_digits = mobile.removeprefix("+")
        mobile_row = self.s.execute(
            text(
                """
                SELECT 1 FROM security.users
                WHERE primary_mobile IS NOT NULL
                  AND regexp_replace(primary_mobile, '[^0-9]', '', 'g')=:mobile_digits
                LIMIT 1
                """
            ),
            {"mobile_digits": mobile_digits},
        ).first()
        if mobile_row is not None:
            raise ValueError("Mobile number is already registered")

    def _require_no_live_attempt(self, email: str, mobile: str) -> None:
        row = self.s.execute(
            text(
                """
                SELECT 1
                FROM security.platform_user_signup_attempts
                WHERE status='AUTHORIZED_FOR_CLERK'
                  AND (lower(email)=:email OR mobile=:mobile)
                LIMIT 1
                """
            ),
            {"email": email, "mobile": mobile},
        ).first()
        if row is not None:
            raise ValueError("Email or mobile number already has an active signup attempt")

    def _require_clerk_identity_not_registered(self, clerk_user_id: str) -> None:
        row = self.s.execute(
            text(
                """
                SELECT 1
                FROM security.external_identities
                WHERE provider='CLERK' AND provider_subject=:clerk_user_id
                LIMIT 1
                """
            ),
            {"clerk_user_id": clerk_user_id},
        ).first()
        if row is not None:
            raise ValueError("Clerk identity is already registered")

    @staticmethod
    def _email(value: str) -> str:
        clean = value.strip().lower()
        if not clean or "@" not in clean or clean.startswith("@") or clean.endswith("@"):
            raise ValueError("A valid email address is required")
        if any(char.isspace() for char in clean):
            raise ValueError("A valid email address is required")
        return clean

    @staticmethod
    def _name(value: str, label: str) -> str:
        clean = " ".join(value.strip().split())
        if not clean:
            raise ValueError(f"{label} is required")
        return clean

    @staticmethod
    def _indian_mobile(value: str) -> str:
        digits = "".join(char for char in value if char.isdigit())
        if len(digits) == 12 and digits.startswith("91"):
            digits = digits[2:]
        elif len(digits) == 11 and digits.startswith("0"):
            digits = digits[1:]
        if len(digits) != 10 or digits[0] not in "6789":
            raise ValueError("A valid 10-digit Indian mobile number is required")
        return f"+91{digits}"

    def _security_event(
        self,
        *,
        user_id: str,
        source_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.security_events
                (security_event_id,principal_id,actor_type,event_type,entity_type,entity_id,
                 outcome,reason_code,source_ip,correlation_id,occurred_at_utc)
                VALUES (:event_id,:principal_id,'USER','GLOBAL_USER_EMAIL_VERIFIED_REGISTERED','USER',
                        :entity_id,'PENDING_ADMIN_APPROVAL','SECURITY_ADMIN_APPROVAL_REQUIRED',
                        CAST(:source_ip AS inet),:correlation_id,:now)
                """
            ),
            {
                "event_id": str(uuid4()),
                "principal_id": user_id,
                "entity_id": user_id,
                "source_ip": source_ip,
                "correlation_id": correlation_id,
                "now": now,
            },
        )
