from __future__ import annotations

from contextlib import suppress
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from verigence_security.adapters.clerk_backend import ClerkBackendClient, ClerkBackendError
from verigence_security.core.errors import security_error

_HASHER = PasswordHasher()
_ATTEMPT_TTL = timedelta(minutes=30)


class Phase1SelfOnboardingService:
    """Backend-only Phase 1 onboarding with Clerk-owned password and email OTP.

    The channel talks to Verigence only. Security validates the onboarding gate, creates a banned
    Clerk user server-to-server, forces the email unverified, asks Clerk to send/verify email OTP,
    and creates a PENDING Security USER only after successful email verification.
    """

    def __init__(self, session: Session) -> None:
        self.s = session

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
        clean_first = self._name(first_name, "First name")
        clean_last = self._name(last_name, "Last name")
        clean_email = self._email(email)
        clean_mobile = self._indian_mobile(mobile)
        if not password:
            raise ValueError("Password is required")
        now = datetime.now(UTC)

        self._require_valid_onboarding_key(onboarding_key)
        self._expire_stale_identity_attempts(
            email=clean_email,
            mobile=clean_mobile,
            now=now,
            clerk=clerk,
        )
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

        clerk_user_id: str | None = None
        try:
            clerk_user_id, email_address_id = clerk.create_pending_email_user(
                first_name=clean_first,
                last_name=clean_last,
                email=clean_email,
                password=password,
            )
            self.s.execute(
                text(
                    """
                    UPDATE security.platform_user_signup_attempts
                    SET clerk_user_id=:clerk_user_id,
                        clerk_email_address_id=:email_address_id
                    WHERE signup_attempt_id=:attempt_id
                      AND status='AUTHORIZED_FOR_CLERK'
                    """
                ),
                {
                    "attempt_id": attempt_id,
                    "clerk_user_id": clerk_user_id,
                    "email_address_id": email_address_id,
                },
            )
            self.s.commit()
        except Exception:
            self.s.rollback()
            self.s.execute(
                text(
                    """
                    UPDATE security.platform_user_signup_attempts
                    SET status='CANCELLED'
                    WHERE signup_attempt_id=:attempt_id
                      AND status='AUTHORIZED_FOR_CLERK'
                    """
                ),
                {"attempt_id": attempt_id},
            )
            self.s.commit()
            if clerk_user_id is not None:
                with suppress(Exception):
                    clerk.delete_user(clerk_user_id)
            raise

        return {
            "signupAttemptId": attempt_id,
            "status": "EMAIL_VERIFICATION_REQUIRED",
            "expiresAt": expires_at.isoformat(),
        }

    def resend_email_code(
        self,
        *,
        signup_attempt_id: str,
        clerk: ClerkBackendClient,
    ) -> dict[str, Any]:
        attempt = self._load_attempt(signup_attempt_id)
        self._require_completable(attempt)
        email_address_id = self._required_clerk_email_id(attempt)
        self.s.rollback()
        clerk.prepare_email_verification(email_address_id)
        return {
            "signupAttemptId": signup_attempt_id,
            "status": "EMAIL_VERIFICATION_REQUIRED",
            "expiresAt": attempt["expires_at_utc"].isoformat(),
        }

    def verify_email_code(
        self,
        *,
        signup_attempt_id: str,
        code: str,
        source_ip: str,
        correlation_id: str,
        clerk: ClerkBackendClient,
    ) -> dict[str, Any]:
        if not code.strip():
            raise ValueError("Verification code is required")

        attempt = self._load_attempt(signup_attempt_id)
        self._require_completable(attempt)
        clerk_user_id = self._required_clerk_user_id(attempt)
        email_address_id = self._required_clerk_email_id(attempt)
        expected_email = str(attempt["email"])
        first_name = str(attempt["first_name"])
        last_name = str(attempt["last_name"])
        mobile = str(attempt["mobile"])

        # Never hold a database transaction open across Clerk network calls. Password and OTP
        # values are never written to Security storage/audit/log state. If a prior attempt already
        # verified the exact email but Security failed before commit, accept that same provider state.
        self.s.rollback()
        verification_accepted = clerk.attempt_email_verification(email_address_id, code.strip())
        email_verified = clerk.is_email_verified(clerk_user_id, expected_email)
        if not verification_accepted and not email_verified:
            raise ValueError("Invalid or expired email verification code")
        if not email_verified:
            raise ValueError("Email verification did not complete for the signup address")

        now = datetime.now(UTC)
        locked_attempt = self._load_attempt(signup_attempt_id, for_update=True)
        self._require_completable(locked_attempt, now=now)
        if self._required_clerk_user_id(locked_attempt) != clerk_user_id:
            raise ValueError("Signup identity changed during verification")
        self._require_identity_not_registered(expected_email, mobile)
        self._require_clerk_identity_not_registered(clerk_user_id)

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
                    "clerk_user_id": clerk_user_id,
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
                    "clerk_user_id": clerk_user_id,
                    "source_ip": source_ip,
                    "now": now,
                    "correlation_id": correlation_id,
                },
            )
            self.s.execute(
                text(
                    """
                    UPDATE security.platform_user_signup_attempts
                    SET status='COMPLETED',completed_at_utc=:now
                    WHERE signup_attempt_id=:attempt_id
                    """
                ),
                {"attempt_id": signup_attempt_id, "now": now},
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

        # The Clerk identity remains banned. Existing Security admin activation is authoritative
        # and unbans it only when the Security USER transitions to ACTIVE.
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
                       created_at_utc,expires_at_utc,clerk_user_id,clerk_email_address_id,
                       completed_at_utc
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

    def _expire_stale_identity_attempts(
        self,
        *,
        email: str,
        mobile: str,
        now: datetime,
        clerk: ClerkBackendClient,
    ) -> None:
        rows = list(
            self.s.execute(
                text(
                    """
                    SELECT signup_attempt_id,clerk_user_id
                    FROM security.platform_user_signup_attempts
                    WHERE status='AUTHORIZED_FOR_CLERK'
                      AND expires_at_utc<=:now
                      AND (lower(email)=:email OR mobile=:mobile)
                    """
                ),
                {"now": now, "email": email, "mobile": mobile},
            ).mappings()
        )
        if not rows:
            return
        self.s.execute(
            text(
                """
                UPDATE security.platform_user_signup_attempts
                SET status='EXPIRED'
                WHERE status='AUTHORIZED_FOR_CLERK'
                  AND expires_at_utc<=:now
                  AND (lower(email)=:email OR mobile=:mobile)
                """
            ),
            {"now": now, "email": email, "mobile": mobile},
        )
        self.s.commit()
        for row in rows:
            clerk_user_id = row["clerk_user_id"]
            if not clerk_user_id:
                continue
            try:
                clerk.delete_user(str(clerk_user_id))
            except ClerkBackendError as exc:
                if exc.status_code != 404:
                    raise

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
    def _required_clerk_user_id(attempt: dict[str, Any]) -> str:
        value = attempt.get("clerk_user_id")
        if not isinstance(value, str) or not value.startswith("user_"):
            raise ValueError("Signup identity has not been prepared")
        return value

    @staticmethod
    def _required_clerk_email_id(attempt: dict[str, Any]) -> str:
        value = attempt.get("clerk_email_address_id")
        if not isinstance(value, str) or not value:
            raise ValueError("Signup email verification has not been prepared")
        return value

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
