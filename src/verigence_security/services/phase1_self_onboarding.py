from __future__ import annotations

from contextlib import suppress
from datetime import UTC, datetime
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


class Phase1SelfOnboardingService:
    """Single-submit Phase 1 self-onboarding with Clerk backend user creation.

    Security validates the Platform onboarding gate and global identity uniqueness first. Clerk
    creates the credential identity next. Only after Clerk succeeds does Security persist the
    global USER as PENDING together with the immutable Clerk subject.
    """

    def __init__(self, session: Session) -> None:
        self.s = session

    def register(
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

        self._require_valid_onboarding_key(onboarding_key)
        self._require_identity_not_registered(clean_email, clean_mobile)

        # Release the read transaction before the Clerk network call. The database uniqueness
        # constraints remain the final concurrency guard when the local USER is persisted.
        self.s.rollback()

        clerk_user_id = clerk.create_user(
            first_name=clean_first,
            last_name=clean_last,
            email=clean_email,
            password=password,
        )

        now = datetime.now(UTC)
        user_id = str(uuid4())
        request_id = str(uuid4())
        display_name = f"{clean_first} {clean_last}".strip()
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
                    "principal_name": clean_email,
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
                    "first_name": clean_first,
                    "last_name": clean_last,
                    "email": clean_email,
                    "mobile": clean_mobile,
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
                    "email": clean_email,
                    "clerk_user_id": clerk_user_id,
                    "source_ip": source_ip,
                    "now": now,
                    "correlation_id": correlation_id,
                },
            )
            self._security_event(
                user_id=user_id,
                outcome="PENDING_ADMIN_APPROVAL",
                source_ip=source_ip,
                correlation_id=correlation_id,
                now=now,
            )
            self.s.commit()
        except IntegrityError as exc:
            self.s.rollback()
            self._compensate_clerk_user(clerk, clerk_user_id)
            raise ValueError("Email or mobile number is already registered") from exc
        except Exception:
            self.s.rollback()
            self._compensate_clerk_user(clerk, clerk_user_id)
            raise

        return {
            "onboardingRequestId": request_id,
            "status": "PENDING_ADMIN_APPROVAL",
            "message": "Registration successful. Pending administrator approval.",
        }

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

    @staticmethod
    def _compensate_clerk_user(clerk: ClerkBackendClient, clerk_user_id: str) -> None:
        # Security still fails closed because no local usable USER mapping was committed.
        # Operational reconciliation can remove an orphan Clerk identity if this best effort fails.
        with suppress(ClerkBackendError):
            clerk.delete_user(clerk_user_id)

    def _security_event(
        self,
        *,
        user_id: str,
        outcome: str,
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
                VALUES (:event_id,:principal_id,'USER','GLOBAL_USER_SELF_REGISTERED','USER',
                        :entity_id,:outcome,'SECURITY_ADMIN_APPROVAL_REQUIRED',
                        CAST(:source_ip AS inet),:correlation_id,:now)
                """
            ),
            {
                "event_id": str(uuid4()),
                "principal_id": user_id,
                "entity_id": user_id,
                "outcome": outcome,
                "source_ip": source_ip,
                "correlation_id": correlation_id,
                "now": now,
            },
        )
