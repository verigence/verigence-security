from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

from verigence_security.adapters.clerk_backend import ClerkBackendClient, ClerkBackendError

_RESET_TTL = timedelta(minutes=15)
_RATE_WINDOW = timedelta(minutes=15)
_MAX_REQUESTS_PER_WINDOW = 5


class PasswordRecoveryService:
    """Backend-only password recovery using Clerk email OTP as identity proof.

    The browser sends email/code/new-password only to Verigence. Security resolves the immutable
    Clerk identity from its own USER mapping, asks Clerk to send/verify an email code, and updates
    the Clerk-owned password only after successful verification. OTP and password values are never
    persisted by Security.
    """

    def __init__(self, session: Session) -> None:
        self.s = session

    def start(
        self,
        *,
        email: str,
        source_ip: str,
        correlation_id: str,
        clerk: ClerkBackendClient,
    ) -> dict[str, Any]:
        normalized = email.strip().lower()
        if not normalized or "@" not in normalized:
            raise ValueError("Enter a valid email address")

        now = datetime.now(UTC)
        expires_at = now + _RESET_TTL
        public_attempt_id = str(uuid4())

        rows = self.s.execute(
            text(
                """
                SELECT u.user_id,e.provider_subject
                FROM security.users u
                JOIN security.external_identities e
                  ON e.user_id=u.user_id
                 AND e.provider='CLERK'
                 AND e.status='ACTIVE'
                WHERE lower(u.primary_email)=:email
                  AND u.status IN ('ACTIVE','SUSPENDED','PENDING')
                LIMIT 2
                """
            ),
            {"email": normalized},
        ).mappings().all()

        # Deliberately keep the public response shape identical for unknown/non-eligible accounts.
        # No attempt row is stored and no provider call is made in that case.
        if len(rows) != 1:
            self.s.rollback()
            return self._public_start_response(public_attempt_id, expires_at)

        user_id = str(rows[0]["user_id"])
        clerk_user_id = str(rows[0]["provider_subject"])

        recent_count = int(
            self.s.execute(
                text(
                    """
                    SELECT count(*)
                    FROM security.password_reset_attempts
                    WHERE user_id=:user_id
                      AND created_at_utc>=:window_start
                    """
                ),
                {"user_id": user_id, "window_start": now - _RATE_WINDOW},
            ).scalar_one()
        )
        if recent_count >= _MAX_REQUESTS_PER_WINDOW:
            self.s.rollback()
            raise ValueError("Too many password reset requests. Please try again later.")

        # Cancel an older live challenge before asking Clerk for a fresh one.
        self.s.execute(
            text(
                """
                UPDATE security.password_reset_attempts
                SET status='CANCELLED'
                WHERE user_id=:user_id AND status='PENDING'
                """
            ),
            {"user_id": user_id},
        )
        self.s.commit()

        email_address_id = self._verified_clerk_email_id(
            clerk=clerk,
            clerk_user_id=clerk_user_id,
            expected_email=normalized,
        )
        verification_id = clerk.prepare_email_verification(email_address_id)

        self.s.execute(
            text(
                """
                INSERT INTO security.password_reset_attempts
                (password_reset_attempt_id,user_id,clerk_user_id,clerk_email_address_id,
                 clerk_email_verification_id,status,submitted_source_ip,correlation_id,
                 created_at_utc,expires_at_utc)
                VALUES
                (:attempt_id,:user_id,:clerk_user_id,:email_address_id,:verification_id,'PENDING',
                 CAST(:source_ip AS inet),:correlation_id,:now,:expires_at)
                """
            ),
            {
                "attempt_id": public_attempt_id,
                "user_id": user_id,
                "clerk_user_id": clerk_user_id,
                "email_address_id": email_address_id,
                "verification_id": verification_id,
                "source_ip": source_ip,
                "correlation_id": correlation_id,
                "now": now,
                "expires_at": expires_at,
            },
        )
        self.s.commit()
        return self._public_start_response(public_attempt_id, expires_at)

    def resend(self, *, attempt_id: str, clerk: ClerkBackendClient) -> dict[str, Any]:
        attempt = self._load(attempt_id)
        self._require_pending(attempt)
        email_address_id = str(attempt["clerk_email_address_id"])
        self.s.rollback()

        verification_id = clerk.prepare_email_verification(email_address_id)
        updated = self.s.execute(
            text(
                """
                UPDATE security.password_reset_attempts
                SET clerk_email_verification_id=:verification_id
                WHERE password_reset_attempt_id=:attempt_id AND status='PENDING'
                RETURNING expires_at_utc
                """
            ),
            {"verification_id": verification_id, "attempt_id": attempt_id},
        ).mappings().first()
        if updated is None:
            self.s.rollback()
            raise ValueError("Password reset request is no longer available")
        self.s.commit()
        return self._public_start_response(attempt_id, updated["expires_at_utc"])

    def complete(
        self,
        *,
        attempt_id: str,
        code: str,
        new_password: str,
        clerk: ClerkBackendClient,
    ) -> dict[str, str]:
        clean_code = code.strip()
        if not clean_code:
            raise ValueError("Verification code is required")
        if len(new_password) < 8:
            raise ValueError("New password must be at least 8 characters long")

        attempt = self._load(attempt_id, for_update=True)
        self._require_pending(attempt)
        user_id = str(attempt["user_id"])
        clerk_user_id = str(attempt["clerk_user_id"])
        email_address_id = str(attempt["clerk_email_address_id"])
        verification_id = str(attempt["clerk_email_verification_id"])
        self.s.rollback()

        if not clerk.attempt_email_verification(email_address_id, verification_id, clean_code):
            raise ValueError("Invalid or expired verification code")

        # Clerk owns password storage. The new password exists only on this active TLS request path.
        clerk._request_object(  # noqa: SLF001 - Security's backend-only Clerk facade
            "PATCH",
            f"/users/{clerk_user_id}",
            json={
                "password": new_password,
                "sign_out_of_other_sessions": True,
            },
        )
        if not clerk.verify_password(clerk_user_id=clerk_user_id, password=new_password):
            raise RuntimeError("Identity provider did not accept the new password")

        now = datetime.now(UTC)
        locked = self._load(attempt_id, for_update=True)
        self._require_pending(locked, now=now)
        if str(locked["clerk_user_id"]) != clerk_user_id:
            self.s.rollback()
            raise ValueError("Password reset identity changed during completion")
        if str(locked["clerk_email_verification_id"]) != verification_id:
            self.s.rollback()
            raise ValueError("Password reset verification changed during completion")

        self.s.execute(
            text(
                """
                UPDATE security.password_reset_attempts
                SET status='COMPLETED',completed_at_utc=:now
                WHERE password_reset_attempt_id=:attempt_id AND status='PENDING'
                """
            ),
            {"attempt_id": attempt_id, "now": now},
        )
        # Password reset invalidates Security-owned application sessions as well as Clerk sessions.
        self.s.execute(
            text(
                """
                UPDATE security.access_sessions
                SET status='REVOKED',last_activity_at_utc=:now
                WHERE principal_id=:user_id
                  AND actor_type='USER'
                  AND status='ACTIVE'
                """
            ),
            {"user_id": user_id, "now": now},
        )
        self.s.commit()
        return {
            "status": "PASSWORD_RESET_COMPLETED",
            "message": "Your password has been reset. You can now sign in with the new password.",
        }

    def _load(self, attempt_id: str, *, for_update: bool = False) -> dict[str, Any]:
        suffix = " FOR UPDATE" if for_update else ""
        row = self.s.execute(
            text(
                """
                SELECT password_reset_attempt_id,user_id,clerk_user_id,clerk_email_address_id,
                       clerk_email_verification_id,status,created_at_utc,expires_at_utc,
                       completed_at_utc
                FROM security.password_reset_attempts
                WHERE password_reset_attempt_id=:attempt_id
                """
                + suffix
            ),
            {"attempt_id": attempt_id},
        ).mappings().first()
        if row is None:
            raise LookupError("Password reset request was not found")
        return dict(row)

    def _require_pending(self, attempt: dict[str, Any], *, now: datetime | None = None) -> None:
        current = now or datetime.now(UTC)
        if str(attempt["status"]) != "PENDING":
            raise ValueError("Password reset request is no longer available")
        if attempt["expires_at_utc"] <= current:
            self.s.execute(
                text(
                    """
                    UPDATE security.password_reset_attempts
                    SET status='EXPIRED'
                    WHERE password_reset_attempt_id=:attempt_id AND status='PENDING'
                    """
                ),
                {"attempt_id": str(attempt["password_reset_attempt_id"])},
            )
            self.s.commit()
            raise ValueError("Password reset request has expired")

    @staticmethod
    def _verified_clerk_email_id(
        *,
        clerk: ClerkBackendClient,
        clerk_user_id: str,
        expected_email: str,
    ) -> str:
        user = clerk.get_user(clerk_user_id)
        values = user.get("email_addresses")
        if not isinstance(values, list):
            raise ClerkBackendError("Clerk user response did not contain email addresses")
        expected = expected_email.strip().lower()
        for item in values:
            if not isinstance(item, dict):
                continue
            value = item.get("email_address")
            if not isinstance(value, str) or value.strip().lower() != expected:
                continue
            verification = item.get("verification")
            if not isinstance(verification, dict) or verification.get("status") != "verified":
                raise ClerkBackendError("Registered email is not verified at Clerk")
            email_address_id = item.get("id")
            if not isinstance(email_address_id, str) or not email_address_id:
                raise ClerkBackendError("Clerk email address did not contain an ID")
            return email_address_id
        raise ClerkBackendError("Clerk user did not contain the registered email address")

    @staticmethod
    def _public_start_response(attempt_id: str, expires_at: datetime) -> dict[str, Any]:
        return {
            "passwordResetAttemptId": attempt_id,
            "status": "EMAIL_VERIFICATION_REQUIRED",
            "expiresAt": expires_at.isoformat(),
            "message": (
                "If the account is eligible, a verification code has been sent to the registered "
                "email address."
            ),
        }
