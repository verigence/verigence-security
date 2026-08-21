from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import text

from verigence_security.adapters.clerk_backend import (
    ClerkBackendClient,
    ClerkBackendError,
    ClerkBackendUser,
)
from verigence_security.config import Settings
from verigence_security.core.errors import SecurityError, security_error
from verigence_security.db.session import build_session_factory


@dataclass(frozen=True, slots=True)
class ClerkCredentialResult:
    clerk_user: ClerkBackendUser


class ClerkCredentialService:
    """Backend-only Phase-1 human password verification against Clerk.

    Security is authoritative for which human identity may authenticate. An ACTIVE Verigence
    USER/principal with an ACTIVE Clerk mapping proceeds to Clerk password verification. A fully
    verified UC-001 USER that is still PENDING_ADMIN_APPROVAL receives the explicit pending
    lifecycle denial instead; its Clerk identity intentionally remains banned until approval.
    """

    def __init__(self, settings: Settings, clerk: ClerkBackendClient | None = None) -> None:
        self.settings = settings
        self.clerk = clerk or ClerkBackendClient(settings)

    def authenticate(
        self,
        *,
        identifier: str,
        password: str,
    ) -> ClerkCredentialResult:
        normalized = identifier.strip().lower()
        if not normalized or not password:
            raise security_error("AUTH_TOKEN_INVALID")

        expected_clerk_user_id = self._resolve_verigence_clerk_subject(normalized)
        if expected_clerk_user_id is None:
            # Keep all states generic except the deliberate UC-001 PENDING_ADMIN_APPROVAL
            # lifecycle signal emitted by _resolve_verigence_clerk_subject().
            raise security_error("AUTH_TOKEN_INVALID")

        try:
            user = self._clerk_user(expected_clerk_user_id)
            if user.banned or user.locked:
                raise security_error("AUTH_TOKEN_INVALID")
            if not self.clerk.verify_password(
                clerk_user_id=expected_clerk_user_id,
                password=password,
            ):
                raise security_error("AUTH_TOKEN_INVALID")
            return ClerkCredentialResult(clerk_user=user)
        except SecurityError:
            raise
        except ClerkBackendError as exc:
            if exc.retryable:
                raise security_error("IDENTITY_PROVIDER_UNAVAILABLE") from exc
            # Do not expose identifier existence/provider details on authentication failures.
            raise security_error("AUTH_TOKEN_INVALID") from exc

    def _resolve_verigence_clerk_subject(self, normalized_email: str) -> str | None:
        factory = build_session_factory(self.settings)
        if factory is None:
            raise security_error("DATABASE_UNAVAILABLE")
        session = factory()
        try:
            rows = session.execute(
                text(
                    """
                    SELECT e.provider_subject,
                           u.status AS user_status,
                           p.status AS principal_status,
                           e.status AS identity_status,
                           EXISTS (
                               SELECT 1
                               FROM security.platform_user_onboarding_requests r
                               WHERE r.user_id=u.user_id
                                 AND r.status='PENDING_ADMIN_APPROVAL'
                           ) AS pending_admin_approval
                    FROM security.users u
                    JOIN security.security_principals p
                      ON p.principal_id=u.user_id
                     AND p.actor_type='USER'
                    JOIN security.external_identities e
                      ON e.user_id=u.user_id
                     AND e.provider='CLERK'
                     AND e.status='ACTIVE'
                    WHERE lower(u.primary_email)=:email
                    LIMIT 2
                    """
                ),
                {"email": normalized_email},
            ).mappings().all()
            # Historical REVOKED Clerk identities are deliberately retained for auditability and
            # must not make an otherwise valid active account look ambiguous. Multiple ACTIVE
            # mappings still fail closed via this exact-one requirement.
            if len(rows) != 1:
                return None

            row = rows[0]
            if (
                row["user_status"] == "PENDING"
                and row["principal_status"] == "ACTIVE"
                and row["identity_status"] == "ACTIVE"
                and bool(row["pending_admin_approval"])
            ):
                # Pending Clerk users are deliberately banned by the approved onboarding design,
                # so Clerk cannot be used as the normal sign-in gate for this UX state. UC-001
                # explicitly requires the channel to distinguish this completed, verified pending
                # lifecycle from an invalid credential attempt. No access token is issued.
                raise security_error("USER_PENDING_APPROVAL")

            if (
                row["user_status"] != "ACTIVE"
                or row["principal_status"] != "ACTIVE"
                or row["identity_status"] != "ACTIVE"
            ):
                return None

            subject = row["provider_subject"]
            return str(subject) if isinstance(subject, str) and subject.startswith("user_") else None
        finally:
            session.close()

    def _clerk_user(self, clerk_user_id: str) -> ClerkBackendUser:
        data = self.clerk.get_user(clerk_user_id)
        return self._user_from_payload(data)

    @staticmethod
    def _user_from_payload(row: dict[str, Any]) -> ClerkBackendUser:
        user_id = row.get("id")
        if not isinstance(user_id, str) or not user_id:
            raise ClerkBackendError("Clerk user response did not contain an immutable user ID")
        first_name = row.get("first_name") if isinstance(row.get("first_name"), str) else ""
        last_name = row.get("last_name") if isinstance(row.get("last_name"), str) else ""
        display_name = " ".join(value for value in (first_name, last_name) if value).strip()
        primary_email: str | None = None
        primary_id = row.get("primary_email_address_id")
        values = row.get("email_addresses")
        if isinstance(values, list):
            for item in values:
                if not isinstance(item, dict):
                    continue
                value = item.get("email_address")
                if isinstance(value, str) and (item.get("id") == primary_id or primary_email is None):
                    primary_email = value
                    if item.get("id") == primary_id:
                        break
        return ClerkBackendUser(
            user_id=user_id,
            display_name=display_name or primary_email or user_id,
            primary_email=primary_email,
            totp_enabled=bool(row.get("totp_enabled")),
            banned=bool(row.get("banned")),
            locked=bool(row.get("locked")),
        )
