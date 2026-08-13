from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

from verigence_security.adapters.clerk_backend import ClerkBackendClient, ClerkBackendUser
from verigence_security.config import Settings
from verigence_security.core.errors import security_error
from verigence_security.repositories.platform_admin_repository import PlatformAdminRepository
from verigence_security.services.platform_admin_token import (
    PlatformAdminClaims,
    PlatformAdminTokenService,
)


@dataclass(frozen=True, slots=True)
class ClerkCredentialResult:
    clerk_user: ClerkBackendUser


@dataclass(frozen=True, slots=True)
class PlatformClerkLoginResult:
    access_token: str
    expires_at_utc: datetime
    user_id: str
    roles: tuple[str, ...]
    permissions: tuple[str, ...]


class ClerkCredentialService:
    def __init__(self, settings: Settings) -> None:
        self.clerk = ClerkBackendClient(settings)

    def authenticate(
        self,
        *,
        identifier: str,
        password: str,
        totp_code: str | None = None,
    ) -> ClerkCredentialResult:
        user = self.clerk.find_user(identifier)
        if user is None or user.banned or user.locked:
            raise security_error("AUTH_TOKEN_INVALID")
        if not self.clerk.verify_password(user_id=user.user_id, password=password):
            raise security_error("AUTH_TOKEN_INVALID")
        if user.totp_enabled:
            if not totp_code or not self.clerk.verify_totp(user_id=user.user_id, code=totp_code):
                raise security_error("AUTH_TOKEN_INVALID")
        return ClerkCredentialResult(clerk_user=user)


class ClerkPlatformAuthenticationService:
    _BOOTSTRAP_LOCK_KEY = "verigence.platform.super_admin.bootstrap"

    def __init__(self, session: Session, settings: Settings) -> None:
        self.s = session
        self.settings = settings
        self.credentials = ClerkCredentialService(settings)
        self.repository = PlatformAdminRepository(session)
        self.tokens = PlatformAdminTokenService(settings)

    def bootstrap_claim(
        self,
        *,
        identifier: str,
        password: str,
        totp_code: str | None,
        correlation_id: str,
    ) -> PlatformClerkLoginResult:
        if not self.settings.platform_bootstrap_enabled:
            raise security_error("PERMISSION_DENIED")
        authenticated = self.credentials.authenticate(
            identifier=identifier,
            password=password,
            totp_code=totp_code,
        )
        clerk_user = authenticated.clerk_user
        expected = self.settings.security_bootstrap_super_admin_clerk_user_id.strip()
        if clerk_user.user_id != expected:
            raise security_error("PERMISSION_DENIED")

        now = datetime.now(UTC)
        try:
            self.s.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
                {"key": self._BOOTSTRAP_LOCK_KEY},
            )
            if self.repository.active_super_admin_exists():
                raise security_error("PERMISSION_DENIED")
            user_id = self._resolve_or_create_security_user(clerk_user=clerk_user, now=now)
            self.s.execute(
                text(
                    """
                    INSERT INTO security.platform_user_role_assignments
                    (assignment_id,user_id,role_key,status,assignment_source,assigned_at_utc)
                    VALUES (:assignment_id,:user_id,'platform.super_admin','ACTIVE',
                            'BOOTSTRAP',:now)
                    """
                ),
                {"assignment_id": str(uuid4()), "user_id": user_id, "now": now},
            )
            self.repository.insert_admin_change(
                correlation_id=correlation_id,
                actor_user_id=user_id,
                operation_key="platform.super_admin.clerk_bootstrap",
                resource_type="platform_user",
                resource_id=user_id,
                outcome="SUCCESS",
                after_state_json=json.dumps(
                    {
                        "identityProvider": "CLERK",
                        "platformRole": "platform.super_admin",
                    }
                ),
                now=now,
            )
            self.s.commit()
        except Exception:
            self.s.rollback()
            raise
        return self._issue_for_user(user_id)

    def login(
        self,
        *,
        identifier: str,
        password: str,
        totp_code: str | None = None,
    ) -> PlatformClerkLoginResult:
        authenticated = self.credentials.authenticate(
            identifier=identifier,
            password=password,
            totp_code=totp_code,
        )
        user_id = self._security_user_for_clerk_subject(authenticated.clerk_user.user_id)
        if user_id is None:
            raise security_error("PERMISSION_DENIED")
        state = self.s.execute(
            text(
                """
                SELECT u.status AS user_status,p.status AS principal_status
                FROM security.users u
                JOIN security.security_principals p ON p.principal_id=u.user_id
                WHERE u.user_id=:user_id
                """
            ),
            {"user_id": user_id},
        ).mappings().first()
        if state is None or state["user_status"] != "ACTIVE" or state["principal_status"] != "ACTIVE":
            raise security_error("PERMISSION_DENIED")
        return self._issue_for_user(user_id)

    def _issue_for_user(self, user_id: str) -> PlatformClerkLoginResult:
        roles, permissions = self.repository.platform_roles_permissions(user_id)
        if not roles or not permissions:
            raise security_error("PERMISSION_DENIED")
        token, expires_at = self.tokens.issue(
            PlatformAdminClaims(
                user_id=user_id,
                roles=roles,
                permissions=permissions,
                must_change_password=False,
            )
        )
        return PlatformClerkLoginResult(
            access_token=token,
            expires_at_utc=expires_at,
            user_id=user_id,
            roles=roles,
            permissions=permissions,
        )

    def _security_user_for_clerk_subject(self, clerk_user_id: str) -> str | None:
        row = self.s.execute(
            text(
                """
                SELECT user_id FROM security.external_identities
                WHERE provider='CLERK' AND provider_subject=:subject AND status='ACTIVE'
                """
            ),
            {"subject": clerk_user_id},
        ).first()
        return str(row[0]) if row else None

    def _resolve_or_create_security_user(
        self,
        *,
        clerk_user: ClerkBackendUser,
        now: datetime,
    ) -> str:
        existing = self._security_user_for_clerk_subject(clerk_user.user_id)
        if existing is not None:
            return existing
        user_id = str(uuid4())
        self.s.execute(
            text(
                """
                INSERT INTO security.security_principals
                (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                VALUES (:user_id,'USER',:display_name,'ACTIVE',:now,:now)
                """
            ),
            {"user_id": user_id, "display_name": clerk_user.display_name, "now": now},
        )
        self.s.execute(
            text(
                """
                INSERT INTO security.users
                (user_id,display_name,primary_email,status,created_at_utc,updated_at_utc)
                VALUES (:user_id,:display_name,:email,'ACTIVE',:now,:now)
                """
            ),
            {
                "user_id": user_id,
                "display_name": clerk_user.display_name,
                "email": clerk_user.primary_email,
                "now": now,
            },
        )
        self.s.execute(
            text(
                """
                INSERT INTO security.external_identities
                (external_identity_id,user_id,provider,provider_subject,status,linked_at_utc)
                VALUES (:id,:user_id,'CLERK',:subject,'ACTIVE',:now)
                """
            ),
            {
                "id": str(uuid4()),
                "user_id": user_id,
                "subject": clerk_user.user_id,
                "now": now,
            },
        )
        return user_id
