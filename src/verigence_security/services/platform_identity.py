from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

from verigence_security.adapters.identity import AuthenticatedIdentity
from verigence_security.config import Settings
from verigence_security.core.errors import security_error
from verigence_security.repositories.platform_admin_repository import PlatformAdminRepository
from verigence_security.services.platform_admin_token import (
    PlatformAdminClaims,
    PlatformAdminTokenService,
)


@dataclass(frozen=True, slots=True)
class PlatformIdentityResult:
    access_token: str
    expires_at_utc: datetime
    user_id: str
    roles: tuple[str, ...]
    permissions: tuple[str, ...]


class PlatformIdentityService:
    """Clerk-authenticated Platform administration boundary from design v1.4.1."""

    _BOOTSTRAP_LOCK_KEY = "verigence.platform.super_admin.bootstrap"

    def __init__(self, session: Session, settings: Settings) -> None:
        self.s = session
        self.settings = settings
        self.repository = PlatformAdminRepository(session)
        self.tokens = PlatformAdminTokenService(settings)

    def bootstrap_claim(
        self,
        *,
        identity: AuthenticatedIdentity,
        correlation_id: str,
    ) -> PlatformIdentityResult:
        self._require_clerk(identity)
        if not self.settings.security_bootstrap_enabled:
            raise security_error("PERMISSION_DENIED")

        expected = self.settings.security_bootstrap_super_admin_clerk_user_id.strip()
        if not expected or identity.provider_subject != expected:
            raise security_error("PERMISSION_DENIED")

        now = datetime.now(UTC)
        try:
            self.s.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
                {"key": self._BOOTSTRAP_LOCK_KEY},
            )
            if self.repository.active_super_admin_exists():
                raise security_error("PERMISSION_DENIED")

            user_id = self._resolve_or_create_security_user(
                clerk_subject=identity.provider_subject,
                now=now,
            )
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
            self.repository.commit()
        except Exception:
            self.repository.rollback()
            raise

        return self._issue_for_user(user_id)

    def login(self, *, identity: AuthenticatedIdentity) -> PlatformIdentityResult:
        self._require_clerk(identity)
        state = self._clerk_user_state(identity.provider_subject)
        if state is None:
            raise security_error("PERMISSION_DENIED")
        if state["identity_status"] != "ACTIVE" or state["principal_status"] != "ACTIVE":
            raise security_error("PRINCIPAL_NOT_ACTIVE")
        if state["user_status"] != "ACTIVE":
            raise security_error("USER_NOT_ACTIVE")
        return self._issue_for_user(str(state["user_id"]))

    def _issue_for_user(self, user_id: str) -> PlatformIdentityResult:
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
        return PlatformIdentityResult(
            access_token=token,
            expires_at_utc=expires_at,
            user_id=user_id,
            roles=roles,
            permissions=permissions,
        )

    def _resolve_or_create_security_user(self, *, clerk_subject: str, now: datetime) -> str:
        state = self._clerk_user_state(clerk_subject)
        if state is not None:
            if state["identity_status"] != "ACTIVE" or state["principal_status"] != "ACTIVE":
                raise security_error("PRINCIPAL_NOT_ACTIVE")
            if state["user_status"] != "ACTIVE":
                raise security_error("USER_NOT_ACTIVE")
            return str(state["user_id"])

        user_id = str(uuid4())
        principal_name = f"clerk:{clerk_subject}"
        self.s.execute(
            text(
                """
                INSERT INTO security.security_principals
                (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                VALUES (:user_id,'USER',:principal_name,'ACTIVE',:now,:now)
                """
            ),
            {"user_id": user_id, "principal_name": principal_name, "now": now},
        )
        self.s.execute(
            text(
                """
                INSERT INTO security.users
                (user_id,display_name,status,created_at_utc,updated_at_utc)
                VALUES (:user_id,:display_name,'ACTIVE',:now,:now)
                """
            ),
            {"user_id": user_id, "display_name": principal_name, "now": now},
        )
        self.s.execute(
            text(
                """
                INSERT INTO security.external_identities
                (external_identity_id,user_id,provider,provider_subject,status,linked_at_utc)
                VALUES (:external_identity_id,:user_id,'CLERK',:subject,'ACTIVE',:now)
                """
            ),
            {
                "external_identity_id": str(uuid4()),
                "user_id": user_id,
                "subject": clerk_subject,
                "now": now,
            },
        )
        return user_id

    def _clerk_user_state(self, clerk_subject: str) -> dict[str, object] | None:
        row = self.s.execute(
            text(
                """
                SELECT e.user_id,e.status AS identity_status,
                       u.status AS user_status,p.status AS principal_status
                FROM security.external_identities e
                JOIN security.users u ON u.user_id=e.user_id
                JOIN security.security_principals p ON p.principal_id=e.user_id
                WHERE e.provider='CLERK' AND e.provider_subject=:subject
                """
            ),
            {"subject": clerk_subject},
        ).mappings().first()
        return dict(row) if row else None

    @staticmethod
    def _require_clerk(identity: AuthenticatedIdentity) -> None:
        if identity.provider != "CLERK" or not identity.provider_subject:
            raise security_error("AUTH_TOKEN_INVALID")
