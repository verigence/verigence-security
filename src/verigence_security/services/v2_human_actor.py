from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from verigence_security.adapters.identity import AuthenticatedIdentity
from verigence_security.core.errors import security_error
from verigence_security.repositories.v2_human_actor_repository import (
    V2HumanActorRepository,
)


@dataclass(frozen=True, slots=True)
class AdminScope:
    role_key: str
    scope_type: str
    scope_id: str | None


@dataclass(frozen=True, slots=True)
class HumanActorContext:
    user_id: str
    clerk_subject: str
    admin_scopes: tuple[AdminScope, ...]

    @property
    def is_super_admin(self) -> bool:
        return any(
            scope.role_key == "SuperAdmin"
            and scope.scope_type == "PLATFORM"
            and scope.scope_id is None
            for scope in self.admin_scopes
        )

    def is_tenant_admin(self, tenant_id: str) -> bool:
        return any(
            scope.role_key == "TenantAdmin"
            and scope.scope_type == "TENANT"
            and scope.scope_id == tenant_id
            for scope in self.admin_scopes
        )

    def is_module_admin(self, module_key: str) -> bool:
        return any(
            scope.role_key == "ModuleAdmin"
            and scope.scope_type == "MODULE"
            and scope.scope_id == module_key
            for scope in self.admin_scopes
        )

    @property
    def has_admin_classification(self) -> bool:
        return bool(self.admin_scopes)


class HumanActorAuthenticationService:
    """Resolve the authenticated Security USER to current v2 human actor state.

    Active v2 routes receive a global USER id from a validated Security-issued human JWT.
    Clerk remains behind Security: this service reads the stored Clerk mapping only for
    Security-owned lifecycle operations and never trusts a client-supplied Clerk subject.
    """

    def __init__(self, session: Session) -> None:
        self.repository = V2HumanActorRepository(session)

    def authenticate_user_id(self, user_id: str) -> HumanActorContext:
        normalized_user_id = user_id.strip()
        if not normalized_user_id:
            raise security_error("AUTH_TOKEN_INVALID")
        row = self.repository.human_for_user_id(normalized_user_id)
        if row is None:
            raise security_error("USER_NOT_ONBOARDED")
        clerk_subject = row.get("clerk_subject")
        if not isinstance(clerk_subject, str) or not clerk_subject.strip():
            raise security_error("USER_NOT_ONBOARDED")
        return self._context_from_row(row, clerk_subject=clerk_subject)

    def authenticate(self, identity: AuthenticatedIdentity) -> HumanActorContext:
        """Legacy external-identity resolver retained outside the active v2 route boundary."""

        if identity.provider != "CLERK":
            raise security_error("ACTOR_TYPE_NOT_ALLOWED")

        row = self.repository.human_for_external_identity(
            provider="CLERK",
            provider_subject=identity.provider_subject,
        )
        if row is None:
            raise security_error("USER_NOT_ONBOARDED")
        return self._context_from_row(row, clerk_subject=identity.provider_subject)

    def _context_from_row(
        self,
        row: dict[str, Any],
        *,
        clerk_subject: str,
    ) -> HumanActorContext:
        if row.get("identity_status") != "ACTIVE":
            raise security_error("USER_NOT_ONBOARDED")
        if row.get("principal_actor_type") != "USER":
            raise security_error("ACTOR_TYPE_NOT_ALLOWED")
        if row.get("principal_status") != "ACTIVE":
            raise security_error("PRINCIPAL_NOT_ACTIVE")
        if row.get("user_status") != "ACTIVE":
            raise security_error("USER_NOT_ACTIVE")

        user_id = str(row["user_id"])
        admin_scopes = tuple(
            AdminScope(
                role_key=str(assignment["role_key"]),
                scope_type=str(assignment["scope_type"]),
                scope_id=(
                    str(assignment["scope_id"])
                    if assignment["scope_id"] is not None
                    else None
                ),
            )
            for assignment in self.repository.active_admin_assignments(user_id)
        )
        return HumanActorContext(
            user_id=user_id,
            clerk_subject=clerk_subject,
            admin_scopes=admin_scopes,
        )

    @staticmethod
    def require_super_admin(actor: HumanActorContext) -> None:
        if not actor.is_super_admin:
            raise security_error("PERMISSION_DENIED")

    @staticmethod
    def require_tenant_admin(actor: HumanActorContext, tenant_id: str) -> None:
        if not actor.is_tenant_admin(tenant_id):
            raise security_error("PERMISSION_DENIED")

    @staticmethod
    def require_module_admin(actor: HumanActorContext, module_key: str) -> None:
        if not actor.is_module_admin(module_key):
            raise security_error("PERMISSION_DENIED")
