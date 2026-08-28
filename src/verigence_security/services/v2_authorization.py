from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from verigence_security.core.errors import security_error
from verigence_security.services.token_service import TokenService

AUDIT_MODULE_ADMIN_PERMISSIONS = frozenset(
    {
        "audit.project.read",
        "audit.project.update",
        "audit.project.assignment.manage",
        "audit.master.read",
        "audit.master.write",
        "audit.master.publish",
        "audit.analytics.read",
        "audit.audit_trail.read",
    }
)

DI_MODULE_ADMIN_PERMISSIONS = frozenset(
    {
        "di.requirement_profile.read",
        "di.requirement_profile.write",
        "di.requirement_profile.publish",
        "di.requirement_profile.assign",
        "di.extraction_config.read",
        "di.extraction_config.write",
        "di.extraction_config.publish",
        "di.quality_config.read",
        "di.quality_config.write",
        "di.tenant_config.read",
        "di.tenant_config.write",
        "di.operations.read",
    }
)

# Phase 1 uses only explicitly approved module-administration sets. New modules must
# register an approved administration set before TenantAdmin/ModuleAdmin can receive
# those module permissions; no wildcard or *.manage inference is permitted.
MODULE_ADMIN_PERMISSIONS: dict[str, frozenset[str]] = {
    "audit": AUDIT_MODULE_ADMIN_PERMISSIONS,
    "di": DI_MODULE_ADMIN_PERMISSIONS,
}


class AuthorizationRepository(Protocol):
    def active_service_integration(self, integration_key: str) -> bool: ...

    def human_for_user_id(self, user_id: str) -> dict[str, Any] | None: ...

    def active_permission(self, permission_key: str) -> dict[str, Any] | None: ...

    def tenant_status(self, tenant_id: str) -> str | None: ...

    def active_admin_assignments(self, user_id: str) -> list[dict[str, Any]]: ...

    def active_module_roles(
        self,
        *,
        user_id: str,
        tenant_id: str,
        module_key: str,
    ) -> list[str]: ...

    def module_role_has_permission(
        self,
        *,
        module_key: str,
        role_key: str,
        permission_key: str,
    ) -> bool: ...

    def active_operating_role(self, *, user_id: str, tenant_id: str) -> str | None: ...

    def tenant_role_has_permission(
        self,
        *,
        tenant_id: str,
        role_key: str,
        permission_key: str,
    ) -> bool: ...

    def active_test_identity_for_user(self, user_id: str) -> str | None: ...


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    allowed: bool
    reason_code: str
    user_id: str | None
    tenant_id: str | None
    permission_key: str
    module_key: str | None
    classification: str | None = None
    role_key: str | None = None


class HumanAuthorizationResolver:
    """Resolve current Phase-1 human authorization from Security-owned state only."""

    def __init__(self, repository: AuthorizationRepository) -> None:
        self.repository = repository

    def check(
        self,
        *,
        user_id: str,
        tenant_id: str | None,
        permission_key: str,
    ) -> AuthorizationDecision:
        trusted_user_id = user_id.strip()
        required_permission = permission_key.strip()
        tenant = tenant_id.strip() if tenant_id is not None else None
        if tenant == "":
            tenant = None

        human = self.repository.human_for_user_id(trusted_user_id)
        if human is None or human.get("identity_status") != "ACTIVE":
            return self._deny(
                "USER_NOT_ONBOARDED",
                user_id=trusted_user_id or None,
                tenant_id=tenant,
                permission_key=required_permission,
            )

        resolved_user_id = str(human["user_id"])
        if human.get("principal_actor_type") != "USER":
            return self._deny(
                "ACTOR_TYPE_NOT_ALLOWED",
                user_id=resolved_user_id,
                tenant_id=tenant,
                permission_key=required_permission,
            )
        if human.get("principal_status") != "ACTIVE":
            return self._deny(
                "PRINCIPAL_NOT_ACTIVE",
                user_id=resolved_user_id,
                tenant_id=tenant,
                permission_key=required_permission,
            )
        if human.get("user_status") != "ACTIVE":
            return self._deny(
                "USER_NOT_ACTIVE",
                user_id=resolved_user_id,
                tenant_id=tenant,
                permission_key=required_permission,
            )

        permission = self.repository.active_permission(required_permission)
        if permission is None:
            return self._deny(
                "PERMISSION_NOT_ACTIVE",
                user_id=resolved_user_id,
                tenant_id=tenant,
                permission_key=required_permission,
            )
        module_key = str(permission["module_key"]).lower()

        if tenant is not None and self.repository.tenant_status(tenant) != "ACTIVE":
            return self._deny(
                "TENANT_NOT_ACTIVE",
                user_id=resolved_user_id,
                tenant_id=tenant,
                permission_key=required_permission,
                module_key=module_key,
            )

        admin_assignments = self.repository.active_admin_assignments(resolved_user_id)
        if self._is_super_admin(admin_assignments):
            return self._allow(
                "ALLOW_SUPER_ADMIN",
                user_id=resolved_user_id,
                tenant_id=tenant,
                permission_key=required_permission,
                module_key=module_key,
                classification="SuperAdmin",
            )

        test_tenant_id = self.repository.active_test_identity_for_user(resolved_user_id)
        if test_tenant_id is not None:
            if tenant != test_tenant_id:
                return self._deny(
                    "TEST_TENANT_REQUIRED",
                    user_id=resolved_user_id,
                    tenant_id=tenant,
                    permission_key=required_permission,
                    module_key=module_key,
                    classification="TestUser",
                )
            if self.repository.tenant_role_has_permission(
                tenant_id=test_tenant_id,
                role_key="PC",
                permission_key=required_permission,
            ):
                return self._allow(
                    "ALLOW_TEST_USER_PC",
                    user_id=resolved_user_id,
                    tenant_id=tenant,
                    permission_key=required_permission,
                    module_key=module_key,
                    classification="TestUser",
                    role_key="PC",
                )
            return self._deny(
                "ROLE_PERMISSION_DENIED",
                user_id=resolved_user_id,
                tenant_id=tenant,
                permission_key=required_permission,
                module_key=module_key,
                classification="TestUser",
                role_key="PC",
            )

        # Secondary module roles are evaluated only inside their own permission
        # module. They never replace or block the user's primary operating/admin role.
        if module_key == "attendance" and tenant is not None:
            for module_role in self.repository.active_module_roles(
                user_id=resolved_user_id,
                tenant_id=tenant,
                module_key="attendance",
            ):
                if self.repository.module_role_has_permission(
                    module_key="attendance",
                    role_key=module_role,
                    permission_key=required_permission,
                ):
                    return self._allow(
                        "ALLOW_MODULE_ROLE",
                        user_id=resolved_user_id,
                        tenant_id=tenant,
                        permission_key=required_permission,
                        module_key=module_key,
                        classification="Module",
                        role_key=module_role,
                    )

        # Existing primary-admin behavior remains unchanged.
        if admin_assignments:
            admin_set = MODULE_ADMIN_PERMISSIONS.get(module_key, frozenset())
            if required_permission in admin_set:
                if tenant is not None and self._is_tenant_admin(admin_assignments, tenant):
                    return self._allow(
                        "ALLOW_TENANT_ADMIN",
                        user_id=resolved_user_id,
                        tenant_id=tenant,
                        permission_key=required_permission,
                        module_key=module_key,
                        classification="TenantAdmin",
                    )
                if self._is_module_admin(admin_assignments, module_key):
                    return self._allow(
                        "ALLOW_MODULE_ADMIN",
                        user_id=resolved_user_id,
                        tenant_id=tenant,
                        permission_key=required_permission,
                        module_key=module_key,
                        classification="ModuleAdmin",
                    )
            return self._deny(
                "ADMIN_SCOPE_OR_PERMISSION_DENIED",
                user_id=resolved_user_id,
                tenant_id=tenant,
                permission_key=required_permission,
                module_key=module_key,
                classification="Admin",
            )

        if tenant is None:
            return self._deny(
                "TENANT_CONTEXT_REQUIRED",
                user_id=resolved_user_id,
                tenant_id=None,
                permission_key=required_permission,
                module_key=module_key,
            )

        role_key = self.repository.active_operating_role(
            user_id=resolved_user_id,
            tenant_id=tenant,
        )
        if role_key is None:
            return self._deny(
                "OPERATING_ROLE_NOT_ASSIGNED",
                user_id=resolved_user_id,
                tenant_id=tenant,
                permission_key=required_permission,
                module_key=module_key,
            )
        if self.repository.tenant_role_has_permission(
            tenant_id=tenant,
            role_key=role_key,
            permission_key=required_permission,
        ):
            return self._allow(
                "ALLOW_OPERATING_ROLE",
                user_id=resolved_user_id,
                tenant_id=tenant,
                permission_key=required_permission,
                module_key=module_key,
                classification="Operating",
                role_key=role_key,
            )
        return self._deny(
            "ROLE_PERMISSION_DENIED",
            user_id=resolved_user_id,
            tenant_id=tenant,
            permission_key=required_permission,
            module_key=module_key,
            classification="Operating",
            role_key=role_key,
        )

    @staticmethod
    def _is_super_admin(assignments: list[dict[str, Any]]) -> bool:
        return any(
            row.get("role_key") == "SuperAdmin"
            and row.get("scope_type") == "PLATFORM"
            and row.get("scope_id") is None
            for row in assignments
        )

    @staticmethod
    def _is_tenant_admin(assignments: list[dict[str, Any]], tenant_id: str) -> bool:
        return any(
            row.get("role_key") == "TenantAdmin"
            and row.get("scope_type") == "TENANT"
            and str(row.get("scope_id")) == tenant_id
            for row in assignments
        )

    @staticmethod
    def _is_module_admin(assignments: list[dict[str, Any]], module_key: str) -> bool:
        return any(
            row.get("role_key") == "ModuleAdmin"
            and row.get("scope_type") == "MODULE"
            and str(row.get("scope_id")).lower() == module_key
            for row in assignments
        )

    @staticmethod
    def _allow(
        reason_code: str,
        *,
        user_id: str,
        tenant_id: str | None,
        permission_key: str,
        module_key: str,
        classification: str,
        role_key: str | None = None,
    ) -> AuthorizationDecision:
        return AuthorizationDecision(
            allowed=True,
            reason_code=reason_code,
            user_id=user_id,
            tenant_id=tenant_id,
            permission_key=permission_key,
            module_key=module_key,
            classification=classification,
            role_key=role_key,
        )

    @staticmethod
    def _deny(
        reason_code: str,
        *,
        tenant_id: str | None,
        permission_key: str,
        user_id: str | None = None,
        module_key: str | None = None,
        classification: str | None = None,
        role_key: str | None = None,
    ) -> AuthorizationDecision:
        return AuthorizationDecision(
            allowed=False,
            reason_code=reason_code,
            user_id=user_id,
            tenant_id=tenant_id,
            permission_key=permission_key,
            module_key=module_key,
            classification=classification,
            role_key=role_key,
        )


class AuthorizationCheckService:
    """Authenticate the backend caller and make one synchronous human AuthZ decision."""

    def __init__(self, repository: AuthorizationRepository, tokens: TokenService) -> None:
        self.repository = repository
        self.tokens = tokens
        self.humans = HumanAuthorizationResolver(repository)

    def check(
        self,
        *,
        service_token: str,
        user_id: str,
        tenant_id: str | None,
        permission_key: str,
    ) -> AuthorizationDecision:
        claims = self.tokens.verify_service_token(service_token, audience="security")
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.strip():
            raise security_error("AUTH_TOKEN_INVALID")
        if not self.repository.active_service_integration(subject):
            raise security_error("AUTH_TOKEN_INVALID")
        return self.humans.check(
            user_id=user_id,
            tenant_id=tenant_id,
            permission_key=permission_key,
        )
