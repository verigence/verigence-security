from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from verigence_security.config import Settings
from verigence_security.core.errors import security_error
from verigence_security.repositories.platform_admin_repository import PlatformAdminRepository
from verigence_security.services.admin_control_plane_catalog import STANDARD_TENANT_ADMIN_ROLES
from verigence_security.services.platform_admin_token import (
    PlatformAdminClaims,
    PlatformAdminTokenService,
)

_PASSWORD_HASHER = PasswordHasher()


@dataclass(frozen=True, slots=True)
class PlatformLoginResult:
    access_token: str
    expires_at_utc: datetime
    user_id: str
    roles: tuple[str, ...]
    permissions: tuple[str, ...]
    must_change_password: bool


class PlatformBootstrapService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self.repository = PlatformAdminRepository(session)
        self.settings = settings

    def bootstrap_if_needed(self) -> str | None:
        if not self.settings.platform_bootstrap_enabled:
            return None
        if self.repository.active_super_admin_exists():
            return None

        now = datetime.now(UTC)
        password_hash = _PASSWORD_HASHER.hash(self.settings.platform_bootstrap_password)
        try:
            user_id = self.repository.create_bootstrap_super_admin(
                login_name=self.settings.platform_bootstrap_login.strip(),
                password_hash=password_hash,
                now=now,
            )
            self.repository.insert_admin_change(
                correlation_id=f"bootstrap-{uuid4()}",
                actor_user_id=user_id,
                operation_key="platform.super_admin.bootstrap",
                resource_type="platform_user",
                resource_id=user_id,
                outcome="SUCCESS",
                now=now,
            )
            self.repository.commit()
            return user_id
        except Exception:
            self.repository.rollback()
            raise


class PlatformAuthenticationService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self.repository = PlatformAdminRepository(session)
        self.tokens = PlatformAdminTokenService(settings)

    def login(self, *, login_name: str, password: str) -> PlatformLoginResult:
        credential = self.repository.local_credential_by_login(login_name)
        if credential is None:
            raise security_error("AUTH_TOKEN_INVALID")
        if (
            credential["credential_status"] != "ACTIVE"
            or credential["principal_status"] != "ACTIVE"
            or credential["user_status"] != "ACTIVE"
        ):
            raise security_error("AUTH_TOKEN_INVALID")
        try:
            _PASSWORD_HASHER.verify(str(credential["password_hash"]), password)
        except (VerifyMismatchError, VerificationError, InvalidHashError) as exc:
            raise security_error("AUTH_TOKEN_INVALID") from exc

        user_id = str(credential["user_id"])
        roles, permissions = self.repository.platform_roles_permissions(user_id)
        if not roles or not permissions:
            raise security_error("PERMISSION_DENIED")
        must_change = bool(credential["must_change_password"])
        token, expires_at = self.tokens.issue(
            PlatformAdminClaims(
                user_id=user_id,
                roles=roles,
                permissions=permissions,
                must_change_password=must_change,
            )
        )
        return PlatformLoginResult(
            access_token=token,
            expires_at_utc=expires_at,
            user_id=user_id,
            roles=roles,
            permissions=permissions,
            must_change_password=must_change,
        )

    def change_password(
        self,
        *,
        user_id: str,
        new_password: str,
        correlation_id: str,
    ) -> None:
        state = self.repository.credential_state_for_user(user_id)
        if state is None or state["status"] != "ACTIVE":
            raise security_error("AUTH_TOKEN_INVALID")
        now = datetime.now(UTC)
        password_hash = _PASSWORD_HASHER.hash(new_password)
        try:
            changed = self.repository.change_password(
                user_id=user_id,
                password_hash=password_hash,
                now=now,
            )
            if not changed:
                raise security_error("AUTH_TOKEN_INVALID")
            self.repository.insert_admin_change(
                correlation_id=correlation_id,
                actor_user_id=user_id,
                operation_key="platform.auth.change_password",
                resource_type="local_user_credential",
                resource_id=user_id,
                outcome="SUCCESS",
                now=now,
            )
            self.repository.commit()
        except Exception:
            self.repository.rollback()
            raise


class PlatformTenantService:
    def __init__(self, session: Session) -> None:
        self.s = session
        self.repository = PlatformAdminRepository(session)

    def create_tenant(
        self,
        *,
        actor_user_id: str,
        tenant_code: str,
        tenant_name: str,
        correlation_id: str,
        self_onboarding_enabled: bool = False,
        self_onboarding_token: str | None = None,
    ) -> dict[str, object]:
        now = datetime.now(UTC)
        tenant_id = str(uuid4())
        try:
            self.repository.create_tenant(
                tenant_id=tenant_id,
                tenant_code=tenant_code,
                tenant_name=tenant_name,
                now=now,
            )
            self._seed_standard_tenant_roles(tenant_id=tenant_id, now=now)
            if self_onboarding_token is not None:
                self.repository.upsert_self_onboarding_token(
                    tenant_id=tenant_id,
                    token_hash=_PASSWORD_HASHER.hash(self_onboarding_token),
                    enabled=self_onboarding_enabled,
                    actor_user_id=actor_user_id,
                    now=now,
                )
            self.repository.insert_admin_change(
                correlation_id=correlation_id,
                actor_user_id=actor_user_id,
                operation_key="platform.tenant.create",
                resource_type="tenant",
                resource_id=tenant_id,
                outcome="SUCCESS",
                tenant_id=tenant_id,
                after_state_json=json.dumps(
                    {
                        "tenantId": tenant_id,
                        "tenantCode": tenant_code,
                        "tenantName": tenant_name,
                        "status": "CONFIGURING",
                        "selfOnboardingConfigured": self_onboarding_token is not None,
                    }
                ),
                now=now,
            )
            self.repository.commit()
        except IntegrityError:
            self.repository.rollback()
            raise
        except Exception:
            self.repository.rollback()
            raise
        tenant = self.repository.tenant_by_id(tenant_id)
        if tenant is None:
            raise RuntimeError("Created Tenant could not be reloaded")
        return tenant

    def list_tenants(self) -> list[dict[str, Any]]:
        return self.repository.tenants()

    def get_tenant(self, tenant_id: str) -> dict[str, Any] | None:
        return self.repository.tenant_by_id(tenant_id)

    def update_tenant_name(
        self,
        *,
        actor_user_id: str,
        tenant_id: str,
        tenant_name: str,
        correlation_id: str,
    ) -> dict[str, object] | None:
        before = self.repository.tenant_by_id(tenant_id)
        if before is None:
            return None
        now = datetime.now(UTC)
        try:
            if not self.repository.update_tenant_name(
                tenant_id=tenant_id,
                tenant_name=tenant_name,
                now=now,
            ):
                self.repository.rollback()
                return None
            self.repository.insert_admin_change(
                correlation_id=correlation_id,
                actor_user_id=actor_user_id,
                operation_key="platform.tenant.update",
                resource_type="tenant",
                resource_id=tenant_id,
                outcome="SUCCESS",
                tenant_id=tenant_id,
                before_state_json=json.dumps(_json_tenant(before)),
                after_state_json=json.dumps(
                    {**_json_tenant(before), "tenantName": tenant_name}
                ),
                now=now,
            )
            self.repository.commit()
        except Exception:
            self.repository.rollback()
            raise
        return self.repository.tenant_by_id(tenant_id)

    def _seed_standard_tenant_roles(self, *, tenant_id: str, now: datetime) -> None:
        for definition in STANDARD_TENANT_ADMIN_ROLES:
            role_id = str(uuid4())
            self.s.execute(
                text(
                    """
                    INSERT INTO security.roles
                    (role_id,tenant_id,role_key,role_name,description,status,
                     created_at_utc,updated_at_utc)
                    VALUES (:role_id,:tenant_id,:role_key,:role_name,:description,
                            'ACTIVE',:now,:now)
                    """
                ),
                {
                    "role_id": role_id,
                    "tenant_id": tenant_id,
                    "role_key": definition.role_key,
                    "role_name": definition.role_name,
                    "description": definition.description,
                    "now": now,
                },
            )
            for permission_key in sorted(definition.permission_keys):
                self.s.execute(
                    text(
                        """
                        INSERT INTO security.role_permissions
                        (tenant_id,role_id,permission_key,assigned_at_utc)
                        VALUES (:tenant_id,:role_id,:permission_key,:now)
                        """
                    ),
                    {
                        "tenant_id": tenant_id,
                        "role_id": role_id,
                        "permission_key": permission_key,
                        "now": now,
                    },
                )


def _json_tenant(row: dict[str, object]) -> dict[str, object]:
    return {
        "tenantId": str(row["tenant_id"]),
        "tenantCode": row["tenant_code"],
        "tenantName": row["tenant_name"],
        "status": row["status"],
    }
