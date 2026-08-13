from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from verigence_security.repositories.user_admin_repository import UserAdminRepository


@dataclass(frozen=True, slots=True)
class UserAdministrationConfiguration:
    user_id: str
    principal_name: str
    principal_status: str
    display_name: str
    primary_email: str | None
    primary_mobile: str | None
    user_status: str


@dataclass(frozen=True, slots=True)
class ExternalIdentityConfiguration:
    external_identity_id: str
    provider: str
    provider_subject: str
    status: str


class UserAdministrationService:
    """Internal USER persistence; provider invitations remain outside this service."""

    def __init__(self, repository: UserAdminRepository) -> None:
        self.repository = repository

    def configure_user(
        self,
        *,
        configuration: UserAdministrationConfiguration,
        now: datetime,
    ) -> bool:
        try:
            self.repository.create_user_principal_if_absent(
                user_id=configuration.user_id,
                principal_name=configuration.principal_name,
                principal_status=configuration.principal_status,
                now=now,
            )
            principal = self.repository.principal(configuration.user_id)
            if principal is None or principal["actor_type"] != "USER":
                self.repository.rollback()
                return False
            self.repository.update_user_principal(
                user_id=configuration.user_id,
                principal_name=configuration.principal_name,
                principal_status=configuration.principal_status,
                now=now,
            )
            self.repository.upsert_user(
                user_id=configuration.user_id,
                display_name=configuration.display_name,
                primary_email=configuration.primary_email,
                primary_mobile=configuration.primary_mobile,
                user_status=configuration.user_status,
                now=now,
            )
            self.repository.commit()
            return True
        except Exception:
            self.repository.rollback()
            raise

    def link_external_identity(
        self,
        *,
        user_id: str,
        configuration: ExternalIdentityConfiguration,
        linked_at: datetime,
    ) -> bool:
        try:
            principal = self.repository.principal(user_id)
            if principal is None or principal["actor_type"] != "USER":
                self.repository.rollback()
                return False
            existing = self.repository.external_identity(
                provider=configuration.provider,
                provider_subject=configuration.provider_subject,
            )
            if existing is not None and str(existing["user_id"]) != user_id:
                self.repository.rollback()
                return False
            self.repository.upsert_external_identity(
                external_identity_id=configuration.external_identity_id,
                user_id=user_id,
                provider=configuration.provider,
                provider_subject=configuration.provider_subject,
                status=configuration.status,
                linked_at=linked_at,
            )
            self.repository.commit()
            return True
        except Exception:
            self.repository.rollback()
            raise
