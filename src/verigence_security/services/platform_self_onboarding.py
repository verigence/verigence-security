from __future__ import annotations

import json
from datetime import UTC, datetime

from argon2 import PasswordHasher
from sqlalchemy import text
from sqlalchemy.orm import Session

from verigence_security.repositories.platform_admin_repository import PlatformAdminRepository

_HASHER = PasswordHasher()


class PlatformSelfOnboardingService:
    def __init__(self, session: Session) -> None:
        self.s = session
        self.repository = PlatformAdminRepository(session)

    def rotate(
        self,
        *,
        tenant_id: str,
        actor_user_id: str,
        supplied_value: str,
        correlation_id: str,
    ) -> bool:
        if self.repository.tenant_by_id(tenant_id) is None:
            return False
        now = datetime.now(UTC)
        try:
            self.repository.upsert_self_onboarding_token(
                tenant_id=tenant_id,
                token_hash=_HASHER.hash(supplied_value),
                enabled=True,
                actor_user_id=actor_user_id,
                now=now,
            )
            self.repository.insert_admin_change(
                correlation_id=correlation_id,
                actor_user_id=actor_user_id,
                operation_key="platform.tenant.self_onboarding_value.rotate",
                resource_type="tenant_self_onboarding_setting",
                resource_id=tenant_id,
                outcome="SUCCESS",
                tenant_id=tenant_id,
                after_state_json=json.dumps({"status": "ACTIVE"}),
                now=now,
            )
            self.repository.commit()
            return True
        except Exception:
            self.repository.rollback()
            raise

    def disable(
        self,
        *,
        tenant_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> bool:
        if self.repository.tenant_by_id(tenant_id) is None:
            return False
        now = datetime.now(UTC)
        try:
            row = self.s.execute(
                text(
                    """
                    UPDATE security.tenant_self_onboarding_settings
                    SET status='DISABLED',updated_by_user_id=:actor_user_id,
                        updated_at_utc=:now
                    WHERE tenant_id=:tenant_id
                    RETURNING tenant_id
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "actor_user_id": actor_user_id,
                    "now": now,
                },
            ).first()
            if row is None:
                self.repository.rollback()
                return False
            self.repository.insert_admin_change(
                correlation_id=correlation_id,
                actor_user_id=actor_user_id,
                operation_key="platform.tenant.self_onboarding_value.disable",
                resource_type="tenant_self_onboarding_setting",
                resource_id=tenant_id,
                outcome="SUCCESS",
                tenant_id=tenant_id,
                after_state_json=json.dumps({"status": "DISABLED"}),
                now=now,
            )
            self.repository.commit()
            return True
        except Exception:
            self.repository.rollback()
            raise
