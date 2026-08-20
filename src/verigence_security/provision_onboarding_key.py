from __future__ import annotations

import os
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

from verigence_security.config import Settings
from verigence_security.db.session import build_session_factory
from verigence_security.services.global_user_onboarding import GlobalUserOnboardingService
from verigence_security.services.onboarding_key import require_onboarding_key_shape


def _super_admin_user_id(session: Session) -> str:
    row = session.execute(
        text(
            """
            SELECT user_id
            FROM security.user_admin_role_assignments
            WHERE role_key='SuperAdmin'
              AND scope_type='PLATFORM'
              AND scope_id IS NULL
              AND status='ACTIVE'
            ORDER BY assigned_at_utc
            LIMIT 1
            """
        )
    ).first()
    if row is not None:
        return str(row[0])

    row = session.execute(
        text(
            """
            SELECT user_id
            FROM security.platform_user_role_assignments
            WHERE role_key='platform.super_admin'
              AND status='ACTIVE'
            ORDER BY assigned_at_utc
            LIMIT 1
            """
        )
    ).first()
    if row is None:
        raise RuntimeError("An ACTIVE Platform SuperAdmin is required before provisioning the onboarding key")
    return str(row[0])


def main() -> int:
    raw_key = os.getenv("SECURITY_ONBOARDING_KEY", "")
    onboarding_key = require_onboarding_key_shape(raw_key)

    settings = Settings()
    if not settings.database_url.strip():
        raise RuntimeError("DATABASE_URL is required for direct onboarding-key provisioning")
    if not settings.security_user_onboarding_key_encryption_key.strip():
        raise RuntimeError(
            "SECURITY_USER_ONBOARDING_KEY_ENCRYPTION_KEY is required for onboarding-key storage"
        )

    factory = build_session_factory(settings)
    if factory is None:
        raise RuntimeError("Database session factory is unavailable")

    with factory() as session:
        actor_user_id = _super_admin_user_id(session)
        result = GlobalUserOnboardingService(session, settings).set_onboarding_key(
            actor_user_id=actor_user_id,
            onboarding_key=onboarding_key,
            enabled=True,
            correlation_id=f"direct-db-onboarding-key-{uuid4()}",
        )

    print(
        "Onboarding key provisioned directly in Security DB; "
        f"version={result['version']} status={result['status']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
