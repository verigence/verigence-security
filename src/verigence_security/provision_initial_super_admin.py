from __future__ import annotations

import os

from verigence_security.config import Settings
from verigence_security.db.session import build_session_factory
from verigence_security.services.initial_super_admin import (
    PHASE1_SUPER_ADMIN_CLERK_USER_ID,
    InitialSuperAdminProvisioningService,
)


def main() -> int:
    settings = Settings()
    database_url = settings.database_url.strip()
    clerk_user_id = os.getenv(
        "SECURITY_INITIAL_SUPER_ADMIN_CLERK_USER_ID",
        PHASE1_SUPER_ADMIN_CLERK_USER_ID,
    ).strip()
    display_name = os.getenv("SECURITY_INITIAL_SUPER_ADMIN_DISPLAY_NAME", "superadmin").strip()

    if not database_url:
        raise RuntimeError("DATABASE_URL is required for initial Super Admin provisioning")

    factory = build_session_factory(settings)
    if factory is None:
        raise RuntimeError("Database session factory is unavailable")

    with factory() as session:
        result = InitialSuperAdminProvisioningService(session).provision(
            clerk_user_id=clerk_user_id,
            display_name=display_name,
        )

    state = "created" if result.created else "already_provisioned_or_reconciled"
    print(f"Initial Platform Super Admin {state}; security_user_id={result.user_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
