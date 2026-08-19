from __future__ import annotations

from verigence_security.config import Settings
from verigence_security.db.session import build_session_factory
from verigence_security.services.phase1_test_identity import Phase1TestIdentityProvisioningService


def main() -> int:
    settings = Settings()
    if not settings.database_url.strip():
        raise RuntimeError("DATABASE_URL is required for Phase-1 TestUser/TestTenant provisioning")

    factory = build_session_factory(settings)
    if factory is None:
        raise RuntimeError("Database session factory is unavailable")

    with factory() as session:
        result = Phase1TestIdentityProvisioningService(session).provision()

    user_state = "created" if result.user_created else "reused"
    tenant_state = "created" if result.tenant_created else "reused"
    print(
        "Phase-1 Test identity provisioned; "
        f"test_user={user_state} security_user_id={result.user_id} "
        f"test_tenant={tenant_state} tenant_id={result.tenant_id}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
