from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

from verigence_security.services.initial_super_admin import PHASE1_SUPER_ADMIN_CLERK_USER_ID
from verigence_security.services.platform_admin import PlatformTenantService

PHASE1_TEST_USER_CLERK_USER_ID = "user_3I7FdD5Pkmydsp23OfjH9hBMxpN"
PHASE1_TEST_TENANT_CODE = "test-tenant"
PHASE1_TEST_TENANT_NAME = "TestTenant"


@dataclass(frozen=True, slots=True)
class Phase1TestIdentityProvisioningResult:
    user_id: str
    tenant_id: str
    user_created: bool
    tenant_created: bool


class Phase1TestIdentityProvisioningService:
    """Provision/reconcile the one approved Phase-1 TestUser/TestTenant pair."""

    _LOCK_KEY = "verigence.platform.phase1.test_identity.provision"

    def __init__(self, session: Session) -> None:
        self.s = session

    def provision(self) -> Phase1TestIdentityProvisioningResult:
        self.s.execute(
            text("SELECT pg_advisory_lock(hashtext(:key))"),
            {"key": self._LOCK_KEY},
        )
        try:
            actor_user_id = self._approved_super_admin_user_id()
            user_id, user_created = self._ensure_test_user()
            self._reject_test_user_role_conflicts(user_id)
            tenant_id, tenant_created = self._ensure_test_tenant(actor_user_id)
            self._ensure_test_tenant_defaults(
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
            )
            self._ensure_singleton_binding(user_id=user_id, tenant_id=tenant_id)
            self.s.commit()
            return Phase1TestIdentityProvisioningResult(
                user_id=user_id,
                tenant_id=tenant_id,
                user_created=user_created,
                tenant_created=tenant_created,
            )
        except Exception:
            self.s.rollback()
            raise
        finally:
            self.s.execute(
                text("SELECT pg_advisory_unlock(hashtext(:key))"),
                {"key": self._LOCK_KEY},
            )

    def _approved_super_admin_user_id(self) -> str:
        rows = list(
            self.s.execute(
                text(
                    """
                    SELECT DISTINCT a.user_id
                    FROM security.user_admin_role_assignments a
                    JOIN security.external_identities e
                      ON e.user_id=a.user_id
                     AND e.provider='CLERK'
                     AND e.status='ACTIVE'
                    JOIN security.users u
                      ON u.user_id=a.user_id AND u.status='ACTIVE'
                    JOIN security.security_principals p
                      ON p.principal_id=a.user_id AND p.status='ACTIVE'
                    WHERE a.role_key='SuperAdmin'
                      AND a.scope_type='PLATFORM'
                      AND a.scope_id IS NULL
                      AND a.status='ACTIVE'
                      AND e.provider_subject=:subject
                    """
                ),
                {"subject": PHASE1_SUPER_ADMIN_CLERK_USER_ID},
            ).scalars()
        )
        if len(rows) != 1:
            raise RuntimeError(
                "The exact approved Phase-1 SuperAdmin must be provisioned before TestTenant/TestUser"
            )
        return str(rows[0])

    def _ensure_test_user(self) -> tuple[str, bool]:
        row = self.s.execute(
            text(
                """
                SELECT e.user_id,e.status AS identity_status,
                       u.status AS user_status,p.status AS principal_status
                FROM security.external_identities e
                JOIN security.users u ON u.user_id=e.user_id
                JOIN security.security_principals p ON p.principal_id=u.user_id
                WHERE e.provider='CLERK' AND e.provider_subject=:subject
                """
            ),
            {"subject": PHASE1_TEST_USER_CLERK_USER_ID},
        ).mappings().first()
        if row is not None:
            if (
                row["identity_status"] != "ACTIVE"
                or row["user_status"] != "ACTIVE"
                or row["principal_status"] != "ACTIVE"
            ):
                raise RuntimeError("Approved TestUser identity/USER/principal must be ACTIVE")
            return str(row["user_id"]), False

        now = datetime.now(UTC)
        user_id = str(uuid4())
        self.s.execute(
            text(
                """
                INSERT INTO security.security_principals
                (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                VALUES (:user_id,'USER',:principal_name,'ACTIVE',:now,:now)
                """
            ),
            {
                "user_id": user_id,
                "principal_name": f"clerk:{PHASE1_TEST_USER_CLERK_USER_ID}",
                "now": now,
            },
        )
        self.s.execute(
            text(
                """
                INSERT INTO security.users
                (user_id,display_name,status,created_at_utc,updated_at_utc)
                VALUES (:user_id,'TestUser','ACTIVE',:now,:now)
                """
            ),
            {"user_id": user_id, "now": now},
        )
        self.s.execute(
            text(
                """
                INSERT INTO security.external_identities
                (external_identity_id,user_id,provider,provider_subject,status,linked_at_utc)
                VALUES (:identity_id,:user_id,'CLERK',:subject,'ACTIVE',:now)
                """
            ),
            {
                "identity_id": str(uuid4()),
                "user_id": user_id,
                "subject": PHASE1_TEST_USER_CLERK_USER_ID,
                "now": now,
            },
        )
        self.s.commit()
        return user_id, True

    def _reject_test_user_role_conflicts(self, user_id: str) -> None:
        checks = (
            (
                """
                SELECT 1 FROM security.user_tenant_operating_roles
                WHERE user_id=:user_id AND status='ACTIVE' LIMIT 1
                """,
                "TestUser must not have an ACTIVE operating-role assignment",
            ),
            (
                """
                SELECT 1 FROM security.user_admin_role_assignments
                WHERE user_id=:user_id AND status='ACTIVE' LIMIT 1
                """,
                "TestUser must not have an ACTIVE administrative-role assignment",
            ),
            (
                """
                SELECT 1 FROM security.user_role_assignments
                WHERE user_id=:user_id AND status='ACTIVE' LIMIT 1
                """,
                "TestUser must not have an ACTIVE legacy Tenant-role assignment",
            ),
            (
                """
                SELECT 1 FROM security.platform_user_role_assignments
                WHERE user_id=:user_id AND status='ACTIVE' LIMIT 1
                """,
                "TestUser must not have an ACTIVE legacy platform-role assignment",
            ),
        )
        for statement, message in checks:
            if self.s.execute(text(statement), {"user_id": user_id}).first() is not None:
                raise RuntimeError(message)

    def _ensure_test_tenant(self, actor_user_id: str) -> tuple[str, bool]:
        row = self.s.execute(
            text(
                """
                SELECT tenant_id,tenant_name,status
                FROM security.tenants
                WHERE tenant_code=:tenant_code
                """
            ),
            {"tenant_code": PHASE1_TEST_TENANT_CODE},
        ).mappings().first()
        service = PlatformTenantService(self.s)
        created = False
        if row is None:
            tenant = service.create_tenant(
                actor_user_id=actor_user_id,
                tenant_code=PHASE1_TEST_TENANT_CODE,
                tenant_name=PHASE1_TEST_TENANT_NAME,
                correlation_id=f"phase1-test-tenant-{uuid4()}",
            )
            tenant_id = str(tenant["tenant_id"])
            status = str(tenant["status"])
            created = True
        else:
            if str(row["tenant_name"]) != PHASE1_TEST_TENANT_NAME:
                raise RuntimeError("Reserved TestTenant code exists with another Tenant name")
            tenant_id = str(row["tenant_id"])
            status = str(row["status"])

        if status == "CONFIGURING":
            tenant = service.activate_tenant(
                actor_user_id=actor_user_id,
                tenant_id=tenant_id,
                correlation_id=f"phase1-test-tenant-activate-{uuid4()}",
            )
            if tenant is None or str(tenant["status"]) != "ACTIVE":
                raise RuntimeError("TestTenant could not be activated")
        elif status != "ACTIVE":
            raise RuntimeError(f"TestTenant must be CONFIGURING or ACTIVE, found {status}")
        return tenant_id, created

    def _ensure_test_tenant_defaults(self, *, tenant_id: str, actor_user_id: str) -> None:
        platform_rows = {
            (str(row["role_key"]), str(row["permission_key"]))
            for row in self.s.execute(
                text(
                    """
                    SELECT d.role_key,d.permission_key
                    FROM security.platform_role_permission_defaults d
                    JOIN security.permissions p
                      ON p.permission_key=d.permission_key AND p.status='ACTIVE'
                    WHERE d.status='ACTIVE'
                      AND d.role_key IN ('PC','TL','PM','CRM','Executive')
                    """
                )
            ).mappings()
        }
        if {role_key for role_key, _ in platform_rows} != {"PC", "TL", "PM", "CRM", "Executive"}:
            raise RuntimeError("Approved v2 operating-role platform defaults are not ready")

        tenant_rows = {
            (str(row["role_key"]), str(row["permission_key"]))
            for row in self.s.execute(
                text(
                    """
                    SELECT role_key,permission_key
                    FROM security.tenant_role_permissions
                    WHERE tenant_id=:tenant_id
                      AND role_key IN ('PC','TL','PM','CRM','Executive')
                    """
                ),
                {"tenant_id": tenant_id},
            ).mappings()
        }
        if not tenant_rows:
            PlatformTenantService(self.s)._seed_v2_tenant_role_defaults(
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                now=datetime.now(UTC),
            )
            return
        if tenant_rows != platform_rows:
            raise RuntimeError("Existing TestTenant role bundles differ from current platform defaults")

    def _ensure_singleton_binding(self, *, user_id: str, tenant_id: str) -> None:
        existing = self.s.execute(
            text(
                """
                SELECT user_id,tenant_id,status
                FROM security.phase1_test_identity
                WHERE singleton_id=1
                FOR UPDATE
                """
            )
        ).mappings().first()
        if existing is not None:
            if str(existing["user_id"]) != user_id or str(existing["tenant_id"]) != tenant_id:
                raise RuntimeError("Canonical Phase-1 TestUser/TestTenant binding conflicts with existing data")
            if existing["status"] != "ACTIVE":
                raise RuntimeError("Canonical Phase-1 TestUser/TestTenant binding is not ACTIVE")
            return

        self.s.execute(
            text(
                """
                INSERT INTO security.phase1_test_identity
                (singleton_id,user_id,tenant_id,status,created_at_utc)
                VALUES (1,:user_id,:tenant_id,'ACTIVE',:now)
                """
            ),
            {"user_id": user_id, "tenant_id": tenant_id, "now": datetime.now(UTC)},
        )
