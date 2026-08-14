from __future__ import annotations

import base64
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from verigence_security.adapters.identity import AuthenticatedIdentity
from verigence_security.api.routes.access import GroupAwareSecurityRepository
from verigence_security.config import Settings
from verigence_security.core.errors import SecurityError
from verigence_security.services.global_user_onboarding import GlobalUserOnboardingService
from verigence_security.services.tenant_rbac_gate import TenantRbacGateService

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)


def _url(value: str) -> str:
    if value.startswith("postgresql+psycopg://"):
        return value
    if value.startswith("postgresql+asyncpg://"):
        return "postgresql+psycopg://" + value.removeprefix("postgresql+asyncpg://")
    if value.startswith("postgresql://"):
        return "postgresql+psycopg://" + value.removeprefix("postgresql://")
    if value.startswith("postgres://"):
        return "postgresql+psycopg://" + value.removeprefix("postgres://")
    raise ValueError("TEST_DATABASE_URL must be PostgreSQL")


def _settings() -> Settings:
    key = base64.urlsafe_b64encode(b"v" * 32).decode("ascii").rstrip("=")
    return Settings(security_user_onboarding_key_encryption_key=key)


class FakeClerk:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.invitation_calls = 0
        self.pending_committed_before_clerk = False
        self.email_by_subject: dict[str, str] = {}
        self.banned: list[str] = []
        self.unbanned: list[str] = []

    def create_invitation(
        self,
        *,
        email: str,
        security_user_id: str,
        onboarding_request_id: str,
    ) -> str:
        self.invitation_calls += 1
        with self.engine.connect() as conn:
            state = conn.execute(
                text(
                    """
                    SELECT u.status,r.status
                    FROM security.users u
                    JOIN security.platform_user_onboarding_requests r ON r.user_id=u.user_id
                    WHERE u.user_id=:user_id AND r.onboarding_request_id=:request_id
                    """
                ),
                {"user_id": security_user_id, "request_id": onboarding_request_id},
            ).one()
        self.pending_committed_before_clerk = state == ("PENDING", "PENDING_CLERK")
        self.email_by_subject["user_v142_test"] = email.lower()
        return f"inv_{uuid4()}"

    def primary_email(self, clerk_user_id: str) -> str | None:
        return self.email_by_subject.get(clerk_user_id)

    def ban_user(self, clerk_user_id: str) -> None:
        self.banned.append(clerk_user_id)

    def unban_user(self, clerk_user_id: str) -> None:
        self.unbanned.append(clerk_user_id)


def _seed_admin(engine: Engine) -> str:
    user_id = str(uuid4())
    now = datetime.now(UTC)
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO security.security_principals
                (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                VALUES (:id,'USER','v1.4.2 Test Admin','ACTIVE',:now,:now)
                """
            ),
            {"id": user_id, "now": now},
        )
        conn.execute(
            text(
                """
                INSERT INTO security.users
                (user_id,display_name,primary_email,status,created_at_utc,updated_at_utc)
                VALUES (:id,'v1.4.2 Test Admin',:email,'ACTIVE',:now,:now)
                """
            ),
            {"id": user_id, "email": f"v142-admin-{user_id}@example.invalid", "now": now},
        )
    return user_id


def _seed_tenant_role(engine: Engine, suffix: str) -> tuple[str, str]:
    tenant_id = str(uuid4())
    role_id = str(uuid4())
    now = datetime.now(UTC)
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO security.tenants
                (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                VALUES (:tenant,:code,:name,'ACTIVE',:now,:now)
                """
            ),
            {
                "tenant": tenant_id,
                "code": f"V142-{suffix}-{uuid4().hex[:8]}",
                "name": f"v1.4.2 Tenant {suffix}",
                "now": now,
            },
        )
        conn.execute(
            text(
                """
                INSERT INTO security.roles
                (role_id,tenant_id,role_key,role_name,status,created_at_utc,updated_at_utc)
                VALUES (:role,:tenant,:key,:name,'ACTIVE',:now,:now)
                """
            ),
            {
                "role": role_id,
                "tenant": tenant_id,
                "key": f"v142.{suffix.lower()}",
                "name": f"v1.4.2 {suffix} Role",
                "now": now,
            },
        )
        conn.execute(
            text(
                """
                INSERT INTO security.role_permissions
                (tenant_id,role_id,permission_key,assigned_at_utc)
                VALUES (:tenant,:role,'security.tenant.read',:now)
                """
            ),
            {"tenant": tenant_id, "role": role_id, "now": now},
        )
    return tenant_id, role_id


def test_v142_schema_and_runtime_retirement_state() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_url(TEST_DATABASE_URL), pool_pre_ping=True)
    try:
        with engine.connect() as conn:
            tables = set(
                conn.execute(
                    text(
                        """
                        SELECT tablename FROM pg_tables
                        WHERE schemaname='security'
                        """
                    )
                ).scalars()
            )
            assert "platform_user_onboarding_settings" in tables
            assert "platform_user_onboarding_requests" in tables
            assert "user_tenant_authorization_state" in tables

            permissions = set(
                conn.execute(
                    text(
                        """
                        SELECT permission_key FROM security.permissions
                        WHERE catalog_version='1.4.2'
                        """
                    )
                ).scalars()
            )
            assert permissions == {
                "security.user.read",
                "security.user.manage",
                "security.user_onboarding.read",
                "security.user_onboarding.manage",
            }

            super_admin_permissions = set(
                conn.execute(
                    text(
                        """
                        SELECT permission_key FROM security.platform_role_permissions
                        WHERE role_key='platform.super_admin'
                        """
                    )
                ).scalars()
            )
            assert permissions <= super_admin_permissions

            controls = {
                str(row["control_key"]): str(row["status"])
                for row in conn.execute(
                    text(
                        """
                        SELECT control_key,status FROM security.security_control_definitions
                        WHERE control_key IN (
                          'admin.self_onboarding',
                          'core.tenant_membership_validation',
                          'admin.global_user_onboarding',
                          'core.user_status_validation',
                          'core.tenant_authorization_state'
                        )
                        """
                    )
                ).mappings()
            }
            assert controls["admin.self_onboarding"] == "RETIRED"
            assert controls["core.tenant_membership_validation"] == "RETIRED"
            assert controls["admin.global_user_onboarding"] == "ACTIVE"
            assert controls["core.user_status_validation"] == "ACTIVE"
            assert controls["core.tenant_authorization_state"] == "ACTIVE"

        from verigence_security.main import app

        paths = {
            path
            for route in app.routes
            if isinstance((path := getattr(route, "path", None)), str)
        }
        assert "/security/v1/onboarding/users" in paths
        assert "/security/v1/auth/precheck" in paths
        assert "/security/v1/platform/users" in paths
        assert not any("self-registrations" in path for path in paths)
        assert not any("owner-invitations" in path for path in paths)
        assert not any("self-onboarding-token" in path for path in paths)
    finally:
        engine.dispose()


def test_global_user_onboards_once_then_authorizes_across_tenants() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_url(TEST_DATABASE_URL), pool_pre_ping=True)
    settings = _settings()
    clerk = FakeClerk(engine)
    admin_id = _seed_admin(engine)
    email = f"v142-{uuid4()}@example.invalid"
    user_id: str | None = None
    tenant_ids: list[str] = []
    role_ids: list[str] = []
    access_session_id: str | None = None

    try:
        with Session(engine) as session:  # type: ignore[arg-type]
            service = GlobalUserOnboardingService(session, settings)
            saved = service.set_onboarding_key(
                actor_user_id=admin_id,
                onboarding_key="VGN-SAFE888",
                enabled=True,
                correlation_id=str(uuid4()),
            )
            assert saved["onboardingKey"] == "VGN-SAFE888"

            assert service.disable_onboarding_key(
                actor_user_id=admin_id,
                correlation_id=str(uuid4()),
            )
            with pytest.raises(SecurityError):
                service.submit(
                    email=email,
                    display_name="Blocked User",
                    onboarding_key="VGN-SAFE888",
                    source_ip="127.0.0.1",
                    correlation_id=str(uuid4()),
                    clerk=clerk,  # type: ignore[arg-type]
                )
            assert clerk.invitation_calls == 0

            rotated = service.rotate_onboarding_key(
                actor_user_id=admin_id,
                correlation_id=str(uuid4()),
            )
            live_key = str(rotated["onboardingKey"])
            assert live_key.startswith("VGN-")
            assert service.get_onboarding_key()["onboardingKey"] == live_key

            with pytest.raises(SecurityError):
                service.submit(
                    email=email,
                    display_name="Wrong Key User",
                    onboarding_key="VGN-FAKE888",
                    source_ip="127.0.0.1",
                    correlation_id=str(uuid4()),
                    clerk=clerk,  # type: ignore[arg-type]
                )
            assert clerk.invitation_calls == 0

            submitted = service.submit(
                email=email,
                display_name="Global User",
                onboarding_key=live_key,
                source_ip="127.0.0.1",
                correlation_id=str(uuid4()),
                clerk=clerk,  # type: ignore[arg-type]
            )
            user_id = str(submitted["userId"])
            request_id = str(submitted["onboardingRequestId"])
            assert submitted["status"] == "CLERK_INVITED"
            assert clerk.invitation_calls == 1
            assert clerk.pending_committed_before_clerk
            assert not service.precheck(email)

            with pytest.raises(ValueError, match="already exists"):
                service.submit(
                    email=email.upper(),
                    display_name="Duplicate User",
                    onboarding_key=live_key,
                    source_ip="127.0.0.1",
                    correlation_id=str(uuid4()),
                    clerk=clerk,  # type: ignore[arg-type]
                )
            assert clerk.invitation_calls == 1

            bound = service.bind_authenticated_clerk_user(
                onboarding_request_id=request_id,
                identity=AuthenticatedIdentity("CLERK", "user_v142_test", "sess_v142"),
                source_ip="127.0.0.1",
                correlation_id=str(uuid4()),
                clerk=clerk,  # type: ignore[arg-type]
            )
            assert bound["status"] == "PENDING_ADMIN_APPROVAL"
            assert "user_v142_test" in clerk.banned
            assert not service.precheck(email)

            activated = service.set_user_status(
                user_id=user_id,
                new_status="ACTIVE",
                actor_user_id=admin_id,
                reason="approved",
                correlation_id=str(uuid4()),
                clerk=clerk,  # type: ignore[arg-type]
            )
            assert activated["status"] == "ACTIVE"
            assert "user_v142_test" in clerk.unbanned
            assert service.precheck(email)

        tenant_a, role_a = _seed_tenant_role(engine, "A")
        tenant_b, role_b = _seed_tenant_role(engine, "B")
        tenant_ids.extend([tenant_a, tenant_b])
        role_ids.extend([role_a, role_b])

        with Session(engine) as session:  # type: ignore[arg-type]
            rbac = TenantRbacGateService(session)
            assert rbac.assign_user_role(
                tenant_id=tenant_a,
                user_id=user_id,
                role_id=role_a,
                actor_user_id=admin_id,
                correlation_id=str(uuid4()),
            )
            assert rbac.assign_user_role(
                tenant_id=tenant_b,
                user_id=user_id,
                role_id=role_b,
                actor_user_id=admin_id,
                correlation_id=str(uuid4()),
            )
            assert "security.tenant.read" in rbac.authorize_user(
                tenant_id=tenant_a,
                user_id=user_id,
                permission_key="security.tenant.read",
            )[1]
            assert "security.tenant.read" in rbac.authorize_user(
                tenant_id=tenant_b,
                user_id=user_id,
                permission_key="security.tenant.read",
            )[1]

        with engine.connect() as conn:
            assert conn.execute(
                text("SELECT count(*) FROM security.tenant_memberships WHERE user_id=:id"),
                {"id": user_id},
            ).scalar_one() == 0
            states = conn.execute(
                text(
                    """
                    SELECT tenant_id,authorization_version
                    FROM security.user_tenant_authorization_state
                    WHERE user_id=:id
                    """
                ),
                {"id": user_id},
            ).mappings().all()
            assert {str(row["tenant_id"]) for row in states} == set(tenant_ids)
            assert all(int(row["authorization_version"]) >= 2 for row in states)

        now = datetime.now(UTC)
        device_id = str(uuid4())
        location_id = str(uuid4())
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO security.tenant_locations
                    (location_id,tenant_id,location_code,location_name,location_type,
                     latitude,longitude,allowed_radius_meters,timezone_iana,status,
                     created_at_utc,updated_at_utc)
                    VALUES (:location,:tenant,:code,'Test Site','OFFICE',30.7333,76.7794,
                            500,'Asia/Kolkata','ACTIVE',:now,:now)
                    """
                ),
                {
                    "location": location_id,
                    "tenant": tenant_a,
                    "code": f"SITE-{uuid4().hex[:8]}",
                    "now": now,
                },
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.registered_devices
                    (device_id,tenant_id,user_id,device_type,platform,device_name,status,
                     registered_at_utc,approved_by_user_id,approved_at_utc)
                    VALUES (:device,:tenant,:user,'WEB','MACOS','v1.4.2 Test','ACTIVE',
                            :now,:admin,:now)
                    """
                ),
                {
                    "device": device_id,
                    "tenant": tenant_a,
                    "user": user_id,
                    "admin": admin_id,
                    "now": now,
                },
            )

        with Session(engine) as session:  # type: ignore[arg-type]
            repo = GroupAwareSecurityRepository(session)
            context = repo.get_user_context(user_id, tenant_a, datetime.now(UTC))
            access_session_id = repo.create_user_session(
                tenant_id=tenant_a,
                user_id=user_id,
                membership_id="ignored-v1.4.2",
                device_id=device_id,
                location_id=location_id,
                authentication_source="CLERK",
                authz_version=context.authorization_version,
                source_ip="127.0.0.1",
                vpn_status="NOT_DETECTED",
                expires_at=datetime.now(UTC) + timedelta(minutes=10),
                now=datetime.now(UTC),
            )
            repo.commit()

        with engine.connect() as conn:
            row = conn.execute(
                text(
                    """
                    SELECT membership_id,authorization_version
                    FROM security.access_sessions WHERE access_session_id=:id
                    """
                ),
                {"id": access_session_id},
            ).mappings().one()
            assert row["membership_id"] is None
            assert int(row["authorization_version"]) == context.authorization_version

        with Session(engine) as session:  # type: ignore[arg-type]
            service = GlobalUserOnboardingService(session, settings)
            suspended = service.set_user_status(
                user_id=user_id,
                new_status="SUSPENDED",
                actor_user_id=admin_id,
                reason="suspend test",
                correlation_id=str(uuid4()),
                clerk=clerk,  # type: ignore[arg-type]
            )
            assert suspended["status"] == "SUSPENDED"
            assert not service.precheck(email)
            assert clerk.banned.count("user_v142_test") >= 2

        with engine.connect() as conn:
            assert conn.execute(
                text("SELECT status FROM security.access_sessions WHERE access_session_id=:id"),
                {"id": access_session_id},
            ).scalar_one() == "REVOKED"
    finally:
        with engine.begin() as conn:
            if user_id is not None:
                conn.execute(
                    text("DELETE FROM security.access_context_evaluations WHERE principal_id=:id"),
                    {"id": user_id},
                )
                conn.execute(
                    text("DELETE FROM security.access_sessions WHERE principal_id=:id"),
                    {"id": user_id},
                )
                conn.execute(
                    text("DELETE FROM security.registered_devices WHERE user_id=:id"),
                    {"id": user_id},
                )
                conn.execute(
                    text("DELETE FROM security.user_location_assignments WHERE user_id=:id"),
                    {"id": user_id},
                )
                conn.execute(
                    text("DELETE FROM security.user_role_assignments WHERE user_id=:id"),
                    {"id": user_id},
                )
                conn.execute(
                    text("DELETE FROM security.group_memberships WHERE user_id=:id"),
                    {"id": user_id},
                )
                conn.execute(
                    text("DELETE FROM security.user_tenant_authorization_state WHERE user_id=:id"),
                    {"id": user_id},
                )
                conn.execute(
                    text("DELETE FROM security.security_events WHERE principal_id=:id"),
                    {"id": user_id},
                )
                conn.execute(
                    text("DELETE FROM security.external_identities WHERE user_id=:id"),
                    {"id": user_id},
                )
                conn.execute(
                    text("DELETE FROM security.platform_user_onboarding_requests WHERE user_id=:id"),
                    {"id": user_id},
                )
            conn.execute(
                text("DELETE FROM security.admin_change_records WHERE actor_user_id=:id"),
                {"id": admin_id},
            )
            for tenant_id in tenant_ids:
                conn.execute(
                    text("DELETE FROM security.role_permissions WHERE tenant_id=:tenant"),
                    {"tenant": tenant_id},
                )
                conn.execute(
                    text("DELETE FROM security.roles WHERE tenant_id=:tenant"),
                    {"tenant": tenant_id},
                )
                conn.execute(
                    text("DELETE FROM security.tenant_locations WHERE tenant_id=:tenant"),
                    {"tenant": tenant_id},
                )
                conn.execute(
                    text("DELETE FROM security.tenants WHERE tenant_id=:tenant"),
                    {"tenant": tenant_id},
                )
            conn.execute(text("DELETE FROM security.platform_user_onboarding_settings"))
            if user_id is not None:
                conn.execute(text("DELETE FROM security.users WHERE user_id=:id"), {"id": user_id})
                conn.execute(
                    text("DELETE FROM security.security_principals WHERE principal_id=:id"),
                    {"id": user_id},
                )
            conn.execute(text("DELETE FROM security.users WHERE user_id=:id"), {"id": admin_id})
            conn.execute(
                text("DELETE FROM security.security_principals WHERE principal_id=:id"),
                {"id": admin_id},
            )
        engine.dispose()
