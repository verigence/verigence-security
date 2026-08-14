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


def _sqlalchemy_url(url: str) -> str:
    if url.startswith("postgresql+psycopg://"):
        return url
    if url.startswith("postgresql+asyncpg://"):
        return "postgresql+psycopg://" + url.removeprefix("postgresql+asyncpg://")
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url.removeprefix("postgresql://")
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url.removeprefix("postgres://")
    raise ValueError("TEST_DATABASE_URL must be a PostgreSQL URL")


def _settings() -> Settings:
    encryption_key = base64.urlsafe_b64encode(b"v" * 32).decode("ascii").rstrip("=")
    return Settings(
        security_user_onboarding_key_encryption_key=encryption_key,
    )


class _FakeClerk:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.invitation_calls = 0
        self.pending_seen_before_invitation = False
        self.email_by_user_id: dict[str, str] = {}
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
            row = conn.execute(
                text(
                    """
                    SELECT u.status,r.status
                    FROM security.users u
                    JOIN security.platform_user_onboarding_requests r
                      ON r.user_id=u.user_id
                    WHERE u.user_id=:user_id
                      AND r.onboarding_request_id=:request_id
                    """
                ),
                {
                    "user_id": security_user_id,
                    "request_id": onboarding_request_id,
                },
            ).one()
        self.pending_seen_before_invitation = row[0] == "PENDING" and row[1] == "PENDING_CLERK"
        self.email_by_user_id["user_global_test"] = email.lower()
        return f"inv_{uuid4()}"

    def primary_email(self, clerk_user_id: str) -> str | None:
        return self.email_by_user_id.get(clerk_user_id)

    def ban_user(self, clerk_user_id: str) -> None:
        self.banned.append(clerk_user_id)

    def unban_user(self, clerk_user_id: str) -> None:
        self.unbanned.append(clerk_user_id)


def _create_actor(engine: Engine) -> str:
    actor_id = str(uuid4())
    now = datetime.now(UTC)
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO security.security_principals
                (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                VALUES (:id,'USER','v1.4.2 Admin','ACTIVE',:now,:now)
                """
            ),
            {"id": actor_id, "now": now},
        )
        conn.execute(
            text(
                """
                INSERT INTO security.users
                (user_id,display_name,primary_email,status,created_at_utc,updated_at_utc)
                VALUES (:id,'v1.4.2 Admin',:email,'ACTIVE',:now,:now)
                """
            ),
            {
                "id": actor_id,
                "email": f"admin-{actor_id}@example.invalid",
                "now": now,
            },
        )
    return actor_id


def _create_tenant_role(
    engine: Engine,
    *,
    actor_id: str,
    suffix: str,
) -> tuple[str, str]:
    tenant_id = str(uuid4())
    role_id = str(uuid4())
    now = datetime.now(UTC)
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO security.tenants
                (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                VALUES (:tenant_id,:code,:name,'ACTIVE',:now,:now)
                """
            ),
            {
                "tenant_id": tenant_id,
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
                VALUES (:role_id,:tenant_id,:role_key,:role_name,'ACTIVE',:now,:now)
                """
            ),
            {
                "role_id": role_id,
                "tenant_id": tenant_id,
                "role_key": f"v142.{suffix.lower()}",
                "role_name": f"v1.4.2 {suffix} Role",
                "now": now,
            },
        )
        conn.execute(
            text(
                """
                INSERT INTO security.role_permissions
                (tenant_id,role_id,permission_key,assigned_at_utc)
                VALUES (:tenant_id,:role_id,'security.tenant.read',:now)
                """
            ),
            {"tenant_id": tenant_id, "role_id": role_id, "now": now},
        )
    _ = actor_id
    return tenant_id, role_id


def _create_device_and_location(
    engine: Engine,
    *,
    tenant_id: str,
    user_id: str,
    actor_id: str,
) -> tuple[str, str]:
    device_id = str(uuid4())
    location_id = str(uuid4())
    now = datetime.now(UTC)
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO security.tenant_locations
                (location_id,tenant_id,location_code,location_name,location_type,
                 latitude,longitude,allowed_radius_meters,timezone_iana,status,
                 created_at_utc,updated_at_utc)
                VALUES (:location_id,:tenant_id,:code,'v1.4.2 Site','OFFICE',
                        30.7333,76.7794,500,'Asia/Kolkata','ACTIVE',:now,:now)
                """
            ),
            {
                "location_id": location_id,
                "tenant_id": tenant_id,
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
                VALUES (:device_id,:tenant_id,:user_id,'WEB','MACOS','v1.4.2 Test',
                        'ACTIVE',:now,:actor_id,:now)
                """
            ),
            {
                "device_id": device_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "actor_id": actor_id,
                "now": now,
            },
        )
    return device_id, location_id


def test_global_onboarding_once_and_cross_tenant_authorization() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    settings = _settings()
    fake_clerk = _FakeClerk(engine)
    actor_id = _create_actor(engine)
    email = f"v142-{uuid4()}@example.invalid"
    user_id: str | None = None
    tenant_ids: list[str] = []
    role_ids: list[str] = []

    try:
        with Session(engine) as session:  # type: ignore[arg-type]
            service = GlobalUserOnboardingService(session, settings)
            configured = service.set_onboarding_key(
                actor_user_id=actor_id,
                onboarding_key="VGN-START88",
                enabled=True,
                correlation_id=f"v142-key-{uuid4()}",
            )
            assert configured["onboardingKey"] == "VGN-START88"
            rotated = service.rotate_onboarding_key(
                actor_user_id=actor_id,
                correlation_id=f"v142-rotate-{uuid4()}",
            )
            rotated_key = str(rotated["onboardingKey"])
            assert rotated_key.startswith("VGN-")
            assert rotated_key != "VGN-START88"
            assert service.disable_onboarding_key(
                actor_user_id=actor_id,
                correlation_id=f"v142-disable-{uuid4()}",
            )
            with pytest.raises(SecurityError):
                service.submit(
                    email=email,
                    display_name="Blocked Global User",
                    onboarding_key=rotated_key,
                    source_ip="127.0.0.1",
                    correlation_id=f"v142-disabled-{uuid4()}",
                    clerk=fake_clerk,  # type: ignore[arg-type]
                )
            assert fake_clerk.invitation_calls == 0
            service.set_onboarding_key(
                actor_user_id=actor_id,
                onboarding_key="VGN-LIVE888",
                enabled=True,
                correlation_id=f"v142-enable-{uuid4()}",
            )
            with pytest.raises(SecurityError):
                service.submit(
                    email=email,
                    display_name="Wrong Key User",
                    onboarding_key="VGN-WRONG88",
                    source_ip="127.0.0.1",
                    correlation_id=f"v142-wrong-{uuid4()}",
                    clerk=fake_clerk,  # type: ignore[arg-type]
                )
            assert fake_clerk.invitation_calls == 0

            result = service.submit(
                email=email,
                display_name="Global User",
                onboarding_key="VGN-LIVE888",
                source_ip="127.0.0.1",
                correlation_id=f"v142-submit-{uuid4()}",
                clerk=fake_clerk,  # type: ignore[arg-type]
            )
            user_id = str(result["userId"])
            request_id = str(result["onboardingRequestId"])
            assert result["status"] == "CLERK_INVITED"
            assert fake_clerk.invitation_calls == 1
            assert fake_clerk.pending_seen_before_invitation
            assert not service.precheck(email)

            with pytest.raises(ValueError, match="already exists"):
                service.submit(
                    email=email.upper(),
                    display_name="Duplicate User",
                    onboarding_key="VGN-LIVE888",
                    source_ip="127.0.0.1",
                    correlation_id=f"v142-duplicate-{uuid4()}",
                    clerk=fake_clerk,  # type: ignore[arg-type]
                )
            assert fake_clerk.invitation_calls == 1

            bound = service.bind_authenticated_clerk_user(
                onboarding_request_id=request_id,
                identity=AuthenticatedIdentity("CLERK", "user_global_test", "sess_test"),
                source_ip="127.0.0.1",
                correlation_id=f"v142-bind-{uuid4()}",
                clerk=fake_clerk,  # type: ignore[arg-type]
            )
            assert bound["status"] == "PENDING_ADMIN_APPROVAL"
            assert "user_global_test" in fake_clerk.banned
            assert not service.precheck(email)

            activated = service.set_user_status(
                user_id=user_id,
                new_status="ACTIVE",
                actor_user_id=actor_id,
                reason="approved test onboarding",
                correlation_id=f"v142-approve-{uuid4()}",
                clerk=fake_clerk,  # type: ignore[arg-type]
            )
            assert activated["status"] == "ACTIVE"
            assert "user_global_test" in fake_clerk.unbanned
            assert service.precheck(email)

        tenant_a, role_a = _create_tenant_role(engine, actor_id=actor_id, suffix="A")
        tenant_b, role_b = _create_tenant_role(engine, actor_id=actor_id, suffix="B")
        tenant_ids.extend([tenant_a, tenant_b])
        role_ids.extend([role_a, role_b])

        with Session(engine) as session:  # type: ignore[arg-type]
            rbac = TenantRbacGateService(session)
            assert rbac.assign_user_role(
                tenant_id=tenant_a,
                user_id=user_id,
                role_id=role_a,
                actor_user_id=actor_id,
                correlation_id=f"v142-role-a-{uuid4()}",
            )
            assert rbac.assign_user_role(
                tenant_id=tenant_b,
                user_id=user_id,
                role_id=role_b,
                actor_user_id=actor_id,
                correlation_id=f"v142-role-b-{uuid4()}",
            )
            assert rbac.authorize_user(
                tenant_id=tenant_a,
                user_id=user_id,
                permission_key="security.tenant.read",
            )[1] == ["security.tenant.read"]
            assert rbac.authorize_user(
                tenant_id=tenant_b,
                user_id=user_id,
                permission_key="security.tenant.read",
            )[1] == ["security.tenant.read"]

        with engine.connect() as conn:
            membership_count = conn.execute(
                text(
                    """
                    SELECT count(*) FROM security.tenant_memberships
                    WHERE user_id=:user_id
                    """
                ),
                {"user_id": user_id},
            ).scalar_one()
            authz_rows = conn.execute(
                text(
                    """
                    SELECT tenant_id,authorization_version
                    FROM security.user_tenant_authorization_state
                    WHERE user_id=:user_id
                    ORDER BY tenant_id
                    """
                ),
                {"user_id": user_id},
            ).mappings().all()
        assert membership_count == 0
        assert {str(row["tenant_id"]) for row in authz_rows} == set(tenant_ids)
        assert all(int(row["authorization_version"]) >= 2 for row in authz_rows)

        device_id, location_id = _create_device_and_location(
            engine,
            tenant_id=tenant_a,
            user_id=user_id,
            actor_id=actor_id,
        )
        with Session(engine) as session:  # type: ignore[arg-type]
            repo = GroupAwareSecurityRepository(session)
            context = repo.get_user_context(user_id, tenant_a, datetime.now(UTC))
            session_id = repo.create_user_session(
                tenant_id=tenant_a,
                user_id=user_id,
                membership_id="not-required",
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
            access_row = conn.execute(
                text(
                    """
                    SELECT membership_id,authorization_version,status
                    FROM security.access_sessions
                    WHERE access_session_id=:session_id
                    """
                ),
                {"session_id": session_id},
            ).mappings().one()
        assert access_row["membership_id"] is None
        assert int(access_row["authorization_version"]) == context.authorization_version

        with Session(engine) as session:  # type: ignore[arg-type]
            service = GlobalUserOnboardingService(session, settings)
            suspended = service.set_user_status(
                user_id=user_id,
                new_status="SUSPENDED",
                actor_user_id=actor_id,
                reason="suspension test",
                correlation_id=f"v142-suspend-{uuid4()}",
                clerk=fake_clerk,  # type: ignore[arg-type]
            )
            assert suspended["status"] == "SUSPENDED"
            assert fake_clerk.banned.count("user_global_test") >= 2
            assert not service.precheck(email)

        with engine.connect() as conn:
            assert conn.execute(
                text(
                    "SELECT status FROM security.access_sessions "
                    "WHERE access_session_id=:session_id"
                ),
                {"session_id": session_id},
            ).scalar_one() == "REVOKED"

        from verigence_security.main import app

        paths = {route.path for route in app.routes}
        assert "/security/v1/onboarding/users" in paths
        assert "/security/v1/auth/precheck" in paths
        assert not any("self-registrations" in path for path in paths)
        assert not any("owner-invitations" in path for path in paths)
        assert not any("self-onboarding-token" in path for path in paths)
    finally:
        if user_id is not None:
            with engine.begin() as conn:
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
                    text("DELETE FROM security.user_role_assignments WHERE user_id=:id"),
                    {"id": user_id},
                )
                conn.execute(
                    text("DELETE FROM security.group_memberships WHERE user_id=:id"),
                    {"id": user_id},
                )
                conn.execute(
                    text(
                        "DELETE FROM security.user_tenant_authorization_state "
                        "WHERE user_id=:id"
                    ),
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
                    text(
                        "DELETE FROM security.platform_user_onboarding_requests "
                        "WHERE user_id=:id"
                    ),
                    {"id": user_id},
                )
        with engine.begin() as conn:
            conn.execute(
                text(
                    "DELETE FROM security.admin_change_records "
                    "WHERE actor_user_id=:actor_id"
                ),
                {"actor_id": actor_id},
            )
            if role_ids:
                conn.execute(
                    text("DELETE FROM security.role_permissions WHERE role_id = ANY(:role_ids)"),
                    {"role_ids": role_ids},
                )
                conn.execute(
                    text("DELETE FROM security.roles WHERE role_id = ANY(:role_ids)"),
                    {"role_ids": role_ids},
                )
            if tenant_ids:
                conn.execute(
                    text("DELETE FROM security.tenant_locations WHERE tenant_id = ANY(:tenant_ids)"),
                    {"tenant_ids": tenant_ids},
                )
                conn.execute(
                    text("DELETE FROM security.tenants WHERE tenant_id = ANY(:tenant_ids)"),
                    {"tenant_ids": tenant_ids},
                )
            conn.execute(text("DELETE FROM security.platform_user_onboarding_settings"))
            if user_id is not None:
                conn.execute(
                    text("DELETE FROM security.users WHERE user_id=:id"),
                    {"id": user_id},
                )
                conn.execute(
                    text("DELETE FROM security.security_principals WHERE principal_id=:id"),
                    {"id": user_id},
                )
            conn.execute(
                text("DELETE FROM security.users WHERE user_id=:id"),
                {"id": actor_id},
            )
            conn.execute(
                text("DELETE FROM security.security_principals WHERE principal_id=:id"),
                {"id": actor_id},
            )
        engine.dispose()
