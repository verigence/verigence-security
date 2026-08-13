from __future__ import annotations

import os
import secrets
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from argon2 import PasswordHasher
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.core.errors import SecurityError
from verigence_security.services.onboarding import OnboardingService
from verigence_security.services.platform_self_onboarding import PlatformSelfOnboardingService

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)


def _url(url: str) -> str:
    for prefix in ("postgresql+psycopg://", "postgresql://", "postgres://"):
        if url.startswith(prefix):
            return f"postgresql+psycopg://{url.removeprefix(prefix)}"
    if url.startswith("postgresql+asyncpg://"):
        return f"postgresql+psycopg://{url.removeprefix('postgresql+asyncpg://')}"
    raise ValueError("TEST_DATABASE_URL must be PostgreSQL")


def _seed(engine: object) -> dict[str, str]:
    now = datetime.now(UTC)
    ids = {
        "tenant": str(uuid4()),
        "actor": str(uuid4()),
        "role": str(uuid4()),
        "privileged_role": str(uuid4()),
    }
    with engine.begin() as conn:  # type: ignore[union-attr]
        conn.execute(
            text(
                """
                INSERT INTO security.tenants
                (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                VALUES (:id,:code,'Increment F','ACTIVE',:now,:now)
                """
            ),
            {"id": ids["tenant"], "code": f"f-{uuid4().hex}", "now": now},
        )
        conn.execute(
            text(
                """
                INSERT INTO security.security_principals
                (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                VALUES (:id,'USER','F actor','ACTIVE',:now,:now)
                """
            ),
            {"id": ids["actor"], "now": now},
        )
        conn.execute(
            text(
                """
                INSERT INTO security.users
                (user_id,display_name,status,created_at_utc,updated_at_utc)
                VALUES (:id,'F actor','ACTIVE',:now,:now)
                """
            ),
            {"id": ids["actor"], "now": now},
        )
        for role_id, role_key in (
            (ids["role"], "PROCESS_CONSULTANT"),
            (ids["privileged_role"], "tenant.admin"),
        ):
            conn.execute(
                text(
                    """
                    INSERT INTO security.roles
                    (role_id,tenant_id,role_key,role_name,status,
                     created_at_utc,updated_at_utc)
                    VALUES (:role_id,:tenant_id,:role_key,:role_key,'ACTIVE',:now,:now)
                    """
                ),
                {
                    "role_id": role_id,
                    "tenant_id": ids["tenant"],
                    "role_key": role_key,
                    "now": now,
                },
            )
    return ids


def test_increment_f_human_onboarding_state_machine() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_url(TEST_DATABASE_URL), pool_pre_ping=True)
    ids = _seed(engine)
    try:
        with Session(engine) as session:
            service = OnboardingService(session)
            invitation, acceptance_value = service.create_invitation(
                tenant_id=ids["tenant"],
                actor_user_id=ids["actor"],
                display_name="Invited User",
                email="f-invited@example.test",
                mobile=None,
                employee_code="F-001",
                role_ids=[ids["role"]],
                group_ids=[],
                location_assignments=[],
                expires_at_utc=datetime.now(UTC) + timedelta(hours=2),
                correlation_id=str(uuid4()),
            )
            invitation_id = str(invitation["invitation_id"])
            invited_user = str(invitation["invited_user_id"])
            assert _membership(session, ids["tenant"], invited_user) == "PENDING"
            stored_hash = session.execute(
                text(
                    "SELECT acceptance_token_hash FROM security.tenant_invitations "
                    "WHERE invitation_id=:id"
                ),
                {"id": invitation_id},
            ).scalar_one()
            assert str(stored_hash) != acceptance_value
            accepted = service.accept_invitation(
                invitation_id=invitation_id,
                acceptance_token=acceptance_value,
                identity_provider="DEV_MOCK",
                identity_subject=f"f-invite:{uuid4()}",
                correlation_id=str(uuid4()),
            )
            assert accepted["membershipStatus"] == "ACTIVE"
            assert _membership(session, ids["tenant"], invited_user) == "ACTIVE"
            assert _active_roles(session, ids["tenant"], invited_user) == 1

            privileged, privileged_value = service.create_invitation(
                tenant_id=ids["tenant"],
                actor_user_id=ids["actor"],
                display_name="Privileged User",
                email="f-privileged@example.test",
                mobile=None,
                employee_code="F-002",
                role_ids=[ids["privileged_role"]],
                group_ids=[],
                location_assignments=[],
                expires_at_utc=datetime.now(UTC) + timedelta(hours=2),
                correlation_id=str(uuid4()),
            )
            privileged_user = str(privileged["invited_user_id"])
            privileged_result = service.accept_invitation(
                invitation_id=str(privileged["invitation_id"]),
                acceptance_token=privileged_value,
                identity_provider="DEV_MOCK",
                identity_subject=f"f-privileged:{uuid4()}",
                correlation_id=str(uuid4()),
            )
            assert privileged_result["membershipStatus"] == "PENDING"
            assert _membership(session, ids["tenant"], privileged_user) == "PENDING"
            assert _active_roles(session, ids["tenant"], privileged_user) == 0
            pending_privileged = session.execute(
                text(
                    """
                    SELECT count(*) FROM security.privileged_access_requests
                    WHERE tenant_id=:tenant_id AND subject_user_id=:user_id
                      AND status='PENDING'
                    """
                ),
                {"tenant_id": ids["tenant"], "user_id": privileged_user},
            ).scalar_one()
            assert pending_privileged == 1

            first_value = secrets.token_urlsafe(24)
            now = datetime.now(UTC)
            session.execute(
                text(
                    """
                    INSERT INTO security.tenant_self_onboarding_settings
                    (tenant_id,token_hash,token_version,status,created_by_user_id,
                     created_at_utc,updated_by_user_id,updated_at_utc)
                    VALUES (:tenant_id,:value_hash,1,'ACTIVE',:actor,:now,:actor,:now)
                    """
                ),
                {
                    "tenant_id": ids["tenant"],
                    "value_hash": PasswordHasher().hash(first_value),
                    "actor": ids["actor"],
                    "now": now,
                },
            )
            session.execute(
                text(
                    """
                    INSERT INTO security.tenant_security_control_overrides
                    (tenant_id,control_key,override_mode,configuration_version,
                     updated_by_user_id,updated_at_utc,change_reason)
                    VALUES (:tenant_id,'admin.self_onboarding','ENABLED',1,
                            :actor,:now,'Increment F validation')
                    """
                ),
                {"tenant_id": ids["tenant"], "actor": ids["actor"], "now": now},
            )
            session.commit()
            tenant_code = session.execute(
                text("SELECT tenant_code FROM security.tenants WHERE tenant_id=:id"),
                {"id": ids["tenant"]},
            ).scalar_one()
            with pytest.raises(SecurityError):
                service.submit_self_registration(
                    tenant_code=str(tenant_code),
                    onboarding_token=secrets.token_urlsafe(16),
                    identity_provider="DEV_MOCK",
                    identity_subject=f"wrong:{uuid4()}",
                    display_name="Wrong Value",
                    source_ip="127.0.0.1",
                    correlation_id=str(uuid4()),
                )
            session.rollback()
            subject = f"self:{uuid4()}"
            pending = service.submit_self_registration(
                tenant_code=str(tenant_code),
                onboarding_token=first_value,
                identity_provider="DEV_MOCK",
                identity_subject=subject,
                display_name="Self User",
                source_ip="127.0.0.1",
                correlation_id=str(uuid4()),
            )
            assert pending["status"] == "PENDING_ADMIN_APPROVAL"
            duplicate = service.submit_self_registration(
                tenant_code=str(tenant_code),
                onboarding_token=first_value,
                identity_provider="DEV_MOCK",
                identity_subject=subject,
                display_name="Self User",
                source_ip="127.0.0.1",
                correlation_id=str(uuid4()),
            )
            assert duplicate["requestId"] == pending["requestId"]
            approved = service.approve_self_onboarding_request(
                tenant_id=ids["tenant"],
                request_id=str(pending["requestId"]),
                actor_user_id=ids["actor"],
                role_ids=[ids["role"]],
                group_ids=[],
                location_assignments=[],
                correlation_id=str(uuid4()),
            )
            assert approved["status"] == "APPROVED"
            assert _membership(session, ids["tenant"], str(pending["userId"])) == "ACTIVE"

            second_value = secrets.token_urlsafe(24)
            assert PlatformSelfOnboardingService(session).rotate(
                tenant_id=ids["tenant"],
                actor_user_id=ids["actor"],
                supplied_value=second_value,
                correlation_id=str(uuid4()),
            )
            with pytest.raises(SecurityError):
                service.submit_self_registration(
                    tenant_code=str(tenant_code),
                    onboarding_token=first_value,
                    identity_provider="DEV_MOCK",
                    identity_subject=f"old:{uuid4()}",
                    display_name="Old Value",
                    source_ip="127.0.0.1",
                    correlation_id=str(uuid4()),
                )
            session.rollback()
            privileged_self = service.submit_self_registration(
                tenant_code=str(tenant_code),
                onboarding_token=second_value,
                identity_provider="DEV_MOCK",
                identity_subject=f"self-privileged:{uuid4()}",
                display_name="Privileged Self",
                source_ip="127.0.0.1",
                correlation_id=str(uuid4()),
            )
            with pytest.raises(ValueError, match="maker-checker"):
                service.approve_self_onboarding_request(
                    tenant_id=ids["tenant"],
                    request_id=str(privileged_self["requestId"]),
                    actor_user_id=ids["actor"],
                    role_ids=[ids["privileged_role"]],
                    group_ids=[],
                    location_assignments=[],
                    correlation_id=str(uuid4()),
                )
            session.rollback()
            request_status = session.execute(
                text(
                    """
                    SELECT status FROM security.self_onboarding_requests
                    WHERE self_onboarding_request_id=:id
                    """
                ),
                {"id": privileged_self["requestId"]},
            ).scalar_one()
            assert request_status == "PENDING_ADMIN_APPROVAL"
            assert PlatformSelfOnboardingService(session).disable(
                tenant_id=ids["tenant"],
                actor_user_id=ids["actor"],
                correlation_id=str(uuid4()),
            )
            with pytest.raises(SecurityError):
                service.submit_self_registration(
                    tenant_code=str(tenant_code),
                    onboarding_token=second_value,
                    identity_provider="DEV_MOCK",
                    identity_subject=f"disabled:{uuid4()}",
                    display_name="Disabled Value",
                    source_ip="127.0.0.1",
                    correlation_id=str(uuid4()),
                )
            session.rollback()
    finally:
        _cleanup(engine, ids)
        engine.dispose()


def _membership(session: Session, tenant_id: str, user_id: str) -> str:
    value = session.execute(
        text(
            "SELECT status FROM security.tenant_memberships "
            "WHERE tenant_id=:tenant_id AND user_id=:user_id"
        ),
        {"tenant_id": tenant_id, "user_id": user_id},
    ).scalar_one()
    return str(value)


def _active_roles(session: Session, tenant_id: str, user_id: str) -> int:
    value = session.execute(
        text(
            """
            SELECT count(*) FROM security.user_role_assignments
            WHERE tenant_id=:tenant_id AND user_id=:user_id AND status='ACTIVE'
            """
        ),
        {"tenant_id": tenant_id, "user_id": user_id},
    ).scalar_one()
    return int(value)


def _cleanup(engine: object, ids: dict[str, str]) -> None:
    with engine.begin() as conn:  # type: ignore[union-attr]
        user_ids = {
            str(value)
            for value in conn.execute(
                text(
                    "SELECT user_id FROM security.tenant_memberships "
                    "WHERE tenant_id=:tenant_id"
                ),
                {"tenant_id": ids["tenant"]},
            ).scalars()
        }
        for table_name in (
            "admin_change_records",
            "privileged_access_requests",
            "tenant_invitations",
            "self_onboarding_requests",
            "user_role_assignments",
            "role_permissions",
            "tenant_memberships",
            "tenant_self_onboarding_settings",
            "tenant_security_control_overrides",
            "roles",
        ):
            conn.execute(
                text(f"DELETE FROM security.{table_name} WHERE tenant_id=:tenant_id"),
                {"tenant_id": ids["tenant"]},
            )
        for user_id in user_ids:
            conn.execute(
                text("DELETE FROM security.external_identities WHERE user_id=:user_id"),
                {"user_id": user_id},
            )
            conn.execute(
                text("DELETE FROM security.users WHERE user_id=:user_id"),
                {"user_id": user_id},
            )
            conn.execute(
                text("DELETE FROM security.security_principals WHERE principal_id=:user_id"),
                {"user_id": user_id},
            )
        conn.execute(
            text("DELETE FROM security.users WHERE user_id=:id"),
            {"id": ids["actor"]},
        )
        conn.execute(
            text("DELETE FROM security.security_principals WHERE principal_id=:id"),
            {"id": ids["actor"]},
        )
        conn.execute(
            text("DELETE FROM security.tenants WHERE tenant_id=:id"),
            {"id": ids["tenant"]},
        )
