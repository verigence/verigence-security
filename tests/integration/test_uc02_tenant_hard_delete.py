from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.services.platform_admin import PlatformTenantService

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


def test_uc02_hard_delete_removes_tenant_scope_and_preserves_global_user_and_audit() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    tenant_id: str | None = None
    user_id = str(uuid4())
    event_id = str(uuid4())
    now = datetime.now(UTC)

    try:
        with engine.connect() as conn:
            actor_user_id = conn.execute(
                text(
                    """
                    SELECT user_id
                    FROM security.user_admin_role_assignments
                    WHERE role_key='SuperAdmin'
                      AND scope_type='PLATFORM'
                      AND scope_id IS NULL
                      AND status='ACTIVE'
                    LIMIT 1
                    """
                )
            ).scalar_one()

        with Session(engine) as session:  # type: ignore[arg-type]
            tenant = PlatformTenantService(session).create_tenant(
                actor_user_id=str(actor_user_id),
                tenant_code=f"uc02-delete-{uuid4().hex}"[:80],
                tenant_name="UC02 Hard Delete Integration",
                correlation_id=f"uc02-create-{uuid4()}",
                idempotency_key=f"uc02-create-{uuid4()}",
            )
            tenant_id = str(tenant["tenant_id"])

        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO security.security_principals
                    (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                    VALUES (:user_id,'USER',:name,'ACTIVE',:now,:now)
                    """
                ),
                {"user_id": user_id, "name": f"uc02-delete-user-{user_id}", "now": now},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.users
                    (user_id,display_name,status,created_at_utc,updated_at_utc)
                    VALUES (:user_id,'UC02 Delete User','ACTIVE',:now,:now)
                    """
                ),
                {"user_id": user_id, "now": now},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.user_tenant_operating_roles
                    (assignment_id,user_id,tenant_id,role_key,status,
                     assigned_by_user_id,assigned_at_utc)
                    VALUES (:assignment_id,:user_id,:tenant_id,'PC','ACTIVE',
                            :actor_user_id,:now)
                    """
                ),
                {
                    "assignment_id": str(uuid4()),
                    "user_id": user_id,
                    "tenant_id": tenant_id,
                    "actor_user_id": str(actor_user_id),
                    "now": now,
                },
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.security_events
                    (security_event_id,tenant_id,principal_id,actor_type,event_type,
                     outcome,correlation_id,occurred_at_utc)
                    VALUES (:event_id,:tenant_id,:user_id,'USER','UC02_DELETE_PROOF',
                            'SUCCESS',:correlation_id,:now)
                    """
                ),
                {
                    "event_id": event_id,
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "correlation_id": f"uc02-event-{uuid4()}",
                    "now": now,
                },
            )

        with Session(engine) as session:  # type: ignore[arg-type]
            service = PlatformTenantService(session)
            deleted = service.hard_delete_tenant(
                actor_user_id=str(actor_user_id),
                tenant_id=tenant_id,
                correlation_id=f"uc02-delete-{uuid4()}",
            )
            assert deleted is not None
            assert deleted.tenant_id == tenant_id
            assert deleted.already_deleted is False

        with engine.connect() as conn:
            assert conn.execute(
                text("SELECT 1 FROM security.tenants WHERE tenant_id=:id"),
                {"id": tenant_id},
            ).first() is None
            assert conn.execute(
                text("SELECT 1 FROM security.users WHERE user_id=:id"),
                {"id": user_id},
            ).first() is not None
            assert conn.execute(
                text(
                    """
                    SELECT 1 FROM security.user_tenant_operating_roles
                    WHERE tenant_id=:id
                    """
                ),
                {"id": tenant_id},
            ).first() is None
            assert conn.execute(
                text("SELECT 1 FROM security.tenant_role_permissions WHERE tenant_id=:id"),
                {"id": tenant_id},
            ).first() is None
            assert conn.execute(
                text("SELECT 1 FROM security.roles WHERE tenant_id=:id"),
                {"id": tenant_id},
            ).first() is None
            retained_event_tenant = conn.execute(
                text(
                    """
                    SELECT tenant_id FROM security.security_events
                    WHERE security_event_id=:event_id
                    """
                ),
                {"event_id": event_id},
            ).scalar_one()
            assert str(retained_event_tenant) == tenant_id
            delete_receipt = conn.execute(
                text(
                    """
                    SELECT outcome FROM security.admin_change_records
                    WHERE operation_key='platform.tenant.hard_delete'
                      AND resource_id=:tenant_id
                    ORDER BY occurred_at_utc DESC
                    LIMIT 1
                    """
                ),
                {"tenant_id": tenant_id},
            ).scalar_one()
            assert delete_receipt == "SUCCESS"

        with Session(engine) as session:  # type: ignore[arg-type]
            repeated = PlatformTenantService(session).hard_delete_tenant(
                actor_user_id=str(actor_user_id),
                tenant_id=tenant_id,
                correlation_id=f"uc02-delete-retry-{uuid4()}",
            )
            assert repeated is not None
            assert repeated.already_deleted is True
            assert repeated.deleted_at_utc == deleted.deleted_at_utc
    except Exception as exc:
        print(f"UC02_PROOF_EXCEPTION={type(exc).__name__}:{exc}")
        raise
    finally:
        try:
            with engine.begin() as conn:
                conn.execute(
                    text("DELETE FROM security.security_events WHERE security_event_id=:id"),
                    {"id": event_id},
                )
                if tenant_id is not None:
                    conn.execute(
                        text(
                            """
                            DELETE FROM security.admin_change_records
                            WHERE resource_id=:tenant_id OR tenant_id=:tenant_id
                            """
                        ),
                        {"tenant_id": tenant_id},
                    )
                    conn.execute(
                        text("DELETE FROM security.tenants WHERE tenant_id=:id"),
                        {"id": tenant_id},
                    )
                conn.execute(
                    text("DELETE FROM security.users WHERE user_id=:id"),
                    {"id": user_id},
                )
                conn.execute(
                    text("DELETE FROM security.security_principals WHERE principal_id=:id"),
                    {"id": user_id},
                )
        except Exception as cleanup_exc:
            print(f"UC02_CLEANUP_EXCEPTION={type(cleanup_exc).__name__}:{cleanup_exc}")
            raise
        finally:
            engine.dispose()
