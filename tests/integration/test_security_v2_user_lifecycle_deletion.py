from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.services.v2_human_actor import AdminScope, HumanActorContext
from verigence_security.services.v2_user_lifecycle import V2UserLifecycleService

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


class _FakeClerk:
    def __init__(self) -> None:
        self.banned: list[str] = []
        self.unbanned: list[str] = []
        self.deleted: list[str] = []

    def ban_user(self, clerk_user_id: str) -> None:
        self.banned.append(clerk_user_id)

    def unban_user(self, clerk_user_id: str) -> None:
        self.unbanned.append(clerk_user_id)

    def delete_user(self, clerk_user_id: str) -> None:
        self.deleted.append(clerk_user_id)


def _create_active_user(
    conn: object,
    *,
    user_id: str,
    clerk_subject: str,
    display_name: str,
    now: datetime,
) -> None:
    conn.execute(  # type: ignore[attr-defined]
        text(
            """
            INSERT INTO security.security_principals
            (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
            VALUES (:user_id,'USER',:principal_name,'ACTIVE',:now,:now)
            """
        ),
        {"user_id": user_id, "principal_name": display_name, "now": now},
    )
    conn.execute(  # type: ignore[attr-defined]
        text(
            """
            INSERT INTO security.users
            (user_id,display_name,primary_email,status,created_at_utc,updated_at_utc)
            VALUES (:user_id,:display_name,:email,'ACTIVE',:now,:now)
            """
        ),
        {
            "user_id": user_id,
            "display_name": display_name,
            "email": f"{user_id}@example.test",
            "now": now,
        },
    )
    conn.execute(  # type: ignore[attr-defined]
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
            "subject": clerk_subject,
            "now": now,
        },
    )


def test_delete_request_and_superadmin_hard_delete_preserve_tombstone_and_actor_evidence() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    conn = engine.connect()
    outer = conn.begin()
    session = Session(bind=conn, join_transaction_mode="create_savepoint")
    now = datetime.now(UTC)
    suffix = uuid4().hex
    target_user_id = str(uuid4())
    target_subject = f"user_delete_target_{suffix}"
    actor_user_id = str(uuid4())
    actor_subject = f"user_delete_admin_{suffix}"
    clerk = _FakeClerk()

    try:
        # Fail early with a readable signal if migration 0015 has not reached the test DB.
        lifecycle_tables = conn.execute(
            text(
                """
                SELECT
                  to_regclass('security.user_deletion_requests') IS NOT NULL
                  AND to_regclass('security.deleted_user_tombstones') IS NOT NULL
                """
            )
        ).scalar_one()
        assert lifecycle_tables is True

        # This test must not compete with a real Phase-1 SuperAdmin singleton. Use the existing
        # active SuperAdmin as actor where available; otherwise create one inside the rollback.
        existing_admin = conn.execute(
            text(
                """
                SELECT a.user_id,e.provider_subject
                FROM security.user_admin_role_assignments a
                JOIN security.users u ON u.user_id=a.user_id AND u.status='ACTIVE'
                JOIN security.external_identities e
                  ON e.user_id=a.user_id AND e.provider='CLERK' AND e.status='ACTIVE'
                WHERE a.role_key='SuperAdmin'
                  AND a.scope_type='PLATFORM'
                  AND a.scope_id IS NULL
                  AND a.status='ACTIVE'
                LIMIT 1
                """
            )
        ).mappings().first()
        if existing_admin is not None:
            actor_user_id = str(existing_admin["user_id"])
            actor_subject = str(existing_admin["provider_subject"])
        else:
            _create_active_user(
                conn,
                user_id=actor_user_id,
                clerk_subject=actor_subject,
                display_name="Lifecycle Test SuperAdmin",
                now=now,
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.user_admin_role_assignments
                    (assignment_id,user_id,role_key,scope_type,scope_id,status,
                     assigned_by_user_id,assigned_at_utc)
                    VALUES (:assignment_id,:user_id,'SuperAdmin','PLATFORM',NULL,'ACTIVE',NULL,:now)
                    """
                ),
                {"assignment_id": str(uuid4()), "user_id": actor_user_id, "now": now},
            )

        _create_active_user(
            conn,
            user_id=target_user_id,
            clerk_subject=target_subject,
            display_name="Lifecycle Delete Target",
            now=now,
        )

        actor = HumanActorContext(
            user_id=actor_user_id,
            clerk_subject=actor_subject,
            admin_scopes=(AdminScope("SuperAdmin", "PLATFORM", None),),
        )
        service = V2UserLifecycleService(session)

        disabled = service.transition(
            user_id=target_user_id,
            requested_status="DISABLED",
            actor=actor,
            reason_code="DELETE_REQUEST",
            reason="integration test deletion request",
            correlation_id=f"delete-request-{suffix}",
            clerk=clerk,  # type: ignore[arg-type]
        )
        assert disabled.status == "DISABLED"
        assert disabled.previous_status == "ACTIVE"
        assert disabled.deletion_request_id is not None
        assert clerk.banned == [target_subject]

        request_row = conn.execute(
            text(
                """
                SELECT status,requested_by_user_id
                FROM security.user_deletion_requests
                WHERE deletion_request_id=:request_id
                """
            ),
            {"request_id": disabled.deletion_request_id},
        ).mappings().one()
        assert request_row["status"] == "REQUESTED"
        assert str(request_row["requested_by_user_id"]) == actor_user_id

        deleted = service.hard_delete(
            user_id=target_user_id,
            actor=actor,
            correlation_id=f"hard-delete-{suffix}",
            clerk=clerk,  # type: ignore[arg-type]
        )
        assert clerk.deleted == [target_subject]
        assert deleted.deletion_request_id == disabled.deletion_request_id
        assert deleted.retain_until_utc - deleted.deleted_at_utc == timedelta(days=21)

        assert conn.execute(
            text("SELECT count(*) FROM security.users WHERE user_id=:user_id"),
            {"user_id": target_user_id},
        ).scalar_one() == 0
        assert conn.execute(
            text("SELECT count(*) FROM security.security_principals WHERE principal_id=:user_id"),
            {"user_id": target_user_id},
        ).scalar_one() == 0

        tombstone = conn.execute(
            text(
                """
                SELECT deleted_user_id,deletion_request_id,safe_actor_reference,
                       deleted_at_utc,retain_until_utc
                FROM security.deleted_user_tombstones
                WHERE tombstone_id=:tombstone_id
                """
            ),
            {"tombstone_id": deleted.tombstone_id},
        ).mappings().one()
        assert str(tombstone["deleted_user_id"]) == target_user_id
        assert str(tombstone["deletion_request_id"]) == disabled.deletion_request_id
        assert tombstone["retain_until_utc"] - tombstone["deleted_at_utc"] == timedelta(days=21)
        assert str(tombstone["safe_actor_reference"]["requestedByUserId"]) == actor_user_id

        # The deletion request is a live-account workflow record and is removed with the USER.
        # The tombstone plus audit evidence are the retained post-deletion records.
        assert conn.execute(
            text(
                "SELECT count(*) FROM security.user_deletion_requests WHERE deletion_request_id=:request_id"
            ),
            {"request_id": disabled.deletion_request_id},
        ).scalar_one() == 0

        actor_audit_count = conn.execute(
            text(
                """
                SELECT count(*)
                FROM security.admin_change_records
                WHERE actor_user_id=:actor_user_id
                  AND resource_id=:target_user_id
                  AND operation_key='security.user.status.change'
                """
            ),
            {"actor_user_id": actor_user_id, "target_user_id": target_user_id},
        ).scalar_one()
        assert actor_audit_count >= 2
    finally:
        session.close()
        outer.rollback()
        conn.close()
        engine.dispose()
