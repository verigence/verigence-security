from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.core.errors import SecurityError
from verigence_security.services.v2_human_actor import HumanActorAuthenticationService

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


def _create_human(
    conn: object,
    *,
    user_id: str,
    subject: str,
    user_status: str = "ACTIVE",
    principal_status: str = "ACTIVE",
    identity_status: str = "ACTIVE",
) -> None:
    now = datetime.now(UTC)
    conn.execute(  # type: ignore[attr-defined]
        text(
            """
            INSERT INTO security.security_principals
            (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
            VALUES (:user_id,'USER',:name,:principal_status,:now,:now)
            """
        ),
        {
            "user_id": user_id,
            "name": f"clerk:{subject}",
            "principal_status": principal_status,
            "now": now,
        },
    )
    conn.execute(  # type: ignore[attr-defined]
        text(
            """
            INSERT INTO security.users
            (user_id,display_name,status,created_at_utc,updated_at_utc)
            VALUES (:user_id,:subject,:user_status,:now,:now)
            """
        ),
        {
            "user_id": user_id,
            "subject": subject,
            "user_status": user_status,
            "now": now,
        },
    )
    conn.execute(  # type: ignore[attr-defined]
        text(
            """
            INSERT INTO security.external_identities
            (external_identity_id,user_id,provider,provider_subject,status,linked_at_utc)
            VALUES (:identity_id,:user_id,'CLERK',:subject,:identity_status,:now)
            """
        ),
        {
            "identity_id": str(uuid4()),
            "user_id": user_id,
            "subject": subject,
            "identity_status": identity_status,
            "now": now,
        },
    )


def _assert_security_error(exc: pytest.ExceptionInfo[SecurityError], code: str) -> None:
    assert exc.value.code == code


def test_v2_human_actor_resolves_current_admin_scopes_from_global_user() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    user_id = str(uuid4())
    tenant_id = str(uuid4())
    subject = f"user_v2_{uuid4().hex}"
    now = datetime.now(UTC)
    try:
        with engine.begin() as conn:
            _create_human(conn, user_id=user_id, subject=subject)
            conn.execute(
                text(
                    """
                    INSERT INTO security.tenants
                    (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                    VALUES (:tenant_id,:code,:code,'ACTIVE',:now,:now)
                    """
                ),
                {"tenant_id": tenant_id, "code": f"v2-human-{tenant_id}", "now": now},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.user_admin_role_assignments
                    (assignment_id,user_id,role_key,scope_type,scope_id,status,
                     assigned_by_user_id,assigned_at_utc)
                    VALUES
                    (:tenant_assignment,:user_id,'TenantAdmin','TENANT',:tenant_id,
                     'ACTIVE',:user_id,:now),
                    (:module_assignment,:user_id,'ModuleAdmin','MODULE','di',
                     'ACTIVE',:user_id,:now)
                    """
                ),
                {
                    "tenant_assignment": str(uuid4()),
                    "module_assignment": str(uuid4()),
                    "user_id": user_id,
                    "tenant_id": tenant_id,
                    "now": now,
                },
            )

        with Session(engine) as session:
            service = HumanActorAuthenticationService(session)
            actor = service.authenticate_user_id(user_id)

            assert actor.user_id == user_id
            assert actor.clerk_subject == subject
            assert actor.has_admin_classification is True
            assert actor.is_tenant_admin(tenant_id) is True
            assert actor.is_module_admin("di") is True
            assert actor.is_super_admin is False
            service.require_tenant_admin(actor, tenant_id)
            service.require_module_admin(actor, "di")

            with pytest.raises(SecurityError) as exc:
                service.require_super_admin(actor)
            _assert_security_error(exc, "PERMISSION_DENIED")
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM security.user_admin_role_assignments WHERE user_id=:user_id"),
                {"user_id": user_id},
            )
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
                text("DELETE FROM security.tenants WHERE tenant_id=:tenant_id"),
                {"tenant_id": tenant_id},
            )
        engine.dispose()


def test_v2_human_actor_allows_active_human_without_admin_classification() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    user_id = str(uuid4())
    subject = f"user_v2_{uuid4().hex}"
    try:
        with engine.begin() as conn:
            _create_human(conn, user_id=user_id, subject=subject)

        with Session(engine) as session:
            actor = HumanActorAuthenticationService(session).authenticate_user_id(user_id)
            assert actor.user_id == user_id
            assert actor.clerk_subject == subject
            assert actor.has_admin_classification is False
    finally:
        with engine.begin() as conn:
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
        engine.dispose()


@pytest.mark.parametrize(
    ("user_status", "principal_status", "identity_status", "expected_code"),
    [
        ("PENDING", "ACTIVE", "ACTIVE", "USER_NOT_ACTIVE"),
        ("ACTIVE", "SUSPENDED", "ACTIVE", "PRINCIPAL_NOT_ACTIVE"),
        ("ACTIVE", "ACTIVE", "REVOKED", "USER_NOT_ONBOARDED"),
    ],
)
def test_v2_human_actor_fails_closed_for_non_active_identity_or_user(
    user_status: str,
    principal_status: str,
    identity_status: str,
    expected_code: str,
) -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    user_id = str(uuid4())
    subject = f"user_v2_{uuid4().hex}"
    try:
        with engine.begin() as conn:
            _create_human(
                conn,
                user_id=user_id,
                subject=subject,
                user_status=user_status,
                principal_status=principal_status,
                identity_status=identity_status,
            )

        with Session(engine) as session:
            with pytest.raises(SecurityError) as exc:
                HumanActorAuthenticationService(session).authenticate_user_id(user_id)
            _assert_security_error(exc, expected_code)
    finally:
        with engine.begin() as conn:
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
        engine.dispose()


def test_v2_human_actor_rejects_unmapped_security_user_id() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    try:
        with Session(engine) as session:
            with pytest.raises(SecurityError) as exc:
                HumanActorAuthenticationService(session).authenticate_user_id(str(uuid4()))
            _assert_security_error(exc, "USER_NOT_ONBOARDED")
    finally:
        engine.dispose()
