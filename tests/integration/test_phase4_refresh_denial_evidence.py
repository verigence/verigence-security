from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.repositories.session_refresh_repository import (
    SessionRefreshRepository,
)

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


def test_refresh_denial_evidence_allows_unresolved_session_and_geo() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    tenant_id = str(uuid4())
    user_id = str(uuid4())
    evaluation_id = str(uuid4())
    correlation_id = f"phase4-deny-{uuid4()}"
    now = datetime.now(UTC)

    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO security.tenants
                    (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                    VALUES (:tenant_id,:tenant_code,'Phase 4 denial evidence',
                            'ACTIVE',:now,:now)
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "tenant_code": f"p4-deny-{tenant_id}",
                    "now": now,
                },
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.security_principals
                    (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                    VALUES (:user_id,'USER','Phase 4 denial evidence','ACTIVE',:now,:now)
                    """
                ),
                {"user_id": user_id, "now": now},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.users
                    (user_id,display_name,status,created_at_utc,updated_at_utc)
                    VALUES (:user_id,'Phase 4 denial evidence','ACTIVE',:now,:now)
                    """
                ),
                {"user_id": user_id, "now": now},
            )

        with Session(engine) as session:  # type: ignore[arg-type]
            repository = SessionRefreshRepository(session)
            repository.record_evaluation(
                {
                    "evaluation_id": evaluation_id,
                    "tenant_id": tenant_id,
                    "principal_id": user_id,
                    "actor_type": "USER",
                    "source_ip": "203.0.113.10",
                    "decision": "DENY",
                    "decision_reason_code": "GEO_REQUIRED",
                    "correlation_id": correlation_id,
                    "evaluated_at_utc": now,
                }
            )
            repository.commit()

        with engine.connect() as conn:
            row = conn.execute(
                text(
                    """
                    SELECT access_session_id,supplied_latitude,matched_location_id,
                           decision,decision_reason_code,correlation_id
                    FROM security.access_context_evaluations
                    WHERE evaluation_id=:evaluation_id
                    """
                ),
                {"evaluation_id": evaluation_id},
            ).mappings().one()

        assert row["access_session_id"] is None
        assert row["supplied_latitude"] is None
        assert row["matched_location_id"] is None
        assert row["decision"] == "DENY"
        assert row["decision_reason_code"] == "GEO_REQUIRED"
        assert row["correlation_id"] == correlation_id
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM security.access_context_evaluations WHERE tenant_id=:id"),
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
            conn.execute(
                text("DELETE FROM security.tenants WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
        engine.dispose()
