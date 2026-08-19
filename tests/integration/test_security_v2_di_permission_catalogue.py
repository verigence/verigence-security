from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, text

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)

DI_PERMISSION_KEYS = frozenset(
    {
        "di.subject.create",
        "di.subject.read",
        "di.document.upload",
        "di.document.read",
        "di.document.content.read",
        "di.document.fields.read",
        "di.document.quality.read",
        "di.document.delete",
        "di.verification.read",
        "di.verification.write",
        "di.entity_link.read",
        "di.entity_link.write",
        "di.operations.read",
        "di.unassigned_document.read",
        "di.unassigned_document.assign",
        "di.requirement_profile.read",
        "di.requirement_profile.write",
        "di.requirement_profile.publish",
        "di.requirement_profile.assign",
        "di.extraction_config.read",
        "di.extraction_config.write",
        "di.extraction_config.publish",
        "di.quality_config.read",
        "di.quality_config.write",
        "di.tenant_config.read",
        "di.tenant_config.write",
        "di.subject_matching.write",
        "di.platform.whatsapp.admin",
    }
)

NOT_DEFAULT_BUNDLE_KEYS = frozenset(
    {
        "di.document.delete",
        "di.unassigned_document.assign",
        "di.subject_matching.write",
        "di.platform.whatsapp.admin",
    }
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


def test_security_registers_complete_canonical_di_catalogue_without_expanding_role_defaults() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    try:
        with engine.connect() as conn:
            registered = {
                str(row[0])
                for row in conn.execute(
                    text(
                        """
                        SELECT permission_key
                        FROM security.permissions
                        WHERE module_key='di' AND status='ACTIVE'
                        """
                    )
                ).all()
            }
            assert registered >= DI_PERMISSION_KEYS

            default_uses = {
                str(row[0])
                for row in conn.execute(
                    text(
                        """
                        SELECT DISTINCT permission_key
                        FROM security.platform_role_permission_defaults
                        WHERE status='ACTIVE'
                          AND permission_key IN (
                            'di.document.delete',
                            'di.unassigned_document.assign',
                            'di.subject_matching.write',
                            'di.platform.whatsapp.admin'
                          )
                        """
                    )
                ).all()
            }
            assert default_uses == set()
    finally:
        engine.dispose()
