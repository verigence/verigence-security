from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.repositories.module_catalog_repository import ModuleCatalogRepository
from verigence_security.services.module_catalog import (
    CatalogInput,
    ModuleCatalogService,
    PermissionInput,
    PermissionRetirementConflict,
    RoleTemplateInput,
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


def _di_catalog() -> CatalogInput:
    raw = json.loads(Path("catalogs/di-v2.2.json").read_text())
    return CatalogInput(
        module_key=raw["moduleKey"],
        module_name=raw["moduleName"],
        catalog_version=raw["catalogVersion"],
        permissions=tuple(
            PermissionInput(
                key=item["key"],
                name=item["name"],
                description=item.get("description"),
                status=item.get("status", "ACTIVE"),
            )
            for item in raw["permissions"]
        ),
        role_templates=tuple(
            RoleTemplateInput(
                key=item["key"],
                name=item["name"],
                description=item.get("description"),
                status=item.get("status", "ACTIVE"),
                permissions=tuple(item["permissions"]),
            )
            for item in raw["roleTemplates"]
        ),
    )


def test_di_catalog_sync_and_permission_retirement_guard_on_neon() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    connection = engine.connect()
    outer = connection.begin()
    actor_user_id = str(uuid4())
    tenant_id = str(uuid4())
    member_user_id = str(uuid4())
    membership_id = str(uuid4())
    role_id = str(uuid4())
    assignment_id = str(uuid4())
    now = datetime.now(UTC)

    try:
        connection.execute(
            text(
                """
                INSERT INTO security.security_principals
                (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                VALUES (:id,'USER','catalog-admin','ACTIVE',:now,:now),
                       (:member_id,'USER','catalog-member','ACTIVE',:now,:now)
                """
            ),
            {"id": actor_user_id, "member_id": member_user_id, "now": now},
        )
        connection.execute(
            text(
                """
                INSERT INTO security.users
                (user_id,display_name,status,created_at_utc,updated_at_utc)
                VALUES (:id,'catalog-admin','ACTIVE',:now,:now),
                       (:member_id,'catalog-member','ACTIVE',:now,:now)
                """
            ),
            {"id": actor_user_id, "member_id": member_user_id, "now": now},
        )

        with Session(connection) as session:
            repository = ModuleCatalogRepository(session)
            service = ModuleCatalogService(repository)
            result = service.put_catalog(
                actor_user_id=actor_user_id,
                correlation_id=str(uuid4()),
                path_module_key="di",
                catalog=_di_catalog(),
            )
            assert result["moduleKey"] == "di"
            assert result["catalogVersion"] == "2.2"
            assert len(result["permissions"]) == 28
            assert len(result["roleTemplates"]) == 5
            template_keys = {
                str(item["key"])
                for item in result["roleTemplates"]  # type: ignore[union-attr]
            }
            assert template_keys == {
                "di.document_operator",
                "di.document_verifier",
                "di.operations_viewer",
                "di.unassigned_intake_operator",
                "di.configuration_admin",
            }
            assert "di.tenant_admin" not in template_keys
            assert "di.service_integration" not in template_keys
            assert "di.platform_admin" not in template_keys

            partial_update = CatalogInput(
                module_key="di",
                module_name="Document Intelligence",
                catalog_version="2.2.1",
                permissions=(
                    PermissionInput(
                        key="di.operations.read",
                        name="di.operations.read",
                        status="DEPRECATED",
                    ),
                ),
                role_templates=(),
            )
            service.put_catalog(
                actor_user_id=actor_user_id,
                correlation_id=str(uuid4()),
                path_module_key="di",
                catalog=partial_update,
            )
            refreshed = service.get_catalog("di")
            assert refreshed is not None
            permissions = {
                str(item["key"]): str(item["status"])
                for item in refreshed["permissions"]  # type: ignore[union-attr]
            }
            assert permissions["di.operations.read"] == "DEPRECATED"
            assert permissions["di.document.read"] == "ACTIVE"

        connection.execute(
            text(
                """
                INSERT INTO security.tenants
                (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                VALUES (:tenant_id,:tenant_code,'Catalogue guard','CONFIGURING',:now,:now)
                """
            ),
            {
                "tenant_id": tenant_id,
                "tenant_code": f"catalog-{tenant_id}",
                "now": now,
            },
        )
        connection.execute(
            text(
                """
                INSERT INTO security.tenant_memberships
                (membership_id,tenant_id,user_id,status,authorization_version,
                 created_at_utc,updated_at_utc)
                VALUES (:membership_id,:tenant_id,:user_id,'ACTIVE',1,:now,:now)
                """
            ),
            {
                "membership_id": membership_id,
                "tenant_id": tenant_id,
                "user_id": member_user_id,
                "now": now,
            },
        )
        connection.execute(
            text(
                """
                INSERT INTO security.roles
                (role_id,tenant_id,role_key,role_name,status,created_at_utc,updated_at_utc)
                VALUES (:role_id,:tenant_id,'CATALOG_ROLE','Catalogue role','ACTIVE',:now,:now)
                """
            ),
            {"role_id": role_id, "tenant_id": tenant_id, "now": now},
        )
        connection.execute(
            text(
                """
                INSERT INTO security.role_permissions
                (tenant_id,role_id,permission_key,assigned_at_utc)
                VALUES (:tenant_id,:role_id,'di.document.read',:now)
                """
            ),
            {"tenant_id": tenant_id, "role_id": role_id, "now": now},
        )
        connection.execute(
            text(
                """
                INSERT INTO security.user_role_assignments
                (assignment_id,tenant_id,user_id,role_id,status,assigned_by_user_id,
                 assigned_at_utc)
                VALUES (:assignment_id,:tenant_id,:user_id,:role_id,'ACTIVE',:actor_id,:now)
                """
            ),
            {
                "assignment_id": assignment_id,
                "tenant_id": tenant_id,
                "user_id": member_user_id,
                "role_id": role_id,
                "actor_id": actor_user_id,
                "now": now,
            },
        )

        with Session(connection) as session:
            service = ModuleCatalogService(ModuleCatalogRepository(session))
            with pytest.raises(PermissionRetirementConflict) as exc_info:
                service.put_catalog(
                    actor_user_id=actor_user_id,
                    correlation_id=str(uuid4()),
                    path_module_key="di",
                    catalog=CatalogInput(
                        module_key="di",
                        module_name="Document Intelligence",
                        catalog_version="2.3",
                        permissions=(
                            PermissionInput(
                                key="di.document.read",
                                name="di.document.read",
                                status="RETIRED",
                            ),
                        ),
                        role_templates=(),
                    ),
                )
            assert exc_info.value.permission_key == "di.document.read"
            assert any(
                str(row["role_key"]) == "CATALOG_ROLE"
                for row in exc_info.value.affected_roles
            )
    finally:
        outer.rollback()
        connection.close()
        engine.dispose()
