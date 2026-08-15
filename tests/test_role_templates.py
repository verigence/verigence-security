from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from verigence_security.app import create_app
from verigence_security.role_templates import (
    DEFAULT_OPERATIONAL_ROLE_PERMISSIONS,
    MemoryRoleTemplateStore,
    PostgresRoleTemplateStore,
    RoleTemplateService,
)


def _bearer(app, *, subject: str, tenant_id: str, role: str) -> dict[str, str]:
    issued = app.state.token_service.issue_user_access_token(
        subject=subject,
        tenant_id=tenant_id,
        roles=[role],
    )
    return {"Authorization": f"Bearer {issued.access_token}", "X-Correlation-ID": "corr-1"}


def test_default_operational_role_boundaries(settings):
    app = create_app(settings)
    pc = app.state.role_template_service.permissions_for_role("tenant-1", "PC")
    tl = app.state.role_template_service.permissions_for_role("tenant-1", "TL")
    pm = app.state.role_template_service.permissions_for_role("tenant-1", "PM")
    crm = app.state.role_template_service.permissions_for_role("tenant-1", "CRM")

    assert pc == DEFAULT_OPERATIONAL_ROLE_PERMISSIONS["PC"]
    assert "audit.evidence.upload" in pc
    assert "di.document.upload" in pc
    assert "di.verification.write" not in pc
    assert "di.verification.write" in tl
    assert "audit.payment.verify" in tl
    assert "di.verification.write" in pm
    assert "audit.escalation.manage" in pm
    assert "di.document.read" in crm
    assert "di.document.upload" not in crm
    assert "di.verification.write" not in crm


def test_tenant_admin_bootstraps_and_customizes_own_tenant(settings):
    store = MemoryRoleTemplateStore()
    app = create_app(settings, role_store=store)
    client = TestClient(app)
    headers = _bearer(app, subject="ta-1", tenant_id="tenant-1", role="TENANT_ADMIN")

    bootstrap = client.post("/v1/tenants/tenant-1/role-templates/bootstrap", headers=headers)
    assert bootstrap.status_code == 200
    assert {role["roleKey"] for role in bootstrap.json()["roles"]} == {"PC", "TL", "PM", "CRM"}

    updated_permissions = sorted(
        DEFAULT_OPERATIONAL_ROLE_PERMISSIONS["CRM"] | {"audit.analytics.read"}
    )
    response = client.put(
        "/v1/tenants/tenant-1/role-templates/CRM",
        headers=headers,
        json={"permissions": updated_permissions},
    )
    assert response.status_code == 200
    assert "audit.analytics.read" in response.json()["permissions"]

    issued = app.state.token_service.issue_user_access_token(
        subject="crm-1", tenant_id="tenant-1", roles=["CRM"]
    )
    claims = app.state.token_service.decode(issued.access_token)
    assert "audit.analytics.read" in claims["permissions"]
    assert store.audit_events[-1].actor_sub == "ta-1"
    assert store.audit_events[-1].correlation_id == "corr-1"


def test_tenant_admin_cannot_change_another_tenant(settings):
    app = create_app(settings)
    client = TestClient(app)
    headers = _bearer(app, subject="ta-1", tenant_id="tenant-1", role="TENANT_ADMIN")
    response = client.put(
        "/v1/tenants/tenant-2/role-templates/CRM",
        headers=headers,
        json={"permissions": sorted(DEFAULT_OPERATIONAL_ROLE_PERMISSIONS["CRM"])},
    )
    assert response.status_code == 403


def test_super_admin_can_change_tenant_and_platform_defaults(settings):
    app = create_app(settings)
    client = TestClient(app)
    headers = _bearer(app, subject="sa-1", tenant_id="platform-admin", role="SUPER_ADMIN")

    tenant_response = client.put(
        "/v1/tenants/tenant-2/role-templates/CRM",
        headers=headers,
        json={"permissions": sorted(DEFAULT_OPERATIONAL_ROLE_PERMISSIONS["CRM"])},
    )
    assert tenant_response.status_code == 200

    platform_permissions = DEFAULT_OPERATIONAL_ROLE_PERMISSIONS["CRM"] | {"audit.analytics.read"}
    platform_response = client.put(
        "/v1/platform/role-templates/CRM",
        headers=headers,
        json={"permissions": sorted(platform_permissions)},
    )
    assert platform_response.status_code == 200
    assert "audit.analytics.read" in platform_response.json()["permissions"]

    new_tenant = client.post(
        "/v1/tenants/tenant-3/role-templates/bootstrap",
        headers=headers,
    )
    crm = next(role for role in new_tenant.json()["roles"] if role["roleKey"] == "CRM")
    assert "audit.analytics.read" in crm["permissions"]


def test_existing_tenant_is_not_silently_rewritten_by_platform_change(settings):
    app = create_app(settings)
    client = TestClient(app)
    headers = _bearer(app, subject="sa-1", tenant_id="platform-admin", role="SUPER_ADMIN")

    before = client.post("/v1/tenants/tenant-1/role-templates/bootstrap", headers=headers)
    crm_before = next(role for role in before.json()["roles"] if role["roleKey"] == "CRM")
    assert "audit.analytics.read" not in crm_before["permissions"]

    platform_permissions = DEFAULT_OPERATIONAL_ROLE_PERMISSIONS["CRM"] | {"audit.analytics.read"}
    assert client.put(
        "/v1/platform/role-templates/CRM",
        headers=headers,
        json={"permissions": sorted(platform_permissions)},
    ).status_code == 200

    after = client.get("/v1/tenants/tenant-1/role-templates", headers=headers)
    crm_after = next(role for role in after.json()["roles"] if role["roleKey"] == "CRM")
    assert "audit.analytics.read" not in crm_after["permissions"]


def test_operational_template_rejects_forbidden_unknown_and_security_permissions(settings):
    app = create_app(settings)
    client = TestClient(app)
    headers = _bearer(app, subject="ta-1", tenant_id="tenant-1", role="TENANT_ADMIN")

    for invalid_permission in (
        "di.document.delete",
        "di.platform.whatsapp.admin",
        "security.role_template.platform.write",
        "unknown.permission",
    ):
        response = client.put(
            "/v1/tenants/tenant-1/role-templates/PC",
            headers=headers,
            json={"permissions": [invalid_permission]},
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_role_template"


def test_tenant_admin_cannot_change_platform_defaults(settings):
    app = create_app(settings)
    client = TestClient(app)
    headers = _bearer(app, subject="ta-1", tenant_id="tenant-1", role="TENANT_ADMIN")
    response = client.put(
        "/v1/platform/role-templates/CRM",
        headers=headers,
        json={"permissions": sorted(DEFAULT_OPERATIONAL_ROLE_PERMISSIONS["CRM"])},
    )
    assert response.status_code == 403


@pytest.mark.skipif(
    not os.environ.get("SECURITY_TEST_DATABASE_URL"),
    reason="PostgreSQL role-template persistence test requires SECURITY_TEST_DATABASE_URL",
)
def test_postgres_role_override_survives_store_recreation():
    import psycopg

    database_url = os.environ["SECURITY_TEST_DATABASE_URL"]
    schema_sql = Path("database/0001_role_templates.sql").read_text(encoding="utf-8")
    with psycopg.connect(database_url) as conn, conn.cursor() as cur:
        cur.execute(schema_sql)
        cur.execute("TRUNCATE security_role_template_audit, security_role_templates RESTART IDENTITY")
        conn.commit()

    first_store = PostgresRoleTemplateStore(database_url)
    first_service = RoleTemplateService(first_store)
    first_service.seed_platform_defaults()
    first_service.seed_tenant(
        tenant_id="tenant-persist",
        actor_sub="admin-1",
        correlation_id="corr-persist",
    )
    updated = DEFAULT_OPERATIONAL_ROLE_PERMISSIONS["CRM"] | {"audit.analytics.read"}
    first_service.update_tenant(
        tenant_id="tenant-persist",
        role_key="CRM",
        permissions=frozenset(updated),
        actor_sub="admin-1",
        correlation_id="corr-persist",
    )

    second_store = PostgresRoleTemplateStore(database_url)
    second_service = RoleTemplateService(second_store)
    assert "audit.analytics.read" in second_service.permissions_for_role("tenant-persist", "CRM")

    with psycopg.connect(database_url) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT actor_sub, correlation_id
            FROM security_role_template_audit
            WHERE tenant_id = %s AND role_key = %s
            ORDER BY audit_id DESC
            LIMIT 1
            """,
            ("tenant-persist", "CRM"),
        )
        actor_sub, correlation_id = cur.fetchone()
    assert actor_sub == "admin-1"
    assert correlation_id == "corr-persist"
