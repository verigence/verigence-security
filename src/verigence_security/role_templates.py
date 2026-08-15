from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

OPERATIONAL_ROLES = frozenset({"PC", "TL", "PM", "CRM"})

SECURITY_ROLE_TEMPLATE_READ = "security.role_template.read"
SECURITY_ROLE_TEMPLATE_TENANT_WRITE = "security.role_template.tenant.write"
SECURITY_ROLE_TEMPLATE_PLATFORM_WRITE = "security.role_template.platform.write"

SECURITY_ADMIN_ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "TENANT_ADMIN": frozenset(
        {
            SECURITY_ROLE_TEMPLATE_READ,
            SECURITY_ROLE_TEMPLATE_TENANT_WRITE,
        }
    ),
    "SUPER_ADMIN": frozenset(
        {
            SECURITY_ROLE_TEMPLATE_READ,
            SECURITY_ROLE_TEMPLATE_TENANT_WRITE,
            SECURITY_ROLE_TEMPLATE_PLATFORM_WRITE,
        }
    ),
}

AUDIT_PERMISSIONS = frozenset(
    {
        "audit.project.read",
        "audit.project.update",
        "audit.project.assignment.manage",
        "audit.master.read",
        "audit.master.write",
        "audit.master.publish",
        "audit.customer.read",
        "audit.customer.write",
        "audit.journey.create",
        "audit.journey.read",
        "audit.journey.update",
        "audit.journey.submit",
        "audit.evidence.read",
        "audit.evidence.upload",
        "audit.evidence.refresh",
        "audit.payment.read",
        "audit.payment.write",
        "audit.payment.verify",
        "audit.delivery.read",
        "audit.delivery.write",
        "audit.delivery.verify",
        "audit.trade_in.read",
        "audit.trade_in.write",
        "audit.trade_in.verify",
        "audit.finding.read",
        "audit.finding.create",
        "audit.finding.update",
        "audit.finding.resolve",
        "audit.review.read",
        "audit.review.decide",
        "audit.work.read",
        "audit.work.update",
        "audit.work.manage",
        "audit.daily_ops.read",
        "audit.daily_ops.execute",
        "audit.daily_ops.review",
        "audit.crm.read",
        "audit.crm.execute",
        "audit.crm.manage",
        "audit.escalation.read",
        "audit.escalation.manage",
        "audit.analytics.read",
        "audit.audit_trail.read",
    }
)

DI_PERMISSIONS = frozenset(
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

FORBIDDEN_OPERATIONAL_PERMISSIONS = frozenset(
    {
        "di.document.delete",
        "di.platform.whatsapp.admin",
    }
)

EDITABLE_OPERATIONAL_PERMISSIONS = (
    AUDIT_PERMISSIONS | DI_PERMISSIONS
) - FORBIDDEN_OPERATIONAL_PERMISSIONS

DEFAULT_OPERATIONAL_ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "PC": frozenset(
        {
            "audit.project.read",
            "audit.master.read",
            "audit.customer.read",
            "audit.customer.write",
            "audit.journey.create",
            "audit.journey.read",
            "audit.journey.update",
            "audit.journey.submit",
            "audit.evidence.read",
            "audit.evidence.upload",
            "audit.evidence.refresh",
            "audit.payment.read",
            "audit.payment.write",
            "audit.delivery.read",
            "audit.delivery.write",
            "audit.trade_in.read",
            "audit.trade_in.write",
            "audit.finding.read",
            "audit.finding.create",
            "audit.work.read",
            "audit.work.update",
            "audit.daily_ops.read",
            "audit.daily_ops.execute",
            "di.subject.create",
            "di.subject.read",
            "di.document.upload",
            "di.document.read",
            "di.document.content.read",
            "di.document.fields.read",
            "di.document.quality.read",
            "di.entity_link.read",
            "di.entity_link.write",
        }
    ),
    "TL": frozenset(
        {
            "audit.project.read",
            "audit.master.read",
            "audit.customer.read",
            "audit.journey.read",
            "audit.evidence.read",
            "audit.evidence.refresh",
            "audit.payment.read",
            "audit.payment.verify",
            "audit.delivery.read",
            "audit.delivery.verify",
            "audit.trade_in.read",
            "audit.trade_in.verify",
            "audit.finding.read",
            "audit.finding.create",
            "audit.finding.update",
            "audit.review.read",
            "audit.review.decide",
            "audit.work.read",
            "audit.work.update",
            "audit.work.manage",
            "audit.daily_ops.read",
            "audit.daily_ops.review",
            "audit.escalation.read",
            "audit.analytics.read",
            "di.subject.read",
            "di.document.read",
            "di.document.content.read",
            "di.document.fields.read",
            "di.document.quality.read",
            "di.verification.read",
            "di.verification.write",
            "di.operations.read",
        }
    ),
    "PM": frozenset(
        {
            "audit.project.read",
            "audit.project.update",
            "audit.project.assignment.manage",
            "audit.master.read",
            "audit.customer.read",
            "audit.journey.read",
            "audit.evidence.read",
            "audit.evidence.refresh",
            "audit.payment.read",
            "audit.payment.verify",
            "audit.delivery.read",
            "audit.delivery.verify",
            "audit.trade_in.read",
            "audit.trade_in.verify",
            "audit.finding.read",
            "audit.finding.create",
            "audit.finding.update",
            "audit.finding.resolve",
            "audit.review.read",
            "audit.review.decide",
            "audit.work.read",
            "audit.work.update",
            "audit.work.manage",
            "audit.daily_ops.read",
            "audit.daily_ops.review",
            "audit.crm.read",
            "audit.crm.manage",
            "audit.escalation.read",
            "audit.escalation.manage",
            "audit.analytics.read",
            "audit.audit_trail.read",
            "di.subject.read",
            "di.document.read",
            "di.document.content.read",
            "di.document.fields.read",
            "di.document.quality.read",
            "di.verification.read",
            "di.verification.write",
            "di.operations.read",
        }
    ),
    "CRM": frozenset(
        {
            "audit.project.read",
            "audit.customer.read",
            "audit.journey.read",
            "audit.evidence.read",
            "audit.finding.read",
            "audit.work.read",
            "audit.work.update",
            "audit.crm.read",
            "audit.crm.execute",
            "audit.escalation.read",
            "di.subject.read",
            "di.document.read",
            "di.document.content.read",
            "di.document.fields.read",
            "di.document.quality.read",
        }
    ),
}


class RoleTemplateError(Exception):
    """Base role-template error."""


class InvalidRoleTemplate(RoleTemplateError):
    """A role-template mutation is invalid."""


class UnknownRoleTemplate(RoleTemplateError):
    """The requested operational role is unknown."""


@dataclass(frozen=True)
class RoleTemplate:
    scope_type: str
    tenant_id: str | None
    role_key: str
    permissions: frozenset[str]
    version: int
    updated_by: str
    updated_at: datetime


@dataclass(frozen=True)
class RoleTemplateAuditEvent:
    scope_type: str
    tenant_id: str | None
    role_key: str
    previous_permissions: frozenset[str]
    new_permissions: frozenset[str]
    actor_sub: str
    correlation_id: str | None
    changed_at: datetime


class RoleTemplateStore(Protocol):
    def get(self, scope_type: str, tenant_id: str | None, role_key: str) -> RoleTemplate | None: ...

    def list(self, scope_type: str, tenant_id: str | None) -> list[RoleTemplate]: ...

    def upsert(
        self,
        *,
        scope_type: str,
        tenant_id: str | None,
        role_key: str,
        permissions: frozenset[str],
        actor_sub: str,
        correlation_id: str | None,
    ) -> RoleTemplate: ...


class MemoryRoleTemplateStore:
    def __init__(self) -> None:
        self._rows: dict[tuple[str, str | None, str], RoleTemplate] = {}
        self.audit_events: list[RoleTemplateAuditEvent] = []

    def get(self, scope_type: str, tenant_id: str | None, role_key: str) -> RoleTemplate | None:
        return self._rows.get((scope_type, tenant_id, role_key))

    def list(self, scope_type: str, tenant_id: str | None) -> list[RoleTemplate]:
        return sorted(
            [
                row
                for key, row in self._rows.items()
                if key[0] == scope_type and key[1] == tenant_id
            ],
            key=lambda row: row.role_key,
        )

    def upsert(
        self,
        *,
        scope_type: str,
        tenant_id: str | None,
        role_key: str,
        permissions: frozenset[str],
        actor_sub: str,
        correlation_id: str | None,
    ) -> RoleTemplate:
        key = (scope_type, tenant_id, role_key)
        previous = self._rows.get(key)
        now = datetime.now(timezone.utc)
        row = RoleTemplate(
            scope_type=scope_type,
            tenant_id=tenant_id,
            role_key=role_key,
            permissions=permissions,
            version=1 if previous is None else previous.version + 1,
            updated_by=actor_sub,
            updated_at=now,
        )
        self._rows[key] = row
        self.audit_events.append(
            RoleTemplateAuditEvent(
                scope_type=scope_type,
                tenant_id=tenant_id,
                role_key=role_key,
                previous_permissions=frozenset() if previous is None else previous.permissions,
                new_permissions=permissions,
                actor_sub=actor_sub,
                correlation_id=correlation_id,
                changed_at=now,
            )
        )
        return row


class PostgresRoleTemplateStore:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url

    def get(self, scope_type: str, tenant_id: str | None, role_key: str) -> RoleTemplate | None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT scope_type, tenant_id, role_key, permissions, version, updated_by, updated_at
                FROM security_role_templates
                WHERE scope_type = %s AND tenant_id = %s AND role_key = %s
                """,
                (scope_type, tenant_id or "", role_key),
            )
            row = cur.fetchone()
        return None if row is None else _role_template_from_row(row)

    def list(self, scope_type: str, tenant_id: str | None) -> list[RoleTemplate]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT scope_type, tenant_id, role_key, permissions, version, updated_by, updated_at
                FROM security_role_templates
                WHERE scope_type = %s AND tenant_id = %s
                ORDER BY role_key
                """,
                (scope_type, tenant_id or ""),
            )
            rows = cur.fetchall()
        return [_role_template_from_row(row) for row in rows]

    def upsert(
        self,
        *,
        scope_type: str,
        tenant_id: str | None,
        role_key: str,
        permissions: frozenset[str],
        actor_sub: str,
        correlation_id: str | None,
    ) -> RoleTemplate:
        tenant_key = tenant_id or ""
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT permissions, version
                FROM security_role_templates
                WHERE scope_type = %s AND tenant_id = %s AND role_key = %s
                FOR UPDATE
                """,
                (scope_type, tenant_key, role_key),
            )
            previous = cur.fetchone()
            previous_permissions = frozenset(previous[0]) if previous is not None else frozenset()
            version = 1 if previous is None else int(previous[1]) + 1
            permission_list = sorted(permissions)
            cur.execute(
                """
                INSERT INTO security_role_templates
                    (scope_type, tenant_id, role_key, permissions, version, updated_by, updated_at)
                VALUES (%s, %s, %s, %s::jsonb, %s, %s, now())
                ON CONFLICT (scope_type, tenant_id, role_key)
                DO UPDATE SET
                    permissions = EXCLUDED.permissions,
                    version = EXCLUDED.version,
                    updated_by = EXCLUDED.updated_by,
                    updated_at = now()
                RETURNING scope_type, tenant_id, role_key, permissions, version, updated_by, updated_at
                """,
                (
                    scope_type,
                    tenant_key,
                    role_key,
                    json.dumps(permission_list),
                    version,
                    actor_sub,
                ),
            )
            updated = cur.fetchone()
            cur.execute(
                """
                INSERT INTO security_role_template_audit
                    (scope_type, tenant_id, role_key, previous_permissions, new_permissions,
                     actor_sub, correlation_id, changed_at)
                VALUES (%s, %s, %s, %s::jsonb, %s::jsonb, %s, %s, now())
                """,
                (
                    scope_type,
                    tenant_key,
                    role_key,
                    json.dumps(sorted(previous_permissions)),
                    json.dumps(permission_list),
                    actor_sub,
                    correlation_id,
                ),
            )
            conn.commit()
        if updated is None:
            raise RuntimeError("role-template upsert did not return a row")
        return _role_template_from_row(updated)

    def _connect(self):
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - installation/runtime guard
            raise RuntimeError("psycopg is required for PostgreSQL role-template storage") from exc
        return psycopg.connect(self.database_url)


class RoleTemplateService:
    def __init__(self, store: RoleTemplateStore) -> None:
        self.store = store

    def seed_platform_defaults(self) -> list[RoleTemplate]:
        rows: list[RoleTemplate] = []
        for role_key, permissions in DEFAULT_OPERATIONAL_ROLE_PERMISSIONS.items():
            existing = self.store.get("PLATFORM", None, role_key)
            rows.append(
                existing
                if existing is not None
                else self.store.upsert(
                    scope_type="PLATFORM",
                    tenant_id=None,
                    role_key=role_key,
                    permissions=permissions,
                    actor_sub="SYSTEM",
                    correlation_id=None,
                )
            )
        return sorted(rows, key=lambda row: row.role_key)

    def seed_tenant(
        self,
        *,
        tenant_id: str,
        actor_sub: str,
        correlation_id: str | None,
        replace: bool = False,
    ) -> list[RoleTemplate]:
        platform_defaults = {row.role_key: row for row in self.seed_platform_defaults()}
        rows: list[RoleTemplate] = []
        for role_key in sorted(OPERATIONAL_ROLES):
            existing = self.store.get("TENANT", tenant_id, role_key)
            if existing is not None and not replace:
                rows.append(existing)
                continue
            rows.append(
                self.store.upsert(
                    scope_type="TENANT",
                    tenant_id=tenant_id,
                    role_key=role_key,
                    permissions=platform_defaults[role_key].permissions,
                    actor_sub=actor_sub,
                    correlation_id=correlation_id,
                )
            )
        return rows

    def list_platform(self) -> list[RoleTemplate]:
        self.seed_platform_defaults()
        return self.store.list("PLATFORM", None)

    def list_tenant(self, tenant_id: str) -> list[RoleTemplate]:
        return self.seed_tenant(
            tenant_id=tenant_id,
            actor_sub="SYSTEM_FALLBACK_SEED",
            correlation_id=None,
            replace=False,
        )

    def update_platform(
        self,
        *,
        role_key: str,
        permissions: frozenset[str],
        actor_sub: str,
        correlation_id: str | None,
    ) -> RoleTemplate:
        _validate_operational_template(role_key, permissions)
        return self.store.upsert(
            scope_type="PLATFORM",
            tenant_id=None,
            role_key=role_key,
            permissions=permissions,
            actor_sub=actor_sub,
            correlation_id=correlation_id,
        )

    def update_tenant(
        self,
        *,
        tenant_id: str,
        role_key: str,
        permissions: frozenset[str],
        actor_sub: str,
        correlation_id: str | None,
    ) -> RoleTemplate:
        _validate_operational_template(role_key, permissions)
        self.seed_tenant(
            tenant_id=tenant_id,
            actor_sub="SYSTEM_FALLBACK_SEED",
            correlation_id=None,
            replace=False,
        )
        return self.store.upsert(
            scope_type="TENANT",
            tenant_id=tenant_id,
            role_key=role_key,
            permissions=permissions,
            actor_sub=actor_sub,
            correlation_id=correlation_id,
        )

    def permissions_for_role(self, tenant_id: str, role_key: str) -> frozenset[str] | None:
        admin_permissions = SECURITY_ADMIN_ROLE_PERMISSIONS.get(role_key)
        if admin_permissions is not None:
            return admin_permissions
        if role_key not in OPERATIONAL_ROLES:
            return None
        tenant = self.store.get("TENANT", tenant_id, role_key)
        if tenant is not None:
            return tenant.permissions
        platform = self.store.get("PLATFORM", None, role_key)
        if platform is not None:
            return platform.permissions
        return DEFAULT_OPERATIONAL_ROLE_PERMISSIONS[role_key]


def _validate_operational_template(role_key: str, permissions: frozenset[str]) -> None:
    if role_key not in OPERATIONAL_ROLES:
        raise UnknownRoleTemplate(role_key)
    forbidden = permissions.intersection(FORBIDDEN_OPERATIONAL_PERMISSIONS)
    security_permissions = {permission for permission in permissions if permission.startswith("security.")}
    unknown = permissions - EDITABLE_OPERATIONAL_PERMISSIONS
    if forbidden or security_permissions or unknown:
        invalid = sorted(forbidden | security_permissions | unknown)
        raise InvalidRoleTemplate(f"invalid operational permissions: {', '.join(invalid)}")


def _role_template_from_row(row) -> RoleTemplate:
    scope_type, tenant_id, role_key, permissions, version, updated_by, updated_at = row
    return RoleTemplate(
        scope_type=str(scope_type),
        tenant_id=None if tenant_id in (None, "") else str(tenant_id),
        role_key=str(role_key),
        permissions=frozenset(permissions),
        version=int(version),
        updated_by=str(updated_by),
        updated_at=updated_at,
    )
