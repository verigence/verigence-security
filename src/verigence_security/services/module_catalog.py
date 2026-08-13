from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime

from verigence_security.repositories.module_catalog_repository import ModuleCatalogRepository
from verigence_security.services.permissions import is_canonical_permission

_ALLOWED_LIFECYCLE = {"ACTIVE", "DEPRECATED", "RETIRED"}


class ModuleCatalogError(ValueError):
    pass


class PermissionRetirementConflict(ModuleCatalogError):
    def __init__(self, permission_key: str, affected_roles: list[dict[str, object]]) -> None:
        super().__init__(f"Permission {permission_key} is referenced by effective Tenant roles")
        self.permission_key = permission_key
        self.affected_roles = affected_roles


@dataclass(frozen=True, slots=True)
class PermissionInput:
    key: str
    name: str
    description: str | None = None
    status: str = "ACTIVE"


@dataclass(frozen=True, slots=True)
class RoleTemplateInput:
    key: str
    name: str
    permissions: tuple[str, ...]
    description: str | None = None
    status: str = "ACTIVE"


@dataclass(frozen=True, slots=True)
class CatalogInput:
    module_key: str
    module_name: str
    catalog_version: str
    permissions: tuple[PermissionInput, ...]
    role_templates: tuple[RoleTemplateInput, ...]


class ModuleCatalogService:
    def __init__(self, repository: ModuleCatalogRepository) -> None:
        self.repository = repository

    def list_modules(self) -> list[dict[str, object]]:
        return [self._summary(row) for row in self.repository.modules()]

    def get_catalog(self, module_key: str) -> dict[str, object] | None:
        module = self.repository.module(module_key)
        if module is None:
            return None
        return self._catalog_response(module_key, module)

    def put_catalog(
        self,
        *,
        actor_user_id: str,
        correlation_id: str,
        path_module_key: str,
        catalog: CatalogInput,
    ) -> dict[str, object]:
        module_key = path_module_key.strip().lower()
        self._validate_catalog(module_key, catalog)
        now = datetime.now(UTC)
        try:
            self.repository.upsert_module(
                module_key=module_key,
                module_name=catalog.module_name.strip(),
                catalog_version=catalog.catalog_version.strip(),
                actor_user_id=actor_user_id,
                now=now,
            )
            for permission in catalog.permissions:
                existing = self.repository.permission(permission.key)
                if existing is not None and str(existing["module_key"]) != module_key:
                    raise ModuleCatalogError(
                        f"Permission {permission.key} is owned by another module"
                    )
                if permission.status == "RETIRED":
                    affected = self.repository.effective_role_references(permission.key)
                    if affected:
                        raise PermissionRetirementConflict(permission.key, affected)
                parts = permission.key.split(".")
                self.repository.upsert_permission(
                    permission_key=permission.key,
                    module_key=module_key,
                    resource_key=".".join(parts[1:-1]),
                    action_key=parts[-1],
                    display_name=permission.name.strip(),
                    description=permission.description,
                    status=permission.status,
                    catalog_version=catalog.catalog_version.strip(),
                    now=now,
                )

            for template in catalog.role_templates:
                template_id = self.repository.upsert_template(
                    module_key=module_key,
                    template_key=template.key,
                    template_name=template.name.strip(),
                    description=template.description,
                    catalog_version=catalog.catalog_version.strip(),
                    status=template.status,
                    now=now,
                )
                self.repository.replace_template_permissions(
                    template_id=template_id,
                    permission_keys=tuple(sorted(set(template.permissions))),
                    now=now,
                )

            response = self._catalog_response(
                module_key,
                self.repository.module(module_key) or {},
            )
            self.repository.insert_admin_change(
                correlation_id=correlation_id,
                actor_user_id=actor_user_id,
                operation_key="security.module.catalog.put",
                resource_id=module_key,
                after_state_json=json.dumps(response, default=str, sort_keys=True),
                now=now,
            )
            self.repository.commit()
            return response
        except Exception:
            self.repository.rollback()
            raise

    def _validate_catalog(self, module_key: str, catalog: CatalogInput) -> None:
        if not module_key or catalog.module_key.strip().lower() != module_key:
            raise ModuleCatalogError("Path moduleKey must match request moduleKey")
        if not catalog.module_name.strip():
            raise ModuleCatalogError("moduleName is required")
        if not catalog.catalog_version.strip():
            raise ModuleCatalogError("catalogVersion is required")

        permission_keys = [permission.key for permission in catalog.permissions]
        if len(permission_keys) != len(set(permission_keys)):
            raise ModuleCatalogError("Duplicate permission keys are not allowed")
        submitted_permissions = set(permission_keys)
        for permission in catalog.permissions:
            self._validate_permission(module_key, permission)

        template_keys = [template.key for template in catalog.role_templates]
        if len(template_keys) != len(set(template_keys)):
            raise ModuleCatalogError("Duplicate module role-template keys are not allowed")
        for template in catalog.role_templates:
            if not template.key.startswith(f"{module_key}."):
                raise ModuleCatalogError(
                    f"Template {template.key} does not belong to module {module_key}"
                )
            if template.status not in _ALLOWED_LIFECYCLE:
                raise ModuleCatalogError(f"Invalid template status {template.status}")
            if len(template.permissions) != len(set(template.permissions)):
                raise ModuleCatalogError(
                    f"Template {template.key} contains duplicate permissions"
                )
            for permission_key in template.permissions:
                if not permission_key.startswith(f"{module_key}."):
                    raise ModuleCatalogError(
                        f"Template {template.key} references another module namespace"
                    )
                if permission_key not in submitted_permissions:
                    existing = self.repository.permission(permission_key)
                    if existing is None or str(existing["module_key"]) != module_key:
                        raise ModuleCatalogError(
                            f"Template {template.key} references unregistered permission "
                            f"{permission_key}"
                        )
                    if str(existing["status"]) != "ACTIVE":
                        raise ModuleCatalogError(
                            f"Template {template.key} references non-ACTIVE permission "
                            f"{permission_key}"
                        )
                else:
                    submitted = next(p for p in catalog.permissions if p.key == permission_key)
                    if submitted.status != "ACTIVE":
                        raise ModuleCatalogError(
                            f"Template {template.key} references non-ACTIVE permission "
                            f"{permission_key}"
                        )

    @staticmethod
    def _validate_permission(module_key: str, permission: PermissionInput) -> None:
        if not is_canonical_permission(permission.key):
            raise ModuleCatalogError(f"Invalid canonical permission {permission.key}")
        if not permission.key.startswith(f"{module_key}."):
            raise ModuleCatalogError(
                f"Permission {permission.key} does not belong to module {module_key}"
            )
        if not permission.name.strip():
            raise ModuleCatalogError(f"Permission {permission.key} requires a name")
        if permission.status not in _ALLOWED_LIFECYCLE:
            raise ModuleCatalogError(f"Invalid permission status {permission.status}")

    def _catalog_response(
        self,
        module_key: str,
        module: dict[str, object],
    ) -> dict[str, object]:
        return {
            "moduleKey": module_key,
            "moduleName": module.get("module_name"),
            "catalogVersion": module.get("catalog_version"),
            "status": module.get("status"),
            "permissions": [
                {
                    "key": row["permission_key"],
                    "name": row["display_name"],
                    "description": row["description"],
                    "status": row["status"],
                    "catalogVersion": row["catalog_version"],
                }
                for row in self.repository.module_permissions(module_key)
            ],
            "roleTemplates": [
                {
                    "key": row["template_key"],
                    "name": row["template_name"],
                    "description": row["description"],
                    "status": row["status"],
                    "catalogVersion": row["catalog_version"],
                    "permissions": list(row["permission_keys"]),
                }
                for row in self.repository.module_templates(module_key)
            ],
        }

    @staticmethod
    def _summary(row: dict[str, object]) -> dict[str, object]:
        return {
            "moduleKey": row["module_key"],
            "moduleName": row["module_name"],
            "catalogVersion": row["catalog_version"],
            "status": row["status"],
        }
