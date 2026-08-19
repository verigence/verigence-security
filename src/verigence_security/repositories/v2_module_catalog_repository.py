from __future__ import annotations

from typing import Any

from sqlalchemy import text

from verigence_security.repositories.module_catalog_repository import ModuleCatalogRepository


class V2AwareModuleCatalogRepository(ModuleCatalogRepository):
    """Extend existing catalogue safety checks to the active v2 role-bundle model."""

    def effective_role_references(self, permission_key: str) -> list[dict[str, Any]]:
        references = list(super().effective_role_references(permission_key))

        # Tenant-specific v2 bundles are current runtime authorization configuration even
        # when no USER is presently assigned that role; retiring the permission would make
        # the configured role bundle invalid for the next assignment.
        references.extend(
            dict(row)
            for row in self.s.execute(
                text(
                    """
                    SELECT DISTINCT trp.tenant_id,
                           ('v2:' || trp.role_key) AS role_id,
                           trp.role_key,
                           rd.display_name AS role_name
                    FROM security.tenant_role_permissions trp
                    JOIN security.role_definitions rd ON rd.role_key=trp.role_key
                    WHERE trp.permission_key=:permission_key
                      AND rd.status='ACTIVE'
                    ORDER BY trp.tenant_id,trp.role_key
                    """
                ),
                {"permission_key": permission_key},
            ).mappings()
        )

        # Platform defaults are also protected: newly created Tenants inherit them.
        references.extend(
            dict(row)
            for row in self.s.execute(
                text(
                    """
                    SELECT 'PLATFORM' AS tenant_id,
                           ('default:' || d.role_key) AS role_id,
                           d.role_key,
                           rd.display_name AS role_name
                    FROM security.platform_role_permission_defaults d
                    JOIN security.role_definitions rd ON rd.role_key=d.role_key
                    WHERE d.permission_key=:permission_key
                      AND d.status='ACTIVE'
                      AND rd.status='ACTIVE'
                    ORDER BY d.role_key
                    """
                ),
                {"permission_key": permission_key},
            ).mappings()
        )

        # Deduplicate readable references while preserving the repository's established
        # affected-role response shape.
        result: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for row in references:
            key = (str(row["tenant_id"]), str(row["role_id"]), str(row["role_key"]))
            if key in seen:
                continue
            seen.add(key)
            result.append(row)
        return result
