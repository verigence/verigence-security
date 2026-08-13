from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from verigence_security.api.module_catalog_schemas import (
    ModuleCatalogPutRequest,
    ModuleCatalogResponse,
    ModuleSummaryResponse,
)
from verigence_security.api.platform_dependencies import (
    platform_session,
    require_platform_permission,
)
from verigence_security.repositories.module_catalog_repository import ModuleCatalogRepository
from verigence_security.services.module_catalog import (
    CatalogInput,
    ModuleCatalogError,
    ModuleCatalogService,
    PermissionInput,
    PermissionRetirementConflict,
    RoleTemplateInput,
)

router = APIRouter(prefix="/security/v1/platform/modules", tags=["Platform Module Catalogue"])


@router.get("", response_model=list[ModuleSummaryResponse])
def list_modules(
    claims: dict[str, Any] = Depends(require_platform_permission("security.module.read")),
    session: Session = Depends(platform_session),
) -> list[dict[str, object]]:
    _ = claims
    return ModuleCatalogService(ModuleCatalogRepository(session)).list_modules()


@router.get("/{moduleKey}", response_model=ModuleCatalogResponse)
def get_module(
    moduleKey: str,
    claims: dict[str, Any] = Depends(require_platform_permission("security.module.read")),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    _ = claims
    catalog = ModuleCatalogService(ModuleCatalogRepository(session)).get_catalog(moduleKey.lower())
    if catalog is None:
        raise HTTPException(status_code=404, detail="Module not found")
    return catalog


@router.put("/{moduleKey}/catalog", response_model=ModuleCatalogResponse)
def put_module_catalog(
    moduleKey: str,
    body: ModuleCatalogPutRequest,
    request: Request,
    claims: dict[str, Any] = Depends(require_platform_permission("security.module.manage")),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    service = ModuleCatalogService(ModuleCatalogRepository(session))
    try:
        return service.put_catalog(
            actor_user_id=str(claims["sub"]),
            correlation_id=request.state.correlation_id,
            path_module_key=moduleKey,
            catalog=CatalogInput(
                module_key=body.moduleKey,
                module_name=body.moduleName,
                catalog_version=body.catalogVersion,
                permissions=tuple(
                    PermissionInput(
                        key=item.key,
                        name=item.name,
                        description=item.description,
                        status=item.status,
                    )
                    for item in body.permissions
                ),
                role_templates=tuple(
                    RoleTemplateInput(
                        key=item.key,
                        name=item.name,
                        description=item.description,
                        status=item.status,
                        permissions=tuple(item.permissions),
                    )
                    for item in body.roleTemplates
                ),
            ),
        )
    except PermissionRetirementConflict as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "permissionKey": exc.permission_key,
                "affectedRoles": [
                    {
                        "tenantId": str(row["tenant_id"]),
                        "roleId": str(row["role_id"]),
                        "roleKey": str(row["role_key"]),
                        "roleName": str(row["role_name"]),
                    }
                    for row in exc.affected_roles
                ],
            },
        ) from exc
    except ModuleCatalogError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
