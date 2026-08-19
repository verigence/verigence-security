from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from verigence_security.api.module_catalog_schemas import (
    ModuleCatalogPutRequest,
    ModuleCatalogResponse,
    ModulePermissionResponse,
    ModuleSummaryResponse,
)
from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.core.errors import security_error
from verigence_security.repositories.v2_module_catalog_repository import (
    V2AwareModuleCatalogRepository,
)
from verigence_security.services.module_catalog import (
    CatalogInput,
    ModuleCatalogError,
    ModuleCatalogService,
    PermissionInput,
    PermissionRetirementConflict,
    RoleTemplateInput,
)
from verigence_security.services.v2_human_actor import HumanActorContext

router = APIRouter(prefix="/security/v1/platform/modules", tags=["Platform Module Catalogue"])


def _require_super_admin(actor: HumanActorContext) -> None:
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")


def _require_admin(actor: HumanActorContext) -> None:
    if not actor.has_admin_classification:
        raise security_error("PERMISSION_DENIED")


@router.get("", response_model=list[ModuleSummaryResponse])
def list_modules(
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> list[dict[str, object]]:
    _ = actor
    return ModuleCatalogService(V2AwareModuleCatalogRepository(session)).list_modules()


@router.get("/{moduleKey}", response_model=ModuleCatalogResponse)
def get_module(
    moduleKey: str,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    _ = actor
    catalog = ModuleCatalogService(V2AwareModuleCatalogRepository(session)).get_catalog(
        moduleKey.lower()
    )
    if catalog is None:
        raise HTTPException(status_code=404, detail="Module not found")
    return catalog


@router.get("/{moduleKey}/permissions", response_model=list[ModulePermissionResponse])
def list_module_permissions(
    moduleKey: str,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> list[dict[str, object]]:
    _require_admin(actor)
    catalog = ModuleCatalogService(V2AwareModuleCatalogRepository(session)).get_catalog(
        moduleKey.lower()
    )
    if catalog is None:
        raise HTTPException(status_code=404, detail="Module not found")
    return list(catalog["permissions"])  # type: ignore[arg-type]


@router.put("/{moduleKey}/catalog", response_model=ModuleCatalogResponse)
def put_module_catalog(
    moduleKey: str,
    body: ModuleCatalogPutRequest,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    _require_super_admin(actor)
    service = ModuleCatalogService(V2AwareModuleCatalogRepository(session))
    try:
        return service.put_catalog(
            actor_user_id=actor.user_id,
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
