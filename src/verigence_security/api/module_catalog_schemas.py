from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

LifecycleStatus = Literal["ACTIVE", "DEPRECATED", "RETIRED"]


class ModulePermissionInput(BaseModel):
    key: str = Field(min_length=3, max_length=180)
    name: str = Field(min_length=1, max_length=240)
    description: str | None = None
    status: LifecycleStatus = "ACTIVE"


class ModuleRoleTemplateInput(BaseModel):
    key: str = Field(min_length=3, max_length=180)
    name: str = Field(min_length=1, max_length=240)
    description: str | None = None
    status: LifecycleStatus = "ACTIVE"
    permissions: list[str]


class ModuleCatalogPutRequest(BaseModel):
    moduleKey: str = Field(min_length=1, max_length=40)
    moduleName: str = Field(min_length=1, max_length=240)
    catalogVersion: str = Field(min_length=1, max_length=40)
    permissions: list[ModulePermissionInput]
    roleTemplates: list[ModuleRoleTemplateInput]


class ModulePermissionResponse(BaseModel):
    key: str
    name: str | None
    description: str | None
    status: LifecycleStatus
    catalogVersion: str | None


class ModuleRoleTemplateResponse(BaseModel):
    key: str
    name: str
    description: str | None
    status: LifecycleStatus
    catalogVersion: str
    permissions: list[str]


class ModuleCatalogResponse(BaseModel):
    moduleKey: str
    moduleName: str
    catalogVersion: str
    status: str
    permissions: list[ModulePermissionResponse]
    roleTemplates: list[ModuleRoleTemplateResponse]


class ModuleSummaryResponse(BaseModel):
    moduleKey: str
    moduleName: str
    catalogVersion: str
    status: str


class RetirementConflictResponse(BaseModel):
    permissionKey: str
    affectedRoles: list[dict[str, str]]
