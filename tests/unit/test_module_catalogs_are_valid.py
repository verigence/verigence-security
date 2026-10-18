"""Every catalogue under `catalogs/` must satisfy the module-catalog rules.

A catalogue is registered by PUT /platform/modules/{moduleKey}/catalog, which
validates it there and then. Without this test a malformed catalogue is only
discovered when somebody tries to register it against a live tenant, and a
module's whole permission set and role templates fail together.

No database: validation of a self-contained catalogue -- every template
permission also submitted in the same catalogue -- never consults the
repository, so this runs in ordinary CI rather than only against Neon.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from verigence_security.services.module_catalog import (
    CatalogInput,
    ModuleCatalogService,
    PermissionInput,
    RoleTemplateInput,
)

CATALOGS = sorted(Path("catalogs").glob("*.json"))


class _NoRepository:
    """A template here may only use permissions the same catalogue submits."""

    @staticmethod
    def permission(permission_key: str) -> None:
        return None


def _catalog_input(raw: dict) -> CatalogInput:
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


def test_catalogs_directory_is_not_empty() -> None:
    assert CATALOGS, "No module catalogues found under catalogs/"


@pytest.mark.parametrize("path", CATALOGS, ids=lambda path: path.name)
def test_catalog_passes_registration_validation(path: Path) -> None:
    raw = json.loads(path.read_text())
    catalog = _catalog_input(raw)
    service = ModuleCatalogService(_NoRepository())
    service._validate_catalog(raw["moduleKey"], catalog)


@pytest.mark.parametrize("path", CATALOGS, ids=lambda path: path.name)
def test_catalog_filename_matches_its_module_and_version(path: Path) -> None:
    """`audit-v2.2.json` holds module `audit` at version `2.2`, so the file on
    disk cannot drift from what registering it would actually do."""
    raw = json.loads(path.read_text())
    assert path.stem == f"{raw['moduleKey']}-v{raw['catalogVersion']}"


def _audit_templates() -> dict[str, set[str]]:
    raw = json.loads(Path("catalogs/audit-v2.2.json").read_text())
    return {item["name"]: set(item["permissions"]) for item in raw["roleTemplates"]}


def test_audit_catalog_carries_the_six_operating_roles() -> None:
    """The operating roles Audit Core maps people to
    (AUDIT_CORE_DEFAULT_ROLE_BUNDLES_v1.1)."""
    assert set(_audit_templates()) == {"PC", "TL", "PM", "CRM", "REVIEWER", "EXECUTIVE"}


def test_reviewer_may_correct_a_value_but_not_upload_or_close_a_task() -> None:
    """REVIEWER differs from CRM by exactly one permission,
    `audit.journey.update`: a Reviewer corrects what Document Intelligence read
    wrongly, where CRM reads only.

    The limits are what the token withholds rather than a role-name check in
    Audit Core, so they are asserted here where the bundle is defined.
    """
    templates = _audit_templates()
    reviewer = templates["REVIEWER"]

    assert "audit.journey.read" in reviewer
    assert "audit.journey.update" in reviewer
    assert "audit.evidence.upload" not in reviewer
    assert not {key for key in reviewer if key.startswith("audit.work.")}
    assert not {key for key in reviewer if key.endswith(".verify")}

    assert reviewer - templates["CRM"] == {"audit.journey.update", "audit.master.read",
                                           "audit.evidence.refresh", "audit.analytics.read"}
    assert "audit.journey.update" not in templates["CRM"]


def test_executive_holds_every_audit_privilege() -> None:
    """Executive holds all audit privileges across the whole project (owner
    decision 2026-10-18), so its bundle is the module's permission set itself.

    Asserted against the catalogue's own permissions rather than a fixed list,
    so a permission added to the module and not to Executive fails here instead
    of quietly leaving Executive short of a privilege it is meant to have.
    """
    raw = json.loads(Path("catalogs/audit-v2.2.json").read_text())
    every_permission = {item["key"] for item in raw["permissions"]}
    templates = _audit_templates()

    assert templates["EXECUTIVE"] == every_permission
    for role, permissions in templates.items():
        assert permissions <= templates["EXECUTIVE"], f"{role} exceeds Executive"
