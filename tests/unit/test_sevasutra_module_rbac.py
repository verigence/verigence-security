"""The SevaSutra module and the ANALYST operating role, asserted where they are defined.

SevaSutra (workshop audit) runs with three roles: ANALYST (new) detects and documents, TL approves and
reports, PM governs and settles. Separation of duties is carried by the bundles: whoever raises an
observation never approves it, so ANALYST holds no approve permission.
"""
from __future__ import annotations

import re
from pathlib import Path

from verigence_security.api.v2_rbac_schemas import OperatingRoleKey

MIGRATION = Path("migrations/0052_sevasutra_module_rbac.sql")
CLIENT_MIGRATION = Path("migrations/0056_sevasutra_client_role.sql")
WORKFLOW = Path(".github/workflows/sevasutra-security-bind.yml")


def _bundle(role_key: str, migration: Path = MIGRATION) -> set[str]:
    match = re.search(rf"\('{role_key}',ARRAY\[(.*?)\]::varchar\[\]\)", migration.read_text(), re.DOTALL)
    assert match is not None, f"No {role_key} bundle in {migration.name}"
    return set(re.findall(r"'([a-z0-9._]+)'", match.group(1)))


def _catalogue() -> set[str]:
    source = MIGRATION.read_text().split("sevasutra_permissions(permission_key,resource_key,action_key) AS (", 1)[1]
    source = source.split("INSERT INTO security.permissions", 1)[0]
    return set(re.findall(r"\('(sevasutra\.[a-z.]+)','[a-z]+','[a-z]+'\)", source))


def test_analyst_is_an_assignable_operating_role() -> None:
    assert "ANALYST" in OperatingRoleKey.__args__
    from verigence_security.services.v2_rbac import OPERATING_ROLE_KEYS

    assert "ANALYST" in OPERATING_ROLE_KEYS


def test_analyst_is_defined_and_accepted_by_the_assignment_check() -> None:
    source = MIGRATION.read_text()
    assert "('ANALYST','OPERATING','Analyst','ACTIVE'" in source
    assert "DROP CONSTRAINT IF EXISTS user_tenant_operating_roles_role_key_check" in source
    assert "CHECK (role_key IN ('PC','TL','PM','CRM','Executive','REVIEWER','ANALYST'))" in source


def test_the_operating_role_check_accepts_an_active_analyst_role() -> None:
    from verigence_security.services.v2_rbac import OperatingRoleAssignmentService

    class _Repository:
        def role_definition(self, role_key: str) -> dict[str, str]:
            return {"status": "ACTIVE", "role_class": "OPERATING"}

    service = OperatingRoleAssignmentService.__new__(OperatingRoleAssignmentService)
    service.repository = _Repository()  # type: ignore[assignment]
    service._require_operating_role("ANALYST")


def test_every_bundle_grants_only_registered_sevasutra_permissions() -> None:
    catalogue = _catalogue()
    assert len(catalogue) == 16
    for role in ("ANALYST", "TL", "PM"):
        bundle = _bundle(role)
        assert bundle, role
        assert bundle <= catalogue, f"{role} grants unregistered {sorted(bundle - catalogue)}"
        assert all(key.startswith("sevasutra.") for key in bundle)


def test_whoever_raises_never_approves() -> None:
    analyst = _bundle("ANALYST")
    assert "sevasutra.observation.raise" in analyst
    assert "sevasutra.observation.approve" not in analyst
    assert "sevasutra.report.issue" not in analyst
    assert not {key for key in analyst if key.startswith("sevasutra.leakage.")}
    assert "sevasutra.settings.manage" not in analyst


def test_only_the_pm_settles_leakage_and_changes_thresholds() -> None:
    tl, pm = _bundle("TL"), _bundle("PM")
    assert "sevasutra.observation.approve" in tl and "sevasutra.observation.approve" in pm
    assert "sevasutra.leakage.verify" in tl
    for key in ("sevasutra.leakage.settle", "sevasutra.settings.manage", "sevasutra.benchmark.approve",
                "sevasutra.task.schedule", "sevasutra.team.manage"):
        assert key in pm, key
        assert key not in tl, key
    # The PM governs; capture stays on site.
    assert "sevasutra.evidence.upload" not in pm


def test_existing_projects_are_backfilled_with_sevasutra_permissions_only() -> None:
    backfill = MIGRATION.read_text().split("INSERT INTO security.tenant_role_permissions", 1)[1]
    assert "d.role_key IN ('ANALYST','TL','PM')" in backfill
    assert "d.permission_key LIKE 'sevasutra.%'" in backfill
    assert "ON CONFLICT (tenant_id,role_key,permission_key) DO NOTHING" in backfill


def test_the_binding_workflow_never_handles_the_plaintext_secret() -> None:
    source = WORKFLOW.read_text()
    assert "workflow_dispatch" in source
    # It runs on dev only when its own file changes (dispatch needs the file on main, which is not touched).
    trigger = source.split("permissions:", 1)[0]
    push = trigger.split("  push:", 1)[1].split("  workflow_dispatch:", 1)[0]
    assert push.split() == ["branches:", "-", "dev", "paths:", "-", ".github/workflows/sevasutra-security-bind.yml"]
    assert "SEVASUTRA_SECRET_HASH" in source
    assert "$argon2id$" in source
    assert "CLIENT_SECRET" not in source


# ---------------------------------------------------------------- client access (0056, 9 Nov 2026)


def test_client_is_an_assignable_operating_role() -> None:
    from verigence_security.services.v2_rbac import OPERATING_ROLE_KEYS

    assert "CLIENT" in OperatingRoleKey.__args__
    assert "CLIENT" in OPERATING_ROLE_KEYS
    source = CLIENT_MIGRATION.read_text()
    assert "('CLIENT','OPERATING','Client (analytics)','ACTIVE'" in source
    assert "CHECK (role_key IN ('PC','TL','PM','CRM','Executive','REVIEWER','ANALYST','CLIENT'))" in source


def test_a_client_sees_the_analytics_and_nothing_else() -> None:
    assert _bundle("CLIENT", CLIENT_MIGRATION) == {"sevasutra.project.read", "sevasutra.analytics.read"}
    assert _bundle("CLIENT", CLIENT_MIGRATION) <= _catalogue()


def test_existing_projects_are_backfilled_with_the_client_bundle_only() -> None:
    backfill = CLIENT_MIGRATION.read_text().split("INSERT INTO security.tenant_role_permissions", 1)[1]
    assert "d.role_key='CLIENT'" in backfill
    assert "ON CONFLICT (tenant_id,role_key,permission_key) DO NOTHING" in backfill


def test_super_admin_does_not_sign_off_in_sevasutra() -> None:
    from verigence_security.services.v2_authorization import SUPER_ADMIN_EXCLUDED_PERMISSIONS

    assert {"sevasutra.observation.approve", "sevasutra.leakage.settle"} <= SUPER_ADMIN_EXCLUDED_PERMISSIONS
    assert "sevasutra.analytics.read" not in SUPER_ADMIN_EXCLUDED_PERMISSIONS


# ---------------------------------------------------------------- Executive (0057, 9 Nov 2026)

EXECUTIVE_MIGRATION = Path("migrations/0057_sevasutra_executive.sql")


def test_the_executive_holds_the_pm_bundle() -> None:
    assert _bundle("Executive", EXECUTIVE_MIGRATION) == _bundle("PM")
    assert "sevasutra.evidence.upload" not in _bundle("Executive", EXECUTIVE_MIGRATION)


def test_existing_projects_are_backfilled_with_the_executive_sevasutra_bundle_only() -> None:
    backfill = EXECUTIVE_MIGRATION.read_text().split("INSERT INTO security.tenant_role_permissions", 1)[1]
    assert "d.role_key='Executive'" in backfill
    assert "d.permission_key LIKE 'sevasutra.%'" in backfill
    assert "ON CONFLICT (tenant_id,role_key,permission_key) DO NOTHING" in backfill
