"""The REVIEWER operating role, asserted where it is defined.

A Reviewer reviews what a Process Consultant captured, across every Outlet
they are mapped to: opens each uploaded document, corrects values Document
Intelligence read wrongly, and marks a stage's documents reviewed.

What a Reviewer may *not* do is carried by the permissions the bundle
withholds, not by a role-name check inside Audit Core, so the limits are
asserted here against the migration that grants them.
"""
from __future__ import annotations

import re
from pathlib import Path

from verigence_security.api.v2_rbac_schemas import OperatingRoleKey

REVIEWER_MIGRATION = Path("migrations/0046_reviewer_operating_role.sql")
DEFAULTS_MIGRATION = Path("migrations/0013_v2_operating_role_defaults.sql")
FOUNDATION_MIGRATION = Path("migrations/0011_security_v2_role_foundation.sql")


def _bundle(migration: Path, role_key: str) -> set[str]:
    """The permission keys one role's ARRAY[...] bundle grants."""
    source = migration.read_text()
    match = re.search(
        rf"\('{role_key}',\s*ARRAY\[(.*?)\]::varchar\[\]\)",
        source,
        re.DOTALL,
    )
    assert match is not None, f"No {role_key} bundle found in {migration.name}"
    return set(re.findall(r"'([a-z0-9._]+)'", match.group(1)))


def test_reviewer_is_an_assignable_operating_role() -> None:
    assert "REVIEWER" in OperatingRoleKey.__args__


def test_reviewer_is_defined_as_an_operating_role() -> None:
    source = REVIEWER_MIGRATION.read_text()
    assert "('REVIEWER','OPERATING','Reviewer','ACTIVE'" in source


def test_an_operating_role_assignment_accepts_reviewer() -> None:
    """`user_tenant_operating_roles.role_key` carries a CHECK listing the
    allowed keys, so the role is rejected at the database until it is widened --
    whatever the bundles say."""
    foundation = FOUNDATION_MIGRATION.read_text()
    assert "CHECK (role_key IN ('PC','TL','PM','CRM','Executive'))" in foundation

    source = REVIEWER_MIGRATION.read_text()
    assert "DROP CONSTRAINT IF EXISTS user_tenant_operating_roles_role_key_check" in source
    assert (
        "CHECK (role_key IN ('PC','TL','PM','CRM','Executive','REVIEWER'))" in source
    )


def test_reviewer_may_correct_a_value_but_not_upload_or_close_a_task() -> None:
    reviewer = _bundle(REVIEWER_MIGRATION, "REVIEWER")

    assert "audit.journey.read" in reviewer
    assert "audit.journey.update" in reviewer
    assert "audit.evidence.read" in reviewer
    assert "audit.evidence.refresh" in reviewer

    # No upload, on either side of the boundary.
    assert "audit.evidence.upload" not in reviewer
    assert "di.document.upload" not in reviewer
    # No task queue, so no way to complete, cancel or close one.
    assert not {key for key in reviewer if key.startswith("audit.work.")}
    # Neither raises nor adjudicates findings, and verification stays with
    # TL/PM; the documents-reviewed marks are Audit Core journey state under
    # audit.journey.update, not a verification.
    assert not {key for key in reviewer if key.endswith(".verify")}
    assert "audit.finding.create" not in reviewer
    assert "audit.review.decide" not in reviewer
    assert "di.verification.write" not in reviewer


def test_reviewer_differs_from_crm_by_the_ability_to_correct() -> None:
    """CRM reads; a Reviewer corrects. `audit.journey.update` is the whole
    capability difference on the Audit Core side."""
    reviewer = _bundle(REVIEWER_MIGRATION, "REVIEWER")
    crm = _bundle(DEFAULTS_MIGRATION, "CRM")

    assert "audit.journey.update" in reviewer
    assert "audit.journey.update" not in crm

    audit_only = {key for key in reviewer - crm if key.startswith("audit.")}
    assert audit_only == {
        "audit.journey.update",
        "audit.master.read",
        "audit.evidence.refresh",
        "audit.analytics.read",
    }


def test_reviewer_grants_nothing_beyond_the_registered_catalogue() -> None:
    """Every permission a bundle grants must already be registered by 0013,
    which the migration also checks at apply time -- asserted here so a typo
    fails in CI rather than against a live database."""
    registered = set(re.findall(r"\('([a-z0-9._]+)','(?:audit|di)'", DEFAULTS_MIGRATION.read_text()))
    assert registered, "No registered permissions parsed from 0013"

    reviewer = _bundle(REVIEWER_MIGRATION, "REVIEWER")
    assert reviewer <= registered, f"Unregistered: {sorted(reviewer - registered)}"


def test_tenant_seeding_no_longer_hard_codes_the_operating_roles() -> None:
    """A new Project is seeded from every OPERATING role that has defaults.

    With the previous hard-coded list a Project created after 0046 would have
    been provisioned without REVIEWER, so a Reviewer would hold the role and
    resolve no permissions at all.
    """
    source = Path("src/verigence_security/services/platform_tenant_runtime.py").read_text()
    seeding = source.split("INSERT INTO security.tenant_role_permissions", 1)[1]
    assert "r.role_class='OPERATING'" in seeding
    assert "role_key IN ('PC','TL','PM','CRM','Executive')" not in seeding


def test_existing_tenants_are_backfilled() -> None:
    """Nothing re-seeds a Project that already holds its bundles, so without a
    backfill a Reviewer would work only in Projects created after 0046."""
    source = REVIEWER_MIGRATION.read_text()
    backfill = source.split("INSERT INTO security.tenant_role_permissions", 1)[1]
    assert "d.role_key='REVIEWER'" in backfill
    assert "ON CONFLICT (tenant_id,role_key,permission_key) DO NOTHING" in backfill
