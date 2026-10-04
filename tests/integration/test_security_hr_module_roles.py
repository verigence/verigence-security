from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.services.hr_module_roles import HrModuleRoleService

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)


def _url(url: str) -> str:
    for prefix in ("postgresql+asyncpg://", "postgresql://", "postgres://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url.removeprefix(prefix)
    return url


@pytest.fixture
def session() -> Iterator[Session]:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_url(TEST_DATABASE_URL), pool_pre_ping=True)
    conn = engine.connect()
    outer = conn.begin()
    db = Session(bind=conn, join_transaction_mode="create_savepoint")
    try:
        yield db
    finally:
        db.close()
        outer.rollback()
        conn.close()
        engine.dispose()


def _user(db: Session, status: str = "ACTIVE") -> str:
    user_id = str(uuid4())
    now = datetime.now(UTC)
    email = f"hr.{user_id[:8]}@example.test"
    db.execute(text("INSERT INTO security.security_principals VALUES (:i,'USER',:e,'ACTIVE',:n,:n)"),
               {"i": user_id, "e": email, "n": now})
    db.execute(
        text("INSERT INTO security.users (user_id,display_name,primary_email,status,created_at_utc,updated_at_utc)"
             " VALUES (:i,'HR Person',:e,:s,:n,:n)"),
        {"i": user_id, "e": email, "s": status, "n": now},
    )
    return user_id


def _rows(session: Session, sql: str, **params: object) -> set[tuple[object, ...]]:
    return {tuple(r) for r in session.execute(text(sql), params)}


def test_migration_created_the_hr_roles_and_grants(session: Session) -> None:
    roles = _rows(
        session,
        "SELECT role_key FROM security.module_roles WHERE module_key='hr' AND status='ACTIVE'",
    )
    assert roles == {("HRADMIN",), ("FINANCEADMIN",), ("CEO",)}
    grants = _rows(
        session,
        "SELECT role_key,permission_key FROM security.module_role_permissions"
        " WHERE module_key='hr' AND status='ACTIVE'",
    )
    assert ("FINANCEADMIN", "hr.employee.manage") not in grants
    assert ("FINANCEADMIN", "hr.employee.read") in grants
    assert ("HRADMIN", "hr.employee.manage") in grants and ("CEO", "hr.settings.manage") in grants


def test_assign_is_idempotent_audited_and_removable(session: Session) -> None:
    actor, user = _user(session), _user(session)
    service = HrModuleRoleService(session)
    changed, first = service.assign(user_id=user, role_key="HRADMIN", actor_user_id=actor, correlation_id="c1")
    again, same = service.assign(user_id=user, role_key="HRADMIN", actor_user_id=actor, correlation_id="c2")
    assert changed is True and again is False and same == first
    both, _ = service.assign(user_id=user, role_key="FINANCEADMIN", actor_user_id=actor, correlation_id="c3")
    assert both is True  # one person may hold several HR roles
    removed, _ = service.remove(user_id=user, role_key="HRADMIN", actor_user_id=actor, correlation_id="c4")
    assert removed is True
    left = _rows(
        session,
        "SELECT role_key FROM security.user_global_module_role_assignments"
        " WHERE user_id=:u AND module_key='hr' AND status='ACTIVE'",
        u=user,
    )
    assert left == {("FINANCEADMIN",)}
    audit = _rows(
        session,
        "SELECT count(*) FROM security.admin_change_records"
        " WHERE operation_key='security.hr_module_role.manage' AND resource_id=:u",
        u=user,
    )
    assert audit == {(3,)}


def test_inactive_user_and_unknown_role_are_refused(session: Session) -> None:
    actor = _user(session)
    service = HrModuleRoleService(session)
    suspended = _user(session, status="SUSPENDED")
    with pytest.raises(ValueError):
        service.assign(user_id=suspended, role_key="CEO", actor_user_id=actor, correlation_id="c")
    with pytest.raises(ValueError):
        service.assign(user_id=_user(session), role_key="ROOT", actor_user_id=actor, correlation_id="c")


def test_list_roles_shows_only_current_hr_roles_in_fixed_order(session: Session) -> None:
    actor, user = _user(session), _user(session)
    service = HrModuleRoleService(session)
    assert service.list_roles(user_id=user) == []
    service.assign(user_id=user, role_key="CEO", actor_user_id=actor, correlation_id="c1")
    service.assign(user_id=user, role_key="HRADMIN", actor_user_id=actor, correlation_id="c2")
    assert service.list_roles(user_id=user) == ["HRADMIN", "CEO"]
    service.remove(user_id=user, role_key="HRADMIN", actor_user_id=actor, correlation_id="c3")
    assert service.list_roles(user_id=user) == ["CEO"]
    with pytest.raises(ValueError):
        service.list_roles(user_id=str(uuid4()))


def test_phase2_grants_split_prepare_review_and_approve(session: Session) -> None:
    grants = _rows(
        session,
        "SELECT role_key,permission_key FROM security.module_role_permissions"
        " WHERE module_key='hr' AND status='ACTIVE'",
    )
    # Only the CEO approves a payroll run; HR prepares it, Finance cannot.
    assert ("CEO", "hr.payroll.approve") in grants
    assert ("HRADMIN", "hr.payroll.approve") not in grants
    assert ("FINANCEADMIN", "hr.payroll.approve") not in grants
    assert ("HRADMIN", "hr.payroll.prepare") in grants
    # Salary structures: HR proposes, Finance approves.
    assert ("HRADMIN", "hr.salary.propose") in grants and ("HRADMIN", "hr.salary.approve") not in grants
    assert ("FINANCEADMIN", "hr.salary.approve") in grants and ("FINANCEADMIN", "hr.salary.propose") not in grants
    # Claims above the threshold and exceptions are Finance's; routine ones are HR's.
    assert ("FINANCEADMIN", "hr.claim.review_finance") in grants
    assert ("HRADMIN", "hr.claim.review_finance") not in grants
    assert ("HRADMIN", "hr.claim.review") in grants
    # The CEO holds every HR permission.
    keys = {p for _, p in grants}
    assert {p for r, p in grants if r == "CEO"} == keys


def test_support_permission_exists_but_no_hr_role_holds_it(session: Session) -> None:
    # Feedback & Support tickets reach SuperAdmin only: SuperAdmin passes any active permission.
    active = _rows(
        session,
        "SELECT permission_key FROM security.permissions WHERE permission_key='hr.support.manage' AND status='ACTIVE'",
    )
    assert active == {("hr.support.manage",)}
    held = _rows(
        session,
        "SELECT role_key FROM security.module_role_permissions WHERE permission_key='hr.support.manage'",
    )
    assert held == set()


def test_housekeeping_permission_exists_but_no_hr_role_holds_it(session: Session) -> None:
    # Clearing old HR records is SuperAdmin's alone: it passes any active permission.
    active = _rows(
        session,
        "SELECT permission_key FROM security.permissions"
        " WHERE permission_key='hr.housekeeping.manage' AND status='ACTIVE'",
    )
    assert active == {("hr.housekeeping.manage",)}
    held = _rows(
        session,
        "SELECT role_key FROM security.module_role_permissions WHERE permission_key='hr.housekeeping.manage'",
    )
    assert held == set()
