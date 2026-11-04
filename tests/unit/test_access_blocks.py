from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from verigence_security.core.errors import SecurityError
from verigence_security.services.access_blocks import require_not_blocked


class _Session:
    def __init__(self, row=None, fail=False):
        self.row = row
        self.fail = fail

    def execute(self, statement, params=None):
        if self.fail:
            raise RuntimeError("database unavailable")
        return SimpleNamespace(first=lambda: self.row)


PAUSE = ("b1", "Approvals past the Monday 09:00 deadline", "hrmgmt", datetime(2026, 11, 9, 3, 30, tzinfo=UTC))


def test_a_paused_person_is_refused_with_a_plain_reason():
    with pytest.raises(SecurityError) as refused:
        require_not_blocked(_Session(PAUSE), user_id="u", is_super_admin=False)
    assert refused.value.code == "ACCESS_BLOCKED" and refused.value.status_code == 403
    assert "Monday 09:00" in refused.value.detail and "SuperAdmin" in refused.value.detail


def test_superadmin_and_people_without_a_pause_pass_and_an_unreadable_store_never_locks_out():
    require_not_blocked(_Session(PAUSE), user_id="u", is_super_admin=True)
    require_not_blocked(_Session(None), user_id="u", is_super_admin=False)
    require_not_blocked(_Session(fail=True), user_id="u", is_super_admin=False)
