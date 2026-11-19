from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from verigence_security.core.errors import SecurityError
from verigence_security.services.app_version_policy import (
    AppVersionPolicyService,
    Policy,
    ProjectPolicy,
    can_show_update_page,
    is_native_app,
    parse_version,
    require_project_app,
    require_project_device,
    require_supported_app,
    require_supported_device,
    update_notice,
)

NOW = datetime(2026, 11, 5, 10, 0, tzinfo=UTC)


class _Session:
    """Answers the policy read and, optionally, the stored device read."""

    def __init__(self, policy: tuple | None, device: tuple | None = None, fail: bool = False) -> None:
        self.policy = policy
        self.device = device
        self.fail = fail

    def execute(self, statement, params=None):
        if self.fail:
            raise RuntimeError("database unavailable")
        sql = str(statement)
        row = self.policy if "app_version_policy" in sql else self.device
        return SimpleNamespace(first=lambda: row)


def _policy(minimum="1.5.0", effective=None) -> tuple:
    return (minimum, effective, "https://example.test/apps")


def test_versions_compare_as_numbers_not_text():
    assert parse_version("1.10.0") > parse_version("1.9.9")
    assert parse_version("1.5") is None and parse_version("") is None and parse_version(None) is None
    p = Policy("1.5.0", None, "")
    assert p.too_old("1.4.0") and p.too_old("0.1.0") and p.too_old(None) and p.too_old("garbage")
    assert not p.too_old("1.5.0") and not p.too_old("1.10.0") and not p.too_old("2.0.0")


def test_only_the_native_app_is_checked():
    assert is_native_app(browser_name="Capacitor WebView", app_version=None)
    assert is_native_app(browser_name=None, app_version="1.4.0")
    assert not is_native_app(browser_name="Chrome", app_version=None)
    # a web browser passes whatever the policy says
    require_supported_app(_Session(_policy()), browser_name="Firefox", app_version=None, now=NOW)


def test_an_old_app_that_cannot_show_the_update_page_is_refused_with_where_to_get_the_latest():
    for version in ("0.1.0", "1.0.0", None):
        with pytest.raises(SecurityError) as refused:
            require_supported_app(
                _Session(_policy()), browser_name="Capacitor WebView", app_version=version, now=NOW
            )
        assert refused.value.code == "APP_UPDATE_REQUIRED" and refused.value.status_code == 426
        assert "1.5.0 or newer" in refused.value.detail
        assert "https://example.test/apps" in refused.value.detail
    require_supported_app(
        _Session(_policy()), browser_name="Capacitor WebView", app_version="1.5.0", now=NOW
    )


def test_an_old_app_that_can_show_the_update_page_signs_in_and_is_shown_it():
    assert can_show_update_page("1.1.0") and can_show_update_page("1.4.0")
    assert not can_show_update_page("1.0.0") and not can_show_update_page(None)
    require_supported_app(
        _Session(_policy()), browser_name="Capacitor WebView", app_version="1.4.0", now=NOW
    )
    policy = Policy("1.5.1", None, "https://example.test/apps")
    for version in ("1.4.0", "1.5.0", None):
        notice = update_notice(policy, version, NOW)
        assert notice is not None and notice["kind"] == "MAINTENANCE" and notice["active"]
        assert "https://example.test/apps" in notice["body"] and "1.5.1" in notice["body"]
    assert update_notice(policy, "1.5.1", NOW) is None
    assert update_notice(Policy(None, None, "x"), "0.1.0", NOW) is None
    later = Policy("1.5.1", NOW + timedelta(hours=1), "x")
    assert update_notice(later, "1.4.0", NOW) is None


def test_nothing_is_refused_before_the_effective_time_or_without_a_minimum():
    later = NOW + timedelta(days=2)
    require_supported_app(
        _Session(_policy(effective=later)), browser_name="Capacitor WebView", app_version="1.0.0", now=NOW
    )
    with pytest.raises(SecurityError):
        require_supported_app(
            _Session(_policy(effective=later)),
            browser_name="Capacitor WebView",
            app_version="1.0.0",
            now=later,
        )
    require_supported_app(
        _Session(_policy(minimum=None)), browser_name="Capacitor WebView", app_version="0.1.0", now=NOW
    )


def test_an_unreadable_policy_never_breaks_sign_in():
    require_supported_app(
        _Session(None, fail=True), browser_name="Capacitor WebView", app_version="0.1.0", now=NOW
    )


def test_session_renewal_uses_the_device_recorded_at_sign_in():
    with pytest.raises(SecurityError):
        require_supported_device(
            _Session(_policy(), device=("Capacitor WebView", "0.1.0")), user_id="u", device_id="d"
        )
    require_supported_device(_Session(_policy(), device=("Chrome", None)), user_id="u", device_id="d")
    require_supported_device(_Session(_policy(), device=None), user_id="u", device_id="d")


# ---- a minimum for one Project (product owner, 19 Nov 2026) -----------------------------------------

MAHINDRA = "00000000-0000-4000-8000-0000000000a1"
HYUNDAI = "00000000-0000-4000-8000-0000000000a2"


class _ProjectSession:
    """A person's Projects with a minimum (what the service's read returns for them), the policy for
    everyone and, optionally, the stored device."""

    def __init__(self, projects: list[tuple], device: tuple | None = None, fail: bool = False) -> None:
        self.projects = projects
        self.device = device
        self.fail = fail
        self.savepoints = 0

    def begin_nested(self):
        session = self

        class _Savepoint:
            def __enter__(self):
                session.savepoints += 1

            def __exit__(self, *exc):
                return False

        return _Savepoint()

    def execute(self, statement, params=None):
        if self.fail:
            raise RuntimeError("database unavailable")
        sql = str(statement)
        if "app_version_project_policies" in sql:
            assert "user_tenant_operating_roles" in sql and "status = 'ACTIVE'" in sql
            return SimpleNamespace(all=lambda: self.projects)
        if "app_version_policy" in sql:
            return SimpleNamespace(first=lambda: ("1.7.0", None, "https://example.test/apps"))
        return SimpleNamespace(first=lambda: self.device)


def _project(minimum="1.9.0", effective=None, tenant=MAHINDRA, name="Mahindra Orissa") -> tuple:
    return (tenant, name, minimum, effective)


def test_a_project_minimum_refuses_the_old_app_of_its_people_with_where_to_get_the_latest():
    session = _ProjectSession([_project()])
    for version in ("1.7.0", "1.8.0", None):
        with pytest.raises(SecurityError) as refused:
            require_project_app(
                session, user_id="u", browser_name="Capacitor WebView", app_version=version, now=NOW
            )
        assert refused.value.code == "APP_UPDATE_REQUIRED" and refused.value.status_code == 426
        assert "Mahindra Orissa" in refused.value.detail and "1.9.0 or newer" in refused.value.detail
        assert "https://example.test/apps" in refused.value.detail
    for version in ("1.9.0", "1.10.0", "2.0.0"):
        require_project_app(session, user_id="u", browser_name="Capacitor WebView", app_version=version, now=NOW)
    assert session.savepoints  # read apart from the caller's own transaction


def test_people_of_other_projects_and_web_browsers_are_not_held_to_it():
    # The read returns only the Projects the person works in: none for a person of another Project.
    nobody = _ProjectSession([])
    require_project_app(nobody, user_id="u", browser_name="Capacitor WebView", app_version="1.0.0", now=NOW)
    # A browser passes whatever the Project says: that is where the new app is downloaded.
    held = _ProjectSession([_project()])
    require_project_app(held, user_id="u", browser_name="Chrome", app_version=None, now=NOW)


def test_a_project_minimum_waits_for_its_time_and_the_highest_one_in_force_holds():
    later = NOW + timedelta(hours=6)
    waiting = _ProjectSession([_project(effective=later)])
    require_project_app(waiting, user_id="u", browser_name="Capacitor WebView", app_version="1.7.0", now=NOW)
    with pytest.raises(SecurityError):
        require_project_app(
            waiting, user_id="u", browser_name="Capacitor WebView", app_version="1.7.0", now=later
        )
    # In two Projects: 1.10.0 is not in force yet, so 1.9.0 holds; then 1.10.0 does.
    two = _ProjectSession([_project(), _project("1.10.0", later, HYUNDAI, "Hyundai Orissa")])
    service = AppVersionPolicyService(two)  # type: ignore[arg-type]
    assert service.project_policy_for_user("u", NOW) == ProjectPolicy(MAHINDRA, "Mahindra Orissa", "1.9.0", None)
    held = service.project_policy_for_user("u", later)
    assert held is not None and (held.tenant_name, held.minimum_version) == ("Hyundai Orissa", "1.10.0")
    require_project_app(two, user_id="u", browser_name="Capacitor WebView", app_version="1.9.0", now=NOW)
    with pytest.raises(SecurityError) as refused:
        require_project_app(two, user_id="u", browser_name="Capacitor WebView", app_version="1.9.0", now=later)
    assert "Hyundai Orissa" in refused.value.detail and "1.10.0 or newer" in refused.value.detail


def test_an_unreadable_project_policy_never_breaks_sign_in():
    broken = _ProjectSession([], fail=True)
    require_project_app(broken, user_id="u", browser_name="Capacitor WebView", app_version="0.1.0", now=NOW)
    require_project_device(broken, user_id="u", device_id="d", now=NOW)


def test_session_renewal_holds_the_stored_device_to_the_project_minimum():
    old_app = _ProjectSession([_project()], device=("Capacitor WebView", "1.7.0"))
    with pytest.raises(SecurityError):
        require_project_device(old_app, user_id="u", device_id="d", now=NOW)
    require_project_device(
        _ProjectSession([_project()], device=("Capacitor WebView", "1.9.0")), user_id="u", device_id="d", now=NOW
    )
    require_project_device(_ProjectSession([_project()], device=("Chrome", None)), user_id="u", device_id="d", now=NOW)
    # A device not recorded yet is not judged here: sign-in and "keep me signed in" already did.
    require_project_device(_ProjectSession([_project()], device=None), user_id="u", device_id="d", now=NOW)


def test_a_project_minimum_must_be_a_version():
    with pytest.raises(ValueError, match="1.5.0"):
        AppVersionPolicyService(_ProjectSession([])).set_project_policy(  # type: ignore[arg-type]
            tenant_id=MAHINDRA, minimum_version="1.9", effective_from=None, actor_user_id="a", correlation_id="c"
        )
