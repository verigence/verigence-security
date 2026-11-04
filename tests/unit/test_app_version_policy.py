from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from verigence_security.core.errors import SecurityError
from verigence_security.services.app_version_policy import (
    Policy,
    can_show_update_page,
    is_native_app,
    parse_version,
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
