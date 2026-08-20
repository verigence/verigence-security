from __future__ import annotations

from typing import Any

import pytest

from verigence_security.adapters.clerk_backend import ClerkBackendError
from verigence_security.services.phase1_self_onboarding import Phase1SelfOnboardingService
from verigence_security.services.uc001_self_onboarding import UC001SelfOnboardingService


class _Result:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows

    def mappings(self) -> list[dict[str, Any]]:
        return self.rows


class _ReleaseSession:
    def __init__(self) -> None:
        self.commits = 0
        self.statements: list[str] = []

    def execute(self, statement: object, params: dict[str, str]) -> _Result:
        assert params == {"email": "retry@example.com", "mobile": "+919876543210"}
        sql = str(statement)
        self.statements.append(sql)
        if "UPDATE security.platform_user_signup_attempts" in sql and "RETURNING" in sql:
            return _Result(
                [
                    {
                        "signup_attempt_id": "attempt-live",
                        "clerk_user_id": "user_old_live",
                    }
                ]
            )
        if "status IN ('CANCELLED','EXPIRED')" in sql:
            return _Result(
                [
                    {
                        "signup_attempt_id": "attempt-live",
                        "clerk_user_id": "user_old_live",
                    },
                    {
                        "signup_attempt_id": "attempt-orphan",
                        "clerk_user_id": "user_old_orphan",
                    },
                ]
            )
        raise AssertionError(f"Unexpected SQL: {sql}")

    def commit(self) -> None:
        self.commits += 1


class _FakeClerk:
    def __init__(self, failures: dict[str, int] | None = None) -> None:
        self.deleted: list[str] = []
        self.failures = failures or {}

    def delete_user(self, clerk_user_id: str) -> None:
        self.deleted.append(clerk_user_id)
        status = self.failures.get(clerk_user_id)
        if status is not None:
            raise ClerkBackendError("delete failed", status_code=status)


def test_restart_validates_complete_key_before_releasing_prior_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = UC001SelfOnboardingService(object())  # type: ignore[arg-type]
    order: list[str] = []

    monkeypatch.setattr(
        service,
        "_require_valid_onboarding_key",
        lambda supplied: order.append(f"key:{supplied}"),
    )
    monkeypatch.setattr(
        service,
        "_release_prior_attempts",
        lambda **kwargs: order.append(
            f"release:{kwargs['email']}:{kwargs['mobile']}"
        ),
    )

    def _base_start(_self: object, **kwargs: object) -> dict[str, str]:
        order.append(f"base:{kwargs['email']}:{kwargs['mobile']}")
        return {"status": "EMAIL_VERIFICATION_REQUIRED"}

    monkeypatch.setattr(Phase1SelfOnboardingService, "start", _base_start)

    result = service.start(
        first_name="Amit",
        last_name="Goyal",
        email=" Retry@Example.com ",
        mobile="98765 43210",
        password="password-is-transient",
        onboarding_key="VGN-8273105",
        source_ip="127.0.0.1",
        correlation_id="test-correlation",
        clerk=object(),  # type: ignore[arg-type]
    )

    assert result["status"] == "EMAIL_VERIFICATION_REQUIRED"
    assert order == [
        "key:VGN-8273105",
        "release:retry@example.com:+919876543210",
        "base:retry@example.com:+919876543210",
    ]


def test_restart_cancels_live_attempt_and_deduplicates_clerk_cleanup() -> None:
    session = _ReleaseSession()
    clerk = _FakeClerk()
    service = UC001SelfOnboardingService(session)  # type: ignore[arg-type]

    service._release_prior_attempts(  # noqa: SLF001 - targeted UC-001 contract test
        email="retry@example.com",
        mobile="+919876543210",
        clerk=clerk,  # type: ignore[arg-type]
    )

    assert session.commits == 1
    assert len(session.statements) == 2
    assert set(clerk.deleted) == {"user_old_live", "user_old_orphan"}
    assert len(clerk.deleted) == 2


def test_restart_treats_already_deleted_clerk_placeholder_as_clean() -> None:
    session = _ReleaseSession()
    clerk = _FakeClerk({"user_old_orphan": 404})
    service = UC001SelfOnboardingService(session)  # type: ignore[arg-type]

    service._release_prior_attempts(  # noqa: SLF001 - targeted UC-001 contract test
        email="retry@example.com",
        mobile="+919876543210",
        clerk=clerk,  # type: ignore[arg-type]
    )

    assert session.commits == 1
    assert set(clerk.deleted) == {"user_old_live", "user_old_orphan"}


def test_restart_surfaces_provider_cleanup_failure_after_db_release() -> None:
    session = _ReleaseSession()
    clerk = _FakeClerk({"user_old_live": 503})
    service = UC001SelfOnboardingService(session)  # type: ignore[arg-type]

    with pytest.raises(ClerkBackendError):
        service._release_prior_attempts(  # noqa: SLF001 - targeted UC-001 contract test
            email="retry@example.com",
            mobile="+919876543210",
            clerk=clerk,  # type: ignore[arg-type]
        )

    # The attempt is deliberately committed as CANCELLED before the network cleanup call. A later
    # retry will include CANCELLED rows and retry deletion instead of leaving the contact locked.
    assert session.commits == 1
