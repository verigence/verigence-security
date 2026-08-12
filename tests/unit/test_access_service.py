from __future__ import annotations

from datetime import UTC, datetime, time, timedelta

import pytest

from verigence_security.adapters.identity import AuthenticatedIdentity
from verigence_security.adapters.network_risk import NetworkRiskResult
from verigence_security.core.errors import SecurityError, security_error
from verigence_security.core.types import GeoIntegrityStatus, GeoSource, VpnStatus
from verigence_security.repositories.security_repository import TenantPolicy, UserContext
from verigence_security.services.access_service import UserAccessService
from verigence_security.services.geo import GeoSample, LocationCandidate
from verigence_security.services.schedule import ScheduleWindow


class FakeNetwork:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def evaluate(self, source_ip: str, correlation_id: str) -> NetworkRiskResult:
        assert correlation_id == "corr-1"
        self.events.append("network")
        return NetworkRiskResult(VpnStatus.NOT_DETECTED)


class FakeTokenService:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.claims = None

    def issue(self, claims):
        self.claims = claims
        if self.fail:
            raise security_error("SIGNING_KEY_UNAVAILABLE")
        return "signed-token"


class FakeRepo:
    def __init__(self, *, active=None, permissions=None) -> None:
        self.events: list[str] = []
        self.active = active
        self.permissions = permissions or ["di.document.read"]
        self.committed = False
        self.rolled_back = False
        self.updated = None
        self.evaluation = None

    def tenant_status(self, tenant_id: str) -> str:
        self.events.append("tenant")
        return "ACTIVE"

    def resolve_identity_user(self, provider: str, provider_subject: str) -> str:
        return "user-1"

    def get_user_context(self, user_id: str, tenant_id: str, now: datetime) -> UserContext:
        return UserContext("user-1", "ACTIVE", "membership-1", "ACTIVE", 1)

    def get_tenant_policy(self, tenant_id: str) -> TenantPolicy:
        return TenantPolicy(
            max_active_devices_per_user=2,
            max_geo_accuracy_meters=50,
            max_geo_age_seconds=300,
            geo_revalidation_interval_seconds=3600,
            access_token_ttl_minutes=60,
            machine_token_ttl_minutes=30,
            session_idle_timeout_minutes=30,
            session_max_duration_minutes=20,
            vpn_detected_action="FLAG",
            vpn_unknown_action="FLAG",
            status="ACTIVE",
        )

    def lock_active_device(self, user_id: str, tenant_id: str, device_id: str):
        return {"status": "ACTIVE"}

    def assigned_locations(self, user_id: str, tenant_id: str, now: datetime):
        return [LocationCandidate("loc-1", 28.4595, 77.0266, 100, "UTC", "sched-1")]

    def ensure_active_schedule(self, tenant_id: str, schedule_id: str):
        return None

    def schedule_windows(self, tenant_id: str, schedule_id: str):
        today = datetime.now(UTC).isoweekday()
        return [ScheduleWindow(today, time(0, 0), time(0, 0), True)]

    def active_override_until(self, tenant_id: str, user_id: str, location_id: str, now: datetime):
        return None

    def effective_user_permissions(self, tenant_id: str, user_id: str, now: datetime):
        return ["PC"], self.permissions

    def expire_stale_user_sessions(
        self, tenant_id: str, user_id: str, device_id: str, now: datetime
    ):
        return None

    def active_user_session(self, tenant_id: str, user_id: str, device_id: str):
        return self.active

    def create_user_session(self, **kwargs):
        return "session-new"

    def update_reused_user_session(self, **kwargs):
        self.updated = kwargs

    def record_evaluation(self, payload):
        self.evaluation = payload

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


def _geo() -> GeoSample:
    return GeoSample(
        28.4595,
        77.0266,
        8,
        datetime.now(UTC),
        GeoSource.NATIVE,
        GeoIntegrityStatus.NORMAL,
    )


def _identity() -> AuthenticatedIdentity:
    return AuthenticatedIdentity("CLERK", "clerk-user", "clerk-session")


def test_network_provider_is_evaluated_before_database_transaction_work():
    repo = FakeRepo()
    network = FakeNetwork(repo.events)
    service = UserAccessService(repo, network, FakeTokenService())

    service.create_or_reuse(
        identity=_identity(),
        tenant_id="tenant-1",
        device_id="device-1",
        geo=_geo(),
        source_ip="203.0.113.10",
        correlation_id="corr-1",
    )

    assert repo.events[:2] == ["network", "tenant"]


def test_conflicting_active_location_is_rejected_and_rolled_back():
    now = datetime.now(UTC)
    repo = FakeRepo(
        active={
            "access_session_id": "existing",
            "location_id": "other-location",
            "started_at_utc": now,
        }
    )
    service = UserAccessService(repo, FakeNetwork(repo.events), FakeTokenService())

    with pytest.raises(SecurityError) as exc:
        service.create_or_reuse(
            identity=_identity(),
            tenant_id="tenant-1",
            device_id="device-1",
            geo=_geo(),
            source_ip="203.0.113.10",
            correlation_id="corr-1",
        )

    assert exc.value.code == "ACCESS_SESSION_CONTEXT_CONFLICT"
    assert repo.rolled_back
    assert not repo.committed


def test_reused_session_token_is_capped_by_original_session_maximum():
    started = datetime.now(UTC) - timedelta(minutes=10)
    repo = FakeRepo(
        active={
            "access_session_id": "existing",
            "location_id": "loc-1",
            "started_at_utc": started,
        }
    )
    tokens = FakeTokenService()
    service = UserAccessService(repo, FakeNetwork(repo.events), tokens)

    service.create_or_reuse(
        identity=_identity(),
        tenant_id="tenant-1",
        device_id="device-1",
        geo=_geo(),
        source_ip="203.0.113.10",
        correlation_id="corr-1",
    )

    assert tokens.claims is not None
    assert tokens.claims.expires_at <= started + timedelta(minutes=20)
    assert repo.updated is not None
    assert repo.updated["authorization_version"] == 1


def test_token_signing_failure_rolls_back_session_and_evidence():
    repo = FakeRepo()
    service = UserAccessService(repo, FakeNetwork(repo.events), FakeTokenService(fail=True))

    with pytest.raises(SecurityError) as exc:
        service.create_or_reuse(
            identity=_identity(),
            tenant_id="tenant-1",
            device_id="device-1",
            geo=_geo(),
            source_ip="203.0.113.10",
            correlation_id="corr-1",
        )

    assert exc.value.code == "SIGNING_KEY_UNAVAILABLE"
    assert repo.rolled_back
    assert not repo.committed


def test_legacy_permission_from_database_is_not_issued():
    repo = FakeRepo(permissions=["document:upload"])
    service = UserAccessService(repo, FakeNetwork(repo.events), FakeTokenService())

    with pytest.raises(ValueError):
        service.create_or_reuse(
            identity=_identity(),
            tenant_id="tenant-1",
            device_id="device-1",
            geo=_geo(),
            source_ip="203.0.113.10",
            correlation_id="corr-1",
        )

    assert repo.rolled_back
    assert not repo.committed


def test_user_access_response_matches_v13_access_token_response_shape():
    repo = FakeRepo()
    service = UserAccessService(repo, FakeNetwork(repo.events), FakeTokenService())

    result = service.create_or_reuse(
        identity=_identity(),
        tenant_id="tenant-1",
        device_id="device-1",
        geo=_geo(),
        source_ip="203.0.113.10",
        correlation_id="corr-1",
    )

    assert set(result) == {
        "accessSessionId",
        "accessToken",
        "expiresAtUtc",
        "actorType",
        "tenantId",
        "deviceId",
        "locationId",
        "roles",
        "permissions",
    }
    assert result["actorType"] == "USER"
