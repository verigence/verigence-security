from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from verigence_security.adapters.network_risk import NetworkRiskResult
from verigence_security.core.errors import SecurityError
from verigence_security.core.types import (
    GeoIntegrityStatus,
    GeoSource,
    VpnStatus,
)
from verigence_security.repositories.security_repository import TenantPolicy, UserContext
from verigence_security.services.geo import GeoSample, LocationCandidate
from verigence_security.services.session_refresh_service import UserSessionRefreshService
from verigence_security.services.token_service import AccessTokenClaims


@dataclass
class FakeSecurityRepository:
    locations: list[LocationCandidate]
    evaluations: list[dict[str, Any]] = field(default_factory=list)

    def tenant_status(self, tenant_id: str) -> str:
        _ = tenant_id
        return "ACTIVE"

    def get_user_context(
        self,
        user_id: str,
        tenant_id: str,
        now: datetime,
    ) -> UserContext:
        _ = (tenant_id, now)
        return UserContext(
            user_id=user_id,
            user_status="ACTIVE",
            membership_id="membership-1",
            membership_status="ACTIVE",
            authorization_version=7,
        )

    def get_tenant_policy(self, tenant_id: str) -> TenantPolicy:
        _ = tenant_id
        return TenantPolicy(
            max_active_devices_per_user=2,
            max_geo_accuracy_meters=100,
            max_geo_age_seconds=300,
            geo_revalidation_interval_seconds=300,
            access_token_ttl_minutes=10,
            machine_token_ttl_minutes=10,
            session_idle_timeout_minutes=30,
            session_max_duration_minutes=60,
            vpn_detected_action="DENY",
            vpn_unknown_action="FLAG",
            status="ACTIVE",
        )

    def lock_active_device(
        self,
        user_id: str,
        tenant_id: str,
        device_id: str,
    ) -> dict[str, Any]:
        _ = (user_id, tenant_id)
        return {"device_id": device_id, "status": "ACTIVE"}

    def assigned_locations(
        self,
        user_id: str,
        tenant_id: str,
        now: datetime,
    ) -> list[LocationCandidate]:
        _ = (user_id, tenant_id, now)
        return self.locations

    def ensure_active_schedule(self, tenant_id: str, schedule_id: str) -> None:
        _ = (tenant_id, schedule_id)

    def schedule_windows(self, tenant_id: str, schedule_id: str) -> list[Any]:
        _ = (tenant_id, schedule_id)
        return []

    def active_override_until(
        self,
        tenant_id: str,
        user_id: str,
        location_id: str,
        now: datetime,
    ) -> datetime:
        _ = (tenant_id, user_id, location_id)
        return now + timedelta(minutes=20)

    def effective_user_permissions(
        self,
        tenant_id: str,
        user_id: str,
        now: datetime,
    ) -> tuple[list[str], list[str]]:
        _ = (tenant_id, user_id, now)
        return ["PROCESS_CONSULTANT"], ["di.document.upload"]

    def record_evaluation(self, payload: dict[str, Any]) -> None:
        self.evaluations.append(payload)


@dataclass
class FakeRefreshRepository:
    session: dict[str, Any]
    updates: list[dict[str, Any]] = field(default_factory=list)
    commits: int = 0
    rollbacks: int = 0

    def user_session_for_update(
        self,
        *,
        access_session_id: str,
        tenant_id: str,
        user_id: str,
    ) -> dict[str, Any]:
        _ = (access_session_id, tenant_id, user_id)
        return self.session

    def update_active_session_context(self, **kwargs: Any) -> bool:
        self.updates.append(kwargs)
        return True

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


@dataclass
class FakeNetwork:
    calls: int = 0

    def evaluate(self, source_ip: str, correlation_id: str) -> NetworkRiskResult:
        _ = (source_ip, correlation_id)
        self.calls += 1
        return NetworkRiskResult(VpnStatus.NOT_DETECTED)


@dataclass
class FakeTokens:
    claims: list[AccessTokenClaims] = field(default_factory=list)

    def issue(self, claims: AccessTokenClaims) -> str:
        self.claims.append(claims)
        return "refreshed-token"


def _location(location_id: str, latitude: float, longitude: float) -> LocationCandidate:
    return LocationCandidate(
        location_id=location_id,
        latitude=latitude,
        longitude=longitude,
        allowed_radius_meters=300,
        timezone_iana="UTC",
        schedule_id=f"schedule-{location_id}",
    )


def _geo(latitude: float, longitude: float) -> GeoSample:
    return GeoSample(
        latitude=latitude,
        longitude=longitude,
        accuracy_meters=10,
        captured_at=datetime.now(UTC),
        source=GeoSource.NATIVE,
        integrity_status=GeoIntegrityStatus.NORMAL,
    )


def _service(
    *,
    locations: list[LocationCandidate],
) -> tuple[
    UserSessionRefreshService,
    FakeRefreshRepository,
    FakeSecurityRepository,
    FakeNetwork,
    FakeTokens,
]:
    now = datetime.now(UTC)
    security = FakeSecurityRepository(locations=locations)
    refresh = FakeRefreshRepository(
        session={
            "access_session_id": "session-1",
            "status": "ACTIVE",
            "device_id": "device-1",
            "location_id": "location-a",
            "started_at_utc": now - timedelta(minutes=5),
            "expires_at_utc": now + timedelta(minutes=5),
        }
    )
    network = FakeNetwork()
    tokens = FakeTokens()
    service = UserSessionRefreshService(
        security=security,  # type: ignore[arg-type]
        refresh=refresh,  # type: ignore[arg-type]
        network=network,
        tokens=tokens,  # type: ignore[arg-type]
    )
    return service, refresh, security, network, tokens


def test_refresh_moves_context_to_different_approved_location() -> None:
    service, refresh, security, network, tokens = _service(
        locations=[
            _location("location-a", 28.6139, 77.2090),
            _location("location-b", 28.7041, 77.1025),
        ]
    )

    result = service.refresh(
        user_id="user-1",
        tenant_id="tenant-1",
        access_session_id="session-1",
        geo=_geo(28.7041, 77.1025),
        source_ip="203.0.113.10",
        correlation_id="phase4-refresh-move",
    )

    assert result.access_session_id == "session-1"
    assert result.location_id == "location-b"
    assert refresh.updates[0]["location_id"] == "location-b"
    assert tokens.claims[0].location_id == "location-b"
    assert security.evaluations[0]["matched_location_id"] == "location-b"
    assert refresh.commits == 1
    assert refresh.rollbacks == 0
    assert network.calls == 1


def test_refresh_keeps_context_when_same_approved_location_matches() -> None:
    service, refresh, _, _, tokens = _service(
        locations=[_location("location-a", 28.6139, 77.2090)]
    )

    result = service.refresh(
        user_id="user-1",
        tenant_id="tenant-1",
        access_session_id="session-1",
        geo=_geo(28.6139, 77.2090),
        source_ip="203.0.113.10",
        correlation_id="phase4-refresh-same",
    )

    assert result.location_id == "location-a"
    assert refresh.updates[0]["location_id"] == "location-a"
    assert tokens.claims[0].location_id == "location-a"


def test_refresh_rejects_geo_outside_all_approved_locations() -> None:
    service, refresh, security, _, tokens = _service(
        locations=[_location("location-a", 28.6139, 77.2090)]
    )

    with pytest.raises(SecurityError) as exc_info:
        service.refresh(
            user_id="user-1",
            tenant_id="tenant-1",
            access_session_id="session-1",
            geo=_geo(19.0760, 72.8777),
            source_ip="203.0.113.10",
            correlation_id="phase4-refresh-deny",
        )

    assert exc_info.value.code == "LOCATION_NOT_ALLOWED"
    assert refresh.updates == []
    assert security.evaluations == []
    assert tokens.claims == []
    assert refresh.commits == 0
    assert refresh.rollbacks == 1
