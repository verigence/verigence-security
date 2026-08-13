from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from verigence_security.adapters.network_risk import NetworkRiskResult
from verigence_security.core.errors import SecurityError, security_error
from verigence_security.core.types import GeoIntegrityStatus, GeoSource, VpnStatus
from verigence_security.repositories.security_repository import TenantPolicy, UserContext
from verigence_security.services.geo import GeoSample
from verigence_security.services.session_refresh_service import UserSessionRefreshService


def test_refresh_nonactive_device_denies_and_records_existing_reason_code() -> None:
    now = datetime.now(UTC)
    security = Mock()
    refresh = Mock()
    network = Mock()
    tokens = Mock()

    security.tenant_status.return_value = "ACTIVE"
    security.get_user_context.return_value = UserContext(
        user_id="user-1",
        user_status="ACTIVE",
        membership_id="membership-1",
        membership_status="ACTIVE",
        authorization_version=3,
    )
    security.get_tenant_policy.return_value = TenantPolicy(
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
    refresh.user_session.return_value = {
        "access_session_id": "session-1",
        "status": "ACTIVE",
        "device_id": "device-1",
        "location_id": "location-a",
        "started_at_utc": now - timedelta(minutes=5),
        "expires_at_utc": now + timedelta(minutes=5),
    }
    network.evaluate.return_value = NetworkRiskResult(VpnStatus.NOT_DETECTED)
    security.lock_active_device.side_effect = security_error("DEVICE_NOT_ACTIVE")

    service = UserSessionRefreshService(
        security=security,
        refresh=refresh,
        network=network,
        tokens=tokens,
    )
    geo = GeoSample(
        latitude=28.6139,
        longitude=77.2090,
        accuracy_meters=10,
        captured_at=now,
        source=GeoSource.NATIVE,
        integrity_status=GeoIntegrityStatus.NORMAL,
    )

    with pytest.raises(SecurityError) as exc_info:
        service.refresh(
            user_id="user-1",
            tenant_id="tenant-1",
            access_session_id="session-1",
            geo=geo,
            source_ip="203.0.113.10",
            correlation_id="phase4-device-not-active",
        )

    assert exc_info.value.code == "DEVICE_NOT_ACTIVE"
    security.lock_active_device.assert_called_once_with(
        "user-1",
        "tenant-1",
        "device-1",
    )
    refresh.user_session_for_update.assert_not_called()
    refresh.update_active_session_context.assert_not_called()
    tokens.issue.assert_not_called()

    assert refresh.rollback.call_count == 1
    assert refresh.record_evaluation.call_count == 1
    denial = refresh.record_evaluation.call_args.args[0]
    assert denial["decision"] == "DENY"
    assert denial["decision_reason_code"] == "DEVICE_NOT_ACTIVE"
    assert denial["access_session_id"] == "session-1"
    assert denial["correlation_id"] == "phase4-device-not-active"
    assert refresh.commit.call_count == 1
