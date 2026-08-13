from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.core.errors import SecurityError
from verigence_security.services.device_lifecycle import DeviceApprovalService

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)


def _sqlalchemy_url(url: str) -> str:
    if url.startswith("postgresql+psycopg://"):
        return url
    if url.startswith("postgresql+asyncpg://"):
        return "postgresql+psycopg://" + url.removeprefix("postgresql+asyncpg://")
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url.removeprefix("postgresql://")
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url.removeprefix("postgres://")
    raise ValueError("TEST_DATABASE_URL must be a PostgreSQL URL")


def test_concurrent_approvals_cannot_exceed_tenant_device_limit() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    tenant_id = str(uuid4())
    user_id = str(uuid4())
    membership_id = str(uuid4())
    device_ids = [str(uuid4()), str(uuid4())]
    request_ids = [str(uuid4()), str(uuid4())]
    now = datetime.now(UTC)

    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO security.tenants
                    (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                    VALUES (:tenant_id,:tenant_code,'Phase 4 device limit','ACTIVE',:now,:now)
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "tenant_code": f"p4-limit-{tenant_id}",
                    "now": now,
                },
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.security_principals
                    (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                    VALUES (:user_id,'USER','Phase 4 device limit','ACTIVE',:now,:now)
                    """
                ),
                {"user_id": user_id, "now": now},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.users
                    (user_id,display_name,status,created_at_utc,updated_at_utc)
                    VALUES (:user_id,'Phase 4 device limit','ACTIVE',:now,:now)
                    """
                ),
                {"user_id": user_id, "now": now},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.tenant_memberships
                    (membership_id,tenant_id,user_id,status,authorization_version,
                     created_at_utc,updated_at_utc)
                    VALUES (:membership_id,:tenant_id,:user_id,'ACTIVE',1,:now,:now)
                    """
                ),
                {
                    "membership_id": membership_id,
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "now": now,
                },
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.tenant_security_policies
                    (tenant_id,max_active_devices_per_user,max_geo_accuracy_meters,
                     max_geo_age_seconds,geo_revalidation_interval_seconds,
                     access_token_ttl_minutes,machine_token_ttl_minutes,
                     session_idle_timeout_minutes,session_max_duration_minutes,
                     vpn_detected_action,vpn_unknown_action,configuration_version,
                     status,updated_by_user_id,updated_at_utc)
                    VALUES (:tenant_id,1,100,300,300,10,10,30,60,'DENY','FLAG',1,
                            'ACTIVE',:user_id,:now)
                    """
                ),
                {"tenant_id": tenant_id, "user_id": user_id, "now": now},
            )
            for device_id, request_id in zip(device_ids, request_ids, strict=True):
                conn.execute(
                    text(
                        """
                        INSERT INTO security.registered_devices
                        (device_id,tenant_id,user_id,device_type,platform,device_name,
                         status,registered_at_utc)
                        VALUES (:device_id,:tenant_id,:user_id,'MOBILE','ANDROID',
                                'Phase 4 device limit','PENDING',:now)
                        """
                    ),
                    {
                        "device_id": device_id,
                        "tenant_id": tenant_id,
                        "user_id": user_id,
                        "now": now,
                    },
                )
                conn.execute(
                    text(
                        """
                        INSERT INTO security.device_enrollment_requests
                        (enrollment_request_id,tenant_id,user_id,device_id,source_ip,
                         requested_at_utc,status)
                        VALUES (:request_id,:tenant_id,:user_id,:device_id,
                                '203.0.113.10',:now,'PENDING')
                        """
                    ),
                    {
                        "request_id": request_id,
                        "tenant_id": tenant_id,
                        "user_id": user_id,
                        "device_id": device_id,
                        "now": now,
                    },
                )

        barrier = Barrier(2)

        def approve(device_id: str, request_id: str) -> str:
            with Session(engine) as session:  # type: ignore[arg-type]
                service = DeviceApprovalService(session)
                barrier.wait(timeout=10)
                try:
                    approved = service.approve_pending_device(
                        enrollment_request_id=request_id,
                        tenant_id=tenant_id,
                        user_id=user_id,
                        device_id=device_id,
                        decided_by_user_id=user_id,
                        decided_at=datetime.now(UTC),
                    )
                except SecurityError as exc:
                    return exc.code
                return "APPROVED" if approved else "NOT_APPROVED"

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(approve, device_id, request_id)
                for device_id, request_id in zip(device_ids, request_ids, strict=True)
            ]
            results = sorted(future.result(timeout=20) for future in futures)

        assert results == ["APPROVED", "DEVICE_LIMIT_REACHED"]

        with engine.connect() as conn:
            active_count = conn.execute(
                text(
                    """
                    SELECT count(*) FROM security.registered_devices
                    WHERE tenant_id=:tenant_id AND user_id=:user_id AND status='ACTIVE'
                    """
                ),
                {"tenant_id": tenant_id, "user_id": user_id},
            ).scalar_one()
            pending_count = conn.execute(
                text(
                    """
                    SELECT count(*) FROM security.registered_devices
                    WHERE tenant_id=:tenant_id AND user_id=:user_id AND status='PENDING'
                    """
                ),
                {"tenant_id": tenant_id, "user_id": user_id},
            ).scalar_one()
        assert active_count == 1
        assert pending_count == 1
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM security.device_enrollment_requests WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.registered_devices WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.tenant_security_policies WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.tenant_memberships WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.users WHERE user_id=:id"),
                {"id": user_id},
            )
            conn.execute(
                text("DELETE FROM security.security_principals WHERE principal_id=:id"),
                {"id": user_id},
            )
            conn.execute(
                text("DELETE FROM security.tenants WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
        engine.dispose()
