from __future__ import annotations

import os
from datetime import UTC, datetime, time
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from verigence_security.repositories.security_repository import SecurityRepository
from verigence_security.services.tenant_access_configuration import (
    AccessScheduleConfiguration,
    AccessScheduleWindowConfiguration,
    TenantAccessConfigurationService,
    TenantLocationConfiguration,
)

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


@pytest.fixture()
def tenant_fixture() -> tuple[object, str]:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    tenant_id = str(uuid4())
    now = datetime.now(UTC)

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO security.tenants
                (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                VALUES (:tenant_id,:tenant_code,'Phase 5 Access Admin',
                        'CONFIGURING',:now,:now)
                """
            ),
            {
                "tenant_id": tenant_id,
                "tenant_code": f"p5-access-{tenant_id}",
                "now": now,
            },
        )

    try:
        yield engine, tenant_id
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM security.access_schedule_windows WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.access_schedules WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.tenant_locations WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.tenants WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
        engine.dispose()


def _location(location_id: str, *, name: str) -> TenantLocationConfiguration:
    return TenantLocationConfiguration(
        location_id=location_id,
        location_code="DELHI-01",
        location_name=name,
        location_type="OFFICE",
        latitude=28.6139,
        longitude=77.2090,
        allowed_radius_meters=250,
        timezone_iana="Asia/Kolkata",
        address_line1="Phase 5 address",
        city="New Delhi",
        state_region="Delhi",
        country_code="IN",
        postal_code="110001",
        status="ACTIVE",
    )


def test_location_upsert_preserves_tenant_scope_and_explicit_values(
    tenant_fixture: tuple[object, str],
) -> None:
    engine, tenant_id = tenant_fixture
    location_id = str(uuid4())
    now = datetime.now(UTC)

    with Session(engine) as session:  # type: ignore[arg-type]
        service = TenantAccessConfigurationService(session)
        assert service.configure_location(
            tenant_id=tenant_id,
            configuration=_location(location_id, name="Delhi Office"),
            now=now,
        )
        assert service.configure_location(
            tenant_id=tenant_id,
            configuration=_location(location_id, name="Delhi Main Office"),
            now=now,
        )

    with engine.connect() as conn:  # type: ignore[union-attr]
        row = conn.execute(
            text(
                """
                SELECT location_name,latitude,longitude,allowed_radius_meters,
                       timezone_iana,country_code,count(*) OVER () AS row_count
                FROM security.tenant_locations
                WHERE tenant_id=:tenant_id AND location_id=:location_id
                """
            ),
            {"tenant_id": tenant_id, "location_id": location_id},
        ).mappings().one()
    assert row["location_name"] == "Delhi Main Office"
    assert float(row["latitude"]) == 28.6139
    assert float(row["longitude"]) == 77.209
    assert row["allowed_radius_meters"] == 250
    assert row["timezone_iana"] == "Asia/Kolkata"
    assert row["country_code"] == "IN"
    assert row["row_count"] == 1


def test_schedule_and_windows_are_runtime_compatible(
    tenant_fixture: tuple[object, str],
) -> None:
    engine, tenant_id = tenant_fixture
    schedule_id = str(uuid4())
    normal_window_id = str(uuid4())
    overnight_window_id = str(uuid4())
    now = datetime.now(UTC)

    configuration = AccessScheduleConfiguration(
        schedule_id=schedule_id,
        schedule_key="PROCESS-CONSULTANT",
        schedule_name="Process Consultant Hours",
        status="ACTIVE",
        windows=(
            AccessScheduleWindowConfiguration(
                schedule_window_id=normal_window_id,
                iso_day_of_week=1,
                start_local_time=time(9, 0),
                end_local_time=time(18, 0),
                crosses_midnight=False,
                status="ACTIVE",
            ),
            AccessScheduleWindowConfiguration(
                schedule_window_id=overnight_window_id,
                iso_day_of_week=6,
                start_local_time=time(22, 0),
                end_local_time=time(2, 0),
                crosses_midnight=True,
                status="ACTIVE",
            ),
        ),
    )

    with Session(engine) as session:  # type: ignore[arg-type]
        service = TenantAccessConfigurationService(session)
        assert service.configure_schedule(
            tenant_id=tenant_id,
            configuration=configuration,
            now=now,
        )

    with Session(engine) as session:  # type: ignore[arg-type]
        runtime = SecurityRepository(session)
        runtime.ensure_active_schedule(tenant_id, schedule_id)
        windows = runtime.schedule_windows(tenant_id, schedule_id)
        assert len(windows) == 2
        assert any(
            window.iso_day_of_week == 1
            and window.start_local_time == time(9, 0)
            and window.end_local_time == time(18, 0)
            and not window.crosses_midnight
            for window in windows
        )
        assert any(
            window.iso_day_of_week == 6
            and window.start_local_time == time(22, 0)
            and window.end_local_time == time(2, 0)
            and window.crosses_midnight
            for window in windows
        )


def test_location_constraints_reject_invalid_radius_without_partial_write(
    tenant_fixture: tuple[object, str],
) -> None:
    engine, tenant_id = tenant_fixture
    location_id = str(uuid4())
    invalid = _location(location_id, name="Invalid Office")
    invalid = TenantLocationConfiguration(
        location_id=invalid.location_id,
        location_code=invalid.location_code,
        location_name=invalid.location_name,
        location_type=invalid.location_type,
        latitude=invalid.latitude,
        longitude=invalid.longitude,
        allowed_radius_meters=0,
        timezone_iana=invalid.timezone_iana,
        address_line1=invalid.address_line1,
        city=invalid.city,
        state_region=invalid.state_region,
        country_code=invalid.country_code,
        postal_code=invalid.postal_code,
        status=invalid.status,
    )

    with Session(engine) as session:  # type: ignore[arg-type]
        service = TenantAccessConfigurationService(session)
        with pytest.raises(IntegrityError):
            service.configure_location(
                tenant_id=tenant_id,
                configuration=invalid,
                now=datetime.now(UTC),
            )

    with engine.connect() as conn:  # type: ignore[union-attr]
        count = conn.execute(
            text(
                """
                SELECT count(*) FROM security.tenant_locations
                WHERE tenant_id=:tenant_id AND location_id=:location_id
                """
            ),
            {"tenant_id": tenant_id, "location_id": location_id},
        ).scalar_one()
    assert count == 0
