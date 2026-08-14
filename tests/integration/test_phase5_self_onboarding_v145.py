from __future__ import annotations

import base64
import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from verigence_security.config import Settings
from verigence_security.core.errors import SecurityError
from verigence_security.services.global_user_onboarding import GlobalUserOnboardingService
from verigence_security.services.phase1_self_onboarding import Phase1SelfOnboardingService

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)


def _url(value: str) -> str:
    if value.startswith("postgresql+psycopg://"):
        return value
    if value.startswith("postgresql+asyncpg://"):
        return "postgresql+psycopg://" + value.removeprefix("postgresql+asyncpg://")
    if value.startswith("postgresql://"):
        return "postgresql+psycopg://" + value.removeprefix("postgresql://")
    if value.startswith("postgres://"):
        return "postgresql+psycopg://" + value.removeprefix("postgres://")
    raise ValueError("TEST_DATABASE_URL must be PostgreSQL")


def _settings() -> Settings:
    key = base64.urlsafe_b64encode(b"p" * 32).decode("ascii").rstrip("=")
    return Settings(security_user_onboarding_key_encryption_key=key)


class FakeClerk:
    def __init__(self) -> None:
        self.create_calls: list[dict[str, str]] = []
        self.deleted: list[str] = []
        self.next_user_id: str | None = None

    def create_user(
        self,
        *,
        first_name: str,
        last_name: str,
        email: str,
        password: str,
    ) -> str:
        self.create_calls.append(
            {
                "first_name": first_name,
                "last_name": last_name,
                "email": email,
                "password": password,
            }
        )
        if self.next_user_id is not None:
            result = self.next_user_id
            self.next_user_id = None
            return result
        return f"user_v145_{uuid4().hex}"

    def delete_user(self, clerk_user_id: str) -> None:
        self.deleted.append(clerk_user_id)


def _seed_admin(engine: Engine) -> str:
    user_id = str(uuid4())
    now = datetime.now(UTC)
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO security.security_principals
                (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                VALUES (:id,'USER',:name,'ACTIVE',:now,:now)
                """
            ),
            {"id": user_id, "name": f"v1.4.5 Admin {user_id}", "now": now},
        )
        conn.execute(
            text(
                """
                INSERT INTO security.users
                (user_id,display_name,primary_email,status,created_at_utc,updated_at_utc)
                VALUES (:id,:name,:email,'ACTIVE',:now,:now)
                """
            ),
            {
                "id": user_id,
                "name": "v1.4.5 Test Admin",
                "email": f"v145-admin-{user_id}@example.invalid",
                "now": now,
            },
        )
    return user_id


def test_phase1_self_onboarding_creates_clerk_then_pending_security_user() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_url(TEST_DATABASE_URL), pool_pre_ping=True)
    admin_id = _seed_admin(engine)
    clerk = FakeClerk()
    email = f"v145-{uuid4()}@example.invalid"
    mobile_digits = f"9{uuid4().int % 1_000_000_000:09d}"
    mobile = f"+91{mobile_digits}"
    second_email = f"v145-second-{uuid4()}@example.invalid"
    user_id: str | None = None

    try:
        with Session(engine) as session:
            key_service = GlobalUserOnboardingService(session, _settings())
            key_service.set_onboarding_key(
                actor_user_id=admin_id,
                onboarding_key="VGN-PHASE845",
                enabled=True,
                correlation_id=str(uuid4()),
            )

        with Session(engine) as session:
            service = Phase1SelfOnboardingService(session)
            with pytest.raises(SecurityError):
                service.register(
                    first_name="Wrong",
                    last_name="Key",
                    email=email,
                    mobile=mobile,
                    password="safe-password-123",
                    onboarding_key="VGN-WRONG845",
                    source_ip="127.0.0.1",
                    correlation_id=str(uuid4()),
                    clerk=clerk,  # type: ignore[arg-type]
                )
            assert clerk.create_calls == []

        with Session(engine) as session:
            result = Phase1SelfOnboardingService(session).register(
                first_name="Amit",
                last_name="Goyal",
                email=email.upper(),
                mobile=f"+91 {mobile_digits[:5]} {mobile_digits[5:]}",
                password="safe-password-123",
                onboarding_key="VGN-PHASE845",
                source_ip="127.0.0.1",
                correlation_id=str(uuid4()),
                clerk=clerk,  # type: ignore[arg-type]
            )
            assert result["status"] == "PENDING_ADMIN_APPROVAL"
            assert result["message"] == "Registration successful. Pending administrator approval."
            assert "userId" not in result
            assert len(clerk.create_calls) == 1
            assert clerk.create_calls[0] == {
                "first_name": "Amit",
                "last_name": "Goyal",
                "email": email.lower(),
                "password": "safe-password-123",
            }

        with engine.connect() as conn:
            row = conn.execute(
                text(
                    """
                    SELECT u.user_id,u.first_name,u.last_name,u.primary_email,u.primary_mobile,
                           u.status,e.provider_subject,r.status AS onboarding_status,
                           r.clerk_invitation_id
                    FROM security.users u
                    JOIN security.external_identities e
                      ON e.user_id=u.user_id AND e.provider='CLERK'
                    JOIN security.platform_user_onboarding_requests r ON r.user_id=u.user_id
                    WHERE lower(u.primary_email)=:email
                    """
                ),
                {"email": email.lower()},
            ).mappings().one()
            user_id = str(row["user_id"])
            clerk_user_id = str(row["provider_subject"])
            assert row["first_name"] == "Amit"
            assert row["last_name"] == "Goyal"
            assert row["primary_email"] == email.lower()
            assert row["primary_mobile"] == mobile
            assert row["status"] == "PENDING"
            assert row["onboarding_status"] == "PENDING_ADMIN_APPROVAL"
            assert row["clerk_invitation_id"] is None

            mobile_index = conn.execute(
                text(
                    """
                    SELECT 1 FROM pg_indexes
                    WHERE schemaname='security'
                      AND indexname='uq_security_users_primary_mobile_digits'
                    """
                )
            ).first()
            assert mobile_index is not None

        with Session(engine) as session:
            service = Phase1SelfOnboardingService(session)
            with pytest.raises(ValueError, match="Email address is already registered"):
                service.register(
                    first_name="Duplicate",
                    last_name="Email",
                    email=email.upper(),
                    mobile="+919123456789",
                    password="safe-password-456",
                    onboarding_key="VGN-PHASE845",
                    source_ip="127.0.0.1",
                    correlation_id=str(uuid4()),
                    clerk=clerk,  # type: ignore[arg-type]
                )
            assert len(clerk.create_calls) == 1

        with Session(engine) as session:
            service = Phase1SelfOnboardingService(session)
            with pytest.raises(ValueError, match="Mobile number is already registered"):
                service.register(
                    first_name="Duplicate",
                    last_name="Mobile",
                    email=second_email,
                    mobile=mobile_digits,
                    password="safe-password-789",
                    onboarding_key="VGN-PHASE845",
                    source_ip="127.0.0.1",
                    correlation_id=str(uuid4()),
                    clerk=clerk,  # type: ignore[arg-type]
                )
            assert len(clerk.create_calls) == 1

        compensation_email = f"v145-comp-{uuid4()}@example.invalid"
        clerk.next_user_id = clerk_user_id
        with (
            Session(engine) as session,
            pytest.raises(ValueError, match="Email or mobile number is already registered"),
        ):
            Phase1SelfOnboardingService(session).register(
                first_name="Compensation",
                last_name="Check",
                email=compensation_email,
                mobile="+918123456789",
                password="safe-password-999",
                onboarding_key="VGN-PHASE845",
                source_ip="127.0.0.1",
                correlation_id=str(uuid4()),
                clerk=clerk,  # type: ignore[arg-type]
            )
        assert clerk_user_id in clerk.deleted
        with engine.connect() as conn:
            assert conn.execute(
                text("SELECT 1 FROM security.users WHERE lower(primary_email)=:email"),
                {"email": compensation_email.lower()},
            ).first() is None

        with Session(engine) as session:
            assert not GlobalUserOnboardingService(session, _settings()).precheck(email)
    finally:
        if user_id is not None:
            with engine.begin() as conn:
                conn.execute(
                    text("DELETE FROM security.security_events WHERE principal_id=:user_id"),
                    {"user_id": user_id},
                )
                conn.execute(
                    text("DELETE FROM security.platform_user_onboarding_requests WHERE user_id=:user_id"),
                    {"user_id": user_id},
                )
                conn.execute(
                    text("DELETE FROM security.external_identities WHERE user_id=:user_id"),
                    {"user_id": user_id},
                )
                conn.execute(
                    text("DELETE FROM security.users WHERE user_id=:user_id"),
                    {"user_id": user_id},
                )
                conn.execute(
                    text("DELETE FROM security.security_principals WHERE principal_id=:user_id"),
                    {"user_id": user_id},
                )
        engine.dispose()
