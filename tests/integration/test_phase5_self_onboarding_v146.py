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
    key = base64.urlsafe_b64encode(b"o" * 32).decode("ascii").rstrip("=")
    return Settings(security_user_onboarding_key_encryption_key=key)


class FakeClerk:
    def __init__(self, clerk_user_id: str, email_address_id: str) -> None:
        self.clerk_user_id = clerk_user_id
        self.email_address_id = email_address_id
        self.verified = False
        self.created: list[tuple[str, str, str, str]] = []
        self.prepare_calls: list[str] = []
        self.attempt_calls: list[tuple[str, str]] = []
        self.verify_calls: list[tuple[str, str]] = []
        self.deleted: list[str] = []

    def create_pending_email_user(
        self,
        *,
        first_name: str,
        last_name: str,
        email: str,
        password: str,
    ) -> tuple[str, str]:
        self.created.append((first_name, last_name, email, password))
        return self.clerk_user_id, self.email_address_id

    def prepare_email_verification(self, email_address_id: str) -> None:
        self.prepare_calls.append(email_address_id)

    def attempt_email_verification(self, email_address_id: str, code: str) -> bool:
        self.attempt_calls.append((email_address_id, code))
        return self.verified

    def is_email_verified(self, clerk_user_id: str, expected_email: str) -> bool:
        self.verify_calls.append((clerk_user_id, expected_email))
        return self.verified

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
            {"id": user_id, "name": f"v1.4.8 Admin {user_id}", "now": now},
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
                "name": "v1.4.8 Test Admin",
                "email": f"v148-admin-{user_id}@example.invalid",
                "now": now,
            },
        )
    return user_id


def test_backend_email_otp_is_required_before_pending_security_user() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_url(TEST_DATABASE_URL), pool_pre_ping=True)
    admin_id = _seed_admin(engine)
    email = f"v148-{uuid4()}@example.invalid"
    mobile_digits = f"9{uuid4().int % 1_000_000_000:09d}"
    mobile = f"+91{mobile_digits}"
    clerk_user_id = f"user_v148_{uuid4().hex}"
    email_address_id = f"idn_v148_{uuid4().hex}"
    clerk = FakeClerk(clerk_user_id, email_address_id)
    user_id: str | None = None
    attempt_id: str | None = None

    try:
        with Session(engine) as session:
            GlobalUserOnboardingService(session, _settings()).set_onboarding_key(
                actor_user_id=admin_id,
                onboarding_key="VGN-PHASE848",
                enabled=True,
                correlation_id=str(uuid4()),
            )

        with Session(engine) as session, pytest.raises(SecurityError):
            Phase1SelfOnboardingService(session).start(
                first_name="Wrong",
                last_name="Key",
                email=email,
                mobile=mobile,
                password="never-sent-because-key-is-invalid",
                onboarding_key="VGN-WRONG848",
                source_ip="127.0.0.1",
                correlation_id=str(uuid4()),
                clerk=clerk,  # type: ignore[arg-type]
            )
        assert clerk.created == []

        with engine.connect() as conn:
            assert conn.execute(
                text("SELECT 1 FROM security.platform_user_signup_attempts WHERE lower(email)=:email"),
                {"email": email.lower()},
            ).first() is None
            assert conn.execute(
                text("SELECT 1 FROM security.users WHERE lower(primary_email)=:email"),
                {"email": email.lower()},
            ).first() is None

        signup_password = "Clerk-owns-this-password-848"
        with Session(engine) as session:
            result = Phase1SelfOnboardingService(session).start(
                first_name="Amit",
                last_name="Goyal",
                email=email.upper(),
                mobile=f"+91 {mobile_digits[:5]} {mobile_digits[5:]}",
                password=signup_password,
                onboarding_key="VGN-PHASE848",
                source_ip="127.0.0.1",
                correlation_id=str(uuid4()),
                clerk=clerk,  # type: ignore[arg-type]
            )
            attempt_id = str(result["signupAttemptId"])
            assert result["status"] == "EMAIL_VERIFICATION_REQUIRED"
            assert "expiresAt" in result
            assert "password" not in result

        assert clerk.created == [("Amit", "Goyal", email.lower(), signup_password)]

        with engine.connect() as conn:
            attempt = conn.execute(
                text(
                    """
                    SELECT status,email,mobile,clerk_user_id,clerk_email_address_id,
                           expires_at_utc>created_at_utc AS valid_expiry
                    FROM security.platform_user_signup_attempts
                    WHERE signup_attempt_id=:attempt_id
                    """
                ),
                {"attempt_id": attempt_id},
            ).mappings().one()
            assert attempt["status"] == "AUTHORIZED_FOR_CLERK"
            assert attempt["email"] == email.lower()
            assert attempt["mobile"] == mobile
            assert attempt["clerk_user_id"] == clerk_user_id
            assert attempt["clerk_email_address_id"] == email_address_id
            assert attempt["valid_expiry"] is True
            assert conn.execute(
                text("SELECT 1 FROM security.users WHERE lower(primary_email)=:email"),
                {"email": email.lower()},
            ).first() is None

            columns = {
                str(row["column_name"])
                for row in conn.execute(
                    text(
                        """
                        SELECT column_name
                        FROM information_schema.columns
                        WHERE table_schema='security'
                          AND table_name='platform_user_signup_attempts'
                        """
                    )
                ).mappings()
            }
            assert "password" not in columns
            assert "otp" not in columns
            assert "verification_code" not in columns

        with Session(engine) as session, pytest.raises(ValueError, match="active signup attempt"):
            Phase1SelfOnboardingService(session).start(
                first_name="Duplicate",
                last_name="Attempt",
                email=email,
                mobile="+918123456789",
                password="duplicate-attempt-password",
                onboarding_key="VGN-PHASE848",
                source_ip="127.0.0.1",
                correlation_id=str(uuid4()),
                clerk=clerk,  # type: ignore[arg-type]
            )

        with Session(engine) as session, pytest.raises(ValueError, match="Invalid or expired"):
            Phase1SelfOnboardingService(session).verify_email_code(
                signup_attempt_id=attempt_id,
                code="000000",
                source_ip="127.0.0.1",
                correlation_id=str(uuid4()),
                clerk=clerk,  # type: ignore[arg-type]
            )
        assert clerk.attempt_calls == [(email_address_id, "000000")]
        assert clerk.verify_calls == []

        with engine.connect() as conn:
            assert conn.execute(
                text("SELECT 1 FROM security.users WHERE lower(primary_email)=:email"),
                {"email": email.lower()},
            ).first() is None

        with Session(engine) as session:
            result = Phase1SelfOnboardingService(session).resend_email_code(
                signup_attempt_id=attempt_id,
                clerk=clerk,  # type: ignore[arg-type]
            )
            assert result["status"] == "EMAIL_VERIFICATION_REQUIRED"
        assert clerk.prepare_calls == [email_address_id]

        clerk.verified = True
        with Session(engine) as session:
            result = Phase1SelfOnboardingService(session).verify_email_code(
                signup_attempt_id=attempt_id,
                code="123456",
                source_ip="127.0.0.1",
                correlation_id=str(uuid4()),
                clerk=clerk,  # type: ignore[arg-type]
            )
            assert result["status"] == "PENDING_ADMIN_APPROVAL"
            assert result["message"] == "Registration successful. Pending administrator approval."

        assert clerk.attempt_calls[-1] == (email_address_id, "123456")
        assert clerk.verify_calls[-1] == (clerk_user_id, email.lower())

        with engine.connect() as conn:
            row = conn.execute(
                text(
                    """
                    SELECT u.user_id,u.first_name,u.last_name,u.primary_email,u.primary_mobile,
                           u.status,p.status AS principal_status,e.provider_subject,
                           r.status AS onboarding_status,a.status AS attempt_status,
                           a.clerk_user_id AS attempt_clerk_user_id,
                           a.clerk_email_address_id AS attempt_clerk_email_address_id
                    FROM security.users u
                    JOIN security.security_principals p ON p.principal_id=u.user_id
                    JOIN security.external_identities e
                      ON e.user_id=u.user_id AND e.provider='CLERK'
                    JOIN security.platform_user_onboarding_requests r ON r.user_id=u.user_id
                    JOIN security.platform_user_signup_attempts a
                      ON a.signup_attempt_id=:attempt_id
                    WHERE lower(u.primary_email)=:email
                    """
                ),
                {"attempt_id": attempt_id, "email": email.lower()},
            ).mappings().one()
            user_id = str(row["user_id"])
            assert row["first_name"] == "Amit"
            assert row["last_name"] == "Goyal"
            assert row["primary_email"] == email.lower()
            assert row["primary_mobile"] == mobile
            assert row["status"] == "PENDING"
            assert row["principal_status"] == "ACTIVE"
            assert row["provider_subject"] == clerk_user_id
            assert row["onboarding_status"] == "PENDING_ADMIN_APPROVAL"
            assert row["attempt_status"] == "COMPLETED"
            assert row["attempt_clerk_user_id"] == clerk_user_id
            assert row["attempt_clerk_email_address_id"] == email_address_id

        with Session(engine) as session, pytest.raises(ValueError, match="no longer available"):
            Phase1SelfOnboardingService(session).verify_email_code(
                signup_attempt_id=attempt_id,
                code="123456",
                source_ip="127.0.0.1",
                correlation_id=str(uuid4()),
                clerk=clerk,  # type: ignore[arg-type]
            )

        with Session(engine) as session:
            assert not GlobalUserOnboardingService(session, _settings()).precheck(email)
    finally:
        with engine.begin() as conn:
            if user_id is not None:
                conn.execute(
                    text(
                        """
                        DELETE FROM security.security_events
                        WHERE principal_id=CAST(:user_id AS uuid)
                           OR entity_id=CAST(:user_id AS varchar)
                        """
                    ),
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
            if attempt_id is not None:
                conn.execute(
                    text("DELETE FROM security.platform_user_signup_attempts WHERE signup_attempt_id=:attempt_id"),
                    {"attempt_id": attempt_id},
                )
            conn.execute(
                text("DELETE FROM security.users WHERE user_id=:admin_id"),
                {"admin_id": admin_id},
            )
            conn.execute(
                text("DELETE FROM security.security_principals WHERE principal_id=:admin_id"),
                {"admin_id": admin_id},
            )
        engine.dispose()
