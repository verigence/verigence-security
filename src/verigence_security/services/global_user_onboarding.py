from __future__ import annotations

import base64
import secrets
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from verigence_security.adapters.clerk_backend import ClerkBackendClient, ClerkBackendError
from verigence_security.adapters.identity import AuthenticatedIdentity
from verigence_security.config import Settings
from verigence_security.core.errors import security_error

_HASHER = PasswordHasher()
_ALLOWED_ONBOARDING_CHARS = frozenset(
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_"
)


class GlobalUserOnboardingService:
    """Platform-global, one-time human onboarding and Security-owned USER lifecycle."""

    def __init__(self, session: Session, settings: Settings) -> None:
        self.s = session
        self.settings = settings

    # ------------------------------------------------------------------
    # Platform onboarding-key administration
    # ------------------------------------------------------------------
    def set_onboarding_key(
        self,
        *,
        actor_user_id: str,
        onboarding_key: str,
        enabled: bool,
        correlation_id: str,
    ) -> dict[str, Any]:
        value = self._validate_onboarding_key(onboarding_key)
        now = datetime.now(UTC)
        encrypted = self._encrypt_key(value)
        row = self.s.execute(
            text(
                """
                SELECT key_version FROM security.platform_user_onboarding_settings
                WHERE singleton_id=1 FOR UPDATE
                """
            )
        ).first()
        version = int(row[0]) + 1 if row else 1
        try:
            self.s.execute(
                text(
                    """
                    INSERT INTO security.platform_user_onboarding_settings
                    (singleton_id,key_hash,key_ciphertext,key_version,status,
                     created_by_user_id,created_at_utc,updated_by_user_id,updated_at_utc)
                    VALUES (1,:key_hash,:key_ciphertext,:version,:status,
                            :actor,:now,:actor,:now)
                    ON CONFLICT (singleton_id) DO UPDATE SET
                      key_hash=EXCLUDED.key_hash,
                      key_ciphertext=EXCLUDED.key_ciphertext,
                      key_version=EXCLUDED.key_version,
                      status=EXCLUDED.status,
                      updated_by_user_id=EXCLUDED.updated_by_user_id,
                      updated_at_utc=EXCLUDED.updated_at_utc
                    """
                ),
                {
                    "key_hash": _HASHER.hash(value),
                    "key_ciphertext": encrypted,
                    "version": version,
                    "status": "ACTIVE" if enabled else "DISABLED",
                    "actor": actor_user_id,
                    "now": now,
                },
            )
            self._admin_audit(
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
                operation_key="security.user_onboarding.key.set",
                resource_type="GLOBAL_USER_ONBOARDING_KEY",
                resource_id="1",
                after={"status": "ACTIVE" if enabled else "DISABLED", "version": version},
                now=now,
            )
            self.s.commit()
        except Exception:
            self.s.rollback()
            raise
        return self.get_onboarding_key()

    def rotate_onboarding_key(
        self,
        *,
        actor_user_id: str,
        correlation_id: str,
    ) -> dict[str, Any]:
        generated = "VGN-" + "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(8))
        return self.set_onboarding_key(
            actor_user_id=actor_user_id,
            onboarding_key=generated,
            enabled=True,
            correlation_id=correlation_id,
        )

    def disable_onboarding_key(
        self,
        *,
        actor_user_id: str,
        correlation_id: str,
    ) -> bool:
        now = datetime.now(UTC)
        row = self.s.execute(
            text(
                """
                UPDATE security.platform_user_onboarding_settings
                SET status='DISABLED',updated_by_user_id=:actor,updated_at_utc=:now
                WHERE singleton_id=1
                RETURNING key_version
                """
            ),
            {"actor": actor_user_id, "now": now},
        ).first()
        if row is None:
            self.s.rollback()
            return False
        self._admin_audit(
            actor_user_id=actor_user_id,
            correlation_id=correlation_id,
            operation_key="security.user_onboarding.key.disable",
            resource_type="GLOBAL_USER_ONBOARDING_KEY",
            resource_id="1",
            after={"status": "DISABLED", "version": int(row[0])},
            now=now,
        )
        self.s.commit()
        return True

    def get_onboarding_key(self) -> dict[str, Any]:
        row = self.s.execute(
            text(
                """
                SELECT key_ciphertext,key_version,status,created_at_utc,updated_at_utc
                FROM security.platform_user_onboarding_settings
                WHERE singleton_id=1
                """
            )
        ).mappings().first()
        if row is None:
            raise LookupError("Global user onboarding key is not configured")
        return {
            "onboardingKey": self._decrypt_key(str(row["key_ciphertext"])),
            "version": int(row["key_version"]),
            "status": str(row["status"]),
            "createdAtUtc": row["created_at_utc"],
            "updatedAtUtc": row["updated_at_utc"],
        }

    # ------------------------------------------------------------------
    # Public one-time onboarding
    # ------------------------------------------------------------------
    def submit(
        self,
        *,
        email: str,
        display_name: str,
        onboarding_key: str,
        source_ip: str,
        correlation_id: str,
        clerk: ClerkBackendClient,
    ) -> dict[str, Any]:
        clean_email = email.strip().lower()
        clean_name = display_name.strip()
        if not clean_email or "@" not in clean_email:
            raise ValueError("A valid email is required")
        if not clean_name:
            raise ValueError("Display name is required")
        self._require_valid_onboarding_key(onboarding_key)

        existing = self.s.execute(
            text(
                """
                SELECT user_id,status FROM security.users
                WHERE lower(primary_email)=:email
                """
            ),
            {"email": clean_email},
        ).mappings().first()
        if existing is not None:
            raise ValueError("A Verigence USER already exists for this email")

        now = datetime.now(UTC)
        user_id = str(uuid4())
        request_id = str(uuid4())
        try:
            self.s.execute(
                text(
                    """
                    INSERT INTO security.security_principals
                    (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                    VALUES (:id,'USER',:name,'ACTIVE',:now,:now)
                    """
                ),
                {"id": user_id, "name": clean_name, "now": now},
            )
            self.s.execute(
                text(
                    """
                    INSERT INTO security.users
                    (user_id,display_name,primary_email,status,created_at_utc,updated_at_utc)
                    VALUES (:id,:name,:email,'PENDING',:now,:now)
                    """
                ),
                {"id": user_id, "name": clean_name, "email": clean_email, "now": now},
            )
            self.s.execute(
                text(
                    """
                    INSERT INTO security.platform_user_onboarding_requests
                    (onboarding_request_id,user_id,email,status,submitted_source_ip,
                     submitted_at_utc,correlation_id)
                    VALUES (:request_id,:user_id,:email,'PENDING_CLERK',CAST(:source_ip AS inet),
                            :now,:correlation_id)
                    """
                ),
                {
                    "request_id": request_id,
                    "user_id": user_id,
                    "email": clean_email,
                    "source_ip": source_ip,
                    "now": now,
                    "correlation_id": correlation_id,
                },
            )
            self._security_event(
                user_id=user_id,
                event_type="GLOBAL_USER_ONBOARDING_ACCEPTED",
                outcome="PENDING_CLERK",
                reason_code="ONBOARDING_KEY_VALID",
                source_ip=source_ip,
                correlation_id=correlation_id,
                now=now,
            )
            self.s.commit()
        except IntegrityError as exc:
            self.s.rollback()
            raise ValueError("A Verigence USER already exists for this email") from exc
        except Exception:
            self.s.rollback()
            raise

        # Never hold a database transaction open across Clerk network calls.
        try:
            invitation_id = clerk.create_invitation(
                email=clean_email,
                security_user_id=user_id,
                onboarding_request_id=request_id,
            )
        except ClerkBackendError:
            self.s.execute(
                text(
                    """
                    UPDATE security.platform_user_onboarding_requests
                    SET status='CLERK_PROVISIONING_FAILED'
                    WHERE onboarding_request_id=:request_id
                    """
                ),
                {"request_id": request_id},
            )
            self.s.commit()
            raise

        self.s.execute(
            text(
                """
                UPDATE security.platform_user_onboarding_requests
                SET status='CLERK_INVITED',clerk_invitation_id=:invitation_id
                WHERE onboarding_request_id=:request_id
                """
            ),
            {"request_id": request_id, "invitation_id": invitation_id},
        )
        self.s.commit()
        return {
            "onboardingRequestId": request_id,
            "userId": user_id,
            "status": "CLERK_INVITED",
        }

    def bind_authenticated_clerk_user(
        self,
        *,
        onboarding_request_id: str,
        identity: AuthenticatedIdentity,
        source_ip: str,
        correlation_id: str,
        clerk: ClerkBackendClient,
    ) -> dict[str, Any]:
        if identity.provider != "CLERK":
            raise security_error("AUTH_TOKEN_INVALID")
        row = self.s.execute(
            text(
                """
                SELECT r.*,u.status AS user_status
                FROM security.platform_user_onboarding_requests r
                JOIN security.users u ON u.user_id=r.user_id
                WHERE r.onboarding_request_id=:request_id
                """
            ),
            {"request_id": onboarding_request_id},
        ).mappings().first()
        if row is None:
            raise LookupError("Onboarding request not found")
        if row["status"] not in {"CLERK_INVITED", "PENDING_ADMIN_APPROVAL"}:
            raise ValueError("Onboarding request is not ready for Clerk identity binding")
        if row["user_status"] != "PENDING":
            raise ValueError("Security USER is not pending onboarding approval")

        clerk_user_id = identity.provider_subject
        clerk_email = clerk.primary_email(clerk_user_id)
        if clerk_email is None or clerk_email.lower() != str(row["email"]).lower():
            raise security_error("PERMISSION_DENIED")

        existing = self.s.execute(
            text(
                """
                SELECT user_id,status FROM security.external_identities
                WHERE provider='CLERK' AND provider_subject=:subject
                """
            ),
            {"subject": clerk_user_id},
        ).mappings().first()
        if existing is not None and str(existing["user_id"]) != str(row["user_id"]):
            raise security_error("PERMISSION_DENIED")

        now = datetime.now(UTC)
        try:
            if existing is None:
                self.s.execute(
                    text(
                        """
                        INSERT INTO security.external_identities
                        (external_identity_id,user_id,provider,provider_subject,status,linked_at_utc)
                        VALUES (:id,:user_id,'CLERK',:subject,'ACTIVE',:now)
                        """
                    ),
                    {
                        "id": str(uuid4()),
                        "user_id": str(row["user_id"]),
                        "subject": clerk_user_id,
                        "now": now,
                    },
                )
            self.s.execute(
                text(
                    """
                    UPDATE security.platform_user_onboarding_requests
                    SET clerk_user_id=:clerk_user_id,status='PENDING_ADMIN_APPROVAL'
                    WHERE onboarding_request_id=:request_id
                    """
                ),
                {"request_id": onboarding_request_id, "clerk_user_id": clerk_user_id},
            )
            self._security_event(
                user_id=str(row["user_id"]),
                event_type="CLERK_IDENTITY_BOUND",
                outcome="PENDING_ADMIN_APPROVAL",
                reason_code="SECURITY_ADMIN_APPROVAL_REQUIRED",
                source_ip=source_ip,
                correlation_id=correlation_id,
                now=now,
            )
            self.s.commit()
        except Exception:
            self.s.rollback()
            raise

        # Security is authoritative for activation. A bound-but-pending Clerk account is banned so
        # it cannot continue signing in until Security Admin explicitly activates the USER.
        clerk.ban_user(clerk_user_id)
        return {
            "onboardingRequestId": onboarding_request_id,
            "userId": str(row["user_id"]),
            "status": "PENDING_ADMIN_APPROVAL",
        }

    # ------------------------------------------------------------------
    # Global USER registry / lifecycle
    # ------------------------------------------------------------------
    def list_users(self, status: str | None = None) -> list[dict[str, Any]]:
        where = "WHERE u.status=:status" if status else ""
        rows = self.s.execute(
            text(
                f"""
                SELECT u.user_id,u.display_name,u.primary_email,u.primary_mobile,u.status,
                       u.created_at_utc,u.updated_at_utc,e.provider_subject AS clerk_user_id,
                       r.onboarding_request_id,r.status AS onboarding_status
                FROM security.users u
                LEFT JOIN security.external_identities e
                  ON e.user_id=u.user_id AND e.provider='CLERK' AND e.status='ACTIVE'
                LEFT JOIN security.platform_user_onboarding_requests r ON r.user_id=u.user_id
                {where}
                ORDER BY u.created_at_utc DESC
                """
            ),
            {"status": status} if status else {},
        ).mappings()
        return [dict(row) for row in rows]

    def set_user_status(
        self,
        *,
        user_id: str,
        new_status: str,
        actor_user_id: str,
        reason: str | None,
        correlation_id: str,
        clerk: ClerkBackendClient,
    ) -> dict[str, Any]:
        target = new_status.upper()
        if target not in {"ACTIVE", "SUSPENDED", "DISABLED", "EXITED"}:
            raise ValueError("Unsupported USER status")
        row = self.s.execute(
            text(
                """
                SELECT u.user_id,u.status,e.provider_subject AS clerk_user_id,
                       r.onboarding_request_id,r.status AS onboarding_status
                FROM security.users u
                LEFT JOIN security.external_identities e
                  ON e.user_id=u.user_id AND e.provider='CLERK' AND e.status='ACTIVE'
                LEFT JOIN security.platform_user_onboarding_requests r ON r.user_id=u.user_id
                WHERE u.user_id=:user_id
                """
            ),
            {"user_id": user_id},
        ).mappings().first()
        if row is None:
            raise LookupError("USER not found")
        current = str(row["status"])
        clerk_user_id = str(row["clerk_user_id"]) if row["clerk_user_id"] is not None else None

        if target == "ACTIVE":
            if current not in {"PENDING", "INVITED", "SUSPENDED", "DISABLED"}:
                raise ValueError(f"USER cannot transition from {current} to ACTIVE")
            if clerk_user_id is None:
                raise ValueError("USER has no active Clerk identity")
            # Fail closed: if Clerk cannot be enabled, Security does not activate the USER.
            clerk.unban_user(clerk_user_id)
        else:
            if current == "EXITED":
                raise ValueError("EXITED USER is terminal")
            if current == target:
                return self._user_by_id(user_id)

        now = datetime.now(UTC)
        try:
            self.s.execute(
                text(
                    """
                    UPDATE security.users SET status=:status,updated_at_utc=:now
                    WHERE user_id=:user_id
                    """
                ),
                {"status": target, "now": now, "user_id": user_id},
            )
            if target != "ACTIVE":
                self.s.execute(
                    text(
                        """
                        UPDATE security.access_sessions
                        SET status='REVOKED',last_activity_at_utc=:now
                        WHERE principal_id=:user_id AND actor_type='USER' AND status='ACTIVE'
                        """
                    ),
                    {"user_id": user_id, "now": now},
                )
            if target == "ACTIVE" and row["onboarding_request_id"] is not None:
                self.s.execute(
                    text(
                        """
                        UPDATE security.platform_user_onboarding_requests
                        SET status='APPROVED',reviewed_by_user_id=:actor,
                            reviewed_at_utc=:now,review_reason=:reason
                        WHERE user_id=:user_id
                          AND status='PENDING_ADMIN_APPROVAL'
                        """
                    ),
                    {
                        "actor": actor_user_id,
                        "now": now,
                        "reason": reason,
                        "user_id": user_id,
                    },
                )
            self._admin_audit(
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
                operation_key="security.user.status.change",
                resource_type="USER",
                resource_id=user_id,
                after={"status": target, "previousStatus": current, "reason": reason},
                now=now,
            )
            self.s.commit()
        except Exception:
            self.s.rollback()
            raise

        # For deactivation the Security state is committed first, so access stays denied even if
        # Clerk lifecycle synchronization fails. The caller receives the Clerk error for follow-up.
        if target != "ACTIVE" and clerk_user_id is not None:
            clerk.ban_user(clerk_user_id)
        return self._user_by_id(user_id)

    def precheck(self, email: str) -> bool:
        clean_email = email.strip().lower()
        row = self.s.execute(
            text(
                """
                SELECT 1
                FROM security.users u
                JOIN security.security_principals p ON p.principal_id=u.user_id
                JOIN security.external_identities e
                  ON e.user_id=u.user_id AND e.provider='CLERK' AND e.status='ACTIVE'
                WHERE lower(u.primary_email)=:email
                  AND u.status='ACTIVE'
                  AND p.status='ACTIVE'
                """
            ),
            {"email": clean_email},
        ).first()
        return row is not None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _require_valid_onboarding_key(self, supplied: str) -> None:
        row = self.s.execute(
            text(
                """
                SELECT key_hash,status FROM security.platform_user_onboarding_settings
                WHERE singleton_id=1
                """
            )
        ).mappings().first()
        if row is None or row["status"] != "ACTIVE":
            raise security_error("PERMISSION_DENIED")
        try:
            valid = _HASHER.verify(str(row["key_hash"]), supplied)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            valid = False
        if not valid:
            raise security_error("PERMISSION_DENIED")

    def _validate_onboarding_key(self, value: str) -> str:
        clean = value.strip()
        if len(clean) < 8 or len(clean) > 64:
            raise ValueError("Onboarding key must be between 8 and 64 characters")
        if any(char not in _ALLOWED_ONBOARDING_CHARS for char in clean):
            raise ValueError("Onboarding key contains unsupported characters")
        return clean

    def _aes_key(self) -> bytes:
        value = self.settings.security_user_onboarding_key_encryption_key.strip()
        if not value:
            raise RuntimeError("SECURITY_USER_ONBOARDING_KEY_ENCRYPTION_KEY is not configured")
        try:
            padded = value + "=" * (-len(value) % 4)
            decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        except (ValueError, UnicodeError) as exc:
            raise RuntimeError("Onboarding-key encryption key is not valid URL-safe base64") from exc
        if len(decoded) != 32:
            raise RuntimeError("Onboarding-key encryption key must decode to exactly 32 bytes")
        return decoded

    def _encrypt_key(self, plaintext: str) -> str:
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(self._aes_key()).encrypt(nonce, plaintext.encode("utf-8"), b"v1.4.2")
        return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")

    def _decrypt_key(self, value: str) -> str:
        raw = base64.urlsafe_b64decode(value.encode("ascii"))
        if len(raw) <= 12:
            raise RuntimeError("Stored onboarding-key ciphertext is invalid")
        plaintext = AESGCM(self._aes_key()).decrypt(raw[:12], raw[12:], b"v1.4.2")
        return plaintext.decode("utf-8")

    def _user_by_id(self, user_id: str) -> dict[str, Any]:
        rows = [row for row in self.list_users() if str(row["user_id"]) == user_id]
        if not rows:
            raise LookupError("USER not found")
        return rows[0]

    def _admin_audit(
        self,
        *,
        actor_user_id: str,
        correlation_id: str,
        operation_key: str,
        resource_type: str,
        resource_id: str,
        after: dict[str, Any],
        now: datetime,
    ) -> None:
        import json

        self.s.execute(
            text(
                """
                INSERT INTO security.admin_change_records
                (admin_change_id,correlation_id,scope_type,actor_user_id,operation_key,
                 resource_type,resource_id,outcome,after_state_json,occurred_at_utc)
                VALUES (:id,:correlation_id,'PLATFORM',:actor,:operation_key,
                        :resource_type,:resource_id,'SUCCESS',CAST(:after AS jsonb),:now)
                """
            ),
            {
                "id": str(uuid4()),
                "correlation_id": correlation_id,
                "actor": actor_user_id,
                "operation_key": operation_key,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "after": json.dumps(after),
                "now": now,
            },
        )

    def _security_event(
        self,
        *,
        user_id: str,
        event_type: str,
        outcome: str,
        reason_code: str,
        source_ip: str,
        correlation_id: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.security_events
                (security_event_id,principal_id,actor_type,event_type,entity_type,entity_id,
                 outcome,reason_code,source_ip,correlation_id,occurred_at_utc)
                VALUES (:id,:user_id,'USER',:event_type,'USER',:user_id,
                        :outcome,:reason_code,CAST(:source_ip AS inet),:correlation_id,:now)
                """
            ),
            {
                "id": str(uuid4()),
                "user_id": user_id,
                "event_type": event_type,
                "outcome": outcome,
                "reason_code": reason_code,
                "source_ip": source_ip,
                "correlation_id": correlation_id,
                "now": now,
            },
        )
