from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from verigence_security.core.errors import security_error
from verigence_security.repositories.service_integration_repository import (
    ServiceIntegrationCredential,
    ServiceIntegrationRepository,
)
from verigence_security.services.token_service import ServiceTokenClaims, TokenService

SERVICE_TOKEN_TTL = timedelta(hours=4)
_PASSWORD_HASHER = PasswordHasher()


@dataclass(frozen=True, slots=True)
class ServiceTokenResult:
    access_token: str
    expires_at_utc: datetime
    audience: str
    subject: str


class ServiceIntegrationTokenService:
    def __init__(self, repository: ServiceIntegrationRepository, tokens: TokenService) -> None:
        self.repository = repository
        self.tokens = tokens

    def issue(
        self,
        *,
        client_id: str,
        client_secret: str,
        audience: str,
    ) -> ServiceTokenResult:
        now = datetime.now(UTC)
        target = audience.strip().lower()
        if not target or not self.repository.audience_is_registered(target):
            raise ValueError("Requested ServiceIntegration audience is not registered")

        try:
            credential = self.repository.active_credential(client_id.strip(), now)
            self._verify_secret(credential, client_secret)
            expires_at = now + SERVICE_TOKEN_TTL
            token = self.tokens.issue_service_token(
                ServiceTokenClaims(
                    subject=credential.integration_key,
                    audience=target,
                    issued_at=now,
                    expires_at=expires_at,
                )
            )
            self.repository.mark_credential_used(credential.credential_id, now)
            self.repository.commit()
        except Exception:
            self.repository.rollback()
            raise

        return ServiceTokenResult(
            access_token=token,
            expires_at_utc=expires_at,
            audience=target,
            subject=credential.integration_key,
        )

    @staticmethod
    def _verify_secret(credential: ServiceIntegrationCredential, supplied_secret: str) -> None:
        stored = credential.secret_hash.strip()
        if stored.startswith("$argon2"):
            try:
                _PASSWORD_HASHER.verify(stored, supplied_secret)
            except (VerifyMismatchError, VerificationError, InvalidHashError) as exc:
                raise security_error("MACHINE_CREDENTIAL_INVALID") from exc
            return

        # Migration compatibility only. Existing Phase-1 machine credentials were stored
        # as SHA-256 digests; new/rotated credentials should use Argon2.
        normalized = stored.lower()
        if len(normalized) == 64 and all(char in "0123456789abcdef" for char in normalized):
            supplied = hashlib.sha256(supplied_secret.encode()).hexdigest()
            if hmac.compare_digest(normalized, supplied):
                return
        raise security_error("MACHINE_CREDENTIAL_INVALID")
