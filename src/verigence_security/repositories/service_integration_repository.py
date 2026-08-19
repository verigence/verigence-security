from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.orm import Session

from verigence_security.core.errors import security_error


@dataclass(frozen=True, slots=True)
class ServiceIntegrationCredential:
    principal_id: str
    integration_key: str
    credential_id: str
    client_id: str
    secret_hash: str


class ServiceIntegrationRepository:
    def __init__(self, session: Session) -> None:
        self.s = session

    def active_credential(self, client_id: str, now: datetime) -> ServiceIntegrationCredential:
        row = self.s.execute(
            text(
                """
                SELECT c.credential_id,c.client_id,c.secret_hash,c.status AS credential_status,
                       c.valid_from_utc,c.valid_to_utc,
                       p.principal_id,p.actor_type,p.status AS principal_status,
                       si.integration_key
                FROM security.principal_credentials c
                JOIN security.security_principals p ON p.principal_id=c.principal_id
                JOIN security.service_integrations si ON si.principal_id=p.principal_id
                WHERE c.client_id=:client_id
                """
            ),
            {"client_id": client_id},
        ).mappings().first()
        if row is None:
            raise security_error("MACHINE_CREDENTIAL_INVALID")
        if row["actor_type"] != "SERVICE_INTEGRATION":
            raise security_error("ACTOR_TYPE_NOT_ALLOWED")
        if row["principal_status"] != "ACTIVE":
            raise security_error("PRINCIPAL_NOT_ACTIVE")
        valid_from = row["valid_from_utc"]
        valid_to = row["valid_to_utc"]
        if row["credential_status"] == "EXPIRED" or (valid_to is not None and valid_to <= now):
            raise security_error("MACHINE_CREDENTIAL_EXPIRED")
        if row["credential_status"] != "ACTIVE" or valid_from > now:
            raise security_error("MACHINE_CREDENTIAL_INVALID")
        return ServiceIntegrationCredential(
            principal_id=str(row["principal_id"]),
            integration_key=str(row["integration_key"]),
            credential_id=str(row["credential_id"]),
            client_id=str(row["client_id"]),
            secret_hash=str(row["secret_hash"]),
        )

    def audience_is_registered(self, audience: str) -> bool:
        if audience == "security":
            return True
        return (
            self.s.execute(
                text(
                    """
                    SELECT 1
                    FROM security.permissions
                    WHERE module_key=:audience AND status='ACTIVE'
                    LIMIT 1
                    """
                ),
                {"audience": audience},
            ).first()
            is not None
        )

    def mark_credential_used(self, credential_id: str, now: datetime) -> None:
        self.s.execute(
            text(
                """
                UPDATE security.principal_credentials
                SET last_used_at_utc=:now
                WHERE credential_id=:credential_id
                """
            ),
            {"credential_id": credential_id, "now": now},
        )

    def commit(self) -> None:
        self.s.commit()

    def rollback(self) -> None:
        self.s.rollback()
