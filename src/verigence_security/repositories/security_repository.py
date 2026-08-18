from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

from verigence_security.core.errors import security_error
from verigence_security.core.types import ActorType
from verigence_security.services.geo import LocationCandidate
from verigence_security.services.schedule import ScheduleWindow


@dataclass(frozen=True, slots=True)
class UserContext:
    user_id: str
    user_status: str
    membership_id: str
    membership_status: str
    authorization_version: int


@dataclass(frozen=True, slots=True)
class TenantPolicy:
    max_active_devices_per_user: int
    max_geo_accuracy_meters: float
    max_geo_age_seconds: int
    geo_revalidation_interval_seconds: int
    access_token_ttl_minutes: int
    machine_token_ttl_minutes: int
    session_idle_timeout_minutes: int
    session_max_duration_minutes: int
    vpn_detected_action: str
    vpn_unknown_action: str
    status: str


@dataclass(frozen=True, slots=True)
class MachineCredential:
    principal_id: str
    actor_type: ActorType
    credential_id: str
    client_id: str
    secret_hash: str


class SecurityRepository:
    def __init__(self, session: Session) -> None:
        self.s = session

    def resolve_identity_user(self, provider: str, provider_subject: str) -> str:
        row = self.s.execute(
            text(
                """
                SELECT u.user_id,
                       sp.actor_type AS principal_actor_type,
                       sp.status AS principal_status
                FROM security.external_identities ei
                JOIN security.users u ON u.user_id = ei.user_id
                JOIN security.security_principals sp ON sp.principal_id = u.user_id
                WHERE ei.provider=:provider
                  AND ei.provider_subject=:subject
                  AND ei.status='ACTIVE'
                """
            ),
            {"provider": provider, "subject": provider_subject},
        ).mappings().first()
        if not row:
            raise security_error("USER_NOT_ONBOARDED")
        if row["principal_actor_type"] != "USER":
            raise security_error("ACTOR_TYPE_NOT_ALLOWED")
        if row["principal_status"] != "ACTIVE":
            raise security_error("PRINCIPAL_NOT_ACTIVE")
        return str(row["user_id"])

    def ensure_dev_mock_identity(self, user_id: str) -> str:
        exists = self.s.execute(
            text(
                """
                SELECT 1
                FROM security.users u
                JOIN security.security_principals sp ON sp.principal_id=u.user_id
                WHERE u.user_id=:uid AND sp.actor_type='USER'
                """
            ),
            {"uid": user_id},
        ).first()
        if not exists:
            raise security_error("USER_NOT_ONBOARDED")
        subject = f"devmock:{user_id}"
        row = self.s.execute(
            text(
                """
                SELECT external_identity_id
                FROM security.external_identities
                WHERE provider='DEV_MOCK' AND provider_subject=:subject
                """
            ),
            {"subject": subject},
        ).first()
        if not row:
            self.s.execute(
                text(
                    """
                    INSERT INTO security.external_identities
                    (external_identity_id,user_id,provider,provider_subject,status,linked_at_utc)
                    VALUES (:id,:uid,'DEV_MOCK',:subject,'ACTIVE',:now)
                    """
                ),
                {
                    "id": str(uuid4()),
                    "uid": user_id,
                    "subject": subject,
                    "now": datetime.now(UTC),
                },
            )
            self.s.commit()
        return subject

    def tenant_status(self, tenant_id: str) -> str:
        row = self.s.execute(
            text("SELECT status FROM security.tenants WHERE tenant_id=:tenant_id"),
            {"tenant_id": tenant_id},
        ).first()
        if not row:
            raise security_error("TENANT_NOT_ACTIVE")
        return str(row[0])

    def get_user_context(
        self, user_id: str, tenant_id: str, now: datetime
    ) -> UserContext:
        row = self.s.execute(
            text(
                """
                SELECT u.user_id,
                       u.status AS user_status,
                       m.membership_id,
                       m.status AS membership_status,
                       m.authorization_version,
                       m.valid_from_utc,
                       m.valid_to_utc
                FROM security.users u
                LEFT JOIN security.tenant_memberships m
                  ON m.user_id=u.user_id AND m.tenant_id=:tenant_id
                WHERE u.user_id=:user_id
                """
            ),
            {"user_id": user_id, "tenant_id": tenant_id},
        ).mappings().first()
        if not row:
            raise security_error("USER_NOT_ONBOARDED")
        if row["user_status"] != "ACTIVE":
            raise security_error("USER_NOT_ACTIVE")
        if row["membership_id"] is None:
            raise security_error("TENANT_MEMBERSHIP_REQUIRED")
        if row["membership_status"] != "ACTIVE":
            raise security_error("TENANT_MEMBERSHIP_INACTIVE")
        valid_from = row["valid_from_utc"]
        valid_to = row["valid_to_utc"]
        if valid_from is not None and valid_from > now:
            raise security_error("TENANT_MEMBERSHIP_INACTIVE")
        if valid_to is not None and valid_to <= now:
            raise security_error("TENANT_MEMBERSHIP_INACTIVE")
        return UserContext(
            user_id=str(row["user_id"]),
            user_status=str(row["user_status"]),
            membership_id=str(row["membership_id"]),
            membership_status=str(row["membership_status"]),
            authorization_version=int(row["authorization_version"]),
        )

    def get_tenant_policy(self, tenant_id: str) -> TenantPolicy:
        row = self.s.execute(
            text("SELECT * FROM security.tenant_security_policies WHERE tenant_id=:tenant_id"),
            {"tenant_id": tenant_id},
        ).mappings().first()
        if not row or row["status"] != "ACTIVE":
            raise security_error("TENANT_SECURITY_NOT_READY")
        return TenantPolicy(
            max_active_devices_per_user=int(row["max_active_devices_per_user"]),
            max_geo_accuracy_meters=float(row["max_geo_accuracy_meters"]),
            max_geo_age_seconds=int(row["max_geo_age_seconds"]),
            geo_revalidation_interval_seconds=int(row["geo_revalidation_interval_seconds"]),
            access_token_ttl_minutes=int(row["access_token_ttl_minutes"]),
            machine_token_ttl_minutes=int(row["machine_token_ttl_minutes"]),
            session_idle_timeout_minutes=int(row["session_idle_timeout_minutes"]),
            session_max_duration_minutes=int(row["session_max_duration_minutes"]),
            vpn_detected_action=str(row["vpn_detected_action"]),
            vpn_unknown_action=str(row["vpn_unknown_action"]),
            status=str(row["status"]),
        )

    def machine_credential(self, client_id: str, now: datetime) -> MachineCredential:
        row = self.s.execute(
            text(
                """
                SELECT c.credential_id,c.client_id,c.secret_hash,c.status AS credential_status,
                       c.valid_from_utc,c.valid_to_utc,
                       p.principal_id,p.actor_type,p.status AS principal_status
                FROM security.principal_credentials c
                JOIN security.security_principals p ON p.principal_id=c.principal_id
                WHERE c.client_id=:client_id
                """
            ),
            {"client_id": client_id},
        ).mappings().first()
        if row is None:
            raise security_error("MACHINE_CREDENTIAL_INVALID")
        if row["principal_status"] != "ACTIVE":
            raise security_error("PRINCIPAL_NOT_ACTIVE")
        try:
            actor_type = ActorType(str(row["actor_type"]))
        except ValueError as exc:
            raise security_error("ACTOR_TYPE_NOT_ALLOWED") from exc
        if actor_type not in {ActorType.SYSTEM, ActorType.SERVICE_INTEGRATION}:
            raise security_error("ACTOR_TYPE_NOT_ALLOWED")

        valid_from = row["valid_from_utc"]
        valid_to = row["valid_to_utc"]
        if row["credential_status"] == "EXPIRED" or (valid_to is not None and valid_to <= now):
            raise security_error("MACHINE_CREDENTIAL_EXPIRED")
        if row["credential_status"] != "ACTIVE" or valid_from > now:
            raise security_error("MACHINE_CREDENTIAL_INVALID")

        return MachineCredential(
            principal_id=str(row["principal_id"]),
            actor_type=actor_type,
            credential_id=str(row["credential_id"]),
            client_id=str(row["client_id"]),
            secret_hash=str(row["secret_hash"]),
        )

    def machine_permissions(
        self,
        principal_id: str,
        tenant_id: str,
        now: datetime,
    ) -> list[str]:
        scope = self.s.execute(
            text(
                """
                SELECT 1
                FROM security.principal_tenant_scopes
                WHERE principal_id=:principal_id
                  AND tenant_id=:tenant_id
                  AND status='ACTIVE'
                  AND (valid_from_utc IS NULL OR valid_from_utc<=:now)
                  AND (valid_to_utc IS NULL OR valid_to_utc>:now)
                """
            ),
            {"principal_id": principal_id, "tenant_id": tenant_id, "now": now},
        ).first()
        if scope is None:
            raise security_error("PRINCIPAL_TENANT_SCOPE_REQUIRED")

        rows = self.s.execute(
            text(
                """
                SELECT DISTINCT p.permission_key
                FROM security.principal_permission_grants g
                JOIN security.permissions p
                  ON p.permission_key=g.permission_key
                 AND p.status='ACTIVE'
                WHERE g.principal_id=:principal_id
                  AND g.tenant_id=:tenant_id
                  AND g.status='ACTIVE'
                ORDER BY p.permission_key
                """
            ),
            {"principal_id": principal_id, "tenant_id": tenant_id},
        ).all()
        return [str(row[0]) for row in rows]

    def create_machine_session(
        self,
        *,
        principal_id: str,
        actor_type: ActorType,
        tenant_id: str,
        credential_id: str,
        source_ip: str,
        expires_at: datetime,
        now: datetime,
    ) -> str:
        session_id = str(uuid4())
        self.s.execute(
            text(
                """
                INSERT INTO security.access_sessions
                (access_session_id,tenant_id,principal_id,actor_type,membership_id,device_id,
                 location_id,credential_id,authentication_source,authorization_version,source_ip,
                 vpn_status,started_at_utc,expires_at_utc,last_activity_at_utc,
                 last_geo_validated_at_utc,status)
                VALUES
                (:session_id,:tenant_id,:principal_id,:actor_type,NULL,NULL,
                 NULL,:credential_id,'CLIENT_CREDENTIAL',NULL,:source_ip,
                 NULL,:now,:expires_at,:now,NULL,'ACTIVE')
                """
            ),
            {
                "session_id": session_id,
                "tenant_id": tenant_id,
                "principal_id": principal_id,
                "actor_type": actor_type.value,
                "credential_id": credential_id,
                "source_ip": source_ip,
                "now": now,
                "expires_at": expires_at,
            },
        )
        return session_id

    def mark_machine_credential_used(self, credential_id: str, now: datetime) -> None:
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

    def lock_active_device(self, user_id: str, tenant_id: str, device_id: str) -> dict[str, Any]:
        row = self.s.execute(
            text(
                """
                SELECT *
                FROM security.registered_devices
                WHERE tenant_id=:tenant_id AND user_id=:user_id AND device_id=:device_id
                FOR UPDATE
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id, "device_id": device_id},
        ).mappings().first()
        if not row:
            raise security_error("DEVICE_NOT_REGISTERED")
        if row["status"] == "PENDING":
            raise security_error("DEVICE_APPROVAL_REQUIRED")
        if row["status"] != "ACTIVE":
            raise security_error("DEVICE_NOT_ACTIVE")
        return dict(row)

    def assigned_locations(
        self,
        user_id: str,
        tenant_id: str,
        now: datetime,
    ) -> list[LocationCandidate]:
        rows = self.s.execute(
            text(
                """
                SELECT l.location_id,
                       l.latitude,
                       l.longitude,
                       l.allowed_radius_meters,
                       l.timezone_iana,
                       a.schedule_id
                FROM security.user_location_assignments a
                JOIN security.tenant_locations l
                  ON l.tenant_id=a.tenant_id AND l.location_id=a.location_id
                WHERE a.tenant_id=:tenant_id
                  AND a.user_id=:user_id
                  AND a.status='ACTIVE'
                  AND l.status='ACTIVE'
                  AND (a.valid_from_utc IS NULL OR a.valid_from_utc<=:now)
                  AND (a.valid_to_utc IS NULL OR a.valid_to_utc>:now)
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id, "now": now},
        ).mappings().all()
        return [
            LocationCandidate(
                location_id=str(row["location_id"]),
                latitude=float(row["latitude"]),
                longitude=float(row["longitude"]),
                allowed_radius_meters=float(row["allowed_radius_meters"]),
                timezone_iana=str(row["timezone_iana"]),
                schedule_id=str(row["schedule_id"]),
            )
            for row in rows
        ]

    def ensure_active_schedule(self, tenant_id: str, schedule_id: str) -> None:
        row = self.s.execute(
            text(
                """
                SELECT status
                FROM security.access_schedules
                WHERE tenant_id=:tenant_id AND schedule_id=:schedule_id
                """
            ),
            {"tenant_id": tenant_id, "schedule_id": schedule_id},
        ).first()
        if not row or row[0] != "ACTIVE":
            raise security_error("ACCESS_SCHEDULE_MISSING")

    def schedule_windows(self, tenant_id: str, schedule_id: str) -> list[ScheduleWindow]:
        rows = self.s.execute(
            text(
                """
                SELECT iso_day_of_week,start_local_time,end_local_time,crosses_midnight
                FROM security.access_schedule_windows
                WHERE tenant_id=:tenant_id AND schedule_id=:schedule_id AND status='ACTIVE'
                """
            ),
            {"tenant_id": tenant_id, "schedule_id": schedule_id},
        ).mappings().all()
        return [
            ScheduleWindow(
                iso_day_of_week=int(row["iso_day_of_week"]),
                start_local_time=row["start_local_time"],
                end_local_time=row["end_local_time"],
                crosses_midnight=bool(row["crosses_midnight"]),
            )
            for row in rows
        ]

    def active_override_until(
        self,
        tenant_id: str,
        user_id: str,
        location_id: str,
        now: datetime,
    ) -> datetime | None:
        row = self.s.execute(
            text(
                """
                SELECT valid_to_utc
                FROM security.access_schedule_overrides
                WHERE tenant_id=:tenant_id
                  AND user_id=:user_id
                  AND location_id=:location_id
                  AND status='ACTIVE'
                  AND valid_from_utc<=:now
                  AND valid_to_utc>:now
                ORDER BY valid_to_utc DESC
                LIMIT 1
                """
            ),
            {
                "tenant_id": tenant_id,
                "user_id": user_id,
                "location_id": location_id,
                "now": now,
            },
        ).first()
        return row[0] if row else None

    def effective_user_permissions(
        self,
        tenant_id: str,
        user_id: str,
        now: datetime,
    ) -> tuple[list[str], list[str]]:
        rows = self.s.execute(
            text(
                """
                SELECT DISTINCT r.role_key,p.permission_key
                FROM security.user_role_assignments ura
                JOIN security.roles r
                  ON r.tenant_id=ura.tenant_id
                 AND r.role_id=ura.role_id
                 AND r.status='ACTIVE'
                JOIN security.role_permissions rp
                  ON rp.tenant_id=r.tenant_id AND rp.role_id=r.role_id
                JOIN security.permissions p
                  ON p.permission_key=rp.permission_key AND p.status='ACTIVE'
                WHERE ura.tenant_id=:tenant_id
                  AND ura.user_id=:user_id
                  AND ura.status='ACTIVE'
                  AND (ura.valid_from_utc IS NULL OR ura.valid_from_utc<=:now)
                  AND (ura.valid_to_utc IS NULL OR ura.valid_to_utc>:now)
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id, "now": now},
        ).mappings().all()
        roles = sorted({str(row["role_key"]) for row in rows})
        permissions = sorted({str(row["permission_key"]) for row in rows})
        if not permissions:
            raise security_error("ROLE_REQUIRED")
        return roles, permissions

    def expire_stale_user_sessions(
        self,
        tenant_id: str,
        user_id: str,
        device_id: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                UPDATE security.access_sessions
                SET status='EXPIRED'
                WHERE tenant_id=:tenant_id
                  AND principal_id=:user_id
                  AND device_id=:device_id
                  AND actor_type='USER'
                  AND status='ACTIVE'
                  AND expires_at_utc<=:now
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id, "device_id": device_id, "now": now},
        )

    def active_user_session(
        self,
        tenant_id: str,
        user_id: str,
        device_id: str,
    ) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT *
                FROM security.access_sessions
                WHERE tenant_id=:tenant_id
                  AND principal_id=:user_id
                  AND device_id=:device_id
                  AND actor_type='USER'
                  AND status='ACTIVE'
                LIMIT 1
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id, "device_id": device_id},
        ).mappings().first()
        return dict(row) if row else None

    def create_user_session(
        self,
        *,
        tenant_id: str,
        user_id: str,
        membership_id: str,
        device_id: str,
        location_id: str,
        authentication_source: str,
        authz_version: int,
        source_ip: str,
        vpn_status: str,
        expires_at: datetime,
        now: datetime,
    ) -> str:
        session_id = str(uuid4())
        self.s.execute(
            text(
                """
                INSERT INTO security.access_sessions
                (access_session_id,tenant_id,principal_id,actor_type,membership_id,device_id,
                 location_id,authentication_source,authorization_version,source_ip,vpn_status,
                 started_at_utc,expires_at_utc,last_activity_at_utc,
                 last_geo_validated_at_utc,status)
                VALUES
                (:session_id,:tenant_id,:user_id,'USER',:membership_id,:device_id,
                 :location_id,:authentication_source,:authz_version,:source_ip,:vpn_status,
                 :now,:expires_at,:now,:now,'ACTIVE')
                """
            ),
            {
                "session_id": session_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "membership_id": membership_id,
                "device_id": device_id,
                "location_id": location_id,
                "authentication_source": authentication_source,
                "authz_version": authz_version,
                "source_ip": source_ip,
                "vpn_status": vpn_status,
                "now": now,
                "expires_at": expires_at,
            },
        )
        return session_id

    def update_reused_user_session(
        self,
        *,
        access_session_id: str,
        source_ip: str,
        vpn_status: str,
        authorization_version: int,
        expires_at: datetime,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                UPDATE security.access_sessions
                SET source_ip=:source_ip,
                    vpn_status=:vpn_status,
                    authorization_version=:authorization_version,
                    expires_at_utc=:expires_at,
                    last_activity_at_utc=:now,
                    last_geo_validated_at_utc=:now
                WHERE access_session_id=:access_session_id AND status='ACTIVE'
                """
            ),
            {
                "access_session_id": access_session_id,
                "source_ip": source_ip,
                "vpn_status": vpn_status,
                "authorization_version": authorization_version,
                "expires_at": expires_at,
                "now": now,
            },
        )

    def record_evaluation(self, payload: dict[str, Any]) -> None:
        columns = ",".join(payload)
        values = ",".join(f":{key}" for key in payload)
        self.s.execute(
            text(f"INSERT INTO security.access_context_evaluations ({columns}) VALUES ({values})"),
            payload,
        )

    def commit(self) -> None:
        self.s.commit()

    def rollback(self) -> None:
        self.s.rollback()
