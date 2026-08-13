from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


class DeviceSessionLifecycleRepository:
    """PostgreSQL primitives for the approved USER device/session lifecycle."""

    def __init__(self, session: Session) -> None:
        self.s = session

    def create_pending_enrollment(
        self,
        *,
        enrollment_request_id: str,
        device_id: str,
        tenant_id: str,
        user_id: str,
        device_type: str,
        platform: str,
        device_name: str | None,
        device_model: str | None,
        os_version: str | None,
        browser_name: str | None,
        browser_version: str | None,
        app_version: str | None,
        platform_device_identifier: str | None,
        mac_address: str | None,
        source_ip: str,
        latitude: float | None,
        longitude: float | None,
        accuracy_meters: float | None,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.registered_devices
                (device_id,tenant_id,user_id,device_type,platform,device_name,device_model,
                 os_version,browser_name,browser_version,app_version,
                 platform_device_identifier,mac_address,first_seen_ip,last_seen_ip,status,
                 registered_at_utc,last_seen_at_utc)
                VALUES
                (:device_id,:tenant_id,:user_id,:device_type,:platform,:device_name,
                 :device_model,:os_version,:browser_name,:browser_version,:app_version,
                 :platform_device_identifier,:mac_address,:source_ip,:source_ip,'PENDING',
                 :now,:now)
                """
            ),
            {
                "device_id": device_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "device_type": device_type,
                "platform": platform,
                "device_name": device_name,
                "device_model": device_model,
                "os_version": os_version,
                "browser_name": browser_name,
                "browser_version": browser_version,
                "app_version": app_version,
                "platform_device_identifier": platform_device_identifier,
                "mac_address": mac_address,
                "source_ip": source_ip,
                "now": now,
            },
        )
        self.s.execute(
            text(
                """
                INSERT INTO security.device_enrollment_requests
                (enrollment_request_id,tenant_id,user_id,device_id,source_ip,latitude,
                 longitude,accuracy_meters,requested_at_utc,status)
                VALUES
                (:enrollment_request_id,:tenant_id,:user_id,:device_id,:source_ip,
                 :latitude,:longitude,:accuracy_meters,:now,'PENDING')
                """
            ),
            {
                "enrollment_request_id": enrollment_request_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "device_id": device_id,
                "source_ip": source_ip,
                "latitude": latitude,
                "longitude": longitude,
                "accuracy_meters": accuracy_meters,
                "now": now,
            },
        )

    def lock_membership_for_device_limit(
        self,
        *,
        tenant_id: str,
        user_id: str,
    ) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT membership_id,status,authorization_version
                FROM security.tenant_memberships
                WHERE tenant_id=:tenant_id AND user_id=:user_id
                FOR UPDATE
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id},
        ).mappings().first()
        return dict(row) if row else None

    def count_active_devices(self, *, tenant_id: str, user_id: str) -> int:
        value = self.s.execute(
            text(
                """
                SELECT count(*)
                FROM security.registered_devices
                WHERE tenant_id=:tenant_id
                  AND user_id=:user_id
                  AND status='ACTIVE'
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id},
        ).scalar_one()
        return int(value)

    def pending_device_for_update(
        self,
        *,
        tenant_id: str,
        user_id: str,
        device_id: str,
    ) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT *
                FROM security.registered_devices
                WHERE tenant_id=:tenant_id
                  AND user_id=:user_id
                  AND device_id=:device_id
                  AND status='PENDING'
                FOR UPDATE
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id, "device_id": device_id},
        ).mappings().first()
        return dict(row) if row else None

    def activate_pending_device(
        self,
        *,
        enrollment_request_id: str,
        tenant_id: str,
        user_id: str,
        device_id: str,
        decided_by_user_id: str,
        decided_at: datetime,
    ) -> bool:
        request_row = self.s.execute(
            text(
                """
                SELECT enrollment_request_id
                FROM security.device_enrollment_requests
                WHERE enrollment_request_id=:enrollment_request_id
                  AND tenant_id=:tenant_id
                  AND user_id=:user_id
                  AND device_id=:device_id
                  AND status='PENDING'
                FOR UPDATE
                """
            ),
            {
                "enrollment_request_id": enrollment_request_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "device_id": device_id,
            },
        ).first()
        if request_row is None:
            return False

        device_row = self.s.execute(
            text(
                """
                UPDATE security.registered_devices
                SET status='ACTIVE',
                    approved_by_user_id=:decided_by_user_id,
                    approved_at_utc=:decided_at
                WHERE tenant_id=:tenant_id
                  AND user_id=:user_id
                  AND device_id=:device_id
                  AND status='PENDING'
                RETURNING device_id
                """
            ),
            {
                "tenant_id": tenant_id,
                "user_id": user_id,
                "device_id": device_id,
                "decided_by_user_id": decided_by_user_id,
                "decided_at": decided_at,
            },
        ).first()
        if device_row is None:
            return False

        updated_request = self.s.execute(
            text(
                """
                UPDATE security.device_enrollment_requests
                SET status='APPROVED',
                    decided_by_user_id=:decided_by_user_id,
                    decided_at_utc=:decided_at
                WHERE enrollment_request_id=:enrollment_request_id
                  AND tenant_id=:tenant_id
                  AND user_id=:user_id
                  AND device_id=:device_id
                  AND status='PENDING'
                RETURNING enrollment_request_id
                """
            ),
            {
                "enrollment_request_id": enrollment_request_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "device_id": device_id,
                "decided_by_user_id": decided_by_user_id,
                "decided_at": decided_at,
            },
        ).first()
        return updated_request is not None

    def user_session_for_update(
        self,
        *,
        access_session_id: str,
        tenant_id: str,
        user_id: str,
    ) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT *
                FROM security.access_sessions
                WHERE access_session_id=:access_session_id
                  AND tenant_id=:tenant_id
                  AND principal_id=:user_id
                  AND actor_type='USER'
                FOR UPDATE
                """
            ),
            {
                "access_session_id": access_session_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
            },
        ).mappings().first()
        return dict(row) if row else None

    def revoke_active_user_session(
        self,
        *,
        access_session_id: str,
        tenant_id: str,
        user_id: str,
    ) -> bool:
        row = self.s.execute(
            text(
                """
                UPDATE security.access_sessions
                SET status='REVOKED'
                WHERE access_session_id=:access_session_id
                  AND tenant_id=:tenant_id
                  AND principal_id=:user_id
                  AND actor_type='USER'
                  AND status='ACTIVE'
                RETURNING access_session_id
                """
            ),
            {
                "access_session_id": access_session_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
            },
        ).first()
        return row is not None

    def commit(self) -> None:
        self.s.commit()

    def rollback(self) -> None:
        self.s.rollback()
