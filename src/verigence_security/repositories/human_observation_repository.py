from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session


class HumanObservationRepository:
    """Lean persistence for global-human device/session observation.

    Canonical human login occurs before Tenant/project context exists, therefore these records are
    deliberately global-human evidence and do not replace Tenant-scoped Phase-4 access controls.
    """

    def __init__(self, session: Session) -> None:
        self.s = session

    def register_observation_session(
        self,
        *,
        user_id: str,
        session_id: UUID,
        device_id: UUID,
        device_type: str,
        platform: str,
        device_name: str | None,
        device_model: str | None,
        os_version: str | None,
        browser_name: str | None,
        browser_version: str | None,
        app_version: str | None,
        source_ip: str,
        token_expires_at: datetime,
        now: datetime,
    ) -> dict[str, Any]:
        # A USER row lock serializes simultaneous observation registration for the same account and
        # makes the one-ACTIVE-session rule deterministic without introducing distributed locking.
        self.s.execute(
            text("SELECT user_id FROM security.users WHERE user_id=:user_id FOR UPDATE"),
            {"user_id": user_id},
        ).one()

        self.s.execute(
            text(
                """
                INSERT INTO security.human_devices
                  (user_id,device_id,device_type,platform,device_name,device_model,os_version,
                   browser_name,browser_version,app_version,first_seen_ip,last_seen_ip,status,
                   first_seen_at_utc,last_seen_at_utc)
                VALUES
                  (:user_id,:device_id,:device_type,:platform,:device_name,:device_model,:os_version,
                   :browser_name,:browser_version,:app_version,:source_ip,:source_ip,'ACTIVE',:now,:now)
                ON CONFLICT (user_id,device_id) DO UPDATE SET
                  device_type=EXCLUDED.device_type,
                  platform=EXCLUDED.platform,
                  device_name=COALESCE(EXCLUDED.device_name,security.human_devices.device_name),
                  device_model=COALESCE(EXCLUDED.device_model,security.human_devices.device_model),
                  os_version=COALESCE(EXCLUDED.os_version,security.human_devices.os_version),
                  browser_name=COALESCE(EXCLUDED.browser_name,security.human_devices.browser_name),
                  browser_version=COALESCE(EXCLUDED.browser_version,security.human_devices.browser_version),
                  app_version=COALESCE(EXCLUDED.app_version,security.human_devices.app_version),
                  last_seen_ip=EXCLUDED.last_seen_ip,
                  last_seen_at_utc=EXCLUDED.last_seen_at_utc
                """
            ),
            {
                "user_id": user_id,
                "device_id": str(device_id),
                "device_type": device_type,
                "platform": platform,
                "device_name": device_name,
                "device_model": device_model,
                "os_version": os_version,
                "browser_name": browser_name,
                "browser_version": browser_version,
                "app_version": app_version,
                "source_ip": source_ip,
                "now": now,
            },
        )

        existing = self.s.execute(
            text(
                """
                SELECT status
                FROM security.human_access_sessions
                WHERE access_session_id=:session_id AND user_id=:user_id AND device_id=:device_id
                """
            ),
            {"session_id": str(session_id), "user_id": user_id, "device_id": str(device_id)},
        ).mappings().first()

        superseded = 0
        previous_different_device = False
        if existing is None:
            previous = self.s.execute(
                text(
                    """
                    SELECT device_id
                    FROM security.human_access_sessions
                    WHERE user_id=:user_id AND status='ACTIVE'
                    """
                ),
                {"user_id": user_id},
            ).mappings().all()
            previous_different_device = any(
                str(row["device_id"]) != str(device_id) for row in previous
            )
            superseded = len(previous)
            self.s.execute(
                text(
                    """
                    UPDATE security.human_access_sessions
                    SET status='SUPERSEDED',superseded_at_utc=:now,last_seen_at_utc=:now
                    WHERE user_id=:user_id AND status='ACTIVE'
                    """
                ),
                {"user_id": user_id, "now": now},
            )
            self.s.execute(
                text(
                    """
                    INSERT INTO security.human_access_sessions
                      (access_session_id,user_id,device_id,status,source_ip,started_at_utc,
                       token_expires_at_utc,last_seen_at_utc,geo_status,observation_mode)
                    VALUES
                      (:session_id,:user_id,:device_id,'ACTIVE',:source_ip,:now,
                       :token_expires_at,:now,'PENDING','OBSERVE')
                    """
                ),
                {
                    "session_id": str(session_id),
                    "user_id": user_id,
                    "device_id": str(device_id),
                    "source_ip": source_ip,
                    "now": now,
                    "token_expires_at": token_expires_at,
                },
            )
        else:
            self.s.execute(
                text(
                    """
                    UPDATE security.human_access_sessions
                    SET last_seen_at_utc=:now,source_ip=:source_ip,
                        token_expires_at_utc=GREATEST(token_expires_at_utc,:token_expires_at)
                    WHERE access_session_id=:session_id
                      AND user_id=:user_id
                      AND device_id=:device_id
                    """
                ),
                {
                    "now": now,
                    "source_ip": source_ip,
                    "token_expires_at": token_expires_at,
                    "session_id": str(session_id),
                    "user_id": user_id,
                    "device_id": str(device_id),
                },
            )

        active_devices = int(
            self.s.execute(
                text(
                    """
                    SELECT count(*)
                    FROM security.human_devices
                    WHERE user_id=:user_id AND status='ACTIVE'
                    """
                ),
                {"user_id": user_id},
            ).scalar_one()
        )
        self.s.commit()
        return {
            "previous_session_superseded": superseded > 0,
            "previous_session_different_device": previous_different_device,
            "active_device_count": active_devices,
            "session_status": str(existing["status"]) if existing is not None else "ACTIVE",
        }

    def record_geo(
        self,
        *,
        user_id: str,
        session_id: UUID,
        device_id: UUID,
        geo_status: str,
        latitude: float | None,
        longitude: float | None,
        accuracy_meters: float | None,
        geo_source: str | None,
        captured_at: datetime | None,
        now: datetime,
    ) -> bool:
        updated = self.s.execute(
            text(
                """
                UPDATE security.human_access_sessions
                SET geo_status=:geo_status,
                    latitude=:latitude,
                    longitude=:longitude,
                    accuracy_meters=:accuracy_meters,
                    geo_source=:geo_source,
                    geo_captured_at_utc=:captured_at,
                    last_seen_at_utc=:now
                WHERE access_session_id=:session_id
                  AND user_id=:user_id
                  AND device_id=:device_id
                RETURNING access_session_id
                """
            ),
            {
                "geo_status": geo_status,
                "latitude": latitude,
                "longitude": longitude,
                "accuracy_meters": accuracy_meters,
                "geo_source": geo_source,
                "captured_at": captured_at,
                "now": now,
                "session_id": str(session_id),
                "user_id": user_id,
                "device_id": str(device_id),
            },
        ).scalar_one_or_none()
        self.s.commit()
        return updated is not None

    def session_status(
        self,
        *,
        user_id: str,
        session_id: UUID,
        device_id: UUID,
    ) -> str | None:
        value = self.s.execute(
            text(
                """
                SELECT status
                FROM security.human_access_sessions
                WHERE access_session_id=:session_id
                  AND user_id=:user_id
                  AND device_id=:device_id
                """
            ),
            {"session_id": str(session_id), "user_id": user_id, "device_id": str(device_id)},
        ).scalar_one_or_none()
        return str(value) if value is not None else None

    def touch_active_session(
        self,
        *,
        user_id: str,
        session_id: UUID,
        device_id: UUID,
        token_expires_at: datetime,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                UPDATE security.human_access_sessions
                SET last_seen_at_utc=:now,token_expires_at_utc=:token_expires_at
                WHERE access_session_id=:session_id
                  AND user_id=:user_id
                  AND device_id=:device_id
                  AND status='ACTIVE'
                """
            ),
            {
                "now": now,
                "token_expires_at": token_expires_at,
                "session_id": str(session_id),
                "user_id": user_id,
                "device_id": str(device_id),
            },
        )
        self.s.commit()
