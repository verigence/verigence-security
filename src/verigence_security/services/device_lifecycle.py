from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from verigence_security.core.errors import security_error
from verigence_security.repositories.device_session_repository import (
    DeviceSessionLifecycleRepository,
)
from verigence_security.repositories.security_repository import SecurityRepository


class DeviceApprovalService:
    """Approve a PENDING USER device under the Tenant-configured active-device limit."""

    def __init__(self, session: Session) -> None:
        self.lifecycle = DeviceSessionLifecycleRepository(session)
        self.security = SecurityRepository(session)

    def approve_pending_device(
        self,
        *,
        enrollment_request_id: str,
        tenant_id: str,
        user_id: str,
        device_id: str,
        decided_by_user_id: str,
        decided_at: datetime,
    ) -> bool:
        try:
            membership = self.lifecycle.lock_membership_for_device_limit(
                tenant_id=tenant_id,
                user_id=user_id,
            )
            if membership is None:
                raise security_error("TENANT_MEMBERSHIP_REQUIRED")
            if membership["status"] != "ACTIVE":
                raise security_error("TENANT_MEMBERSHIP_INACTIVE")

            policy = self.security.get_tenant_policy(tenant_id)
            pending = self.lifecycle.pending_device_for_update(
                tenant_id=tenant_id,
                user_id=user_id,
                device_id=device_id,
            )
            if pending is None:
                self.lifecycle.rollback()
                return False

            active_devices = self.lifecycle.count_active_devices(
                tenant_id=tenant_id,
                user_id=user_id,
            )
            if active_devices >= policy.max_active_devices_per_user:
                raise security_error("DEVICE_LIMIT_REACHED")

            activated = self.lifecycle.activate_pending_device(
                enrollment_request_id=enrollment_request_id,
                tenant_id=tenant_id,
                user_id=user_id,
                device_id=device_id,
                decided_by_user_id=decided_by_user_id,
                decided_at=decided_at,
            )
            if not activated:
                self.lifecycle.rollback()
                return False

            self.lifecycle.commit()
            return True
        except Exception:
            self.lifecycle.rollback()
            raise
