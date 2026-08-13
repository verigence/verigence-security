from __future__ import annotations

from verigence_security.core.errors import security_error
from verigence_security.repositories.device_session_repository import (
    DeviceSessionLifecycleRepository,
)
from verigence_security.services.geo import GeoSample


class UserSessionLifecycleService:
    """Deterministic USER refresh/revoke boundaries frozen by Security v1.3."""

    def __init__(self, repository: DeviceSessionLifecycleRepository) -> None:
        self.repository = repository

    @staticmethod
    def require_refresh_geo(geo: GeoSample | None) -> GeoSample:
        if geo is None:
            raise security_error("GEO_REQUIRED")
        return geo

    def revoke(
        self,
        *,
        access_session_id: str,
        tenant_id: str,
        user_id: str,
    ) -> bool:
        try:
            session = self.repository.user_session_for_update(
                access_session_id=access_session_id,
                tenant_id=tenant_id,
                user_id=user_id,
            )
            if session is None or session["status"] != "ACTIVE":
                self.repository.rollback()
                return False

            revoked = self.repository.revoke_active_user_session(
                access_session_id=access_session_id,
                tenant_id=tenant_id,
                user_id=user_id,
            )
            if not revoked:
                self.repository.rollback()
                return False

            self.repository.commit()
            return True
        except Exception:
            self.repository.rollback()
            raise
