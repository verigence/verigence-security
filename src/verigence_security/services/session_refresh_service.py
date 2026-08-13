from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from verigence_security.adapters.network_risk import NetworkRiskAdapter
from verigence_security.core.errors import security_error
from verigence_security.core.types import ActorType, PolicyAction, VpnStatus
from verigence_security.repositories.security_repository import SecurityRepository
from verigence_security.repositories.session_refresh_repository import (
    SessionRefreshRepository,
)
from verigence_security.services.geo import GeoSample, match_location, validate_geo
from verigence_security.services.permissions import validate_permissions
from verigence_security.services.schedule import evaluate_schedule
from verigence_security.services.session_lifecycle import UserSessionLifecycleService
from verigence_security.services.token_service import AccessTokenClaims, TokenService


@dataclass(frozen=True, slots=True)
class RefreshedUserSession:
    access_session_id: str
    access_token: str
    expires_at_utc: datetime
    tenant_id: str
    user_id: str
    device_id: str
    location_id: str
    roles: tuple[str, ...]
    permissions: tuple[str, ...]


class UserSessionRefreshService:
    """Re-evaluate and refresh an existing ACTIVE USER session."""

    def __init__(
        self,
        *,
        security: SecurityRepository,
        refresh: SessionRefreshRepository,
        network: NetworkRiskAdapter,
        tokens: TokenService,
    ) -> None:
        self.security = security
        self.refresh_repo = refresh
        self.network = network
        self.tokens = tokens

    def refresh(
        self,
        *,
        user_id: str,
        tenant_id: str,
        access_session_id: str,
        geo: GeoSample | None,
        source_ip: str,
        correlation_id: str,
    ) -> RefreshedUserSession:
        geo = UserSessionLifecycleService.require_refresh_geo(geo)
        now = datetime.now(UTC)

        # Keep provider calls outside the database transaction/row-lock window.
        risk = self.network.evaluate(source_ip, correlation_id)

        try:
            tenant_status = self.security.tenant_status(tenant_id)
            if tenant_status in {"OFFBOARDING", "OFFBOARDED"}:
                raise security_error("TENANT_OFFBOARDING")
            if tenant_status != "ACTIVE":
                raise security_error("TENANT_NOT_ACTIVE")

            context = self.security.get_user_context(user_id, tenant_id, now)
            policy = self.security.get_tenant_policy(tenant_id)

            # Read only enough session context to discover the canonical device lock target.
            # Do not lock the session row yet: create/reuse already uses device→session ordering,
            # so refresh must use the same order to avoid a device↔session deadlock cycle.
            observed_session = self.refresh_repo.user_session(
                access_session_id=access_session_id,
                tenant_id=tenant_id,
                user_id=user_id,
            )
            if observed_session is None or observed_session["status"] != "ACTIVE":
                raise security_error("SESSION_REVOKED")

            device_id = str(observed_session["device_id"])
            self.security.lock_active_device(user_id, tenant_id, device_id)

            # Re-read under the session row lock after the device lock. A concurrent revoke or
            # session transition between the initial read and this lock must be observed here.
            session = self.refresh_repo.user_session_for_update(
                access_session_id=access_session_id,
                tenant_id=tenant_id,
                user_id=user_id,
            )
            if session is None or session["status"] != "ACTIVE":
                raise security_error("SESSION_REVOKED")
            if str(session["device_id"]) != device_id:
                # Device identity is not expected to move between sessions. Fail closed if the
                # persisted context changed between the discovery read and the locked re-read.
                raise security_error("SESSION_REVOKED")

            current_expiry = session["expires_at_utc"]
            if current_expiry.tzinfo is None:
                current_expiry = current_expiry.replace(tzinfo=UTC)
            if current_expiry.astimezone(UTC) <= now:
                raise security_error("AUTH_TOKEN_EXPIRED")

            validate_geo(
                geo,
                max_accuracy_meters=policy.max_geo_accuracy_meters,
                max_age_seconds=policy.max_geo_age_seconds,
                now=now,
            )
            location, distance = match_location(
                geo,
                self.security.assigned_locations(user_id, tenant_id, now),
            )

            self.security.ensure_active_schedule(tenant_id, location.schedule_id)
            windows = self.security.schedule_windows(tenant_id, location.schedule_id)
            override = self.security.active_override_until(
                tenant_id,
                user_id,
                location.location_id,
                now,
            )
            schedule = evaluate_schedule(
                now_utc=now,
                timezone_iana=location.timezone_iana,
                windows=windows,
                override_until_utc=override,
            )

            if (
                risk.vpn_status == VpnStatus.DETECTED
                and policy.vpn_detected_action == PolicyAction.DENY.value
            ):
                raise security_error("VPN_ACCESS_DENIED")
            if (
                risk.vpn_status == VpnStatus.UNKNOWN
                and policy.vpn_unknown_action == PolicyAction.DENY.value
            ):
                raise security_error("NETWORK_RISK_UNKNOWN_DENIED")

            roles, database_permissions = self.security.effective_user_permissions(
                tenant_id,
                user_id,
                now,
            )
            permissions = validate_permissions(database_permissions)

            started_at = session["started_at_utc"]
            if started_at.tzinfo is None:
                started_at = started_at.replace(tzinfo=UTC)
            session_max_end = started_at.astimezone(UTC) + timedelta(
                minutes=policy.session_max_duration_minutes
            )
            expiry = min(
                now + timedelta(minutes=policy.access_token_ttl_minutes),
                now + timedelta(seconds=policy.geo_revalidation_interval_seconds),
                session_max_end,
                schedule.authorized_until_utc,
            )
            if expiry <= now:
                raise security_error("AUTH_TOKEN_EXPIRED")

            updated = self.refresh_repo.update_active_session_context(
                access_session_id=access_session_id,
                tenant_id=tenant_id,
                user_id=user_id,
                location_id=location.location_id,
                source_ip=source_ip,
                vpn_status=risk.vpn_status.value,
                authorization_version=context.authorization_version,
                expires_at=expiry,
                now=now,
            )
            if not updated:
                raise security_error("SESSION_REVOKED")

            self.security.record_evaluation(
                {
                    "evaluation_id": str(uuid4()),
                    "access_session_id": access_session_id,
                    "tenant_id": tenant_id,
                    "principal_id": user_id,
                    "actor_type": ActorType.USER.value,
                    "supplied_latitude": geo.latitude,
                    "supplied_longitude": geo.longitude,
                    "supplied_accuracy_meters": geo.accuracy_meters,
                    "geo_captured_at_utc": geo.captured_at,
                    "geo_source": geo.source.value,
                    "geo_integrity_status": geo.integrity_status.value,
                    "geo_integrity_reason": geo.integrity_reason,
                    "matched_location_id": location.location_id,
                    "matched_distance_meters": distance,
                    "evaluated_local_time": schedule.local_time.replace(tzinfo=None),
                    "evaluated_timezone": location.timezone_iana,
                    "schedule_id": location.schedule_id,
                    "source_ip": source_ip,
                    "vpn_status": risk.vpn_status.value,
                    "decision": "ALLOW",
                    "decision_reason_code": "ACCESS_GRANTED",
                    "correlation_id": correlation_id,
                    "evaluated_at_utc": now,
                }
            )

            token = self.tokens.issue(
                AccessTokenClaims(
                    principal_id=user_id,
                    actor_type=ActorType.USER,
                    tenant_id=tenant_id,
                    access_session_id=access_session_id,
                    permissions=tuple(permissions),
                    roles=tuple(roles),
                    device_id=device_id,
                    location_id=location.location_id,
                    expires_at=expiry,
                )
            )
            self.refresh_repo.commit()
        except Exception:
            self.refresh_repo.rollback()
            raise

        return RefreshedUserSession(
            access_session_id=access_session_id,
            access_token=token,
            expires_at_utc=expiry,
            tenant_id=tenant_id,
            user_id=user_id,
            device_id=device_id,
            location_id=location.location_id,
            roles=tuple(roles),
            permissions=tuple(permissions),
        )
