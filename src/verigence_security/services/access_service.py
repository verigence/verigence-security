from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from verigence_security.adapters.identity import AuthenticatedIdentity
from verigence_security.adapters.network_risk import NetworkRiskAdapter
from verigence_security.core.errors import security_error
from verigence_security.core.types import ActorType, PolicyAction, VpnStatus
from verigence_security.repositories.security_repository import SecurityRepository
from verigence_security.services.geo import GeoSample, match_location, validate_geo
from verigence_security.services.permissions import validate_permissions
from verigence_security.services.schedule import evaluate_schedule
from verigence_security.services.token_service import AccessTokenClaims, TokenService


class UserAccessService:
    def __init__(
        self,
        repo: SecurityRepository,
        network: NetworkRiskAdapter,
        tokens: TokenService,
    ) -> None:
        self.repo = repo
        self.network = network
        self.tokens = tokens

    def create_or_reuse(
        self,
        *,
        identity: AuthenticatedIdentity,
        tenant_id: str,
        device_id: str,
        geo: GeoSample,
        source_ip: str,
        correlation_id: str,
    ) -> dict[str, object]:
        now = datetime.now(UTC)

        # v1.3 explicitly forbids holding an external provider call inside the database/device-lock
        # transaction. The identity token has already been cryptographically verified by the route.
        risk = self.network.evaluate(source_ip, correlation_id)

        try:
            tenant_status = self.repo.tenant_status(tenant_id)
            if tenant_status in {"OFFBOARDING", "OFFBOARDED"}:
                raise security_error("TENANT_OFFBOARDING")
            if tenant_status != "ACTIVE":
                raise security_error("TENANT_NOT_ACTIVE")

            user_id = self.repo.resolve_identity_user(identity.provider, identity.provider_subject)
            context = self.repo.get_user_context(user_id, tenant_id, now)
            policy = self.repo.get_tenant_policy(tenant_id)

            # SEC-030: serialize USER session creation on the registered-device row.
            self.repo.lock_active_device(user_id, tenant_id, device_id)

            validate_geo(
                geo,
                max_accuracy_meters=policy.max_geo_accuracy_meters,
                max_age_seconds=policy.max_geo_age_seconds,
                now=now,
            )
            location, distance = match_location(
                geo,
                self.repo.assigned_locations(user_id, tenant_id, now),
            )
            self.repo.ensure_active_schedule(tenant_id, location.schedule_id)
            windows = self.repo.schedule_windows(tenant_id, location.schedule_id)
            override = self.repo.active_override_until(
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

            roles, database_permissions = self.repo.effective_user_permissions(
                tenant_id,
                user_id,
                now,
            )
            permissions = validate_permissions(database_permissions)

            self.repo.expire_stale_user_sessions(tenant_id, user_id, device_id, now)
            active = self.repo.active_user_session(tenant_id, user_id, device_id)

            if active and str(active["location_id"]) != location.location_id:
                # v1.3 requires a conflicting active context to be rejected rather than silently
                # replacing it. The matched location is the concrete USER context persisted by the
                # v1.3 access_sessions schema.
                raise security_error("ACCESS_SESSION_CONTEXT_CONFLICT")

            if active:
                session_id = str(active["access_session_id"])
                started_at = active["started_at_utc"]
                if started_at.tzinfo is None:
                    started_at = started_at.replace(tzinfo=UTC)
                session_max_end = started_at.astimezone(UTC) + timedelta(
                    minutes=policy.session_max_duration_minutes
                )
            else:
                session_max_end = now + timedelta(minutes=policy.session_max_duration_minutes)

            expiry = min(
                now + timedelta(minutes=policy.access_token_ttl_minutes),
                now + timedelta(seconds=policy.geo_revalidation_interval_seconds),
                session_max_end,
                schedule.authorized_until_utc,
            )

            if active:
                self.repo.update_reused_user_session(
                    access_session_id=session_id,
                    source_ip=source_ip,
                    vpn_status=risk.vpn_status.value,
                    authorization_version=context.authorization_version,
                    expires_at=expiry,
                    now=now,
                )
            else:
                session_id = self.repo.create_user_session(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    membership_id=context.membership_id,
                    device_id=device_id,
                    location_id=location.location_id,
                    authentication_source=identity.provider,
                    authz_version=context.authorization_version,
                    source_ip=source_ip,
                    vpn_status=risk.vpn_status.value,
                    expires_at=expiry,
                    now=now,
                )

            self.repo.record_evaluation(
                {
                    "evaluation_id": str(uuid4()),
                    "access_session_id": session_id,
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

            # Sign before commit. If signing fails, rollback the access-session/evidence writes so
            # the caller is never left with a committed session for a token it never received.
            token = self.tokens.issue(
                AccessTokenClaims(
                    principal_id=user_id,
                    actor_type=ActorType.USER,
                    tenant_id=tenant_id,
                    access_session_id=session_id,
                    permissions=tuple(permissions),
                    roles=tuple(roles),
                    device_id=device_id,
                    location_id=location.location_id,
                    expires_at=expiry,
                )
            )
            self.repo.commit()
        except Exception:
            self.repo.rollback()
            raise

        return {
            "accessSessionId": session_id,
            "accessToken": token,
            "expiresAtUtc": expiry.isoformat(),
            "actorType": ActorType.USER.value,
            "tenantId": tenant_id,
            "deviceId": device_id,
            "locationId": location.location_id,
            "roles": roles,
            "permissions": permissions,
        }
