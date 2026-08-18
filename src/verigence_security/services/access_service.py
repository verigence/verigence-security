from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from verigence_security.adapters.identity import AuthenticatedIdentity
from verigence_security.adapters.network_risk import NetworkRiskAdapter
from verigence_security.core.errors import security_error
from verigence_security.core.types import ActorType, PolicyAction, VpnStatus
from verigence_security.repositories.security_repository import MachineCredential, SecurityRepository
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


class MachineAccessService:
    def __init__(self, repo: SecurityRepository, tokens: TokenService) -> None:
        self.repo = repo
        self.tokens = tokens

    def issue_machine_token(
        self,
        *,
        client_id: str,
        client_secret: str,
        tenant_id: str,
        requested_permissions: list[str],
        source_ip: str,
        correlation_id: str,
    ) -> dict[str, object]:
        now = datetime.now(UTC)
        try:
            credential = self._authenticate_credential(client_id, client_secret, now)
            self._require_active_tenant(tenant_id)
            policy = self.repo.get_tenant_policy(tenant_id)
            permissions = self._authorized_permissions(
                credential=credential,
                tenant_id=tenant_id,
                requested_permissions=requested_permissions,
                now=now,
            )
            expiry = now + timedelta(minutes=policy.machine_token_ttl_minutes)
            session_id = self.repo.create_machine_session(
                principal_id=credential.principal_id,
                actor_type=credential.actor_type,
                tenant_id=tenant_id,
                credential_id=credential.credential_id,
                source_ip=source_ip,
                expires_at=expiry,
                now=now,
            )
            self.repo.record_evaluation(
                {
                    "evaluation_id": str(uuid4()),
                    "access_session_id": session_id,
                    "tenant_id": tenant_id,
                    "principal_id": credential.principal_id,
                    "actor_type": credential.actor_type.value,
                    "supplied_latitude": None,
                    "supplied_longitude": None,
                    "supplied_accuracy_meters": None,
                    "geo_captured_at_utc": None,
                    "geo_source": None,
                    "geo_integrity_status": None,
                    "geo_integrity_reason": None,
                    "matched_location_id": None,
                    "matched_distance_meters": None,
                    "evaluated_local_time": None,
                    "evaluated_timezone": None,
                    "schedule_id": None,
                    "source_ip": source_ip,
                    "vpn_status": None,
                    "decision": "ALLOW",
                    "decision_reason_code": "MACHINE_ACCESS_GRANTED",
                    "correlation_id": correlation_id,
                    "evaluated_at_utc": now,
                }
            )
            token = self.tokens.issue(
                AccessTokenClaims(
                    principal_id=credential.principal_id,
                    actor_type=credential.actor_type,
                    tenant_id=tenant_id,
                    access_session_id=session_id,
                    permissions=tuple(permissions),
                    expires_at=expiry,
                    subject=credential.client_id,
                )
            )
            self.repo.mark_machine_credential_used(credential.credential_id, now)
            self.repo.commit()
        except Exception:
            self.repo.rollback()
            raise

        return {
            "accessToken": token,
            "expiresAtUtc": expiry,
            "permissions": permissions,
        }

    def exchange_user_token(
        self,
        *,
        client_id: str,
        client_secret: str,
        subject_token: str,
        requested_permissions: list[str],
    ) -> dict[str, object]:
        now = datetime.now(UTC)
        try:
            credential = self._authenticate_credential(client_id, client_secret, now)
            claims = self.tokens.verify(subject_token)
            if claims.get("actor_type") != ActorType.USER.value:
                raise security_error("AUTH_TOKEN_INVALID")

            subject = claims.get("sub")
            tenant_id = claims.get("tenant_id")
            access_session_id = claims.get("access_session_id")
            roles = claims.get("roles")
            device_id = claims.get("device_id")
            location_id = claims.get("location_id")
            user_permissions = claims.get("permissions")
            expires_at_raw = claims.get("exp")
            if (
                not isinstance(subject, str)
                or not subject
                or not isinstance(tenant_id, str)
                or not tenant_id
                or not isinstance(access_session_id, str)
                or not access_session_id
                or not isinstance(roles, list)
                or not all(isinstance(role, str) for role in roles)
                or not isinstance(device_id, str)
                or not device_id
                or not isinstance(location_id, str)
                or not location_id
                or not isinstance(user_permissions, list)
                or not all(isinstance(permission, str) for permission in user_permissions)
                or not isinstance(expires_at_raw, (int, float))
            ):
                raise security_error("AUTH_TOKEN_INVALID")

            self._require_active_tenant(tenant_id)
            machine_permissions = set(
                self.repo.machine_permissions(credential.principal_id, tenant_id, now)
            )
            validated_user_permissions = set(validate_permissions(user_permissions))
            requested = self._requested_permissions(requested_permissions)
            allowed = machine_permissions.intersection(validated_user_permissions)
            if not set(requested).issubset(allowed):
                raise security_error("PERMISSION_DENIED")

            expiry = datetime.fromtimestamp(float(expires_at_raw), UTC)
            token = self.tokens.issue(
                AccessTokenClaims(
                    principal_id=subject,
                    actor_type=ActorType.USER,
                    tenant_id=tenant_id,
                    access_session_id=access_session_id,
                    permissions=tuple(requested),
                    roles=tuple(roles),
                    device_id=device_id,
                    location_id=location_id,
                    expires_at=expiry,
                    delegated_actor_id=credential.client_id,
                )
            )
            self.repo.mark_machine_credential_used(credential.credential_id, now)
            self.repo.commit()
        except Exception:
            self.repo.rollback()
            raise

        return {
            "accessToken": token,
            "expiresAtUtc": expiry,
            "permissions": requested,
        }

    def _authenticate_credential(
        self,
        client_id: str,
        client_secret: str,
        now: datetime,
    ) -> MachineCredential:
        credential = self.repo.machine_credential(client_id, now)
        verifier = credential.secret_hash.strip().lower()
        if len(verifier) != 64 or any(character not in "0123456789abcdef" for character in verifier):
            raise security_error("MACHINE_CREDENTIAL_INVALID")
        supplied = hashlib.sha256(client_secret.encode()).hexdigest()
        if not hmac.compare_digest(verifier, supplied):
            raise security_error("MACHINE_CREDENTIAL_INVALID")
        return credential

    def _require_active_tenant(self, tenant_id: str) -> None:
        tenant_status = self.repo.tenant_status(tenant_id)
        if tenant_status in {"OFFBOARDING", "OFFBOARDED"}:
            raise security_error("TENANT_OFFBOARDING")
        if tenant_status != "ACTIVE":
            raise security_error("TENANT_NOT_ACTIVE")

    def _authorized_permissions(
        self,
        *,
        credential: MachineCredential,
        tenant_id: str,
        requested_permissions: list[str],
        now: datetime,
    ) -> list[str]:
        requested = self._requested_permissions(requested_permissions)
        allowed = set(
            validate_permissions(
                self.repo.machine_permissions(credential.principal_id, tenant_id, now)
            )
        )
        if not set(requested).issubset(allowed):
            raise security_error("PERMISSION_DENIED")
        return requested

    @staticmethod
    def _requested_permissions(requested_permissions: list[str]) -> list[str]:
        requested = [permission for permission in requested_permissions if permission]
        if not requested:
            raise security_error("PERMISSION_DENIED")
        return validate_permissions(requested)