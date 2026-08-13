from __future__ import annotations

import json
import logging
import secrets
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import text
from sqlalchemy.orm import Session

from verigence_security.core.errors import security_error

_HASHER = PasswordHasher()
_LOG = logging.getLogger(__name__)

PRIVILEGED_ROLE_KEYS = frozenset(
    {
        "tenant.owner",
        "tenant.admin",
        "tenant.rbac_admin",
        "tenant.access_admin",
        "tenant.security_policy_admin",
        "tenant.security_approver",
    }
)


class OnboardingService:
    """Human invitation and self-onboarding state transitions for Increment F."""

    def __init__(self, session: Session) -> None:
        self.s = session

    def create_invitation(
        self,
        *,
        tenant_id: str,
        actor_user_id: str,
        display_name: str,
        email: str | None,
        mobile: str | None,
        employee_code: str | None,
        role_ids: list[str],
        group_ids: list[str],
        location_assignments: list[dict[str, str]],
        expires_at_utc: datetime,
        correlation_id: str,
    ) -> tuple[dict[str, Any], str]:
        now = datetime.now(UTC)
        clean_email = email.strip() if email else None
        clean_mobile = mobile.strip() if mobile else None
        if not clean_email and not clean_mobile:
            raise ValueError("At least one invitation contact channel is required")
        if expires_at_utc <= now:
            raise ValueError("Invitation expiry must be in the future")
        if not self._tenant_exists(tenant_id):
            raise LookupError("Tenant not found")
        access, privileged_role_ids = self._validated_access(
            tenant_id=tenant_id,
            role_ids=role_ids,
            group_ids=group_ids,
            location_assignments=location_assignments,
        )
        invitation_id = str(uuid4())
        user_id = str(uuid4())
        raw_value = secrets.token_urlsafe(32)
        try:
            self._create_invited_user(
                tenant_id=tenant_id,
                user_id=user_id,
                display_name=display_name,
                email=clean_email,
                mobile=clean_mobile,
                employee_code=employee_code,
                now=now,
            )
            self.s.execute(
                text(
                    """
                    INSERT INTO security.tenant_invitations
                    (invitation_id,tenant_id,invited_user_id,invitee_email,invitee_mobile,
                     employee_code,acceptance_token_hash,proposed_access_json,
                     requires_privileged_approval,status,invited_by_user_id,invited_at_utc,
                     expires_at_utc,correlation_id)
                    VALUES (:id,:tenant_id,:user_id,:email,:mobile,:employee_code,
                            :value_hash,CAST(:access_json AS jsonb),:privileged,'PENDING',
                            :actor_id,:now,:expires_at,:correlation_id)
                    """
                ),
                {
                    "id": invitation_id,
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "email": clean_email,
                    "mobile": clean_mobile,
                    "employee_code": employee_code,
                    "value_hash": _HASHER.hash(raw_value),
                    "access_json": json.dumps(access),
                    "privileged": bool(privileged_role_ids),
                    "actor_id": actor_user_id,
                    "now": now,
                    "expires_at": expires_at_utc,
                    "correlation_id": correlation_id,
                },
            )
            self._audit(
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
                operation_key="security.member.invite",
                resource_type="INVITATION",
                resource_id=invitation_id,
                state={
                    "status": "PENDING",
                    "requiresPrivilegedApproval": bool(privileged_role_ids),
                },
                now=now,
            )
            self.s.commit()
        except Exception:
            self.s.rollback()
            raise
        row = self.get_invitation(tenant_id=tenant_id, invitation_id=invitation_id)
        if row is None:
            raise RuntimeError("Created invitation could not be reloaded")
        return row, raw_value

    def list_invitations(self, tenant_id: str) -> list[dict[str, Any]]:
        rows = self.s.execute(
            text(
                """
                SELECT i.invitation_id,i.tenant_id,i.invited_user_id,u.display_name,
                       i.invitee_email,i.invitee_mobile,i.employee_code,
                       i.proposed_access_json,i.requires_privileged_approval,i.status,
                       i.invited_by_user_id,i.invited_at_utc,i.expires_at_utc,
                       i.accepted_at_utc,i.correlation_id
                FROM security.tenant_invitations i
                JOIN security.users u ON u.user_id=i.invited_user_id
                WHERE i.tenant_id=:tenant_id
                ORDER BY i.invited_at_utc DESC
                """
            ),
            {"tenant_id": tenant_id},
        ).mappings()
        return [dict(row) for row in rows]

    def get_invitation(
        self,
        *,
        tenant_id: str,
        invitation_id: str,
    ) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT i.invitation_id,i.tenant_id,i.invited_user_id,u.display_name,
                       i.invitee_email,i.invitee_mobile,i.employee_code,
                       i.proposed_access_json,i.requires_privileged_approval,i.status,
                       i.invited_by_user_id,i.invited_at_utc,i.expires_at_utc,
                       i.accepted_at_utc,i.correlation_id
                FROM security.tenant_invitations i
                JOIN security.users u ON u.user_id=i.invited_user_id
                WHERE i.tenant_id=:tenant_id AND i.invitation_id=:invitation_id
                """
            ),
            {"tenant_id": tenant_id, "invitation_id": invitation_id},
        ).mappings().first()
        return dict(row) if row else None

    def cancel_invitation(
        self,
        *,
        tenant_id: str,
        invitation_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> bool:
        now = datetime.now(UTC)
        row = self.s.execute(
            text(
                """
                SELECT invited_user_id,status FROM security.tenant_invitations
                WHERE tenant_id=:tenant_id AND invitation_id=:invitation_id
                FOR UPDATE
                """
            ),
            {"tenant_id": tenant_id, "invitation_id": invitation_id},
        ).mappings().first()
        if row is None:
            self.s.rollback()
            return False
        if row["status"] != "PENDING":
            self.s.rollback()
            raise ValueError("Only a PENDING invitation can be cancelled")
        try:
            self.s.execute(
                text(
                    """
                    UPDATE security.tenant_invitations SET status='CANCELLED'
                    WHERE tenant_id=:tenant_id AND invitation_id=:invitation_id
                    """
                ),
                {"tenant_id": tenant_id, "invitation_id": invitation_id},
            )
            self.s.execute(
                text(
                    """
                    UPDATE security.tenant_memberships
                    SET status='ENDED',valid_to_utc=:now,updated_at_utc=:now
                    WHERE tenant_id=:tenant_id AND user_id=:user_id AND status='PENDING'
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "user_id": str(row["invited_user_id"]),
                    "now": now,
                },
            )
            self._audit(
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
                operation_key="security.member.invitation.cancel",
                resource_type="INVITATION",
                resource_id=invitation_id,
                state={"status": "CANCELLED"},
                now=now,
            )
            self.s.commit()
            return True
        except Exception:
            self.s.rollback()
            raise

    def accept_invitation(
        self,
        *,
        invitation_id: str,
        acceptance_token: str,
        identity_provider: str,
        identity_subject: str,
        correlation_id: str,
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        invitation = self.s.execute(
            text(
                """
                SELECT * FROM security.tenant_invitations
                WHERE invitation_id=:invitation_id FOR UPDATE
                """
            ),
            {"invitation_id": invitation_id},
        ).mappings().first()
        if invitation is None or invitation["status"] != "PENDING":
            raise security_error("PERMISSION_DENIED")
        if invitation["expires_at_utc"] <= now:
            self.s.execute(
                text(
                    """
                    UPDATE security.tenant_invitations SET status='EXPIRED'
                    WHERE invitation_id=:invitation_id AND status='PENDING'
                    """
                ),
                {"invitation_id": invitation_id},
            )
            self.s.commit()
            raise security_error("PERMISSION_DENIED")
        if not _verify_secret(str(invitation["acceptance_token_hash"]), acceptance_token):
            _LOG.warning(
                "invitation_acceptance_denied correlation_id=%s invitation_id=%s provider=%s",
                correlation_id,
                invitation_id,
                identity_provider,
            )
            raise security_error("PERMISSION_DENIED")
        tenant_id = str(invitation["tenant_id"])
        invited_user_id = str(invitation["invited_user_id"])
        try:
            user_id = self._bind_invitation_identity(
                tenant_id=tenant_id,
                invited_user_id=invited_user_id,
                invitation_id=invitation_id,
                identity_provider=identity_provider,
                identity_subject=identity_subject,
                employee_code=(
                    str(invitation["employee_code"])
                    if invitation["employee_code"] is not None
                    else None
                ),
                now=now,
            )
            access = self._json_access(invitation["proposed_access_json"])
            access, privileged_role_ids = self._validated_access(
                tenant_id=tenant_id,
                role_ids=[str(value) for value in access.get("roleIds", [])],
                group_ids=[str(value) for value in access.get("groupIds", [])],
                location_assignments=self._json_locations(access),
            )
            self.s.execute(
                text(
                    """
                    UPDATE security.users
                    SET status=CASE WHEN status='INVITED' THEN 'ACTIVE' ELSE status END,
                        updated_at_utc=:now
                    WHERE user_id=:user_id
                    """
                ),
                {"user_id": user_id, "now": now},
            )
            self.s.execute(
                text(
                    """
                    UPDATE security.tenant_invitations
                    SET status='ACCEPTED',accepted_at_utc=:now
                    WHERE invitation_id=:invitation_id
                    """
                ),
                {"invitation_id": invitation_id, "now": now},
            )
            request_ids: list[str] = []
            if privileged_role_ids:
                for role_id in privileged_role_ids:
                    request_id = str(uuid4())
                    request_ids.append(request_id)
                    self.s.execute(
                        text(
                            """
                            INSERT INTO security.privileged_access_requests
                            (request_id,tenant_id,subject_user_id,role_id,
                             source_invitation_id,status,requested_by_user_id,
                             requested_at_utc,correlation_id)
                            VALUES (:request_id,:tenant_id,:user_id,:role_id,
                                    :invitation_id,'PENDING',:requested_by,:now,
                                    :correlation_id)
                            """
                        ),
                        {
                            "request_id": request_id,
                            "tenant_id": tenant_id,
                            "user_id": user_id,
                            "role_id": role_id,
                            "invitation_id": invitation_id,
                            "requested_by": str(invitation["invited_by_user_id"]),
                            "now": now,
                            "correlation_id": correlation_id,
                        },
                    )
                membership_status = "PENDING"
            else:
                self._materialize_access(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    actor_user_id=str(invitation["invited_by_user_id"]),
                    access=access,
                    now=now,
                )
                membership_status = "ACTIVE"
            self._audit(
                tenant_id=tenant_id,
                actor_user_id=user_id,
                correlation_id=correlation_id,
                operation_key="security.invitation.accept",
                resource_type="INVITATION",
                resource_id=invitation_id,
                state={
                    "status": "ACCEPTED",
                    "membershipStatus": membership_status,
                    "privilegedRequestsPending": len(request_ids),
                },
                now=now,
            )
            self.s.commit()
        except Exception:
            self.s.rollback()
            raise
        return {
            "invitationId": invitation_id,
            "tenantId": tenant_id,
            "userId": user_id,
            "status": "ACCEPTED",
            "membershipStatus": membership_status,
            "privilegedAccessRequestIds": request_ids,
        }

    def submit_self_registration(
        self,
        *,
        tenant_code: str,
        onboarding_token: str,
        identity_provider: str,
        identity_subject: str,
        display_name: str,
        source_ip: str,
        correlation_id: str,
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        tenant = self.s.execute(
            text(
                """
                SELECT tenant_id FROM security.tenants WHERE tenant_code=:tenant_code
                """
            ),
            {"tenant_code": tenant_code},
        ).mappings().first()
        if tenant is None:
            self._log_self_denial(correlation_id, tenant_code, identity_provider)
            raise security_error("PERMISSION_DENIED")
        tenant_id = str(tenant["tenant_id"])
        if not self._effective_control(tenant_id, "admin.self_onboarding"):
            self._log_self_denial(correlation_id, tenant_code, identity_provider)
            raise security_error("PERMISSION_DENIED")
        setting = self.s.execute(
            text(
                """
                SELECT token_hash,status FROM security.tenant_self_onboarding_settings
                WHERE tenant_id=:tenant_id
                """
            ),
            {"tenant_id": tenant_id},
        ).mappings().first()
        if (
            setting is None
            or setting["status"] != "ACTIVE"
            or not _verify_secret(str(setting["token_hash"]), onboarding_token)
        ):
            self._log_self_denial(correlation_id, tenant_code, identity_provider)
            raise security_error("PERMISSION_DENIED")
        try:
            user_id, external_identity_id = self._resolve_or_create_identity_user(
                identity_provider=identity_provider,
                identity_subject=identity_subject,
                display_name=display_name,
                now=now,
            )
            membership = self.s.execute(
                text(
                    """
                    SELECT membership_id,status FROM security.tenant_memberships
                    WHERE tenant_id=:tenant_id AND user_id=:user_id FOR UPDATE
                    """
                ),
                {"tenant_id": tenant_id, "user_id": user_id},
            ).mappings().first()
            if membership is not None and membership["status"] == "ACTIVE":
                self.s.commit()
                return {
                    "tenantId": tenant_id,
                    "userId": user_id,
                    "status": "ACTIVE",
                    "requestId": None,
                }
            if membership is not None and membership["status"] in {"SUSPENDED", "ENDED"}:
                raise ValueError("Existing Tenant membership cannot self-onboard")
            pending = self._pending_self_request(tenant_id, user_id)
            if pending is not None:
                self.s.commit()
                return {
                    "tenantId": tenant_id,
                    "userId": user_id,
                    "status": str(pending["status"]),
                    "requestId": str(pending["self_onboarding_request_id"]),
                }
            if membership is None:
                self.s.execute(
                    text(
                        """
                        INSERT INTO security.tenant_memberships
                        (membership_id,tenant_id,user_id,status,authorization_version,
                         created_at_utc,updated_at_utc)
                        VALUES (:id,:tenant_id,:user_id,'PENDING',1,:now,:now)
                        """
                    ),
                    {"id": str(uuid4()), "tenant_id": tenant_id, "user_id": user_id, "now": now},
                )
            request_id = str(uuid4())
            self.s.execute(
                text(
                    """
                    INSERT INTO security.self_onboarding_requests
                    (self_onboarding_request_id,tenant_id,user_id,external_identity_id,
                     status,submitted_at_utc,submitted_source_ip,correlation_id)
                    VALUES (:id,:tenant_id,:user_id,:external_identity_id,
                            'PENDING_ADMIN_APPROVAL',:now,CAST(:source_ip AS inet),
                            :correlation_id)
                    """
                ),
                {
                    "id": request_id,
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "external_identity_id": external_identity_id,
                    "now": now,
                    "source_ip": source_ip,
                    "correlation_id": correlation_id,
                },
            )
            self._audit(
                tenant_id=tenant_id,
                actor_user_id=user_id,
                correlation_id=correlation_id,
                operation_key="security.self_onboarding.submit",
                resource_type="SELF_ONBOARDING_REQUEST",
                resource_id=request_id,
                state={"status": "PENDING_ADMIN_APPROVAL"},
                now=now,
            )
            self.s.commit()
        except Exception:
            self.s.rollback()
            raise
        return {
            "tenantId": tenant_id,
            "userId": user_id,
            "status": "PENDING_ADMIN_APPROVAL",
            "requestId": request_id,
        }

    def list_self_onboarding_requests(self, tenant_id: str) -> list[dict[str, Any]]:
        rows = self.s.execute(
            text(
                """
                SELECT r.self_onboarding_request_id,r.tenant_id,r.user_id,u.display_name,
                       u.primary_email,u.primary_mobile,r.status,r.submitted_at_utc,
                       r.reviewed_by_user_id,r.reviewed_at_utc,r.review_reason,r.correlation_id
                FROM security.self_onboarding_requests r
                JOIN security.users u ON u.user_id=r.user_id
                WHERE r.tenant_id=:tenant_id ORDER BY r.submitted_at_utc DESC
                """
            ),
            {"tenant_id": tenant_id},
        ).mappings()
        return [dict(row) for row in rows]

    def get_self_onboarding_request(
        self,
        *,
        tenant_id: str,
        request_id: str,
    ) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT r.self_onboarding_request_id,r.tenant_id,r.user_id,u.display_name,
                       u.primary_email,u.primary_mobile,r.status,r.submitted_at_utc,
                       r.reviewed_by_user_id,r.reviewed_at_utc,r.review_reason,r.correlation_id
                FROM security.self_onboarding_requests r
                JOIN security.users u ON u.user_id=r.user_id
                WHERE r.tenant_id=:tenant_id AND r.self_onboarding_request_id=:request_id
                """
            ),
            {"tenant_id": tenant_id, "request_id": request_id},
        ).mappings().first()
        return dict(row) if row else None

    def approve_self_onboarding_request(
        self,
        *,
        tenant_id: str,
        request_id: str,
        actor_user_id: str,
        role_ids: list[str],
        group_ids: list[str],
        location_assignments: list[dict[str, str]],
        correlation_id: str,
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        request_row = self.s.execute(
            text(
                """
                SELECT * FROM security.self_onboarding_requests
                WHERE tenant_id=:tenant_id AND self_onboarding_request_id=:request_id
                FOR UPDATE
                """
            ),
            {"tenant_id": tenant_id, "request_id": request_id},
        ).mappings().first()
        if request_row is None:
            raise LookupError("Self-onboarding request not found")
        if request_row["status"] != "PENDING_ADMIN_APPROVAL":
            self.s.rollback()
            raise ValueError("Self-onboarding request is not pending approval")
        access, privileged_role_ids = self._validated_access(
            tenant_id=tenant_id,
            role_ids=role_ids,
            group_ids=group_ids,
            location_assignments=location_assignments,
        )
        if privileged_role_ids:
            self.s.rollback()
            raise ValueError("Privileged roles require maker-checker Increment G")
        user_id = str(request_row["user_id"])
        membership = self.s.execute(
            text(
                """
                SELECT status FROM security.tenant_memberships
                WHERE tenant_id=:tenant_id AND user_id=:user_id FOR UPDATE
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id},
        ).first()
        if membership is None or membership[0] != "PENDING":
            self.s.rollback()
            raise ValueError("Self-onboarding membership is not PENDING")
        try:
            self._materialize_access(
                tenant_id=tenant_id,
                user_id=user_id,
                actor_user_id=actor_user_id,
                access=access,
                now=now,
            )
            self.s.execute(
                text(
                    """
                    UPDATE security.self_onboarding_requests
                    SET status='APPROVED',reviewed_by_user_id=:actor_user_id,
                        reviewed_at_utc=:now
                    WHERE self_onboarding_request_id=:request_id
                    """
                ),
                {"actor_user_id": actor_user_id, "now": now, "request_id": request_id},
            )
            self._audit(
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
                operation_key="security.member.approve",
                resource_type="SELF_ONBOARDING_REQUEST",
                resource_id=request_id,
                state={"status": "APPROVED", "userId": user_id},
                now=now,
            )
            self.s.commit()
        except Exception:
            self.s.rollback()
            raise
        row = self.get_self_onboarding_request(tenant_id=tenant_id, request_id=request_id)
        if row is None:
            raise RuntimeError("Approved self-onboarding request could not be reloaded")
        return row

    def reject_self_onboarding_request(
        self,
        *,
        tenant_id: str,
        request_id: str,
        actor_user_id: str,
        reason: str | None,
        correlation_id: str,
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        row = self.s.execute(
            text(
                """
                SELECT status FROM security.self_onboarding_requests
                WHERE tenant_id=:tenant_id AND self_onboarding_request_id=:request_id
                FOR UPDATE
                """
            ),
            {"tenant_id": tenant_id, "request_id": request_id},
        ).first()
        if row is None:
            raise LookupError("Self-onboarding request not found")
        if row[0] != "PENDING_ADMIN_APPROVAL":
            self.s.rollback()
            raise ValueError("Self-onboarding request is not pending approval")
        try:
            self.s.execute(
                text(
                    """
                    UPDATE security.self_onboarding_requests
                    SET status='REJECTED',reviewed_by_user_id=:actor_user_id,
                        reviewed_at_utc=:now,review_reason=:reason
                    WHERE self_onboarding_request_id=:request_id
                    """
                ),
                {
                    "actor_user_id": actor_user_id,
                    "now": now,
                    "reason": reason,
                    "request_id": request_id,
                },
            )
            self._audit(
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
                operation_key="security.member.reject",
                resource_type="SELF_ONBOARDING_REQUEST",
                resource_id=request_id,
                state={"status": "REJECTED"},
                now=now,
            )
            self.s.commit()
        except Exception:
            self.s.rollback()
            raise
        result = self.get_self_onboarding_request(tenant_id=tenant_id, request_id=request_id)
        if result is None:
            raise RuntimeError("Rejected self-onboarding request could not be reloaded")
        return result

    def role_id_by_key(self, *, tenant_id: str, role_key: str) -> str:
        row = self.s.execute(
            text(
                """
                SELECT role_id FROM security.roles
                WHERE tenant_id=:tenant_id AND role_key=:role_key AND status='ACTIVE'
                """
            ),
            {"tenant_id": tenant_id, "role_key": role_key},
        ).first()
        if row is None:
            raise LookupError(f"Required Tenant role not found: {role_key}")
        return str(row[0])

    def _create_invited_user(
        self,
        *,
        tenant_id: str,
        user_id: str,
        display_name: str,
        email: str | None,
        mobile: str | None,
        employee_code: str | None,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.security_principals
                (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                VALUES (:user_id,'USER',:display_name,'ACTIVE',:now,:now)
                """
            ),
            {"user_id": user_id, "display_name": display_name, "now": now},
        )
        self.s.execute(
            text(
                """
                INSERT INTO security.users
                (user_id,display_name,primary_email,primary_mobile,status,
                 created_at_utc,updated_at_utc)
                VALUES (:user_id,:display_name,:email,:mobile,'INVITED',:now,:now)
                """
            ),
            {
                "user_id": user_id,
                "display_name": display_name,
                "email": email,
                "mobile": mobile,
                "now": now,
            },
        )
        self.s.execute(
            text(
                """
                INSERT INTO security.tenant_memberships
                (membership_id,tenant_id,user_id,employee_code,status,
                 authorization_version,created_at_utc,updated_at_utc)
                VALUES (:id,:tenant_id,:user_id,:employee_code,'PENDING',1,:now,:now)
                """
            ),
            {
                "id": str(uuid4()),
                "tenant_id": tenant_id,
                "user_id": user_id,
                "employee_code": employee_code,
                "now": now,
            },
        )

    def _bind_invitation_identity(
        self,
        *,
        tenant_id: str,
        invited_user_id: str,
        invitation_id: str,
        identity_provider: str,
        identity_subject: str,
        employee_code: str | None,
        now: datetime,
    ) -> str:
        identity = self.s.execute(
            text(
                """
                SELECT e.user_id,e.status,u.status AS user_status,
                       p.status AS principal_status
                FROM security.external_identities e
                JOIN security.users u ON u.user_id=e.user_id
                JOIN security.security_principals p ON p.principal_id=e.user_id
                WHERE e.provider=:provider AND e.provider_subject=:subject
                """
            ),
            {"provider": identity_provider, "subject": identity_subject},
        ).mappings().first()
        if identity is None:
            self.s.execute(
                text(
                    """
                    INSERT INTO security.external_identities
                    (external_identity_id,user_id,provider,provider_subject,status,linked_at_utc)
                    VALUES (:id,:user_id,:provider,:subject,'ACTIVE',:now)
                    """
                ),
                {
                    "id": str(uuid4()),
                    "user_id": invited_user_id,
                    "provider": identity_provider,
                    "subject": identity_subject,
                    "now": now,
                },
            )
            return invited_user_id
        if identity["status"] != "ACTIVE" or identity["principal_status"] != "ACTIVE":
            raise security_error("PRINCIPAL_NOT_ACTIVE")
        existing_user_id = str(identity["user_id"])
        if existing_user_id == invited_user_id:
            return invited_user_id
        if identity["user_status"] != "ACTIVE":
            raise security_error("USER_NOT_ACTIVE")
        existing_membership = self.s.execute(
            text(
                """
                SELECT 1 FROM security.tenant_memberships
                WHERE tenant_id=:tenant_id AND user_id=:user_id
                """
            ),
            {"tenant_id": tenant_id, "user_id": existing_user_id},
        ).first()
        if existing_membership is not None:
            raise ValueError("Authenticated user already has a Tenant membership")
        self.s.execute(
            text(
                """
                DELETE FROM security.tenant_memberships
                WHERE tenant_id=:tenant_id AND user_id=:user_id AND status='PENDING'
                """
            ),
            {"tenant_id": tenant_id, "user_id": invited_user_id},
        )
        self.s.execute(
            text(
                """
                UPDATE security.tenant_invitations SET invited_user_id=:user_id
                WHERE invitation_id=:invitation_id
                """
            ),
            {"user_id": existing_user_id, "invitation_id": invitation_id},
        )
        self.s.execute(
            text(
                """
                INSERT INTO security.tenant_memberships
                (membership_id,tenant_id,user_id,employee_code,status,
                 authorization_version,created_at_utc,updated_at_utc)
                VALUES (:id,:tenant_id,:user_id,:employee_code,'PENDING',1,:now,:now)
                """
            ),
            {
                "id": str(uuid4()),
                "tenant_id": tenant_id,
                "user_id": existing_user_id,
                "employee_code": employee_code,
                "now": now,
            },
        )
        self.s.execute(
            text("DELETE FROM security.users WHERE user_id=:user_id"),
            {"user_id": invited_user_id},
        )
        self.s.execute(
            text("DELETE FROM security.security_principals WHERE principal_id=:user_id"),
            {"user_id": invited_user_id},
        )
        return existing_user_id

    def _resolve_or_create_identity_user(
        self,
        *,
        identity_provider: str,
        identity_subject: str,
        display_name: str,
        now: datetime,
    ) -> tuple[str, str]:
        row = self.s.execute(
            text(
                """
                SELECT e.external_identity_id,e.user_id,e.status,
                       u.status AS user_status,p.status AS principal_status
                FROM security.external_identities e
                JOIN security.users u ON u.user_id=e.user_id
                JOIN security.security_principals p ON p.principal_id=e.user_id
                WHERE e.provider=:provider AND e.provider_subject=:subject
                """
            ),
            {"provider": identity_provider, "subject": identity_subject},
        ).mappings().first()
        if row is not None:
            if row["status"] != "ACTIVE" or row["principal_status"] != "ACTIVE":
                raise security_error("PRINCIPAL_NOT_ACTIVE")
            if row["user_status"] not in {"ACTIVE", "INVITED"}:
                raise security_error("USER_NOT_ACTIVE")
            user_id = str(row["user_id"])
            if row["user_status"] == "INVITED":
                self.s.execute(
                    text(
                        """
                        UPDATE security.users SET status='ACTIVE',updated_at_utc=:now
                        WHERE user_id=:user_id
                        """
                    ),
                    {"user_id": user_id, "now": now},
                )
            return user_id, str(row["external_identity_id"])
        user_id = str(uuid4())
        external_identity_id = str(uuid4())
        self.s.execute(
            text(
                """
                INSERT INTO security.security_principals
                (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                VALUES (:user_id,'USER',:display_name,'ACTIVE',:now,:now)
                """
            ),
            {"user_id": user_id, "display_name": display_name, "now": now},
        )
        self.s.execute(
            text(
                """
                INSERT INTO security.users
                (user_id,display_name,status,created_at_utc,updated_at_utc)
                VALUES (:user_id,:display_name,'ACTIVE',:now,:now)
                """
            ),
            {"user_id": user_id, "display_name": display_name, "now": now},
        )
        self.s.execute(
            text(
                """
                INSERT INTO security.external_identities
                (external_identity_id,user_id,provider,provider_subject,status,linked_at_utc)
                VALUES (:external_id,:user_id,:provider,:subject,'ACTIVE',:now)
                """
            ),
            {
                "external_id": external_identity_id,
                "user_id": user_id,
                "provider": identity_provider,
                "subject": identity_subject,
                "now": now,
            },
        )
        return user_id, external_identity_id

    def _validated_access(
        self,
        *,
        tenant_id: str,
        role_ids: list[str],
        group_ids: list[str],
        location_assignments: list[dict[str, str]],
    ) -> tuple[dict[str, Any], list[str]]:
        roles = list(dict.fromkeys(role_ids))
        groups = list(dict.fromkeys(group_ids))
        privileged: list[str] = []
        for role_id in roles:
            row = self.s.execute(
                text(
                    """
                    SELECT role_key FROM security.roles
                    WHERE tenant_id=:tenant_id AND role_id=:role_id AND status='ACTIVE'
                    """
                ),
                {"tenant_id": tenant_id, "role_id": role_id},
            ).first()
            if row is None:
                raise ValueError("Role must belong to the Tenant and be ACTIVE")
            if str(row[0]) in PRIVILEGED_ROLE_KEYS:
                privileged.append(role_id)
        for group_id in groups:
            row = self.s.execute(
                text(
                    """
                    SELECT 1 FROM security.groups
                    WHERE tenant_id=:tenant_id AND group_id=:group_id AND status='ACTIVE'
                    """
                ),
                {"tenant_id": tenant_id, "group_id": group_id},
            ).first()
            if row is None:
                raise ValueError("Group must belong to the Tenant and be ACTIVE")
        locations: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for assignment in location_assignments:
            location_id = str(assignment["locationId"])
            schedule_id = str(assignment["scheduleId"])
            pair = (location_id, schedule_id)
            if pair in seen:
                continue
            seen.add(pair)
            row = self.s.execute(
                text(
                    """
                    SELECT 1 FROM security.tenant_locations l
                    JOIN security.access_schedules s
                      ON s.tenant_id=l.tenant_id AND s.schedule_id=:schedule_id
                    WHERE l.tenant_id=:tenant_id AND l.location_id=:location_id
                      AND l.status='ACTIVE' AND s.status='ACTIVE'
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "location_id": location_id,
                    "schedule_id": schedule_id,
                },
            ).first()
            if row is None:
                raise ValueError(
                    "Location and schedule must belong to the Tenant and be ACTIVE"
                )
            locations.append({"locationId": location_id, "scheduleId": schedule_id})
        return {"roleIds": roles, "groupIds": groups, "locationAssignments": locations}, privileged

    def _materialize_access(
        self,
        *,
        tenant_id: str,
        user_id: str,
        actor_user_id: str,
        access: dict[str, Any],
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                UPDATE security.tenant_memberships
                SET status='ACTIVE',valid_from_utc=COALESCE(valid_from_utc,:now),
                    updated_at_utc=:now
                WHERE tenant_id=:tenant_id AND user_id=:user_id AND status='PENDING'
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id, "now": now},
        )
        for role_id in access["roleIds"]:
            self.s.execute(
                text(
                    """
                    INSERT INTO security.user_role_assignments
                    (assignment_id,tenant_id,user_id,role_id,valid_from_utc,status,
                     assigned_by_user_id,assigned_at_utc)
                    VALUES (:id,:tenant_id,:user_id,:role_id,:now,'ACTIVE',:actor_id,:now)
                    ON CONFLICT DO NOTHING
                    """
                ),
                {
                    "id": str(uuid4()),
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "role_id": str(role_id),
                    "actor_id": actor_user_id,
                    "now": now,
                },
            )
        for group_id in access["groupIds"]:
            self.s.execute(
                text(
                    """
                    INSERT INTO security.group_memberships
                    (group_membership_id,tenant_id,group_id,user_id,status,valid_from_utc,
                     added_by_user_id,added_at_utc)
                    VALUES (:id,:tenant_id,:group_id,:user_id,'ACTIVE',:now,:actor_id,:now)
                    ON CONFLICT DO NOTHING
                    """
                ),
                {
                    "id": str(uuid4()),
                    "tenant_id": tenant_id,
                    "group_id": str(group_id),
                    "user_id": user_id,
                    "actor_id": actor_user_id,
                    "now": now,
                },
            )
        for assignment in access["locationAssignments"]:
            self.s.execute(
                text(
                    """
                    INSERT INTO security.user_location_assignments
                    (assignment_id,tenant_id,user_id,location_id,schedule_id,
                     valid_from_utc,status,assigned_by_user_id,assigned_at_utc)
                    VALUES (:id,:tenant_id,:user_id,:location_id,:schedule_id,:now,
                            'ACTIVE',:actor_id,:now)
                    ON CONFLICT DO NOTHING
                    """
                ),
                {
                    "id": str(uuid4()),
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "location_id": str(assignment["locationId"]),
                    "schedule_id": str(assignment["scheduleId"]),
                    "actor_id": actor_user_id,
                    "now": now,
                },
            )

    def _effective_control(self, tenant_id: str, control_key: str) -> bool:
        row = self.s.execute(
            text(
                """
                SELECT d.configurable,d.default_enabled,d.parent_control_key,
                       p.enabled AS platform_enabled,o.override_mode
                FROM security.security_control_definitions d
                LEFT JOIN security.platform_security_control_settings p
                  ON p.control_key=d.control_key
                LEFT JOIN security.tenant_security_control_overrides o
                  ON o.control_key=d.control_key AND o.tenant_id=:tenant_id
                WHERE d.control_key=:control_key AND d.status='ACTIVE'
                """
            ),
            {"tenant_id": tenant_id, "control_key": control_key},
        ).mappings().first()
        if row is None:
            return False
        if not bool(row["configurable"]) or row["override_mode"] == "ENABLED":
            enabled = True
        elif row["override_mode"] == "DISABLED":
            enabled = False
        elif row["platform_enabled"] is not None:
            enabled = bool(row["platform_enabled"])
        else:
            enabled = bool(row["default_enabled"])
        parent = row["parent_control_key"]
        if enabled and parent is not None:
            return self._effective_control(tenant_id, str(parent))
        return enabled

    def _pending_self_request(self, tenant_id: str, user_id: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT self_onboarding_request_id,status
                FROM security.self_onboarding_requests
                WHERE tenant_id=:tenant_id AND user_id=:user_id
                  AND status='PENDING_ADMIN_APPROVAL'
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id},
        ).mappings().first()
        return dict(row) if row else None

    def _tenant_exists(self, tenant_id: str) -> bool:
        return self.s.execute(
            text("SELECT 1 FROM security.tenants WHERE tenant_id=:tenant_id"),
            {"tenant_id": tenant_id},
        ).first() is not None

    @staticmethod
    def _json_access(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError("Stored invitation access is invalid")
        return {str(key): item for key, item in value.items()}

    @staticmethod
    def _json_locations(access: dict[str, Any]) -> list[dict[str, str]]:
        raw = access.get("locationAssignments", [])
        if not isinstance(raw, list):
            raise ValueError("Stored invitation locations are invalid")
        result: list[dict[str, str]] = []
        for value in raw:
            if not isinstance(value, dict):
                raise ValueError("Stored invitation location is invalid")
            result.append(
                {
                    "locationId": str(value["locationId"]),
                    "scheduleId": str(value["scheduleId"]),
                }
            )
        return result

    def _audit(
        self,
        *,
        tenant_id: str,
        actor_user_id: str,
        correlation_id: str,
        operation_key: str,
        resource_type: str,
        resource_id: str,
        state: dict[str, Any],
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.admin_change_records
                (admin_change_id,correlation_id,scope_type,tenant_id,actor_user_id,
                 operation_key,resource_type,resource_id,outcome,after_state_json,
                 occurred_at_utc)
                VALUES (:id,:correlation_id,'TENANT',:tenant_id,:actor_id,
                        :operation_key,:resource_type,:resource_id,'SUCCESS',
                        CAST(:state AS jsonb),:now)
                """
            ),
            {
                "id": str(uuid4()),
                "correlation_id": correlation_id,
                "tenant_id": tenant_id,
                "actor_id": actor_user_id,
                "operation_key": operation_key,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "state": json.dumps(state),
                "now": now,
            },
        )

    @staticmethod
    def _log_self_denial(
        correlation_id: str,
        tenant_code: str,
        identity_provider: str,
    ) -> None:
        _LOG.warning(
            "self_onboarding_denied correlation_id=%s tenant_code=%s provider=%s",
            correlation_id,
            tenant_code,
            identity_provider,
        )


def _verify_secret(encoded_hash: str, candidate: str) -> bool:
    try:
        return bool(_HASHER.verify(encoded_hash, candidate))
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
