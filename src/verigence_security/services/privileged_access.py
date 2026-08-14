from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from verigence_security.services.tenant_rbac_gate import TenantRbacGateService

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


class PrivilegedAccessService(TenantRbacGateService):
    """Increment G maker-checker for privileged Tenant role assignments."""

    def __init__(self, session: Session) -> None:
        super().__init__(session)

    def request_or_assign_user_role(
        self,
        *,
        tenant_id: str,
        user_id: str,
        role_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        if not self._active_membership(tenant_id, user_id, now):
            raise ValueError("User must be ACTIVE")
        role = self.s.execute(
            text(
                """
                SELECT role_key,status FROM security.roles
                WHERE tenant_id=:tenant_id AND role_id=:role_id
                """
            ),
            {"tenant_id": tenant_id, "role_id": role_id},
        ).mappings().first()
        if role is None or role["status"] != "ACTIVE":
            raise ValueError("Role must be ACTIVE")
        role_key = str(role["role_key"])
        if role_key not in PRIVILEGED_ROLE_KEYS:
            created = super().assign_user_role(
                tenant_id=tenant_id,
                user_id=user_id,
                role_id=role_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
            )
            return {"status": "ACTIVE", "created": created, "privileged": False}

        active = self.s.execute(
            text(
                """
                SELECT assignment_id FROM security.user_role_assignments
                WHERE tenant_id=:tenant_id AND user_id=:user_id
                  AND role_id=:role_id AND status='ACTIVE'
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id, "role_id": role_id},
        ).first()
        if active is not None:
            self.s.rollback()
            return {"status": "ACTIVE", "created": False, "privileged": True}

        pending = self._pending_request(tenant_id, user_id, role_id)
        if pending is not None:
            self.s.rollback()
            return self._public(pending, role_key)

        request_id = str(uuid4())
        try:
            self.s.execute(
                text(
                    """
                    INSERT INTO security.privileged_access_requests
                    (request_id,tenant_id,subject_user_id,role_id,status,
                     requested_by_user_id,requested_at_utc,correlation_id)
                    VALUES (:request_id,:tenant_id,:user_id,:role_id,'PENDING',
                            :actor_user_id,:now,:correlation_id)
                    """
                ),
                {
                    "request_id": request_id,
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "role_id": role_id,
                    "actor_user_id": actor_user_id,
                    "now": now,
                    "correlation_id": correlation_id,
                },
            )
            self._audit(
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
                operation_key="security.privileged_access.request",
                resource_type="PRIVILEGED_ACCESS_REQUEST",
                resource_id=request_id,
                now=now,
            )
            self.s.commit()
        except IntegrityError:
            self.s.rollback()
            pending = self._pending_request(tenant_id, user_id, role_id)
            if pending is None:
                raise
            return self._public(pending, role_key)
        return {
            "requestId": request_id,
            "tenantId": tenant_id,
            "subjectUserId": user_id,
            "roleId": role_id,
            "roleKey": role_key,
            "status": "PENDING",
            "requestedByUserId": actor_user_id,
            "privileged": True,
        }

    def list_requests(self, tenant_id: str, status_filter: str | None = None) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"tenant_id": tenant_id}
        predicate = ""
        if status_filter is not None:
            predicate = " AND r.status=:status"
            params["status"] = status_filter
        rows = self.s.execute(
            text(
                """
                SELECT r.request_id,r.tenant_id,r.subject_user_id,r.role_id,r.source_invitation_id,
                       r.status,r.requested_by_user_id,r.requested_at_utc,r.approved_by_user_id,
                       r.decided_at_utc,r.decision_reason,r.correlation_id,
                       ro.role_key,ro.role_name,u.display_name AS subject_display_name
                FROM security.privileged_access_requests r
                JOIN security.roles ro
                  ON ro.tenant_id=r.tenant_id AND ro.role_id=r.role_id
                JOIN security.users u ON u.user_id=r.subject_user_id
                WHERE r.tenant_id=:tenant_id
                """
                + predicate
                + " ORDER BY r.requested_at_utc DESC"
            ),
            params,
        ).mappings()
        return [self._public(dict(row), str(row["role_key"])) for row in rows]

    def approve(
        self,
        *,
        tenant_id: str,
        request_id: str,
        approver_user_id: str,
        correlation_id: str,
        reason: str | None,
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        request = self._locked_request(tenant_id, request_id)
        self._require_pending_and_independent(request, approver_user_id)
        subject_user_id = str(request["subject_user_id"])
        role_id = str(request["role_id"])
        if not self._active_membership(tenant_id, subject_user_id, now):
            raise ValueError("Subject user must be ACTIVE")
        if not self._active_role(tenant_id, role_id):
            raise ValueError("Role must be ACTIVE")
        exists = self.s.execute(
            text(
                """
                SELECT assignment_id FROM security.user_role_assignments
                WHERE tenant_id=:tenant_id AND user_id=:user_id
                  AND role_id=:role_id AND status='ACTIVE'
                """
            ),
            {"tenant_id": tenant_id, "user_id": subject_user_id, "role_id": role_id},
        ).first()
        if exists is None:
            self.s.execute(
                text(
                    """
                    INSERT INTO security.user_role_assignments
                    (assignment_id,tenant_id,user_id,role_id,status,valid_from_utc,
                     assigned_by_user_id,assigned_at_utc)
                    VALUES (:id,:tenant_id,:user_id,:role_id,'ACTIVE',:now,
                            :requested_by,:now)
                    """
                ),
                {
                    "id": str(uuid4()),
                    "tenant_id": tenant_id,
                    "user_id": subject_user_id,
                    "role_id": role_id,
                    "requested_by": str(request["requested_by_user_id"]),
                    "now": now,
                },
            )
            self._bump_versions(tenant_id, [subject_user_id], now)
        self.s.execute(
            text(
                """
                UPDATE security.privileged_access_requests
                SET status='APPROVED',approved_by_user_id=:approver,
                    decided_at_utc=:now,decision_reason=:reason
                WHERE tenant_id=:tenant_id AND request_id=:request_id
                """
            ),
            {
                "tenant_id": tenant_id,
                "request_id": request_id,
                "approver": approver_user_id,
                "now": now,
                "reason": reason,
            },
        )
        self._audit(
            tenant_id=tenant_id,
            actor_user_id=approver_user_id,
            correlation_id=correlation_id,
            operation_key="security.privileged_access.approve",
            resource_type="PRIVILEGED_ACCESS_REQUEST",
            resource_id=request_id,
            now=now,
        )
        self.s.commit()
        return self._public(self._request(tenant_id, request_id), str(request["role_key"]))

    def reject(
        self,
        *,
        tenant_id: str,
        request_id: str,
        approver_user_id: str,
        correlation_id: str,
        reason: str | None,
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        request = self._locked_request(tenant_id, request_id)
        self._require_pending_and_independent(request, approver_user_id)
        self.s.execute(
            text(
                """
                UPDATE security.privileged_access_requests
                SET status='REJECTED',approved_by_user_id=:approver,
                    decided_at_utc=:now,decision_reason=:reason
                WHERE tenant_id=:tenant_id AND request_id=:request_id
                """
            ),
            {
                "tenant_id": tenant_id,
                "request_id": request_id,
                "approver": approver_user_id,
                "now": now,
                "reason": reason,
            },
        )
        self._audit(
            tenant_id=tenant_id,
            actor_user_id=approver_user_id,
            correlation_id=correlation_id,
            operation_key="security.privileged_access.reject",
            resource_type="PRIVILEGED_ACCESS_REQUEST",
            resource_id=request_id,
            now=now,
        )
        self.s.commit()
        return self._public(self._request(tenant_id, request_id), str(request["role_key"]))

    def _pending_request(self, tenant_id: str, user_id: str, role_id: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT r.*,ro.role_key FROM security.privileged_access_requests r
                JOIN security.roles ro ON ro.tenant_id=r.tenant_id AND ro.role_id=r.role_id
                WHERE r.tenant_id=:tenant_id AND r.subject_user_id=:user_id
                  AND r.role_id=:role_id AND r.status='PENDING'
                ORDER BY r.requested_at_utc DESC LIMIT 1
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id, "role_id": role_id},
        ).mappings().first()
        return dict(row) if row else None

    def _request(self, tenant_id: str, request_id: str) -> dict[str, Any]:
        row = self.s.execute(
            text(
                """
                SELECT r.*,ro.role_key FROM security.privileged_access_requests r
                JOIN security.roles ro ON ro.tenant_id=r.tenant_id AND ro.role_id=r.role_id
                WHERE r.tenant_id=:tenant_id AND r.request_id=:request_id
                """
            ),
            {"tenant_id": tenant_id, "request_id": request_id},
        ).mappings().first()
        if row is None:
            raise LookupError("Privileged access request not found")
        return dict(row)

    def _locked_request(self, tenant_id: str, request_id: str) -> dict[str, Any]:
        row = self.s.execute(
            text(
                """
                SELECT r.*,ro.role_key FROM security.privileged_access_requests r
                JOIN security.roles ro ON ro.tenant_id=r.tenant_id AND ro.role_id=r.role_id
                WHERE r.tenant_id=:tenant_id AND r.request_id=:request_id
                FOR UPDATE OF r
                """
            ),
            {"tenant_id": tenant_id, "request_id": request_id},
        ).mappings().first()
        if row is None:
            raise LookupError("Privileged access request not found")
        return dict(row)

    @staticmethod
    def _require_pending_and_independent(request: dict[str, Any], approver_user_id: str) -> None:
        if request["status"] != "PENDING":
            raise ValueError("Privileged access request is no longer pending")
        if str(request["requested_by_user_id"]) == approver_user_id:
            raise ValueError("Requester cannot approve or reject their own privileged access request")
        if str(request["subject_user_id"]) == approver_user_id:
            raise ValueError("Subject cannot approve or reject their own privileged access request")

    @staticmethod
    def _public(row: dict[str, Any], role_key: str) -> dict[str, Any]:
        return {
            "requestId": str(row["request_id"]),
            "tenantId": str(row["tenant_id"]),
            "subjectUserId": str(row["subject_user_id"]),
            "roleId": str(row["role_id"]),
            "roleKey": role_key,
            "status": str(row["status"]),
            "requestedByUserId": str(row["requested_by_user_id"]),
            "requestedAt": row.get("requested_at_utc"),
            "approvedByUserId": (
                str(row["approved_by_user_id"]) if row.get("approved_by_user_id") is not None else None
            ),
            "decidedAt": row.get("decided_at_utc"),
            "decisionReason": row.get("decision_reason"),
            "sourceInvitationId": (
                str(row["source_invitation_id"]) if row.get("source_invitation_id") is not None else None
            ),
            "privileged": True,
        }
